# -*- coding: utf-8 -*-
"""The HIP ``R1_COUNTER`` generation counter is eight octets, not four.

GitHub issue #672. :rfc:`7401#section-5.2.3` states the width twice -- its
diagram labels the field "R1 generation counter, 8 bytes", and the prose below it
says the parameter "contains a 64-bit unsigned integer in network byte order" --
so nothing here is inferred from a figure.
:rfc:`5201#section-5.2.3` gives the same ``Reserved, 4 bytes`` plus 8-octet
counter layout, which is why both codes that reach
:class:`~pcapkit.protocols.schema.internet.hip.R1CounterParameter` are affected:
``R1_Counter`` (128, HIPv1) and ``R1_COUNTER`` (129).

``counter`` was a :class:`~pcapkit.corekit.fields.numbers.UInt32Field`. The
parameter therefore *declared* the correct ``len=12`` -- 4 octets of ``Reserved``
plus 8 of counter, which is the ``Length 12`` the RFC states -- and *packed* only
eight of those twelve, for a record of 12 octets where :rfc:`7401`
Section 5.2.1's ``Total Length = 11 + Length - (Length + 3) % 8`` makes it 16.
Four short, at ``4 (mod 8)``, in both directions: a conformant receiver reading
``Length = 12`` consumes 16 octets and takes four octets of the next parameter as
this one's tail, and a real peer's 16-octet ``R1_COUNTER`` leaves its last four
octets to be read as the following parameter's ``Type``.

Why the existing suite could not see it
---------------------------------------

Three things hid it at once, and the third is the reason this module asserts
against the RFC's arithmetic rather than against a round trip.

1. ``HIP_COPIES = 2`` in :mod:`examples.generators.options` puts two copies of
   each parameter in a frame, and two four-octet shortfalls sum to eight, so the
   record area stays 8-aligned and ``HIP.make``'s ``total_length // 8 + 4``
   comes out exact.
2. Before #651 the padding aligned the parameter *contents* rather than the
   record, which at ``Length = 12`` appended exactly the four surplus octets this
   parameter was missing. Correcting the padding did not break ``R1_COUNTER``; it
   stopped compensating for it.
3. The round trip cannot see it at all, because pcapkit's reader consumes exactly
   the twelve octets its writer wrote. Only a comparison against the RFC's own
   stride -- or a real peer -- can tell the difference, which is what
   :meth:`test_r1_counter_record_is_the_rfc_total_at_both_codes` does, with the
   formula spelled out locally rather than taken from the library.

The fixture could not see it either, for a fourth reason
--------------------------------------------------------

``R1_COUNTER`` had no entry in ``_hip_overrides()``, so the generator built it
with ``counter = 0``. An RFC-only walk over :file:`options-internet.pcap` read
``Length = 12``, advanced 16 over a 12-octet record, landed four octets inside the
second copy, and found a phantom ``Type = 0, Length = 0`` record in that copy's
own zeroed contents -- whose "padding" was four zero octets, so its zero-padding
check passed and the walk ended tidily on the area boundary. Measured on
``f0999858e``: patching one counter to ``aabbccdd`` turns that silence into
``frame 101: type 0 padding not zeroed: aabbccdd``. A zero-valued field cannot
discriminate a width defect from a correct one, so
:meth:`test_the_generator_gives_r1_counter_a_non_zero_counter` pins the override
that stops the fixture hiding the next one.
"""
from __future__ import annotations

import importlib.util
import unittest

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Header fields shared by every HIP packet built here. The same set
#: :data:`examples.generators.options.HIP_BASE` uses, so a failure here is not a
#: failure to drive the constructor.
HIP_BASE = {
    'next': 6, 'packet': 1, 'checksum': b'\x00\x00',
    'controls_anonymous': False, 'shit': 0, 'rhit': 0, 'payload': b'',
}


def rfc_total(length: 'int') -> 'int':
    """:rfc:`7401#section-5.2.1`'s ``Total Length = 11 + Length - (Length + 3) % 8``.

    Written out here rather than imported from
    :func:`pcapkit.protocols.schema.internet.hip.parameter_total_len`, so that
    this module compares the packed octets against the RFC and not against the
    library's own reading of it.

    Args:
        length: The parameter's ``Length`` field, i.e. its contents in octets.

    Returns:
        The whole record's length in octets, including ``Type``, ``Length`` and
        padding.

    """
    return 11 + length - (length + 3) % 8


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HIPR1CounterWidthTests(unittest.TestCase):
    """``R1_COUNTER``'s counter width, against :rfc:`7401#section-5.2.3`."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_r1_counter_record_is_the_rfc_total_at_both_codes(self) -> None:
        """Both codes pack the 16 octets ``Length = 12`` requires.

        The exact octets are pinned, not just the length, because the length
        alone would pass for a record padded to 16 with a four-octet counter as
        readily as for one carrying the eight-octet counter the RFC specifies --
        and the padding is what the pre-#651 rule appended. So the assertion
        names where the eight octets sit: four of ``Reserved`` after the
        type-and-length header, then the counter, then no padding at all, since
        ``rfc_total(12) - 4 - 12`` is zero.
        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        hip = object.__new__(HIP)
        for code, version, prefix in ((Parameter.R1_Counter, 1, '0080'),
                                      (Parameter.R1_COUNTER, 2, '0081')):
            with self.subTest(code=int(code), name=code.name):
                schema = hip._make_param_r1_counter(  # type: ignore[arg-type]
                    code, version=version, counter=1)
                raw = schema.pack()

                # The declared ``Length`` was never wrong -- it is the packed
                # contents that disagreed with it.
                self.assertEqual(schema.len, 12)
                self.assertEqual(len(raw), rfc_total(12))
                self.assertEqual(len(raw), 16)
                self.assertEqual(len(raw) % 8, 0)
                # Twelve octets before #672, four of them the counter:
                # ``00 8x 00 0c 00 00 00 00 00 00 00 01``.
                self.assertEqual(
                    raw.hex(), prefix + '000c' + '00000000' + '0000000000000001')
                # No padding: ``Length = 12`` plus the four header octets is
                # already a multiple of eight.
                self.assertEqual(rfc_total(12) - 4 - 12, 0)

    def test_the_counter_carries_a_64_bit_value(self) -> None:
        """A counter above ``2**32`` survives the round trip.

        This is the assertion that cannot be satisfied by padding. :rfc:`7401`
        Section 5.2.3 calls the field "a 64-bit unsigned integer", so the
        interesting values are the ones a 32-bit field cannot hold at all: a
        :class:`~pcapkit.corekit.fields.numbers.UInt32Field` either raises
        packing ``2**32`` or silently keeps the low half, and both outcomes lose
        the generation counter a peer sent.
        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.protocols.schema.internet.hip import R1CounterParameter

        hip = object.__new__(HIP)
        for counter in (0, 1, 0xffffffff, 0x1_0000_0000, 0x0123456789abcdef,
                        0xffffffffffffffff):
            with self.subTest(counter=counter):
                schema = hip._make_param_r1_counter(  # type: ignore[arg-type]
                    Parameter.R1_COUNTER, version=2, counter=counter)
                raw = schema.pack()
                self.assertEqual(len(raw), 16)
                # Network byte order, over the whole eight octets.
                self.assertEqual(raw[8:16], counter.to_bytes(8, 'big'))
                back = R1CounterParameter.unpack(raw, len(raw))  # type: ignore[arg-type]
                self.assertEqual(back.counter, counter)
                self.assertEqual(back.pack(), raw)

    def test_a_lone_r1_counter_parameter_survives_a_hip_packet(self) -> None:
        """One copy in a real packet builds, parses, and gives the counter back.

        ``HIP.make`` derives the header's ``len`` as ``total_length // 8 + 4``,
        and ``_read_hip_param`` compares the recovered length exactly, so a
        parameter that is not a multiple of eight on its own cannot survive
        alone -- the floor division drops the remainder. Measured on
        ``f0999858e`` this raised ``ProtocolError: HIPv2: invalid format`` at
        both codes; the two-copy pairing in
        :mod:`examples.generators.options` is what concealed that.

        Code 128 is deliberately not exercised here. It fails for an unrelated
        reason that #672 does not touch -- the schema registry is keyed on the
        ``code=`` of the class statement and ``R1CounterParameter`` declares only
        129, so 128 parses as an ``UnassignedParameter`` -- which is #690, and
        which ``hip-parameter/R1_Counter`` in
        :mod:`tests.protocols.test_option_roundtrip_unit` records.
        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        counter = 0x0123456789abcdef
        built = HIP(parameters=[(Parameter.R1_COUNTER, {'counter': counter})],
                    extension=True, version=2, **HIP_BASE)
        octets = built.data
        parsed = HIP(octets, len(octets), extension=True)

        params = parsed.info.parameters
        self.assertEqual(len(list(params)), 1,
                         msg='a 12-octet record leaves four octets to be read as '
                             'a second, fabricated parameter')
        param = params[Parameter.R1_COUNTER]
        self.assertEqual(param.counter, counter)
        # The reported length is the whole record, ``rfc_total(12)``.
        self.assertEqual(param.length, rfc_total(12))
        self.assertEqual(param.length, 16)

    def test_the_generator_gives_r1_counter_a_non_zero_counter(self) -> None:
        """``_hip_overrides()`` must not leave this counter at zero.

        Not a style preference. The RFC-only walk over
        :file:`options-internet.pcap` reported no violation on this parameter for
        as long as the counter was zero, because every octet it mis-read while
        striding 16 over a 12-octet record was itself zero -- so its
        zero-padding check passed on a phantom record it had fabricated out of
        the second copy. Measured on ``f0999858e``: a non-zero counter takes that
        walk from 1 violation to 2, the new one being ``frame 101: type 0 padding
        not zeroed: aabbccdd``.

        The width is fixed now, so the walk finds nothing here either way. This
        pins the override anyway, because a fixture that cannot discriminate a
        wrong width from a right one is what let this defect survive as long as
        it did -- the same trap #608 fell into with the ``SOLUTION`` field.
        """
        from pcapkit.const.hip.parameter import Parameter

        from tests.protocols.test_option_roundtrip_unit import _load_generator

        overrides = _load_generator()._hip_overrides()
        for code in (Parameter.R1_Counter, Parameter.R1_COUNTER):
            with self.subTest(code=int(code), name=code.name):
                self.assertIn(code, overrides)
                self.assertNotEqual(
                    overrides[code].get('counter', 0), 0,
                    msg='a zero-valued counter cannot discriminate a width '
                        'defect from a correct one')


if __name__ == '__main__':
    unittest.main()
