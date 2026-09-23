# -*- coding: utf-8 -*-
"""HIP ``LOCATOR_SET``, whose ``Length`` unit and padding source were both wrong.

GitHub issue #679. Two pre-existing defects, neither fixable alone:

1. ``LocatorSetParameter.padding`` read the **nested** ``Locator.len`` rather than
   the parameter's. A :class:`~pcapkit.corekit.fields.collections.ListField` packs
   each nested schema into the enclosing packet context --
   :meth:`Schema.pack <pcapkit.protocols.schema.schema.Schema.pack>` opens with
   ``packet.update(self.__dict__)`` -- and :class:`Locator` declares a ``len`` of
   its own, so by the time ``padding`` was evaluated ``pkt['len']`` was the last
   locator's. That is 4 for any IPv6 locator whatever the count, so the old
   expression appended exactly four octets to every ``LOCATOR_SET``.
2. The parameter's ``len`` was ``sum(Locator.len)``, in the 4-octet units
   :rfc:`8046#section-4` gives ``Locator Length``, where :rfc:`7401`
   Section 5.2.1's ``Length`` is "length of the Contents, in bytes". So contents of
   24, 48 and 120 octets declared ``Length`` 4, 8 and 20 -- ``4n`` where the
   contents are ``24n``.

Why they had to move together
-----------------------------

Always-4 padding gives ``4 + 24n + 4 = 24n + 8``; and because ``24n`` is a
multiple of eight, the RFC total for a byte-count ``Length`` of ``24n`` is
``11 + 24n - 3``, the same ``24n + 8``. So the two errors cancelled and the
parameter was conformant -- 32, 56 and 128 octets at n = 1, 2, 5 -- which is why
#651 and #664 deliberately excluded this one site: correcting the padding alone
would have left ``24n + 4``, four octets short at every count.

**The cancellation was never general, and that is the whole reason this module
sweeps shapes rather than counts.** It needs every locator to be 24 octets and
there to be at least one of them. Measured on ``f0999858e``, the shapes where it
does not hold were non-conformant before this fix:

===================  ==============  ======  =========================
shape                declared ``len``  packed  RFC total for the contents
===================  ==============  ======  =========================
empty, n = 0         0               **4**   8
plain IPv6, n = 1    4               32      32
plain IPv6, n = 2    8               56      56
plain IPv6, n = 5    20              128     128
SPI, n = 1           5               **35**  32
SPI, n = 2           10              **63**  64
plain then SPI       9               **59**  56
SPI then plain       9               **60**  56
===================  ==============  ======  =========================

Four of the seven were not even multiples of eight. A sweep over n = 1..5 of
plain locators passes today by cancellation and would pass a half-fix too, so it
discriminates nothing; the empty set, the SPI-bearing variant and a mixed set in
both orders are the shapes that do.

The reader consumed the same quantity
-------------------------------------

This is why #679 was judged a different class of change from #664's
one-expression padding fix rather than a second instance of it.
``LocatorSetParameter.locators`` is declared
``ListField(length=lambda pkt: pkt['len'])``, and :meth:`Schema.unpack
<pcapkit.protocols.schema.schema.Schema.unpack>` reads exactly ``field.length``
octets off the stream and hands only those to the list. With ``Length`` at ``4n``
a set of *n* plain locators was offered ``4n`` octets of a ``24n``-octet
contents, so -- measured on ``f0999858e`` -- n = 2 and n = 5 both parsed **one**
truncated locator, warned ``SchemaWarning: packet length < 0``, left the
remainder of the record unconsumed, and repacked to something other than what was
read. In a whole packet that remainder was read as a second, fabricated
parameter: a one-copy ``LOCATOR_SET`` frame parsed as *two* parameters. The
expression was right and the quantity was wrong, so fixing the unit repairs the
reader rather than breaking it -- which
:meth:`test_every_shape_parses_back_to_the_locators_it_was_built_from` and
:meth:`test_a_lone_locator_set_parameter_survives_a_hip_packet` assert directly.
"""
from __future__ import annotations

import importlib.util
import unittest
import warnings

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Header fields shared by every HIP packet built here, as in
#: :data:`examples.generators.options.HIP_BASE`.
HIP_BASE = {
    'next': 6, 'packet': 1, 'version': 2, 'checksum': b'\x00\x00',
    'controls_anonymous': False, 'shit': 0, 'rhit': 0, 'payload': b'',
}

#: A plain IPv6 locator: ``Locator Length`` 4, so 8 + 16 = 24 octets.
PLAIN = {'ip': '2001:db8::1'}
#: An SPI-bearing locator: ``Locator Length`` 5, so 8 + 20 = 28 octets.
#:
#: ``type=1`` is not redundant. ``_make_param_locator_set`` sets
#: ``length = 5`` when ``spi`` is given but leaves ``type`` at its default 0, and
#: :func:`~pcapkit.protocols.schema.internet.hip.locator_value_selector` accepts
#: only ``type == 0, len == 4`` or ``type == 1, len == 5`` -- so ``spi=`` without
#: an explicit ``type=1`` raises ``FieldValueError: invalid locator type or
#: length``. That is a separate rough edge in the maker, noted rather than fixed
#: here, and it is why an earlier attempt to measure these shapes could not reach
#: the SPI path at all.
SPI = {'ip': '2001:db8::2', 'spi': 0xdeadbeef, 'type': 1}

#: Every shape, with the octets each locator record occupies. Ordered so that the
#: three the old cancellation covered come first and the four it did not follow.
SHAPES = (
    ('empty', [], 0),
    ('plain n=1', [PLAIN], 24),
    ('plain n=2', [PLAIN, PLAIN], 48),
    ('plain n=5', [PLAIN] * 5, 120),
    ('SPI n=1', [SPI], 28),
    ('SPI n=2', [SPI, SPI], 56),
    ('mixed plain then SPI', [PLAIN, SPI], 52),
    ('mixed SPI then plain', [SPI, PLAIN], 52),
)


def rfc_total(length: 'int') -> 'int':
    """:rfc:`7401#section-5.2.1`'s ``Total Length = 11 + Length - (Length + 3) % 8``.

    Written out here rather than imported from
    :func:`pcapkit.protocols.schema.internet.hip.parameter_total_len`, so the
    packed octets are compared against the RFC rather than against the library's
    own reading of it.

    Args:
        length: The parameter's ``Length`` field, i.e. its contents in octets.

    Returns:
        The whole record's length in octets, including ``Type``, ``Length`` and
        padding.

    """
    return 11 + length - (length + 3) % 8


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HIPLocatorSetLengthTests(unittest.TestCase):
    """``LOCATOR_SET``'s ``Length`` unit and padding source, over seven shapes."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _make(self, locators: 'list[dict]') -> 'tuple':
        """Build one ``LOCATOR_SET`` schema and pack it.

        Args:
            locators: Locator keyword mappings, as ``_make_param_locator_set``
                takes them.

        Returns:
            The schema and its packed octets.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        hip = object.__new__(HIP)
        schema = hip._make_param_locator_set(  # type: ignore[arg-type]
            Parameter.LOCATOR_SET, version=2,
            locator_set=[dict(locator) for locator in locators])
        return schema, schema.pack()

    def test_every_shape_packs_the_rfc_total(self) -> None:
        """Each shape's record is ``11 + Length - (Length + 3) % 8`` octets.

        Shapes, not counts. Sampling counts within the homogeneous plain-IPv6
        shape is exactly how the cancellation stayed hidden: n = 1, 2 and 5 all
        passed on ``f0999858e`` and all would pass a fix to only one of the two
        defects. The empty set, the SPI variant and the two mixed orders are what
        distinguish the three states -- broken, half-fixed and right.
        """
        for name, locators, contents in SHAPES:
            with self.subTest(shape=name):
                schema, raw = self._make(locators)

                # ``Length`` is the contents in bytes, not in 4-octet units.
                self.assertEqual(
                    schema.len, contents,
                    msg=f'{name}: Length must be a byte count; RFC 8046 section '
                        f'4 gives Locator Length in 4-octet units, RFC 7401 '
                        f'section 5.2.1 gives Length in bytes')
                # And the record is the total that ``Length`` implies.
                self.assertEqual(
                    len(raw), rfc_total(schema.len),
                    msg=f'{name}: {len(raw)} octets declared Length '
                        f'{schema.len}, which requires {rfc_total(schema.len)}')
                self.assertEqual(
                    len(raw) % 8, 0,
                    msg=f'{name}: RFC 7401 section 5.2.1 requires a multiple of '
                        f'eight; got {len(raw)}')
                # The contents really are where ``Length`` says, so the total is
                # not reached by over-padding a short contents.
                self.assertEqual(len(raw), 4 + contents + (len(raw) - 4 - contents))
                self.assertEqual(raw[2:4], contents.to_bytes(2, 'big'))

    def test_the_three_plain_shapes_keep_the_octet_counts_main_emitted(self) -> None:
        """n = 1, 2, 5 still pack 32, 56 and 128 octets.

        The one part of this parameter that was already right, and the reason
        #651 and #664 left it alone. Those three are the shapes where the two
        defects cancelled exactly, so they are also the three that a correct fix
        must not move -- if they change, something has gone wrong even though
        every other shape improved. Only the two ``Length`` octets differ from
        ``f0999858e``: ``0004`` became ``0018`` at n = 1, and so on.
        """
        for locators, total, length in (([PLAIN], 32, 24),
                                        ([PLAIN, PLAIN], 56, 48),
                                        ([PLAIN] * 5, 128, 120)):
            with self.subTest(n=len(locators)):
                schema, raw = self._make(locators)
                self.assertEqual(len(raw), total)
                self.assertEqual(len(raw), rfc_total(length))
                self.assertEqual(schema.len, length)

    def test_padding_comes_from_the_parameters_length_not_the_locators(self) -> None:
        """The padding callback reads the parameter's ``Length``.

        This is the discriminating assertion for the *first* defect on its own,
        and it is built by hand rather than through the maker precisely so that
        the two lengths disagree. A parameter ``len`` of 9 over a single locator
        whose own ``len`` is 4 needs ``rfc_total(9) - 4 - 9`` = 3 padding octets;
        the shadowed nested value would give the 4 that ``len = 4`` implies.
        Measured on ``f0999858e``: 32 octets, i.e. 4 of padding. The declared
        ``Length`` deliberately does not match the 24 octets the locator actually
        occupies, so the record total here is not meaningful -- the padding count
        is what is under test.
        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.schema.internet.hip import (Locator, LocatorSetParameter,
                                                           locator_set_padding_len)

        locator = Locator(traffic=0, type=0, len=4, flags={'preferred': False},
                          lifetime=0, value=b'\x20\x01\x0d\xb8' + b'\x00' * 11 + b'\x01')
        schema = LocatorSetParameter(type=Parameter.LOCATOR_SET, len=9,
                                     locators=[locator])
        raw = schema.pack()

        self.assertEqual(rfc_total(9) - 4 - 9, 3)
        self.assertEqual(
            len(raw), 4 + 24 + 3,
            msg=f'{len(raw)} octets: 4 header + 24 of locator + padding. 3 is the '
                f'count for the parameter Length of 9; 4 would be the count for '
                f'the nested locator len of 4, which is what shadowing gives')

        # And the callback in isolation, on both the key it reads and the value
        # that key is a snapshot of.
        from pcapkit.protocols.schema.internet.hip import LOCATOR_SET_LEN
        self.assertEqual(locator_set_padding_len({LOCATOR_SET_LEN: 9}), 3)
        self.assertEqual(locator_set_padding_len({LOCATOR_SET_LEN: 0}), 4)
        self.assertEqual(locator_set_padding_len({LOCATOR_SET_LEN: 24}), 4)
        self.assertEqual(locator_set_padding_len({LOCATOR_SET_LEN: 28}), 0)

    def test_the_snapshot_survives_the_nested_locators(self) -> None:
        """The packet context keeps the parameter's ``Length`` under its own key.

        The mechanism, asserted rather than inferred: after a pack, the shared
        context's ``len`` has been overwritten by the last nested locator's while
        :data:`~pcapkit.protocols.schema.internet.hip.LOCATOR_SET_LEN` still holds
        the parameter's. Without this the two would be indistinguishable at the
        one shape where the numbers happen to agree.
        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.protocols.schema.internet.hip import LOCATOR_SET_LEN

        hip = object.__new__(HIP)
        schema = hip._make_param_locator_set(  # type: ignore[arg-type]
            Parameter.LOCATOR_SET, version=2, locator_set=[dict(SPI)])
        context = {}  # type: dict
        schema.pack(context)

        self.assertEqual(context[LOCATOR_SET_LEN], 28)
        self.assertEqual(
            context['len'], 5,
            msg='the nested Locator.len is expected to shadow the parameter here; '
                'if it no longer does, the snapshot has become unnecessary rather '
                'than wrong')

    def test_every_shape_parses_back_to_the_locators_it_was_built_from(self) -> None:
        """The reader consumes the whole contents and repacks identically.

        ``ListField(length=lambda pkt: pkt['len'])`` is handed ``Length`` octets
        and no more, so this is the half of #679 that a padding fix could not
        have reached. Measured on ``f0999858e``, every non-empty shape parsed
        exactly **one** locator regardless of how many it was built with, warned
        ``SchemaWarning: packet length < 0``, and repacked to something other
        than what it read.

        The residual warnings are asserted to be absent *at the parameter level*
        only for the empty shape. Every nested :class:`Locator` still raises six
        of them, one per field, because ``SchemaField`` seeds a nested schema's
        ``__length__`` at the ``-1`` placeholder
        :meth:`Schema.pack <pcapkit.protocols.schema.schema.Schema.pack>`
        documents; that is pre-existing, unrelated to ``Length`` units, and
        unchanged by this fix -- what changed is that it now fires once per
        locator actually parsed rather than once per truncated first locator.
        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.protocols.schema.internet.hip import LocatorSetParameter

        hip = object.__new__(HIP)
        for name, locators, contents in SHAPES:
            with self.subTest(shape=name):
                schema, raw = self._make(locators)

                back = LocatorSetParameter.unpack(raw, len(raw))  # type: ignore[arg-type]
                self.assertEqual(back.len, contents)
                self.assertEqual(
                    len(back.locators), len(locators),
                    msg=f'{name}: built {len(locators)} locator(s), parsed '
                        f'{len(back.locators)}')
                self.assertEqual(
                    back.pack(), raw,
                    msg=f'{name}: repacking what was read did not reproduce it')

                # And the data model reports the whole record, not a derivative
                # of the wrong unit. On ``f0999858e`` this read 12 for the
                # 32-octet n = 1 record.
                data = hip._read_param_locator_set(  # type: ignore[arg-type]
                    back, version=2, options=None)  # type: ignore[arg-type]
                self.assertEqual(data.length, len(raw))
                self.assertEqual(data.length, rfc_total(contents))
                self.assertEqual(len(data.locator_set), len(locators))

    def test_a_lone_locator_set_parameter_survives_a_hip_packet(self) -> None:
        """One copy in a real packet builds, parses, and yields one parameter.

        The end-to-end consequence of the ``Length`` unit, and the sharpest of
        these assertions because it catches the silent case rather than the loud
        one. Measured on ``f0999858e``: the empty shape raised, the SPI and mixed
        shapes raised ``ProtocolError: HIPv2: invalid format`` -- and the three
        plain shapes *succeeded* while parsing **two** parameters, the second
        fabricated out of the 20n octets the reader never consumed, with a
        reported ``length`` of 12 for a 32-octet record.
        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        for name, locators, contents in SHAPES:
            with self.subTest(shape=name):
                built = HIP(
                    parameters=[(Parameter.LOCATOR_SET,
                                 {'locator_set': [dict(x) for x in locators]})],
                    extension=True, **HIP_BASE)
                octets = built.data

                with warnings.catch_warnings():
                    # The per-locator ``__length__`` warnings described above are
                    # pre-existing noise on a now-correct parse; the assertions
                    # below are what this case is about.
                    warnings.simplefilter('ignore')
                    parsed = HIP(octets, len(octets), extension=True)

                params = parsed.info.parameters
                self.assertEqual(
                    len(list(params)), 1,
                    msg=f'{name}: unconsumed contents get read as a second, '
                        f'fabricated parameter')
                param = params[Parameter.LOCATOR_SET]
                self.assertEqual(param.length, rfc_total(contents))
                self.assertEqual(len(param.locator_set), len(locators))


if __name__ == '__main__':
    unittest.main()
