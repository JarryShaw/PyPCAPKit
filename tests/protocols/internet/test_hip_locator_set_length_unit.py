# -*- coding: utf-8 -*-
"""HIP ``LOCATOR_SET`` counts ``Length`` in bytes and pads from its own length.

GitHub issue #679 fixed two defects together:

1. ``LocatorSetParameter.padding`` read the nested ``Locator.len`` rather than
   the parameter's: :meth:`Schema.pack <pcapkit.protocols.schema.Schema.pack>`
   opens with ``packet.update(self.__dict__)``, so each nested locator
   overwrites ``pkt['len']`` in the shared context.
2. ``Length`` was ``sum(Locator.len)``, in the 4-octet units
   :rfc:`8046#section-4` gives ``Locator Length``, where :rfc:`7401`
   Section 5.2.1 counts bytes.

Why Shapes, Not Counts
----------------------

For *n* plain IPv6 locators the errors cancel: always-4 padding gives
``4 + 24n + 4``, the RFC total for a ``Length`` of ``24n``. So a sweep over *n*
cannot tell broken from fixed, and fixing either defect alone is
non-conformant. The other shapes do discriminate; unfixed, they packed:

===================  ================  ======  =========================
shape                declared ``len``  packed  RFC total for the contents
===================  ================  ======  =========================
empty, n = 0         0                 **4**   8
plain IPv6, n = 1    4                 32      32
plain IPv6, n = 2    8                 56      56
plain IPv6, n = 5    20                128     128
SPI, n = 1           5                 **35**  32
SPI, n = 2           10                **63**  64
plain then SPI       9                 **59**  56
SPI then plain       9                 **60**  56
===================  ================  ======  =========================

The reader consumes the same quantity: ``LocatorSetParameter.locators`` is
``ListField(length=lambda pkt: pkt['len'])``, so a ``4n`` ``Length`` offered it
part of a ``24n``-octet contents. It parsed one truncated locator, and in a
whole packet read the remainder as a second, fabricated parameter.
:meth:`test_every_shape_parses_back_to_the_locators_it_was_built_from` and
:meth:`test_a_lone_locator_set_parameter_survives_a_hip_packet` pin the reader.
"""
from __future__ import annotations

import importlib.util
import unittest
import warnings

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Header fields shared by every HIP packet built here, as in
#: :data:`examples.generators.option_families.hip.HIP_BASE`.
HIP_BASE = {
    'next': 6, 'packet': 1, 'version': 2, 'checksum': b'\x00\x00',
    'controls_anonymous': False, 'shit': 0, 'rhit': 0, 'payload': b'',
}

#: A plain IPv6 locator, ``Locator Length`` 4, so 8 + 16 = 24 octets.
PLAIN = {'ip': '2001:db8::1'}
#: An SPI-bearing locator, ``Locator Length`` 5, so 8 + 20 = 28 octets.
#: ``type=1`` restates what ``_make_param_locator_set`` derives from ``spi``.
SPI = {'ip': '2001:db8::2', 'spi': 0xdeadbeef, 'type': 1}

#: Every shape, with its contents in octets; the shapes the cancellation covers
#: come first.
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

    Written out rather than imported from
    :func:`pcapkit.protocols.internet.hip.schema.parameter_total_len`, so the
    check is against the RFC, not the library's reading of it.

    Args:
        length: The parameter's ``Length`` field, i.e. its contents in octets.

    Returns:
        The whole record's length in octets, including ``Type``, ``Length`` and
        padding.

    """
    return 11 + length - (length + 3) % 8


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HIPLocatorSetLengthTests(unittest.TestCase):
    """``LOCATOR_SET``'s ``Length`` unit and padding source, over every shape."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _make(self, locators: 'list[dict]') -> 'tuple':
        """Build one ``LOCATOR_SET`` schema and pack it.

        Args:
            locators: Locator keyword mappings, as ``_make_param_locator_set``
                takes them.

        Returns:
            The schema and its packed octets.

        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip.protocol import HIP

        hip = object.__new__(HIP)
        schema = hip._make_param_locator_set(  # type: ignore[arg-type]
            Parameter.LOCATOR_SET, version=2,
            locator_set=[dict(locator) for locator in locators])
        return schema, schema.pack()

    def test_every_shape_packs_the_rfc_total(self) -> None:
        """Each shape's record is ``11 + Length - (Length + 3) % 8`` octets.

        The empty set, the SPI variant and the two mixed orders are what tell
        broken, half-fixed and fixed apart; the plain shapes cannot.
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

    def test_the_plain_shapes_pack_their_rfc_octet_counts(self) -> None:
        """n = 1, 2, 5 pack 32, 56 and 128 octets.

        The defects cancel exactly at these shapes, so a correct fix must not
        move their totals; only the ``Length`` octets change.
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

        Built by hand so the two lengths disagree, which isolates the *first*
        defect. A parameter ``len`` of 9 over one locator whose own ``len`` is 4
        needs ``rfc_total(9) - 4 - 9`` = 3 padding octets; the shadowed read
        gives ``parameter_padding_len({'len': 4})`` = 0, packing 28 octets
        instead of 31. ``Length`` deliberately mismatches the locator's 24
        octets, so only the padding count is under test.
        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip.schema import (Locator, LocatorSetParameter,
                                                           locator_set_padding_len)

        locator = Locator(traffic=0, type=0, len=4, flags={'reserved': 0, 'preferred': False},
                          lifetime=0, value=b'\x20\x01\x0d\xb8' + b'\x00' * 11 + b'\x01')
        schema = LocatorSetParameter(type=Parameter.LOCATOR_SET, len=9,
                                     locators=[locator])
        raw = schema.pack()

        self.assertEqual(rfc_total(9) - 4 - 9, 3)
        self.assertEqual(
            len(raw), 4 + 24 + 3,
            msg=f'{len(raw)} octets: 4 header + 24 of locator + padding. 3 is the '
                f'count for the parameter Length of 9; shadowing by the nested '
                f'locator len of 4 gives 0, i.e. 28 octets')

        # And the callback in isolation, on both the key it reads and the value
        # that key is a snapshot of.
        from pcapkit.protocols.internet.hip.schema import LOCATOR_SET_LEN
        self.assertEqual(locator_set_padding_len({LOCATOR_SET_LEN: 9}), 3)
        self.assertEqual(locator_set_padding_len({LOCATOR_SET_LEN: 4}), 0)
        self.assertEqual(locator_set_padding_len({LOCATOR_SET_LEN: 0}), 4)
        self.assertEqual(locator_set_padding_len({LOCATOR_SET_LEN: 24}), 4)
        self.assertEqual(locator_set_padding_len({LOCATOR_SET_LEN: 28}), 0)

    def test_the_snapshot_survives_the_nested_locators(self) -> None:
        """The packet context keeps the parameter's ``Length`` under its own key.

        After a pack the shared context's ``len`` is the last nested locator's,
        while :data:`~pcapkit.protocols.internet.hip.schema.LOCATOR_SET_LEN`
        still holds the parameter's.
        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip.protocol import HIP
        from pcapkit.protocols.internet.hip.schema import LOCATOR_SET_LEN

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
        and no more, so this is the half of #679 a padding fix cannot reach.
        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip.protocol import HIP
        from pcapkit.protocols.internet.hip.schema import LocatorSetParameter

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
                # of the wrong unit.
                data = hip._read_param_locator_set(  # type: ignore[arg-type]
                    back, version=2, options=None)  # type: ignore[arg-type]
                self.assertEqual(data.length, len(raw))
                self.assertEqual(data.length, rfc_total(contents))
                self.assertEqual(len(data.locator_set), len(locators))

    def test_a_lone_locator_set_parameter_survives_a_hip_packet(self) -> None:
        """One copy in a real packet builds, parses, and yields one parameter.

        It catches the silent case: with the wrong unit the plain shapes parsed
        without error but yielded a second parameter fabricated from the octets
        the reader never consumed.
        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip.protocol import HIP

        for name, locators, contents in SHAPES:
            with self.subTest(shape=name):
                built = HIP(
                    parameters=[(Parameter.LOCATOR_SET,
                                 {'locator_set': [dict(x) for x in locators]})],
                    extension=True, **HIP_BASE)
                octets = built.data

                with warnings.catch_warnings():
                    # Warnings are not under test here.
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
