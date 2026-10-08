# -*- coding: utf-8 -*-
"""GitHub issue #1382: undefined ``epb_flags`` sub-field values round-trip.

A direction of ``0b11`` or a reception type of ``0b101`` to ``0b111`` raised
:exc:`~pcapkit.utilities.exceptions.ProtocolError`, so a capture carrying one
could be neither parsed nor rebuilt. Both now resolve to an ``Unassigned``
member that keeps the wire value. Bits 9 to 11, which pcapng-06 Table 5 defines
(checksum not ready, checksum valid, TCP segmentation offloaded), are named
instead of sitting in ``reserved``.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import unittest
import warnings

from tests.protocols.misc.test_pcapng_roundtrip2_unit import H, PCAPNGTestCase, _epb_with_options


def _pb_with_flags(word: 'bytes') -> 'bytes':
    """An obsolete Packet Block on interface 0 carrying ``abcd`` and a ``pack_flags`` word."""
    return H('02000000 30000000 0000 0000 00000000 00000000 04000000 04000000 61626364'
             '0200 0400') + word + H('00000000 30000000')


class TestPCAPNGFlagsUndefined(PCAPNGTestCase):
    """Pin how undefined and newly named flags bits parse and rebuild."""

    def _flags(self, word: 'str') -> 'tuple[bytes, object]':
        from pcapkit.const.pcapng.option_type import OptionType

        octets = _epb_with_options(H('0200 0400' + word))
        return octets, self._parse(octets).info.options[OptionType.epb_flags]

    def test_undefined_direction_parses_and_rebuilds(self) -> None:
        octets, flags = self._flags('03000000')
        self.assertEqual(int(flags.direction), 0b11)  # type: ignore[attr-defined]
        self.assertEqual(flags.direction.name, 'Unassigned')  # type: ignore[attr-defined]
        self.assertRebuilds(octets)

    def test_undefined_reception_parses_and_rebuilds(self) -> None:
        for value in (0b101, 0b110, 0b111):
            with self.subTest(reception=value):
                octets, flags = self._flags(f'{value << 2:02x}000000')
                self.assertEqual(int(flags.reception), value)  # type: ignore[attr-defined]
                self.assertEqual(flags.reception.name, 'Unassigned')  # type: ignore[attr-defined]
                self.assertRebuilds(octets)

    def test_every_word_rebuilds(self) -> None:
        """Every direction and reception value, with every other bit set."""
        for low in range(0x20):
            with self.subTest(low=low):
                octets, _ = self._flags(f'{0xffffffe0 | low:08x}')
                self.assertRebuilds(octets)

    def test_pack_flags_undefined_values_rebuild(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType

        octets = _pb_with_flags(H('1f000000'))
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')  # the Packet Block is obsolete
            flags = self._parse(octets).info.options[OptionType.pack_flags]
            self.assertEqual((int(flags.direction), int(flags.reception)), (0b11, 0b111))
            self.assertRebuilds(octets)

    def test_make_accepts_undefined_values(self) -> None:
        """``make`` -> parse -> pack keeps an undefined value."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        context = self._context()
        block = PCAPNG(num=2, sct=1, ctx=context, type=BlockType.Enhanced_Packet_Block,
                       block={'packet_data': b'abcd', 'timestamp': 0,
                              'options': [(OptionType.epb_flags, {'direction': 0b11, 'reception': 0b110})]})
        self.assertIn(H('0200 0400 1b000000'), block.data)
        self.assertRebuilds(block.data, context)

    def test_offload_bits_are_named(self) -> None:
        _, flags = self._flags('000e0000')
        self.assertEqual((flags.checksum_not_ready, flags.checksum_valid,  # type: ignore[attr-defined]
                          flags.tcp_segmentation_offloaded, flags.reserved),  # type: ignore[attr-defined]
                         (True, True, True, 0))
        _, flags = self._flags('00f0ff00')
        self.assertEqual((flags.checksum_not_ready, flags.checksum_valid,  # type: ignore[attr-defined]
                          flags.tcp_segmentation_offloaded, flags.reserved),  # type: ignore[attr-defined]
                         (False, False, False, 0xfff))

    def test_make_sets_offload_bits(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        for kwargs, word in (({'checksum_not_ready': True}, '00020000'),
                             ({'checksum_valid': True}, '00040000'),
                             ({'tcp_segmentation_offloaded': True}, '00080000'),
                             ({'reserved': 1}, '00100000')):
            with self.subTest(**kwargs):
                block = PCAPNG(num=2, sct=1, ctx=self._context(), type=BlockType.Enhanced_Packet_Block,
                               block={'packet_data': b'abcd', 'timestamp': 0,
                                      'options': [(OptionType.epb_flags, kwargs)]})
                self.assertIn(H('0200 0400' + word), block.data)

    def test_out_of_range_value_still_raises(self) -> None:
        from pcapkit.protocols.misc.pcapng import PacketDirection, PacketReception
        from pcapkit.utilities.exceptions import EnumValueError

        with self.assertRaises(EnumValueError):
            PacketDirection(4)
        with self.assertRaises(EnumValueError):
            PacketReception(8)
        # The unassigned member stays out of the lookup tables.
        PacketDirection(3)
        self.assertNotIn(3, PacketDirection._value2member_map_)


if __name__ == '__main__':
    unittest.main()
