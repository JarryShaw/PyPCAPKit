# -*- coding: utf-8 -*-
"""PCAP-NG blocks keep their lengths and padding when built and rebuilt.

* #1276 -- string option lengths counted characters, not octets.
* #1279 -- the Decryption Secrets Block never padded its secrets data.
* #1280 -- the systemd Journal Export Block was never padded.
* #1282 -- the ZigBee NWK/APS secrets counted the block padding in Secrets Length.
* #1283 -- a packet longer than the snaplen was written whole behind a clipped
  captured length (PCAP-NG and PCAP).
* #1284 -- a custom option shorter than its 4-octet PEN read the PEN from the
  padding.

Every case builds its own octets in memory and reads no capture.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load, so that a
module that purged it earlier does not leave these tests holding stale classes.

"""

import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

H = bytes.fromhex


class PCAPNGTestCase(unittest.TestCase):
    """Helpers that parse and rebuild one PCAP-NG block."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _context(self, snaplen: 'int' = 0x40000) -> 'Any':
        """A one-section little-endian context with one Ethernet interface."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.engines.pcapng import Context
        from pcapkit.protocols.misc.pcapng import PCAPNG

        section = PCAPNG(num=0, sct=1, ctx=None, type=BlockType.Section_Header_Block, block={})
        context = Context(section.info)  # type: Any
        interface = PCAPNG(num=1, sct=1, ctx=context, type=BlockType.Interface_Description_Block,
                           block={'linktype': LinkType.ETHERNET, 'snaplen': snaplen})
        context.interfaces.append(interface.info)
        return context

    def _parse(self, octets: 'bytes', context: 'Any' = None) -> 'Any':
        """Parse ``octets`` as one block; a section header needs no context."""
        from pcapkit.protocols.misc.pcapng import PCAPNG

        if octets[:4] == b'\x0a\x0d\x0d\x0a':
            return PCAPNG(octets, len(octets), num=0, sct=1, ctx=None)
        return PCAPNG(octets, len(octets), num=2, sct=1, ctx=context or self._context())

    def _rebuild(self, octets: 'bytes', context: 'Any' = None) -> 'bytes':
        """Parse ``octets`` as one block and rebuild it from its data model."""
        from pcapkit.protocols.misc.pcapng import PCAPNG

        if octets[:4] == b'\x0a\x0d\x0d\x0a':
            parsed = PCAPNG(octets, len(octets), num=0, sct=1, ctx=None)
            return PCAPNG.from_data(parsed.info, num=0, sct=1, ctx=None).data
        context = context or self._context()
        parsed = PCAPNG(octets, len(octets), num=2, sct=1, ctx=context)
        return PCAPNG.from_data(parsed.info, num=2, sct=1, ctx=context).data

    def assertRebuilds(self, octets: 'bytes', context: 'Any' = None) -> None:  # pylint: disable=invalid-name
        """Assert that ``octets`` rebuild byte-exactly from their data model."""
        self.assertEqual(self._rebuild(octets, context).hex(), octets.hex())


class TestPCAPNGLengths(PCAPNGTestCase):
    """Pin lengths and padding of rebuilt PCAP-NG blocks."""

    def test_string_option_length_counts_octets(self) -> None:
        """#1276: ``opt_comment`` of ``é`` is two octets long, not one."""
        octets = H('0a0d0d0a 24000000 4d3c2b1a 0100 0000 ffffffffffffffff'
                   '01000200 c3a90000 24000000')
        self.assertEqual(self._parse(octets).info.options[1].comment, 'é')
        self.assertRebuilds(octets)

    def test_dsb_pads_odd_secrets(self) -> None:
        """#1279: three octets of secrets get one pad octet; Secrets Length stays 3."""
        self.assertRebuilds(H('0a000000 18000000 78563412 03000000 01020300 18000000'))

    def test_systemd_entry_is_padded(self) -> None:
        """#1280: a 14-octet journal entry is padded to 16."""
        self.assertRebuilds(H('09000000 1c000000 4d4553534147453d68656c6c6f0a0000 1c000000'))

    def test_zigbee_secrets_length_excludes_padding(self) -> None:
        """#1282: Secrets Length is 18 for an NWK key and 22 for an APS key."""
        key = bytes(range(16))
        nwk = H('0a000000 28000000 4b574e5a 12000000') + key + H('3412 0000 28000000')
        aps = H('0a000000 2c000000 5350415a 16000000') + key + H('3412 7856 bc9a 0000 2c000000')
        self.assertRebuilds(nwk)
        self.assertRebuilds(aps)

    def test_packet_blocks_clip_to_snaplen(self) -> None:
        """#1283: EPB, PB and SPB built over a snaplen of 8 hold 8 data octets."""
        import warnings

        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        context = self._context(snaplen=8)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')  # the Packet Block is obsolete
            for type_, size in ((BlockType.Enhanced_Packet_Block, 40),
                                (BlockType.Packet_Block, 40),
                                (BlockType.Simple_Packet_Block, 24)):
                with self.subTest(type=type_):
                    block = PCAPNG(num=2, sct=1, ctx=context, type=type_,
                                   block={'packet_data': b'A' * 16, 'timestamp': 0})
                    self.assertEqual(len(block.data), size)
                    self.assertEqual(block.info.original_len, 16)
                    self.assertEqual(block.info.captured_len, 8)
                    self.assertRebuilds(block.data, context)

    def test_snaplen_zero_means_no_limit(self) -> None:
        """#1283: a snaplen of zero clips nothing."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        block = PCAPNG(num=2, sct=1, ctx=self._context(snaplen=0), type=BlockType.Enhanced_Packet_Block,
                       block={'packet_data': b'A' * 16, 'timestamp': 0})
        self.assertEqual(block.info.captured_len, 16)

    def test_pcap_frame_clips_to_snaplen(self) -> None:
        """#1283: a PCAP record over a snaplen of 8 is 16 + 8 octets."""
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcap.header import Header

        frame = Frame(num=1, header=Header(snaplen=8).info, packet=b'A' * 16)
        self.assertEqual(len(frame.data), 24)
        self.assertEqual(frame.info.cap_len, 8)
        self.assertEqual(frame.info.len, 16)

    def test_custom_option_shorter_than_pen_is_rejected(self) -> None:
        """#1284: Option Length 3 cannot hold the 4-octet PEN.

        Its PEN and padding run past the eight-octet option area, so the area
        is kept as captured rather than read as an option (#1325), and the
        block rebuilds byte for byte.
        """
        import warnings

        octets = H('0a0d0d0a 24000000 4d3c2b1a 0100 0000 ffffffffffffffff'
                   'ad0b0300 61626300 24000000')
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            block = self._parse(octets).info
            self.assertEqual(len(block.options), 0)
            self.assertEqual(block.options_raw, H('ad0b0300 61626300'))
            self.assertRebuilds(octets)


#: A big-endian section header with no options -- the repro of #1272.
SHB_BE = H('0a0d0d0a 0000001c 1a2b3c4d 0001 0000 ffffffffffffffff 0000001c')


def _epb_with_options(options: 'bytes', order: 'str' = 'little') -> 'bytes':
    """An EPB on interface 0 carrying ``abcd`` and ``options`` (``opt_endofopt`` appended)."""
    def u32(value: 'int') -> 'bytes':
        return value.to_bytes(4, order)  # type: ignore[arg-type]

    body = u32(0) + u32(0) + u32(0) + u32(4) + u32(4) + b'abcd' + options + bytes(4)
    length = len(body) + 12
    return u32(6) + u32(length) + body + u32(length)


class TestPCAPNGModelling(PCAPNGTestCase):
    """Pin how PCAP-NG blocks and options are modelled."""

    def _big_endian_context(self) -> 'Any':
        """A one-section big-endian context with one Ethernet interface."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.engines.pcapng import Context
        from pcapkit.protocols.misc.pcapng import PCAPNG

        context = Context(PCAPNG(SHB_BE, len(SHB_BE), num=0, sct=1, ctx=None).info)  # type: Any
        interface = PCAPNG(num=1, sct=1, ctx=context, type=BlockType.Interface_Description_Block,
                           block={'linktype': LinkType.ETHERNET, 'snaplen': 0x40000})
        context.interfaces.append(interface.info)
        return context

    def test_big_endian_section_header_rebuilds(self) -> None:
        """#1272: a big-endian SHB keeps its byte order, with or without a context."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        self.assertEqual(self._parse(SHB_BE).info.byteorder, 'big')
        self.assertRebuilds(SHB_BE)
        built = PCAPNG(num=0, sct=1, ctx=None, type=BlockType.Section_Header_Block,
                       block={'byteorder': 'big'})
        self.assertEqual(built.data, SHB_BE)

    def test_flags_are_numbered_from_the_least_significant_bit(self) -> None:
        """#1273: direction is bits 0-1 and the FCS length bits 5-8 of the word."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PCAPNG, PacketDirection

        context = self._context()
        for kwargs, word in (({'direction': PacketDirection.INBOUND}, '01000000'),
                             ({'fcs_len': 4}, '80000000')):
            with self.subTest(**kwargs):
                block = PCAPNG(num=2, sct=1, ctx=context, type=BlockType.Enhanced_Packet_Block,
                               block={'packet_data': b'abcd', 'timestamp': 0,
                                      'options': [(OptionType.epb_flags, kwargs)]})
                self.assertIn(H('0200 0400' + word), block.data)

        flags = self._parse(_epb_with_options(H('0200 0400 01000000'))).info.options[OptionType.epb_flags]
        self.assertEqual(flags.direction, PacketDirection.INBOUND)
        self.assertEqual(flags.fcs_len, 0)

        flags = self._parse(_epb_with_options(H('0200 0400 e5010000'))).info.options[OptionType.epb_flags]
        self.assertEqual((flags.direction, flags.reception, flags.fcs_len), (1, 1, 15))

    def test_flags_rebuild_in_either_byte_order(self) -> None:
        """#1273: every bit of the word survives, little- and big-endian."""
        octets = _epb_with_options(H('0200 0400 e5fdffff'))
        self.assertRebuilds(octets)
        octets = _epb_with_options(H('0002 0004 fffffde5'), order='big')
        self.assertRebuilds(octets, self._big_endian_context())

    def test_pack_flags_are_numbered_from_the_least_significant_bit(self) -> None:
        """#1273: ``pack_flags`` shares the numbering."""
        import warnings

        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PacketDirection

        octets = H('02000000 30000000 0000 0000 00000000 00000000 04000000 04000000 61626364'
                   '0200 0400 02000000 00000000 30000000')
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')  # the Packet Block is obsolete
            flags = self._parse(octets).info.options[OptionType.pack_flags]
            self.assertEqual(flags.direction, PacketDirection.OUTBOUND)
            self.assertRebuilds(octets)

    def test_undefined_direction_is_rejected(self) -> None:
        """#1273: direction ``0b11`` raises an in-library error."""
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaisesRegex(ProtocolError, r'invalid PacketDirection'):
            self._parse(_epb_with_options(H('0200 0400 03000000')))

    def test_nrb_names_decode_as_utf8(self) -> None:
        """#1277: record names are UTF-8, not a guessed charset."""
        octets = H('04000000 2c000000 01001800 0a000001 612e6578616d706c6500 622e6578616d706c6500'
                   '00000000 2c000000')
        records = self._parse(octets).info.records
        self.assertEqual(records[1].records, ('a.example', 'b.example'))
        self.assertRebuilds(octets)

    def test_non_utf8_nrb_name_rebuilds(self) -> None:
        """#1277: a name that is not UTF-8 keeps its octets through the split."""
        octets = H('04000000 24000000 01000e00 0a000001 ff2e6578616d706c6500 0000'
                   '00000000 24000000')
        self.assertRebuilds(octets)

    def test_ns_dnsname_decodes_as_utf8(self) -> None:
        """#1277: ``ns_dnsname`` is UTF-8, never a guessed charset.

        ``caf\\xe9`` is Latin-1, not UTF-8: a guessing decoder reads it as
        ``café``, a UTF-8 one as ``caf\\ufffd`` that still packs back exactly.
        """
        from pcapkit.const.pcapng.option_type import OptionType

        for name, text in ((b'caf\xe9.example', 'caf\ufffd.example'),
                           ('mañana.example'.encode('utf-8'), 'mañana.example')):
            with self.subTest(name=name):
                option = H('0200') + len(name).to_bytes(2, 'little') + name + bytes(-len(name) % 4)
                body = H('00000000') + option + H('00000000')
                size = (len(body) + 12).to_bytes(4, 'little')
                octets = H('04000000') + size + body + size
                self.assertEqual(self._parse(octets).info.options[OptionType.ns_dnsname].name, text)
                self.assertRebuilds(octets)

    def test_unknown_block_rebuilds(self) -> None:
        """#1278: Block Total Length counts the 12 framing octets."""
        self.assertRebuilds(H('77070000 14000000 0102030405060708 14000000'))

    def test_repeated_epb_verdict_rebuilds(self) -> None:
        """#1281: ``epb_verdict`` may appear more than once."""
        verdict = H('0700 0800 0001020304050607')
        self.assertRebuilds(_epb_with_options(verdict + verdict))

    def test_wireguard_error_names_the_line(self) -> None:
        """#1286: the error message carries the offending line."""
        from pcapkit.utilities.exceptions import FieldValueError

        body = b'a b c\n\x00\x00'
        octets = b''.join((
            (10).to_bytes(4, 'little'), (28).to_bytes(4, 'little'),
            (0x57474b4c).to_bytes(4, 'little'), (6).to_bytes(4, 'little'),
            body, (28).to_bytes(4, 'little'),
        ))
        with self.assertRaisesRegex(FieldValueError, r"format: 'a b c'"):
            self._parse(octets)


if __name__ == '__main__':
    unittest.main()
