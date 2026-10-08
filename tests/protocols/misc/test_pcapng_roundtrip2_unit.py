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
        """#1284: Option Length 3 cannot hold the 4-octet PEN."""
        from pcapkit.utilities.exceptions import ProtocolError

        octets = H('0a0d0d0a 24000000 4d3c2b1a 0100 0000 ffffffffffffffff'
                   'ad0b0300 61626300 24000000')
        with self.assertRaisesRegex(ProtocolError, r'opt_custom\] invalid length'):
            self._parse(octets)


if __name__ == '__main__':
    unittest.main()
