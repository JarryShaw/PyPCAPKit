# -*- coding: utf-8 -*-
"""GitHub issue #1384: a Simple Packet Block longer than the snaplen keeps its excess.

An SPB holding 16 data octets under an interface snaplen of 8 parsed as 8
octets: the other 8 were dropped, the trailing Block Total Length was read from
the packet data, and the rebuild was 8 octets shorter. The parse now keeps every
octet the block holds past the snaplen and its padding, warns that the data
exceeds the snaplen, and rebuilds byte-exactly. A block sized for the snaplen
still reads ``min(original_len, snaplen)`` octets.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import struct
import unittest
import warnings

from tests.protocols.misc.test_pcapng_roundtrip2_unit import PCAPNGTestCase


def _spb(data: 'bytes', original_len: 'int | None' = None) -> 'bytes':
    """A Simple Packet Block carrying ``data``, zero-padded to 32 bits."""
    body = struct.pack('<I', len(data) if original_len is None else original_len)
    body += data + bytes((4 - len(data) % 4) % 4)
    length = len(body) + 12
    return struct.pack('<II', 3, length) + body + struct.pack('<I', length)


class TestPCAPNGSPBSnaplen(PCAPNGTestCase):
    """Pin how an SPB's data length relates to the snaplen."""

    def _parse_quiet(self, octets: 'bytes', snaplen: 'int') -> 'tuple[object, list[str]]':
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            parsed = self._parse(octets, self._context(snaplen=snaplen))
        return parsed, [str(item.message) for item in caught]

    def test_excess_past_the_snaplen_is_kept(self) -> None:
        for data, original_len in ((b'A' * 16, None), (b'A' * 16, 20), (b'A' * 12, 16)):
            with self.subTest(size=len(data), original_len=original_len):
                octets = _spb(data, original_len)
                parsed, messages = self._parse_quiet(octets, snaplen=8)
                self.assertEqual(parsed.info.captured_len, len(data))  # type: ignore[attr-defined]
                self.assertEqual(parsed.packet.payload, data)  # type: ignore[attr-defined]
                self.assertTrue(any('exceeds the snaplen of 8' in text for text in messages), messages)
                self.assertFalse(any('block length mismatch' in text for text in messages), messages)
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    self.assertRebuilds(octets, self._context(snaplen=8))

    def test_block_sized_for_the_snaplen_is_unchanged(self) -> None:
        for snaplen, data, original_len in ((8, b'A' * 8, 16), (6, b'A' * 6, 10), (0, b'A' * 16, None)):
            with self.subTest(snaplen=snaplen, original_len=original_len):
                octets = _spb(data, original_len)
                parsed, messages = self._parse_quiet(octets, snaplen=snaplen)
                self.assertEqual(parsed.info.captured_len, len(data))  # type: ignore[attr-defined]
                self.assertFalse(any('exceeds the snaplen' in text for text in messages), messages)
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    self.assertRebuilds(octets, self._context(snaplen=snaplen))

    def test_make_still_clips_to_the_snaplen(self) -> None:
        """``make`` -> parse -> pack: a fresh block holds the snaplen's worth."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        context = self._context(snaplen=8)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            block = PCAPNG(num=2, sct=1, ctx=context, type=BlockType.Simple_Packet_Block,
                           block={'packet_data': b'A' * 16})
            self.assertEqual(len(block.data), 24)
            self.assertRebuilds(block.data, context)


if __name__ == '__main__':
    unittest.main()
