# -*- coding: utf-8 -*-
"""GitHub issues #1413 and #1414: malformed PCAP-NG blocks rebuild byte-exactly.

* #1413 -- a Journal Export binary field filling its entry with no closing
  newline gained one on rebuild (28 octets in, 32 out), and a bare ``KEY`` with
  no ``=`` and no newline was dropped (16 in, 12 out). Under the #1406 ruling the
  whole entry is now kept as captured, as ``entry_raw``.
* #1414 -- a Simple Packet Block holding more data than its ``original_len``
  lost the excess (24 in, 20 out), and an Enhanced Packet Block or Packet Block
  below its 32-octet minimum rebuilt at 32. Both now keep the octets captured.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import struct
import unittest
import warnings
from decimal import Decimal

from tests.protocols.misc.test_pcapng_roundtrip2_unit import PCAPNGTestCase


def _block(type_: 'int', body: 'bytes') -> 'bytes':
    """A little-endian block of ``type_`` around ``body``."""
    length = len(body) + 12
    return struct.pack('<II', type_, length) + body + struct.pack('<I', length)


def _journal(entry: 'bytes') -> 'bytes':
    """A systemd Journal Export Block holding ``entry``, zero-padded to 32 bits."""
    return _block(9, entry + bytes(-len(entry) % 4))


class TestPCAPNGKeptAsCaptured(PCAPNGTestCase):
    """Pin that malformed journal entries and packet blocks rebuild as captured."""

    def _parse_warned(self, octets: 'bytes') -> 'tuple[object, list[str]]':
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            parsed = self._parse(octets)
        return parsed, [str(item.message) for item in caught]

    def test_malformed_journal_entries_are_kept_and_rebuild(self) -> None:
        """#1413: the issue's two shapes, plus a bare key after a good field."""
        for entry, reason, size in ((b'BIN\n' + struct.pack('<Q', 4) + b'abc\n', 'is not followed by', 28),
                                    (b'KEY', 'has no terminating newline', 16),
                                    (b'A=1\nKEY', 'has no terminating newline', 20)):
            with self.subTest(entry=entry):
                octets = _journal(entry)
                self.assertEqual(len(octets), size)
                parsed, messages = self._parse_warned(octets)
                self.assertTrue(any(reason in text and 'kept as captured' in text for text in messages), messages)
                self.assertEqual(parsed.info.data, ())  # type: ignore[attr-defined]
                self.assertEqual(parsed.info.entry_raw, octets[8:-4])  # type: ignore[attr-defined]
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    self.assertRebuilds(octets)

    def test_spb_data_past_original_len_is_kept(self) -> None:
        """#1414: ``original_len=3`` with 8 data octets keeps all 8."""
        octets = _block(3, struct.pack('<I', 3) + b'abcdefgh')
        self.assertEqual(len(octets), 24)
        parsed, messages = self._parse_warned(octets)
        self.assertEqual(parsed.info.captured_len, 8)  # type: ignore[attr-defined]
        self.assertEqual(parsed.packet.payload, b'abcdefgh')  # type: ignore[attr-defined]
        self.assertTrue(any('exceeds the original length of 3' in text for text in messages), messages)
        self.assertFalse(any('block length mismatch' in text for text in messages), messages)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            self.assertRebuilds(octets)

    def test_spb_padding_past_original_len_is_not_data(self) -> None:
        """An SPB of ``original_len=3`` with one pad octet still reads 3 octets."""
        octets = _block(3, struct.pack('<I', 3) + b'abc\x00')
        parsed, messages = self._parse_warned(octets)
        self.assertEqual(parsed.info.captured_len, 3)  # type: ignore[attr-defined]
        self.assertFalse(any('exceeds' in text for text in messages), messages)
        self.assertRebuilds(octets)

    def test_short_epb_and_pb_are_kept(self) -> None:
        """#1414: every Block Total Length below 32 rebuilds at its own length."""
        from pcapkit.const.pcapng.block_type import BlockType

        for type_ in (BlockType.Enhanced_Packet_Block, BlockType.Packet_Block):
            for length in range(12, 32, 4):
                with self.subTest(type=type_, length=length):
                    octets = _block(int(type_), bytes(length - 12))
                    parsed, messages = self._parse_warned(octets)
                    self.assertTrue(any(f'block length {length} is below the 32-octet minimum' in text
                                        for text in messages), messages)
                    self.assertFalse(any('block length mismatch' in text for text in messages), messages)
                    self.assertEqual(parsed.info.block_raw, octets[8:-4])  # type: ignore[attr-defined]
                    self.assertEqual(parsed.info.captured_len, 0)  # type: ignore[attr-defined]
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        self.assertRebuilds(octets)

    def test_short_epb_keeps_the_fields_it_holds(self) -> None:
        """A 28-octet EPB holds its interface ID, timestamp and captured length."""
        octets = _block(6, struct.pack('<IIII', 0, 1, 2, 5))
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            info = self._parse(octets).info
        self.assertEqual((info.interface_id, info.captured_len, info.original_len), (0, 5, 0))
        # microseconds, the default resolution
        self.assertEqual(info.timestamp_epoch, Decimal('4294.967298'))

    def test_extraction_continues_past_a_short_epb(self) -> None:
        """The block after a short EPB is read where it sits, and the EPB rebuilds."""
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from tests.protocols.misc.test_pcapng_unit import NamedBuffer

        shb = struct.pack('<IIIHHqI', 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
        idb = struct.pack('<IIHHII', 0x00000001, 20, 1, 0, 0, 20)
        short = _block(6, bytes(16))
        good = _block(6, struct.pack('<IIIII', 0, 0, 0, 4, 4) + b'abcd')
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = Extractor(NamedBuffer(shb + idb + short + good), nofile=True, store=True)
            frames = extractor.frame
            self.assertEqual(len(frames), 2)
            self.assertEqual(frames[1].info.captured_len, 4)
            context = extractor.engine._ctx_list[0]
            rebuilt = PCAPNG.from_data(frames[0].info, num=2, sct=1, ctx=context).data
        self.assertEqual(rebuilt, short)


if __name__ == '__main__':
    unittest.main()
