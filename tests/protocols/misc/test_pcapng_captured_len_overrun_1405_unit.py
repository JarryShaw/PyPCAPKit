# -*- coding: utf-8 -*-
"""GitHub issue #1405: a captured length running past the block rebuilds byte-exactly.

An Enhanced Packet Block whose ``captured_len`` runs past the block read that
many octets as packet data: the trailing Block Total Length and whatever
followed went with them, so a 36-octet block rebuilt as 40 or 41. The packet
data is now bounded by the block, the padding and option area are sized from
the octets read, and the declared ``captured_len`` is kept, so the block rebuilds
as captured. The obsolete Packet Block has the same shape and the same fix.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import struct
import unittest
import warnings

from tests.protocols.misc.test_pcapng_roundtrip2_unit import PCAPNGTestCase


def _epb(captured_len: 'int', data: 'bytes', options: 'bytes' = b'') -> 'bytes':
    """An Enhanced Packet Block on interface 0 declaring ``captured_len`` over ``data``."""
    body = struct.pack('<IIIII', 0, 0, 0, captured_len, captured_len) + data + options
    length = len(body) + 12
    return struct.pack('<II', 6, length) + body + struct.pack('<I', length)


def _pb(captured_len: 'int', data: 'bytes') -> 'bytes':
    """An obsolete Packet Block on interface 0 declaring ``captured_len`` over ``data``."""
    body = struct.pack('<HHIIII', 0, 0, 0, 0, captured_len, captured_len) + data
    length = len(body) + 12
    return struct.pack('<II', 2, length) + body + struct.pack('<I', length)


class TestPCAPNGCapturedLenOverrun(PCAPNGTestCase):
    """Pin how a captured length past the block parses and rebuilds."""

    def _parse_noisy(self, octets: 'bytes') -> 'tuple[object, list[str]]':
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            parsed = self._parse(octets)
        return parsed, [str(item.message) for item in caught]

    def test_epb_overrun_rebuilds(self) -> None:
        for captured_len in (5, 6, 8, 100, 0xFFFFFF):
            with self.subTest(captured_len=captured_len):
                octets = _epb(captured_len, b'abcd')
                self.assertEqual(len(octets), 36)
                parsed, messages = self._parse_noisy(octets)
                self.assertEqual(parsed.info.captured_len, captured_len)  # type: ignore[attr-defined]
                self.assertEqual(parsed.packet.payload, b'abcd')  # type: ignore[attr-defined]
                self.assertTrue(any('runs past the block' in text for text in messages), messages)
                self.assertFalse(any('block length mismatch' in text for text in messages), messages)
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    self.assertRebuilds(octets)

    def test_overrun_reads_option_octets_as_data(self) -> None:
        """The octets after the declared data are the block's, so they stay in it."""
        octets = _epb(100, b'abcd', b'\x01\x00\x03\x00abc\x00')
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = self._parse(octets)
            self.assertEqual(parsed.packet.payload, b'abcd\x01\x00\x03\x00abc\x00')
            self.assertRebuilds(octets)

    def test_pb_overrun_rebuilds(self) -> None:
        for captured_len in (5, 100):
            with self.subTest(captured_len=captured_len):
                octets = _pb(captured_len, b'abcd')
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')  # the Packet Block is obsolete
                    self.assertEqual(self._parse(octets).info.captured_len, captured_len)
                    self.assertRebuilds(octets)

    def test_well_formed_blocks_are_unchanged(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType

        for captured_len, data in ((4, b'abcd'), (5, b'abcde\x00\x00\x00'), (0, b'')):
            with self.subTest(captured_len=captured_len):
                octets = _epb(captured_len, data, b'\x01\x00\x03\x00abc\x00\x00\x00\x00\x00')
                parsed, messages = self._parse_noisy(octets)
                self.assertEqual(parsed.packet.payload, data[:captured_len])  # type: ignore[attr-defined]
                self.assertEqual(parsed.info.options[OptionType.opt_comment].comment, 'abc')  # type: ignore[attr-defined]
                self.assertFalse(any('runs past the block' in text for text in messages), messages)
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    self.assertRebuilds(octets)


if __name__ == '__main__':
    unittest.main()
