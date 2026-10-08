# -*- coding: utf-8 -*-
"""GitHub issue #1383: NRB record names round-trip byte-exactly.

The parse stripped every trailing NUL before splitting the name resolution
data, so ``a\\0\\0`` came back as one name and rebuilt as ``a\\0``. Names are now
split one per terminator, so an empty name is kept as ``''``. Data that is
empty or not zero-terminated cannot be expressed as a list of names; it is
malformed, and the record area is kept as the octets captured (#1325).

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import struct
import unittest
import warnings

from tests.protocols.misc.test_pcapng_roundtrip2_unit import PCAPNGTestCase


def _nrb(names: 'bytes', ipv6: 'bool' = False) -> 'bytes':
    """A Name Resolution Block holding one IPv4 (or IPv6) record with ``names`` as its data."""
    address = bytes(range(16)) if ipv6 else bytes([10, 0, 0, 1])
    record = struct.pack('<HH', 2 if ipv6 else 1, len(address) + len(names)) + address + names
    record += bytes((4 - len(record) % 4) % 4)
    body = record + struct.pack('<HH', 0, 0)
    length = len(body) + 12
    return struct.pack('<II', 4, length) + body + struct.pack('<I', length)


class TestPCAPNGNRBEmptyNames(PCAPNGTestCase):
    """Pin how NRB record names parse and rebuild."""

    def test_empty_names_are_kept(self) -> None:
        for ipv6 in (False, True):
            for data, names in ((b'a\x00\x00', ('a', '')),
                                (b'a\x00\x00\x00', ('a', '', '')),
                                (b'\x00\x00', ('', '')),
                                (b'a\x00\x00b\x00', ('a', '', 'b')),
                                (b'a\x00b\x00', ('a', 'b')),
                                (b'\x00', ('',))):
                with self.subTest(data=data, ipv6=ipv6):
                    octets = _nrb(data, ipv6)
                    records = self._parse(octets).info.records
                    self.assertEqual(records[2 if ipv6 else 1].records, names)
                    self.assertRebuilds(octets)

    def test_unterminated_data_is_kept_as_captured(self) -> None:
        from pcapkit.utilities.warnings import ProtocolWarning

        for ipv6 in (False, True):
            for data in (b'a', b'a\x00b', b''):
                with self.subTest(data=data, ipv6=ipv6):
                    octets = _nrb(data, ipv6)
                    with warnings.catch_warnings(record=True) as caught:
                        warnings.simplefilter('always')
                        info = self._parse(octets).info
                    self.assertTrue(any(issubclass(item.category, ProtocolWarning) for item in caught))
                    self.assertEqual(len(info.records), 0)
                    self.assertEqual(info.records_raw, octets[8:-4])  # the whole record area
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        self.assertRebuilds(octets)

    def test_make_writes_empty_names(self) -> None:
        """``make`` -> parse -> pack keeps a trailing empty name."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.record_type import RecordType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        context = self._context()
        block = PCAPNG(num=2, sct=1, ctx=context, type=BlockType.Name_Resolution_Block,
                       block={'records': [(RecordType.nrb_record_ipv4,
                                           {'ip': '10.0.0.1', 'names': ['a', '']})]})
        self.assertIn(b'\x0a\x00\x00\x01a\x00\x00', block.data)
        self.assertEqual(self._parse(block.data, context).info.records[RecordType.nrb_record_ipv4].records, ('a', ''))
        self.assertRebuilds(block.data, context)


if __name__ == '__main__':
    unittest.main()
