# -*- coding: utf-8 -*-
"""A PCAP-NG option area holding a malformed option is kept as captured.

GitHub issue #1325: an option or record whose declared length runs past its
area used to be clamped to the octets the area had left, so the block parsed
but rebuilt a different length or padding than it was read with. Now the whole
area is kept as the octets captured: the block's ``options`` (or ``records``)
are empty, ``options_raw`` (or ``records_raw``) holds the area, the block
rebuilds byte for byte, and a capture holding such a block still extracts.

Every case builds its own octets in memory. :mod:`pcapkit` is imported inside
each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import os
import struct
import tempfile
import unittest
import warnings

from tests.protocols.misc.test_pcapng_roundtrip2_unit import PCAPNGTestCase


def _block(type_: int, body: bytes) -> bytes:
    """A little-endian block of ``type_`` around ``body``."""
    length = len(body) + 12
    return struct.pack('<II', type_, length) + body + struct.pack('<I', length)


def _shb(options: bytes) -> bytes:
    return (b'\x0a\x0d\x0d\x0a' + struct.pack('<I', 28 + len(options))
            + bytes.fromhex('4d3c2b1a 0100 0000') + b'\xff' * 8
            + options + struct.pack('<I', 28 + len(options)))


def _idb(options: bytes) -> bytes:
    return _block(1, struct.pack('<HHI', 1, 0, 0x40000) + options)


def _epb(options: bytes) -> bytes:
    return _block(6, struct.pack('<IIIII', 0, 0, 0, 4, 4) + b'abcd' + options)


def _isb(options: bytes) -> bytes:
    return _block(5, struct.pack('<III', 0, 0, 0) + options)


def _nrb(records: bytes) -> bytes:
    return _block(4, records)


#: An option declaring 65,535 octets with none present, and one declaring 5
#: with 4 present (#594's vector, and the smallest over-declaration).
OVER_ALL = bytes.fromhex('fa00ffff')
OVER_ONE = bytes.fromhex('fa000500 aabbccdd')

#: (block octets, name of the area kept, the area's octets)
CASES = {
    'SHB 65535': (_shb(OVER_ALL), 'options', OVER_ALL),
    # #1284: Option Length 3 cannot hold the custom option's 4-octet PEN
    'SHB custom shorter than PEN': (_shb(bytes.fromhex('ad0b0300 61626300')), 'options',
                                    bytes.fromhex('ad0b0300 61626300')),
    'IDB 65535': (_idb(OVER_ALL), 'options', OVER_ALL),
    'EPB 65535': (_epb(OVER_ALL), 'options', OVER_ALL),
    'EPB over by one': (_epb(OVER_ONE), 'options', OVER_ONE),
    # a complete option, then one declaring 8 octets with none left
    'EPB tail option': (_epb(bytes.fromhex('fa000200 aabb0000 fa000800')), 'options',
                        bytes.fromhex('fa000200 aabb0000 fa000800')),
    'ISB 65535': (_isb(OVER_ALL), 'options', OVER_ALL),
    # an IPv4 record declaring 65,535 octets with none present
    'NRB record': (_nrb(bytes.fromhex('0100ffff')), 'records', bytes.fromhex('0100ffff')),
}


class TestPCAPNGOptionAreaKept(PCAPNGTestCase):
    """Pin that a malformed option area is kept, not clamped (#1325)."""

    def test_the_area_is_kept_as_captured(self) -> None:
        for case, (octets, name, area) in CASES.items():
            with self.subTest(case=case):
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    parsed = self._parse(octets)
                block = parsed.info
                self.assertEqual(getattr(block, f'{name}_raw'), area)
                self.assertEqual(len(getattr(block, name)), 0)

    def test_the_block_rebuilds_byte_for_byte(self) -> None:
        for case, (octets, _, _) in CASES.items():
            with self.subTest(case=case):
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    self.assertRebuilds(octets)

    def test_keeping_the_area_is_reported(self) -> None:
        from pcapkit.utilities.warnings import ProtocolWarning

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            self._parse(CASES['EPB 65535'][0])
        self.assertTrue(any(issubclass(item.category, ProtocolWarning)
                            and 'kept as captured' in str(item.message) for item in caught))

    def test_an_option_schema_alone_refuses_the_overrun(self) -> None:
        from pcapkit.protocols.schema.misc.pcapng import UnknownOption
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaisesRegex(ProtocolError, 'left in its area'):
            UnknownOption.unpack(OVER_ALL, len(OVER_ALL), {'byteorder': 'little'})

    def test_a_capture_holding_the_block_still_extracts(self) -> None:
        from pcapkit.foundation.extraction import Extractor

        capture = _shb(b'') + _idb(b'') + _epb(OVER_ALL) + _epb(b'')
        with tempfile.TemporaryDirectory(prefix='w1325-') as tmp:
            path = os.path.join(tmp, 'kept.pcapng')
            with open(path, 'wb') as file:
                file.write(capture)
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                extractor = Extractor(fin=path, nofile=True, store=True)
        self.assertEqual(len(extractor.frame), 2)
        self.assertEqual(extractor.frame[0].info.options_raw, OVER_ALL)


if __name__ == '__main__':
    unittest.main()
