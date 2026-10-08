# -*- coding: utf-8 -*-
"""The DPKT engine keeps a frame dpkt cannot parse, rather than aborting.

GitHub issue #1351: dpkt 1.9.8 reads ``frag_off`` from whatever header follows
an IPv6 Fragment header, so a Fragment header followed by ESP or Destination
Options raises :exc:`AttributeError` from ``dpkt/ip6.py``. The engine did not
catch it, so the third-party exception ended the whole extraction.

Every case writes its own one-frame capture to a temporary directory. Everything
from :mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load.

"""

import importlib.util
import os
import struct
import tempfile
import unittest
import warnings

from tests._support import reimport_once_per_class

HAS_DPKT = importlib.util.find_spec('dpkt') is not None

#: IPv6 header with Next Header 44 (Fragment) and a 16-octet payload.
IPV6 = (bytes.fromhex('60000000') + (16).to_bytes(2, 'big') + bytes([44, 64])
        + bytes(15) + b'\x01' + bytes(15) + b'\x02')
#: Fragment header (offset 0, M=0) followed by eight octets, per next header.
PAYLOADS = {
    50: bytes([50, 0, 0, 0, 0, 0, 0, 1]) + bytes(8),
    60: bytes([60, 0, 0, 0, 0, 0, 0, 1]) + bytes.fromhex('3b00010400000000'),
}


def _write_pcap(path: str, frame: bytes) -> None:
    """Write a little-endian Ethernet PCAP holding one frame."""
    with open(path, 'wb') as file:
        file.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        file.write(struct.pack('<IIII', 1, 0, len(frame), len(frame)) + frame)


@unittest.skipUnless(HAS_DPKT, 'dpkt is not installed')
class TestDPKTParseError(unittest.TestCase):
    """Pin how the DPKT engine handles a frame dpkt fails to parse."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_unparsable_frame_is_kept_as_raw_data(self) -> None:
        import pcapkit
        from pcapkit.utilities.warnings import DPKTWarning

        for nxt, payload in PAYLOADS.items():
            frame = bytes(12) + b'\x86\xdd' + IPV6 + payload
            with self.subTest(next_header=nxt), tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, f'frag-{nxt}.pcap')
                _write_pcap(path, frame)

                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    ext = pcapkit.extract(fin=path, engine='dpkt', nofile=True,
                                          store=True, ip=True, ipv6=True)

                self.assertEqual(ext.length, 1)
                self.assertEqual(bytes(ext.frame[0]), frame)
                self.assertTrue(any(issubclass(item.category, DPKTWarning)
                                    and 'cannot parse' in str(item.message) for item in caught))


if __name__ == '__main__':
    unittest.main()
