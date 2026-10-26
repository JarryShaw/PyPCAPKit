# -*- coding: utf-8 -*-
"""The DPKT engine keeps a frame dpkt cannot parse, rather than aborting.

GitHub issue #1351: dpkt 1.9.8 reads ``frag_off`` from whatever header follows
an IPv6 Fragment header, so a Fragment header followed by ESP or Destination
Options raises :exc:`AttributeError` from ``dpkt/ip6.py``. Guards against the
engine letting that third-party exception end the whole extraction.

Every case writes its own capture to a temporary directory. Everything
from :mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load.

"""

import importlib.util
import os
import struct
import tempfile
import unittest
import warnings

from tests._support import close_extractor, reimport_once_per_class

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

    def test_unparsable_frame_is_written_out(self) -> None:
        # The engine writes every frame through packet2dict. Without the fix,
        # packet2dict reads the header fields a frame kept raw does not have, so
        # AttributeError ends the extraction there (#1662). Such a frame maps to
        # no fields, then the next frame is read.
        import pcapkit
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.dpkt import packet2dict

        frame = bytes(12) + b'\x86\xdd' + IPV6 + PAYLOADS[60]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'frag-60.pcap')
            _write_pcap(path, frame)
            with open(path, 'ab') as file:
                file.write(struct.pack('<IIII', 2, 0, len(frame), len(frame)) + frame)
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                ext = pcapkit.extract(fin=path, fout=os.path.join(tmp, 'out'), format='json',
                                      engine='dpkt', store=True)
            try:
                self.assertEqual(ext.length, 2)
                self.assertEqual(packet2dict(ext.frame[0], 1.0, data_link=LinkType.ETHERNET),
                                 {'timestamp': 1.0, 'packet': frame, 'ETHERNET': {}})
            finally:
                close_extractor(ext)


if __name__ == '__main__':
    unittest.main()
