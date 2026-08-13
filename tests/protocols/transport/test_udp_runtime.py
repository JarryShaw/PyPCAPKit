from __future__ import annotations

import importlib.util
import unittest

from tests._support import close_extractor, purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class UDPRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _extract(self, sample: str, *, store: bool = True, auto: bool = True):
        from pcapkit.interface import extract

        extractor = extract(fin=sample, fout='/tmp/out', format='tree', store=store, nofile=True, auto=auto)
        self.addCleanup(close_extractor, extractor)
        return extractor

    def test_ipv4_udp_frame_exposes_length_checksum_and_raw_payload(self) -> None:
        extractor = self._extract('sample/ipv4.pcap', store=False, auto=False)
        frame = next(extractor)
        udp = frame.payload.payload.payload

        self.assertEqual(str(frame.protochain), 'Ethernet:IPv4:UDP:Raw')
        self.assertEqual(udp.name, 'User Datagram Protocol')
        self.assertEqual(int(udp.info.srcport), 42054)
        self.assertEqual(int(udp.info.dstport), 12345)
        self.assertEqual(udp.info.len, 1836)
        self.assertEqual(udp.info.checksum.hex(), 'ff0b')
        self.assertEqual(type(udp.payload).__name__, 'Raw')

    def test_ipv6_udp_mdns_frame_exposes_multicast_ports_and_checksum(self) -> None:
        extractor = self._extract('sample/stream.pcap')
        frame = extractor.frame[1]
        udp = frame.payload.payload.payload

        self.assertEqual(str(frame.protochain), 'Ethernet:IPv6:UDP:Raw')
        self.assertEqual(udp.name, 'User Datagram Protocol')
        self.assertEqual(int(udp.info.srcport), 5353)
        self.assertEqual(int(udp.info.dstport), 5353)
        self.assertEqual(udp.info.len, 145)
        self.assertEqual(udp.info.checksum.hex(), '9cb1')
        self.assertEqual(type(udp.payload).__name__, 'Raw')


if __name__ == '__main__':
    unittest.main()
