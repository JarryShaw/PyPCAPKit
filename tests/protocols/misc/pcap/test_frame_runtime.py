from __future__ import annotations

import importlib.util
import unittest

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PcapFrameRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_frame_exposes_expected_public_metadata(self) -> None:
        from pcapkit.interface import extract

        extractor = extract(fin='sample/in.pcap', fout='/tmp/out', format='tree', store=True, nofile=True)
        frame = extractor.frame[0]

        self.assertEqual(frame.name, 'Frame 1')
        self.assertEqual(str(frame.protochain), 'Ethernet:IPv6:IPv6_ICMP')
        self.assertEqual(frame.protochain.aliases, ('Ethernet', 'IPv6', 'IPv6_ICMP'))
        self.assertEqual(frame.index('IPv6'), 1)
        self.assertEqual(frame.info.number, 1)
        self.assertEqual(frame.info.cap_len, frame.info.len)

    def test_frame_packet_and_payload_walk_protocol_stack(self) -> None:
        from pcapkit.interface import extract

        extractor = extract(fin='sample/arp.pcap', fout='/tmp/out', format='tree', store=True, nofile=True)
        frame = extractor.frame[0]

        self.assertEqual(type(frame.packet).__name__, 'Packet')
        self.assertEqual(type(frame.payload).__name__, 'Ethernet')
        self.assertEqual(type(frame.payload.payload).__name__, 'ARP')
        self.assertEqual(type(frame.payload.payload.payload).__name__, 'Raw')

    def test_frame_info_records_protocol_summary(self) -> None:
        from pcapkit.interface import extract

        extractor = extract(fin='sample/arp.pcap', fout='/tmp/out', format='tree', store=True, nofile=True)
        frame = extractor.frame[0]

        self.assertEqual(frame.info.protocols, 'Ethernet:ARP:Raw')
        self.assertIsNotNone(frame.info.ethernet)
        self.assertEqual(frame.payload.name, 'Ethernet Protocol')
        self.assertEqual(frame.payload.payload.name, 'Address Resolution Protocol')
        self.assertEqual(frame.payload.payload.payload.name, 'Unknown')


if __name__ == '__main__':
    unittest.main()
