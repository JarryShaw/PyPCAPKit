from __future__ import annotations

import importlib.util
import unittest

from tests._support import close_extractor, purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class LinkProtocolRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _extract(self, sample: str):
        from pcapkit.interface import extract

        extractor = extract(fin=sample, fout='/tmp/out', format='tree', store=True, nofile=True)
        self.addCleanup(close_extractor, extractor)
        return extractor

    def test_ethernet_protocol_exposes_addresses_and_next_layer(self) -> None:
        extractor = self._extract('sample/arp.pcap')
        ethernet = extractor.frame[0].payload

        self.assertEqual(type(ethernet).__name__, 'Ethernet')
        self.assertEqual(ethernet.name, 'Ethernet Protocol')
        self.assertTrue(hasattr(ethernet.info, 'src'))
        self.assertTrue(hasattr(ethernet.info, 'dst'))
        self.assertEqual(type(ethernet.payload).__name__, 'ARP')

    def test_arp_protocol_exposes_request_fields_and_nested_raw_payload(self) -> None:
        extractor = self._extract('sample/arp.pcap')
        arp = extractor.frame[0].payload.payload

        self.assertEqual(type(arp).__name__, 'ARP')
        self.assertEqual(arp.name, 'Address Resolution Protocol')
        self.assertEqual(int(arp.info.oper), 1)
        self.assertEqual(arp.info.sha, '00:0c:29:19:dc:61')
        self.assertEqual(arp.info.tha, '00:0c:29:7d:1d:b4')
        self.assertEqual(str(arp.info.spa), '10.20.30.131')
        self.assertEqual(str(arp.info.tpa), '10.20.30.130')
        self.assertEqual(type(arp.payload).__name__, 'Raw')

    def test_arp_reply_frame_exposes_reverse_addresses(self) -> None:
        extractor = self._extract('sample/arp.pcap')
        arp = extractor.frame[1].payload.payload

        self.assertEqual(int(arp.info.oper), 2)
        self.assertEqual(arp.info.sha, '00:0c:29:7d:1d:b4')
        self.assertEqual(arp.info.tha, '00:0c:29:19:dc:61')
        self.assertEqual(str(arp.info.spa), '10.20.30.130')
        self.assertEqual(str(arp.info.tpa), '10.20.30.131')

    def test_ipv6_chain_from_sample_includes_expected_protocol_names(self) -> None:
        extractor = self._extract('sample/in.pcap')
        ethernet = extractor.frame[0].payload
        ipv6 = ethernet.payload
        raw = ipv6.payload

        self.assertEqual(ethernet.name, 'Ethernet Protocol')
        self.assertEqual(ipv6.name, 'Internet Protocol version 6')
        self.assertEqual(str(ipv6.src), 'fe80::a6:87f9:2793:16ee')
        self.assertEqual(str(ipv6.dst), 'fe80::1ccd:7c77:bac7:46b7')
        self.assertEqual(ipv6.info.limit, 255)
        self.assertEqual(type(raw).__name__, 'Raw')
        self.assertEqual(raw.info.protocol.name, 'IPv6_ICMP')
        self.assertIn('IPv6', str(ipv6.protochain))
        self.assertEqual(ipv6.protochain.aliases[0], 'IPv6')


if __name__ == '__main__':
    unittest.main()
