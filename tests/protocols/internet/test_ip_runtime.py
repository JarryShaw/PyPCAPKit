from __future__ import annotations

import importlib.util
import unittest

from tests._support import close_extractor, purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class InternetProtocolRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _extract(self, sample: str):
        from pcapkit.interface import extract

        extractor = extract(fin=sample, fout='/tmp/out', format='tree', store=True, nofile=True)
        self.addCleanup(close_extractor, extractor)
        return extractor

    def test_ipv4_packet_exposes_addresses_ttl_and_udp_payload(self) -> None:
        extractor = self._extract('sample/ipv4.pcap')
        frame = extractor.frame[0]
        ipv4 = frame.payload.payload
        udp = ipv4.payload

        self.assertEqual(str(frame.protochain), 'Ethernet:IPv4:UDP:Raw')
        self.assertEqual(ipv4.name, 'Internet Protocol version 4')
        self.assertEqual(str(ipv4.src), '172.31.127.230')
        self.assertEqual(str(ipv4.dst), '239.1.3.3')
        self.assertEqual(ipv4.info.ttl.total_seconds(), 1)
        self.assertEqual(ipv4.info.protocol.name, 'UDP')
        self.assertEqual(udp.name, 'User Datagram Protocol')
        self.assertEqual(int(udp.info.dstport), 12345)
        self.assertEqual(type(udp.payload).__name__, 'Raw')

    def test_ipv6_icmp_payload_falls_back_to_raw_with_protocol_hint(self) -> None:
        extractor = self._extract('sample/ipv6.pcap')
        frame = extractor.frame[2]
        ipv6 = frame.payload.payload
        raw = ipv6.payload

        self.assertEqual(str(frame.protochain), 'Ethernet:IPv6:IPv6_ICMP')
        self.assertEqual(ipv6.name, 'Internet Protocol version 6')
        self.assertEqual(str(ipv6.src), 'fe80::a423:b61d:7c92:70c6')
        self.assertEqual(str(ipv6.dst), 'fe80::821f:12ff:fec9:d13d')
        self.assertEqual(ipv6.info.limit, 255)
        self.assertEqual(ipv6.info.next.name, 'IPv6_ICMP')
        self.assertEqual(type(raw).__name__, 'Raw')
        self.assertEqual(raw.info.protocol.name, 'IPv6_ICMP')

    def test_ipv6_udp_packet_exposes_multicast_and_reply_addresses(self) -> None:
        extractor = self._extract('sample/stream.pcap')
        frame = extractor.frame[1]
        ipv6 = frame.payload.payload
        udp = ipv6.payload

        self.assertEqual(str(frame.protochain), 'Ethernet:IPv6:UDP:Raw')
        self.assertEqual(str(ipv6.dst), 'ff02::fb')
        self.assertEqual(ipv6.info.limit, 255)
        self.assertEqual(int(udp.info.srcport), 5353)
        self.assertEqual(int(udp.info.dstport), 5353)
        self.assertEqual(type(udp.payload).__name__, 'Raw')

    def test_sample_in_tcp_frames_expose_fin_ack_and_null_payload(self) -> None:
        extractor = self._extract('sample/in.pcap')

        server_fin = extractor.frame[2].payload.payload.payload
        client_ack = extractor.frame[3].payload.payload.payload
        client_fin = extractor.frame[4].payload.payload.payload

        self.assertEqual(int(server_fin.info.srcport), 80)
        self.assertEqual(int(server_fin.info.dstport), 55232)
        self.assertTrue(server_fin.info.flags.fin)
        self.assertTrue(server_fin.info.flags.ack)
        self.assertEqual(type(server_fin.payload).__name__, 'NoPayload')

        self.assertEqual(int(client_ack.info.srcport), 55232)
        self.assertEqual(int(client_ack.info.dstport), 80)
        self.assertFalse(client_ack.info.flags.fin)
        self.assertTrue(client_ack.info.flags.ack)
        self.assertEqual(type(client_ack.payload).__name__, 'NoPayload')

        self.assertEqual(int(client_fin.info.srcport), 55216)
        self.assertEqual(int(client_fin.info.dstport), 80)
        self.assertTrue(client_fin.info.flags.fin)
        self.assertTrue(client_fin.info.flags.ack)
        self.assertEqual(type(client_fin.payload).__name__, 'NoPayload')

    def test_sample_in_udp_frame_exposes_broadcast_destination_and_raw_payload(self) -> None:
        extractor = self._extract('sample/in.pcap')
        frame = extractor.frame[5]
        ipv4 = frame.payload.payload
        udp = ipv4.payload

        self.assertEqual(str(frame.protochain), 'Ethernet:IPv4:UDP:Raw')
        self.assertEqual(str(ipv4.src), '192.168.1.1')
        self.assertEqual(str(ipv4.dst), '255.255.255.255')
        self.assertEqual(int(udp.info.srcport), 37444)
        self.assertEqual(int(udp.info.dstport), 5001)
        self.assertEqual(udp.info.len, 125)
        self.assertEqual(udp.info.checksum.hex(), '63b1')
        self.assertEqual(type(udp.payload).__name__, 'Raw')


if __name__ == '__main__':
    unittest.main()
