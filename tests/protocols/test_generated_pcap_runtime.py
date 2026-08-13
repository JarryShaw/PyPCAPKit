from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

from tests._support import close_extractor, purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)
HAS_SCAPY = importlib.util.find_spec('scapy') is not None


@unittest.skipUnless(HAS_RUNTIME and HAS_SCAPY, 'runtime or scapy dependencies not installed')
class GeneratedPcapRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_scapy_generated_pcap_decodes_ipv4_udp_and_ipv6_tcp(self) -> None:
        from scapy.all import Ether, IP, IPv6, Raw, TCP, UDP, wrpcap

        from pcapkit.interface import extract

        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_file = Path(tmpdir) / 'generated-protocols.pcap'
            wrpcap(str(pcap_file), [
                Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02')
                / IP(src='192.0.2.1', dst='198.51.100.2')
                / UDP(sport=12345, dport=54321)
                / Raw(b'udp-body'),
                Ether(src='02:00:00:00:00:03', dst='02:00:00:00:00:04')
                / IPv6(src='2001:db8::1', dst='2001:db8::2')
                / TCP(sport=443, dport=50000, flags='PA', seq=100, ack=1)
                / Raw(b'tcp-body'),
            ])

            extractor = extract(fin=str(pcap_file), fout='/tmp/pypcapkit-generated',
                                format='tree', store=True, nofile=True)
            self.addCleanup(close_extractor, extractor)

            self.assertEqual(extractor.length, 2)
            self.assertEqual(len(extractor.frame), 2)
            self.assertEqual(extractor.magic_number, b'\xd4\xc3\xb2\xa1')

            udp_frame = extractor.frame[0]
            udp_eth = udp_frame.payload
            udp_ip = udp_eth.payload
            udp = udp_ip.payload
            udp_raw = udp.payload

            self.assertEqual(str(udp_frame.protochain), 'Ethernet:IPv4:UDP:Raw')
            self.assertEqual(udp_eth.info.src, '02:00:00:00:00:01')
            self.assertEqual(udp_eth.info.dst, '02:00:00:00:00:02')
            self.assertEqual(str(udp_ip.info.src), '192.0.2.1')
            self.assertEqual(str(udp_ip.info.dst), '198.51.100.2')
            self.assertEqual(int(udp.info.srcport), 12345)
            self.assertEqual(int(udp.info.dstport), 54321)
            self.assertEqual(udp_raw.info.packet, b'udp-body')

            tcp_frame = extractor.frame[1]
            tcp_eth = tcp_frame.payload
            tcp_ip = tcp_eth.payload
            tcp = tcp_ip.payload
            tcp_raw = tcp.payload

            self.assertEqual(str(tcp_frame.protochain), 'Ethernet:IPv6:TCP:Raw')
            self.assertEqual(tcp_eth.info.src, '02:00:00:00:00:03')
            self.assertEqual(tcp_eth.info.dst, '02:00:00:00:00:04')
            self.assertEqual(str(tcp_ip.info.src), '2001:db8::1')
            self.assertEqual(str(tcp_ip.info.dst), '2001:db8::2')
            self.assertEqual(int(tcp.info.srcport), 443)
            self.assertEqual(int(tcp.info.dstport), 50000)
            self.assertTrue(tcp.info.flags.psh)
            self.assertTrue(tcp.info.flags.ack)
            self.assertEqual(tcp_raw.info.packet, b'tcp-body')

    def test_scapy_generated_pcap_decodes_arp_and_vlan_ipv4_udp(self) -> None:
        from scapy.all import ARP, Dot1Q, Ether, IP, Raw, UDP, wrpcap

        from pcapkit.interface import extract

        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_file = Path(tmpdir) / 'generated-link-protocols.pcap'
            wrpcap(str(pcap_file), [
                Ether(src='02:00:00:00:00:05', dst='ff:ff:ff:ff:ff:ff')
                / ARP(hwsrc='02:00:00:00:00:05', psrc='192.0.2.5',
                      hwdst='00:00:00:00:00:00', pdst='192.0.2.1', op=1),
                Ether(src='02:00:00:00:00:06', dst='02:00:00:00:00:07')
                / Dot1Q(vlan=100, prio=3, dei=0)
                / IP(src='192.0.2.6', dst='198.51.100.7')
                / UDP(sport=1111, dport=2222)
                / Raw(b'vlan'),
            ])

            extractor = extract(fin=str(pcap_file), fout='/tmp/pypcapkit-generated-link',
                                format='tree', store=True, nofile=True)
            self.addCleanup(close_extractor, extractor)

            self.assertEqual(extractor.length, 2)

            arp_frame = extractor.frame[0]
            arp = arp_frame.payload.payload
            self.assertEqual(str(arp_frame.protochain), 'Ethernet:ARP')
            self.assertEqual(arp.info.sha, '02:00:00:00:00:05')
            self.assertEqual(str(arp.info.spa), '192.0.2.5')
            self.assertEqual(arp.info.tha, '00:00:00:00:00:00')
            self.assertEqual(str(arp.info.tpa), '192.0.2.1')
            self.assertEqual(arp.info.oper.name, 'REQUEST')

            vlan_frame = extractor.frame[1]
            vlan = vlan_frame.payload.payload
            ipv4 = vlan.payload
            udp = ipv4.payload
            raw = udp.payload

            self.assertEqual(str(vlan_frame.protochain), 'Ethernet:802.1Q:IPv4:UDP:Raw')
            self.assertEqual(vlan.info.tci.vid, 100)
            self.assertEqual(vlan.info.tci.pcp.name, 'CA')
            self.assertEqual(str(ipv4.info.src), '192.0.2.6')
            self.assertEqual(str(ipv4.info.dst), '198.51.100.7')
            self.assertEqual(int(udp.info.srcport), 1111)
            self.assertEqual(int(udp.info.dstport), 2222)
            self.assertEqual(raw.info.packet, b'vlan')


if __name__ == '__main__':
    unittest.main()
