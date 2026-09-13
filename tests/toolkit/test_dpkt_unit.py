from __future__ import annotations

import importlib.util
from ipaddress import ip_address
import socket
import types
import unittest
import warnings

from tests._support import purge_modules

HAS_DPKT = importlib.util.find_spec('dpkt') is not None
RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class FakeHeader:
    length = 8


class FakeFragment:
    nh = 6
    nxt = 2
    m_flag = 1

    def __len__(self) -> int:
        return 8


class FakeIPv6:
    __hdr_len__ = 40
    src = ip_address('2001:db8::1').packed
    dst = ip_address('2001:db8::2').packed
    flow = 7

    def __init__(self, frag: FakeFragment | None = None) -> None:
        self.extension_hdrs = {0: FakeHeader()}
        if frag is not None:
            self.extension_hdrs[44] = frag

    def __len__(self) -> int:
        return len(self.pack())

    def pack(self) -> bytes:
        return b'I' * 40 + b'H' * 8 + b'F' * 8 + b'PAYLOAD'


class TCP:
    __hdr_fields__ = ('sport', 'dport', 'seq', 'ack', 'flags')
    __hdr_len__ = 4
    sport = 2345
    dport = 443
    seq = 20
    ack = 15
    flags = 0b00010011
    data = b'ip6'

    def pack(self) -> bytes:
        return b'HEADip6'


class FakeTCPIPv6:
    __hdr_fields__ = ('src', 'dst')
    src = ip_address('2001:db8::10').packed
    dst = ip_address('2001:db8::20').packed

    def __init__(self) -> None:
        self.data = TCP()


class FakeDPKTPacket:
    __hdr_fields__ = ('link',)
    link = 1

    def __init__(self) -> None:
        self.ip6 = FakeTCPIPv6()
        self.data = self.ip6

    def pack(self) -> bytes:
        return b'packet'


@unittest.skipUnless(HAS_RUNTIME and HAS_DPKT, 'runtime dependencies not installed')
class DPKTToolkitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _make_ipv4_tcp_packet(self, *, df: bool = False, fragmented: bool = False):
        import dpkt

        eth = dpkt.ethernet.Ethernet(
            src=b'\xaa' * 6,
            dst=b'\xbb' * 6,
            type=dpkt.ethernet.ETH_TYPE_IP,
        )
        ipv4 = dpkt.ip.IP(
            src=socket.inet_aton('192.0.2.1'),
            dst=socket.inet_aton('198.51.100.1'),
            p=dpkt.ip.IP_PROTO_TCP,
            id=123,
        )
        ipv4.df = int(df)
        ipv4.mf = int(fragmented and not df)
        ipv4.offset = 2 if fragmented and not df else 0
        ipv4.data = dpkt.tcp.TCP(
            sport=1234,
            dport=80,
            seq=10,
            ack=5,
            flags=dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK,
            data=b'data',
        )
        ipv4.len = len(ipv4)
        eth.data = ipv4
        return dpkt.ethernet.Ethernet(bytes(eth))

    def test_packet_chain_dict_and_ipv4_reassembly_with_real_dpkt_packet(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import dpkt as toolkit

        packet = self._make_ipv4_tcp_packet()
        self.assertEqual(toolkit.packet2chain(packet), 'Ethernet:IP:TCP')
        converted = toolkit.packet2dict(packet, 123.5, data_link=LinkType.ETHERNET)
        self.assertEqual(converted['timestamp'], 123.5)
        self.assertEqual(converted['packet'], packet.pack())
        self.assertIn('IP', converted['ETHERNET'])

        fragment = self._make_ipv4_tcp_packet(fragmented=True)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            reassembled = toolkit.ipv4_reassembly(fragment, count=4)
        self.assertIsNotNone(reassembled)
        assert reassembled is not None
        self.assertEqual(reassembled.num, 4)
        self.assertEqual(reassembled.bufid[0], ip_address('192.0.2.1'))
        self.assertEqual(reassembled.bufid[1], ip_address('198.51.100.1'))
        self.assertEqual(reassembled.bufid[2], 123)
        self.assertTrue(reassembled.mf)
        self.assertEqual(bytes(reassembled.payload), fragment.ip.pack()[fragment.ip.__hdr_len__:])

        self.assertIsNone(toolkit.ipv4_reassembly(types.SimpleNamespace(), count=1))
        self.assertIsNone(toolkit.ipv4_reassembly(self._make_ipv4_tcp_packet(df=True), count=1))

    def test_tcp_reassembly_and_traceflow_accept_dpkt_data_payload_tcp(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import dpkt as toolkit

        packet = self._make_ipv4_tcp_packet()
        tcp = toolkit.tcp_reassembly(packet, count=9)
        self.assertIsNotNone(tcp)
        assert tcp is not None
        self.assertEqual(tcp.bufid[1], 1234)
        self.assertEqual(tcp.bufid[3], 80)
        self.assertTrue(tcp.syn)
        self.assertFalse(tcp.fin)
        self.assertEqual(tcp.first, 10)
        self.assertEqual(tcp.last, 14)

        flow = toolkit.tcp_traceflow(packet, 50.25, data_link=LinkType.ETHERNET, count=9)
        self.assertIsNotNone(flow)
        assert flow is not None
        self.assertEqual(flow.index, 9)
        self.assertEqual(flow.protocol, LinkType.ETHERNET)
        self.assertTrue(flow.syn)
        self.assertFalse(flow.fin)
        self.assertEqual(flow.timestamp, 50.25)

        self.assertIsNone(toolkit.tcp_reassembly(types.SimpleNamespace(), count=1))
        self.assertIsNone(toolkit.tcp_traceflow(types.SimpleNamespace(), 1.0,
                                                data_link=LinkType.ETHERNET, count=1))
        raw_ip = types.SimpleNamespace(src=b'\x7f\x00\x00\x01', dst=b'\x7f\x00\x00\x01',
                                       data=b'not tcp')
        self.assertIsNone(toolkit.tcp_reassembly(types.SimpleNamespace(ip=raw_ip), count=1))
        self.assertIsNone(toolkit.tcp_traceflow(types.SimpleNamespace(ip=raw_ip), 1.0,
                                                data_link=LinkType.ETHERNET, count=1))

    def test_tcp_helpers_cover_ipv6_and_data_payload_fallback(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import dpkt as toolkit

        packet = FakeDPKTPacket()
        tcp = toolkit.tcp_reassembly(packet, count=12)
        self.assertIsNotNone(tcp)
        assert tcp is not None
        self.assertEqual(tcp.bufid[0], ip_address('2001:db8::10'))
        self.assertEqual(tcp.bufid[2], ip_address('2001:db8::20'))
        self.assertTrue(tcp.syn)
        self.assertTrue(tcp.fin)
        self.assertEqual(bytes(tcp.payload), b'ip6')

        flow = toolkit.tcp_traceflow(packet, 60.5, data_link=LinkType.ETHERNET, count=12)
        self.assertIsNotNone(flow)
        assert flow is not None
        self.assertEqual(flow.index, 12)
        self.assertEqual(flow.src, ip_address('2001:db8::10'))
        self.assertEqual(flow.dst, ip_address('2001:db8::20'))
        self.assertTrue(flow.syn)
        self.assertTrue(flow.fin)
        self.assertEqual(flow.frame['ETHERNET']['FakeTCPIPv6']['TCP']['sport'], 2345)

    def test_ipv6_header_length_and_reassembly_with_fragment_fake(self) -> None:
        from pcapkit.toolkit import dpkt as toolkit

        frag = FakeFragment()
        ipv6 = FakeIPv6(frag)
        self.assertEqual(toolkit.ipv6_hdr_len(ipv6), 48)

        packet = types.SimpleNamespace(ip6=ipv6)
        reassembled = toolkit.ipv6_reassembly(packet, count=5)
        self.assertIsNotNone(reassembled)
        assert reassembled is not None
        self.assertEqual(reassembled.num, 5)
        self.assertEqual(reassembled.bufid[0], ip_address('2001:db8::1'))
        self.assertEqual(reassembled.bufid[1], ip_address('2001:db8::2'))
        self.assertEqual(reassembled.bufid[2], 7)
        self.assertEqual(reassembled.fo, 2)
        self.assertTrue(reassembled.mf)
        self.assertEqual(reassembled.ihl, 48)
        self.assertEqual(bytes(reassembled.payload), b'PAYLOAD')

        self.assertIsNone(toolkit.ipv6_reassembly(types.SimpleNamespace(), count=1))
        self.assertIsNone(toolkit.ipv6_reassembly(types.SimpleNamespace(ip6=FakeIPv6()), count=1))


if __name__ == '__main__':
    unittest.main()
