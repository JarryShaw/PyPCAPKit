from __future__ import annotations

import importlib.util
from ipaddress import ip_address
import builtins
import importlib
import unittest
from unittest import mock

from tests._support import purge_modules

HAS_SCAPY = importlib.util.find_spec('scapy') is not None
RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME and HAS_SCAPY, 'runtime dependencies not installed')
class ScapyToolkitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _ether_kwargs(self) -> dict[str, str]:
        return {
            'src': 'aa:aa:aa:aa:aa:aa',
            'dst': 'bb:bb:bb:bb:bb:bb',
        }

    def _make_ipv4_tcp_packet(self):
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw

        packet = (
            Ether(**self._ether_kwargs()) /
            IP(src='192.0.2.1', dst='198.51.100.1', id=123) /
            TCP(sport=1234, dport=80, seq=10, ack=5, flags='SA') /
            Raw(b'data')
        )
        return Ether(bytes(packet))

    def _make_ipv4_fragment(self, *, df: bool = False):
        from scapy.layers.inet import IP
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw

        flags = 'DF' if df else 'MF'
        packet = (
            Ether(**self._ether_kwargs()) /
            IP(src='192.0.2.1', dst='198.51.100.1', id=123, flags=flags,
               frag=0 if df else 2) /
            Raw(b'fragment')
        )
        return Ether(bytes(packet))

    def _make_ipv6_fragment(self):
        from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw

        packet = (
            Ether(**self._ether_kwargs()) /
            IPv6(src='2001:db8::1', dst='2001:db8::2', fl=7) /
            IPv6ExtHdrFragment(nh=6, offset=1, m=1) /
            Raw(b'v6')
        )
        return Ether(bytes(packet))

    def _make_ipv6_tcp_packet(self):
        from scapy.layers.inet import TCP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw

        packet = (
            Ether(**self._ether_kwargs()) /
            IPv6(src='2001:db8::1', dst='2001:db8::2', fl=7) /
            TCP(sport=1234, dport=443, seq=10, ack=5, flags='S') /
            Raw(b'v6tcp')
        )
        return Ether(bytes(packet))

    def _make_ether_raw(self):
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw

        return Ether(bytes(Ether(**self._ether_kwargs()) / Raw(b'raw')))

    def test_import_without_scapy_sets_none_and_warns(self) -> None:
        purge_modules(['pcapkit.toolkit.scapy'])
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == 'scapy':
                raise ModuleNotFoundError("No module named 'scapy'")
            return real_import(name, *args, **kwargs)

        with mock.patch('builtins.__import__', side_effect=fake_import):
            module = importlib.import_module('pcapkit.toolkit.scapy')

        self.assertIsNone(module.scapy)

    def test_packet_chain_dict_and_optional_dependency_errors(self) -> None:
        from pcapkit.toolkit import scapy as toolkit
        from pcapkit.utilities.exceptions import ModuleNotFound

        packet = self._make_ipv4_tcp_packet()
        self.assertEqual(toolkit.packet2chain(packet), 'Ethernet:IP:TCP:Raw')
        converted = toolkit.packet2dict(packet)
        self.assertEqual(converted['packet'], bytes(packet))
        self.assertIn('IP', converted['Ethernet'])
        self.assertIn('TCP', converted['Ethernet']['IP'])

        with mock.patch.object(toolkit, 'scapy', None):
            with self.assertRaises(ModuleNotFound):
                toolkit.packet2chain(packet)
            with self.assertRaises(ModuleNotFound):
                toolkit.packet2dict(packet)
            with self.assertRaises(ModuleNotFound):
                toolkit.ipv6_reassembly(packet)

    def test_ipv4_and_ipv6_reassembly(self) -> None:
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6ExtHdrFragment

        from pcapkit.toolkit import scapy as toolkit

        fragment = self._make_ipv4_fragment()
        ipv4 = fragment[IP]
        reassembled = toolkit.ipv4_reassembly(fragment, count=3)
        self.assertIsNotNone(reassembled)
        assert reassembled is not None
        self.assertEqual(reassembled.num, 3)
        self.assertEqual(reassembled.bufid[0], ip_address('192.0.2.1'))
        self.assertEqual(reassembled.bufid[1], ip_address('198.51.100.1'))
        self.assertEqual(reassembled.bufid[2], 123)
        self.assertEqual(reassembled.ihl, 20)
        self.assertEqual(reassembled.header, bytes(ipv4)[:20])
        self.assertEqual(bytes(reassembled.payload), bytes(ipv4.payload))
        self.assertTrue(reassembled.mf)

        self.assertIsNone(toolkit.ipv4_reassembly(self._make_ether_raw(), count=1))
        self.assertIsNone(toolkit.ipv4_reassembly(self._make_ipv4_fragment(df=True), count=1))

        v6_packet = self._make_ipv6_fragment()
        ipv6_frag = v6_packet[IPv6ExtHdrFragment]
        v6 = toolkit.ipv6_reassembly(v6_packet, count=4)
        self.assertIsNotNone(v6)
        assert v6 is not None
        self.assertEqual(v6.num, 4)
        self.assertEqual(v6.bufid[0], ip_address('2001:db8::1'))
        self.assertEqual(v6.bufid[1], ip_address('2001:db8::2'))
        self.assertEqual(v6.bufid[2], 7)
        self.assertEqual(v6.bufid[3].value, 6)
        self.assertEqual(v6.fo, 1)
        self.assertTrue(v6.mf)
        self.assertEqual(bytes(v6.payload), bytes(ipv6_frag.payload))

        self.assertIsNone(toolkit.ipv6_reassembly(self._make_ipv4_tcp_packet(), count=1))
        self.assertIsNone(toolkit.ipv6_reassembly(self._make_ipv6_tcp_packet(), count=1))

    def test_tcp_reassembly_and_traceflow(self) -> None:
        from scapy.layers.inet import TCP
        from scapy.packet import Raw

        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import scapy as toolkit

        packet = self._make_ipv4_tcp_packet()
        tcp_layer = packet[TCP]
        tcp = toolkit.tcp_reassembly(packet, count=8)
        self.assertIsNotNone(tcp)
        assert tcp is not None
        self.assertEqual(tcp.bufid[0], ip_address('192.0.2.1'))
        self.assertEqual(tcp.bufid[1], 1234)
        self.assertEqual(tcp.bufid[3], 80)
        self.assertTrue(tcp.syn)
        self.assertFalse(tcp.fin)
        self.assertFalse(tcp.rst)
        self.assertEqual(tcp.header, bytes(tcp_layer)[:tcp_layer.dataofs * 4])
        self.assertEqual(bytes(tcp.payload), bytes(tcp_layer[Raw]))
        v6_tcp = toolkit.tcp_reassembly(self._make_ipv6_tcp_packet(), count=9)
        self.assertIsNotNone(v6_tcp)
        assert v6_tcp is not None
        self.assertEqual(v6_tcp.bufid[0], ip_address('2001:db8::1'))
        self.assertEqual(v6_tcp.bufid[3], 443)

        with mock.patch('pcapkit.toolkit.scapy.time.time', return_value=77.25):
            flow = toolkit.tcp_traceflow(packet, count=8)
        self.assertIsNotNone(flow)
        assert flow is not None
        self.assertEqual(flow.protocol, LinkType.ETHERNET)
        self.assertEqual(flow.index, 8)
        self.assertTrue(flow.syn)
        self.assertFalse(flow.fin)
        self.assertEqual(flow.timestamp, 77.25)

        self.assertIsNone(toolkit.tcp_reassembly(self._make_ipv4_fragment(), count=1))
        self.assertIsNone(toolkit.tcp_reassembly(self._make_ether_raw(), count=1))
        self.assertIsNone(toolkit.tcp_traceflow(self._make_ipv4_fragment(), count=1))


if __name__ == '__main__':
    unittest.main()
