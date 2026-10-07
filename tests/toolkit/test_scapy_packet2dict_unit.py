"""Regression tests for :func:`pcapkit.toolkit.scapy.packet2dict` (#1259, #1260)."""

from __future__ import annotations

import importlib.util
import unittest

from tests._support import reimport_once_per_class

HAS_SCAPY = importlib.util.find_spec('scapy') is not None
RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME and HAS_SCAPY, 'runtime dependencies not installed')
class ScapyPacket2DictTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _walk(self, value):
        """Yield every value nested in ``value``."""
        yield value
        if isinstance(value, dict):
            for item in value.values():
                yield from self._walk(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                yield from self._walk(item)

    def assertNoPacketObjects(self, converted) -> None:
        from scapy.packet import Packet

        leftover = [type(v).__name__ for v in self._walk(converted) if isinstance(v, Packet)]
        self.assertEqual(leftover, [])

    def test_ip_options_list_is_converted(self) -> None:
        from scapy.layers.inet import IP, IPOption_NOP, IPOption_RR
        from scapy.layers.l2 import Ether

        from pcapkit.toolkit.scapy import packet2dict

        built = Ether() / IP(options=[IPOption_NOP(), IPOption_RR(routers=['192.0.2.1'])])
        packet = Ether(bytes(built))
        converted = packet2dict(packet)

        self.assertNoPacketObjects(converted)
        options = converted['Ethernet']['IP']['options']
        self.assertEqual(options[0]['option'], 1)
        self.assertEqual(options[1]['routers'], ['192.0.2.1'])

    def test_hand_built_nested_packet_carries_only_its_set_fields(self) -> None:
        from scapy.layers.inet import IP, IPOption_NOP, IPOption_RR
        from scapy.layers.l2 import Ether

        from pcapkit.toolkit.scapy import packet2dict

        converted = packet2dict(Ether() / IP(options=[IPOption_NOP(), IPOption_RR(routers=['192.0.2.1'])]))
        self.assertNoPacketObjects(converted)
        self.assertEqual(converted['Ethernet']['IP']['options'],
                         [{}, {'routers': ['192.0.2.1']}])

    def _assert_layer_keys_match_fields(self, packet) -> None:
        from pcapkit.toolkit.scapy import packet2dict

        converted = packet2dict(packet)
        node = converted[packet.name]
        for layer in packet.iterpayloads():
            with self.subTest(layer=layer.name):
                payload = layer.payload
                extra = {payload.name} if payload else set()
                self.assertEqual(set(node), set(layer.fields) | extra)
            if payload:
                node = node[payload.name]

    def test_dissected_icmp_echo_has_only_wire_fields(self) -> None:
        from scapy.layers.inet import ICMP, IP
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw

        built = Ether() / IP() / ICMP(type=8, id=1, seq=2) / Raw(b'ping')
        self._assert_layer_keys_match_fields(Ether(bytes(built)))

    def test_fixture_icmp_echo_has_only_wire_fields(self) -> None:
        from scapy.layers.inet import ICMP
        from scapy.utils import rdpcap

        from tests._support import sample_path

        try:
            path = sample_path('little_endian.pcap')
        except FileNotFoundError as exc:
            self.skipTest(str(exc))
        echoes = [p for p in rdpcap(path) if ICMP in p and p[ICMP].type in (0, 8)]
        self.assertTrue(echoes)
        self._assert_layer_keys_match_fields(echoes[0])

    def test_dns_records_are_converted(self) -> None:
        from scapy.layers.dns import DNS, DNSQR, DNSRR
        from scapy.layers.inet import IP, UDP
        from scapy.layers.l2 import Ether

        from pcapkit.toolkit.scapy import packet2dict

        built = (Ether() / IP() / UDP(sport=53, dport=53) /
                 DNS(qd=DNSQR(qname='example.com'), an=DNSRR(rrname='example.com', rdata='192.0.2.1')))
        converted = packet2dict(Ether(bytes(built)))

        self.assertNoPacketObjects(converted)
        dns = converted['Ethernet']['IP']['UDP']['DNS']
        self.assertEqual(dns['qd'][0]['qname'], b'example.com.')
        self.assertEqual(dns['an'][0]['rdata'], '192.0.2.1')

    def test_packet_inside_a_tuple_is_converted(self) -> None:
        from scapy.layers.inet import IP, TCP, TCPAOValue
        from scapy.layers.l2 import Ether

        from pcapkit.toolkit.scapy import packet2dict

        built = Ether() / IP() / TCP(options=[('AO', TCPAOValue(keyid=1, rnextkeyid=2, mac=b'\x01\x02\x03\x04'))])
        converted = packet2dict(Ether(bytes(built)))

        self.assertNoPacketObjects(converted)
        name, value = converted['Ethernet']['IP']['TCP']['options'][0]
        self.assertEqual(name, 'AO')
        self.assertEqual(value['keyid'], 1)
        self.assertEqual(value['mac'], b'\x01\x02\x03\x04')

    def test_input_packet_is_not_mutated(self) -> None:
        from scapy.layers.inet import IP
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw

        from pcapkit.toolkit.scapy import packet2dict

        for packet in (Ether() / IP() / Raw(b'x'),
                       Ether(bytes(Ether(dst='bb:bb:bb:bb:bb:bb') / IP() / Raw(b'x')))):
            with self.subTest(packet=packet.summary()):
                before = {layer.name: dict(layer.fields) for layer in packet.iterpayloads()}
                converted = packet2dict(packet)
                after = {layer.name: dict(layer.fields) for layer in packet.iterpayloads()}

                self.assertEqual(after, before)
                self.assertIn('Raw', converted['Ethernet']['IP'])
                self.assertEqual(bytes(packet.copy()), bytes(packet))


if __name__ == '__main__':
    unittest.main()
