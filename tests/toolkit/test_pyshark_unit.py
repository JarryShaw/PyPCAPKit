from __future__ import annotations

import importlib.util
from ipaddress import ip_address
import unittest

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class FakeLayer:
    def __init__(self, layer_name: str, **fields: object) -> None:
        self.layer_name = layer_name
        self.field_names = tuple(fields)
        for name, value in fields.items():
            setattr(self, name, value)


class FakePySharkPacket:
    def __init__(self, *, ipv6: bool = False, tcp: bool = True,
                 ip: bool = True) -> None:
        self.number = '12'
        self.frame_info = FakeLayer('frame', time_epoch=70.5, cap_len='54')
        self.layers = [
            FakeLayer('ethernet', src='aa:aa:aa:aa:aa:aa'),
            FakeLayer('ip', src='192.0.2.1', dst='198.51.100.1'),
            FakeLayer('tcp', srcport='1234', dstport='80',
                      flags_syn='1', flags_fin='0'),
        ]
        self._contains = set()
        if ip:
            if ipv6:
                self._contains.add('IPv6')
                self.ipv6 = FakeLayer('ipv6', src='2001:db8::1', dst='2001:db8::2')
                self.layers[1] = self.ipv6
            else:
                self._contains.add('IP')
                self.ip = FakeLayer('ip', src='192.0.2.1', dst='198.51.100.1')
        if tcp:
            self._contains.add('TCP')
            self.tcp = self.layers[2]
        else:
            self.layers = self.layers[:2]

    def __contains__(self, name: str) -> bool:
        return name in self._contains


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PySharkToolkitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_packet2dict_nests_frame_and_layers(self) -> None:
        from pcapkit.toolkit import pyshark as toolkit

        packet = FakePySharkPacket()
        converted = toolkit.packet2dict(packet)
        self.assertEqual(converted['time_epoch'], 70.5)
        self.assertEqual(converted['ETHERNET']['src'], 'aa:aa:aa:aa:aa:aa')
        self.assertEqual(converted['ETHERNET']['IP']['src'], '192.0.2.1')
        self.assertEqual(converted['ETHERNET']['IP']['TCP']['srcport'], '1234')

    def test_tcp_traceflow_ipv4_ipv6_and_negative_paths(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import pyshark as toolkit

        flow = toolkit.tcp_traceflow(FakePySharkPacket())
        self.assertIsNotNone(flow)
        assert flow is not None
        self.assertEqual(flow.protocol, LinkType.ETHERNET)
        self.assertEqual(flow.index, 12)
        self.assertEqual(flow.src, ip_address('192.0.2.1'))
        self.assertEqual(flow.dst, ip_address('198.51.100.1'))
        self.assertEqual(flow.srcport, 1234)
        self.assertEqual(flow.dstport, 80)
        self.assertTrue(flow.syn)
        self.assertFalse(flow.fin)
        self.assertEqual(flow.timestamp, 70.5)

        v6_flow = toolkit.tcp_traceflow(FakePySharkPacket(ipv6=True))
        self.assertIsNotNone(v6_flow)
        assert v6_flow is not None
        self.assertEqual(v6_flow.src, ip_address('2001:db8::1'))
        self.assertEqual(v6_flow.dst, ip_address('2001:db8::2'))

        self.assertIsNone(toolkit.tcp_traceflow(FakePySharkPacket(ip=False)))
        self.assertIsNone(toolkit.tcp_traceflow(FakePySharkPacket(tcp=False)))


if __name__ == '__main__':
    unittest.main()
