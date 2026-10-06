# -*- coding: utf-8 -*-
"""ARP packs non-IP protocol addresses as octets and checks ``hlen``/``plen``.

GitHub issue #1139: :meth:`ARP._make_proto_resolve
<pcapkit.protocols.link.arp.ARP._make_proto_resolve>` encoded a :data:`str`
protocol address as its ASCII text when ``ptype`` was neither IPv4 nor IPv6,
while :meth:`~pcapkit.protocols.link.arp.ARP._read_proto_resolve` returns hex;
and :meth:`~pcapkit.protocols.link.arp.ARP.make` let the schema silently
truncate an address that disagreed with ``hlen``/``plen``.

Every case builds its own octets in memory and reads no capture.

"""

import unittest

from pcapkit.const.arp.hardware import Hardware
from pcapkit.const.reg.ethertype import EtherType
from pcapkit.protocols.link.arp import ARP
from pcapkit.utilities.exceptions import ProtocolError

#: A protocol type that is neither IPv4 nor IPv6.
NON_IP = EtherType.get(0x88B5)

#: ARP request: htype, ptype, hlen, plen, oper, then sha/spa/tha/tpa.
ARP_IPV4 = bytes.fromhex('0001' '0800' '06' '04' '0001'
                         '0123456789ab' 'c0000201' 'fedcba987654' 'c0000202')
ARP_IPV6 = bytes.fromhex('0001' '86dd' '06' '10' '0001'
                         '0123456789ab' '20010db8000000000000000000000001'
                         'fedcba987654' '20010db8000000000000000000000002')
ARP_NON_IP = bytes.fromhex('0001' '88b5' '06' '03' '0001'
                           '0123456789ab' 'a1b2c3' 'fedcba987654' 'd4e5f6')


class TestARPProtocolAddress(unittest.TestCase):
    """Pin the wire form of non-IP protocol addresses."""

    def test_non_ip_str_packs_as_octets(self) -> None:
        proto = ARP(ptype=NON_IP, spa='a1b2c3', tpa='d4e5f6',
                    sha='01:23:45:67:89:ab', tha='fe:dc:ba:98:76:54')
        self.assertEqual(proto.data, ARP_NON_IP)
        self.assertEqual(proto.info.spa, 'a1b2c3')

    def test_non_ip_str_not_hex_raises(self) -> None:
        with self.assertRaises(ProtocolError):
            ARP(ptype=NON_IP, spa='raw', tpa='raw')

    def test_from_data_round_trips(self) -> None:
        for name, data in (('IPv4', ARP_IPV4), ('IPv6', ARP_IPV6), ('non-IP', ARP_NON_IP)):
            with self.subTest(ptype=name):
                parsed = ARP(data)
                self.assertEqual(ARP.from_data(parsed.info).data, data)


class TestARPLengthFields(unittest.TestCase):
    """``hlen``/``plen`` are derived when omitted and checked when given."""

    def test_lengths_derived_from_addresses(self) -> None:
        proto = ARP(ptype=EtherType.Internet_Protocol_version_6,
                    sha='01:23:45:67:89:ab', spa='2001:db8::1',
                    tha='fe:dc:ba:98:76:54', tpa='2001:db8::2')
        self.assertEqual(proto.data, ARP_IPV6)

    def test_mismatched_lengths_raise(self) -> None:
        cases = {
            'hlen': dict(hlen=4),
            'plen': dict(plen=2),
            'ipv6 plen': dict(ptype=EtherType.Internet_Protocol_version_6, plen=4,
                              spa='::1', tpa='::2'),
            'tha': dict(htype=Hardware.Fibre_Channel, sha='aabbcc', tha='aabb'),
            'tpa': dict(ptype=NON_IP, spa='a1b2c3', tpa='d4e5'),
        }
        for name, kwargs in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(ProtocolError):
                    ARP(**kwargs)

    def test_matching_explicit_lengths_pass(self) -> None:
        proto = ARP(hlen=6, plen=4, sha='01:23:45:67:89:ab', spa='192.0.2.1',
                    tha='fe:dc:ba:98:76:54', tpa='192.0.2.2')
        self.assertEqual(proto.data, ARP_IPV4)


if __name__ == '__main__':
    unittest.main()
