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
from pcapkit.utilities.exceptions import FieldValueError, ProtocolError

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


class TestARPNonIPAddressType(unittest.TestCase):
    """A non-IP ``ptype`` checks the address type too. See #2166.

    Only the IPv4 and IPv6 branches went through ``parse_ip_address``, so any
    other ``ptype`` returned a :obj:`bool` or :class:`int` unchanged, and
    :meth:`~pcapkit.protocols.link.arp.ARP.make` then failed with ``TypeError:
    object of type 'bool' has no len()``.
    """

    def test_bool_raises_field_value_error(self) -> None:
        cases = {
            'non-IP': dict(ptype=NON_IP),
            'IPv4 with plen 6': dict(ptype=EtherType.Internet_Protocol_version_4, plen=6),
        }
        for name, kwargs in cases.items():
            for value in (True, False):
                with self.subTest(case=name, value=value):
                    with self.assertRaises(FieldValueError) as context:
                        ARP(spa=value, tpa=value, **kwargs)
                    self.assertIn('must not be a bool', str(context.exception))

    def test_non_bytes_raises_protocol_error(self) -> None:
        for value in (5, 1.5, None, ['a1', 'b2', 'c3']):
            with self.subTest(value=value):
                with self.assertRaises(ProtocolError):
                    ARP(ptype=NON_IP, spa=value, tpa=value)

    def test_bytes_and_bytearray_pack_as_given(self) -> None:
        proto = ARP(ptype=NON_IP, spa=b'\xa1\xb2\xc3', tpa=bytearray(b'\xd4\xe5\xf6'),
                    sha='01:23:45:67:89:ab', tha='fe:dc:ba:98:76:54')
        self.assertEqual(proto.data, ARP_NON_IP)


class TestARPHardwareAddressType(unittest.TestCase):
    """The hardware address resolver checks the address type too. See #2166.

    A :obj:`bool` or :class:`int` ``sha``/``tha`` reached the MAC pattern
    (``TypeError: expected string or bytes-like object``) for Ethernet, and fell
    through unchanged (``TypeError: object of type 'bool' has no len()``) for
    any other ``htype``.

    A :obj:`bool` is rejected like any other wrong type, with
    :exc:`~pcapkit.utilities.exceptions.ProtocolError` (#2256).
    """

    HTYPES = {'Ethernet': Hardware.Ethernet, 'non-Ethernet': Hardware.Fibre_Channel}

    #: The address noun each ``htype`` uses in its messages.
    NOUNS = {'Ethernet': 'MAC address', 'non-Ethernet': 'hardware address'}

    def test_wrong_type_message(self) -> None:
        for name, htype in self.HTYPES.items():
            for value in (True, False, 5, None, 1.5):
                with self.subTest(htype=name, value=value):
                    with self.assertRaises(ProtocolError) as context:
                        ARP(htype=htype, sha=value, tha=value)
                    self.assertNotIsInstance(context.exception, FieldValueError)
                    self.assertEqual(
                        str(context.exception),
                        f'ARP: invalid {self.NOUNS[name]}: must be a str, bytes or '
                        f'bytearray, not {value!r}')

    def test_malformed_str_message(self) -> None:
        for name, htype in self.HTYPES.items():
            with self.subTest(htype=name):
                with self.assertRaises(ProtocolError) as context:
                    ARP(htype=htype, sha='zz', tha='zz')
                self.assertEqual(str(context.exception),
                                 f"ARP: invalid {self.NOUNS[name]}: 'zz'")

    def test_unsupported_type_raises_protocol_error(self) -> None:
        for name, htype in self.HTYPES.items():
            for value in (5, None, [1, 2, 3, 4, 5, 6], memoryview(b'\x01' * 6)):
                with self.subTest(htype=name, value=value):
                    with self.assertRaises(ProtocolError):
                        ARP(htype=htype, sha=value, tha=value)

    def test_supported_forms_still_pack(self) -> None:
        raw = bytes.fromhex('0123456789ab')
        cases = (
            (Hardware.Ethernet, '01:23:45:67:89:ab'),
            (Hardware.Ethernet, '01-23-45-67-89-ab'),
            (Hardware.Ethernet, b'01:23:45:67:89:ab'),
            (Hardware.Ethernet, bytearray(b'01:23:45:67:89:ab')),
            (Hardware.Fibre_Channel, '0123456789ab'),
            (Hardware.Fibre_Channel, '01:23:45:67:89:ab'),
            (Hardware.Fibre_Channel, raw),
            (Hardware.Fibre_Channel, bytearray(raw)),
        )
        for htype, value in cases:
            with self.subTest(htype=htype.name, value=value):
                proto = ARP(htype=htype, sha=value, tha=value)
                self.assertEqual(proto.data[8:14], raw)
                self.assertEqual(proto.data[18:24], raw)


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
