from __future__ import annotations

import importlib.util
import ipaddress
import unittest

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Prefix lengths whose octet happens to be an ASCII digit, i.e. ``0x30``--``0x39``.
#: :meth:`IPv6InterfaceField.post_process` used to read the octet as an ASCII
#: decimal string, so these were the only prefix lengths that parsed at all --
#: and every one of them decoded to ``prefixlen - 48``. Every other prefix length,
#: including all the common ones, raised :exc:`ValueError`.
ASCII_DIGIT_PREFIX_LENGTHS = tuple(range(48, 58))

#: Section 4.2 of the PCAP-NG specification: ``if_IPv6addr`` is 17 octets, of
#: which the first 16 are the address and the 17th is the prefix length, so
#: ``2001:0db8:85a3:08d3:1319:8a2e:0370:7344/64`` is written with a trailing ``40``.
SPEC_INTERFACE = '2001:0db8:85a3:08d3:1319:8a2e:0370:7344/64'
SPEC_ENCODING = bytes.fromhex('2001 0db8 85a3 08d3 1319 8a2e 0370 7344 40'.replace(' ', ''))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPAddressFieldTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_address_fields_round_trip_and_reject_the_other_version(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv4AddressField, IPv6AddressField
        from pcapkit.utilities.exceptions import FieldValueError

        ipv4 = IPv4AddressField()
        self.assertEqual(ipv4.length, 4)
        self.assertEqual(ipv4.unpack(ipv4.pack(ipaddress.ip_address('192.0.2.1'), {}), {}),
                         ipaddress.ip_address('192.0.2.1'))

        ipv6 = IPv6AddressField()
        self.assertEqual(ipv6.length, 16)
        self.assertEqual(ipv6.unpack(ipv6.pack(ipaddress.ip_address('2001:db8::1'), {}), {}),
                         ipaddress.ip_address('2001:db8::1'))

        with self.assertRaises(FieldValueError):
            ipv4.pre_process('2001:db8::1', {})
        with self.assertRaises(FieldValueError):
            ipv6.pre_process('192.0.2.1', {})

    def test_ipv6_interface_round_trips_every_prefix_length(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv6InterfaceField

        field = IPv6InterfaceField()
        self.assertEqual(field.length, 17)

        for prefixlen in range(129):
            interface = ipaddress.ip_interface(f'2001:db8:85a3:8d3:1319:8a2e:370:7344/{prefixlen}')
            raw = field.pack(interface, {})

            self.assertEqual(len(raw), 17, msg=f'/{prefixlen} packed to {len(raw)} octets')
            self.assertEqual(raw[:16], interface.ip.packed,
                             msg=f'/{prefixlen} packed the wrong address')
            self.assertEqual(raw[16], prefixlen,
                             msg=f'/{prefixlen} wrote prefix length octet {raw[16]:#04x}')
            self.assertEqual(field.unpack(raw, {}), interface,
                             msg=f'/{prefixlen} did not survive the round trip')

    def test_ipv6_interface_prefix_length_octet_matches_specification(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv6InterfaceField

        field = IPv6InterfaceField()
        interface = ipaddress.ip_interface(SPEC_INTERFACE)

        self.assertEqual(field.pack(interface, {}), SPEC_ENCODING)
        self.assertEqual(field.unpack(SPEC_ENCODING, {}), interface)
        self.assertEqual(field.unpack(SPEC_ENCODING, {}).network.prefixlen, 64)

    def test_ipv6_interface_does_not_read_prefix_length_octet_as_an_ascii_digit(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv6InterfaceField

        field = IPv6InterfaceField()
        for prefixlen in ASCII_DIGIT_PREFIX_LENGTHS:
            with self.subTest(prefixlen=prefixlen):
                interface = ipaddress.ip_interface(f'2001:db8::1/{prefixlen}')
                raw = field.pack(interface, {})

                # the octet really is an ASCII digit, which is why these ten used
                # to parse while every other prefix length raised
                self.assertIn(raw[16:], [str(digit).encode() for digit in range(10)])

                parsed = field.unpack(raw, {})
                self.assertEqual(parsed, interface)
                self.assertEqual(parsed.network.prefixlen, prefixlen)
                # the old ASCII reading decoded /48../57 as /0../9
                self.assertNotEqual(parsed.network.prefixlen, prefixlen - 48)

    def test_ipv6_interface_rejects_out_of_range_prefix_length(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv6InterfaceField
        from pcapkit.utilities.exceptions import FieldValueError

        field = IPv6InterfaceField()
        address = ipaddress.IPv6Address('2001:db8::1').packed

        for prefixlen in (129, 200, 255):
            with self.subTest(prefixlen=prefixlen):
                with self.assertRaises(FieldValueError) as context:
                    field.unpack(address + bytes([prefixlen]), {})
                self.assertIn(str(prefixlen), str(context.exception))

    def test_ipv6_interface_rejects_the_other_version(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv6InterfaceField
        from pcapkit.utilities.exceptions import FieldValueError

        with self.assertRaises(FieldValueError):
            IPv6InterfaceField().pre_process('192.0.2.1/24', {})

    def test_ipv4_interface_round_trips_every_prefix_length_as_a_netmask(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv4InterfaceField

        field = IPv4InterfaceField()
        self.assertEqual(field.length, 8)

        for prefixlen in range(33):
            interface = ipaddress.ip_interface(f'192.0.2.1/{prefixlen}')
            raw = field.pack(interface, {})

            self.assertEqual(len(raw), 8, msg=f'/{prefixlen} packed to {len(raw)} octets')
            self.assertEqual(raw[:4], interface.ip.packed,
                             msg=f'/{prefixlen} packed the wrong address')
            # the IPv4 option carries a dotted netmask, not a prefix length --
            # the two interface fields are deliberately not interchangeable
            self.assertEqual(raw[4:], interface.netmask.packed,
                             msg=f'/{prefixlen} wrote {raw[4:].hex()} instead of a netmask')
            self.assertEqual(field.unpack(raw, {}), interface,
                             msg=f'/{prefixlen} did not survive the round trip')

    def test_interface_field_encodings_are_not_interchangeable(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv4InterfaceField, IPv6InterfaceField

        ipv4 = IPv4InterfaceField().pack(ipaddress.ip_interface('192.0.2.1/24'), {})
        ipv6 = IPv6InterfaceField().pack(ipaddress.ip_interface('2001:db8::1/24'), {})

        # /24 as four netmask octets on one side, as a single binary octet on the other
        self.assertEqual(ipv4[4:], b'\xff\xff\xff\x00')
        self.assertEqual(ipv6[16:], b'\x18')

    def test_ipv4_interface_rejects_the_other_version(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv4InterfaceField
        from pcapkit.utilities.exceptions import FieldValueError

        with self.assertRaises(FieldValueError):
            IPv4InterfaceField().pre_process('2001:db8::1/64', {})


if __name__ == '__main__':
    unittest.main()
