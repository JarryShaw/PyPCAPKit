# -*- coding: utf-8 -*-
"""The IP pseudo-header packs to the octets the upper-layer checksum covers.

GitHub issue #2471: :class:`~pcapkit.protocols.internet.ip_pseudo.IP_Pseudo` is
built from a parsed IPv4 or IPv6 layer, or from explicit values, and packs to
the :rfc:`793#section-3.1` or :rfc:`8200#section-8.1` layout.

The captured cases come from the tracked :file:`examples/captures/in.pcap` and
:file:`examples/captures/dhcp.pcapng`. Each expected pseudo-header is sliced
from the captured IP header by hand, and the one's-complement sum over it and
the upper-layer octets is checked against the sender's own checksum.

"""
from __future__ import annotations

import importlib.util
import io
import ipaddress
import unittest
import warnings

from tests._support import reimport_once_per_class, sample_path

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Ethernet header length.
ETH = 14


def ones_complement_sum(octets: bytes) -> int:
    """Return the 16-bit one's-complement sum of ``octets``, :rfc:`1071`."""
    if len(octets) % 2:
        octets += b'\x00'
    total = sum(int.from_bytes(octets[i:i + 2], 'big') for i in range(0, len(octets), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def expected_ipv4(ip: bytes) -> bytes:
    """Slice the IPv4 pseudo-header out of a captured IPv4 header without options."""
    upper = int.from_bytes(ip[2:4], 'big') - (ip[0] & 0x0F) * 4
    return ip[12:16] + ip[16:20] + b'\x00' + ip[9:10] + upper.to_bytes(2, 'big')


def expected_ipv6(ip: bytes) -> bytes:
    """Slice the IPv6 pseudo-header out of a captured IPv6 header with no extension header."""
    return ip[8:24] + ip[24:40] + bytes(2) + ip[4:6] + bytes(3) + ip[6:7]


def ethernet_frames(name: str) -> 'list[bytes]':
    """Return the Ethernet frames of a tracked capture."""
    import pcapkit

    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        extraction = pcapkit.extract(fin=sample_path(name), nofile=True, store=True,
                                     engine='default', verbose=False)
    return [frame.info.packet for frame in extraction.frame]


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPPseudoCapturedTests(unittest.TestCase):
    """Pseudo-headers built from captured IPv4 and IPv6 layers."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def check(self, frame: bytes, version: int, expected: bytes) -> None:
        from pcapkit.protocols.internet.ip_pseudo import IP_Pseudo
        from pcapkit.protocols.link.ethernet import Ethernet

        ip = Ethernet(frame)[f'IPv{version}']
        pseudo = IP_Pseudo(ip=ip)

        self.assertEqual(pseudo.data, expected)
        self.assertEqual(pseudo.version, version)
        self.assertEqual(ones_complement_sum(pseudo.data + bytes(ip.payload)), 0xFFFF)

    def test_ipv4_tcp(self) -> None:
        frame = ethernet_frames('in.pcap')[2]
        expected = expected_ipv4(frame[ETH:])
        self.assertEqual(expected, bytes.fromhex('7b81d287' 'c0a80164' '00' '06' '0014'))
        self.check(frame, 4, expected)

    def test_ipv4_udp(self) -> None:
        frame = ethernet_frames('dhcp.pcapng')[0]
        expected = expected_ipv4(frame[ETH:])
        self.assertEqual(expected, bytes.fromhex('00000000' 'ffffffff' '00' '11' '0118'))
        self.check(frame, 4, expected)

    def test_ipv6_icmpv6(self) -> None:
        for number in (0, 1):
            frame = ethernet_frames('in.pcap')[number]
            with self.subTest(frame=number):
                self.assertEqual(frame[ETH + 6], 58)
                self.check(frame, 6, expected_ipv6(frame[ETH:]))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPPseudoUnitTests(unittest.TestCase):
    """Pseudo-headers built from explicit values and constructed layers."""

    #: IPv6 addresses of the IPv6 cases.
    SRC6 = '2001:db8::1'
    DST6 = '2001:db8::2'
    #: Their packed octets.
    ADDRS6 = ipaddress.IPv6Address(SRC6).packed + ipaddress.IPv6Address(DST6).packed

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_explicit_ipv4(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ip_pseudo import IP_Pseudo

        pseudo = IP_Pseudo(src='192.0.2.1', dst='198.51.100.2', protocol=TransType.UDP, upper_length=28)
        self.assertEqual(pseudo.data, bytes.fromhex('c0000201' 'c6336402' '00' '11' '001c'))
        self.assertEqual(len(pseudo), 12)
        self.assertEqual(pseudo.length, 12)
        self.assertEqual(pseudo.protocol, TransType.UDP)

    def test_explicit_ipv6(self) -> None:
        from pcapkit.protocols.internet.ip_pseudo import IP_Pseudo

        pseudo = IP_Pseudo(src=self.SRC6, dst=self.DST6, protocol='TCP', upper_length=0x10203)
        self.assertEqual(pseudo.data, self.ADDRS6 + bytes.fromhex('00010203' '000000' '06'))
        self.assertEqual(pseudo.length, 40)
        self.assertEqual(pseudo.src, ipaddress.IPv6Address(self.SRC6))
        self.assertEqual(pseudo.dst, ipaddress.IPv6Address(self.DST6))

    def test_protocol_namespace(self) -> None:
        from pcapkit.protocols.internet.ip_pseudo import IP_Pseudo

        pseudo = IP_Pseudo(src='10.0.0.1', dst='10.0.0.2', protocol='spam',
                           protocol_namespace={99: 'spam'}, upper_length=0)
        self.assertEqual(pseudo.data[9], 99)
        self.assertEqual(pseudo.read().protocol, 99)

    def test_make_read_round_trip(self) -> None:
        from pcapkit.protocols.internet.ip_pseudo import IP_Pseudo

        for made in (IP_Pseudo(src='10.0.0.1', dst='10.0.0.2', protocol=6, upper_length=40),
                     IP_Pseudo(src=self.SRC6, dst=self.DST6, protocol=17, upper_length=8)):
            with self.subTest(version=made.version):
                parsed = IP_Pseudo(made.data)
                self.assertEqual(parsed.info, made.info)
                self.assertEqual(bytes(IP_Pseudo.from_data(parsed.info)), made.data)

    def test_nonzero_reserved_octets_round_trip(self) -> None:
        from pcapkit.protocols.internet.ip_pseudo import IP_Pseudo

        for octets in (bytes.fromhex('0a000001' '0a000002' 'ff' '06' '0014'),
                       self.ADDRS6 + bytes.fromhex('00000008' 'abcdef' '11')):
            with self.subTest(length=len(octets)):
                parsed = IP_Pseudo(octets)
                self.assertEqual(bytes(IP_Pseudo.from_data(parsed.info)), octets)

    def test_explicit_values_override_the_layer(self) -> None:
        from pcapkit.protocols.internet.ip_pseudo import IP_Pseudo
        from pcapkit.protocols.internet.ipv4 import IPv4

        ip = IPv4(src='10.0.0.1', dst='10.0.0.2', protocol='TCP', payload=bytes(20))
        self.assertEqual(IP_Pseudo(ip=ip).data, bytes.fromhex('0a000001' '0a000002' '00' '06' '0014'))
        self.assertEqual(IP_Pseudo(ip=ip, dst='10.0.0.3', upper_length=7).data,
                         bytes.fromhex('0a000001' '0a000003' '00' '06' '0007'))

    def test_ipv6_extension_headers_are_skipped(self) -> None:
        from pcapkit.protocols.internet.ip_pseudo import IP_Pseudo
        from pcapkit.protocols.internet.ipv6 import IPv6

        # Hop-by-Hop Options (next UDP, one PadN) ahead of an 8-octet UDP header.
        hopopt = bytes.fromhex('1100' '0104' '00000000')
        udp = bytes.fromhex('0035' '0035' '0008' '0000')
        ip = IPv6(bytes.fromhex('60000000' '0010' '00' '40') + self.ADDRS6 + hopopt + udp)

        self.assertEqual(IP_Pseudo(ip=ip).data, self.ADDRS6 + bytes.fromhex('00000008' '000000' '11'))

    def test_ipv6_routing_header_final_destination(self) -> None:
        from pcapkit.protocols.internet.ip_pseudo import IP_Pseudo
        from pcapkit.protocols.internet.ipv6 import IPv6

        final = ipaddress.IPv6Address('2001:db8::99').packed
        # Type 0 Routing header, one segment left, next UDP.
        route = bytes.fromhex('1102' '0001' '00000000') + final
        udp = bytes.fromhex('0035' '0035' '0008' '0000')
        ip = IPv6(bytes.fromhex('60000000' '0020' '2b' '40') + self.ADDRS6 + route + udp)

        expected = ipaddress.IPv6Address(self.SRC6).packed + final + bytes.fromhex('00000008' '000000' '11')
        self.assertEqual(IP_Pseudo(ip=ip).data, expected)

        # Type 2 Routing header (RFC 6275), which carries one address.
        type2 = bytes.fromhex('1102' '0201' '00000000') + final
        ip2 = IPv6(bytes.fromhex('60000000' '0020' '2b' '40') + self.ADDRS6 + type2 + udp)
        self.assertEqual(IP_Pseudo(ip=ip2).data, expected)

        # NOTE: No segment left: the header's own destination is the final one.
        done = bytearray(ip.data)
        done[40 + 3] = 0
        self.assertEqual(IP_Pseudo(ip=IPv6(bytes(done))).data, self.ADDRS6 + bytes.fromhex('00000008' '000000' '11'))

    def test_rejections(self) -> None:
        from pcapkit.protocols.internet.ip_pseudo import IP_Pseudo
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.utilities.exceptions import FieldValueError, ProtocolError, UnsupportedCall

        with self.assertRaisesRegex(ProtocolError, 'invalid length 13'):
            IP_Pseudo(bytes(13))
        with self.assertRaisesRegex(ProtocolError, 'invalid length 13'):
            IP_Pseudo(io.BytesIO(bytes(40)), length=13)
        self.assertEqual(IP_Pseudo(io.BytesIO(bytes(41)), length=40).version, 6)
        with self.assertRaisesRegex(ProtocolError, 'required without ip'):
            IP_Pseudo(src='10.0.0.1', dst='10.0.0.2', protocol=6)
        with self.assertRaisesRegex(ProtocolError, 'unsupported enclosing layer Raw'):
            IP_Pseudo(ip=Raw(b''))
        with self.assertRaises(FieldValueError):
            IP_Pseudo(src='10.0.0.1', dst='::2', protocol=6, upper_length=0)
        with self.assertRaises(UnsupportedCall):
            IP_Pseudo.__index__()

    def test_name_and_chain(self) -> None:
        from pcapkit.protocols.internet.ip_pseudo import IP_Pseudo
        from pcapkit.protocols.misc.null import NoPayload

        pseudo = IP_Pseudo(src='10.0.0.1', dst='10.0.0.2', protocol=6, upper_length=20)
        self.assertEqual(pseudo.name, 'IP Pseudo-Header')
        self.assertIsInstance(pseudo.payload, NoPayload)
        self.assertEqual(pseudo.protochain.protocols, (IP_Pseudo,))
        self.assertEqual(pseudo.__length_hint__(), 12)


if __name__ == '__main__':
    unittest.main()
