# -*- coding: utf-8 -*-
"""The IP pseudo-header packs to the octets the upper-layer checksum covers.

GitHub issue #2471: :class:`~pcapkit.protocols.misc.checksum.ip_pseudo.IP_Pseudo` is
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
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
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
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo

        pseudo = IP_Pseudo(src='192.0.2.1', dst='198.51.100.2', protocol=TransType.UDP, upper_length=28)
        self.assertEqual(pseudo.data, bytes.fromhex('c0000201' 'c6336402' '00' '11' '001c'))
        self.assertEqual(len(pseudo), 12)
        self.assertEqual(pseudo.length, 12)
        self.assertEqual(pseudo.protocol, TransType.UDP)

    def test_explicit_ipv6(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo

        pseudo = IP_Pseudo(src=self.SRC6, dst=self.DST6, protocol='TCP', upper_length=0x10203)
        self.assertEqual(pseudo.data, self.ADDRS6 + bytes.fromhex('00010203' '000000' '06'))
        self.assertEqual(pseudo.length, 40)
        self.assertEqual(pseudo.src, ipaddress.IPv6Address(self.SRC6))
        self.assertEqual(pseudo.dst, ipaddress.IPv6Address(self.DST6))

    def test_protocol_namespace(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo

        pseudo = IP_Pseudo(src='10.0.0.1', dst='10.0.0.2', protocol='spam',
                           protocol_namespace={99: 'spam'}, upper_length=0)
        self.assertEqual(pseudo.data[9], 99)
        self.assertEqual(pseudo.read().protocol, 99)

    def test_make_read_round_trip(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo

        for made in (IP_Pseudo(src='10.0.0.1', dst='10.0.0.2', protocol=6, upper_length=40),
                     IP_Pseudo(src=self.SRC6, dst=self.DST6, protocol=17, upper_length=8)):
            with self.subTest(version=made.version):
                parsed = IP_Pseudo(made.data)
                self.assertEqual(parsed.info, made.info)
                self.assertEqual(bytes(IP_Pseudo.from_data(parsed.info)), made.data)

    def test_nonzero_reserved_octets_round_trip(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo

        for octets in (bytes.fromhex('0a000001' '0a000002' 'ff' '06' '0014'),
                       self.ADDRS6 + bytes.fromhex('00000008' 'abcdef' '11')):
            with self.subTest(length=len(octets)):
                parsed = IP_Pseudo(octets)
                self.assertEqual(bytes(IP_Pseudo.from_data(parsed.info)), octets)

    def test_explicit_values_override_the_layer(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
        from pcapkit.protocols.internet.ipv4 import IPv4

        ip = IPv4(src='10.0.0.1', dst='10.0.0.2', protocol='TCP', payload=bytes(20))
        self.assertEqual(IP_Pseudo(ip=ip).data, bytes.fromhex('0a000001' '0a000002' '00' '06' '0014'))
        self.assertEqual(IP_Pseudo(ip=ip, dst='10.0.0.3', upper_length=7).data,
                         bytes.fromhex('0a000001' '0a000003' '00' '06' '0007'))

    def test_ipv6_extension_headers_are_skipped(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
        from pcapkit.protocols.internet.ipv6 import IPv6

        # Hop-by-Hop Options (next UDP, one PadN) ahead of an 8-octet UDP header.
        hopopt = bytes.fromhex('1100' '0104' '00000000')
        udp = bytes.fromhex('0035' '0035' '0008' '0000')
        ip = IPv6(bytes.fromhex('60000000' '0010' '00' '40') + self.ADDRS6 + hopopt + udp)

        self.assertEqual(IP_Pseudo(ip=ip).data, self.ADDRS6 + bytes.fromhex('00000008' '000000' '11'))

    def test_ipv6_routing_header_final_destination(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
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
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
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
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
        from pcapkit.protocols.misc.null import NoPayload

        pseudo = IP_Pseudo(src='10.0.0.1', dst='10.0.0.2', protocol=6, upper_length=20)
        self.assertEqual(pseudo.name, 'IP Pseudo-Header')
        self.assertIsInstance(pseudo.payload, NoPayload)
        self.assertEqual(pseudo.protochain.protocols, (IP_Pseudo,))
        self.assertEqual(pseudo.__length_hint__(), 12)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPPseudoBoundaryTests(unittest.TestCase):
    """Values an IP layer does not determine, and values out of range.

    The packets are built by scapy, whose checksums the pseudo-headers verify.

    """

    SRC6 = ipaddress.IPv6Address('2001:db8::1').packed
    DST6 = ipaddress.IPv6Address('2001:db8::2').packed
    #: An 8-octet UDP header, ports 53, with no checksum.
    UDP = bytes.fromhex('0035' '0035' '0008' '0000')

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def ipv6(self, next_: int, rest: bytes, payload: 'int | None' = None) -> object:
        from pcapkit.protocols.internet.ipv6 import IPv6

        length = len(rest) if payload is None else payload
        return IPv6(bytes.fromhex('60000000') + length.to_bytes(2, 'big') + bytes([next_, 64])
                    + self.SRC6 + self.DST6 + rest)

    def verify(self, ip: object, expected: bytes) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo

        pseudo = IP_Pseudo(ip=ip)
        self.assertEqual(pseudo.data, expected)
        self.assertEqual(ones_complement_sum(pseudo.data + bytes(ip.payload)), 0xFFFF)  # type: ignore[attr-defined]

    def test_ipv4_options_excluded_from_length(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4

        ip = IPv4(bytes.fromhex('460000230001000040118b91c0000201c6336402' '01010100'
                                '00350035000b4ed4616263'))
        self.verify(ip, bytes.fromhex('c0000201' 'c6336402' '00' '11' '000b'))

    def test_routing_header_last_address(self) -> None:
        # Type 0 Routing header, two addresses, two segments left.
        route = bytes.fromhex('1104' '0002' '00000000'
                              '20010db8000000000000000000000098' '20010db8000000000000000000000099')
        ip = self.ipv6(0x2B, route + bytes.fromhex('003500350008a368'))
        self.verify(ip, self.SRC6 + bytes.fromhex('20010db8000000000000000000000099' '00000008' '000000' '11'))

    def test_home_address_option_source(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo

        opts = bytes.fromhex('1102' '01020000' 'c910' '20010db8000000000000000000000077')
        ip = self.ipv6(0x3C, opts + bytes.fromhex('003500350008a389'))
        self.verify(ip, bytes.fromhex('20010db8000000000000000000000077') + self.DST6
                    + bytes.fromhex('00000008' '000000' '11'))
        self.assertEqual(IP_Pseudo(ip=ip, src='2001:db8::1').data[:16], self.SRC6)
        padded = self.ipv6(0x3C, bytes.fromhex('1100' '0104' '00000000') + self.UDP)
        self.assertEqual(IP_Pseudo(ip=padded).data[:16], self.SRC6)

    def test_segment_routing_header(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
        from pcapkit.utilities.exceptions import ProtocolError

        # Segment Routing Header, Segment List[0] 2001:db8::99, one segment left.
        srh = bytes.fromhex('1104' '0401' '01000000'
                            '20010db8000000000000000000000099' '20010db8000000000000000000000002')
        ip = self.ipv6(0x2B, srh + self.UDP)
        with self.assertRaisesRegex(ProtocolError, 'Routing type 4 not parsed; give dst'):
            IP_Pseudo(ip=ip)
        self.assertEqual(IP_Pseudo(ip=ip, dst='2001:db8::99').data[16:32], srh[8:24])

        done = bytearray(srh)
        done[3] = 0
        self.assertEqual(IP_Pseudo(ip=self.ipv6(0x2B, bytes(done) + self.UDP)).data[16:32], self.DST6)

    def test_fragments_need_the_reassembled_length(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.utilities.exceptions import ProtocolError

        first = self.ipv6(0x2C, bytes.fromhex('1100' '0001' '00000005') + self.UDP)
        later = IPv4(bytes.fromhex('4500001c0001000140008ea9c0000201c6336402') + bytes(8))
        more = IPv4(bytes.fromhex('4500001c000120004011' '0000' 'c0000201c6336402') + self.UDP)
        for ip in (first, later, more):
            with self.subTest(ip=ip):
                with self.assertRaisesRegex(ProtocolError, 'fragment; give upper_length'):
                    IP_Pseudo(ip=ip)
                self.assertEqual(IP_Pseudo(ip=ip, upper_length=9).info.len, 9)

        # An atomic fragment is a whole packet.
        atomic = self.ipv6(0x2C, bytes.fromhex('1100' '0000' '00000005') + bytes.fromhex('003500350008a3ff'))
        self.verify(atomic, self.SRC6 + self.DST6 + bytes.fromhex('00000008' '000000' '11'))

    def test_unparsed_next_header(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
        from pcapkit.utilities.exceptions import ProtocolError

        # ESP, SPI 1, sequence 1, encrypted.
        ip = self.ipv6(0x32, bytes.fromhex('00000001' '00000001') + bytes(16))
        for kwargs in ({}, {'protocol': 50}, {'upper_length': 24}):
            with self.subTest(**kwargs):
                with self.assertRaisesRegex(ProtocolError, 'upper layer of IPv6 not parsed'):
                    IP_Pseudo(ip=ip, **kwargs)
        self.assertEqual(IP_Pseudo(ip=ip, protocol=50, upper_length=24).data[-8:],
                         bytes.fromhex('00000018' '000000' '32'))

    def test_jumbogram(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
        from pcapkit.utilities.exceptions import ProtocolError

        # Hop-by-Hop Options with a Jumbo Payload option, then UDP of 65,544 octets.
        jumbo = 8 + 8 + 65536
        hopopt = bytes.fromhex('1100' 'c204') + jumbo.to_bytes(4, 'big')
        ip = self.ipv6(0x00, hopopt + bytes.fromhex('00350035' '00000000') + bytes(65536), payload=0)
        self.assertEqual(IP_Pseudo(ip=ip).data[32:], (jumbo - 8).to_bytes(4, 'big') + bytes.fromhex('000000' '11'))

        with self.assertRaisesRegex(ProtocolError, 'Payload Length 0 and no Jumbo Payload option'):
            IP_Pseudo(ip=self.ipv6(0x11, self.UDP, payload=0))

    def test_upper_length_range(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.utilities.exceptions import FieldValueError

        for src, limit in (('10.0.0.1', 0xFFFF), ('::1', 0xFFFFFFFF)):
            dst = '10.0.0.2' if src == '10.0.0.1' else '::2'
            with self.subTest(src=src):
                self.assertEqual(IP_Pseudo(src=src, dst=dst, protocol=6, upper_length=limit).info.len, limit)
                for value in (limit + 1, -1):
                    with self.assertRaisesRegex(FieldValueError, f'length {value} out of range'):
                        IP_Pseudo(src=src, dst=dst, protocol=6, upper_length=value)

        # Total Length 0, as a TSO capture has it: the UDP Length field gives the length.
        ip = IPv4(bytes.fromhex('450000000001000040118e99c0000201c6336402') + self.UDP)
        self.assertEqual(IP_Pseudo(ip=ip).info.len, 8)

        # Without one, the IP layer's length is negative.
        tcp = IPv4(bytes.fromhex('450000000001000040068e99c0000201c6336402') + bytes(20))
        with self.assertRaisesRegex(FieldValueError, 'length -20 out of range'):
            IP_Pseudo(ip=tcp)

    def test_zero_is_kept_at_the_layout_width(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo

        ipv4 = IP_Pseudo(src='10.0.0.1', dst='10.0.0.2', protocol=6, upper_length=20, zero=b'\xaa\xbb')
        self.assertEqual(ipv4.data, bytes.fromhex('0a000001' '0a000002' 'aa' '06' '0014'))
        self.assertEqual(ipv4.info.zero, b'\xaa')
        for zero, kept in ((b'\xaa\xbb\xcc\xdd', 'aabbcc'), (b'\xaa', 'aa0000')):
            with self.subTest(zero=zero):
                ipv6 = IP_Pseudo(src='::1', dst='::2', protocol=6, upper_length=20, zero=zero)
                self.assertEqual(ipv6.data[32:], bytes.fromhex('00000014') + bytes.fromhex(kept) + b'\x06')
                self.assertEqual(ipv6.info.zero, bytes.fromhex(kept))

    def test_each_value_is_required_without_ip(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
        from pcapkit.utilities.exceptions import ProtocolError

        values = {'src': '10.0.0.1', 'dst': '10.0.0.2', 'protocol': 6, 'upper_length': 20}
        for missing in values:
            with self.subTest(missing=missing):
                with self.assertRaisesRegex(ProtocolError, 'required without ip'):
                    IP_Pseudo(**{key: value for key, value in values.items() if key != missing})

    def test_octets_must_match_the_length(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaisesRegex(ProtocolError, 'invalid length 0; expected 12 or 40'):
            IP_Pseudo(b'')
        with self.assertRaisesRegex(ProtocolError, 'invalid length 0; expected 12 or 40'):
            IP_Pseudo(io.BytesIO(b''))
        with self.assertRaisesRegex(ProtocolError, 'length 12 disagrees with 40 octets'):
            IP_Pseudo(bytes(40), length=12)
        with self.assertRaisesRegex(ProtocolError, 'length 12 disagrees with 5 octets'):
            IP_Pseudo(io.BytesIO(bytes(5)), length=12)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPPseudoWalkTests(unittest.TestCase):
    """Upper layers the IP walk gives wrong values for, and malformed headers.

    Each expected pseudo-header is spelled out from its RFC, not from the code.

    """

    SRC6 = ipaddress.IPv6Address('2001:db8::1').packed
    DST6 = ipaddress.IPv6Address('2001:db8::2').packed
    #: An 8-octet UDP header, ports 53, with no checksum.
    UDP = bytes.fromhex('0035' '0035' '0008' '0000')
    #: An 8-octet ICMPv6 echo request, whose checksum is not filled in.
    ICMPV6 = bytes.fromhex('8000' '0000' '00000000')

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def ipv6(self, next_: int, rest: bytes, payload: 'int | None' = None) -> object:
        from pcapkit.protocols.internet.ipv6 import IPv6

        length = len(rest) if payload is None else payload
        return IPv6(bytes.fromhex('60000000') + length.to_bytes(2, 'big') + bytes([next_, 64])
                    + self.SRC6 + self.DST6 + rest)

    @staticmethod
    def ipv4_route(kind: int, pointer: int, route: 'list[str]') -> object:
        """An IPv4 packet whose first hop is 192.0.2.10, with a source route option."""
        from pcapkit.protocols.internet.ipv4 import IPv4

        option = bytes([kind, 3 + 4 * len(route), pointer])
        option += b''.join(ipaddress.IPv4Address(address).packed for address in route)
        option += bytes(-len(option) % 4)
        header = (bytes([0x40 | (5 + len(option) // 4), 0]) + (20 + len(option) + 8).to_bytes(2, 'big')
                  + bytes(4) + bytes([64, 17, 0, 0]) + ipaddress.IPv4Address('10.0.0.1').packed
                  + ipaddress.IPv4Address('192.0.2.10').packed)
        return IPv4(header + option + bytes.fromhex('0035' '0035' '0008' '0000'))

    @staticmethod
    def ipv4(proto: int, rest: bytes) -> object:
        """An IPv4 packet from 192.0.2.1 to 198.51.100.2 carrying ``rest``."""
        from pcapkit.protocols.internet.ipv4 import IPv4

        header = (bytes([0x45, 0]) + (20 + len(rest)).to_bytes(2, 'big') + bytes(4)
                  + bytes([64, proto, 0, 0]) + ipaddress.IPv4Address('192.0.2.1').packed
                  + ipaddress.IPv4Address('198.51.100.2').packed)
        return IPv4(header + rest)

    def test_udp_length_field(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
        from pcapkit.protocols.internet.ipv4 import IPv4

        # The UDP Length field is 8, though the IP layer carries 12 octets (RFC 768).
        ip = self.ipv6(17, self.UDP + bytes(4))
        self.assertEqual(IP_Pseudo(ip=ip).data[32:], bytes.fromhex('00000008' '000000' '11'))

        ipv4 = IPv4(bytes.fromhex('45000020' '00010000' '4011' '0000' 'c0000201' 'c6336402')
                    + self.UDP + bytes(4))
        self.assertEqual(IP_Pseudo(ip=ipv4).info.len, 8)

    def test_source_route_final_destination(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo

        # LSR (131) and SSR (137). With the pointer on or before the last address,
        # that address is the destination; once the route is exhausted (RFC 791
        # section 3.1), the destination field is.
        for kind in (131, 137):
            for pointer, final in ((4, '192.0.2.30'), (8, '192.0.2.30'), (12, '192.0.2.10')):
                with self.subTest(kind=kind, pointer=pointer):
                    ip = self.ipv4_route(kind, pointer, ['192.0.2.20', '192.0.2.30'])
                    self.assertEqual(ip.info.dst, ipaddress.IPv4Address('192.0.2.10'))  # type: ignore[attr-defined]
                    self.assertEqual(IP_Pseudo(ip=ip).data[4:8],  # type: ignore[arg-type]
                                     ipaddress.IPv4Address(final).packed)

    def test_source_route_without_addresses_keeps_the_header_destination(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo

        ip = self.ipv4_route(131, 4, [])
        self.assertEqual(IP_Pseudo(ip=ip).data[4:8], ipaddress.IPv4Address('192.0.2.10').packed)

    def test_udp_length_after_an_atomic_fragment(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo

        # An atomic fragment (Offset 0, More Fragments clear) whose Next Header is
        # Destination Options, then UDP. The UDP header sits 16 octets past the
        # fixed header, so its Length field is read from there (RFC 8200 section 4.5).
        fragment = bytes([60, 0]) + bytes.fromhex('0000' '01020304')
        # Tunnel Encapsulation Limit (type 4), then Pad1s; non-zero, so a wrong offset shows.
        dest_opts = bytes([17, 0, 4, 1, 5, 0, 0, 0])
        ip = self.ipv6(44, fragment + dest_opts + self.UDP)
        self.assertEqual(IP_Pseudo(ip=ip).data[32:], bytes.fromhex('00000008' '000000' '11'))

    def test_authentication_header_is_walked(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
        from pcapkit.utilities.exceptions import ProtocolError

        # AH (RFC 4302 section 2.2): Next Header, then Payload Len in 32-bit words
        # less two, so 24 octets with a 12-octet ICV. Two nested, then UDP: the
        # upper layer is UDP, and the length is the UDP header's alone.
        first = bytes([51, 4]) + bytes(22)
        second = bytes([17, 4]) + bytes(22)
        pseudo = IP_Pseudo(ip=self.ipv4(51, first + second + self.UDP))
        self.assertEqual(pseudo.data[8:], bytes.fromhex('00' '11' '0008'))
        # A lone one cut short after its first octets.
        with self.assertRaisesRegex(ProtocolError, 'Authentication Header of IPv4 not parsed'):
            IP_Pseudo(ip=self.ipv4(51, bytes([17, 4]) + bytes(4)))

    def test_esp_is_never_walked(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
        from pcapkit.utilities.exceptions import ProtocolError

        # ESP (RFC 4303): the upper layer is encrypted, so an IPv4 packet with
        # one needs its protocol and length given, as an IPv6 packet does.
        with self.assertRaisesRegex(ProtocolError, 'upper layer of IPv4 not parsed'):
            IP_Pseudo(ip=self.ipv4(50, bytes(16)))
        self.assertEqual(IP_Pseudo(ip=self.ipv4(50, bytes(16)), protocol=50, upper_length=24)
                         .data[8:], bytes.fromhex('00' '32' '0018'))

    def test_authentication_header_over_tcp(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo

        # AH (RFC 4302) of 24 octets naming TCP, then a 20-octet TCP header: the length
        # is the TCP octets alone, not the 44 that a walk ignoring the AH would count.
        pseudo = IP_Pseudo(ip=self.ipv4(51, bytes([6, 4]) + bytes(22) + bytes(20)))
        self.assertEqual(pseudo.info.len, 20)
        self.assertEqual(pseudo.protocol, 6)

    def test_authentication_header_offsets_the_udp_length_field(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo

        # The UDP header follows the 24-octet AH; a walk that drops the AH reads the
        # Length field from the ICV, 0xAAAA, not 8. The 4 padding octets keep the two apart.
        ip = self.ipv4(51, bytes([17, 4]) + bytes([0xAA] * 22) + self.UDP + bytes(4))
        self.assertEqual(IP_Pseudo(ip=ip).data[8:], bytes.fromhex('00' '11' '0008'))

    def test_authentication_header_in_a_non_first_fragment_is_not_walked(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.utilities.exceptions import ProtocolError

        # Fragment Offset 1 (8 octets), More Fragments clear: the payload is a continuation,
        # not an AH header, so the 6 it starts with must not be read as the Next Header.
        payload = bytes([6, 4]) + bytes(22) + self.UDP
        header = (bytes([0x45, 0]) + (20 + len(payload)).to_bytes(2, 'big') + bytes(2)
                  + (1).to_bytes(2, 'big') + bytes([64, 51, 0, 0])
                  + ipaddress.IPv4Address('192.0.2.1').packed
                  + ipaddress.IPv4Address('198.51.100.2').packed)
        fragment = IPv4(header + payload)
        with self.assertRaisesRegex(ProtocolError, 'upper layer of IPv4 not parsed'):
            IP_Pseudo(ip=fragment, upper_length=8)
        self.assertEqual(IP_Pseudo(ip=fragment, protocol=51, upper_length=8).data[8:],
                         bytes.fromhex('00' '33' '0008'))

    def test_esp_under_ipv6_with_an_sa_is_never_walked(self) -> None:
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.esp import ESPContext, SecurityAssociation
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.utilities.exceptions import ProtocolError

        # ESP (SPI 0x4321, seq 1) under an ENCR_NULL SA, whose plaintext is UDP then a
        # trailer naming UDP. The SA gives the ESP header a Next Header of 17, which
        # the walk must not follow: the upper layer is encrypted (RFC 4303).
        packet = bytes.fromhex('00004321' '00000001') + self.UDP + bytes([0, 17])
        registry = ContextRegistry.make(ESPContext(SecurityAssociation(spi=0x4321)))
        ip = IPv6(bytes.fromhex('60000000') + len(packet).to_bytes(2, 'big') + bytes([50, 64])
                  + self.SRC6 + self.DST6 + packet, __context__=registry)
        with self.assertRaisesRegex(ProtocolError, 'upper layer of IPv6 not parsed'):
            IP_Pseudo(ip=ip)

    def test_truncated_udp_header_keeps_the_layer_length(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo

        # Payload Length 8, but the octets end before the UDP header does.
        ip = self.ipv6(17, b'', payload=8)
        self.assertEqual(IP_Pseudo(ip=ip).data[32:], bytes.fromhex('00000008' '000000' '11'))

    def test_mobility_header_and_hip_are_the_upper_layer(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo

        # Mobility Header, Next Header TCP, 8 octets: the chain ends at it, so it is
        # the upper layer, and the TCP named inside it is not (RFC 6275 section 6.1.1).
        ip = self.ipv6(135, bytes([6, 0, 5, 0]) + bytes(4))
        pseudo = IP_Pseudo(ip=ip)
        self.assertEqual(pseudo.data[32:], bytes.fromhex('00000008' '000000' '87'))
        self.assertEqual(pseudo.protocol, 135)

        # Headers after it are not walked past it: 8 octets of HIP ahead of 8 of UDP.
        ip = self.ipv6(139, bytes([17, 1, 0, 0, 0, 0, 0, 0]) + self.UDP)
        pseudo = IP_Pseudo(ip=ip)
        self.assertEqual(pseudo.data[32:], bytes.fromhex('00000010' '000000' '8b'))
        self.assertEqual(pseudo.protocol, 139)

    def test_extension_header_limit(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
        from pcapkit.utilities.exceptions import ProtocolError

        # The walk takes at most 32 headers; a 33rd Destination Options is unparsed.
        def chain(count: int) -> bytes:
            return b''.join(bytes([60 if index < count - 1 else 17, 0]) + bytes(6)
                            for index in range(count))

        self.assertEqual(IP_Pseudo(ip=self.ipv6(60, chain(32) + self.UDP)).info.len, 8)
        with self.assertRaisesRegex(ProtocolError, 'upper layer of IPv6 not parsed'):
            IP_Pseudo(ip=self.ipv6(60, chain(33) + self.UDP))

    def test_truncated_headers_are_unparsed(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
        from pcapkit.utilities.exceptions import ProtocolError

        # A Type 0 Routing header claiming two segments, cut by snaplen.
        with self.assertRaisesRegex(ProtocolError, 'Routing header of IPv6 not parsed; give dst'):
            IP_Pseudo(ip=self.ipv6(43, bytes([17, 2, 0, 1, 0, 0, 0, 0])))
        # A Fragment header cut by snaplen.
        with self.assertRaisesRegex(ProtocolError, 'upper layer of IPv6 not parsed'):
            IP_Pseudo(ip=self.ipv6(44, bytes([17, 0, 0, 0])))

    def test_malformed_extension_headers_raise_protocol_error(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
        from pcapkit.utilities.exceptions import ProtocolError

        # Destination Options whose length runs past the payload.
        with self.assertRaisesRegex(ProtocolError, 'Destination Options of IPv6 not parsed; give src'):
            IP_Pseudo(ip=self.ipv6(60, bytes([17, 2]) + bytes(22), payload=8))
        # A Type 0 Routing header with an odd Hdr Ext Len.
        with self.assertRaisesRegex(ProtocolError, 'Routing header of IPv6 not parsed; give dst'):
            IP_Pseudo(ip=self.ipv6(43, bytes([17, 1, 0, 1, 0, 0, 0, 0]) + bytes(8)))

    def test_last_fragment_needs_the_reassembled_length(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
        from pcapkit.utilities.exceptions import ProtocolError

        # Fragment Offset 1 (8 octets), More Fragments clear: the last fragment of a packet.
        last = self.ipv6(44, bytes([17, 0]) + bytes.fromhex('0008' '00000005') + self.UDP)
        with self.assertRaisesRegex(ProtocolError, 'fragment; give upper_length'):
            IP_Pseudo(ip=last)
        self.assertEqual(IP_Pseudo(ip=last, upper_length=8).info.len, 8)

    def test_extension_header_lengths_are_summed(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo

        # Hop-by-Hop Options, then Destination Options, then ICMPv6: 16 octets of
        # headers ahead of the 8-octet ICMPv6 message in a 24-octet payload. ICMPv6
        # has no length field, so the walk alone gives the 8.
        hop_by_hop = bytes([60, 0]) + bytes(6)
        dest_opts = bytes([58, 0]) + bytes(6)
        ip = self.ipv6(0, hop_by_hop + dest_opts + self.ICMPV6)
        self.assertEqual(IP_Pseudo(ip=ip).data[32:], bytes.fromhex('00000008' '000000' '3a'))

    def test_duplicate_header_types_are_each_summed(self) -> None:
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo

        # Two Destination Options headers, the second one carrying ICMPv6.
        first = bytes([60, 0]) + bytes(6)
        second = bytes([58, 0]) + bytes(6)
        ip = self.ipv6(60, first + second + self.ICMPV6)
        self.assertEqual(IP_Pseudo(ip=ip).data[32:], bytes.fromhex('00000008' '000000' '3a'))


if __name__ == '__main__':
    unittest.main()
