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
        from pcapkit.protocols.internet.ip_pseudo import IP_Pseudo

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
        from pcapkit.protocols.internet.ip_pseudo import IP_Pseudo

        opts = bytes.fromhex('1102' '01020000' 'c910' '20010db8000000000000000000000077')
        ip = self.ipv6(0x3C, opts + bytes.fromhex('003500350008a389'))
        self.verify(ip, bytes.fromhex('20010db8000000000000000000000077') + self.DST6
                    + bytes.fromhex('00000008' '000000' '11'))
        self.assertEqual(IP_Pseudo(ip=ip, src='2001:db8::1').data[:16], self.SRC6)
        padded = self.ipv6(0x3C, bytes.fromhex('1100' '0104' '00000000') + self.UDP)
        self.assertEqual(IP_Pseudo(ip=padded).data[:16], self.SRC6)

    def test_segment_routing_header(self) -> None:
        from pcapkit.protocols.internet.ip_pseudo import IP_Pseudo
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
        from pcapkit.protocols.internet.ip_pseudo import IP_Pseudo
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
        from pcapkit.protocols.internet.ip_pseudo import IP_Pseudo
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
        from pcapkit.protocols.internet.ip_pseudo import IP_Pseudo
        from pcapkit.utilities.exceptions import ProtocolError

        # Hop-by-Hop Options with a Jumbo Payload option, then UDP of 65,544 octets.
        jumbo = 8 + 8 + 65536
        hopopt = bytes.fromhex('1100' 'c204') + jumbo.to_bytes(4, 'big')
        ip = self.ipv6(0x00, hopopt + bytes.fromhex('00350035' '00000000') + bytes(65536), payload=0)
        self.assertEqual(IP_Pseudo(ip=ip).data[32:], (jumbo - 8).to_bytes(4, 'big') + bytes.fromhex('000000' '11'))

        with self.assertRaisesRegex(ProtocolError, 'Payload Length 0 and no Jumbo Payload option'):
            IP_Pseudo(ip=self.ipv6(0x11, self.UDP, payload=0))

    def test_upper_length_range(self) -> None:
        from pcapkit.protocols.internet.ip_pseudo import IP_Pseudo
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.utilities.exceptions import FieldValueError

        for src, limit in (('10.0.0.1', 0xFFFF), ('::1', 0xFFFFFFFF)):
            dst = '10.0.0.2' if src == '10.0.0.1' else '::2'
            with self.subTest(src=src):
                self.assertEqual(IP_Pseudo(src=src, dst=dst, protocol=6, upper_length=limit).info.len, limit)
                for value in (limit + 1, -1):
                    with self.assertRaisesRegex(FieldValueError, f'length {value} out of range'):
                        IP_Pseudo(src=src, dst=dst, protocol=6, upper_length=value)

        # Total Length 0, as a TSO capture has it.
        ip = IPv4(bytes.fromhex('450000000001000040118e99c0000201c6336402') + self.UDP)
        with self.assertRaisesRegex(FieldValueError, 'length -20 out of range'):
            IP_Pseudo(ip=ip)

    def test_zero_is_kept_at_the_layout_width(self) -> None:
        from pcapkit.protocols.internet.ip_pseudo import IP_Pseudo

        ipv4 = IP_Pseudo(src='10.0.0.1', dst='10.0.0.2', protocol=6, upper_length=20, zero=b'\xaa\xbb')
        self.assertEqual(ipv4.data, bytes.fromhex('0a000001' '0a000002' 'aa' '06' '0014'))
        self.assertEqual(ipv4.info.zero, b'\xaa')
        for zero, kept in ((b'\xaa\xbb\xcc\xdd', 'aabbcc'), (b'\xaa', 'aa0000')):
            with self.subTest(zero=zero):
                ipv6 = IP_Pseudo(src='::1', dst='::2', protocol=6, upper_length=20, zero=zero)
                self.assertEqual(ipv6.data[32:], bytes.fromhex('00000014') + bytes.fromhex(kept) + b'\x06')
                self.assertEqual(ipv6.info.zero, bytes.fromhex(kept))

    def test_each_value_is_required_without_ip(self) -> None:
        from pcapkit.protocols.internet.ip_pseudo import IP_Pseudo
        from pcapkit.utilities.exceptions import ProtocolError

        values = {'src': '10.0.0.1', 'dst': '10.0.0.2', 'protocol': 6, 'upper_length': 20}
        for missing in values:
            with self.subTest(missing=missing):
                with self.assertRaisesRegex(ProtocolError, 'required without ip'):
                    IP_Pseudo(**{key: value for key, value in values.items() if key != missing})

    def test_octets_must_match_the_length(self) -> None:
        from pcapkit.protocols.internet.ip_pseudo import IP_Pseudo
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaisesRegex(ProtocolError, 'invalid length 0; expected 12 or 40'):
            IP_Pseudo(b'')
        with self.assertRaisesRegex(ProtocolError, 'invalid length 0; expected 12 or 40'):
            IP_Pseudo(io.BytesIO(b''))
        with self.assertRaisesRegex(ProtocolError, 'length 12 disagrees with 40 octets'):
            IP_Pseudo(bytes(40), length=12)
        with self.assertRaisesRegex(ProtocolError, 'length 12 disagrees with 5 octets'):
            IP_Pseudo(io.BytesIO(bytes(5)), length=12)


if __name__ == '__main__':
    unittest.main()
