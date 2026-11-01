# -*- coding: utf-8 -*-
"""UDP verifies and computes its checksum over the IP pseudo-header.

GitHub issue #2474: the enclosing IPv4 or IPv6 layer verifies the UDP checksum
(:rfc:`768`) once parsed, under :data:`~pcapkit.utilities.config.CHECKSUM_VERIFY`,
and computes it for a datagram constructed as its payload under
:data:`~pcapkit.utilities.config.CHECKSUM_COMPUTE`. A zero checksum means none over
IPv4 and is wrong over IPv6 (:rfc:`8200#section-8.1`), and a computed zero is sent
as all ones. The captured datagram is from the tracked
:file:`examples/captures/in.pcap`; expected checksums are the hand-written sum of
``tests/foundation/_roundtrip.py`` over a hand-built pseudo-header.

"""
from __future__ import annotations

import importlib.util
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire

#: Test tier (#1958): hand-picked parse -> rebuild and make -> parse round trips.
__tier__ = 'ALL'

#: An IPv4 packet carrying UDP as captured (``in.pcap`` frame 5), a router's
#: broadcast to port 5001.
CAPTURED = bytes.fromhex(
    '4500009100004000401178b3c0a80101ffffffff92441389007d63b101010e00e12b83c7f98b0067000000'
    '06000a544c2d57445236333030000b0003362e3000070001010005001142382d46382d38332d41352d4639'
    '2d34370008000b3139322e3136382e312e310009000a74706c6f67696e2e636e000a000e544c2d57445236'
    '33303020362e30000c0005312e372e34'
)

HAS_SCAPY = importlib.util.find_spec('scapy') is not None


def pseudo4(src: bytes, dst: bytes, length: int) -> bytes:
    """The IPv4 pseudo-header of UDP (RFC 768)."""
    return src + dst + b'\x00\x11' + length.to_bytes(2, 'big')


def pseudo6(src: bytes, dst: bytes, length: int) -> bytes:
    """The IPv6 pseudo-header of UDP (RFC 8200 section 8.1)."""
    return src + dst + length.to_bytes(4, 'big') + b'\x00\x00\x00\x11'


def expected(prefix: bytes, datagram: bytes) -> bytes:
    """The checksum ``datagram`` should carry over ``prefix``; zero is sent as all ones."""
    value = wire.checksum(prefix + datagram[:6] + b'\x00\x00' + datagram[8:])
    return (value or 0xFFFF).to_bytes(2, 'big')


def with_checksum(packet: bytes, field: bytes, at: int) -> bytes:
    """``packet`` with ``field`` at ``at``."""
    return packet[:at] + field + packet[at + 2:]


class UDPChecksumTests(unittest.TestCase):
    """Verifying and computing the UDP checksum."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.misc.checksum.checksum import ChecksumStatus
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
        from pcapkit.protocols.transport.udp import UDP
        from pcapkit.utilities import config
        from pcapkit.utilities.warnings import ChecksumWarning, ProtocolWarning

        self.IPv4, self.IPv6, self.UDP, self.IP_Pseudo = IPv4, IPv6, UDP, IP_Pseudo
        self.Status = ChecksumStatus
        self.config = config
        self.ProtocolWarning = ProtocolWarning
        self.ChecksumWarning = ChecksumWarning

    def parse(self, octets: bytes, cls: 'type | None' = None, *,
              verify: bool = True) -> 'tuple[object, list[tuple[type, str]]]':
        """``octets`` parsed as ``cls``, IPv4 by default, and its ProtocolWarnings as ``(category, message)``."""
        with mock.patch.object(self.config, 'CHECKSUM_VERIFY', verify), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            layer = (cls or self.IPv4)(octets)
        return layer, [(item.category, str(item.message))
                       for item in caught if issubclass(item.category, self.ProtocolWarning)]

    def status(self, octets: bytes, **kwargs: object) -> 'tuple[object, list[tuple[type, str]]]':
        """The UDP checksum status of ``octets``, and its ProtocolWarnings as ``(category, message)``."""
        layer, messages = self.parse(octets, **kwargs)
        return layer['UDP'].info.get('checksum_status'), messages

    def make6(self, **kwargs: object) -> bytes:
        """The octets of an IPv6 packet carrying a UDP datagram made with ``kwargs``."""
        udp = self.UDP(srcport=40000, dstport=9, payload=b'hello', **kwargs)
        return self.IPv6(src='2001:db8::1', dst='2001:db8::2', next='UDP', payload=udp).data

    def test_the_captured_checksum_verifies(self) -> None:
        self.assertEqual(expected(pseudo4(CAPTURED[12:16], CAPTURED[16:20], 125), CAPTURED[20:]), CAPTURED[26:28])
        self.assertEqual(self.status(CAPTURED), (self.Status.VALID, []))

    def test_a_corrupted_checksum_warns(self) -> None:
        status, messages = self.status(with_checksum(CAPTURED, b'\x63\xb2', 26))
        self.assertIs(status, self.Status.INVALID)
        self.assertEqual(messages, [(self.ChecksumWarning, 'UDP: checksum 0x63b2 is wrong; 0x63b1 expected')])

    def test_zero_is_none_over_ipv4_only(self) -> None:
        self.assertEqual(self.status(with_checksum(CAPTURED, b'\x00\x00', 26)), (self.Status.NOT_COMPUTED, []))
        status, messages = self.status(with_checksum(self.make6(), b'\x00\x00', 46), cls=self.IPv6)
        self.assertIs(status, self.Status.INVALID)
        self.assertEqual([category for category, _ in messages], [self.ChecksumWarning])

    def test_offload_is_not_computed(self) -> None:
        prefix4 = pseudo4(CAPTURED[12:16], CAPTURED[16:20], 125)
        partial4 = (~wire.checksum(prefix4) & 0xFFFF).to_bytes(2, 'big')
        self.assertEqual(self.status(with_checksum(CAPTURED, partial4, 26)), (self.Status.NOT_COMPUTED, []))
        partial6 = (~wire.checksum(pseudo6(wire.IPV6_A, wire.IPV6_B, 13)) & 0xFFFF).to_bytes(2, 'big')
        self.assertEqual(self.status(with_checksum(self.make6(), partial6, 46), cls=self.IPv6),
                         (self.Status.NOT_COMPUTED, []))

    def test_a_first_fragment_has_no_pseudo_header(self) -> None:
        header = bytearray(CAPTURED[:6] + b'\x20\x00' + CAPTURED[8:10] + b'\x00\x00' + CAPTURED[12:20])
        header[10:12] = wire.checksum(bytes(header)).to_bytes(2, 'big')
        self.assertEqual(self.status(bytes(header) + CAPTURED[20:]), (self.Status.NO_PSEUDO_HEADER, []))

    def test_off_verifies_nothing(self) -> None:
        self.assertEqual(self.status(with_checksum(CAPTURED, b'\x63\xb2', 26), verify=False), (None, []))

    def test_parse_rebuild_is_exact(self) -> None:
        for packet in (CAPTURED, with_checksum(CAPTURED, b'\x63\xb2', 26), with_checksum(CAPTURED, b'\x00\x00', 26)):
            for verify in (True, False):
                with self.subTest(packet=packet.hex(), verify=verify):
                    layer, _ = self.parse(packet, verify=verify)
                    self.assertEqual(self.IPv4.from_data(layer.info).data, packet)

    def test_the_ip_layer_computes_it(self) -> None:
        octets = self.IPv4(src='192.0.2.1', dst='198.51.100.2', protocol='UDP',
                           payload=self.UDP(srcport=40000, dstport=9, payload=b'hello')).data
        self.assertEqual(octets[26:28], expected(pseudo4(wire.IPV4_A, wire.IPV4_B, 13), octets[20:]))
        self.assertEqual(self.status(octets), (self.Status.VALID, []))

        octets = self.make6()
        self.assertEqual(octets[46:48], expected(pseudo6(wire.IPV6_A, wire.IPV6_B, 13), octets[40:]))
        layer, messages = self.parse(octets, self.IPv6)
        self.assertEqual((layer['UDP'].info.checksum_status, messages), (self.Status.VALID, []))
        self.assertEqual(self.IPv6.from_data(layer.info).data, octets)

    def test_a_fragment_leaves_it_out(self) -> None:
        # The checksum covers the whole datagram, which a fragment does not hold.
        for kwargs in ({'mf': True}, {'offset': 185}):
            with self.subTest(**kwargs):
                udp = self.UDP(srcport=40000, dstport=9, payload=b'hello')
                octets = self.IPv4(src='192.0.2.1', dst='198.51.100.2', protocol='UDP', payload=udp, **kwargs).data
                self.assertEqual(octets[20:], udp.data)
                self.assertEqual(octets[26:28], b'\x00\x00')

    def test_the_length_field_bounds_it(self) -> None:
        # The trailer past the Length field is neither summed nor in the pseudo-header.
        udp = self.UDP(srcport=40000, dstport=9, payload=b'hello', trailer=b'pad')
        octets = self.IPv4(src='192.0.2.1', dst='198.51.100.2', protocol='UDP', payload=udp).data
        self.assertEqual(octets[26:28], expected(pseudo4(wire.IPV4_A, wire.IPV4_B, 13), octets[20:33]))
        self.assertEqual(self.status(octets), (self.Status.VALID, []))

    def test_a_computed_zero_is_sent_as_all_ones(self) -> None:
        # Two payload octets chosen so that the sum over everything else is all ones.
        prefix = pseudo4(wire.IPV4_A, wire.IPV4_B, 10)
        rest = ~wire.checksum(prefix + b'\x9c\x40\x00\x09\x00\x0a\x00\x00') & 0xFFFF
        word = (0xFFFF - rest).to_bytes(2, 'big')
        octets = self.IPv4(src='192.0.2.1', dst='198.51.100.2', protocol='UDP',
                           payload=self.UDP(srcport=40000, dstport=9, payload=word)).data
        self.assertEqual(wire.checksum(prefix + octets[20:26] + b'\x00\x00' + octets[28:]), 0)
        self.assertEqual(octets[26:28], b'\xff\xff')
        self.assertEqual(self.status(octets), (self.Status.VALID, []))

    def test_make_takes_the_pseudo_header(self) -> None:
        pseudo = self.IP_Pseudo(src='192.0.2.1', dst='198.51.100.2', protocol='UDP', upper_length=0)
        datagram = self.UDP(srcport=40000, dstport=9, payload=b'alone', pseudo=pseudo).data
        self.assertEqual(datagram[6:8], expected(pseudo4(wire.IPV4_A, wire.IPV4_B, 13), datagram))

        # A jumbogram's zero Length (RFC 2675): the datagram is all but the trailer.
        pseudo = self.IP_Pseudo(src='2001:db8::1', dst='2001:db8::2', protocol='UDP', upper_length=0)
        datagram = self.UDP(srcport=40000, dstport=9, payload=b'alone', total_length=0,
                            trailer=b'pad', pseudo=pseudo).data
        self.assertEqual(datagram[6:8], expected(pseudo6(wire.IPV6_A, wire.IPV6_B, 13), datagram[:13]))

    @unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
    def test_make_agrees_with_scapy(self) -> None:
        from scapy.layers.inet import IP
        from scapy.layers.inet import UDP as ScapyUDP

        octets = self.IPv4(src='192.0.2.1', dst='198.51.100.2', protocol='UDP',
                           payload=self.UDP(srcport=40000, dstport=9, payload=b'hello')).data
        packet = IP(octets)
        del packet[ScapyUDP].chksum
        self.assertEqual(bytes(packet), octets)

    def test_off_or_given_is_written_as_is(self) -> None:
        with mock.patch.object(self.config, 'CHECKSUM_COMPUTE', False):
            self.assertEqual(self.make6()[46:48], b'\x00\x00')
        self.assertEqual(self.make6(checksum=b'\xbe\xef')[46:48], b'\xbe\xef')
        self.assertEqual(self.UDP(srcport=40000, dstport=9).data[6:8], b'\x00\x00')


if __name__ == '__main__':
    unittest.main()
