# -*- coding: utf-8 -*-
"""TCP verifies and computes its checksum over the IP pseudo-header.

GitHub issue #2473: the enclosing IPv4 or IPv6 layer verifies the TCP checksum
(:rfc:`793#section-3.1`) once parsed, under
:data:`~pcapkit.utilities.config.CHECKSUM_VERIFY`, and computes it for a segment
constructed as its payload under :data:`~pcapkit.utilities.config.CHECKSUM_COMPUTE`;
:meth:`TCP.make <pcapkit.protocols.transport.tcp.TCP.make>` also takes the
``pseudo`` itself. The captured segments are from the tracked
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

#: IPv4 packets carrying TCP as captured (``in.pcap`` frames 2 to 4); the last
#: two were sent by the capturing host, which computed its checksums.
CAPTURED = (
    bytes.fromhex('45000028c53440002b067a867b81d287c0a801640050d7c0d59fb154a67aa0ff50117cb07c8e0000'),
    bytes.fromhex('450000280000400040062abbc0a801647b81d287d7c00050a67aa0ffd59fb1555010fffff93e0000'),
    bytes.fromhex('450000280000400040062abbc0a801647b81d287d7b000502dd48d216d65746e5011ffff2af40000'),
)

HAS_SCAPY = importlib.util.find_spec('scapy') is not None


def pseudo4(packet: bytes, length: int) -> bytes:
    """The IPv4 pseudo-header of ``packet``, an IPv4 header without options."""
    return packet[12:20] + b'\x00\x06' + length.to_bytes(2, 'big')


def pseudo6(src: bytes, dst: bytes, length: int) -> bytes:
    """The IPv6 pseudo-header of TCP (RFC 8200 section 8.1)."""
    return src + dst + length.to_bytes(4, 'big') + b'\x00\x00\x00\x06'


def expected(prefix: bytes, segment: bytes) -> bytes:
    """The checksum ``segment`` should carry over ``prefix``."""
    return wire.checksum(prefix + segment[:16] + b'\x00\x00' + segment[18:]).to_bytes(2, 'big')


def with_checksum(packet: bytes, field: bytes, at: int = 20 + 16) -> bytes:
    """``packet`` with ``field`` at ``at``, the TCP checksum behind a 20-octet IPv4 header."""
    return packet[:at] + field + packet[at + 2:]


class TCPChecksumTests(unittest.TestCase):
    """Verifying and computing the TCP checksum."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.corekit.checksum.internet import ChecksumStatus
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities import config
        from pcapkit.utilities.warnings import ChecksumWarning, ProtocolWarning

        self.IPv4, self.IPv6, self.TCP, self.IP_Pseudo = IPv4, IPv6, TCP, IP_Pseudo
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
        """The TCP checksum status of ``octets``, and its ProtocolWarnings as ``(category, message)``."""
        layer, messages = self.parse(octets, **kwargs)
        return layer['TCP'].info.get('checksum_status'), messages

    def test_captured_checksums_verify(self) -> None:
        for packet in CAPTURED:
            with self.subTest(packet=packet.hex()):
                self.assertEqual(expected(pseudo4(packet, 20), packet[20:]), packet[36:38])
                self.assertEqual(self.status(packet), (self.Status.VALID, []))

    def test_a_corrupted_checksum_warns(self) -> None:
        status, messages = self.status(with_checksum(CAPTURED[0], b'\x7c\x8f'))
        self.assertIs(status, self.Status.INVALID)
        self.assertEqual(messages, [(self.ChecksumWarning, 'TCP: checksum 0x7c8f is wrong; 0x7c8e expected')])

    def test_offload_is_not_computed(self) -> None:
        # Linux offload leaves the pseudo-header's sum alone, uncomplemented.
        partial = (~wire.checksum(pseudo4(CAPTURED[1], 20)) & 0xFFFF).to_bytes(2, 'big')
        for field in (b'\x00\x00', partial):
            with self.subTest(field=field.hex()):
                self.assertEqual(self.status(with_checksum(CAPTURED[1], field)), (self.Status.NOT_COMPUTED, []))

    def test_off_verifies_nothing(self) -> None:
        self.assertEqual(self.status(with_checksum(CAPTURED[0], b'\x7c\x8f'), verify=False), (None, []))

    def test_without_a_pseudo_header(self) -> None:
        # A first fragment: the segment's length is only known once reassembled.
        header = bytearray(CAPTURED[0][:6] + b'\x20\x00' + CAPTURED[0][8:10] + b'\x00\x00' + CAPTURED[0][12:20])
        header[10:12] = wire.checksum(bytes(header)).to_bytes(2, 'big')
        status, messages = self.status(bytes(header) + CAPTURED[0][20:])
        self.assertEqual((status, messages), (self.Status.NO_PSEUDO_HEADER, []))
        # Alone, a segment has no IP layer to verify it.
        tcp, _ = self.parse(CAPTURED[0][20:], self.TCP)
        self.assertNotIn('checksum_status', tcp.info)

    def test_behind_an_authentication_header(self) -> None:
        # IPv4 carries AH as its payload, ahead of the segment (RFC 4302 section 2.2).
        segment = self.TCP(srcport=40000, dstport=80, payload=b'signed', checksum=b'\x00\x00').data
        ah = bytes([6, 4, 0, 0]) + (0x1234).to_bytes(4, 'big') + (1).to_bytes(4, 'big') + bytes(12)
        header = bytearray(b'\x45\x00' + (20 + len(ah) + len(segment)).to_bytes(2, 'big') + bytes(4)
                           + b'\x40\x33\x00\x00' + wire.IPV4_A + wire.IPV4_B)
        header[10:12] = wire.checksum(bytes(header)).to_bytes(2, 'big')
        prefix = wire.IPV4_A + wire.IPV4_B + b'\x00\x06' + len(segment).to_bytes(2, 'big')
        packet = bytes(header) + ah + segment[:16] + expected(prefix, segment) + segment[18:]
        self.assertEqual(self.status(packet), (self.Status.VALID, []))

    def test_an_upper_layer_the_pseudo_header_does_not_name(self) -> None:
        # IPv6 walks a Mobility Header as an extension header, but it is the
        # pseudo-header's upper layer (RFC 6275 section 6.1.1), not the segment.
        segment = self.TCP(srcport=40000, dstport=80, checksum=b'\x00\x00').data
        mh = bytes([6, 0, 0, 0, 0, 0, 0, 0])
        packet = (b'\x60\x00\x00\x00' + (len(mh) + len(segment)).to_bytes(2, 'big') + bytes([135, 64])
                  + wire.IPV6_A + wire.IPV6_B + mh + segment)
        layer, messages = self.parse(packet, self.IPv6)
        self.assertEqual(str(layer.protochain), 'IPv6:MH:TCP')
        self.assertEqual((layer['TCP'].info.checksum_status, messages), (self.Status.NO_PSEUDO_HEADER, []))

    def test_ipv6_and_truncation(self) -> None:
        segment = self.TCP(srcport=80, dstport=40000, seq_no=1, ack=True, ack_no=2, payload=b'odd').data
        with mock.patch.object(self.config, 'CHECKSUM_COMPUTE', True):
            packet = self.IPv6(src='2001:db8::1', dst='2001:db8::2', next='TCP', payload=segment).data
        self.assertEqual(self.status(packet, cls=self.IPv6), (self.Status.NOT_COMPUTED, []))

        made = self.IPv6(src='2001:db8::1', dst='2001:db8::2', next='TCP',
                         payload=self.TCP(srcport=80, dstport=40000, payload=b'odd')).data
        self.assertEqual(made[56:58], expected(pseudo6(wire.IPV6_A, wire.IPV6_B, 23), made[40:]))
        self.assertEqual(self.status(made, cls=self.IPv6), (self.Status.VALID, []))
        self.assertEqual(self.status(made[:-1], cls=self.IPv6), (self.Status.TRUNCATED, []))

    def test_parse_rebuild_is_exact(self) -> None:
        for packet in (*CAPTURED, with_checksum(CAPTURED[0], b'\x7c\x8f'), with_checksum(CAPTURED[1], b'\x00\x00')):
            for verify in (True, False):
                with self.subTest(packet=packet.hex(), verify=verify):
                    layer, _ = self.parse(packet, verify=verify)
                    self.assertEqual(self.IPv4.from_data(layer.info).data, packet)

    def make(self, compute: bool = True, **kwargs: object) -> bytes:
        """The octets of an IPv4 packet carrying a TCP segment made with ``kwargs``."""
        with mock.patch.object(self.config, 'CHECKSUM_COMPUTE', compute):
            tcp = self.TCP(srcport=40000, dstport=80, seq_no=7, syn=True, payload=b'hello', **kwargs)
            return self.IPv4(src='192.0.2.1', dst='198.51.100.2', ttl=64, protocol='TCP', payload=tcp).data

    def test_the_ip_layer_computes_it(self) -> None:
        octets = self.make()
        self.assertEqual(octets[36:38], expected(pseudo4(octets, 25), octets[20:]))
        layer, messages = self.parse(octets)
        self.assertIs(layer['TCP'].info.checksum_status, self.Status.VALID)
        self.assertEqual(messages, [])
        self.assertEqual(self.IPv4.from_data(layer.info).data, octets)

    def test_a_source_route_names_the_destination(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber

        tcp = self.TCP(srcport=40000, dstport=80, payload=b'routed')
        octets = self.IPv4(src='192.0.2.1', dst='198.51.100.2', protocol='TCP', payload=tcp,
                           options=[(OptionNumber.LSR, {'counts': 2, 'route': ['203.0.113.1'],
                                                        'remaining': ['203.0.113.9']})]).data
        hdr = (octets[0] & 0x0F) * 4
        prefix = octets[12:16] + bytes([203, 0, 113, 9]) + b'\x00\x06' + (len(octets) - hdr).to_bytes(2, 'big')
        self.assertEqual(octets[hdr + 16:hdr + 18], expected(prefix, octets[hdr:]))
        self.assertEqual(self.status(octets), (self.Status.VALID, []))

    def test_a_wrong_header_checksum_warns_once(self) -> None:
        with mock.patch.object(self.config, 'CHECKSUM_VERIFY', True), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            ipv4 = self.IPv4(src='192.0.2.1', dst='198.51.100.2', protocol='TCP', checksum=b'\xbe\xef',
                             payload=self.TCP(srcport=40000, dstport=80))
        messages = [(item.category, str(item.message))
                    for item in caught if issubclass(item.category, self.ProtocolWarning)]
        self.assertEqual(len(messages), 1, messages)
        self.assertIs(messages[0][0], self.ChecksumWarning, messages)
        self.assertTrue(messages[0][1].startswith('IPv4: checksum 0xbeef is wrong'), messages)
        self.assertIs(ipv4['TCP'].info.checksum_status, self.Status.VALID)

    def test_make_takes_the_pseudo_header(self) -> None:
        pseudo = self.IP_Pseudo(src='192.0.2.1', dst='198.51.100.2', protocol='TCP', upper_length=0)
        segment = self.TCP(srcport=40000, dstport=80, payload=b'alone', pseudo=pseudo).data
        prefix = wire.IPV4_A + wire.IPV4_B + b'\x00\x06' + len(segment).to_bytes(2, 'big')
        self.assertEqual(segment[16:18], expected(prefix, segment))

    @unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
    def test_make_agrees_with_scapy(self) -> None:
        from scapy.layers.inet import IP
        from scapy.layers.inet import TCP as ScapyTCP

        octets = self.make()
        packet = IP(octets)
        del packet[ScapyTCP].chksum
        self.assertEqual(bytes(packet), octets)

    def test_off_or_given_is_written_as_is(self) -> None:
        self.assertEqual(self.make(compute=False)[36:38], b'\x00\x00')
        self.assertEqual(self.make(checksum=b'\xbe\xef')[36:38], b'\xbe\xef')
        alone = self.TCP(srcport=40000, dstport=80)
        self.assertEqual(alone.data[16:18], b'\x00\x00')


if __name__ == '__main__':
    unittest.main()
