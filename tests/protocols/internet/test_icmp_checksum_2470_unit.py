# -*- coding: utf-8 -*-
"""ICMP and ICMPv6 verify and compute their checksums.

GitHub issue #2470: :meth:`ICMPv4.read <pcapkit.protocols.internet.icmpv4.ICMPv4.read>`
verifies the checksum over the message alone (:rfc:`792`), and the enclosing IPv6
layer verifies the ICMPv6 checksum over its pseudo-header (:rfc:`4443#section-2.3`),
both under :data:`~pcapkit.utilities.config.CHECKSUM_VERIFY`; ``make()`` computes one
it is not given under :data:`~pcapkit.utilities.config.CHECKSUM_COMPUTE`. The ICMPv6
messages are from the tracked :file:`examples/captures/in.pcap`; expected checksums
are the hand-written sum of ``tests/foundation/_roundtrip.py``.

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

#: An IPv4 packet carrying an ICMP Echo request, with its sender's checksum.
ECHO = bytes.fromhex('4500003c4e2100004001db730a141e830a141e820800083a3f210001211ba46a081f6a04'
                     '9680ef6445e70f48a870edac63255fe850848af33d4c2bf6')

#: IPv6 packets carrying ICMPv6 as captured (``in.pcap`` frames 0 and 1): a
#: Neighbor Solicitation and its Advertisement.
CAPTURED = (
    bytes.fromhex('6000000000203afffe8000000000000000a687f9279316eefe800000000000001ccd7c77bac746b7'
                  '87000eaa00000000fe800000000000001ccd7c77bac746b70101a45e60d96b97'),
    bytes.fromhex('6000000000183afffe800000000000001ccd7c77bac746b7fe8000000000000000a687f9279316ee'
                  '88003f8240000000fe800000000000001ccd7c77bac746b7'),
)

HAS_SCAPY = importlib.util.find_spec('scapy') is not None


def pseudo6(packet: bytes, length: int) -> bytes:
    """The ICMPv6 pseudo-header of ``packet``'s addresses (RFC 8200 section 8.1)."""
    return packet[8:40] + length.to_bytes(4, 'big') + b'\x00\x00\x00\x3a'


def expected(prefix: bytes, message: bytes) -> bytes:
    """The checksum ``message`` should carry over ``prefix``."""
    return wire.checksum(prefix + message[:2] + b'\x00\x00' + message[4:]).to_bytes(2, 'big')


def with_checksum(packet: bytes, field: bytes, at: int) -> bytes:
    """``packet`` with ``field`` at ``at``."""
    return packet[:at] + field + packet[at + 2:]


class ChecksumTestCase(unittest.TestCase):
    """Imports and helpers both protocols' tests share."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.protocols.internet.icmpv4 import ICMPv4
        from pcapkit.protocols.internet.icmpv6 import ICMPv6
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.misc.checksum.checksum import ChecksumStatus
        from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
        from pcapkit.utilities import config
        from pcapkit.utilities.warnings import ChecksumWarning, ProtocolWarning

        self.ICMPv4, self.ICMPv6, self.IPv4, self.IPv6, self.IP_Pseudo = ICMPv4, ICMPv6, IPv4, IPv6, IP_Pseudo
        self.Status = ChecksumStatus
        self.config = config
        self.ProtocolWarning = ProtocolWarning
        self.ChecksumWarning = ChecksumWarning

    def parse(self, octets: bytes, cls: type, *, verify: bool = True) -> 'tuple[object, list[tuple[type, str]]]':
        """``octets`` parsed as ``cls``, and its ProtocolWarnings as ``(category, message)``."""
        with mock.patch.object(self.config, 'CHECKSUM_VERIFY', verify), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            layer = cls(octets)
        return layer, [(item.category, str(item.message))
                       for item in caught if issubclass(item.category, self.ProtocolWarning)]


class ICMPv4ChecksumTests(ChecksumTestCase):
    """Reading and making the ICMP checksum."""

    def status(self, octets: bytes, **kwargs: object) -> 'tuple[object, list[tuple[type, str]]]':
        """The ICMP checksum status of the IPv4 packet ``octets``, and its ProtocolWarnings."""
        layer, messages = self.parse(octets, self.IPv4, **kwargs)
        return layer['ICMP'].info.get('checksum_status'), messages

    def test_the_captured_checksum_verifies(self) -> None:
        self.assertEqual(expected(b'', ECHO[20:]), ECHO[22:24])
        self.assertEqual(self.status(ECHO), (self.Status.VALID, []))
        icmp, messages = self.parse(ECHO[20:], self.ICMPv4)
        self.assertEqual((icmp.info.checksum_status, messages), (self.Status.VALID, []))

    def test_a_corrupted_checksum_warns(self) -> None:
        status, messages = self.status(with_checksum(ECHO, b'\x08\x3b', 22))
        self.assertIs(status, self.Status.INVALID)
        self.assertEqual(messages, [(self.ChecksumWarning, 'ICMP: checksum 0x083b is wrong; 0x083a expected')])

    def test_truncated_and_off(self) -> None:
        self.assertEqual(self.status(ECHO[:-1]), (self.Status.TRUNCATED, []))
        self.assertEqual(self.status(with_checksum(ECHO, b'\x08\x3b', 22), verify=False), (None, []))

    def test_a_fragment_is_not_verified(self) -> None:
        # The first 32 of the Echo's 40 octets, More Fragments set: the checksum
        # covers all 40, so the fragment cannot be checked, as TCP's cannot.
        message = ECHO[20:]
        packets = {
            'IPv4': (self.IPv4, wire.ipv4(message[:32], mf=True, proto=1)),
            'behind AH': (self.IPv4, wire.ipv4(bytes([1, 4]) + bytes(22) + message[:32], mf=True, proto=51)),
            'IPv6': (self.IPv6, wire.ipv6_fragment(message[:32], mf=True, nxt=1)),
        }
        for name, (cls, packet) in packets.items():
            with self.subTest(name):
                layer, messages = self.parse(packet, cls)
                self.assertEqual((layer['ICMP'].info.checksum_status, messages),
                                 (self.Status.NO_PSEUDO_HEADER, []))
                self.assertEqual(cls.from_data(layer.info).data, packet)
        # An atomic fragment is the whole datagram.
        layer, messages = self.parse(wire.ipv6_fragment(message, nxt=1), self.IPv6)
        self.assertEqual((layer['ICMP'].info.checksum_status, messages), (self.Status.VALID, []))

    def test_parse_rebuild_is_exact(self) -> None:
        for packet in (ECHO, with_checksum(ECHO, b'\x08\x3b', 22), with_checksum(ECHO, b'\x00\x00', 22)):
            for verify in (True, False):
                with self.subTest(packet=packet.hex(), verify=verify):
                    layer, _ = self.parse(packet, self.IPv4, verify=verify)
                    self.assertEqual(self.IPv4.from_data(layer.info).data, packet)

    def test_make_computes_the_checksum(self) -> None:
        body = {'id': 0x3f21, 'seq': 1, 'data': b'odd'}
        made = self.ICMPv4(type='Echo', body=body).data
        self.assertEqual(made[2:4], expected(b'', made))
        icmp, messages = self.parse(made, self.ICMPv4)
        self.assertEqual((icmp.info.checksum_status, messages), (self.Status.VALID, []))
        self.assertEqual(self.ICMPv4.from_data(icmp.info).data, made)
        with mock.patch.object(self.config, 'CHECKSUM_COMPUTE', False):
            self.assertEqual(self.ICMPv4(type='Echo', body=body).data[2:4], b'\x00\x00')
        self.assertEqual(self.ICMPv4(type='Echo', body=body, checksum=b'\xbe\xef').data[2:4], b'\xbe\xef')

    @unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
    def test_make_agrees_with_scapy(self) -> None:
        from scapy.layers.inet import ICMP

        made = self.ICMPv4(type='Echo', body={'id': 7, 'seq': 2, 'data': b'ping'}).data
        packet = ICMP(made)
        del packet.chksum
        self.assertEqual(bytes(packet), made)


class ICMPv6ChecksumTests(ChecksumTestCase):
    """Verifying and computing the ICMPv6 checksum."""

    def status(self, octets: bytes, **kwargs: object) -> 'tuple[object, list[tuple[type, str]]]':
        """The ICMPv6 checksum status of the IPv6 packet ``octets``, and its ProtocolWarnings."""
        layer, messages = self.parse(octets, self.IPv6, **kwargs)
        return layer['ICMPv6'].info.get('checksum_status'), messages

    def test_captured_checksums_verify(self) -> None:
        for packet in CAPTURED:
            with self.subTest(packet=packet.hex()):
                self.assertEqual(expected(pseudo6(packet, len(packet) - 40), packet[40:]), packet[42:44])
                self.assertEqual(self.status(packet), (self.Status.VALID, []))

    def test_a_corrupted_checksum_warns(self) -> None:
        status, messages = self.status(with_checksum(CAPTURED[0], b'\x0e\xab', 42))
        self.assertIs(status, self.Status.INVALID)
        self.assertEqual(messages, [(self.ChecksumWarning, 'ICMPv6: checksum 0x0eab is wrong; 0x0eaa expected')])

    def test_off_or_alone_verifies_nothing(self) -> None:
        self.assertEqual(self.status(with_checksum(CAPTURED[0], b'\x0e\xab', 42), verify=False), (None, []))
        icmp, _ = self.parse(CAPTURED[0][40:], self.ICMPv6)
        self.assertNotIn('checksum_status', icmp.info)

    def test_a_first_fragment_has_no_pseudo_header(self) -> None:
        packet = wire.ipv6_fragment(CAPTURED[0][40:], mf=True, nxt=58)
        self.assertEqual(self.status(packet), (self.Status.NO_PSEUDO_HEADER, []))

    def test_behind_an_extension_header(self) -> None:
        # A Hop-by-Hop Options header with one PadN; the pseudo-header names ICMPv6.
        message = CAPTURED[0][40:]
        packet = CAPTURED[0][:4] + (len(message) + 8).to_bytes(2, 'big') + b'\x00' + CAPTURED[0][7:40] \
            + b'\x3a\x00\x01\x04\x00\x00\x00\x00' + message
        self.assertEqual(self.status(packet), (self.Status.VALID, []))

    def test_parse_rebuild_is_exact(self) -> None:
        for packet in (*CAPTURED, with_checksum(CAPTURED[0], b'\x0e\xab', 42)):
            for verify in (True, False):
                with self.subTest(packet=packet.hex(), verify=verify):
                    layer, _ = self.parse(packet, self.IPv6, verify=verify)
                    self.assertEqual(self.IPv6.from_data(layer.info).data, packet)

    def make(self, **kwargs: object) -> bytes:
        """The octets of an IPv6 packet carrying an Echo Request made with ``kwargs``."""
        icmp = self.ICMPv6(type='Echo_Request', body={'id': 7, 'seq': 2, 'data': b'odd'}, **kwargs)
        return self.IPv6(src='2001:db8::1', dst='2001:db8::2', next='IPv6_ICMP', payload=icmp).data

    def test_the_ipv6_layer_computes_it(self) -> None:
        made = self.make()
        self.assertEqual(made[42:44], expected(pseudo6(made, 11), made[40:]))
        layer, messages = self.parse(made, self.IPv6)
        self.assertEqual((layer['ICMPv6'].info.checksum_status, messages), (self.Status.VALID, []))
        self.assertEqual(self.IPv6.from_data(layer.info).data, made)

    def test_make_takes_the_pseudo_header(self) -> None:
        pseudo = self.IP_Pseudo(src='2001:db8::1', dst='2001:db8::2', protocol='IPv6_ICMP', upper_length=0)
        message = self.ICMPv6(type='Echo_Request', body={'id': 7, 'seq': 2, 'data': b'odd'}, pseudo=pseudo).data
        self.assertEqual(message, self.make()[40:])
        # Alone, with no pseudo-header to compute it over, it is left zero.
        self.assertEqual(self.ICMPv6(type='Echo_Request').data[2:4], b'\x00\x00')

    @unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
    def test_make_agrees_with_scapy(self) -> None:
        from scapy.layers.inet6 import IPv6

        made = self.make()
        packet = IPv6(made)
        del packet.payload.cksum
        self.assertEqual(bytes(packet), made)

    def test_off_or_given_is_written_as_is(self) -> None:
        with mock.patch.object(self.config, 'CHECKSUM_COMPUTE', False):
            self.assertEqual(self.make()[42:44], b'\x00\x00')
        self.assertEqual(self.make(checksum=b'\xbe\xef')[42:44], b'\xbe\xef')


if __name__ == '__main__':
    unittest.main()
