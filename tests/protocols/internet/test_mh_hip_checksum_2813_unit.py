# -*- coding: utf-8 -*-
"""MH and HIP verify and compute their checksums over the IP pseudo-header.

GitHub issue #2813: the enclosing IP layer verifies the Mobility Header checksum over
the IPv6 pseudo-header (RFC 6275 section 6.1.1) and the HIP checksum over the IPv4 or
IPv6 one (RFC 7401 section 5.1.1), under ``CHECKSUM_VERIFY``; ``make()`` computes one
it is not given under ``CHECKSUM_COMPUTE``. Each covers its own header alone, whose
length the pseudo-header carries. The HIP packets are the I1 examples of RFC 7401
Appendix C, with the checksums the RFC gives; the MH ones are hand-written, and their
checksums agree with scapy's.

"""
from __future__ import annotations

import importlib.util
import ipaddress
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire

#: Test tier (#1958): hand-picked parse -> rebuild and make -> parse round trips.
__tier__ = 'ALL'

HAS_SCAPY = importlib.util.find_spec('scapy') is not None

#: Addresses of RFC 7401 Appendix C, which the MH packets share.
V6_SRC, V6_DST = ipaddress.ip_address('2001:db8::1'), ipaddress.ip_address('2001:db8::2')
V4_SRC, V4_DST = ipaddress.ip_address('192.0.2.1'), ipaddress.ip_address('192.0.2.2')
#: The home address of a Home Address option, the source the MH checksum covers.
HOME = ipaddress.ip_address('2001:db8:a::1')

#: A Binding Refresh Request, Payload Proto 59, from V6_SRC to V6_DST.
MH_BRR = bytes.fromhex('3b00000068fb0000')
#: The same message sent with a Home Address option: the checksum covers HOME.
MH_BRR_HOME = bytes.fromhex('3b00000068f10000')
#: A Destination Options header, Next Header 135, padded to carry HOME at 8n+6.
HOME_OPTS = bytes.fromhex('870201020000c910') + HOME.packed

#: The HIP I1 packet of RFC 7401 Appendix C, its checksum left out (octets 4 and 5).
HIP_I1 = (bytes.fromhex('3b050121') + bytes(4) + ipaddress.ip_address('2001:20::1').packed
          + ipaddress.ip_address('2001:20::2').packed + bytes.fromhex('01ff000303040800'))
#: Its checksum over IPv6 (Appendix C.1) and IPv4 (Appendix C.2).
HIP_V6_CHECKSUM, HIP_V4_CHECKSUM = b'\x1a\x5e', b'\xf1\xce'


def with_checksum(octets: bytes, field: bytes, at: int = 4) -> bytes:
    """``octets`` with ``field`` at ``at``."""
    return octets[:at] + field + octets[at + 2:]


def ipv6(payload: bytes, *, nxt: int, src: object = V6_SRC) -> bytes:
    """An IPv6 packet from ``src`` to V6_DST."""
    return (b'\x60\x00\x00\x00' + len(payload).to_bytes(2, 'big') + bytes([nxt, 64])
            + src.packed + V6_DST.packed + payload)


def ipv6_fragment(payload: bytes, *, nxt: int, mf: bool) -> bytes:
    """An IPv6 packet carrying a first Fragment header."""
    return ipv6(bytes([nxt, 0, 0, 1 if mf else 0]) + bytes.fromhex('12345678') + payload, nxt=44)


def ipv4(payload: bytes, *, proto: int, mf: bool = False) -> bytes:
    """An IPv4 packet from V4_SRC to V4_DST."""
    header = bytearray(b'\x45\x00' + (20 + len(payload)).to_bytes(2, 'big') + b'\x12\x34'
                       + (b'\x20\x00' if mf else b'\x00\x00') + bytes([64, proto]) + b'\x00\x00'
                       + V4_SRC.packed + V4_DST.packed)
    header[10:12] = wire.checksum(bytes(header)).to_bytes(2, 'big')
    return bytes(header) + payload


def expected(pseudo: bytes, header: bytes) -> bytes:
    """The checksum ``header`` should carry over ``pseudo``."""
    return wire.checksum(pseudo + with_checksum(header, b'\x00\x00')).to_bytes(2, 'big')


def pseudo6(src: object, length: int, nxt: int) -> bytes:
    """An IPv6 pseudo-header to V6_DST (RFC 8200 section 8.1)."""
    return src.packed + V6_DST.packed + length.to_bytes(4, 'big') + bytes([0, 0, 0, nxt])


class ChecksumTestCase(unittest.TestCase):
    """Imports and helpers both protocols' tests share."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.const.hip.group import Group
        from pcapkit.const.hip.packet import Packet as HIPPacket
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.const.mh.packet import Packet as MHPacket
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.checksum.internet import ChecksumStatus
        from pcapkit.protocols.internet.hip.protocol import HIP
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.protocols.internet.mh.protocol import MH
        from pcapkit.protocols.misc.checksum.ip_pseudo.protocol import IP_Pseudo
        from pcapkit.utilities import config
        from pcapkit.utilities.exceptions import UnsupportedCall
        from pcapkit.utilities.warnings import ChecksumWarning, ProtocolWarning

        self.MH, self.HIP, self.IPv4, self.IPv6, self.IP_Pseudo = MH, HIP, IPv4, IPv6, IP_Pseudo
        self.Group, self.HIPPacket, self.Parameter, self.MHPacket = Group, HIPPacket, Parameter, MHPacket
        self.TransType, self.Status, self.config = TransType, ChecksumStatus, config
        self.UnsupportedCall = UnsupportedCall
        self.ChecksumWarning, self.ProtocolWarning = ChecksumWarning, ProtocolWarning

    def parse(self, octets: bytes, cls: type, *, verify: bool = True) -> 'tuple[object, list[tuple[type, str]]]':
        """``octets`` parsed as ``cls``, and its ProtocolWarnings as ``(category, message)``."""
        with mock.patch.object(self.config, 'CHECKSUM_VERIFY', verify), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            layer = cls(octets)
        return layer, [(item.category, str(item.message))
                       for item in caught if issubclass(item.category, self.ProtocolWarning)]

    def header(self, ip: object, code: int) -> object:
        """The MH or HIP header of the parsed IP layer ``ip``: an IPv6 extension header, or IPv4's payload."""
        if isinstance(ip, self.IPv6):
            return ip.extension_headers.getlist(code)[0]
        return ip.payload

    def status(self, octets: bytes, code: int, cls: 'type | None' = None,
               **kwargs: object) -> 'tuple[object, list[tuple[type, str]]]':
        """The checksum status of the MH or HIP header in ``octets``, and its ProtocolWarnings."""
        ip, messages = self.parse(octets, cls or self.IPv6, **kwargs)
        return self.header(ip, code).info.get('checksum_status'), messages

    def assertRebuilds(self, packets: 'list[tuple[type, bytes]]') -> None:
        """Each packet rebuilds byte for byte, verified or not."""
        for cls, packet in packets:
            for verify in (True, False):
                with self.subTest(packet=packet.hex(), verify=verify):
                    ip, _ = self.parse(packet, cls, verify=verify)
                    self.assertEqual(cls.from_data(ip.info).data, packet)


class MHChecksumTests(ChecksumTestCase):
    """Verifying and computing the Mobility Header checksum."""

    def test_the_checksum_verifies(self) -> None:
        # RFC 6275 section 6.1.1: with a Home Address option, the home address is the source.
        self.assertEqual(expected(pseudo6(V6_SRC, 8, 135), MH_BRR), MH_BRR[4:6])
        self.assertEqual(expected(pseudo6(HOME, 8, 135), MH_BRR_HOME), MH_BRR_HOME[4:6])
        packets = {'plain': ipv6(MH_BRR, nxt=135), 'home address': ipv6(HOME_OPTS + MH_BRR_HOME, nxt=60)}
        for name, packet in packets.items():
            with self.subTest(name):
                self.assertEqual(self.status(packet, 135), (self.Status.VALID, []))

    def test_a_corrupted_checksum_warns(self) -> None:
        status, messages = self.status(ipv6(with_checksum(MH_BRR, b'\x12\x34'), nxt=135), 135)
        self.assertIs(status, self.Status.INVALID)
        self.assertEqual(messages, [(self.ChecksumWarning, 'MH: checksum 0x1234 is wrong; 0x68fb expected')])
        # Without the home address the pseudo-header names another source.
        self.assertEqual(self.status(ipv6(MH_BRR_HOME, nxt=135), 135)[0], self.Status.INVALID)

    def test_off_or_alone_verifies_nothing(self) -> None:
        corrupted = ipv6(with_checksum(MH_BRR, b'\x12\x34'), nxt=135)
        self.assertEqual(self.status(corrupted, 135, verify=False), (None, []))
        mh, _ = self.parse(MH_BRR, self.MH)
        self.assertNotIn('checksum_status', mh.info)

    def test_a_fragment_has_no_pseudo_header(self) -> None:
        self.assertEqual(self.status(ipv6_fragment(MH_BRR, nxt=135, mf=True), 135),
                         (self.Status.NO_PSEUDO_HEADER, []))
        # An atomic fragment is the whole datagram.
        self.assertEqual(self.status(ipv6_fragment(MH_BRR, nxt=135, mf=False), 135), (self.Status.VALID, []))

    def test_what_follows_it_is_not_covered(self) -> None:
        # Payload Proto UDP: the pseudo-header carries the 8 octets of the header alone.
        header = bytes.fromhex('11000000') + bytes(4)
        header = with_checksum(header, expected(pseudo6(V6_SRC, 8, 135), header))
        ip, messages = self.parse(ipv6(header + wire.udp(b'abc'), nxt=135), self.IPv6)
        self.assertEqual((self.header(ip, 135).info.checksum_status, messages),
                         (self.Status.VALID, []))
        # The UDP datagram is not what the pseudo-header names.
        self.assertIs(ip['UDP'].info.checksum_status, self.Status.NO_PSEUDO_HEADER)

    def test_ipv4_gives_no_pseudo_header(self) -> None:
        # RFC 6275 defines the checksum over IPv6 header fields alone.
        self.assertEqual(self.status(ipv4(MH_BRR, proto=135), 135, self.IPv4), (self.Status.NO_PSEUDO_HEADER, []))
        made = self.IPv4.from_fields(src=V4_SRC, dst=V4_DST, protocol=self.TransType.Mobility_Header,
                                     payload=self.MH.from_fields(next=59)).data
        self.assertEqual(made[20:], with_checksum(MH_BRR, b'\x00\x00'))
        pseudo = self.IP_Pseudo.from_fields(src=V4_SRC, dst=V4_DST, protocol=135, upper_length=0)
        self.assertEqual(self.MH.from_fields(next=59, pseudo=pseudo).data[4:6], b'\x00\x00')

    def test_parse_rebuild_is_exact(self) -> None:
        self.assertRebuilds([
            (self.IPv6, ipv6(MH_BRR, nxt=135)),
            (self.IPv6, ipv6(with_checksum(MH_BRR, b'\x12\x34'), nxt=135)),
            (self.IPv6, ipv6(HOME_OPTS + MH_BRR_HOME, nxt=60)),
            (self.IPv6, ipv6_fragment(MH_BRR, nxt=135, mf=True)),
            (self.IPv4, ipv4(MH_BRR, proto=135)),
        ])

    def make(self, **kwargs: object) -> bytes:
        """The octets of an IPv6 packet carrying a Binding Refresh Request made with ``kwargs``."""
        mh = self.MH.from_fields(next=59, type=self.MHPacket.Binding_Refresh_Request, **kwargs)
        return self.IPv6.from_fields(src=V6_SRC, dst=V6_DST, next=self.TransType.Mobility_Header, payload=mh).data

    def test_the_ipv6_layer_computes_it(self) -> None:
        made = self.make()
        self.assertEqual(made, ipv6(MH_BRR, nxt=135))
        ip, messages = self.parse(made, self.IPv6)
        self.assertEqual((self.header(ip, 135).info.checksum_status, messages),
                         (self.Status.VALID, []))
        self.assertEqual(self.IPv6.from_data(ip.info).data, made)

    def test_make_takes_the_pseudo_header(self) -> None:
        pseudo = self.IP_Pseudo.from_fields(src=V6_SRC, dst=V6_DST, protocol=135, upper_length=0)
        self.assertEqual(self.MH.from_fields(next=59, pseudo=pseudo).data, MH_BRR)
        # Alone, with no pseudo-header to compute it over, it is left zero.
        self.assertEqual(self.MH.from_fields(next=59).data, with_checksum(MH_BRR, b'\x00\x00'))

    def test_off_or_given_is_written_as_is(self) -> None:
        with mock.patch.object(self.config, 'CHECKSUM_COMPUTE', False):
            self.assertEqual(self.make()[44:46], b'\x00\x00')
        self.assertEqual(self.make(checksum=b'\xbe\xef')[44:46], b'\xbe\xef')

    def test_make_takes_checksum_as_hip_does(self) -> None:
        with self.assertRaisesRegex(self.UnsupportedCall, "'chksum' \\(did you mean 'checksum'\\?\\)"):
            self.MH.from_fields(next=59, chksum=b'\x00\x00')

    @unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
    def test_make_agrees_with_scapy(self) -> None:
        from scapy.layers.inet6 import IPv6, MIP6MH_BRR

        self.assertEqual(bytes(IPv6(src=str(V6_SRC), dst=str(V6_DST)) / MIP6MH_BRR()), self.make())


class HIPChecksumTests(ChecksumTestCase):
    """Verifying and computing the HIP checksum, over IPv6 and IPv4."""

    def packets(self) -> 'dict[str, tuple[type, bytes]]':
        """RFC 7401 Appendix C's I1 packets, over IPv6 and IPv4."""
        return {
            'IPv6': (self.IPv6, ipv6(with_checksum(HIP_I1, HIP_V6_CHECKSUM), nxt=139)),
            'IPv4': (self.IPv4, ipv4(with_checksum(HIP_I1, HIP_V4_CHECKSUM), proto=139)),
        }

    def test_the_rfc_examples_verify(self) -> None:
        self.assertEqual(expected(pseudo6(V6_SRC, 48, 139), HIP_I1), HIP_V6_CHECKSUM)
        self.assertEqual(expected(V4_SRC.packed + V4_DST.packed + b'\x00\x8b\x00\x30', HIP_I1), HIP_V4_CHECKSUM)
        for name, (cls, packet) in self.packets().items():
            with self.subTest(name):
                self.assertEqual(self.status(packet, 139, cls), (self.Status.VALID, []))

    def test_a_corrupted_checksum_warns(self) -> None:
        cls, packet = self.packets()['IPv4']
        status, messages = self.status(with_checksum(packet, b'\xf1\xcf', 24), 139, cls)
        self.assertIs(status, self.Status.INVALID)
        self.assertEqual(messages, [(self.ChecksumWarning, 'HIPv2: checksum 0xf1cf is wrong; 0xf1ce expected')])
        # The IPv6 checksum is not the IPv4 one.
        self.assertIs(self.status(ipv4(with_checksum(HIP_I1, HIP_V6_CHECKSUM), proto=139), 139, cls)[0],
                      self.Status.INVALID)

    def test_off_verifies_nothing(self) -> None:
        cls, packet = self.packets()['IPv6']
        self.assertEqual(self.status(with_checksum(packet, b'\x1a\x5f', 44), 139, cls, verify=False), (None, []))

    def test_a_fragment_has_no_pseudo_header(self) -> None:
        packets = {
            'IPv6': (self.IPv6, ipv6_fragment(with_checksum(HIP_I1, HIP_V6_CHECKSUM), nxt=139, mf=True)),
            'IPv4': (self.IPv4, ipv4(with_checksum(HIP_I1, HIP_V4_CHECKSUM), proto=139, mf=True)),
        }
        for name, (cls, packet) in packets.items():
            with self.subTest(name):
                self.assertEqual(self.status(packet, 139, cls), (self.Status.NO_PSEUDO_HEADER, []))
        atomic = ipv6_fragment(with_checksum(HIP_I1, HIP_V6_CHECKSUM), nxt=139, mf=False)
        self.assertEqual(self.status(atomic, 139), (self.Status.VALID, []))

    def test_parse_rebuild_is_exact(self) -> None:
        cls, packet = self.packets()['IPv4']
        self.assertRebuilds([*self.packets().values(), (cls, with_checksum(packet, b'\xf1\xcf', 24)),
                             (cls, ipv4(with_checksum(HIP_I1, HIP_V4_CHECKSUM), proto=139, mf=True))])

    def i1(self, **kwargs: object) -> object:
        """The I1 packet of RFC 7401 Appendix C, made with ``kwargs``."""
        groups = [self.Group.get(3), self.Group.get(4), self.Group.get(8)]
        return self.HIP.from_fields(next=59, packet=self.HIPPacket.I1, shit=int(ipaddress.ip_address('2001:20::1')),
                                    rhit=int(ipaddress.ip_address('2001:20::2')),
                                    parameters=[(self.Parameter.DH_GROUP_LIST, {'groups': groups})], **kwargs)

    def test_the_ip_layer_computes_the_rfc_checksums(self) -> None:
        made = {
            'IPv6': self.IPv6.from_fields(src=V6_SRC, dst=V6_DST, next=self.TransType.HIP, payload=self.i1()).data,
            'IPv4': self.IPv4.from_fields(src=V4_SRC, dst=V4_DST, protocol=self.TransType.HIP, payload=self.i1()).data,
        }
        self.assertEqual(made['IPv6'], self.packets()['IPv6'][1])
        self.assertEqual(made['IPv4'][20:], self.packets()['IPv4'][1][20:])
        for name, octets in made.items():
            with self.subTest(name):
                cls = self.packets()[name][0]
                ip, messages = self.parse(octets, cls)
                self.assertEqual((self.header(ip, 139).info.checksum_status, messages),
                                 (self.Status.VALID, []))
                self.assertEqual(cls.from_data(ip.info).data, octets)

    def test_make_takes_the_pseudo_header(self) -> None:
        for src, dst, field in ((V6_SRC, V6_DST, HIP_V6_CHECKSUM), (V4_SRC, V4_DST, HIP_V4_CHECKSUM)):
            with self.subTest(version=src.version):
                pseudo = self.IP_Pseudo.from_fields(src=src, dst=dst, protocol=139, upper_length=0)
                self.assertEqual(self.i1(pseudo=pseudo).data, with_checksum(HIP_I1, field))
        self.assertEqual(self.i1().data, HIP_I1)

    def test_what_follows_it_is_not_covered(self) -> None:
        pseudo = self.IP_Pseudo.from_fields(src=V6_SRC, dst=V6_DST, protocol=139, upper_length=0)
        made = self.HIP.from_fields(next=17, packet=self.HIPPacket.I1, pseudo=pseudo, payload=wire.udp(b'abc')).data
        self.assertEqual(made[4:6], expected(pseudo6(V6_SRC, 40, 139), made[:40]))
        self.assertEqual(self.status(ipv6(made, nxt=139), 139), (self.Status.VALID, []))

    def test_off_or_given_is_written_as_is(self) -> None:
        pseudo = self.IP_Pseudo.from_fields(src=V6_SRC, dst=V6_DST, protocol=139, upper_length=0)
        with mock.patch.object(self.config, 'CHECKSUM_COMPUTE', False):
            self.assertEqual(self.i1(pseudo=pseudo).data[4:6], b'\x00\x00')
        self.assertEqual(self.i1(pseudo=pseudo, checksum=b'\xbe\xef').data[4:6], b'\xbe\xef')


if __name__ == '__main__':
    unittest.main()
