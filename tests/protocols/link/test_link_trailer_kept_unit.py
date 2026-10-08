# -*- coding: utf-8 -*-
"""Octets captured past an IP packet's own length survive a rebuild.

GitHub issue #1209: :class:`~pcapkit.protocols.link.ethernet.Ethernet` and the
VLAN tags hand the whole rest of the frame to the next layer, but
:class:`~pcapkit.protocols.internet.ipv4.IPv4` reads only its Total Length and
:class:`~pcapkit.protocols.internet.ipv6.IPv6` only its Payload Length. The
octets after that -- most often the padding of a 60-octet minimum Ethernet
frame -- were kept by no ``info``, so
:meth:`~pcapkit.protocols.protocol.ProtocolBase.from_data` dropped them: the
frame below rebuilt as 42 octets of its 60.

The IP layer owns them as ``trailer``, since its own length field is what
leaves them out of the payload, and so the IP packet rebuilds byte for byte on
its own as well as inside a frame.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`,
c.f. ``tests/protocols/link/test_ethernet_mac_roundtrip_unit.py``.

"""

import importlib
import unittest

from tests._support import reimport_once_per_class

#: Destination and source MAC addresses.
MACS = bytes.fromhex('001122334455' '66778899aabb')
#: An IPv4/UDP packet, Total Length 28.
UDP4 = bytes.fromhex('4500001c000100004011f97d7f0000017f000001' '0035003500080000')
#: The two IPv6 addresses, ``::1`` twice.
ADDRS6 = (bytes(15) + b'\x01') * 2
#: An IPv6 header, Payload Length 0 and No Next Header.
NONXT6 = bytes.fromhex('60000000' '0000' '3b' '40') + ADDRS6

#: Frames whose IP packet is shorter than what the link layer carries.
FRAMES = {
    'ethernet': MACS + b'\x08\x00' + UDP4 + bytes(18),
    'ethernet-junk': MACS + b'\x08\x00' + UDP4 + b'\x01\x02\x03' * 6,
    'c-tag': MACS + bytes.fromhex('8100' '0064' '0800') + UDP4 + bytes(14),
    'q-in-q': MACS + bytes.fromhex('88a8' '00c8' '8100' '0064' '0800') + UDP4 + bytes(10),
    'ethernet-ipv6': MACS + b'\x86\xdd' + NONXT6 + b'\xaa\xbb',
}

#: Bare IP packets with octets past their own length, and those octets.
PACKETS = {
    'ipv4': ('pcapkit.protocols.internet.ipv4', 'IPv4',
             bytes.fromhex('450000180001000040fd0000' '7f000001' '7f000001') + b'abcd' + bytes(6),
             bytes(6)),
    'ipv4-options': ('pcapkit.protocols.internet.ipv4', 'IPv4',
                     bytes.fromhex('4600001c0001000040fd0000' '7f000001' '7f000001' '01010100')
                     + b'abcd' + b'\xee' * 5,
                     b'\xee' * 5),
    'ipv4-header-only': ('pcapkit.protocols.internet.ipv4', 'IPv4',
                         bytes.fromhex('450000140001000040fd0000' '7f000001' '7f000001') + b'wxyz',
                         b'wxyz'),
    'ipv6': ('pcapkit.protocols.internet.ipv6', 'IPv6', NONXT6 + b'\xaa\xbb', b'\xaa\xbb'),
    'ipv6-hopopt': ('pcapkit.protocols.internet.ipv6', 'IPv6',
                    bytes.fromhex('60000000' '0010' '00' '40') + ADDRS6
                    + bytes.fromhex('1100010400000000' '0035003500080000') + bytes(6),
                    bytes(6)),
}

#: Bare IP packets that end at or before their own length.
NO_TRAILER = {
    'ipv4-exact': ('pcapkit.protocols.internet.ipv4', 'IPv4',
                   bytes.fromhex('450000180001000040fd0000' '7f000001' '7f000001') + b'abcd'),
    'ipv4-truncated': ('pcapkit.protocols.internet.ipv4', 'IPv4',
                       bytes.fromhex('450000280001000040fd0000' '7f000001' '7f000001') + b'abcdefghij'),
    'ipv6-exact': ('pcapkit.protocols.internet.ipv6', 'IPv6', NONXT6),
    'ipv6-truncated': ('pcapkit.protocols.internet.ipv6', 'IPv6',
                       bytes.fromhex('60000000' '0010' '3b' '40') + ADDRS6 + b'\xaa' * 4),
}


def _klass(module: str, name: str) -> type:
    return getattr(importlib.import_module(module), name)


class TestLinkTrailerKept(unittest.TestCase):
    """Pin the octets past an IP packet's own length through ``from_data``."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_frame_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.link.ethernet import Ethernet

        for name, frame in FRAMES.items():
            with self.subTest(frame=name):
                parsed = Ethernet(frame)
                self.assertEqual(len(parsed.data), 60 if name != 'ethernet-ipv6' else 56)
                self.assertEqual(Ethernet.from_data(parsed.info).data, frame)

    def test_packet_rebuilds_byte_for_byte(self) -> None:
        for name, (module, klass, packet, trailer) in PACKETS.items():
            with self.subTest(packet=name):
                proto = _klass(module, klass)
                parsed = proto(packet)
                self.assertEqual(parsed.info.trailer, trailer)
                self.assertEqual(proto.from_data(parsed.info).data, packet)

    def test_no_trailer_key_without_excess(self) -> None:
        for name, (module, klass, packet) in NO_TRAILER.items():
            with self.subTest(packet=name):
                proto = _klass(module, klass)
                parsed = proto(packet)
                self.assertNotIn('trailer', parsed.info)
                self.assertEqual(proto.from_data(parsed.info).data, packet)

    def test_padded_frame_records_padding_on_ipv4(self) -> None:
        from pcapkit.protocols.link.ethernet import Ethernet

        info = Ethernet(FRAMES['ethernet']).info
        self.assertEqual(info.ipv4.len, 28)
        self.assertEqual(info.ipv4.trailer, bytes(18))
        self.assertNotIn('trailer', info)

    def test_make_writes_trailer_outside_the_length(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.internet.ipv6 import IPv6

        ipv4 = IPv4(protocol=253, payload=b'abcd', trailer=b'\x00\x01')
        self.assertEqual(ipv4.info.len, 24)
        self.assertEqual(ipv4.data[-6:], b'abcd\x00\x01')
        self.assertEqual(ipv4.info.trailer, b'\x00\x01')

        ipv6 = IPv6(next=59, payload=b'abcd', trailer=b'\x01')
        self.assertEqual(ipv6.info.payload, 4)
        self.assertEqual(ipv6.data[-5:], b'abcd\x01')
        self.assertEqual(ipv6.info.trailer, b'\x01')


if __name__ == '__main__':
    unittest.main()
