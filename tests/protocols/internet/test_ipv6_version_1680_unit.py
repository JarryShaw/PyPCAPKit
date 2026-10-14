# -*- coding: utf-8 -*-
"""IPv6 rejects a header whose Version is not 6. C.f. #1680.

GitHub issue #1680: :meth:`IPv6.read <pcapkit.protocols.internet.ipv6.IPv6.read>`
copied the Version nibble without checking it, so a header of any Version was
read as IPv6, and :meth:`~pcapkit.protocols.internet.ipv6.IPv6.from_data`, which
always writes 6, rebuilt it with another first octet. It now rejects any Version
but 6, as :meth:`IPv4.read <pcapkit.protocols.internet.ipv4.IPv4.read>` rejects
any but 4: each concrete class reads only its own protocol. Behind Ethernet or
inside a tunnel the frame stops there, kept raw and rebuilt as captured.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`,
c.f. ``tests/protocols/link/test_ethernet_mac_roundtrip_unit.py``.

"""

import struct
import unittest

from tests._support import reimport_once_per_class

#: The two IPv6 addresses, ``::1`` and ``::2``.
ADDRS = bytes(15) + b'\x01' + bytes(15) + b'\x02'
#: A UDP datagram to the discard port, carrying ``ab``.
UDP = struct.pack('>HHHH', 40000, 9, 10, 0) + b'ab'
#: Destination and source MAC addresses, then the IPv6 EtherType.
ETHER = bytes.fromhex('001122334455' '66778899aabb' '86dd')
#: Every Version but 6.
VERSIONS = tuple(version for version in range(16) if version != 6)


def ipv6(version: 'int', nxt: 'int' = 17, body: 'bytes' = UDP) -> 'bytes':
    """An IPv6 header of ``version`` carrying ``body`` as ``nxt``."""
    return struct.pack('>IHBB', version << 28, len(body), nxt, 64) + ADDRS + body


def ipv4(body: 'bytes', proto: 'int') -> 'bytes':
    """An IPv4 header, checksum zero, carrying ``body`` as ``proto``."""
    return struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(body), 1, 0x4000, 64, proto, 0,
                       b'\x0a\x00\x00\x01', b'\x0a\x00\x00\x02') + body


class TestIPv6Version(unittest.TestCase):
    """Pin that only a Version of 6 is read as IPv6."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_ipv6_rejects_every_other_version(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.utilities.exceptions import ProtocolError

        for version in VERSIONS:
            with self.subTest(version=version):
                with self.assertRaises(ProtocolError) as caught:
                    IPv6(ipv6(version))
                self.assertEqual(str(caught.exception), f'[IPv6] invalid version: {version}')

    def test_version_6_is_read(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6

        data = ipv6(6)
        proto = IPv6(data)
        self.assertEqual(proto.info.version, 6)
        self.assertEqual(str(proto.protochain), 'IPv6:UDP:Raw')
        self.assertEqual(IPv6.from_data(proto.info).data, data)

    def test_behind_ethernet_the_frame_stops_at_ipv6(self) -> None:
        # as at an IPv4 header of another version: kept raw, and rebuilt as captured
        from pcapkit.protocols.link.ethernet import Ethernet

        for version in VERSIONS:
            for trailer in (b'', b'\xee' * 4):
                with self.subTest(version=version, trailer=trailer):
                    frame = ETHER + ipv6(version) + trailer
                    proto = Ethernet(frame)
                    self.assertEqual(str(proto.protochain), 'Ethernet:Internet_Protocol_version_6')
                    self.assertNotIn('IPv6', proto)
                    self.assertEqual(proto.info.packet, ipv6(version) + trailer)
                    self.assertEqual(Ethernet.from_data(proto.info).data, frame)

    def test_inside_a_tunnel_the_frame_stops_at_the_inner_header(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.internet.ipv6 import IPv6

        for version in VERSIONS:
            for label, cls, frame, chain in (
                ('IPv4', IPv4, ipv4(ipv6(version), 41), 'IPv4:IPv6'),
                ('IPv6', IPv6, ipv6(6, 41, ipv6(version)), 'IPv6:IPv6'),
            ):
                with self.subTest(version=version, outer=label):
                    proto = cls(frame)
                    self.assertEqual(str(proto.protochain), chain)
                    self.assertIsNot(type(proto.payload), IPv6)
                    self.assertEqual(proto.payload.info.packet, ipv6(version))
                    self.assertEqual(cls.from_data(proto.info).data, frame)


if __name__ == '__main__':
    unittest.main()
