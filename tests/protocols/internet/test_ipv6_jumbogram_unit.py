# -*- coding: utf-8 -*-
"""An IPv6 jumbogram's payload is dissected up to its Jumbo Payload Length.

GitHub issue #1434: a jumbogram [:rfc:`2675`] sets the Payload Length to zero
and carries its real length in a Jumbo Payload option of the Hop-by-Hop
Options header. :class:`~pcapkit.protocols.internet.ipv6.IPv6` read only the
Payload Length, so its next layer was
:class:`~pcapkit.protocols.misc.null.NoPayload` and the whole jumbo payload
ended up in ``info.trailer``.

The Jumbo Payload Length now gives the payload extent, and only the octets
past it are ``trailer``. Every packet still rebuilds byte for byte.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`,
c.f. ``tests/protocols/link/test_ethernet_mac_roundtrip_unit.py``.

"""

import struct
import unittest
import warnings

from tests._support import reimport_once_per_class

#: The two IPv6 addresses, ``::1`` and ``::2``.
ADDRS = bytes(15) + b'\x01' + bytes(15) + b'\x02'
#: A UDP datagram of 24 octets.
UDP = struct.pack('>HHHH', 1234, 5678, 24, 0) + b'jumbo payload!!!'
#: Destination and source MAC addresses, then the IPv6 EtherType.
ETHER = bytes.fromhex('001122334455' '66778899aabb' '86dd')


def hbh(nxt: 'int', jumbo: 'int') -> 'bytes':
    """A Hop-by-Hop Options header carrying only a Jumbo Payload option."""
    return bytes([nxt, 0, 0xC2, 4]) + struct.pack('>I', jumbo)


def ipv6(plen: 'int', nxt: 'int', body: 'bytes') -> 'bytes':
    """An IPv6 header with the given Payload Length and Next Header."""
    return bytes.fromhex('60000000') + struct.pack('>HBB', plen, nxt, 64) + ADDRS + body


#: A well-formed jumbogram: Jumbo Payload Length covers HBH and UDP exactly.
JUMBO = ipv6(0, 0, hbh(17, 32) + UDP)


class TestIPv6Jumbogram(unittest.TestCase):
    """Pin how a jumbogram's payload extent is read."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def parse(self, data: 'bytes') -> 'object':
        from pcapkit.protocols.internet.ipv6 import IPv6

        proto = IPv6(data)
        self.assertEqual(IPv6.from_data(proto.info).data, data)
        return proto

    def test_payload_is_dissected(self) -> None:
        proto = self.parse(JUMBO)
        self.assertEqual(str(proto.protochain), 'IPv6:HOPOPT:UDP:Raw')
        self.assertEqual(proto.info.payload, 0)
        self.assertEqual(proto.info.raw_len, 24)
        self.assertNotIn('trailer', proto.info)
        self.assertEqual(proto.info.udp.len, 24)

    def test_octets_past_jumbo_length_are_trailer(self) -> None:
        proto = self.parse(JUMBO + b'\xee' * 6)
        self.assertEqual(str(proto.protochain), 'IPv6:HOPOPT:UDP:Raw')
        self.assertEqual(proto.info.trailer, b'\xee' * 6)

    def test_jumbo_length_shorter_than_captured(self) -> None:
        data = ipv6(0, 0, hbh(17, 16) + UDP)
        proto = self.parse(data)
        self.assertEqual(proto.info.raw_len, 8)
        self.assertEqual(proto.info.trailer, UDP[8:])

    def test_jumbo_length_longer_than_captured(self) -> None:
        # a truncated capture keeps the declared length, c.f. #1155
        proto = self.parse(ipv6(0, 0, hbh(17, 100) + UDP))
        self.assertEqual(str(proto.protochain), 'IPv6:HOPOPT:UDP:Raw')
        self.assertEqual(proto.info.raw_len, 92)
        self.assertNotIn('trailer', proto.info)

    def test_inside_ethernet(self) -> None:
        from pcapkit.protocols.link.ethernet import Ethernet

        frame = ETHER + JUMBO
        proto = Ethernet(frame)
        self.assertEqual(str(proto.protochain), 'Ethernet:IPv6:HOPOPT:UDP:Raw')
        self.assertEqual(Ethernet.from_data(proto.info).data, frame)

    def test_non_zero_payload_length_wins_and_warns(self) -> None:
        from pcapkit.utilities.warnings import ProtocolWarning

        data = ipv6(32, 0, hbh(17, 16) + UDP)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            proto = self.parse(data)
        self.assertTrue(any(issubclass(w.category, ProtocolWarning)
                            and 'Jumbo Payload option with non-zero Payload Length 32' in str(w.message)
                            for w in caught))
        self.assertEqual(proto.info.raw_len, 24)
        self.assertEqual(str(proto.protochain), 'IPv6:HOPOPT:UDP:Raw')

    def test_jumbo_outside_leading_hop_by_hop_is_ignored(self) -> None:
        # a Hop-by-Hop header after a Destination Options header, RFC 8200 4.1
        body = bytes([0, 0, 1, 4, 0, 0, 0, 0]) + hbh(17, 40) + UDP
        proto = self.parse(ipv6(0, 60, body))
        self.assertEqual(proto.info.trailer, body)

    def test_zero_payload_length_without_jumbo_is_unchanged(self) -> None:
        body = bytes([17, 0, 1, 4, 0, 0, 0, 0]) + UDP
        proto = self.parse(ipv6(0, 0, body))
        self.assertEqual(proto.info.trailer, body)

    def test_make_writes_zero_payload_length_past_65535(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6

        body = hbh(59, 8 + 70000) + bytes(70000)
        proto = IPv6(next=0, payload=body, trailer=b'\xee\xee')
        self.assertEqual(proto.data[4:6], b'\x00\x00')
        self.assertEqual(proto.data[40:], body + b'\xee\xee')

        parsed = IPv6(proto.data)
        self.assertEqual(parsed.info.raw_len, 70000)
        self.assertEqual(parsed.info.trailer, b'\xee\xee')
        self.assertEqual(IPv6.from_data(parsed.info).data, proto.data)


if __name__ == '__main__':
    unittest.main()
