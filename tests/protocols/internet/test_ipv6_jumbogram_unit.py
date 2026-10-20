# -*- coding: utf-8 -*-
"""An IPv6 jumbogram is dissected up to its Jumbo Payload Length, and one RFC 2675 calls an error not at all.

GitHub issue #1434: a jumbogram [:rfc:`2675`] sets the Payload Length to zero
and carries its real length in a Jumbo Payload option of the Hop-by-Hop
Options header. :class:`~pcapkit.protocols.internet.ipv6.IPv6` read only the
Payload Length, so its next layer was
:class:`~pcapkit.protocols.misc.null.NoPayload` and the whole jumbo payload
ended up in ``info.trailer``. The Jumbo Payload Length now gives the payload
extent, and only the octets past it are ``trailer``. Every packet still
rebuilds byte for byte.

GitHub issue #1687: :rfc:`2675#section-3` lists four errors a receiver must
detect -- a Payload Length of 0 with a Hop-by-Hop Options header and no Jumbo
Payload option, a non-zero Payload Length with the option, a Jumbo Payload
Length below 65,536, and the option with a Fragment header. The parser read
each as a jumbogram, or warned and went on; it now rejects each, as
:meth:`IPv4.read <pcapkit.protocols.internet.ipv4.IPv4.read>` rejects a version
other than 4, so behind Ethernet the frame stops at the IPv6 layer, kept raw.
And ``IPv6.make`` with no ``payload_length`` writes a Payload Length of 0 for a
payload carrying a Jumbo Payload option, rather than its own length, so a
genuine Jumbo Payload Length builds a jumbogram the parser accepts.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`,
c.f. ``tests/protocols/link/test_ethernet_mac_roundtrip_unit.py``.

"""

import struct
import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): exercises integer, bytes and struct edge cases, whose limits
#: differ by interpreter.
__tier__ = 'ALL'

#: The two IPv6 addresses, ``::1`` and ``::2``.
ADDRS = bytes(15) + b'\x01' + bytes(15) + b'\x02'
#: A TCP header of 20 octets, no options.
TCP = struct.pack('>HHIIBBHHH', 1234, 5678, 1, 0, 0x50, 0x18, 0xFFFF, 0, 0)
#: A TCP segment too long for a Payload Length.
SEGMENT = TCP + b'j' * 70000
#: Destination and source MAC addresses, then the IPv6 EtherType.
ETHER = bytes.fromhex('001122334455' '66778899aabb' '86dd')


def hbh(nxt: 'int', jumbo: 'int') -> 'bytes':
    """A Hop-by-Hop Options header carrying only a Jumbo Payload option."""
    return bytes([nxt, 0, 0xC2, 4]) + struct.pack('>I', jumbo)


def ipv6(plen: 'int', nxt: 'int', body: 'bytes') -> 'bytes':
    """An IPv6 header with the given Payload Length and Next Header."""
    return bytes.fromhex('60000000') + struct.pack('>HBB', plen, nxt, 64) + ADDRS + body


#: A jumbogram RFC 2675 accepts: its Jumbo Payload Length covers HBH and TCP exactly.
JUMBO = ipv6(0, 0, hbh(6, 8 + len(SEGMENT)) + SEGMENT)

#: Each error :rfc:`2675#section-3` lists, by case: the packet, then what the
#: parser's :exc:`~pcapkit.utilities.exceptions.ProtocolError` says of it.
ERRORS = {
    'Payload Length 0, Hop-by-Hop Options header, no Jumbo Payload option': (
        ipv6(0, 0, bytes([6, 0, 1, 4, 0, 0, 0, 0]) + TCP),
        'Payload Length 0 and a Hop-by-Hop Options header with no Jumbo Payload option'),
    'Payload Length 0, Next Header 0, nothing after the header': (
        ipv6(0, 0, b''), 'Payload Length 0 and a Hop-by-Hop Options header with no Jumbo Payload option'),
    'Payload Length 28, Jumbo Payload Length 70000': (
        ipv6(8 + len(TCP), 0, hbh(6, 70000) + TCP), 'Jumbo Payload option with a non-zero Payload Length 28'),
    'Payload Length 4, Jumbo Payload option past it': (
        ipv6(4, 0, hbh(6, 70000) + TCP), 'Jumbo Payload option with a non-zero Payload Length 4'),
    'Jumbo Payload Length 28': (
        ipv6(0, 0, hbh(6, 8 + len(TCP)) + TCP), 'Jumbo Payload Length 28, not greater than 65,535'),
    'Jumbo Payload Length 65535': (
        ipv6(0, 0, hbh(6, 65535) + TCP + bytes(65535 - 8 - len(TCP))),
        'Jumbo Payload Length 65535, not greater than 65,535'),
    'Jumbo Payload Length 0': (ipv6(0, 0, hbh(59, 0)), 'Jumbo Payload Length 0, not greater than 65,535'),
    'Fragment header': (
        ipv6(0, 0, hbh(44, 8 + 8 + len(SEGMENT)) + bytes([6, 0, 0, 0, 0, 0, 0, 1]) + SEGMENT),
        'Jumbo Payload option with a Fragment header'),
    'Fragment header behind a Destination Options header': (
        ipv6(0, 0, hbh(60, 8 + 8 + 8 + len(SEGMENT)) + bytes([44, 0, 1, 4, 0, 0, 0, 0])
             + bytes([6, 0, 0, 1, 0, 0, 0, 1]) + SEGMENT),
        'Jumbo Payload option with a Fragment header'),
}


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
        self.assertEqual(str(proto.protochain), 'IPv6:HOPOPT:TCP:Raw')
        self.assertEqual(proto.info.payload, 0)
        self.assertEqual(proto.info.raw_len, len(SEGMENT))
        self.assertNotIn('trailer', proto.info)

    def test_octets_past_jumbo_length_are_trailer(self) -> None:
        proto = self.parse(JUMBO + b'\xee' * 6)
        self.assertEqual(str(proto.protochain), 'IPv6:HOPOPT:TCP:Raw')
        self.assertEqual(proto.info.trailer, b'\xee' * 6)

    def test_jumbo_length_shorter_than_captured(self) -> None:
        proto = self.parse(ipv6(0, 0, hbh(6, 8 + len(SEGMENT) - 16) + SEGMENT))
        self.assertEqual(proto.info.raw_len, len(SEGMENT) - 16)
        self.assertEqual(proto.info.trailer, SEGMENT[-16:])

    def test_jumbo_length_longer_than_captured(self) -> None:
        # a truncated capture keeps the declared length, c.f. #1155
        proto = self.parse(ipv6(0, 0, hbh(6, 8 + len(SEGMENT) + 100) + SEGMENT))
        self.assertEqual(str(proto.protochain), 'IPv6:HOPOPT:TCP:Raw')
        self.assertEqual(proto.info.raw_len, len(SEGMENT) + 100)
        self.assertNotIn('trailer', proto.info)

    def test_least_jumbo_payload_length(self) -> None:
        # RFC 2675 section 2: greater than 65,535, so 65,536 is the least
        segment = TCP + bytes(65536 - 8 - len(TCP))
        proto = self.parse(ipv6(0, 0, hbh(6, 65536) + segment))
        self.assertEqual(proto.info.raw_len, len(segment))

    def test_inside_ethernet(self) -> None:
        from pcapkit.protocols.link.ethernet import Ethernet

        frame = ETHER + JUMBO
        proto = Ethernet(frame)
        self.assertEqual(str(proto.protochain), 'Ethernet:IPv6:HOPOPT:TCP:Raw')
        self.assertEqual(Ethernet.from_data(proto.info).data, frame)

    def test_jumbo_outside_leading_hop_by_hop_is_ignored(self) -> None:
        # a Hop-by-Hop header after a Destination Options header, RFC 8200 4.1
        body = bytes([0, 0, 1, 4, 0, 0, 0, 0]) + hbh(6, 40) + TCP
        proto = self.parse(ipv6(0, 60, body))
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


class TestRFC2675Errors(unittest.TestCase):
    """Each error :rfc:`2675#section-3` lists is rejected, and the frame stops there (#1687)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_ipv6_rejects_each_error(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.utilities.exceptions import ProtocolError

        for label, (data, message) in ERRORS.items():
            with self.subTest(case=label):
                with self.assertRaises(ProtocolError) as caught:
                    IPv6(data)
                self.assertEqual(str(caught.exception), f'IPv6: {message}')

    def test_behind_ethernet_the_frame_stops_at_ipv6(self) -> None:
        # as at an IPv4 header of another version: kept raw, and rebuilt as captured
        from pcapkit.protocols.link.ethernet import Ethernet

        for label, (data, _) in ERRORS.items():
            for trailer in (b'', b'\xee' * 4):
                with self.subTest(case=label, trailer=trailer):
                    frame = ETHER + data + trailer
                    proto = Ethernet(frame)
                    self.assertEqual(str(proto.protochain), 'Ethernet:Internet_Protocol_version_6')
                    self.assertNotIn('IPv6', proto)
                    self.assertEqual(proto.info.packet, data + trailer)
                    self.assertEqual(Ethernet.from_data(proto.info).data, frame)


class TestMakeJumbogram(unittest.TestCase):
    """``IPv6.make`` writes a Payload Length of 0 beside a Jumbo Payload option (#1687)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_a_jumbo_payload_option_makes_payload_length_zero(self) -> None:
        # a Jumbo Payload Length past the octets at hand, as in a capture cut short
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv6 import IPv6

        body = hbh(6, 70000) + TCP
        for label, payload in (('bytes', body), ('protocol', HOPOPT(body)), ('schema', HOPOPT(body).schema)):
            with self.subTest(payload=label):
                proto = IPv6(next=0, src='::1', dst='::2', payload=payload)
                self.assertEqual(proto.data, ipv6(0, 0, body))
                self.assertEqual(str(proto.protochain), 'IPv6:HOPOPT:TCP')
                self.assertEqual((proto.info.payload, proto.info.raw_len), (0, 70000 - 8))
                self.assertEqual(IPv6.from_data(proto.info).data, proto.data)
                self.assertEqual(IPv6(proto.data).data, proto.data)

    def test_explicitly_invalid_input_still_raises(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.utilities.exceptions import ProtocolError

        for label, kwargs, message in (
            ('Jumbo Payload Length 28', {'payload': hbh(6, 8 + len(TCP)) + TCP},
             'Jumbo Payload Length 28, not greater than 65,535'),
            ('Jumbo Payload Length 65535', {'payload': hbh(6, 65535) + TCP},
             'Jumbo Payload Length 65535, not greater than 65,535'),
            ('a non-zero payload_length', {'payload': hbh(6, 70000) + TCP, 'payload_length': 8 + len(TCP)},
             'Jumbo Payload option with a non-zero Payload Length 28'),
            ('Fragment header', {'payload': hbh(44, 70000) + bytes([6, 0, 0, 0, 0, 0, 0, 1]) + TCP},
             'Jumbo Payload option with a Fragment header'),
        ):
            with self.subTest(case=label):
                with self.assertRaises(ProtocolError) as caught:
                    IPv6(next=0, **kwargs)
                self.assertEqual(str(caught.exception), f'IPv6: {message}')

    def test_no_leading_jumbo_payload_option_keeps_the_payload_length(self) -> None:
        # RFC 2675 section 2: only a Hop-by-Hop Options header right after the IPv6 header holds one
        from pcapkit.protocols.internet.ipv6 import IPv6

        for label, nxt, body in (
            ('Hop-by-Hop Options header, no Jumbo Payload option', 0, bytes([6, 0, 1, 4, 0, 0, 0, 0]) + TCP),
            ('Jumbo Payload option behind a Destination Options header', 60,
             bytes([0, 0, 1, 4, 0, 0, 0, 0]) + hbh(6, 70000) + TCP),
        ):
            with self.subTest(case=label):
                proto = IPv6(next=nxt, src='::1', dst='::2', payload=body)
                self.assertEqual(proto.data, ipv6(len(body), nxt, body))
                self.assertEqual(IPv6.from_data(proto.info).data, proto.data)

    def test_hopopt_alone_and_in_ipv4_are_unchanged(self) -> None:
        # the Payload Length rule is IPv6's, so a short Jumbo Payload Length elsewhere is kept as given
        from pcapkit.const.ipv6.option import Option
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv4 import IPv4

        hop = HOPOPT(next=6, options=[(Option.Jumbo_Payload, {'len': 8 + len(TCP)})], payload=TCP)
        self.assertEqual(hop.data, hbh(6, 8 + len(TCP)) + TCP)
        self.assertEqual(str(hop.protochain), 'HOPOPT:TCP')
        self.assertEqual(HOPOPT.from_data(hop.info).data, hop.data)

        proto = IPv4(protocol=0, payload=hop)
        self.assertEqual(proto.data[2:4], (20 + len(hop.data)).to_bytes(2, 'big'))
        self.assertEqual(proto.data[20:], hop.data)
        self.assertEqual(str(proto.protochain), 'IPv4:HOPOPT:TCP')
        self.assertEqual(IPv4.from_data(proto.info).data, proto.data)
        self.assertEqual(IPv4(proto.data).data, proto.data)


if __name__ == '__main__':
    unittest.main()
