# -*- coding: utf-8 -*-
"""pyshark keys a segment by its header's addresses, and reads within the default engine's bounds. C.f. #1609, #1671.

Where a frame's octets cannot be had, pyshark traces the TCP tshark dissects.
It took tshark's ``ip.dst`` for the destination there. tshark reports none
behind an LSRR or SSRR option whose route data is no whole number of
addresses, so a bare :exc:`AttributeError` ended the extraction; and behind a
route not yet used up, ``ip.dst`` is the route's last address, so the segment
was keyed by that hop. It now takes the header's destination, tshark's
``ip.cur_rt`` there, and reads no segment where tshark reports no destination,
as the default engine's parser rejects such an option (#1671).

Read from its octets, a frame was followed through IP-in-IP, AH and extension
headers past its 64th layer, where the default engine dissects nothing. And a
frame tshark stops in was not read at all: tshark dissects no more than 20
802.1Q tags of a frame. pyshark now counts the layers as the default engine
does, and reads a frame tshark stops in a stack of 802.1Q tags from its octets
too (#1609).

Every capture is built here, so the module is in the unit tier. The tests that
run tshark skip unless the pyshark engine runs, which needs ``pyshark``, the
``tshark`` binary and Python 3.13 or older; the rest use fakes.

"""
from __future__ import annotations

import ipaddress
import struct
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire
from tests.toolkit.test_pyshark_encapsulated_tcp_1639_unit import (BAD_TIMESTAMP, HAS_RUNTIME,
                                                                   HOP_1, HOP_2, LSRR, FakeField,
                                                                   FakeLayer, build, eth,
                                                                   fake_packet, ip_layer, read,
                                                                   route, tcp, tcp_layer, v4, v6,
                                                                   vlan)
from tests.toolkit.test_tcp_carrier_walk_1606_1617_unit import ah, options

if TYPE_CHECKING:
    from typing import Any, Callable

#: An 802.1Q and an 802.1ad tag's TPID.
C_TAG, S_TAG = 0x8100, 0x88A8


def option(kind: int, length: int, pointer: int, data: bytes) -> bytes:
    """An IPv4 option of ``kind`` claiming ``length`` octets, then ``pointer`` and ``data``, padded to 32 bits."""
    raw = bytes([kind, length, pointer]) + data
    return raw + bytes(-len(raw) % 4)


#: An LSRR option of length 9, whose route data is no whole number of addresses.
LSRR_9 = option(0x83, 9, 4, HOP_1 + b'\x01\x02')


def nest(packet: bytes, count: int, outer: int = 4) -> bytes:
    """``packet`` tunnelled in ``count`` IPv4 (``outer`` 4) or IPv6 (6) headers."""
    for _ in range(count):
        proto = 41 if packet[0] >> 4 == 6 else 4
        packet = v4(packet, proto) if outer == 4 else v6(packet, proto)
    return packet


def pairs(count: int, ipv6: bool, number: int) -> bytes:
    """TCP behind ``count`` IPv4 packets, each with an AH, or IPv6 packets, each with a Hop-by-Hop header."""
    packet, nxt = tcp(number), 6
    for _ in range(count):
        packet = v6(options(nxt) + packet, 0) if ipv6 else v4(ah(nxt) + packet, 51)
        nxt = 41 if ipv6 else 4
    return packet


def chain(count: int, nxt: int = 6) -> bytes:
    """``count`` Destination Options headers in a row, the last naming ``nxt``."""
    return b''.join(bytes([60 if index < count - 1 else nxt, 0, 1, 4, 0, 0, 0, 0]) for index in range(count))


#: Ethernet frames carrying TCP behind an IPv4 route option, each with whether
#: the default engine traces it, by a name for it, as
#: :data:`~tests.toolkit.test_pyshark_encapsulated_tcp_1639_unit.ENCAPSULATION_CASES`.
#: tshark reports no ``ip.dst`` behind each malformed route, and the last hop
#: as ``ip.dst`` behind each route not used up.
ROUTE_CASES = {
    'control': (True, lambda n: eth(v4(tcp(n)))),
    'lsrr of length 9': (False, lambda n: eth(v4(tcp(n), opts=LSRR_9))),
    'ssrr of length 9': (False, lambda n: eth(v4(tcp(n), opts=option(0x89, 9, 4, HOP_1 + b'\x01\x02')))),
    'lsrr of length 9, one hop used': (False, lambda n: eth(v4(tcp(n), opts=option(0x83, 9, 8, HOP_1 + b'\x01\x02')))),
    'lsrr of length 5': (False, lambda n: eth(v4(tcp(n), opts=option(0x83, 5, 4, b'\x01\x02')))),
    'lsrr of length 13': (False, lambda n: eth(v4(tcp(n), opts=option(0x83, 13, 4, HOP_1 + bytes(6))))),
    'lsrr of length 9, inner': (False, lambda n: eth(v4(v4(tcp(n), inner=True, opts=LSRR_9), 4))),
    'lsrr': (True, lambda n: eth(v4(tcp(n), opts=LSRR))),
    'ssrr': (True, lambda n: eth(v4(tcp(n), opts=route(0x89, 4, HOP_1)))),
    'lsrr, two hops, one used': (True, lambda n: eth(v4(tcp(n), opts=route(0x83, 8, HOP_1, HOP_2)))),
    'lsrr, used up': (True, lambda n: eth(v4(tcp(n), opts=route(0x83, 8, HOP_1)))),
    'record route': (True, lambda n: eth(v4(tcp(n), opts=route(0x07, 8, HOP_1)))),
    'lsrr, inner': (True, lambda n: eth(v4(v4(tcp(n), inner=True, opts=LSRR), 4))),
    'lsrr, 4in4': (True, lambda n: eth(v4(v4(tcp(n), inner=True), 4, opts=LSRR))),
    'lsrr, 6in4': (True, lambda n: eth(v4(v6(tcp(n), inner=True), 41, opts=LSRR))),
    'control, ipv6': (True, lambda n: eth(v6(tcp(n)))),
    'control, after the rest': (True, lambda n: eth(v4(tcp(n)))),
}

#: Ethernet frames carrying TCP around the 64-layer bound of a frame, Ethernet
#: being layer 1, and each VLAN tag, IP header, AH and IPv6 extension header one
#: more; by a name for each, with whether the default engine traces it. tshark
#: traces every one but those behind more than 20 802.1Q tags.
BOUND_CASES = {
    'tcp in 62 ipv4 (layer 64)': (True, lambda n: eth(nest(v4(tcp(n)), 61))),
    'tcp in 63 ipv4 (layer 65)': (False, lambda n: eth(nest(v4(tcp(n)), 62))),
    'tcp in 100 ipv4': (False, lambda n: eth(nest(v4(tcp(n)), 99))),
    'tcp in 62 ipv6 (layer 64)': (True, lambda n: eth(nest(v6(tcp(n)), 61, 6))),
    'tcp in 63 ipv6 (layer 65)': (False, lambda n: eth(nest(v6(tcp(n)), 62, 6))),
    'tcp in ipv4 in 61 ipv6 (layer 64)': (True, lambda n: eth(nest(v4(tcp(n)), 61, 6))),
    'tcp in ipv4 in 62 ipv6 (layer 65)': (False, lambda n: eth(nest(v4(tcp(n)), 62, 6))),
    'tcp behind 31 (ipv4, ah) pairs (layer 64)': (True, lambda n: eth(pairs(31, False, n))),
    'tcp behind 32 (ipv4, ah) pairs (layer 66)': (False, lambda n: eth(pairs(32, False, n))),
    'tcp behind 31 (ipv6, hop-by-hop) pairs (layer 64)': (True, lambda n: eth(pairs(31, True, n))),
    'tcp behind 32 (ipv6, hop-by-hop) pairs (layer 66)': (False, lambda n: eth(pairs(32, True, n))),
    'tcp behind 61 ipv4 and a hop-by-hop header (layer 64)': (
        True, lambda n: eth(nest(v4(options(6) + tcp(n), 0), 60))),
    'tcp behind 62 ipv4 and a hop-by-hop header (layer 65)': (
        False, lambda n: eth(nest(v4(options(6) + tcp(n), 0), 61))),
    'tcp behind 50 ipv4, ipv6 and 11 extension headers (layer 64)': (
        True, lambda n: eth(nest(v6(chain(11) + tcp(n), 60), 50))),
    'tcp behind 50 ipv4, ipv6 and 12 extension headers (layer 65)': (
        False, lambda n: eth(nest(v6(chain(12) + tcp(n), 60), 50))),
    'tcp behind 61 802.1ad tags (layer 64)': (True, lambda n: vlan(v4(tcp(n)), *[S_TAG] * 61)),
    'tcp behind 62 802.1ad tags (layer 65)': (False, lambda n: vlan(v4(tcp(n)), *[S_TAG] * 62)),
    # tshark dissects at most 20 802.1Q tags of a frame
    'tcp behind 20 802.1q tags': (True, lambda n: vlan(v4(tcp(n)), *[C_TAG] * 20)),
    'tcp behind 21 802.1q tags': (True, lambda n: vlan(v4(tcp(n)), *[C_TAG] * 21)),
    'tcp behind 30 802.1q tags, ipv6': (True, lambda n: vlan(v6(tcp(n)), *[C_TAG] * 30)),
    'tcp behind 42 802.1ad and 802.1q tags': (True, lambda n: vlan(v4(tcp(n)), *[S_TAG, C_TAG] * 21)),
    'tcp in 4in4 behind 30 802.1q tags': (True, lambda n: vlan(v4(v4(tcp(n), inner=True), 4), *[C_TAG] * 30)),
    'tcp behind 61 802.1q tags (layer 64)': (True, lambda n: vlan(v4(tcp(n)), *[C_TAG] * 61)),
    'tcp behind 62 802.1q tags (layer 65)': (False, lambda n: vlan(v4(tcp(n)), *[C_TAG] * 62)),
    'udp behind 30 802.1q tags': (False, lambda n: vlan(v4(wire.udp(b'data'), 17), *[C_TAG] * 30)),
    'tcp behind 30 802.1q tags, rejected ipv4 options': (
        False, lambda n: vlan(v4(tcp(n), opts=BAD_TIMESTAMP), *[C_TAG] * 30)),
}

#: Frames of other link types carrying TCP around the bound, by a name for
#: each, with the link type and whether the default engine traces it.
LINK_BOUND_CASES = {
    'null, tcp in 62 ipv4 (layer 64)': (0, True, lambda n: b'\x02\x00\x00\x00' + nest(v4(tcp(n)), 61)),
    'null, tcp in 63 ipv4 (layer 65)': (0, False, lambda n: b'\x02\x00\x00\x00' + nest(v4(tcp(n)), 62)),
    'raw, tcp in 63 ipv4 (layer 64)': (101, True, lambda n: nest(v4(tcp(n)), 62)),
    'raw, tcp in 64 ipv4 (layer 65)': (101, False, lambda n: nest(v4(tcp(n)), 63)),
}


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PySharkFallbackAndBoundTests(unittest.TestCase):
    """The pyshark engine traces the TCP the default engine reads, as the cases say."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def agree(self, cases: 'dict[str, tuple[bool, Callable[[int], bytes]]]', linktype: int = 1) -> None:
        frames, reads = build(cases)
        capture = wire.pcap([(1, number, octets) for number, octets in enumerate(frames)], linktype=linktype)
        names = dict(enumerate(cases, start=1))
        base = read(self, 'default', capture)
        # what the default engine reads, as the cases say
        self.assertEqual([names[number] for number in sorted(base['trace'])], [names[number] for number in reads])
        seen = read(self, 'pyshark', capture)
        self.assertEqual({names[number]: seen['trace'].get(number) for number in names},
                         {names[number]: base['trace'].get(number) for number in names})
        self.assertEqual(seen['flows'], base['flows'])

    def test_where_the_octets_cannot_be_had_a_route_option_ends_no_extraction(self) -> None:
        # the second pass fails, so every frame is traced as tshark dissects
        # it: the header's destination, and nothing where tshark reports none
        with mock.patch('pcapkit.toolkit.pyshark.OCTETS_FILTER', 'tcp ||'):
            self.agree(ROUTE_CASES)
            self.agree({'raw, lsrr': (True, lambda n: v4(tcp(n), opts=LSRR)),
                        'raw, lsrr of length 9': (False, lambda n: v4(tcp(n), opts=LSRR_9))}, 101)

    def test_nothing_is_traced_past_the_frame_layer_bound(self) -> None:
        self.agree(BOUND_CASES)
        for linktype in sorted({link for link, _, _ in LINK_BOUND_CASES.values()}):
            with self.subTest(linktype=linktype):
                self.agree({name: (reads, make) for name, (link, reads, make) in LINK_BOUND_CASES.items()
                            if link == linktype}, linktype)


def routed(octets: bytes, start: int, hop: bytes) -> FakeLayer:
    """tshark's ``ip`` layer behind a route not used up: the header's destination as ``cur_rt``, ``hop`` as ``dst``."""
    layer = ip_layer(octets, start)
    return FakeLayer('ip', **{**{name: getattr(layer, name) for name in layer.field_names}, 'cur_rt': layer.dst,
                              'dst': FakeField(str(ipaddress.ip_address(hop)), start + 23, hop.hex())})


def bare(layer: FakeLayer, *names: str) -> FakeLayer:
    """``layer`` without its fields ``names``, as tshark reports a layer it does not finish."""
    return FakeLayer(layer.layer_name, **{name: getattr(layer, name) for name in layer.field_names
                                          if name not in names})


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ToolkitFallbackTests(unittest.TestCase):
    """Where the frame cannot be had, :func:`tcp_traceflow` keys tshark's segment by the header; no tshark."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_a_header_tshark_reports_no_address_of_is_not_traced(self) -> None:
        from pcapkit.toolkit import pyshark as toolkit

        octets = eth(v4(tcp(7), opts=LSRR_9))
        header = ip_layer(octets, 14)
        for name, layer in (('no destination', bare(header, 'dst')),
                            ('no destination, the header\'s as cur_rt', FakeLayer('ip', **{
                                **{field: getattr(header, field) for field in header.field_names if field != 'dst'},
                                'cur_rt': header.dst})),
                            ('no source', bare(header, 'src'))):
            for captured in (None, lambda p: None):
                with self.subTest(case=name, captured=captured):
                    packet = fake_packet('eth', '1', [layer, tcp_layer(octets, 46)])
                    self.assertIsNone(toolkit.tcp_traceflow(packet, captured=captured))

    def test_a_source_routed_segment_is_keyed_by_the_header_destination(self) -> None:
        from pcapkit.toolkit import pyshark as toolkit

        plain = eth(v4(tcp(7), opts=LSRR))
        tunnel = eth(v4(v4(tcp(7), inner=True, opts=LSRR), 4))  # the inner header's addresses swapped
        for name, packet, addresses in (
            ('lsrr', fake_packet('eth', '1', [routed(plain, 14, HOP_1), tcp_layer(plain, 42)]),
             (wire.IPV4_A, wire.IPV4_B)),
            ('lsrr, inner', fake_packet('eth', '1', [ip_layer(tunnel, 14), routed(tunnel, 34, HOP_1),
                                                     tcp_layer(tunnel, 62)]), (wire.IPV4_B, wire.IPV4_A)),
        ):
            for captured in (None, lambda p: None):
                with self.subTest(case=name, captured=captured):
                    data = toolkit.tcp_traceflow(packet, captured=captured)
                    self.assertEqual((data.src, data.dst, data.srcport),
                                     (*map(ipaddress.ip_address, addresses), 1007))
        # an IPv6 header's destination is tshark's ipv6.dst
        octets = eth(v6(tcp(7)))
        data = toolkit.tcp_traceflow(fake_packet('eth', '1', [ip_layer(octets, 14), tcp_layer(octets, 54)]))
        self.assertEqual(data.dst, ipaddress.ip_address(wire.IPV6_B))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ToolkitBoundTests(unittest.TestCase):
    """:func:`tcp_traceflow` reads a frame's octets within the default engine's bounds; no tshark."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def trace(self, linktype: int, octets: bytes, ip: int, at: int, link: str = 'eth') -> 'Any':
        """Trace ``octets`` as tshark dissects them: the IP header at ``ip``, the TCP one at ``at``."""
        from pcapkit.toolkit import pyshark as toolkit

        packet = fake_packet(link, '1', [ip_layer(octets, ip), tcp_layer(octets, at)])
        return toolkit.tcp_traceflow(packet, captured=lambda p: toolkit.Captured(linktype, octets))

    def test_no_tcp_is_read_past_the_64th_layer(self) -> None:
        # Ethernet is layer 1, then each IP header, AH and extension header
        reads = {}
        for count, layer in ((61, 64), (62, 65)):
            octets = eth(nest(v4(tcp(7)), count))
            reads[f'tcp in {count + 1} ipv4 (layer {layer})'] = self.trace(1, octets, 14, 14 + 20 * (count + 1))
            octets = nest(v4(tcp(7)), count + 1)
            reads[f'raw, tcp in {count + 2} ipv4 (layer {layer})'] = self.trace(101, octets, 0, 20 * (count + 2), 'raw')
            octets = eth(nest(v6(tcp(7)), count, 6))
            reads[f'tcp in {count + 1} ipv6 (layer {layer})'] = self.trace(1, octets, 14, 14 + 40 * (count + 1))
        for headers, layer in ((11, 64), (12, 65), (13, 66)):
            octets = eth(nest(v6(chain(headers) + tcp(7), 60), 50))
            reads[f'tcp behind 50 ipv4, ipv6 and {headers} extension headers (layer {layer})'] = self.trace(
                1, octets, 14, 14 + 50 * 20 + 40 + 8 * headers)
        for count, layer in ((31, 64), (32, 66)):
            octets = eth(pairs(count, False, 7))  # each pair 44 octets: an IPv4 header and a 24-octet AH
            reads[f'tcp behind {count} (ipv4, ah) pairs (layer {layer})'] = self.trace(1, octets, 14,
                                                                                       14 + 44 * count)
        self.assertEqual({name: data is not None for name, data in reads.items()}, {
            'tcp in 62 ipv4 (layer 64)': True, 'raw, tcp in 63 ipv4 (layer 64)': True,
            'tcp in 62 ipv6 (layer 64)': True,
            'tcp in 63 ipv4 (layer 65)': False, 'raw, tcp in 64 ipv4 (layer 65)': False,
            'tcp in 63 ipv6 (layer 65)': False,
            'tcp behind 50 ipv4, ipv6 and 11 extension headers (layer 64)': True,
            'tcp behind 50 ipv4, ipv6 and 12 extension headers (layer 65)': False,
            'tcp behind 50 ipv4, ipv6 and 13 extension headers (layer 66)': False,
            'tcp behind 31 (ipv4, ah) pairs (layer 64)': True,
            'tcp behind 32 (ipv4, ah) pairs (layer 66)': False,
        })

    def test_a_frame_tshark_stops_in_802_1q_tags_is_read_from_its_octets(self) -> None:
        from pcapkit.toolkit import pyshark as toolkit

        # tshark dissects 21 vlan layers, the last with "Too many nested VLAN tags", and stops
        stopped = [FakeLayer('vlan') for _ in range(21)]
        reads = {}
        for count, layer in ((30, 33), (61, 64), (62, 65)):
            octets = vlan(v4(tcp(7)), *[C_TAG] * count)
            asked = []  # type: list[Any]
            packet = fake_packet('eth', '1', stopped)
            data = toolkit.tcp_traceflow(packet, captured=lambda p, o=octets: asked.append(p)
                                         or toolkit.Captured(1, o))
            self.assertEqual(asked, [packet])
            reads[f'tcp behind {count} 802.1q tags (layer {layer})'] = None if data is None else data.srcport
        octets = wire.ethernet(struct.pack('>HH', 1, C_TAG) * 29 + struct.pack('>HH', 1, 0x0806) + bytes(28), C_TAG)
        reads['arp behind 30 802.1q tags'] = toolkit.tcp_traceflow(
            fake_packet('eth', '1', stopped), captured=lambda p: toolkit.Captured(1, octets))
        self.assertEqual(reads, {'tcp behind 30 802.1q tags (layer 33)': 1007,
                                 'tcp behind 61 802.1q tags (layer 64)': 1007,
                                 'tcp behind 62 802.1q tags (layer 65)': None,
                                 'arp behind 30 802.1q tags': None})

        # a frame tshark dissects an IP layer behind its tags in is not asked
        # for, unless it finds TCP there; and the second pass writes every
        # frame with a VLAN tag
        def refuse(packet: 'Any') -> 'Any':
            raise AssertionError('octets asked for')

        octets = vlan(v4(wire.udp(b'data'), 17), C_TAG)
        self.assertIsNone(toolkit.tcp_traceflow(fake_packet('eth', '1', [FakeLayer('vlan'), ip_layer(octets, 18),
                                                                         FakeLayer('udp')]), captured=refuse))
        self.assertEqual(toolkit.OCTETS_FILTER.rsplit(' || ', maxsplit=1)[1], 'vlan')


if __name__ == '__main__':
    unittest.main()
