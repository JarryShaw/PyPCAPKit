# -*- coding: utf-8 -*-
"""scapy reads what the default engine dissects at every link type, and within its bounds. C.f. #1609, #1626, #1650.

The default engine dissects the first layer of six link types alone, and keeps
the frames of any other raw. `Scapy`_ dissects IP and TCP straight behind the
headers of many of those, such as ``LINUX_SLL``, ``LINUX_SLL2``, ``PPP`` and the
``DLT_RAW`` of 12, and its engine handed them over. Behind a BSD loopback header
it read IPv6 at the ``AF_INET6`` of the host it ran on, and IPv4 at family 0 too,
where the default engine reads IPv4 at family 2 and IPv6 at 24, 28 and 30 on
every host (#1650).

The default engine dissects no layer past the 64th of a frame, nor an
extension header past the 32nd in a row. `Scapy`_ stops at neither, and its
engine handed over the TCP, IPv4 and IPv6 fragments it found past them, behind
62 VLAN tags among them (#1609).

`Scapy`_ dissects no TCP and no IPv4 behind an AH, and IPv4 where its Next Header
is 0; nothing behind a Mobility header; and neither HIP nor Shim6. The default
engine reads past each, so scapy now walks an IPv6 extension header chain over
the octets by the default engine's rules, as it walks those inside IPv4 (#1626).

Every engine is compared frame for frame with the default engine, on every
input it hands TCP and IP reassembly and TCP flow tracing. Every capture is
built here, so the module is in the unit tier.

.. _Scapy: https://scapy.net

"""
from __future__ import annotations

import importlib.util
import unittest
from typing import TYPE_CHECKING, NamedTuple
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire
from tests.toolkit import test_dpkt_ipv4_reassembly_input_1615_1616_unit as ipv4_input
from tests.toolkit.test_scapy_ipv6_fragment_and_encap_walk_1635_1636_unit import (C_TAG, fragment6,
                                                                                  read, tagged)
from tests.toolkit.test_tcp_carrier_walk_1606_1617_unit import ah, eth, options, tcp, v4, v6

if TYPE_CHECKING:
    from typing import Any, Callable

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)
HAS_SCAPY = importlib.util.find_spec('scapy') is not None

#: The inputs compared, as :func:`read` keys them.
ASPECTS = ('tcp', 'trace', 'ipv4', 'ipv6', 'ipv4 datagrams', 'ipv6 datagrams', 'ids', 'flows')


class Case(NamedTuple):
    """Frames of one link type, and what the default engine reads in them."""

    #: The capture's link type.
    linktype: int
    #: The frames.
    frames: 'list[bytes]'
    #: How many frames the default engine hands TCP, IPv4 and IPv6 reassembly.
    reads: 'tuple[int, int, int]'


def version(packet: bytes) -> int:
    return 6 if packet[0] >> 4 == 6 else 4


def v4_fragments(ident: int) -> 'list[bytes]':
    """The two fragments of a 24-octet IPv4 datagram."""
    return [ipv4_input.ipv4(b'A' * 16, ident=ident, mf=True), ipv4_input.ipv4(b'B' * 8, ident=ident, offset=16)]


def v6_fragments(ident: int, head: bytes = b'', code: int = 44) -> 'list[bytes]':
    """The two fragments of a 24-octet IPv6 datagram, ``head`` (of code ``code``) before each Fragment header."""
    return [v6(head + fragment6(b'A' * 16, ident=ident, mf=True), code),
            v6(head + fragment6(b'B' * 8, ident=ident, offset=16), code)]


def each(carry: 'Callable[[bytes], bytes]') -> 'list[bytes]':
    """TCP in IPv4 and in IPv6, then two IPv4 and two IPv6 fragments, each carried by ``carry``."""
    return [carry(packet) for packet in (v4(tcp(1), 6), v6(tcp(2), 6), *v4_fragments(3), *v6_fragments(4))]


def ethertype(packet: bytes) -> bytes:
    """The EtherType of the IP ``packet``, as octets."""
    return (0x86DD if version(packet) == 6 else 0x0800).to_bytes(2, 'big')


def sll(packet: bytes) -> bytes:
    """A LINUX_SLL header (16 octets), then the IP ``packet``."""
    return b'\x00\x00\x00\x01\x00\x06' + wire.MAC_A + b'\x00\x00' + ethertype(packet) + packet


def sll2(packet: bytes) -> bytes:
    """A LINUX_SLL2 header (20 octets), then the IP ``packet``."""
    return ethertype(packet) + b'\x00\x00\x00\x00\x00\x01\x00\x01\x00\x06' + wire.MAC_A + b'\x00\x00' + packet


def ppp(packet: bytes) -> bytes:
    """A PPP frame with no HDLC-like framing, carrying the IP ``packet``."""
    return (0x0057 if version(packet) == 6 else 0x0021).to_bytes(2, 'big') + packet


def loopback(order: str, ipv4: int, ipv6: int) -> 'Callable[[bytes], bytes]':
    """A BSD loopback header of family ``ipv4`` or ``ipv6``, written ``order``-endian, then the IP packet."""
    return lambda packet: (ipv6 if version(packet) == 6 else ipv4).to_bytes(4, order) + packet


def nest(packet: bytes, count: int, outer: int) -> bytes:
    """``packet`` tunnelled in ``count`` IPv4 (``outer`` 4) or IPv6 (6) headers."""
    for _ in range(count):
        proto = 41 if version(packet) == 6 else 4
        packet = v4(packet, proto) if outer == 4 else v6(packet, proto)
    return packet


def vlan(packet: bytes, count: int) -> bytes:
    """An Ethernet frame carrying the IP ``packet`` behind ``count`` 802.1Q tags."""
    return tagged(packet, *[C_TAG] * count)


def pairs(count: int, ipv6: bool) -> bytes:
    """TCP behind ``count`` IPv4 packets, each with an AH, or IPv6 packets, each with a Hop-by-Hop header."""
    packet, nxt = tcp(1), 6
    for _ in range(count):
        packet = v6(options(nxt) + packet, 0) if ipv6 else v4(ah(nxt) + packet, 51)
        nxt = 41 if ipv6 else 4
    return packet


def chain(count: int, nxt: int, code: int = 60) -> bytes:
    """``count`` 8-octet headers of type ``code``, each one PadN option, the last naming ``nxt``."""
    return b''.join(bytes([code if index < count - 1 else nxt, 0, 1, 4, 0, 0, 0, 0]) for index in range(count))


def frag(nxt: int, mf: bool = False) -> bytes:
    """A Fragment header of offset 0."""
    return bytes([nxt, 0, 0, int(mf)]) + (0xDEADBEEF).to_bytes(4, 'big')


#: The IPv6 extension headers of #1626, each a builder taking the Next Header it
#: names, and its own code.
HEADERS = {
    'fragment then ah': (lambda nxt: frag(51) + ah(nxt), 44),
    'ah': (ah, 51),
    'mobility': (lambda nxt: bytes([nxt, 0, 0, 0, 0, 0, 0, 0]), 135),
    'hip': (lambda nxt: bytes([nxt, 4, 1, 0x21, 0, 0, 0, 0]) + b'\x11' * 32, 139),
    'shim6': (lambda nxt: bytes([nxt, 0]) + bytes(6), 140),
    'hop-by-hop then mobility': (lambda nxt: options(135) + bytes([nxt, 0, 0, 0, 0, 0, 0, 0]), 0),
    'ah then hop-by-hop': (lambda nxt: ah(0) + options(nxt), 51),
}


def cases_1650() -> 'dict[str, Case]':
    cases = {
        'linux_sll (113)': Case(113, each(sll), (0, 0, 0)),
        'linux_sll2 (276)': Case(276, each(sll2), (0, 0, 0)),
        'dlt_raw (12)': Case(12, each(lambda packet: packet), (0, 0, 0)),
        'ppp (9) without ff 03': Case(9, each(ppp), (0, 0, 0)),
        # controls: the link types the default engine dissects
        'ethernet (1)': Case(1, each(eth), (2, 3, 2)),
        'raw (101)': Case(101, each(lambda packet: packet), (2, 3, 2)),
        'ipv4 (228)': Case(228, each(lambda packet: packet), (1, 3, 0)),
        'ipv6 (229)': Case(229, each(lambda packet: packet), (1, 0, 2)),
    }
    for linktype, name, order in ((0, 'null', 'little'), (0, 'null', 'big'), (108, 'loop', 'big')):
        for family in (24, 28, 30):
            cases[f'{name} ({linktype}) {order}-endian, ipv6 at {family}'] = Case(
                linktype, each(loopback(order, 2, family)), (2, 3, 2))
        cases[f'{name} ({linktype}) {order}-endian, ipv6 at 10'] = Case(
            linktype, each(loopback(order, 2, 10)), (1, 3, 0))
        cases[f'{name} ({linktype}) {order}-endian, family 0'] = Case(
            linktype, each(loopback(order, 0, 0)), (0, 0, 0))
    cases['loop (108) little-endian'] = Case(108, each(loopback('little', 2, 24)), (0, 0, 0))
    cases['null (0) cut short'] = Case(0, [b'\x02\x00'], (0, 0, 0))
    cases['null (0) ipv4 cut short'] = Case(0, [loopback('little', 2, 24)(v4(tcp(1), 6))[:20]], (0, 0, 0))
    return cases


def cases_1609() -> 'dict[str, Case]':
    # Ethernet is layer 1, and each VLAN tag, IP header and extension header one more
    return {
        'tcp in 62 ipv4 (layer 64)': Case(1, [eth(nest(v4(tcp(1), 6), 61, 4))], (1, 1, 0)),
        'tcp in 63 ipv4 (layer 65)': Case(1, [eth(nest(v4(tcp(1), 6), 62, 4))], (0, 1, 0)),
        'tcp in 63 ipv6 (layer 65)': Case(1, [eth(nest(v6(tcp(1), 6), 62, 6))], (0, 0, 0)),
        'tcp behind 31 (ipv4, ah) pairs (layer 64)': Case(1, [eth(pairs(31, False))], (1, 1, 0)),
        'tcp behind 32 (ipv4, ah) pairs (layer 66)': Case(1, [eth(pairs(32, False))], (0, 1, 0)),
        'tcp behind 31 (ipv6, hop-by-hop) pairs (layer 64)': Case(1, [eth(pairs(31, True))], (1, 0, 0)),
        'tcp behind 32 (ipv6, hop-by-hop) pairs (layer 66)': Case(1, [eth(pairs(32, True))], (0, 0, 0)),
        'ipv4 fragments in 62 ipv6 (layer 64)': Case(1, [eth(nest(p, 62, 6)) for p in v4_fragments(1)], (0, 2, 0)),
        'ipv4 fragments in 63 ipv6 (layer 65)': Case(1, [eth(nest(p, 63, 6)) for p in v4_fragments(1)], (0, 0, 0)),
        'ipv6 fragments in 62 ipv4 (layer 65)': Case(1, [eth(nest(p, 62, 4)) for p in v6_fragments(1)], (0, 2, 0)),
        'tcp behind 61 vlan tags (layer 64)': Case(1, [vlan(v4(tcp(1), 6), 61)], (1, 1, 0)),
        'tcp behind 62 vlan tags (layer 65)': Case(1, [vlan(v4(tcp(1), 6), 62)], (0, 1, 0)),
        'ipv4 fragments behind 63 vlan tags (layer 65)': Case(1, [vlan(p, 63) for p in v4_fragments(1)], (0, 0, 0)),
        'ipv6 fragments behind 62 vlan tags (layer 65)': Case(1, [vlan(p, 62) for p in v6_fragments(1)], (0, 0, 0)),
        'tcp behind 32 extension headers': Case(1, [eth(v6(chain(32, 6) + tcp(1), 60))], (1, 0, 0)),
        'tcp behind 33 extension headers': Case(1, [eth(v6(chain(33, 6) + tcp(1), 60))], (0, 0, 0)),
        'tcp behind 33 hop-by-hop headers': Case(1, [eth(v6(chain(33, 6, 0) + tcp(1), 0))], (0, 0, 0)),
        'tcp behind 1000 extension headers': Case(1, [eth(v6(chain(1000, 6) + tcp(1), 60))], (0, 0, 0)),
        'fragment header after 32 extension headers': Case(
            1, [eth(p) for p in v6_fragments(1, chain(32, 44), 60)], (0, 0, 0)),
        'ipv4 fragments behind 33 extension headers': Case(
            1, [eth(v6(chain(33, 4) + p, 60)) for p in v4_fragments(1)], (0, 0, 0)),
        # Ethernet, 50 IPv4 at 2 to 51, IPv6 at 52, then the chain: the frame bound cuts it
        'tcp behind 50 ipv4, ipv6 and 12 extension headers (layer 65)': Case(
            1, [eth(nest(v6(chain(12, 6) + tcp(1), 60), 50, 4))], (0, 1, 0)),
        'fragment header behind 50 ipv4, ipv6 and 12 extension headers (layer 65)': Case(
            1, [eth(nest(v6(chain(12, 44) + fragment6(b'A' * 16, ident=1, mf=True), 60), 50, 4))], (0, 1, 0)),
        'tcp behind 62 ipv4 and a hop-by-hop header (layer 65)': Case(
            1, [eth(nest(v4(options(6) + tcp(1), 0), 61, 4))], (0, 1, 0)),
        'tcp in 64 ipv4 at link type raw (layer 65)': Case(101, [nest(v4(tcp(1), 6), 63, 4)], (0, 1, 0)),
        'tcp in 63 ipv4 behind a loopback header (layer 65)': Case(
            0, [loopback('little', 2, 24)(nest(v4(tcp(1), 6), 62, 4))], (0, 1, 0)),
        # controls, at the bound
        'tcp in 62 ipv6 (layer 64)': Case(1, [eth(nest(v6(tcp(1), 6), 61, 6))], (1, 0, 0)),
        'ipv6 fragments in 61 ipv4 (layer 64)': Case(1, [eth(nest(p, 61, 4)) for p in v6_fragments(1)], (0, 2, 2)),
        'ipv6 fragments behind 61 vlan tags (layer 64)': Case(1, [vlan(p, 61) for p in v6_fragments(1)], (0, 0, 2)),
        'fragment header after 31 extension headers': Case(
            1, [eth(p) for p in v6_fragments(1, chain(31, 44), 60)], (0, 0, 2)),
    }


def cases_1626() -> 'dict[str, Case]':
    cases = {}
    for label, (head, code) in HEADERS.items():
        cases[f'ipv6, {label}, tcp'] = Case(1, [eth(v6(head(6) + tcp(1), code)),
                                                eth(v6(head(6) + tcp(2, opts=b'\x02\x03\x05\xb4'), code))],
                                            (2, 0, 2 if label == 'fragment then ah' else 0))
        cases[f'ipv6, {label}, ipv4 fragments'] = Case(1, [eth(v6(head(4) + p, code)) for p in v4_fragments(1)],
                                                       (0, 2, 2 if label == 'fragment then ah' else 0))
        cases[f'ipv6, {label}, 6in6'] = Case(1, [eth(v6(head(41) + v6(tcp(1), 6), code))],
                                             (1, 0, 1 if label == 'fragment then ah' else 0))
        if label != 'fragment then ah':
            cases[f'ipv6, {label}, then ipv6 fragments'] = Case(1, [eth(p) for p in v6_fragments(1, head(44), code)],
                                                                (0, 0, 2))
    # behind an extension header in IPv4, the IPv6 packet IPv6 reassembly takes
    cases['6in4 fragments behind hop-by-hop in ipv4'] = Case(1, [eth(v4(options(41) + p, 0)) for p in v6_fragments(1)],
                                                             (0, 2, 2))
    cases['6in4 fragments behind mobility in ipv4'] = Case(
        1, [eth(v4(bytes([41, 0, 0, 0, 0, 0, 0, 0]) + p, 135)) for p in v6_fragments(1)], (0, 2, 2))
    # controls: what Scapy already dissects as the default engine does, and what neither reads past
    cases['ipv6, fragment then destination options, tcp'] = Case(1, [eth(v6(frag(60) + options(6) + tcp(1), 44))],
                                                                 (1, 0, 1))
    cases['ipv6, two fragment headers, tcp'] = Case(1, [eth(v6(frag(44, mf=True) + frag(6) + tcp(1), 44))], (1, 0, 1))
    cases['ipv6, mobility, tcp cut short'] = Case(1, [eth(v6(HEADERS['mobility'][0](6) + tcp(1)[:12], 135))],
                                                  (0, 0, 0))
    cases['ipv6, esp'] = Case(1, [eth(v6(b'\x00\x00\x01\x00\x00\x00\x00\x01' + bytes(8) + tcp(1), 50))], (0, 0, 0))
    cases['ipv6, 253'] = Case(1, [eth(v6(bytes([6, 0, 0, 0, 0, 0, 0, 0]) + tcp(1), 253))], (0, 0, 0))
    cases['ipv6, payload length cuts the chain'] = Case(
        1, [eth(v6(options(6) + tcp(1), 60)[:4] + (4).to_bytes(2, 'big') + v6(options(6) + tcp(1), 60)[6:])], (0, 0, 0))
    return cases


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
@unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
class ScapyLinkTypeAndLayerBoundTests(unittest.TestCase):
    """scapy hands on the TCP and IP the default engine dissects, frame for frame, and no other."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def agree(self, cases: 'dict[str, Case]') -> None:
        reads, disagree = {}, []
        for label, case in cases.items():
            base = read(self, 'default', case.frames, case.linktype)
            reads[label] = tuple(len(base[aspect]) for aspect in ('tcp', 'ipv4', 'ipv6'))
            self.assertEqual(sorted(base['tcp']), sorted(base['trace']), label)
            seen = read(self, 'scapy', case.frames, case.linktype)
            if any(seen[aspect] != base[aspect] for aspect in ASPECTS):
                disagree.append(label)
        # what the default engine reads, as the cases say, then that scapy reads the same
        self.assertEqual(reads, {label: case.reads for label, case in cases.items()})
        self.assertEqual(disagree, [])

    def test_no_ip_is_read_at_a_link_type_the_default_engine_leaves_raw(self) -> None:
        # #1650
        self.agree(cases_1650())

    def test_nothing_is_read_past_the_frame_or_extension_header_bound(self) -> None:
        # #1609
        self.agree(cases_1609())

    def test_tcp_and_ip_are_read_behind_every_extension_header_the_default_engine_reads_past(self) -> None:
        # #1626
        self.agree(cases_1626())

    def test_the_loopback_families_do_not_depend_on_the_host(self) -> None:
        # #1650: Scapy binds IPv6 to the host's own AF_INET6 (10 here), and IPv4
        # to family 0 too; bound as on a BSD instead, it dissects otherwise, but
        # scapy reads the same as the default engine either way
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import Loopback

        bsd = [({'type': 2}, IP), ({'type': 24}, IPv6), ({'type': 28}, IPv6)]
        for linktype, order in ((0, 'little'), (0, 'big'), (108, 'big')):
            for ipv4, ipv6 in ((2, 10), (2, 24), (2, 28), (2, 30), (0, 0)):
                frames = each(loopback(order, ipv4, ipv6))
                with self.subTest(linktype=linktype, order=order, families=(ipv4, ipv6)):
                    base = read(self, 'default', frames, linktype)
                    here = read(self, 'scapy', frames, linktype)
                    with mock.patch.object(Loopback, 'payload_guess', bsd):
                        there = read(self, 'scapy', frames, linktype)
                    self.assertEqual([(here[aspect], there[aspect]) for aspect in ASPECTS],
                                     [(base[aspect], base[aspect]) for aspect in ASPECTS])

    def test_a_packet_built_by_hand_is_read_by_its_first_layer(self) -> None:
        # ``scapy.all`` binds every layer here, as the engine has it do (see pcapkit.toolkit.scapy)
        import scapy.all  # noqa: F401 # pylint: disable=unused-import
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import CookedLinux, Dot3, Ether, Loopback, LoopbackOpenBSD
        from scapy.packet import Raw

        from pcapkit.toolkit import scapy as toolkit

        segment = v4(tcp(1), 6)

        def reads(packet: 'Any') -> bool:
            return toolkit.tcp_reassembly(packet) is not None

        self.assertEqual({
            'ethernet': reads(Ether(eth(segment))),
            'ipv4': reads(IP(segment)),
            'ipv6': reads(IPv6(v6(tcp(1), 6))),
            'null, family 24': reads(Loopback(loopback('little', 2, 24)(v6(tcp(1), 6)))),
            'null, family 10': reads(Loopback(loopback('little', 2, 10)(v6(tcp(1), 6)))),
            'null, family 0': reads(Loopback(loopback('little', 0, 0)(segment))),
            'loop, family 2': reads(LoopbackOpenBSD(loopback('big', 2, 24)(segment))),
            'loop, little-endian': reads(LoopbackOpenBSD(loopback('little', 2, 24)(segment))),
            'linux_sll': reads(CookedLinux(sll(segment))),
            'tcp with no ip': reads(Ether() / TCP()),
            '802.3': reads(Dot3() / Raw(segment)),
        }, {
            'ethernet': True, 'ipv4': True, 'ipv6': True, 'null, family 24': True, 'null, family 10': False,
            'null, family 0': False, 'loop, family 2': True, 'loop, little-endian': False, 'linux_sll': False,
            'tcp with no ip': False, '802.3': False,
        })
        # the link type the engine attaches stands over the first layer
        packet = Ether(eth(segment))
        toolkit.attach_linktype(packet, 113)
        self.assertEqual([toolkit.tcp_reassembly(packet), toolkit.ipv4_reassembly(packet)], [None, None])

    def test_the_fragment_header_behind_a_header_scapy_reads_nothing_past_is_handed_over(self) -> None:
        # #1626: the input is the octets either side of the Fragment header, as the default engine cuts them
        import scapy.all  # noqa: F401 # pylint: disable=unused-import
        from scapy.layers.l2 import Ether

        from pcapkit.toolkit import scapy as toolkit

        mobility = bytes([44, 0, 0, 0, 0, 0, 0, 0])
        frame = eth(v6(mobility + fragment6(b'B' * 8, ident=7, nxt=6, offset=16), 135)) + b'\x00' * 6
        data = toolkit.ipv6_reassembly(Ether(frame), count=1)
        assert data is not None
        self.assertEqual((data.bufid[2:], data.fo, data.mf, data.ihl, data.tl, bytes(data.header), bytes(data.payload)),
                         ((7, 6), 16, False, 48, 56, frame[14:62], b'B' * 8))


if __name__ == '__main__':
    unittest.main()
