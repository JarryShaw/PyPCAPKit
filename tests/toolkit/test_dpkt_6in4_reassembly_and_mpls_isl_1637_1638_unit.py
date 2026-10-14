# -*- coding: utf-8 -*-
"""dpkt reads IPv6 in IPv4, and nothing behind MPLS or Cisco ISL, as the default engine does. C.f. #1637, #1638.

The default engine hands IPv6 reassembly the first IPv6 layer of a frame however
deep, so an IPv6 fragment carried in IPv4 (6in4, RFC 4213) is an input, with the
octets inside the Total Length of each IPv4 packet above it. dpkt took the
network layer only, so gave no input for 6in4, 6in4 inside 4in4 or 6in4 behind
an IPv4 AH (#1637). It now walks the IPv4 tunnels and the headers the default
engine reads past, and stops where that engine does: at an IPv4 header it
rejects, a later IPv4 fragment, or any other protocol, an ICMP error quoting the
packet included. The IPv6 packet ends at its Payload Length or, for a zero one,
at its Jumbo Payload Length, as the default engine reads it; a zero Payload
Length with no Jumbo Payload option leaves that engine no Fragment header to
read, carried in IPv4 or not. Nor does that engine walk more than 32 extension
headers (#1604), so a Fragment header past them is no input either, carried in
IPv4 or not (#1609), nor dissect a frame past its 64th layer (#1610), so neither
is one that deep in nested IPv4.

dpkt's Ethernet decoder pops an MPLS label stack, unwraps a Cisco ISL header and
steps over the legacy QinQ tags ``0x9100`` and ``0x9200``, naming the IP packet
behind them ``ip`` or ``ip6``. The default engine reads all of them as raw octets,
so dpkt handed TCP reassembly, flow tracing and IP reassembly packets it never
reads, and an ISL frame carrying an 802.1Q tag ended the extraction with a
``ProtocolError`` (#1638). dpkt now takes an Ethernet frame's payload only past
the 802.1Q and 802.1ad tags the default engine dissects, and nothing else.

That decoder also keeps only some tags of a stack it reads in two goes, e.g.
802.1Q then 802.1ad, or three tags, so the IP packet behind them was looked for
too early in the frame, and ``ProtocolError`` ended the extraction. The tags are
now read off the captured octets.

Every capture is built here, so the module is in the unit tier.

"""
from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import close_extractor, reimport_once_per_class
from tests.foundation import _roundtrip as wire
from tests.toolkit.test_dpkt_ipv4_reassembly_input_1615_1616_unit import ipv4, ipv6, jumbo
from tests.toolkit.test_tcp_carrier_walk_1606_1617_unit import ah, options, tcp, v4

if TYPE_CHECKING:
    from typing import Any

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)
HAS_DPKT = importlib.util.find_spec('dpkt') is not None

#: An Ethernet trailer, e.g. an FCS, which no IP packet reaches.
TRAILER = b'\xee' * 6


def fragment(ident: int, *, offset: int = 0, mf: bool = True, nxt: int = 253) -> bytes:
    """An IPv6 Fragment header; ``offset`` is in octets."""
    return bytes([nxt, 0]) + (offset | mf).to_bytes(2, 'big') + ident.to_bytes(4, 'big')


def first(ident: int, *, ext: bytes = b'', nxt: int = 44, plen: 'int | None' = None) -> bytes:
    """The first fragment of a 24-octet datagram, behind ``ext``, its Payload Length as given."""
    return ipv6(ext + fragment(ident) + b'A' * 16, nxt, plen=plen)


def last(ident: int) -> bytes:
    """The last fragment of that datagram."""
    return ipv6(fragment(ident, offset=16, mf=False) + b'B' * 8, 44)


def eth(packet: bytes, *, trailer: bytes = b'') -> bytes:
    """An Ethernet frame carrying the IPv4 or IPv6 ``packet``, then ``trailer``."""
    return wire.ethernet(packet, 0x86DD if packet[0] >> 4 == 6 else 0x0800) + trailer


def tagged(tpids: 'list[int]', packet: bytes) -> bytes:
    """An Ethernet frame whose VLAN tags have the TPIDs ``tpids``, then the IP ``packet``."""
    types = list(tpids) + [0x86DD if packet[0] >> 4 == 6 else 0x0800]
    tags = b''.join((100 + i).to_bytes(2, 'big') + types[i + 1].to_bytes(2, 'big') for i in range(len(tpids)))
    return wire.MAC_B + wire.MAC_A + types[0].to_bytes(2, 'big') + tags + packet


def mpls(packet: bytes, *, labels: int = 1, ethertype: int = 0x8847, tpid: 'int | None' = None) -> bytes:
    """An Ethernet frame carrying ``packet`` behind ``labels`` MPLS labels, and an 802.1Q tag if ``tpid``."""
    stack = b''.join(((16 + i) << 12 | (i == labels - 1) << 8 | 64).to_bytes(4, 'big') for i in range(labels))
    tag = b'' if tpid is None else (100).to_bytes(2, 'big') + ethertype.to_bytes(2, 'big')
    return wire.MAC_B + wire.MAC_A + (ethertype if tpid is None else tpid).to_bytes(2, 'big') + tag + stack + packet


def isl(frame: bytes) -> bytes:
    """A Cisco ISL frame: its 26-octet header, the encapsulated ``frame`` and a 4-octet CRC."""
    body = b'\xaa\xaa\x03\x00\x00\x0c' + (1 << 1).to_bytes(2, 'big') + bytes(4) + frame
    return b'\x01\x00\x0c\x00\x00\x00' + wire.MAC_A + len(body).to_bytes(2, 'big') + body + bytes(4)


def icmp_unreach(quote: bytes) -> bytes:
    """An ICMP Destination Unreachable message quoting ``quote``."""
    return bytes([3, 1, 0, 0, 0, 0, 0, 0]) + quote


def gre(packet: bytes) -> bytes:
    """A GRE header carrying the IPv6 ``packet``."""
    return b'\x00\x00\x86\xdd' + packet


def ipv6_in_ipv4() -> 'dict[str, tuple[list[int], list[bytes]]]':
    """IPv6 fragments carried in IPv4, each case with the payload lengths the default engine hands over.

    Every case's datagram has an Identification of its own.

    """
    cases = {}  # type: dict[str, tuple[list[int], list[bytes]]]
    ident = iter(range(1, 1000))

    def pair(label: str, carry: 'Any') -> None:
        number = next(ident)
        cases[label] = ([16, 8], [carry(first(number)), carry(last(number))])

    def one(label: str, payloads: 'list[int]', carry: 'Any') -> None:
        cases[label] = (payloads, [carry(next(ident))])

    # #1637: the first IPv6 layer, in IPv4, in 4in4, and behind the headers the default engine reads past
    one('IPv6 (control)', [16], lambda n: eth(first(n)))
    pair('6in4', lambda p: eth(v4(p, 41)))
    pair('6in4 inside 4in4', lambda p: eth(v4(v4(p, 41), 4)))
    pair('6in4 behind an IPv4 AH', lambda p: eth(v4(ah(41) + p, 51)))
    one('6in4 behind a Hop-by-Hop header in IPv4', [16], lambda n: eth(v4(options(41) + first(n), 0)))
    one('6in4 behind an AH inside 4in4', [16], lambda n: eth(v4(v4(ah(41) + first(n), 51), 4)))
    one('4in4 behind an AH, carrying 6in4', [16], lambda n: eth(v4(ah(4) + v4(first(n), 41), 51)))
    one('6in4 in a first IPv4 fragment', [16], lambda n: eth(v4(first(n), 41, mf=True, ident=n)))
    one('6in4 with IPv4 options', [16],
        lambda n: eth(ipv4(first(n), ident=n, options=b'\x94\x04\x00\x00', proto=41)))
    one('6in4, Hop-by-Hop then Fragment header', [16], lambda n: eth(v4(first(n, ext=options(44), nxt=0), 41)))
    one('6in4 behind an 802.1Q tag', [16], lambda n: tagged([0x8100], v4(first(n), 41)))
    # whose octets end at each Total Length above, or at the IPv6 packet's own length
    one('6in4 with a trailer', [16], lambda n: eth(v4(first(n), 41), trailer=TRAILER))
    one('6in4, Total Length 0, with a trailer', [16], lambda n: eth(v4(first(n), 41, length=0), trailer=TRAILER))
    one('6in4 cut by the Total Length', [6],
        lambda n: eth(v4(first(n), 41, length=20 + 48 + 6), trailer=TRAILER))
    one('6in4 cut by the outer Total Length of 4in4', [6],
        lambda n: eth(v4(v4(first(n), 41), 4, length=40 + 48 + 6), trailer=TRAILER))
    one('6in4 behind an AH, cut by the Total Length', [6],
        lambda n: eth(v4(ah(41) + first(n), 51, length=20 + 24 + 48 + 6), trailer=TRAILER))
    # where the default engine dissects no Fragment header of the first IPv6 layer
    one('6in4, not fragmented', [], lambda n: eth(v4(ipv6(b'A' * 16, 253), 41)))
    one('ICMP quoting a 6in4 fragment', [], lambda n: eth(v4(icmp_unreach(v4(first(n), 41)), 1)))
    one('6in4 in a later IPv4 fragment', [], lambda n: eth(v4(first(n), 41, offset=8, ident=n)))
    # dpkt decodes no later fragment's payload, but the IPv6 behind an AH or
    # Hop-by-Hop header is decoded from the octets, so the fragment check is ours
    one('6in4 behind an AH in a later IPv4 fragment', [],
        lambda n: eth(v4(ah(41) + first(n), 51, offset=8, ident=n)))
    one('6in4 behind a Hop-by-Hop header in a later IPv4 fragment', [],
        lambda n: eth(v4(options(41) + first(n), 0, offset=8, ident=n)))
    one('6in4 behind rejected IPv4 options', [],
        lambda n: eth(ipv4(first(n), ident=n, options=b'\x02\x03\x05\xb4', proto=41)))
    one('6in4, Total Length below the IHL', [], lambda n: eth(v4(first(n), 41, length=12)))
    one('6in4, Total Length inside the IPv6 header', [], lambda n: eth(v4(first(n), 41, length=20 + 30)))
    one('6in4 behind an AH too short', [], lambda n: eth(v4(ah(41, 0) + first(n), 51)))
    one('6in4 with a zero Payload Length', [], lambda n: eth(v4(first(n, plen=0), 41), trailer=TRAILER))
    one('6in4 jumbogram ending inside the Fragment header', [],
        lambda n: eth(v4(first(n, ext=jumbo(44, 8 + 4), nxt=0, plen=0), 41)))
    one('4in6 carrying a 6in4 fragment', [], lambda n: eth(ipv6(v4(first(n), 41), 4)))
    one('6in4 in GRE', [], lambda n: eth(v4(gre(first(n)), 47)))
    one('6in4 behind MPLS', [], lambda n: mpls(v4(first(n), 41)))
    return cases


def payload_length() -> 'dict[str, tuple[list[int], list[bytes]]]':
    """IPv6 fragments in Ethernet with a zero Payload Length, each with the payload lengths handed over."""
    return {
        'a zero Payload Length': ([], [eth(first(901, plen=0))]),
        'a zero Payload Length, with a trailer': ([], [eth(first(902, plen=0), trailer=TRAILER)]),
        'a jumbogram ending inside the Fragment header': ([], [eth(first(905, ext=jumbo(44, 8 + 4), nxt=0,
                                                                         plen=0))]),
        'a Payload Length short of the packet (control)': ([6], [eth(first(906, plen=8 + 6), trailer=TRAILER)]),
    }


def chain_bound() -> 'dict[str, tuple[list[int], list[bytes]]]':
    """IPv6 first fragments behind Destination Options headers, each with the payload lengths handed over.

    The default engine walks 32 extension headers at most, so a Fragment header
    after 32 or more others is not among them.

    """
    cases = {}  # type: dict[str, tuple[list[int], list[bytes]]]
    ident = iter(range(501, 1000))
    for count, payloads in ((31, [16]), (32, []), (33, []), (40, [])):
        ext = options(60) * (count - 1) + options(44)
        label = f'{count} Destination Options headers' + (' (control)' if payloads else '')
        cases[f'IPv6, {label}'] = (payloads, [eth(first(next(ident), ext=ext, nxt=60))])
        cases[f'6in4, {label}'] = (payloads, [eth(v4(first(next(ident), ext=ext, nxt=60), 41))])
        cases[f'6in4 inside 4in4, {label}'] = (payloads, [eth(v4(v4(first(next(ident), ext=ext, nxt=60), 41), 4))])
    return cases


def nested(packet: bytes, count: int, *, proto: int = 41) -> bytes:
    """``packet`` carried as ``proto`` in the innermost of ``count`` nested IPv4 headers."""
    packet = v4(packet, proto)
    for _ in range(count - 1):
        packet = v4(packet, 4)
    return packet


def layer_limit() -> 'dict[str, tuple[list[int], list[bytes]]]':
    """IPv6 first fragments deep in nested IPv4 over Ethernet, each with the payload lengths handed over.

    The default engine dissects no layer past the 64th of a frame (#1610). The
    first is Ethernet, then each VLAN tag, IPv4 header, header in IPv4 it reads
    past, and the IPv6 header, then each extension header before the Fragment
    header, which must be within the 64 too.

    """
    cases = {}  # type: dict[str, tuple[list[int], list[bytes]]]
    ident = iter(range(1001, 2000))

    def one(label: str, payloads: 'list[int]', build: 'Any', tpids: 'tuple[int, ...]' = ()) -> None:
        packet = build(next(ident))
        cases[label + (' (control)' if payloads else '')] = (payloads, [tagged(list(tpids), packet) if tpids
                                                                        else eth(packet)])

    for count, payloads in ((61, [16]), (62, [])):
        one(f'6in4 in {count} IPv4', payloads, lambda n, c=count: nested(first(n), c))
        one(f'6in4 behind an AH in {count - 1} IPv4', payloads,
            lambda n, c=count: nested(ah(41) + first(n), c - 1, proto=51))
    for count, payloads in ((60, [16]), (61, [])):
        one(f'802.1Q, 6in4 in {count} IPv4', payloads, lambda n, c=count: nested(first(n), c), (0x8100,))
    for count, payloads in ((59, [16]), (60, [])):
        # a stack dpkt reads in two goes, so keeps one tag of
        one(f'802.1Q, 802.1ad, 6in4 in {count} IPv4', payloads, lambda n, c=count: nested(first(n), c),
            (0x8100, 0x88A8))
    # where the extension headers before the Fragment header reach the 64th layer
    # first, and where each header the default engine reads past in IPv4 counts
    for count, chain, payloads in ((40, 21, [16]), (40, 22, []), (31, 30, [16]), (31, 31, [])):
        ext = options(60) * (chain - 1) + options(44)
        one(f'6in4 in {count} IPv4, {chain} Destination Options headers', payloads,
            lambda n, c=count, e=ext: nested(first(n, ext=e, nxt=60), c))
    for hops, chain, payloads in ((10, 1, [16]), (10, 2, []), (11, 0, [16]), (12, 0, [])):
        ext = options(60) * (chain - 1) + options(44) if chain else b''
        one(f'6in4 behind {hops} Hop-by-Hop headers in 50 IPv4, {chain} Destination Options headers', payloads,
            lambda n, h=hops, c=chain, e=ext: nested(options(0) * (h - 1) + options(41)
                                                     + first(n, ext=e, nxt=60 if c else 44), 50, proto=0))
    return cases


def raw_layer_limit() -> 'dict[str, tuple[list[int], list[bytes]]]':
    """IPv6 first fragments deep in nested IPv4 of a raw-IP link type, whose first layer is the IPv4 header."""
    return {
        '6in4 in 62 IPv4 (control)': ([16], [nested(first(2001), 62)]),
        '6in4 in 63 IPv4': ([], [nested(first(2002), 63)]),
        '6in4 in 40 IPv4, 22 Destination Options headers (control)':
            ([16], [nested(first(2003, ext=options(60) * 21 + options(44), nxt=60), 40)]),
        '6in4 in 40 IPv4, 23 Destination Options headers':
            ([], [nested(first(2004, ext=options(60) * 22 + options(44), nxt=60), 40)]),
    }


#: VLAN tag stacks by name, each with whether the default engine reads past them.
#: dpkt reads each of them in two goes and keeps only the tags of the second.
STACKS = {
    '802.1Q, 802.1ad': (True, [0x8100, 0x88A8]),
    'two 802.1ad': (True, [0x88A8, 0x88A8]),
    'three 802.1Q': (True, [0x8100] * 3),
    '802.1ad, 802.1Q, 802.1Q': (True, [0x88A8, 0x8100, 0x8100]),
    'four 802.1Q': (True, [0x8100] * 4),
    # where the tag dpkt drops is the one the default engine leaves raw
    '802.1Q, legacy QinQ 0x9100': (False, [0x8100, 0x9100]),
    '802.1ad, 802.1Q, legacy QinQ 0x9100': (False, [0x88A8, 0x8100, 0x9100]),
}


def stacked(tpids: 'list[int]') -> 'list[bytes]':
    """Frames tagged ``tpids``: IPv4 and IPv6 TCP, then IPv4, IPv6 and 6in4 fragment pairs; then an untagged control."""
    return [
        tagged(tpids, v4(tcp(1), 6)), tagged(tpids, wire.ipv6(tcp(2), nxt=6)),
        tagged(tpids, v4(b'A' * 16, 253, mf=True, ident=31)), tagged(tpids, v4(b'B' * 8, 253, offset=16, ident=31)),
        tagged(tpids, first(32)), tagged(tpids, last(32)),
        tagged(tpids, v4(first(33), 41)), tagged(tpids, v4(last(33), 41)),
        eth(v4(tcp(3), 6)),
    ]


def links() -> 'dict[str, tuple[tuple[int, int, int], list[bytes]]]':
    """Frames by link-layer encapsulation, each with the TCP, IPv4 and IPv6 inputs the default engine hands over.

    Every TCP segment has a port of its own, and every fragmented datagram an
    Identification of its own.

    """
    def each(build: 'Any', ident: int) -> 'list[bytes]':
        return [build(v4(b'A' * 16, 253, mf=True, ident=ident)), build(v4(b'B' * 8, 253, offset=16, ident=ident))]

    def each6(build: 'Any', ident: int) -> 'list[bytes]':
        return [build(first(ident)), build(last(ident))]

    return {
        # an IPv4 packet that may be fragmented is an IPv4 reassembly input too
        'IPv4, TCP (control)': ((1, 1, 0), [eth(v4(tcp(1), 6))]),
        '802.1Q, IPv4, TCP (control)': ((1, 1, 0), [tagged([0x8100], v4(tcp(2), 6))]),
        '802.1ad, 802.1Q, IPv6, TCP (control)': ((1, 0, 0), [tagged([0x88A8, 0x8100], wire.ipv6(tcp(3), nxt=6))]),
        'MPLS, IPv4, TCP': ((0, 0, 0), [mpls(v4(tcp(4), 6))]),
        'MPLS, IPv6, TCP': ((0, 0, 0), [mpls(wire.ipv6(tcp(5), nxt=6))]),
        'MPLS multicast, IPv4, TCP': ((0, 0, 0), [mpls(v4(tcp(6), 6), ethertype=0x8848)]),
        'two MPLS labels, IPv4, TCP': ((0, 0, 0), [mpls(v4(tcp(7), 6), labels=2)]),
        '802.1Q, MPLS, IPv4, TCP': ((0, 0, 0), [mpls(v4(tcp(8), 6), tpid=0x8100)]),
        'Cisco ISL, Ethernet, IPv4, TCP': ((0, 0, 0), [isl(eth(v4(tcp(9), 6)))]),
        'Cisco ISL, Ethernet, IPv6, TCP': ((0, 0, 0), [isl(eth(wire.ipv6(tcp(10), nxt=6)))]),
        'legacy QinQ 0x9100, IPv4, TCP': ((0, 0, 0), [tagged([0x9100], v4(tcp(11), 6))]),
        'legacy QinQ 0x9200, 802.1Q, IPv4, TCP': ((0, 0, 0), [tagged([0x9200, 0x8100], v4(tcp(12), 6))]),
        'LLC/SNAP, IPv4, TCP (control)': ((0, 0, 0), [
            wire.MAC_B + wire.MAC_A + (8 + 44).to_bytes(2, 'big') + b'\xaa\xaa\x03\x00\x00\x00\x08\x00'
            + v4(tcp(13), 6)]),
        'MPLS, IPv4 fragments': ((0, 0, 0), each(mpls, 21)),
        'MPLS, IPv6 fragments': ((0, 0, 0), each6(mpls, 22)),
        'Cisco ISL, Ethernet, IPv4 fragments': ((0, 0, 0), each(lambda p: isl(eth(p)), 23)),
        'Cisco ISL, Ethernet, IPv6 fragments': ((0, 0, 0), each6(lambda p: isl(eth(p)), 24)),
        'legacy QinQ 0x9100, IPv4 fragments': ((0, 0, 0), each(lambda p: tagged([0x9100], p), 25)),
        '802.1Q, IPv4 fragments (control)': ((0, 2, 0), each(lambda p: tagged([0x8100], p), 26)),
        '802.1Q, IPv6 fragments (control)': ((0, 0, 2), each6(lambda p: tagged([0x8100], p), 27)),
    }


def read(test: unittest.TestCase, engine: str, frames: 'list[bytes]', linktype: int = 1) -> 'dict[str, Any]':
    """Read ``frames`` of ``linktype`` with ``engine``, with IP and TCP reassembly and TCP flow tracing.

    Returns:
        Every input the engine hands IPv4, IPv6 and TCP reassembly and TCP flow
        tracing, keyed by frame number -- every field, but a trace input's
        ``frame`` -- the reassembled datagrams, and the traced flows.

    """
    from pcapkit import extract
    from pcapkit.foundation.reassembly.ipv4 import IPv4
    from pcapkit.foundation.reassembly.ipv6 import IPv6
    from pcapkit.foundation.reassembly.tcp import TCP
    from pcapkit.foundation.traceflow.traceflow import TraceFlowBase

    seen = {'IPv4': {}, 'IPv6': {}, 'TCP': {}, 'trace': {}}  # type: dict[str, Any]
    calls = {klass: klass.__call__ for klass in (IPv4, IPv6, TCP)}
    trace = TraceFlowBase.__call__

    def fields(packet: 'Any', skip: 'tuple[str, ...]' = ()) -> 'dict[str, Any]':
        return {key: bytes(value) if isinstance(value, bytearray) else value
                for key, value in packet.items() if key not in skip}

    def spy(klass: 'Any') -> 'Any':
        def call(this: 'Any', packet: 'Any') -> 'Any':
            seen[klass.__name__][packet.num] = fields(packet)
            return calls[klass](this, packet)
        return call

    def spy_trace(this: 'Any', packet: 'Any') -> 'Any':
        seen['trace'][packet.index] = fields(packet, ('frame',))
        return trace(this, packet)

    with tempfile.TemporaryDirectory() as tmp, warnings.catch_warnings(), \
            mock.patch.object(IPv4, '__call__', spy(IPv4)), mock.patch.object(IPv6, '__call__', spy(IPv6)), \
            mock.patch.object(TCP, '__call__', spy(TCP)), mock.patch.object(TraceFlowBase, '__call__', spy_trace):
        path = os.path.join(tmp, 'encap.pcap')
        with open(path, 'wb') as file:
            file.write(wire.pcap([(1, number, octets) for number, octets in enumerate(frames)], linktype=linktype))
        warnings.simplefilter('ignore')
        extractor = extract(fin=path, nofile=True, engine=engine, reassembly=True, ip=True, tcp=True,
                            trace=True, trace_fout=os.path.join(tmp, 'trace'), trace_format='json')
        try:
            if extractor._exnam != engine:  # pylint: disable=protected-access
                test.skipTest(f'{engine} did not run')
            seen['datagrams'] = {
                'IPv4': [(datagram.completed, datagram.id, datagram.index, datagram.header, datagram.payload)
                         for datagram in extractor.reassembly.ipv4],
                'IPv6': [(datagram.completed, datagram.id, datagram.index, datagram.header, datagram.payload)
                         for datagram in extractor.reassembly.ipv6],
                'TCP': [datagram.id for datagram in extractor.reassembly.tcp],
            }
            seen['flows'] = [(flow.label, tuple(flow.index)) for flow in extractor.trace.tcp]
        finally:
            close_extractor(extractor)
    return seen


def numbered(cases: 'dict[str, tuple[Any, list[bytes]]]') -> 'tuple[list[bytes], dict[str, list[int]]]':
    """The frames of ``cases`` in order, and each case's one-based frame numbers."""
    frames, numbers = [], {}  # type: list[bytes], dict[str, list[int]]
    for label, (_, built) in cases.items():
        numbers[label] = list(range(len(frames) + 1, len(frames) + 1 + len(built)))
        frames.extend(built)
    return frames, numbers


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
@unittest.skipUnless(HAS_DPKT, 'dpkt not installed')
class DPKTEncapsulationTests(unittest.TestCase):
    """dpkt's reassembly and trace inputs are the default engine's, field for field."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def agree_on_ipv6(self, cases: 'dict[str, tuple[list[int], list[bytes]]]', linktype: int = 1) -> None:
        frames, numbers = numbered(cases)
        base, dpkt = read(self, 'default', frames, linktype), read(self, 'dpkt', frames, linktype)
        for label, (payloads, _) in cases.items():
            with self.subTest(case=label):
                got = [base['IPv6'][number] for number in numbers[label] if number in base['IPv6']]
                self.assertEqual([len(packet['payload']) for packet in got], payloads, 'the default engine')
                self.assertEqual([dpkt['IPv6'].get(number) for number in numbers[label]],
                                 [base['IPv6'].get(number) for number in numbers[label]])
        for aspect in ('IPv4', 'TCP', 'trace', 'datagrams', 'flows'):
            self.assertEqual(dpkt[aspect], base[aspect], aspect)

    def test_ipv6_carried_in_ipv4_is_an_input(self) -> None:
        # #1637
        self.agree_on_ipv6(ipv6_in_ipv4())

    def test_a_zero_payload_length_gives_way_to_a_jumbo_payload_option(self) -> None:
        # #1637: the rule the 6in4 rows need, which holds for IPv6 in Ethernet too
        self.agree_on_ipv6(payload_length())

    def test_a_fragment_header_past_the_chain_bound_is_no_input(self) -> None:
        # #1604, #1609: dpkt walks the whole chain, the default engine 32 headers
        self.agree_on_ipv6(chain_bound())

    def test_a_fragment_header_past_the_frame_layer_limit_is_no_input(self) -> None:
        # #1610: the default engine dissects 64 layers of a frame, dpkt any number
        self.agree_on_ipv6(layer_limit())

    def test_a_raw_ip_frame_counts_no_link_layer(self) -> None:
        # #1610: LINKTYPE_RAW, so the outermost IPv4 header is the first layer
        self.agree_on_ipv6(raw_layer_limit(), linktype=101)

    def test_a_stack_dpkt_reads_in_two_goes_ends_no_extraction(self) -> None:
        # dpkt kept the second go's tags only, so the IP header was looked for 4
        # octets early per tag dropped, and ProtocolError ended the read
        for label, (reads, tpids) in STACKS.items():
            with self.subTest(stack=label):
                frames = stacked(tpids)
                base, dpkt = read(self, 'default', frames), read(self, 'dpkt', frames)
                self.assertEqual((sorted(base['TCP']), sorted(base['IPv6'])),
                                 ([1, 2, 9], [5, 6, 7, 8]) if reads else ([9], []), 'the default engine')
                for aspect in ('TCP', 'trace', 'IPv4', 'IPv6', 'datagrams', 'flows'):
                    self.assertEqual(dpkt[aspect], base[aspect], aspect)

    def test_nothing_is_read_behind_mpls_isl_or_legacy_qinq(self) -> None:
        # #1638
        cases = links()
        frames, numbers = numbered(cases)
        base, dpkt = read(self, 'default', frames), read(self, 'dpkt', frames)
        for label, (counts, _) in cases.items():
            with self.subTest(case=label):
                self.assertEqual(tuple(sum(number in base[aspect] for number in numbers[label])
                                       for aspect in ('TCP', 'IPv4', 'IPv6')), counts, 'the default engine')
                for aspect in ('TCP', 'trace', 'IPv4', 'IPv6'):
                    self.assertEqual([dpkt[aspect].get(number) for number in numbers[label]],
                                     [base[aspect].get(number) for number in numbers[label]], aspect)
        for aspect in ('datagrams', 'flows'):
            self.assertEqual(dpkt[aspect], base[aspect], aspect)

    def test_an_isl_frame_carrying_an_8021q_tag_ends_no_extraction(self) -> None:
        # #1638: dpkt overwrote the ISL tag with the 802.1Q one, so the IPv4
        # header was looked for 26 octets early and ProtocolError ended the read
        frames = [isl(tagged([0x8100], v4(tcp(1), 6))), eth(v4(tcp(2), 6))]
        base, dpkt = read(self, 'default', frames), read(self, 'dpkt', frames)
        self.assertEqual((sorted(base['TCP']), sorted(base['trace'])), ([2], [2]))
        for aspect in ('TCP', 'trace', 'IPv4', 'IPv6', 'datagrams', 'flows'):
            self.assertEqual(dpkt[aspect], base[aspect], aspect)

    def test_a_packet_built_by_hand_is_read_too(self) -> None:
        # with no record octets attached, DPKT's own fields tell what it read
        # past, and the octets are its serialisation of the packet, which here
        # is the octets it was parsed from
        import dpkt

        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import dpkt as toolkit

        for label, octets in (('MPLS', mpls(v4(tcp(1), 6))), ('Cisco ISL', isl(eth(v4(tcp(1), 6)))),
                              ('legacy QinQ', tagged([0x9100], v4(tcp(1), 6)))):
            with self.subTest(case=label):
                packet = dpkt.ethernet.Ethernet(octets)
                self.assertEqual(type(packet.ip).__name__, 'IP')     # what dpkt decodes
                self.assertIsNone(toolkit.tcp_reassembly(packet, 1.0, count=1))
                self.assertIsNone(toolkit.tcp_traceflow(packet, 1.0, data_link=LinkType.ETHERNET, count=1))

        tunnelled = eth(v4(first(1), 41), trailer=TRAILER)
        data = toolkit.ipv6_reassembly(dpkt.ethernet.Ethernet(tunnelled), 1.0, count=1)
        self.assertIsNotNone(data)
        assert data is not None
        self.assertEqual((data.ihl, bytes(data.header), bytes(data.payload)),
                         (40, tunnelled[34:74], b'A' * 16))


if __name__ == '__main__':
    unittest.main()
