# -*- coding: utf-8 -*-
"""dpkt reads a frame's IP layers off its octets, as the default engine does. C.f. #1609, #1626, #1651, #1654.

The dpkt adapters walked what dpkt decoded, which is not what the default engine
dissects:

* #1651: dpkt runs an IPv6 payload to the end of the record when the Payload
  Length is zero, and past a jumbogram's Jumbo Payload Length, so TCP and IPv6
  fragments were read where the default engine reads none, or longer.
* #1654: dpkt reads at most two VLAN tags a pass and two passes, so behind a
  deeper stack it decoded nothing, and the adapters handed over nothing.
* #1609: the default engine walks 32 extension headers in a row and dissects 64
  layers of a frame; the walk for TCP and IPv4 reassembly bounded neither.
* #1626: dpkt decodes none of Mobility, HIP and Shim6, cannot read a later
  fragment whose Next Header is an extension header, and raises at a Fragment
  header first in the chain with another header behind it, which keeps the whole
  frame raw.

The adapters now read every IP layer, extension header and TCP segment off the
captured octets by the default engine's rules, and a frame the engine keeps raw
by the link type it attaches. Every input to TCP reassembly, flow tracing and IP
reassembly is compared with the default engine's, field for field. A frame kept
raw is written out, and traced, rather than ending the extraction.

Every capture is built here, so the module is in the unit tier.

"""
from __future__ import annotations

import importlib.util
import itertools
import os
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import close_extractor, reimport_once_per_class
from tests.foundation import _roundtrip as wire
from tests.toolkit.test_dpkt_6in4_reassembly_and_mpls_isl_1637_1638_unit import (TRAILER, nested,
                                                                                 numbered, read,
                                                                                 tagged)
from tests.toolkit.test_dpkt_ipv4_reassembly_input_1615_1616_unit import ipv6, jumbo
from tests.toolkit.test_tcp_carrier_walk_1606_1617_unit import ah, eth, options, tcp, v4, v6

if TYPE_CHECKING:
    from typing import Any, Callable

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)
HAS_DPKT = importlib.util.find_spec('dpkt') is not None

#: What each case's counts count, in order.
ASPECTS = ('TCP', 'trace', 'IPv4', 'IPv6')

#: TCP ports and fragment Identifications, one per use.
_NUMBERS = itertools.count(1)


def number() -> int:
    """A port offset or Identification no other frame uses."""
    return next(_NUMBERS)


def segment() -> bytes:
    """A TCP segment carrying four octets, on a port pair of its own."""
    return tcp(number())


def frag6(nxt: int, ident: int, *, offset: int = 0, mf: bool = True) -> bytes:
    """An IPv6 Fragment header; ``offset`` is in octets."""
    return bytes([nxt, 0]) + (offset | mf).to_bytes(2, 'big') + ident.to_bytes(4, 'big')


def v4_fragments(carry: 'Callable[[bytes], bytes]') -> 'list[bytes]':
    """The two fragments of a 24-octet IPv4 datagram, each carried by ``carry``."""
    ident = number()
    return [carry(v4(b'A' * 16, 253, mf=True, ident=ident)), carry(v4(b'B' * 8, 253, offset=16, ident=ident))]


def v6_fragments(carry: 'Callable[[bytes], bytes]') -> 'list[bytes]':
    """The two fragments of a 24-octet IPv6 datagram, each carried by ``carry``."""
    ident = number()
    return [carry(v6(frag6(253, ident) + b'A' * 16, 44)),
            carry(v6(frag6(253, ident, offset=16, mf=False) + b'B' * 8, 44))]


def nested6(packet: bytes, count: int, nxt: int) -> bytes:
    """``packet`` carried as ``nxt`` in the innermost of ``count`` nested IPv6 headers."""
    packet = v6(packet, nxt)
    for _ in range(count - 1):
        packet = v6(packet, 41)
    return packet


def pairs(segment: bytes, count: int, *, version: int) -> bytes:
    """``segment`` behind ``count`` (IPv4, AH) or (IPv6, Hop-by-Hop) pairs, as ``version`` says."""
    if version == 4:
        packet = v4(ah(6) + segment, 51)
        for _ in range(count - 1):
            packet = v4(ah(4) + packet, 51)
        return packet
    packet = v6(options(6) + segment, 0)
    for _ in range(count - 1):
        packet = v6(options(41) + packet, 0)
    return packet


def mobility(nxt: int) -> bytes:
    """A Mobility header (135) of 8 octets, a Binding Refresh Request."""
    return bytes([nxt, 0, 0, 0, 0, 0, 0, 0])


def hip(nxt: int) -> bytes:
    """A HIP header (139) of 40 octets, an I1 packet."""
    return bytes([nxt, 4, 1, 0x21, 0, 0, 0, 0]) + b'\x11' * 32


def shim6(nxt: int) -> bytes:
    """A Shim6 header (140) of 8 octets."""
    return bytes([nxt, 0, 0, 0, 0, 0, 0, 0])


def payload_length() -> 'dict[str, tuple[tuple[int, ...], list[bytes]]]':
    """#1651: IPv6 packets whose Payload Length is zero, each with the default engine's input counts."""
    def jumbogram(short: int = 0) -> bytes:
        return ipv6(jumbo(6, 8 + 24 - short) + segment(), 0, plen=0)

    return {
        'IPv6, TCP (control)': ((1, 1, 0, 0), [eth(v6(segment(), 6))]),
        'Payload Length 0, TCP': ((0, 0, 0, 0), [eth(ipv6(segment(), 6, plen=0))]),
        'Payload Length 0, TCP, trailer': ((0, 0, 0, 0), [eth(ipv6(segment(), 6, plen=0)) + TRAILER]),
        '6in4, Payload Length 0, TCP': ((0, 0, 1, 0), [eth(v4(ipv6(segment(), 6, plen=0), 41))]),
        'Payload Length 0, Fragment header': ((0, 0, 0, 0), [eth(ipv6(frag6(253, number()) + b'A' * 16, 44,
                                                                      plen=0))]),
        'Payload Length 0, Fragment header, trailer': ((0, 0, 0, 0), [eth(ipv6(frag6(253, number()) + b'A' * 16, 44,
                                                                               plen=0)) + TRAILER]),
        'Payload Length 0, Hop-by-Hop with no Jumbo Payload option, TCP': (
            (0, 0, 0, 0), [eth(ipv6(options(6) + segment(), 0, plen=0))]),
        'Payload Length 0, 4in6, TCP': ((0, 0, 0, 0), [eth(ipv6(v4(segment(), 6), 4, plen=0))]),
        '6in6, inner Payload Length 0, TCP': ((0, 0, 0, 0), [eth(v6(ipv6(segment(), 6, plen=0), 41))]),
        'jumbogram, Jumbo Payload Length inside the TCP header': ((0, 0, 0, 0), [eth(jumbogram(12))]),
    }


#: VLAN tag stacks dpkt does not finish decoding in two passes, by name.
STACKS = {
    'three 802.1ad': [0x88A8] * 3,
    'five 802.1Q': [0x8100] * 5,
    '802.1ad, four 802.1Q': [0x88A8] + [0x8100] * 4,
    '802.1Q, two 802.1ad': [0x8100, 0x88A8, 0x88A8],
    'eight 802.1Q': [0x8100] * 8,
}


def vlan_stacks() -> 'dict[str, tuple[tuple[int, ...], list[bytes]]]':
    """#1654: IP behind deep VLAN tag stacks, each with the default engine's input counts."""
    cases = {}  # type: dict[str, tuple[tuple[int, ...], list[bytes]]]
    for name, tpids in STACKS.items():
        def carry(packet: bytes, tpids: 'list[int]' = tpids) -> bytes:
            return tagged(tpids, packet)
        cases[f'{name}, IPv4, TCP'] = ((1, 1, 1, 0), [carry(v4(segment(), 6))])
        cases[f'{name}, IPv6, TCP'] = ((1, 1, 0, 0), [carry(v6(segment(), 6))])
        cases[f'{name}, IPv4 fragments'] = ((0, 0, 2, 0), v4_fragments(carry))
        cases[f'{name}, IPv6 fragments'] = ((0, 0, 0, 2), v6_fragments(carry))
        cases[f'{name}, 6in4 fragments'] = ((0, 0, 2, 2), v6_fragments(lambda p, c=carry: c(v4(p, 41))))
    cases['three 802.1ad, IPv4, TCP, trailer'] = ((1, 1, 1, 0), [tagged(STACKS['three 802.1ad'],
                                                                       v4(segment(), 6)) + TRAILER])
    # where dpkt finishes in two passes, and where a legacy tag deep in the stack is left raw
    cases['two 802.1ad, IPv4, TCP (control)'] = ((1, 1, 1, 0), [tagged([0x88A8] * 2, v4(segment(), 6))])
    cases['three 802.1ad, legacy QinQ 0x9100, IPv4, TCP'] = ((0, 0, 0, 0), [tagged([0x88A8] * 3 + [0x9100],
                                                                                  v4(segment(), 6))])
    return cases


def layer_limit() -> 'dict[str, tuple[tuple[int, ...], list[bytes]]]':
    """#1609: TCP and IPv4 fragments deep in a frame, each with the default engine's input counts.

    The default engine walks 32 extension headers in a row (#1604) and dissects
    64 layers of a frame (#1610): Ethernet, then each VLAN tag, IP header,
    header in IPv4 it reads past and IPv6 extension header.

    """
    cases = {
        'IPv6, 32 Hop-by-Hop headers, TCP (control)': ((1, 1, 0, 0), [eth(v6(options(0) * 31 + options(6)
                                                                              + segment(), 0))]),
        'IPv6, 33 Hop-by-Hop headers, TCP': ((0, 0, 0, 0), [eth(v6(options(0) * 32 + options(6) + segment(), 0))]),
        'IPv6, 1000 Hop-by-Hop headers, TCP': ((0, 0, 0, 0), [eth(v6(options(0) * 999 + options(6)
                                                                     + segment(), 0))]),
        'IPv6, 32 Destination Options headers, 4in6, TCP (control)': (
            (1, 1, 1, 0), [eth(v6(options(60) * 31 + options(4) + v4(segment(), 6), 60))]),
        'IPv6, 33 Destination Options headers, 4in6, TCP': (
            (0, 0, 0, 0), [eth(v6(options(60) * 32 + options(4) + v4(segment(), 6), 60))]),
        'TCP in 62 IPv4 (control)': ((1, 1, 1, 0), [eth(nested(segment(), 62, proto=6))]),
        'TCP in 63 IPv4': ((0, 0, 1, 0), [eth(nested(segment(), 63, proto=6))]),
        'TCP in 62 IPv6 (control)': ((1, 1, 0, 0), [eth(nested6(segment(), 62, 6))]),
        'TCP in 63 IPv6': ((0, 0, 0, 0), [eth(nested6(segment(), 63, 6))]),
        'TCP behind 31 (IPv4, AH) pairs (control)': ((1, 1, 1, 0), [eth(pairs(segment(), 31, version=4))]),
        'TCP behind 32 (IPv4, AH) pairs': ((0, 0, 1, 0), [eth(pairs(segment(), 32, version=4))]),
        'TCP behind 31 (IPv6, Hop-by-Hop) pairs (control)': ((1, 1, 0, 0), [eth(pairs(segment(), 31, version=6))]),
        'TCP behind 32 (IPv6, Hop-by-Hop) pairs': ((0, 0, 0, 0), [eth(pairs(segment(), 32, version=6))]),
        'IPv4 fragments in 62 IPv6 (control)': ((0, 0, 2, 0), v4_fragments(lambda p: eth(nested6(p, 62, 4)))),
        'IPv4 fragments in 63 IPv6': ((0, 0, 0, 0), v4_fragments(lambda p: eth(nested6(p, 63, 4)))),
        'TCP behind 61 802.1Q tags (control)': ((1, 1, 1, 0), [tagged([0x8100] * 61, v4(segment(), 6))]),
        'TCP behind 62 802.1Q tags': ((0, 0, 1, 0), [tagged([0x8100] * 62, v4(segment(), 6))]),
        'IPv4 fragments behind 62 802.1Q tags (control)': ((0, 0, 2, 0),
                                                            v4_fragments(lambda p: tagged([0x8100] * 62, p))),
        'IPv4 fragments behind 63 802.1Q tags': ((0, 0, 0, 0), v4_fragments(lambda p: tagged([0x8100] * 63, p))),
        'IPv6 fragments behind 61 802.1Q tags (control)': ((0, 0, 0, 2),
                                                            v6_fragments(lambda p: tagged([0x8100] * 61, p))),
        'IPv6 fragments behind 62 802.1Q tags': ((0, 0, 0, 0), v6_fragments(lambda p: tagged([0x8100] * 62, p))),
    }
    return cases


def raw_layer_limit() -> 'dict[str, tuple[tuple[int, ...], list[bytes]]]':
    """#1609 on a raw-IP link type, whose first layer is the outermost IP header."""
    return {
        'TCP in 63 IPv4 (control)': ((1, 1, 1, 0), [nested(segment(), 63, proto=6)]),
        'TCP in 64 IPv4': ((0, 0, 1, 0), [nested(segment(), 64, proto=6)]),
    }


def chains() -> 'dict[str, tuple[tuple[int, ...], list[bytes]]]':
    """#1626: TCP and IP fragments behind IPv6 extension header chains, each with the default engine's input counts."""
    chain = {
        'Fragment (offset 0, M=0), then AH': (lambda nxt: frag6(51, number(), mf=False) + ah(nxt), 44, 1),
        'Fragment (offset 0, M=0), then Destination Options': (
            lambda nxt: frag6(60, number(), mf=False) + options(nxt), 44, 1),
        'AH': (ah, 51, 0),
        'Mobility (135)': (mobility, 135, 0),
        'HIP (139)': (hip, 139, 0),
        'Shim6 (140)': (shim6, 140, 0),
        'Destination Options (control)': (options, 60, 0),
    }
    cases = {}  # type: dict[str, tuple[tuple[int, ...], list[bytes]]]
    for name, (header, first, fragmented) in chain.items():
        cases[f'{name}, TCP'] = ((1, 1, 0, fragmented), [eth(v6(header(6) + segment(), first))])
        cases[f'{name}, TCP, trailer'] = ((1, 1, 0, fragmented), [eth(v6(header(6) + segment(), first)) + TRAILER])
        cases[f'6in4, {name}, TCP'] = ((1, 1, 1, fragmented), [eth(v4(v6(header(6) + segment(), first), 41))])
        cases[f'{name}, IPv4 fragments'] = ((0, 0, 2, 2 * fragmented),
                                            v4_fragments(lambda p, h=header, f=first: eth(v6(h(4) + p, f))))
    # an IPv6 reassembly input whose Fragment header names another extension header
    ident = number()
    cases.update({
        'Fragment (offset 0, M=1), then 253 (control)': ((0, 0, 0, 1), [eth(v6(frag6(253, number())
                                                                                + b'A' * 16, 44))]),
        'Fragment (offset 0, M=1), then Destination Options': (
            (0, 0, 0, 1), [eth(v6(frag6(60, number()) + options(253) + b'A' * 8, 44))]),
        'Fragment (offset 0, M=0), then Destination Options': (
            (0, 0, 0, 1), [eth(v6(frag6(60, number(), mf=False) + options(253) + b'A' * 8, 44))]),
        'Fragment (offset 0, M=1), then AH': ((0, 0, 0, 1), [eth(v6(frag6(51, number()) + ah(253) + b'A' * 8, 44))]),
        'Fragment (offset 8, M=0), next header 60': (
            (0, 0, 0, 1), [eth(v6(frag6(60, number(), offset=8, mf=False) + b'B' * 8, 44))]),
        'a datagram whose Fragmentable Part starts with Destination Options': (
            (0, 0, 0, 2), [eth(v6(frag6(60, ident) + options(253) + b'A' * 8, 44)),
                           eth(v6(frag6(60, ident, offset=16, mf=False) + b'B' * 8, 44))]),
        'two Fragment headers': ((0, 0, 0, 1), [eth(v6(frag6(44, number()) + frag6(253, number()) + b'A' * 16, 44))]),
        'a Hop-by-Hop header overrunning the packet, TCP': (
            (0, 0, 0, 0), [eth(v6(bytes([6, 5, 1, 4, 0, 0, 0, 0]) + segment(), 0))]),
        '802.1Q, Fragment (offset 0, M=0), then AH, TCP': (
            (1, 1, 0, 1), [tagged([0x8100], v6(frag6(51, number(), mf=False) + ah(6) + segment(), 44))]),
    })
    return cases


def raw_link_chains() -> 'dict[int, dict[str, tuple[tuple[int, ...], list[bytes]]]]':
    """#1626 on the other link types, by link type, where dpkt's decoding raises and the frame is kept raw."""
    def first(nxt: int = 6) -> bytes:
        return v6(frag6(51, number(), mf=False) + ah(nxt) + segment(), 44)

    def later() -> bytes:
        return v6(frag6(60, number()) + options(253) + b'A' * 8, 44)

    return {
        # and where the default engine dissects nothing past the link layer
        1: {'Ethernet, cut short of its header': ((0, 0, 0, 0), [eth(first())[:10]]),
            'Ethernet, 802.1Q tag cut short': ((0, 0, 0, 0), [wire.MAC_B + wire.MAC_A + b'\x81\x00\x00\x64'])},
        101: {'raw IP, Fragment then AH, TCP': ((1, 1, 0, 1), [first()]),
              'raw IP, Fragment then Destination Options': ((0, 0, 0, 1), [later()]),
              'raw IP, version 5': ((0, 0, 0, 0), [bytes([0x55]) + v4(segment(), 6)[1:]]),
              'raw IP, no octets': ((0, 0, 0, 0), [b''])},
        0: {'NULL, Fragment then AH, TCP': ((1, 1, 0, 1), [b'\x18\x00\x00\x00' + first()]),
            'NULL, Fragment then Destination Options': ((0, 0, 0, 1), [b'\x18\x00\x00\x00' + later()]),
            'NULL, cut short of its family': ((0, 0, 0, 0), [b'\x18\x00'])},
        108: {'LOOP, Fragment then AH, TCP': ((1, 1, 0, 1), [b'\x00\x00\x00\x18' + first()])},
        147: {'USER0, IPv4, TCP': ((0, 0, 0, 0), [v4(segment(), 6)])},
        228: {'IPV4, 6in4, Fragment then AH, TCP': ((1, 1, 1, 1), [v4(first(), 41)])},
        229: {'IPV6, Fragment then Destination Options': ((0, 0, 0, 1), [later()])},
    }


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
@unittest.skipUnless(HAS_DPKT, 'dpkt not installed')
class DPKTIPWalkTests(unittest.TestCase):
    """dpkt's reassembly and trace inputs are the default engine's, field for field."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def agree(self, cases: 'dict[str, tuple[tuple[int, ...], list[bytes]]]', linktype: int = 1) -> None:
        frames, numbers = numbered(cases)
        base, dpkt = read(self, 'default', frames, linktype), read(self, 'dpkt', frames, linktype)
        for label, (counts, _) in cases.items():
            with self.subTest(case=label, linktype=linktype):
                self.assertEqual(tuple(sum(frame in base[aspect] for frame in numbers[label]) for aspect in ASPECTS),
                                 counts, 'the default engine')
                for aspect in ASPECTS:
                    self.assertEqual([dpkt[aspect].get(frame) for frame in numbers[label]],
                                     [base[aspect].get(frame) for frame in numbers[label]], aspect)
        for aspect in ('datagrams', 'flows'):
            self.assertEqual(dpkt[aspect], base[aspect], aspect)

    def test_a_zero_payload_length_carries_no_payload_unless_a_jumbogram(self) -> None:
        # #1651
        self.agree(payload_length())

    def test_ip_behind_a_deep_vlan_tag_stack_is_read(self) -> None:
        # #1654
        self.agree(vlan_stacks())

    def test_tcp_and_ipv4_past_the_chain_and_frame_bounds_are_no_input(self) -> None:
        # #1609
        self.agree(layer_limit())
        self.agree(raw_layer_limit(), linktype=101)

    def test_tcp_and_fragments_behind_every_extension_header_chain_are_read(self) -> None:
        # #1626
        self.agree(chains())

    def test_a_frame_dpkt_cannot_decode_is_read_by_its_link_type(self) -> None:
        # #1626: dpkt raises AttributeError for a Fragment header first in the
        # chain with another header behind it, so the engine keeps the frame raw
        for linktype, cases in raw_link_chains().items():
            self.agree(cases, linktype=linktype)

    def test_a_frame_kept_raw_is_written_out(self) -> None:
        # The engine writes every frame through packet2dict, which read the
        # header fields a frame kept raw does not have, so AttributeError ended
        # the extraction at the first frame dpkt could not decode
        from pcapkit import extract

        frames = [eth(v6(frag6(51, number(), mf=False) + ah(6) + segment(), 44)), eth(v4(segment(), 6))]
        with tempfile.TemporaryDirectory() as tmp, warnings.catch_warnings():
            warnings.simplefilter('ignore')
            path = os.path.join(tmp, 'raw.pcap')
            with open(path, 'wb') as file:
                file.write(wire.pcap([(1, index, octets) for index, octets in enumerate(frames)]))
            extractor = extract(fin=path, fout=os.path.join(tmp, 'out'), format='json', engine='dpkt',
                                store=True)
            try:
                if extractor._exnam != 'dpkt':  # pylint: disable=protected-access
                    self.skipTest('dpkt did not run')
                self.assertEqual(len(extractor.frame), 2)
                self.assertEqual(type(extractor.frame[0]).__name__, 'RawPacket')
            finally:
                close_extractor(extractor)


if __name__ == '__main__':
    unittest.main()
