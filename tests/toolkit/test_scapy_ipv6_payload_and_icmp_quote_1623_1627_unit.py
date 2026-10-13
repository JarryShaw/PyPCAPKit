# -*- coding: utf-8 -*-
"""scapy reads IPv4 inside each IPv6 Payload Length, and nothing an ICMP error quotes. C.f. #1623, #1627.

The default engine hands IPv4 reassembly the first IPv4 layer of a frame, with
the octets inside the Payload Length of each IPv6 packet above it. `Scapy`_ files
whatever follows a Payload Length as padding at the end of the packet, so
``bytes()`` of an IPv4 layer carried in IPv6 ran on into the frame's trailer, or
past a Payload Length shorter than the IPv4 packet (#1623).

The default engine has no ICMP or ICMPv6 parser, so it reads nothing an ICMP
message carries. `Scapy`_ dissects the datagram an error quotes as ``IPerror`` or
``IPerror6``, which bind a full ``IPv6`` for 6in4 and 6in6, or ``IP`` for 4in6,
and so a real ``TCP``: that TCP went to TCP reassembly and flow tracing (#1627),
and that IPv4 to IPv4 reassembly. ``packet['IP']`` also reached the IPv4 inside
the IPv6 packet a Redirected Header option holds, in a field rather than a payload.

dpkt is compared with the default engine as well. Behind more than 32 extension
headers, scapy still hands IPv4 reassembly the IPv4 the default engine leaves
raw, which #1609 tracks, so that case is left out here.

Every capture is built here, so the module is in the unit tier.

.. _Scapy: https://scapy.net

"""
from __future__ import annotations

import importlib.util
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class
from tests.toolkit import test_dpkt_ipv4_reassembly_input_1615_1616_unit as ipv4_input
from tests.toolkit import test_tcp_carrier_walk_1606_1617_unit as carrier_walk
from tests.toolkit.test_tcp_carrier_walk_1606_1617_unit import eth, options, tcp, v4, v6

if TYPE_CHECKING:
    from typing import Any, Callable

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: The engines compared with the default engine.
ENGINES = ('dpkt', 'scapy')

#: ICMP Destination Unreachable and Time Exceeded, and an Echo Request, which quotes nothing.
ICMP_UNREACH = bytes([3, 3, 0, 0, 0, 0, 0, 0])
ICMP_TIMEX = bytes([11, 0, 0, 0, 0, 0, 0, 0])
ICMP_ECHO = bytes([8, 0, 0, 0, 0, 1, 0, 1])
#: ICMPv6 Destination Unreachable, Packet Too Big, Time Exceeded and Parameter Problem.
ICMP6_UNREACH = bytes([1, 4, 0, 0, 0, 0, 0, 0])
ICMP6_PTB = bytes([2, 0, 0, 0, 0, 0, 5, 0])
ICMP6_TIMEX = bytes([3, 0, 0, 0, 0, 0, 0, 0])
ICMP6_PARAM = bytes([4, 0, 0, 0, 0, 0, 0, 40])


def has(engine: str) -> bool:
    """Whether ``engine``'s third-party package is installed."""
    return importlib.util.find_spec(engine) is not None


def redirect(packet: bytes) -> bytes:
    """An ICMPv6 Redirect whose Redirected Header option holds ``packet`` (RFC 4861, section 4.6.3)."""
    held = packet + bytes(-(len(packet) + 8) % 8)
    return bytes([137, 0, 0, 0]) + bytes(36) + bytes([4, (len(held) + 8) // 8]) + bytes(6) + held


def ipv4_cases() -> 'dict[str, list[bytes]]':
    """#1615/#1616's frames by case, less #1609's, then those of #1623 and the ICMP quotes."""
    built = ipv4_input.cases()
    del built['4in6 behind 33 extension headers']   # #1609
    ethernet, ipv6 = ipv4_input.ethernet, ipv4_input.ipv6

    def first(ident: int) -> bytes:
        return ipv4_input.ipv4(b'A' * 16, ident=ident, mf=True)

    def last(ident: int) -> bytes:
        return ipv4_input.ipv4(b'B' * 8, ident=ident, offset=16)

    def pair(label: str, carry: 'Callable[[bytes], bytes]', ident: int) -> None:
        built[label] = [carry(first(ident)), carry(last(ident))]

    # #1623: each Payload Length above bounds the IPv4 octets, the inner as well as the outer
    built['4in6 cut by each Payload Length'] = [ethernet(ipv6(first(31), 4, plen=30)),
                                                ethernet(ipv6(last(31), 4, plen=24))]
    pair('4in6 in 6in6 with a trailer', lambda p: ethernet(ipv6(ipv6(p, 4), 41), trailer=b'\xee' * 6), 32)
    built['4in6 in 6in6 cut by the inner Payload Length'] = [ethernet(ipv6(ipv6(first(33), 4, plen=30), 41))]
    built['4in6 in 6in6 cut into the IPv4 header'] = [ethernet(ipv6(ipv6(first(34), 4), 41, plen=50))]
    built['4in6 cut into the IPv4 options'] = [ethernet(ipv6(ipv4_input.ipv4(
        b'A' * 16, ident=35, options=b'\x94\x04\x00\x00', mf=True), 4, plen=22), trailer=b'\x00' * 8)]
    # the outer IPv4 of 4in6in4 is the first, its octets running on to the trailer
    built['4in6in4 with a trailer'] = [ethernet(ipv4_input.ipv4(ipv6(first(36), 4), ident=37, proto=41),
                                                trailer=b'\xee' * 6)]
    # #1627: no IPv4 an ICMP message carries, quoted or held in an option
    pair('4in6 quoted by ICMPv6', lambda p: ethernet(ipv6(ICMP6_UNREACH + ipv6(p, 4), 58)), 38)
    pair('4in6 quoted by ICMPv6 behind Hop-by-Hop Options',
         lambda p: ethernet(ipv6(ipv4_input.options(58) + ICMP6_UNREACH + ipv6(p, 4), 0)), 39)
    pair('4in6 in a Redirected Header', lambda p: ethernet(ipv6(redirect(ipv6(p, 4)), 58)), 40)
    return built


#: Frames carrying TCP inside an ICMP or ICMPv6 message, and controls, each with
#: whether the default engine reads the TCP, by a name for it. Each builder takes
#: the TCP segment it is to carry, given by its frame number.
QUOTES = {
    # #1627: IPerror binds IPv6 for protocol 41, and IPerror6 binds IPv6 for 41 and IPv4 for 4
    'icmp quoting 6in4': (False, lambda n: eth(v4(ICMP_UNREACH + v4(v6(tcp(n), 6), 41), 1))),
    'icmp time exceeded quoting 6in4': (False, lambda n: eth(v4(ICMP_TIMEX + v4(v6(tcp(n), 6), 41), 1))),
    'icmp quoting 4in6 in 6in4': (False, lambda n: eth(v4(ICMP_UNREACH + v4(v6(v4(tcp(n), 6), 4), 41), 1))),
    'icmp in 4in4 quoting 6in4': (False, lambda n: eth(v4(v4(ICMP_UNREACH + v4(v6(tcp(n), 6), 41), 1), 4))),
    'icmp in 4in6 quoting 6in4': (False, lambda n: eth(v6(v4(ICMP_UNREACH + v4(v6(tcp(n), 6), 41), 1), 4))),
    'icmpv6 quoting 6in6': (False, lambda n: eth(v6(ICMP6_UNREACH + v6(v6(tcp(n), 6), 41), 58))),
    'icmpv6 packet too big quoting 6in6': (False, lambda n: eth(v6(ICMP6_PTB + v6(v6(tcp(n), 6), 41), 58))),
    'icmpv6 time exceeded quoting 6in6': (False, lambda n: eth(v6(ICMP6_TIMEX + v6(v6(tcp(n), 6), 41), 58))),
    'icmpv6 parameter problem quoting 6in6': (False, lambda n: eth(v6(ICMP6_PARAM + v6(v6(tcp(n), 6), 41), 58))),
    'icmpv6 quoting 4in6': (False, lambda n: eth(v6(ICMP6_UNREACH + v6(v4(tcp(n), 6), 4), 58))),
    'icmpv6 behind hop-by-hop quoting 6in6': (False, lambda n: eth(v6(options(58) + ICMP6_UNREACH
                                                                      + v6(v6(tcp(n), 6), 41), 0))),
    'icmpv6 in 6in4 quoting 6in6': (False, lambda n: eth(v4(v6(ICMP6_UNREACH + v6(v6(tcp(n), 6), 41), 58), 41))),
    # controls: quotes Scapy dissects as TCPerror, a message quoting nothing, a packet
    # Scapy holds in a field, and no ICMP at all
    'icmp quoting 4in4': (False, lambda n: eth(v4(ICMP_UNREACH + v4(v4(tcp(n), 6), 4), 1))),
    'icmp quoting tcp': (False, lambda n: eth(v4(ICMP_UNREACH + v4(tcp(n), 6), 1))),
    'icmpv6 quoting tcp': (False, lambda n: eth(v6(ICMP6_UNREACH + v6(tcp(n), 6), 58))),
    'icmp echo carrying 6in4': (False, lambda n: eth(v4(ICMP_ECHO + v4(v6(tcp(n), 6), 41), 1))),
    'redirected header holding 6in6': (False, lambda n: eth(v6(redirect(v6(v6(tcp(n), 6), 41)), 58))),
    '6in4': (True, lambda n: eth(v4(v6(tcp(n), 6), 41))),
    '6in6': (True, lambda n: eth(v6(v6(tcp(n), 6), 41))),
    '4in6 with a trailer': (True, lambda n: eth(v6(v4(tcp(n), 6), 4)) + b'\xee' * 6),
    'tcp': (True, lambda n: eth(v4(tcp(n), 6))),
}


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ScapyIPv4ReassemblyInputTests(unittest.TestCase):
    """scapy's IPv4 reassembly inputs are the default engine's, octet for octet."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = ipv4_cases()
        cls.frames = [frame for frames in cls.cases.values() for frame in frames]
        # one-based frame numbers of each case
        cls.numbers = {}  # type: dict[str, list[int]]
        number = 0
        for label, frames in cls.cases.items():
            cls.numbers[label] = list(range(number + 1, number + 1 + len(frames)))
            number += len(frames)

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def read(self, engine: str) -> 'dict[str, Any]':
        """``engine``'s reading of every case, read once per class."""
        if engine != 'default' and not has(engine):
            self.skipTest(f'{engine} not installed')
        seen = type(self).__dict__.get('seen')
        if seen is None:
            seen = type(self).seen = {}
        if engine not in seen:
            seen[engine] = ipv4_input.read(self, engine, self.frames)
        return seen[engine]

    def inputs(self, seen: 'dict[str, Any]', label: str) -> 'list[dict[str, Any]]':
        return [seen['inputs'][number] for number in self.numbers[label] if number in seen['inputs']]

    def test_every_input_agrees_with_the_default_engine(self) -> None:
        base = self.read('default')
        for engine in ENGINES:
            with self.subTest(engine=engine):
                seen = self.read(engine)
                for label in self.cases:
                    with self.subTest(engine=engine, case=label):
                        self.assertEqual(self.inputs(seen, label), self.inputs(base, label))
                self.assertEqual(seen['datagrams'], base['datagrams'])

    def test_each_payload_length_above_bounds_the_input(self) -> None:
        # #1623, the issue's two cases first
        scapy = self.read('scapy')
        for label, payloads in (
            ('4in6 with a trailer', [16, 8]),
            ('4in6 cut by each Payload Length', [10, 4]),
            ('4in6 cut by the Payload Length', [10]),
            ('4in6 cut by the outer Payload Length of 6in6', [10]),
            ('4in6 jumbogram', [10]),
            ('Total Length 0 in 4in6, with a trailer', [16]),
            ('4in6 in 6in6 with a trailer', [16, 8]),
            ('4in6 in 6in6 cut by the inner Payload Length', [10]),
            ('4in6in4 with a trailer', [76 + 6]),
        ):
            with self.subTest(case=label):
                self.assertEqual([len(packet['payload']) for packet in self.inputs(scapy, label)], payloads)
        # so the datagrams cut short are left incomplete, and the others complete
        complete = [datagram[2] for datagram in scapy['datagrams'] if datagram[0]]
        self.assertNotIn(tuple(self.numbers['4in6 cut by each Payload Length']), complete)
        self.assertIn(tuple(self.numbers['4in6 with a trailer']), complete)

    def test_no_input_where_the_default_engine_dissects_no_ipv4(self) -> None:
        for label in ('4in6 jumbogram shorter than the IPv4 header', '4in6 in 6in6 cut into the IPv4 header',
                      '4in6 cut into the IPv4 options', '4in6 quoted by ICMPv6',
                      '4in6 quoted by ICMPv6 behind Hop-by-Hop Options', '4in6 in a Redirected Header'):
            for engine in ('default', *ENGINES):
                with self.subTest(case=label, engine=engine):
                    self.assertEqual(self.inputs(self.read(engine), label), [])

    def test_a_packet_built_by_hand_is_bounded_too(self) -> None:
        # with no capture behind it, the octets are the ones Scapy dissected
        if not has('scapy'):
            self.skipTest('scapy not installed')
        # ``scapy.all`` binds IPv6 and ICMPv6, as the engine has it do (see pcapkit.toolkit.scapy)
        from scapy.all import Ether

        from pcapkit.toolkit import scapy as toolkit
        from pcapkit.utilities.exceptions import ModuleNotFound

        frame = self.cases['4in6 with a trailer'][0]
        data = toolkit.ipv4_reassembly(Ether(frame), count=1)
        self.assertIsNotNone(data)
        assert data is not None
        self.assertEqual((bytes(data.header), bytes(data.payload)), (frame[54:74], b'A' * 16))
        self.assertIsNone(toolkit.ipv4_reassembly(Ether(self.cases['4in6 quoted by ICMPv6'][0])))
        with mock.patch.object(toolkit, 'scapy', None), self.assertRaises(ModuleNotFound):
            toolkit.ipv4_reassembly(Ether(frame))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ScapyICMPQuoteTests(unittest.TestCase):
    """scapy hands on no TCP inside the datagram an ICMP or ICMPv6 error quotes."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_no_tcp_is_read_in_an_icmp_quote(self) -> None:
        # #1627
        frames, reads = carrier_walk.build(QUOTES)
        base = carrier_walk.read(self, 'default', frames)
        # what the default engine reads, as the cases say
        self.assertEqual(sorted(base['tcp']), reads)
        self.assertEqual(sorted(base['trace']), reads)
        names = dict(enumerate(QUOTES, start=1))
        for engine in ENGINES:
            with self.subTest(engine=engine):
                if not has(engine):
                    self.skipTest(f'{engine} not installed')
                seen = carrier_walk.read(self, engine, frames)
                for aspect in ('tcp', 'trace'):
                    self.assertEqual(
                        [names[number] for number in sorted(set(seen[aspect]) ^ set(base[aspect]))], [],
                        f'{aspect}: frames read by one of {engine} and the default engine alone')
                    self.assertEqual(seen[aspect], base[aspect], aspect)
                for aspect in ('ids', 'flows'):
                    self.assertEqual(seen[aspect], base[aspect], aspect)

    def test_a_packet_built_by_hand_is_walked_too(self) -> None:
        if not has('scapy'):
            self.skipTest('scapy not installed')
        # ``scapy.all`` binds IPv6 and ICMPv6, as the engine has it do (see pcapkit.toolkit.scapy)
        from scapy.all import Ether

        from pcapkit.toolkit import scapy as toolkit

        for label, (reads, make) in QUOTES.items():
            with self.subTest(case=label):
                packet = Ether(make(1))
                self.assertEqual(toolkit.tcp_reassembly(packet) is not None, reads)
                self.assertEqual(toolkit.tcp_traceflow(packet) is not None, reads)


if __name__ == '__main__':
    unittest.main()
