# -*- coding: utf-8 -*-
"""IP reassembly in an IP-in-IP tunnel reads the layer that is a fragment. C.f. #2307.

The IPv4 and IPv6 reassembly adapters read the frame's *outermost* IPv4 or
IPv6 layer. In a tunnel whose inner datagram was fragmented, each fragment was
reassembled whole under the tunnel's header, or, with the tunnel's DF set, or
with no Fragment header in the tunnel's IPv6, dropped; the inner datagram was
never reassembled. Each adapter takes the first layer of its IP version, from
the outside in, that is a fragment -- for IPv4, one with MF set or a non-zero
Fragment Offset, for IPv6, one with a Fragment header -- and with none, the
outermost as before. So a tunnel that is itself fragmented, its first fragment
alone carrying the inner header, is reassembled on the tunnel's header still.

Every capture is built here, so the module is in the unit tier. The
``pypcapfile`` engine decodes no tunnel, so has no counterpart.

"""
from __future__ import annotations

import importlib.util
import ipaddress
import os
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import close_extractor, reimport_once_per_class
from tests.foundation import _roundtrip as wire

if TYPE_CHECKING:
    from typing import Any

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: The tunnel's endpoints, by IP version.
OUTER = {4: ('192.0.2.1', '198.51.100.2'), 6: ('2001:db8:ffff::1', '2001:db8:ffff::2')}
#: The endpoints of the datagram carried through it, by IP version.
INNER = {4: ('10.0.0.1', '10.0.0.2'), 6: ('fd00::1', 'fd00::2')}
#: The IP protocol number that carries each IP version in a tunnel.
TUNNEL = {4: 4, 6: 41}
#: The UDP datagram the inner IP datagram carries, 40 octets long.
DATAGRAM = wire.udp(bytes(range(32)))
#: Identification of the inner datagram, and of the tunnel's datagram.
INNER_ID, OUTER_ID = 7, 100
#: Where each datagram is cut into two fragments, in octets.
CUT = 16


def addressed(packet: bytes, src: str, dst: str) -> bytes:
    """``packet``, an IPv4 or IPv6 one, from ``src`` to ``dst``."""
    octets = bytearray(packet)
    if octets[0] >> 4 == 4:
        octets[12:20] = ipaddress.ip_address(src).packed + ipaddress.ip_address(dst).packed
        octets[10:12] = b'\x00\x00'
        octets[10:12] = wire.checksum(bytes(octets[:20])).to_bytes(2, 'big')
    else:
        octets[8:40] = ipaddress.ip_address(src).packed + ipaddress.ip_address(dst).packed
    return bytes(octets)


def whole(version: int, payload: bytes, ends: 'tuple[str, str]', proto: int, *,
          ident: int = 0, df: bool = False) -> bytes:
    """An unfragmented IPv4 or IPv6 packet carrying ``payload`` as ``proto``."""
    if version == 4:
        return addressed(wire.ipv4(payload, ident=ident, df=df, proto=proto), *ends)
    return addressed(wire.ipv6(payload, nxt=proto), *ends)


def fragments(version: int, payload: bytes, ends: 'tuple[str, str]', proto: int,
              ident: int) -> 'list[bytes]':
    """The two fragments of an IPv4 or IPv6 datagram carrying ``payload`` as ``proto``."""
    pieces = ((0, payload[:CUT], True), (CUT, payload[CUT:], False))
    if version == 4:
        return [addressed(wire.ipv4(piece, ident=ident, offset=offset, mf=mf, proto=proto), *ends)
                for offset, piece, mf in pieces]
    return [addressed(wire.ipv6_fragment(piece, ident=ident, offset=offset, mf=mf, nxt=proto), *ends)
            for offset, piece, mf in pieces]


def frame(packet: bytes) -> bytes:
    """An Ethernet frame carrying the IPv4 or IPv6 ``packet``."""
    return wire.ethernet(packet, 0x0800 if packet[0] >> 4 == 4 else 0x86DD)


def inner_fragmented(version: int, *, df: bool = False) -> 'list[bytes]':
    """A whole tunnel packet per fragment of the inner datagram, one tunnel id each.

    ``df`` sets the DF flag of an IPv4 tunnel's header.

    """
    return [frame(whole(version, piece, OUTER[version], TUNNEL[version], ident=OUTER_ID + index, df=df))
            for index, piece in enumerate(fragments(version, DATAGRAM, INNER[version], 17, INNER_ID))]


def outer_fragmented(version: int) -> 'tuple[list[bytes], bytes]':
    """The fragments of a tunnel packet carrying the whole inner datagram, and that datagram."""
    inner = whole(version, DATAGRAM, INNER[version], 17, ident=INNER_ID)
    return [frame(piece) for piece in fragments(version, inner, OUTER[version],
                                                TUNNEL[version], OUTER_ID)], inner


def has(engine: str) -> bool:
    """Whether ``engine``'s third-party package is installed."""
    return engine == 'default' or importlib.util.find_spec(engine) is not None


def reassemble(test: unittest.TestCase, engine: str, version: int, frames: 'list[bytes]', *,
               pcapng: bool = False) -> 'list[Any]':
    """The datagrams ``engine`` reassembles out of ``frames`` with IPv4 or IPv6 reassembly."""
    from pcapkit import extract

    records = [(1, number, octets) for number, octets in enumerate(frames)]
    with tempfile.TemporaryDirectory() as tmp, warnings.catch_warnings():
        path = os.path.join(tmp, 'tunnel.pcapng' if pcapng else 'tunnel.pcap')
        with open(path, 'wb') as file:
            file.write(wire.pcapng(records) if pcapng else wire.pcap(records))
        warnings.simplefilter('ignore')
        extractor = extract(fin=path, nofile=True, engine=engine, reassembly=True,
                            ipv4=version == 4, ipv6=version == 6)
        try:
            if extractor._exnam != engine:  # pylint: disable=protected-access
                test.skipTest(f'{engine} did not run')
            return list(extractor.reassembly.ipv4 if version == 4 else extractor.reassembly.ipv6)
        finally:
            close_extractor(extractor)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TunnelledIPReassemblyTests(unittest.TestCase):
    """The default engine, scapy and dpkt reassemble the IP layer that is a fragment."""

    ENGINES = ('default', 'scapy', 'dpkt')

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def cases(self) -> 'Any':
        """Each engine, and for the default engine each format, as a sub-test."""
        for engine in self.ENGINES:
            for pcapng in ((False, True) if engine == 'default' else (False,)):
                yield engine, pcapng

    def test_fragmented_inner_datagram_is_reassembled(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion

        for engine, pcapng in self.cases():
            for version, df in ((4, False), (4, True), (6, False)):
                with self.subTest(engine=engine, pcapng=pcapng, version=version, df=df):
                    if not has(engine):
                        self.skipTest(f'{engine} not installed')
                    frames = inner_fragmented(version, df=df)
                    datagram, = reassemble(self, engine, version, frames, pcapng=pcapng)
                    self.assertIs(datagram.completed, Completion.COMPLETE)
                    self.assertEqual((str(datagram.id.src), str(datagram.id.dst), datagram.id.id),
                                     (*INNER[version], INNER_ID))
                    self.assertEqual(datagram.index, (1, 2))
                    self.assertEqual(datagram.payload, DATAGRAM)

    def test_fragmented_tunnel_is_reassembled_on_its_own_header(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion

        for engine, pcapng in self.cases():
            for version in (4, 6):
                with self.subTest(engine=engine, pcapng=pcapng, version=version):
                    if not has(engine):
                        self.skipTest(f'{engine} not installed')
                    frames, inner = outer_fragmented(version)
                    datagram, = reassemble(self, engine, version, frames, pcapng=pcapng)
                    self.assertIs(datagram.completed, Completion.COMPLETE)
                    self.assertEqual((str(datagram.id.src), str(datagram.id.dst), datagram.id.id),
                                     (*OUTER[version], OUTER_ID))
                    self.assertEqual(datagram.index, (1, 2))
                    self.assertEqual(datagram.payload, inner)

    def test_a_datagram_an_icmp_error_quotes_is_not_walked_to(self) -> None:
        # A quoted datagram is no tunnel, though DPKT decodes one as an IP layer
        # below the ICMP one: its fragment is never the one reassembled
        quoted = {4: addressed(wire.ipv4(DATAGRAM[:8], ident=INNER_ID, mf=True, proto=17), *INNER[4]),
                  6: addressed(wire.ipv6_fragment(DATAGRAM[:8], ident=INNER_ID, mf=True, nxt=17), *INNER[6])}
        # Destination Unreachable: ICMP port unreachable, ICMPv6 port unreachable
        errors = {4: bytes([3, 3, 0, 0]) + bytes(4) + quoted[4], 6: bytes([1, 4, 0, 0]) + bytes(4) + quoted[6]}
        for engine, pcapng in self.cases():
            for version in (4, 6):
                with self.subTest(engine=engine, pcapng=pcapng, version=version):
                    if not has(engine):
                        self.skipTest(f'{engine} not installed')
                    error = whole(version, errors[version], OUTER[version], 1 if version == 4 else 58,
                                  ident=OUTER_ID)
                    datagrams = reassemble(self, engine, version, [frame(error)], pcapng=pcapng)
                    if version == 6:
                        # the outer IPv6 packet has no Fragment header
                        self.assertEqual(datagrams, [])
                        continue
                    # the outer IPv4 packet, read whole as for any frame of no fragment
                    datagram, = datagrams
                    self.assertEqual((str(datagram.id.src), str(datagram.id.dst), datagram.id.id),
                                     (*OUTER[4], OUTER_ID))
                    self.assertEqual(datagram.payload, errors[4])


if __name__ == '__main__':
    unittest.main()
