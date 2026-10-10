# -*- coding: utf-8 -*-
"""TCP in an IP-in-IP tunnel is keyed by the innermost IP header. C.f. #1581.

The TCP reassembly and flow tracing adapters keyed a segment by the frame's
*first* IP layer, which in a tunnel is the tunnel's own: every connection through
one tunnel that shares a port pair merged into one flow, under the tunnel's
endpoints. The default engine, scapy and pyshark did so (scapy found the inner
IPv4 layer of 4in6 only), and dpkt found no TCP in a tunnel at all. Each now
keys it by the IP layer nearest above the TCP segment, as Wireshark's TCP
conversations do -- and dpkt enters only the tunnels the default engine
dissects, protocols 4 and 41, not the protocol 0 it also decodes as IPv4.

Every capture is built here, so the module is in the unit tier. pyshark runs
only where the interpreter supports it, with tshark on the path. The
``pypcapfile`` engine's counterparts need `pypcapfile`, so live in
:mod:`tests.toolkit.test_pypcapfile_unit`, which the PyPCAPFile CI cell runs.

"""
from __future__ import annotations

import importlib.util
import ipaddress
import io
import os
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import close_extractor, reimport_once_per_class
from tests.foundation import _roundtrip as wire

if TYPE_CHECKING:
    from typing import Any

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: The tunnel's endpoints, by IP version.
OUTER = {4: ('192.0.2.1', '198.51.100.2'), 6: ('2001:db8:ffff::1', '2001:db8:ffff::2')}
#: The endpoints of the two connections through it, by IP version.
INNER = {4: (('10.0.0.1', '10.0.0.2'), ('10.0.0.3', '10.0.0.4')),
         6: (('fd00::1', 'fd00::2'), ('fd00::3', 'fd00::4'))}
#: The IP protocol number that carries each IP version in a tunnel.
TUNNEL = {4: 4, 6: 41}
#: Each tunnel, named inner version first: ``6in4`` is IPv6 carried in IPv4.
KINDS = {'4in4': (4, 4), '6in4': (6, 4), '4in6': (4, 6), '6in6': (6, 6)}
#: Engines that report dissected fields only: no TCP reassembly, and no TCP
#: octets in what they hand flow tracing (as ``NO_TCP_OCTETS`` in
#: :mod:`tests.foundation.engines.test_engine_agreement_runtime`).
FIELDS_ONLY = frozenset(('pyshark',))


def ip(version: int, payload: bytes, src: str, dst: str, proto: int, **fields: 'Any') -> bytes:
    """An IPv4 or IPv6 packet from ``src`` to ``dst`` carrying ``payload`` as ``proto``.

    ``fields`` are :func:`tests.foundation._roundtrip.ipv4`'s, for IPv4 only.

    """
    if version == 4:
        packet = bytearray(wire.ipv4(payload, proto=proto, **fields))
        packet[12:20] = ipaddress.ip_address(src).packed + ipaddress.ip_address(dst).packed
        packet[10:12] = b'\x00\x00'
        packet[10:12] = wire.checksum(bytes(packet[:20])).to_bytes(2, 'big')
        return bytes(packet)
    packet = bytearray(wire.ipv6(payload, nxt=proto))
    packet[8:40] = ipaddress.ip_address(src).packed + ipaddress.ip_address(dst).packed
    return bytes(packet)


def frame(packet: bytes) -> bytes:
    """An Ethernet frame carrying the IPv4 or IPv6 ``packet``."""
    return wire.ethernet(packet, 0x0800 if packet[0] >> 4 == 4 else 0x86DD)


def tunnelled(kind: str, segment: bytes, connection: int = 0, *, inner_proto: int = 6) -> bytes:
    """An Ethernet frame of a ``kind`` tunnel carrying ``segment`` on ``connection``."""
    inner, outer = KINDS[kind]
    packet = ip(inner, segment, *INNER[inner][connection], inner_proto)
    return frame(ip(outer, packet, *OUTER[outer], TUNNEL[inner]))


def connections(kind: str) -> 'list[bytes]':
    """Two connections through one ``kind`` tunnel, on the same port pair.

    Each is a SYN, a data segment and a FIN, from port 40000 to 9.

    """
    return [tunnelled(kind, segment, connection)
            for connection in (0, 1)
            for segment in (wire.tcp(b'', seq=100, syn=True), wire.tcp(b'hello', seq=101, ack=1),
                            wire.tcp(b'', seq=106, ack=1, fin=True))]


def has(engine: str) -> bool:
    """Whether ``engine``'s third-party package is installed."""
    return engine == 'default' or importlib.util.find_spec(engine) is not None


def read(test: unittest.TestCase, engine: str, frames: 'list[bytes]', *,
         pcapng: bool = False) -> 'dict[str, Any]':
    """Read ``frames`` with ``engine``, with TCP reassembly and flow tracing.

    Returns:
        Every input the engine hands TCP reassembly and flow tracing, keyed by
        frame number -- every field, but a trace input's ``frame``, and its
        ``header`` and ``payload`` too for an engine in :data:`FIELDS_ONLY` --
        and the reassembled datagrams' ``id`` and the traced flows' labels and
        frames. An engine in :data:`FIELDS_ONLY` reassembles nothing, so has
        no ``id`` there.

    """
    from pcapkit import extract
    from pcapkit.foundation.reassembly.reassembly import ReassemblyBase
    from pcapkit.foundation.traceflow.traceflow import TraceFlowBase

    seen = {'tcp': {}, 'trace': {}}  # type: dict[str, Any]
    reassemble, trace = ReassemblyBase.__call__, TraceFlowBase.__call__
    fields_only = engine in FIELDS_ONLY
    skip = ('frame', 'header', 'payload') if fields_only else ('frame',)

    def fields(packet: 'Any', skip: 'tuple[str, ...]' = ()) -> 'dict[str, Any]':
        return {key: bytes(value) if isinstance(value, bytearray) else value
                for key, value in packet.items() if key not in skip}

    def spy_reassembly(this: 'Any', packet: 'Any') -> 'Any':
        seen['tcp'][packet.num] = fields(packet)
        return reassemble(this, packet)

    def spy_trace(this: 'Any', packet: 'Any') -> 'Any':
        seen['trace'][packet.index] = fields(packet, skip)
        return trace(this, packet)

    records =[(1, number, octets) for number, octets in enumerate(frames)]
    with tempfile.TemporaryDirectory() as tmp, warnings.catch_warnings(), \
            mock.patch.object(ReassemblyBase, '__call__', spy_reassembly), \
            mock.patch.object(TraceFlowBase, '__call__', spy_trace):
        path = os.path.join(tmp, 'tunnels.pcapng' if pcapng else 'tunnels.pcap')
        with open(path, 'wb') as file:
            file.write(wire.pcapng(records) if pcapng else wire.pcap(records))
        warnings.simplefilter('ignore')
        extractor = extract(fin=path, nofile=True, engine=engine, reassembly=not fields_only,
                            tcp=True, trace=True, trace_fout=os.path.join(tmp, 'trace'),
                            trace_format='json')
        try:
            if extractor._exnam != engine:  # pylint: disable=protected-access
                test.skipTest(f'{engine} did not run')
            seen['ids'] = None if fields_only else [datagram.id for datagram in extractor.reassembly.tcp]
            seen['flows'] = [(flow.label, tuple(flow.index)) for flow in extractor.trace.tcp]
        finally:
            close_extractor(extractor)
    return seen


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TunnelledTCPFlowKeyTests(unittest.TestCase):
    """Every engine keys tunnelled TCP by the innermost IP header, as the default engine does."""

    ENGINES = ('default', 'dpkt', 'scapy', 'pyshark')

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def agree(self, frames: 'list[bytes]', engines: 'tuple[str, ...]' = ENGINES[1:]) -> 'dict[str, Any]':
        """Check each of ``engines`` hands on what the default engine does for ``frames``.

        That is every field of every TCP reassembly and flow tracing input, the
        reassembled datagrams' ``id`` and the traced flows -- for an engine in
        :data:`FIELDS_ONLY`, the flow tracing inputs less their octets, and the
        flows. Returns the default engine's.

        """
        base = read(self, 'default', frames)
        for engine in engines:
            with self.subTest(engine=engine):
                if not has(engine):
                    self.skipTest(f'{engine} not installed')
                seen = read(self, engine, frames)
                want = base
                if engine in FIELDS_ONLY:
                    want = {'flows': base['flows'], 'trace': {
                        number: {key: value for key, value in record.items() if key not in ('header', 'payload')}
                        for number, record in base['trace'].items()}}
                for aspect in want:
                    self.assertEqual(seen[aspect], want[aspect], aspect)
        return base

    def test_two_connections_through_one_tunnel_are_two_flows(self) -> None:
        for engine in self.ENGINES:
            for kind, (inner, _) in KINDS.items():
                for pcapng in ((False, True) if engine == 'default' else (False,)):
                    with self.subTest(engine=engine, kind=kind, pcapng=pcapng):
                        if not has(engine):
                            self.skipTest(f'{engine} not installed')
                        seen = read(self, engine, connections(kind), pcapng=pcapng)
                        pairs = sorted(tuple(map(ipaddress.ip_address, pair)) for pair in INNER[inner])
                        # one flow per connection, under its own endpoints, not the tunnel's
                        self.assertEqual(
                            [label.rsplit('-', 1)[0] for label, _ in seen['flows']],
                            [f'{src}_40000-{dst}_9'.replace(':', '.') for src, dst in INNER[inner]])
                        self.assertEqual([index for _, index in seen['flows']], [(1, 2, 3), (4, 5, 6)])
                        self.assertEqual(sorted({(record['src'], record['dst'])
                                                 for record in seen['trace'].values()}), pairs)
                        if engine in FIELDS_ONLY:
                            continue
                        # and one reassembly buffer per connection
                        self.assertEqual(sorted({(d.src[0], d.dst[0]) for d in seen['ids']}), pairs)
                        self.assertEqual(sorted({(record['bufid'][0], record['bufid'][2])
                                                 for record in seen['tcp'].values()}), pairs)

    def test_protocol_0_is_no_tunnel(self) -> None:
        # dpkt decodes an IPv4 protocol 0 as IPv4, its IP_PROTO_IP; the default
        # engine reads an IPv6 Hop-by-Hop Options header there, and so finds no
        # TCP in the IPv4 packet behind it.
        frames = [frame(ip(4, ip(4, segment, *INNER[4][connection], 6), *OUTER[4], 0))
                  for connection, segment in enumerate((wire.tcp(b'', seq=100, syn=True),
                                                        wire.tcp(b'hello', seq=101, ack=1)))]
        base = self.agree(frames)
        self.assertEqual((base['trace'], base['flows'], base['ids']), ({}, [], []))

    def test_tunnelled_segments_agree_with_the_default_engine(self) -> None:
        # The other engines hand reassembly and flow tracing every field the
        # default engine does, however the tunnel is built.
        segment = wire.tcp(b'payload', seq=7, ack=1)
        # a Data Offset of 6 words in a 20-octet segment, which the TCP parser
        # rejects and the default engine reads out of the raw octets (#1518)
        cut = segment[:12] + b'\x60' + segment[13:20]
        hop_by_hop = bytes([4, 0, 1, 4, 0, 0, 0, 0])
        frames = [
            *(tunnelled(kind, segment) for kind in KINDS),
            # tunnels in tunnels
            frame(ip(4, ip(4, ip(4, segment, *INNER[4][0], 6), '172.16.0.1', '172.16.0.2', 4),
                     *OUTER[4], 4)),
            frame(ip(4, ip(6, ip(4, segment, *INNER[4][0], 6), 'fd01::1', 'fd01::2', 4),
                     *OUTER[4], 41)),
            frame(ip(6, ip(4, ip(6, segment, *INNER[6][0], 6), '172.16.0.1', '172.16.0.2', 41),
                     *OUTER[6], 4)),
            # a TCP header cut short, in a tunnel
            *(tunnelled(kind, cut) for kind in KINDS),
            # behind an IPv6 extension header, and padded
            frame(ip(6, hop_by_hop + ip(4, segment, *INNER[4][1], 6), *OUTER[6], 0)),
            tunnelled('4in4', wire.tcp(b'', seq=1, ack=1)) + bytes(6),
        ]
        base = self.agree(frames)
        self.assertEqual(sorted(base['trace']), list(range(1, len(frames) + 1)))

    def test_tunnelled_first_fragments_agree_with_the_default_engine(self) -> None:
        # Not for pyshark: tshark reassembles IP fragments, so dissects no TCP in
        # a first fragment, tunnelled or not.
        segment = wire.tcp(b'payload', seq=7, ack=1)
        frames = [
            # the tunnel's first fragment, then the inner datagram's
            frame(ip(4, ip(4, segment, *INNER[4][1], 6), *OUTER[4], 4, mf=True)),
            frame(ip(4, ip(4, segment, *INNER[4][1], 6, mf=True), *OUTER[4], 4)),
        ]
        base = self.agree(frames, ('dpkt', 'scapy'))
        self.assertEqual(sorted(base['trace']), [1, 2])

    def test_the_default_engine_reads_the_inner_header(self) -> None:
        from pcapkit import extract
        from pcapkit.toolkit.pcap import tcp_segment

        segment = wire.tcp(b'payload', seq=7, ack=1)
        cut = segment[:12] + b'\x60' + segment[13:20]
        for label, octets, want in (
            ('4in4', tunnelled('4in4', segment), INNER[4][0]),
            ('6in6', tunnelled('6in6', segment, 1), INNER[6][1]),
            # the TCP parser rejects the header, so the segment is read out of
            # the raw octets the inner IP layer is left with
            ('4in4, header cut short', tunnelled('4in4', cut), INNER[4][0]),
            ('6in4, header cut short', tunnelled('6in4', cut, 1), INNER[6][1]),
        ):
            with self.subTest(case=label):
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    extractor = extract(fin=io.BytesIO(wire.pcap([(1, 0, octets)])), nofile=True)
                self.addCleanup(close_extractor, extractor)
                record = tcp_segment(extractor.frame[0])
                assert record is not None
                self.assertEqual((str(record.ip.src), str(record.ip.dst)), want)
                self.assertEqual((record.srcport, record.dstport, record.seq), (40000, 9, 7))

    def test_no_segment_where_the_inner_header_carries_none(self) -> None:
        from pcapkit import extract
        from pcapkit.toolkit.pcap import tcp_segment

        segment = wire.tcp(b'payload', seq=7, ack=1)
        arp = bytes.fromhex('0001080006040001') + bytes(6) + bytes(4) + bytes(6) + bytes(4)
        for label, octets in (
            ('no ip layer at all', wire.ethernet(arp, 0x0806)),
            ('tunnelled udp', tunnelled('4in4', wire.udp(b'x'), inner_proto=17)),
            # an inner header the IPv4 parser rejects leaves the outer one's payload raw
            ('inner ihl past the packet', frame(ip(4, b'\x4f' + ip(4, segment, *INNER[4][0], 6)[1:],
                                                   *OUTER[4], 4))),
            ('inner later fragment', frame(ip(4, ip(4, segment, *INNER[4][0], 6, offset=8),
                                              *OUTER[4], 4))),
            ('inner data offset 4', tunnelled('4in4', segment[:12] + b'\x40' + segment[13:])),
        ):
            with self.subTest(case=label):
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    extractor = extract(fin=io.BytesIO(wire.pcap([(1, 0, octets)])), nofile=True)
                self.addCleanup(close_extractor, extractor)
                self.assertIsNone(tcp_segment(extractor.frame[0]))


if __name__ == '__main__':
    unittest.main()
