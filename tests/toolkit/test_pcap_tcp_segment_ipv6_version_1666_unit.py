# -*- coding: utf-8 -*-
"""The default engine reads past an IPv6 header whose Version is 4, and hands it nothing. C.f. #1666, #1680.

:func:`pcapkit.toolkit.pcap.tcp_segment` reads a TCP header the parser rejected
from its fixed 20 octets, unless the datagram is a later fragment (#1518). It
took the IPv4 branch of that fragment check by the header's Version field, and
IPv6 then read any Version, so an IPv6 layer with Version 4 took it too and read
an ``offset`` IPv6 does not have: the ``AttributeError`` ended the extraction,
PCAP and PCAP-NG alike (#1666). The branch goes by the layer's class. And
IPv6 rejects a Version other than 6 (#1680), so such a header is kept raw:
its frame hands over no input, and every frame after it is still read.

scapy still reads those headers as IPv6 and hands their segments over, which
the best-effort ruling on third-party engines allows (#1687).

Every capture is built here, so the module is in the unit tier.

"""
from __future__ import annotations

import importlib.util
import ipaddress
import os
import struct
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import close_extractor, reimport_once_per_class
from tests.foundation import _roundtrip as wire

if TYPE_CHECKING:
    from typing import Any, Callable

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: The third-party engines read here besides the default engine.
ENGINES = ('scapy',)

#: The endpoints of every IPv6 header built here, then of every IPv4 one.
IPV6 = (ipaddress.IPv6Address(wire.IPV6_A), ipaddress.IPv6Address(wire.IPV6_B))
IPV4 = (ipaddress.IPv4Address(wire.IPV4_A), ipaddress.IPv4Address(wire.IPV4_B))


def bad_tcp(port: int) -> bytes:
    """A TCP segment from ``port`` to 80 whose Data Offset of 15 runs past its 25 octets, so TCP rejects it."""
    return struct.pack('!HHIIBBHHH', port, 80, 1000, 0, 0xF0, 0x18, 65535, 0, 0) + b'hello'


def h4(payload: bytes, nxt: int) -> bytes:
    """An IPv6 header whose Version field is 4, carrying ``payload`` as ``nxt``."""
    return struct.pack('!IHBB', 4 << 28, len(payload), nxt, 64) + wire.IPV6_A + wire.IPV6_B + payload


def eth(packet: bytes, ethertype: int) -> bytes:
    """An Ethernet frame carrying ``packet`` as ``ethertype``."""
    return wire.ethernet(packet, ethertype)


def dot1q(packet: bytes, ethertype: int) -> bytes:
    """An Ethernet frame carrying ``packet`` as ``ethertype`` behind an 802.1Q tag."""
    return wire.MAC_B + wire.MAC_A + b'\x81\x00' + (100).to_bytes(2, 'big') + ethertype.to_bytes(2, 'big') + packet


def fragment(nxt: int) -> bytes:
    """The Fragment header of a first fragment."""
    return bytes([nxt, 0, 0, 1]) + (0x55).to_bytes(4, 'big')


#: Frames carrying a TCP segment TCP rejects, by a name for each, with the
#: endpoints the segment is keyed by. ``H4`` is an IPv6 header of Version 4.
#: Each builder takes the segment it is to carry.
CASES = {
    'Ethernet, H4': (IPV6, lambda s: eth(h4(s, 6), 0x86DD)),
    '802.1Q, H4': (IPV6, lambda s: dot1q(h4(s, 6), 0x86DD)),
    'H4 in IPv4': (IPV6, lambda s: eth(wire.ipv4(h4(s, 6), proto=41), 0x0800)),
    '802.1Q, H4 in IPv4': (IPV6, lambda s: dot1q(wire.ipv4(h4(s, 6), proto=41), 0x0800)),
    'H4 in IPv6': (IPV6, lambda s: eth(wire.ipv6(h4(s, 6), nxt=41), 0x86DD)),
    'H4 in H4': (IPV6, lambda s: eth(h4(h4(s, 6), 41), 0x86DD)),
    'H4 first fragment': (IPV6, lambda s: eth(h4(fragment(6) + s, 44), 0x86DD)),
    'H4, Hop-by-Hop header': (IPV6, lambda s: eth(h4(bytes([6, 0, 1, 4, 0, 0, 0, 0]) + s, 0), 0x86DD)),
    'IPv6 (control)': (IPV6, lambda s: eth(wire.ipv6(s, nxt=6), 0x86DD)),
    'IPv4 (control)': (IPV4, lambda s: eth(wire.ipv4(s, proto=6), 0x0800)),
}

#: The numbers of every frame of :func:`build`, then of the controls alone.
FRAMES = list(range(1, len(CASES) + 1))
CONTROLS = [number for number, name in enumerate(CASES, start=1) if name.endswith('(control)')]


def build() -> 'list[bytes]':
    """The frames of :data:`CASES` in order, the ``n``-th carrying a segment from port ``1000 + n``."""
    return [make(bad_tcp(1000 + number)) for number, (_, make) in enumerate(CASES.values(), start=1)]


def read(test: unittest.TestCase, engine: str, frames: 'list[bytes]', container: str) -> 'dict[str, Any]':
    """Read ``frames`` with ``engine`` from a ``container`` capture, with IP and TCP reassembly and flow tracing.

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

    def spy(klass: 'Any') -> 'Callable[[Any, Any], Any]':
        def call(this: 'Any', packet: 'Any') -> 'Any':
            seen[klass.__name__][packet.num] = fields(packet)
            return calls[klass](this, packet)
        return call

    def spy_trace(this: 'Any', packet: 'Any') -> 'Any':
        seen['trace'][packet.index] = fields(packet, ('frame',))
        return trace(this, packet)

    write = wire.pcapng if container == 'pcapng' else wire.pcap
    with tempfile.TemporaryDirectory() as tmp, warnings.catch_warnings(), \
            mock.patch.object(IPv4, '__call__', spy(IPv4)), mock.patch.object(IPv6, '__call__', spy(IPv6)), \
            mock.patch.object(TCP, '__call__', spy(TCP)), mock.patch.object(TraceFlowBase, '__call__', spy_trace):
        path = os.path.join(tmp, f'version.{container}')
        with open(path, 'wb') as file:
            file.write(write([(1, number, octets) for number, octets in enumerate(frames)]))
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


def check(test: unittest.TestCase, seen: 'dict[str, Any]', numbers: 'list[int]') -> None:
    """Assert ``seen`` holds the TCP reassembly and trace inputs of the frames ``numbers``, and of no other."""
    test.assertEqual(sorted(seen['TCP']), numbers)
    test.assertEqual(sorted(seen['trace']), numbers)
    test.assertEqual([index for _, index in seen['flows']], [(n,) for n in numbers])
    for number, (name, ((src, dst), _)) in enumerate(CASES.items(), start=1):
        if number not in numbers:
            continue
        with test.subTest(case=name):
            segment = bad_tcp(1000 + number)
            reasm, trace = seen['TCP'][number], seen['trace'][number]
            test.assertEqual(reasm['bufid'], (src, 1000 + number, dst, 80))
            test.assertEqual((reasm['dsn'], reasm['ack'], reasm['syn'], reasm['fin'], reasm['rst']),
                             (1000, 0, False, False, False))
            # the Data Offset runs past the segment, so all of it is header
            test.assertEqual((reasm['header'], reasm['payload'], reasm['len']), (segment, b'', 0))
            test.assertEqual((trace['src'], trace['srcport'], trace['dst'], trace['dstport']),
                             (src, 1000 + number, dst, 80))
            test.assertEqual((trace['seq'], trace['ack'], trace['header'], trace['payload']),
                             (1000, 0, segment, b''))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPv6VersionFourTests(unittest.TestCase):
    """An IPv6 header of Version 4 is no IPv6 layer to the default engine, PCAP and PCAP-NG alike."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_the_default_engine_reads_only_the_controls(self) -> None:
        frames = build()
        for container in ('pcap', 'pcapng'):
            with self.subTest(container=container):
                seen = read(self, 'default', frames, container)
                # the controls come after every H4 frame, so each of those was read
                check(self, seen, CONTROLS)
                # nor does the H4 first fragment reach IPv6 reassembly
                self.assertEqual(seen['IPv6'], {})
                self.assertEqual(seen['datagrams']['IPv6'], [])

    def test_scapy_reads_every_segment(self) -> None:
        frames = build()
        for container in ('pcap', 'pcapng'):
            for engine in ENGINES:
                with self.subTest(container=container, engine=engine):
                    if importlib.util.find_spec(engine) is None:
                        self.skipTest(f'{engine} not installed')
                    check(self, read(self, engine, frames, container), FRAMES)


if __name__ == '__main__':
    unittest.main()
