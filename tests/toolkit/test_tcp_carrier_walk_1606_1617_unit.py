# -*- coding: utf-8 -*-
"""TCP carried in IPv4 behind an extension header or in a later fragment. C.f. #1606, #1617.

The default engine dispatches an IPv4 packet's protocol through the registry
IPv6 uses, so it reads an AH or IPv6 extension header carried directly in IPv4,
and the TCP segment or IP-in-IP tunnel behind it, up to
:data:`~pcapkit.utilities.config.EXTENSION_HEADER_LIMIT` headers in a
row (#1606).

A later IPv4 fragment carries no upper-layer header (:rfc:`791#section-3.2`), so
the default engine reads no TCP in one, but `Scapy`_ binds IPv6 to IPv4 protocol
41, and AH to protocol 51, whatever the fragment offset, and its engine handed on
the TCP it then dissected (#1617). It now stops at such a fragment.

`dpkt`_ decodes protocol 0 as IPv4, so a Hop-by-Hop header there can read as an
IPv4 packet dpkt cannot decode, or whose payload is no packet; neither ends the
extraction.

Every capture is built here, so the module is in the unit tier.

.. _dpkt: https://dpkt.readthedocs.io
.. _Scapy: https://scapy.net

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

if TYPE_CHECKING:
    from typing import Any, Callable

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


def has(engine: str) -> bool:
    """Whether ``engine``'s third-party package is installed."""
    return importlib.util.find_spec(engine) is not None


def options(nxt: int) -> bytes:
    """A Hop-by-Hop or Destination Options header of 8 octets, one PadN option in it."""
    return bytes([nxt, 0, 1, 4, 0, 0, 0, 0])


def ah(nxt: int, length: int = 4) -> bytes:
    """An Authentication Header whose Payload Length is ``length``, its ICV filled in."""
    fixed = bytes([nxt, length, 0, 0]) + (0x100).to_bytes(4, 'big') + (7).to_bytes(4, 'big')
    return fixed + b'\xaa' * max((length + 2) * 4 - len(fixed), 0)


def fragment(nxt: int, offset: int = 0) -> bytes:
    """An IPv6 Fragment header; ``offset`` is in octets."""
    return bytes([nxt, 0]) + offset.to_bytes(2, 'big') + (0xDEADBEEF).to_bytes(4, 'big')


def tcp(number: int, *, opts: bytes = b'', words: 'int | None' = None) -> bytes:
    """A TCP segment carrying ``data`` on a port pair of its own, with ``opts`` and a Data Offset of ``words``."""
    segment = wire.tcp(b'data', seq=1, ack=1, sport=1000 + number)
    words = 5 + len(opts) // 4 if words is None else words
    return segment[:12] + bytes([words << 4]) + segment[13:20] + opts + segment[20:]


def v4(payload: bytes, proto: int, *, length: 'int | None' = None, **fields: 'Any') -> bytes:
    """An IPv4 packet carrying ``payload`` as ``proto``, its Total Length ``length`` if given."""
    packet = bytearray(wire.ipv4(payload, proto=proto, **fields))
    if length is not None:
        packet[2:4] = length.to_bytes(2, 'big')
        packet[10:12] = b'\x00\x00'
        packet[10:12] = wire.checksum(bytes(packet[:20])).to_bytes(2, 'big')
    return bytes(packet)


def v6(payload: bytes, nxt: int) -> bytes:
    """An IPv6 packet carrying ``payload`` as ``nxt``."""
    return wire.ipv6(payload, nxt=nxt)


def eth(packet: bytes) -> bytes:
    """An Ethernet frame carrying the IPv4 or IPv6 ``packet``."""
    return wire.ethernet(packet, 0x86DD if packet[0] >> 4 == 6 else 0x0800)


#: Frames carrying TCP behind an AH or IPv6 extension header in IPv4, each with
#: whether the default engine reads the TCP, by a name for it. Each builder takes
#: the TCP segment it is to carry, given by its frame number.
EXTENSION_HEADERS = {
    'hop-by-hop': (True, lambda n: eth(v4(options(6) + tcp(n), 0))),
    'destination options': (True, lambda n: eth(v4(options(6) + tcp(n), 60))),
    'routing': (True, lambda n: eth(v4(bytes([6, 0, 0, 0, 0, 0, 0, 0]) + tcp(n), 43))),
    'fragment': (True, lambda n: eth(v4(fragment(6) + tcp(n), 44))),
    # the default engine reads past an IPv6 Fragment header inside IPv4 whatever its offset
    'later fragment header': (True, lambda n: eth(v4(fragment(6, 40) + tcp(n), 44))),
    'mobility': (True, lambda n: eth(v4(bytes([6, 0, 0, 0, 0, 0, 0, 0]) + tcp(n), 135))),
    'hip': (True, lambda n: eth(v4(bytes([6, 4, 1, 0x21, 0, 0, 0, 0]) + b'\x11' * 32 + tcp(n), 139))),
    'ah': (True, lambda n: eth(v4(ah(6) + tcp(n), 51))),
    'ah without icv': (True, lambda n: eth(v4(ah(6, 1) + tcp(n), 51))),
    # a Payload Length of 0 declares 8 octets, fewer than the fixed header
    'ah too short': (False, lambda n: eth(v4(ah(6, 0) + tcp(n), 51))),
    # Scapy reads a Next Header of 0 as IPv4
    'ah then hop-by-hop': (True, lambda n: eth(v4(ah(0) + options(6) + tcp(n), 51))),
    'hop-by-hop then destination options': (True, lambda n: eth(v4(options(60) + options(6) + tcp(n), 0))),
    'hop-by-hop then ah': (True, lambda n: eth(v4(options(51) + ah(6) + tcp(n), 0))),
    'chain at the limit': (True, lambda n: eth(v4(b''.join(options(60 if i < 31 else 6) for i in range(32))
                                                  + tcp(n), 60))),
    'chain past the limit': (False, lambda n: eth(v4(b''.join(options(60 if i < 32 else 6) for i in range(33))
                                                     + tcp(n), 60))),
    # tunnels behind the headers, and the headers inside tunnels
    '4in4 behind hop-by-hop': (True, lambda n: eth(v4(options(4) + v4(tcp(n), 6), 0))),
    '6in4 behind hop-by-hop': (True, lambda n: eth(v4(options(41) + v6(tcp(n), 6), 0))),
    '6in4 behind ah': (True, lambda n: eth(v4(ah(41) + v6(tcp(n), 6), 51))),
    'hop-by-hop in 4in4': (True, lambda n: eth(v4(v4(options(6) + tcp(n), 0), 4))),
    'hop-by-hop in 4in6': (True, lambda n: eth(v6(v4(options(6) + tcp(n), 0), 4))),
    'hop-by-hop in 4in4 behind hop-by-hop': (True, lambda n: eth(v4(options(4) + v4(options(6) + tcp(n), 0), 0))),
    # IPv4 behind the header that the default engine does not read
    'short ipv4 behind hop-by-hop': (False, lambda n: eth(v4(options(4) + v4(tcp(n), 6)[:12], 0))),
    'short ipv6 behind hop-by-hop': (False, lambda n: eth(v4(options(41) + v6(tcp(n), 6)[:30], 0))),
    'bad ipv4 behind hop-by-hop': (False, lambda n: eth(v4(options(4) + b'\x55' + v4(tcp(n), 6)[1:], 0))),
    # TCP behind the header, read as the TCP parser reads it
    'tcp options': (True, lambda n: eth(v4(options(6) + tcp(n, opts=b'\x02\x04\x05\xb4'), 0))),
    'rejected tcp options': (False, lambda n: eth(v4(options(6) + tcp(n, opts=b'\x02\x03\x05\xb4'), 0))),
    'tcp data offset past the capture': (False, lambda n: eth(v4(options(6) + tcp(n, words=15), 0))),
    'tcp data offset below 5': (False, lambda n: eth(v4(options(6) + tcp(n, words=4), 0))),
    'tcp cut short': (False, lambda n: eth(v4(options(6) + tcp(n)[:16], 0))),
    'no tcp': (False, lambda n: eth(v4(options(17) + wire.udp(b'data', sport=1000 + n), 0))),
    # the Total Length bounds what is read, and a zero one does not
    'total length short of the tcp': (False, lambda n: eth(v4(options(6) + tcp(n), 0, length=40))),
    'total length under the header': (False, lambda n: eth(v4(options(6) + tcp(n), 0, length=12))),
    'zero total length': (True, lambda n: eth(v4(options(6) + tcp(n), 0, length=0))),
    'trailer': (True, lambda n: eth(v4(options(6) + tcp(n), 0)) + b'\x00' * 10),
    'later ipv4 fragment': (False, lambda n: eth(v4(options(6) + tcp(n), 0, offset=8))),
    # Scapy dissects the datagram an ICMP error quotes, the default engine does not
    'quoted in an icmp error': (False, lambda n: eth(v4(bytes([3, 3, 0, 0, 0, 0, 0, 0])
                                                        + v4(options(6) + tcp(n), 0), 1))),
    'control': (True, lambda n: eth(v4(tcp(n), 6))),
}

#: Frames carrying TCP in a later IPv4 fragment or in its first, each with whether
#: the default engine reads the TCP, by a name for it.
FRAGMENTS = {
    '6in4 later fragment': (False, lambda n: eth(v4(v6(tcp(n), 6), 41, offset=40))),
    '4in4 later fragment': (False, lambda n: eth(v4(v4(tcp(n), 6), 4, offset=40))),
    'ah later fragment': (False, lambda n: eth(v4(ah(41) + v6(tcp(n), 6), 51, offset=40))),
    'tcp later fragment': (False, lambda n: eth(v4(tcp(n), 6, offset=40))),
    # in a tunnel, the inner header's offset counts too
    '6in4 later fragment in 4in4': (False, lambda n: eth(v4(v4(v6(tcp(n), 6), 41, offset=40), 4))),
    '6in4 later fragment in 4in6': (False, lambda n: eth(v6(v4(v6(tcp(n), 6), 41, offset=40), 4))),
    '6in4 first fragment': (True, lambda n: eth(v4(v6(tcp(n), 6), 41, mf=True))),
    '6in4': (True, lambda n: eth(v4(v6(tcp(n), 6), 41))),
}


def build(cases: 'dict[str, tuple[bool, Callable[[int], bytes]]]') -> 'tuple[list[bytes], list[int]]':
    """The frames of ``cases``, and the numbers of those the default engine reads TCP from."""
    numbered = list(enumerate(cases.values(), start=1))
    return ([make(number) for number, (_, make) in numbered],
            [number for number, (reads, _) in numbered if reads])


def read(test: unittest.TestCase, engine: str, frames: 'list[bytes]') -> 'dict[str, Any]':
    """Read ``frames`` with ``engine``, with TCP reassembly and flow tracing.

    Returns:
        Every input the engine hands TCP reassembly and flow tracing, keyed by
        frame number -- every field, but a trace input's ``frame`` -- the
        reassembled datagrams' ``id``, and the traced flows' labels and frames.

    """
    from pcapkit import extract
    from pcapkit.foundation.reassembly.tcp import TCP
    from pcapkit.foundation.traceflow.traceflow import TraceFlowBase

    seen = {'tcp': {}, 'trace': {}}  # type: dict[str, Any]
    reassemble, trace = TCP.__call__, TraceFlowBase.__call__

    def fields(packet: 'Any', skip: 'tuple[str, ...]' = ()) -> 'dict[str, Any]':
        return {key: bytes(value) if isinstance(value, bytearray) else value
                for key, value in packet.items() if key not in skip}

    def spy_tcp(this: 'Any', packet: 'Any') -> 'Any':
        seen['tcp'][packet.num] = fields(packet)
        return reassemble(this, packet)

    def spy_trace(this: 'Any', packet: 'Any') -> 'Any':
        seen['trace'][packet.index] = fields(packet, ('frame',))
        return trace(this, packet)

    records = [(1, number, octets) for number, octets in enumerate(frames)]
    with tempfile.TemporaryDirectory() as tmp, warnings.catch_warnings(), \
            mock.patch.object(TCP, '__call__', spy_tcp), \
            mock.patch.object(TraceFlowBase, '__call__', spy_trace):
        path = os.path.join(tmp, 'carrier.pcap')
        with open(path, 'wb') as file:
            file.write(wire.pcap(records))
        warnings.simplefilter('ignore')
        extractor = extract(fin=path, nofile=True, engine=engine, reassembly=True, tcp=True,
                            trace=True, trace_fout=os.path.join(tmp, 'trace'), trace_format='json')
        try:
            if extractor._exnam != engine:  # pylint: disable=protected-access
                test.skipTest(f'{engine} did not run')
            seen['ids'] = [datagram.id for datagram in extractor.reassembly.tcp]
            seen['flows'] = [(flow.label, tuple(flow.index)) for flow in extractor.trace.tcp]
        finally:
            close_extractor(extractor)
    return seen


#: The flow of the second frame of the dpkt cases below, ``tcp(2)`` in plain IPv4.
NEXT_FLOW = ('192.0.2.1_1002-198.51.100.2_9-1.000001', (2,))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TCPCarrierWalkTests(unittest.TestCase):
    """Where the engines read TCP in IPv4, and what dpkt survives on the way."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def assert_reads(self, engine: str, cases: 'dict[str, tuple[bool, Callable[[int], bytes]]]') -> None:
        """``engine`` reads TCP in exactly the frames of ``cases`` marked to be read."""
        frames, reads = build(cases)
        seen = read(self, engine, frames)
        names = dict(enumerate(cases, start=1))
        for aspect in ('tcp', 'trace'):
            self.assertEqual([names[number] for number in sorted(set(seen[aspect]) ^ set(reads))], [],
                             f'{aspect}: frames read, or left unread, against the cases')
        self.assertEqual(len(seen['ids']), len(reads))
        self.assertEqual([index for _, index in seen['flows']], [(number,) for number in reads])

    def test_the_default_engine_reads_tcp_behind_an_extension_header_in_ipv4(self) -> None:
        # #1606
        self.assert_reads('default', EXTENSION_HEADERS)

    def test_no_tcp_is_read_in_a_later_ipv4_fragment(self) -> None:
        # #1617: Scapy dissected TCP behind a later fragment
        for engine in ('default', 'scapy'):
            with self.subTest(engine=engine):
                if engine != 'default' and not has(engine):
                    self.skipTest(f'{engine} not installed')
                self.assert_reads(engine, FRAGMENTS)

    def test_a_tunnel_dpkt_cannot_decode_ends_no_extraction(self) -> None:
        # dpkt 1.9.8 reads ``frag_off`` from whatever header follows an IPv6
        # Fragment header (#1351), so the IPv6 packet behind this Hop-by-Hop
        # header raises AttributeError. The extraction goes on, and the next
        # frame is still read (#1626).
        if not has('dpkt'):
            self.skipTest('dpkt not installed')
        import dpkt

        inner = v6(fragment(0) + options(6) + tcp(1), 44)
        with self.assertRaises(AttributeError):
            dpkt.ip6.IP6(inner)
        seen = read(self, 'dpkt', [eth(v4(options(41) + inner, 0)), eth(v4(tcp(2), 6))])
        self.assertIn(2, seen['tcp'])
        self.assertIn(NEXT_FLOW, seen['flows'])

    def test_a_dpkt_payload_that_is_no_packet_is_leaf_data(self) -> None:
        # dpkt decodes IPv4 protocol 0 as IPv4, so this Hop-by-Hop header and the
        # start of the TCP segment behind it, from source port 112, read as IPv4
        # carrying VRRP, whose data dpkt leaves as ``''``. Tracing the segment
        # converts the frame with ``packet2dict``, which takes that for a layer.
        if not has('dpkt'):
            self.skipTest('dpkt not installed')
        import dpkt

        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import dpkt as toolkit

        octets = eth(v4(options(6) + wire.tcp(b'data', seq=1, ack=1, sport=112), 0))
        packet = dpkt.ethernet.Ethernet(octets)
        self.assertEqual(packet.ip.data.vrrp.data, '')
        info = toolkit.packet2dict(packet, 1.0, data_link=LinkType.ETHERNET)
        self.assertEqual(sorted(info['ETHERNET']['IP']['IP']['VRRP']), sorted(dpkt.vrrp.VRRP.__hdr_fields__))

        # and the extraction goes on to the next frame
        seen = read(self, 'dpkt', [octets, eth(v4(tcp(2), 6))])
        self.assertIn(2, seen['tcp'])
        self.assertIn(NEXT_FLOW, seen['flows'])

    def test_a_dpkt_payload_that_is_no_packet_ends_the_verbose_chain(self) -> None:
        # The same frame as above, whose chain ``packet2chain`` prints for each
        # frame in verbose mode: VRRP's ``''`` ends it.
        if not has('dpkt'):
            self.skipTest('dpkt not installed')
        import contextlib
        import io

        import dpkt

        from pcapkit import extract
        from pcapkit.toolkit import dpkt as toolkit

        octets = eth(v4(options(6) + wire.tcp(b'data', seq=1, ack=1, sport=112), 0))
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, warnings.catch_warnings(), contextlib.redirect_stdout(out):
            warnings.simplefilter('ignore')
            path = os.path.join(tmp, 'vrrp.pcap')
            with open(path, 'wb') as file:
                file.write(wire.pcap([(1, 0, octets), (1, 1, eth(v4(tcp(2), 6)))]))
            extractor = extract(fin=path, nofile=True, engine='dpkt', verbose=True)
            try:
                ran = extractor._exnam  # pylint: disable=protected-access
            finally:
                close_extractor(extractor)
        if ran != 'dpkt':
            self.skipTest('dpkt did not run')
        self.assertEqual([line for line in out.getvalue().splitlines() if line.startswith('Frame')],
                         ['Frame   1: Ethernet:IP:IP:VRRP', 'Frame   2: Ethernet:IP:TCP'])
        self.assertEqual(toolkit.packet2chain(dpkt.ethernet.Ethernet(octets)), 'Ethernet:IP:IP:VRRP')


if __name__ == '__main__':
    unittest.main()
