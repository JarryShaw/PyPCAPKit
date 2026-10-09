# -*- coding: utf-8 -*-
"""Reassembly recovers the payload its fragments or segments were cut from. C.f. #1202.

Each case cuts a known payload -- a UDP datagram for IPv4 and IPv6, a byte
stream for TCP -- into fragments or segments, puts them on the wire in some
order, writes them to an in-memory PCAP savefile and runs that through
:func:`~pcapkit.interface.extract` with reassembly on. The round trip closes
when exactly one datagram comes back per payload, it is
:attr:`~pcapkit.foundation.reassembly.data.data.Completion.COMPLETE`, its octets
are the payload's, and its ``index`` names the frames that carried it.

The orders are the ones a capture produces: in order, reversed, the last piece
first, interleaved, every piece twice (a retransmission), and with one extra
piece overlapping two others with the same octets. Each runs in strict and in
non-strict mode, which differ only in how a datagram with holes is reported --
so for a complete datagram they must agree.

When every IP fragment arrives twice, the second copy of the last one comes
after its datagram completed. Per the owner's ruling on #1507 (item 1), that
copy opens a new buffer and surfaces as a second, ``PARTIAL`` datagram, as RFC
791, Linux, FreeBSD, Suricata, Zeek and Wireshark all do, so those cases expect
both datagrams.

Every case builds its own octets and reads no capture. Classes are imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

from __future__ import annotations

import importlib.util
import io
import unittest
import warnings
from typing import TYPE_CHECKING, NamedTuple

from tests._support import close_extractor, reimport_once_per_class
from tests.foundation import _roundtrip as harness
from tests.foundation._roundtrip import (Gap, Outcome, ethernet, ipv4, ipv6,
                                         ipv6_fragment, payload_pattern, pcap, tcp, udp)

if TYPE_CHECKING:
    from typing import Any

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))


class Stream(NamedTuple):
    """One payload, and the frames that carry it."""

    #: Payload the frames were cut from, as the datagram reports it: a tuple of
    #: runs for a strict ``PARTIAL`` datagram.
    payload: 'bytes | tuple[bytes, ...]'
    #: 1-based frame numbers carrying any of it.
    frames: 'tuple[int, ...]'
    #: Expected datagram header, or :data:`None` not to check it.
    header: 'bytes | None' = None
    #: Expected completion.
    completed: 'str' = 'COMPLETE'


class Case(NamedTuple):
    """One capture to reassemble."""

    label: 'str'
    #: ``'ipv4'``, ``'ipv6'`` or ``'tcp'``.
    kind: 'str'
    frames: 'tuple[bytes, ...]'
    streams: 'tuple[Stream, ...]'
    strict: 'bool'


#: How each payload is cut, as piece lengths; an IP piece but the last is a
#: multiple of 8 octets.
IP_CUTS = {
    'halves': (600, 597),
    'thirds': (400, 400, 397),
    'uneven': (504, 8, 496, 189),
    'eights': (8,) * 149 + (5,),
}
TCP_CUTS = {
    'halves': (1500, 1500),
    'thirds': (1000, 1000, 1000),
    'uneven': (1, 999, 1460, 540),
    'small': (30,) * 100,
}
#: Orders the pieces are sent in, as functions of the piece count.
ORDERS = {
    'forward': lambda n: list(range(n)),
    'reverse': lambda n: list(reversed(range(n))),
    'last-first': lambda n: [n - 1] + list(range(n - 1)),
    'interleave': lambda n: list(range(0, n, 2)) + list(range(1, n, 2)),
    'duplicate': lambda n: [i for i in range(n) for _ in (0, 1)],
}

#: The IP payload: a UDP datagram of 1197 octets, so the last piece is short.
IP_PAYLOAD = udp(payload_pattern(1189))
#: The second IP payload, for two datagrams in flight at once.
IP_PAYLOAD_2 = udp(payload_pattern(709, seed=3), sport=40001)
#: The TCP byte stream.
TCP_STREAM = payload_pattern(3000, seed=5)


def _octets(payload: 'bytes | tuple[bytes, ...]') -> 'int':
    """Octets in a payload, summing the runs of a strict ``PARTIAL`` one."""
    return len(payload) if isinstance(payload, bytes) else sum(len(run) for run in payload)


def _pieces(total: 'int', cuts: 'tuple[int, ...]') -> 'list[tuple[int, int]]':
    assert sum(cuts) == total, (sum(cuts), total)
    out, offset = [], 0
    for size in cuts:
        out.append((offset, size))
        offset += size
    return out


def _ip_frame(kind: 'str', payload: 'bytes', offset: 'int', size: 'int', ident: 'int') -> 'bytes':
    more = offset + size < len(payload)
    chunk = payload[offset:offset + size]
    if kind == 'ipv4':
        return ethernet(ipv4(chunk, ident=ident, offset=offset, mf=more), 0x0800)
    return ethernet(ipv6_fragment(chunk, ident=ident, offset=offset, mf=more), 0x86DD)


def _ip_header(kind: 'str', payload: 'bytes', size: 'int', ident: 'int') -> 'bytes | None':
    """The header the offset-0 fragment carried, for IPv4."""
    if kind != 'ipv4':
        return None
    return ipv4(payload[:size], ident=ident, offset=0, mf=size < len(payload))[:20]


def _ip_cases() -> 'list[Case]':
    cases = []
    for kind in ('ipv4', 'ipv6'):
        for cut, sizes in IP_CUTS.items():
            pieces = _pieces(len(IP_PAYLOAD), sizes)
            header = _ip_header(kind, IP_PAYLOAD, sizes[0], 0x1234)
            for order, permute in ORDERS.items():
                frames = tuple(_ip_frame(kind, IP_PAYLOAD, *pieces[i], 0x1234)
                               for i in permute(len(pieces)))
                for strict in (True, False):
                    if order == 'duplicate':
                        # the last frame repeats the last fragment after completion (#1507)
                        offset, size = pieces[-1]
                        late = IP_PAYLOAD[offset:offset + size]
                        streams = (
                            Stream(IP_PAYLOAD, tuple(range(1, len(frames))), header),
                            Stream((late,) if strict else bytes(offset) + late, (len(frames),),
                                   b'' if kind == 'ipv4' else None, 'PARTIAL'),
                        )
                    else:
                        streams = (Stream(IP_PAYLOAD, tuple(range(1, len(frames) + 1)), header),)
                    cases.append(Case(f'{kind}/{cut}/{order}/{"strict" if strict else "loose"}',
                                      kind, frames, streams, strict))
            # one extra piece straddling a boundary, with the same octets
            frames = [_ip_frame(kind, IP_PAYLOAD, *piece, 0x1234) for piece in pieces]
            end = next(offset + size for offset, size in pieces if offset + size >= 24) - 8
            frames.insert(1, _ip_frame(kind, IP_PAYLOAD, 8, (end - 8) - (end - 8) % 8, 0x1234))
            stream = Stream(IP_PAYLOAD, tuple(range(1, len(frames) + 1)), header)
            for strict in (True, False):
                cases.append(Case(f'{kind}/{cut}/overlap/{"strict" if strict else "loose"}',
                                  kind, tuple(frames), (stream,), strict))

        # unfragmented: one packet, offset 0 and MF clear
        if kind == 'ipv4':
            frame = ethernet(ipv4(IP_PAYLOAD, ident=0x0101), 0x0800)
        else:
            frame = ethernet(ipv6_fragment(IP_PAYLOAD, ident=0x0101), 0x86DD)
        header = _ip_header(kind, IP_PAYLOAD, len(IP_PAYLOAD), 0x0101)
        for strict in (True, False):
            cases.append(Case(f'{kind}/atomic/{"strict" if strict else "loose"}', kind, (frame,),
                              (Stream(IP_PAYLOAD, (1,), header),), strict))

        # two datagrams in flight, their fragments interleaved
        first = [_ip_frame(kind, IP_PAYLOAD, *piece, 0x2001)
                 for piece in _pieces(len(IP_PAYLOAD), IP_CUTS['thirds'])]
        second = [_ip_frame(kind, IP_PAYLOAD_2, *piece, 0x2002)
                  for piece in _pieces(len(IP_PAYLOAD_2), (352, 365))]
        frames = (first[0], second[1], first[2], second[0], first[1])
        streams = (Stream(IP_PAYLOAD, (1, 3, 5), _ip_header(kind, IP_PAYLOAD, 400, 0x2001)),
                   Stream(IP_PAYLOAD_2, (2, 4), _ip_header(kind, IP_PAYLOAD_2, 352, 0x2002)))
        for strict in (True, False):
            cases.append(Case(f'{kind}/two-datagrams/{"strict" if strict else "loose"}', kind,
                              frames, streams, strict))
    return cases


def _tcp_cases() -> 'list[Case]':
    cases = []
    for isn_name, isn in (('isn-low', 1000), ('isn-wrap', (1 << 32) - 1700)):
        syn = ethernet(ipv4(tcp(b'', seq=isn, syn=True), proto=6), 0x0800)
        for cut, sizes in TCP_CUTS.items():
            pieces = _pieces(len(TCP_STREAM), sizes)

            def segment(offset: 'int', size: 'int') -> 'bytes':
                return ethernet(ipv4(tcp(TCP_STREAM[offset:offset + size],
                                         seq=isn + 1 + offset, ack=1), proto=6), 0x0800)

            fin = ethernet(ipv4(tcp(b'', seq=isn + 1 + len(TCP_STREAM), ack=1, fin=True),
                                proto=6), 0x0800)
            for order, permute in ORDERS.items():
                data = [segment(*pieces[i]) for i in permute(len(pieces))]
                frames = (syn, *data, fin)
                stream = Stream(TCP_STREAM, tuple(range(2, len(frames) + 1)))
                for strict in (True, False):
                    cases.append(Case(f'tcp/{isn_name}/{cut}/{order}/{"strict" if strict else "loose"}',
                                      'tcp', frames, (stream,), strict))
            # the FIN reordered ahead of the data
            data = [segment(*piece) for piece in reversed(pieces)]
            frames = (syn, fin, *data)
            stream = Stream(TCP_STREAM, tuple(range(2, len(frames) + 1)))
            for strict in (True, False):
                cases.append(Case(f'tcp/{isn_name}/{cut}/fin-first/{"strict" if strict else "loose"}',
                                  'tcp', frames, (stream,), strict))
            # one extra segment overlapping the first two with the same octets
            data = [segment(*piece) for piece in pieces]
            data.insert(1, segment(1, pieces[0][1] + pieces[1][1] - 2))
            frames = (syn, *data, fin)
            stream = Stream(TCP_STREAM, tuple(range(2, len(frames) + 1)))
            for strict in (True, False):
                cases.append(Case(f'tcp/{isn_name}/{cut}/overlap/{"strict" if strict else "loose"}',
                                  'tcp', frames, (stream,), strict))
    return cases


CASES = {case.label: case for case in _ip_cases() + _tcp_cases()}


def run_case(case: 'Case') -> 'Outcome':
    """Reassemble ``case`` and compare each datagram with the payload it came from."""
    from pcapkit import extract

    # a millisecond apart, so no case outlasts a reassembly timeout
    data = pcap([(1_500_000_000, 1000 * i, frame) for i, frame in enumerate(case.frames)])
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        try:
            extractor = extract(fin=io.BytesIO(data), nofile=True, store=False, reassembly=True,
                                reasm_strict=case.strict, **{case.kind: True})
        except Exception as exc:  # pylint: disable=broad-except
            return Outcome('ERROR', f'{type(exc).__name__}: {exc}')
        close_extractor(extractor)
    datagrams = list(getattr(extractor.reassembly, case.kind))
    if len(datagrams) != len(case.streams):
        return Outcome('COUNT', f'{len(datagrams)} datagrams != {len(case.streams)}: '
                                + ', '.join(f'{d.completed.name} {d.index}' for d in datagrams))
    by_payload = {}  # type: dict[Any, Any]
    for datagram in datagrams:
        payload = datagram.payload
        key = bytes(payload) if isinstance(payload, (bytes, bytearray)) else tuple(payload)
        by_payload[key] = datagram
    for number, stream in enumerate(case.streams):
        datagram = by_payload.get(stream.payload)
        if datagram is None:
            sizes = [(d.completed.name, len(d.payload) if isinstance(d.payload, (bytes, bytearray))
                      else tuple(len(run) for run in d.payload)) for d in datagrams]
            return Outcome('PAYLOAD', f'stream {number}: no datagram carries the '
                                      f'{_octets(stream.payload)}-octet payload; got {sizes}')
        if datagram.completed.name != stream.completed:
            return Outcome('INCOMPLETE', f'stream {number}: {datagram.completed.name} != '
                                         f'{stream.completed}')
        if set(datagram.index) != set(stream.frames):
            return Outcome('INDEX', f'stream {number}: index {datagram.index} != frames {stream.frames}')
        if stream.header is not None and bytes(datagram.header) != stream.header:
            return Outcome('HEADER', f'stream {number}: header {bytes(datagram.header).hex()} != '
                                     f'{stream.header.hex()}')
    return Outcome('OK')


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestReassemblyPayloadRoundTrip(harness.RoundTripBase):
    """Every cut, order and mode recovers the payload exactly."""

    STATUSES = ('ERROR', 'COUNT', 'PAYLOAD', 'INCOMPLETE', 'INDEX', 'HEADER')
    KNOWN_FAILURES = ()  # type: tuple[Gap, ...]

    def setUp(self) -> None:
        super().setUp()
        reimport_once_per_class(self)

    def labels(self) -> 'list[str]':
        return list(CASES)

    def outcome(self, label: 'str') -> 'Outcome':
        return run_case(CASES[label])

    def test_builders_carry_the_payload(self) -> None:
        """The wire builders put the payload where the reassembler looks for it."""
        from pcapkit.protocols.link.ethernet import Ethernet

        frame = ethernet(ipv6(udp(b'abc'), nxt=17), 0x86DD)
        self.assertEqual(len(frame), 14 + 40 + 11)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = Ethernet(frame, len(frame))
        self.assertEqual(parsed.info.type.value, 0x86DD)
        self.assertEqual(bytes(parsed['IPv6'].info.src.packed), bytes.fromhex(
            '20010db8000000000000000000000001'))
        # every case's frames carry the whole payload at least once
        for case in CASES.values():
            with self.subTest(case=case.label):
                self.assertGreaterEqual(sum(len(f) for f in case.frames),
                                        sum(_octets(s.payload) for s in case.streams))


if __name__ == '__main__':
    unittest.main()
