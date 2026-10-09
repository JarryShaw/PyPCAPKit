# -*- coding: utf-8 -*-
"""Flow tracing writes each flow to a file that reads back as exactly its frames. C.f. #1202.

Each case builds a capture of TCP conversations as an in-memory savefile,
traces it through :func:`~pcapkit.interface.extract` with
``trace_format='pcap'``, and reads every flow's output file back twice: with
:mod:`struct` alone, as an independent reference, and with :mod:`pcapkit`. The
round trip closes when

* each output file's global header carries the byte order, timestamp
  resolution and link type asked for;
* its records are, in order, the input records the flow's ``index`` names --
  the same seconds, fraction, captured and original length, and octets;
* :mod:`pcapkit` reads it back as that many frames; and
* every TCP frame of the input lands in exactly one flow, and no other frame
  lands in any.

The conversations cover the shapes :mod:`pcapkit.foundation.traceflow.tcp`
distinguishes: a whole connection, two interleaved, one mixed with UDP, one over
IPv6, a port pair reused after a close, a reset, one left half-open, and the
per-direction ``trace_bidirectional=False`` mode. Each runs in every byte order
and resolution the PCAP writer offers.

Every case builds its own octets and reads no capture. Classes are imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

from __future__ import annotations

import importlib.util
import io
import os
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING, NamedTuple

from tests._support import close_extractor, reimport_once_per_class
from tests.foundation import _roundtrip as harness
from tests.foundation._roundtrip import (Gap, Outcome, ethernet, ipv4,
                                         ipv6, pcap, pcapng, read_pcap, tcp, udp)

if TYPE_CHECKING:
    from typing import Callable

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))


def _segment(payload: 'bytes', *, reply: 'bool', v6: 'bool', port: 'int', **flags: 'int | bool') -> 'bytes':
    """One TCP segment between the two built hosts, from the client unless ``reply``."""
    sport, dport = (9, port) if reply else (port, 9)
    seg = tcp(payload, sport=sport, dport=dport, **flags)  # type: ignore[arg-type]
    if v6:
        return ethernet(ipv6(seg, nxt=6, reverse=reply), 0x86DD, reverse=reply)
    return ethernet(ipv4(seg, proto=6, reverse=reply), 0x0800, reverse=reply)


def connection(port: 'int' = 40000, *, v6: 'bool' = False, close: 'str' = 'fin',
               isn: 'int' = 1000) -> 'list[bytes]':
    """A client-server exchange: handshake, a request, a response, and a close.

    ``close`` is ``'fin'`` for the four-way close, ``'rst'`` for a reset, or
    ``'none'`` to leave the connection open.

    """
    srv = isn + 50000
    req, rsp = b'GET / HTTP/1.0\r\n\r\n', b'HTTP/1.0 200 OK\r\n\r\nhello'
    out = [
        _segment(b'', reply=False, v6=v6, port=port, seq=isn, syn=True),
        _segment(b'', reply=True, v6=v6, port=port, seq=srv, ack=isn + 1, syn=True),
        _segment(req, reply=False, v6=v6, port=port, seq=isn + 1, ack=srv + 1),
        _segment(rsp, reply=True, v6=v6, port=port, seq=srv + 1, ack=isn + 1 + len(req)),
    ]
    cseq, sseq = isn + 1 + len(req), srv + 1 + len(rsp)
    if close == 'fin':
        out += [
            _segment(b'', reply=False, v6=v6, port=port, seq=cseq, ack=sseq, fin=True),
            _segment(b'', reply=True, v6=v6, port=port, seq=sseq, ack=cseq + 1, fin=True),
            _segment(b'', reply=False, v6=v6, port=port, seq=cseq + 1, ack=sseq + 1),
        ]
    elif close == 'rst':
        out.append(_segment(b'', reply=False, v6=v6, port=port, seq=cseq, ack=sseq, rst=True))
    return out


def _interleave(*streams: 'list[bytes]') -> 'list[bytes]':
    out = []  # type: list[bytes]
    for index in range(max(len(stream) for stream in streams)):
        out.extend(stream[index] for stream in streams if index < len(stream))
    return out


def _mixed() -> 'list[bytes]':
    frames = connection()
    noise = [ethernet(ipv4(udp(b'noise %d' % i)), 0x0800) for i in range(3)]
    return [frames[0], noise[0], *frames[1:4], noise[1], *frames[4:], noise[2]]


#: Scenario name -> (frames, bidirectional).
SCENARIOS = {
    'one-connection': (lambda: connection(), True),
    'two-interleaved': (lambda: _interleave(connection(40000), connection(40001, isn=7000)), True),
    'mixed-udp': (_mixed, True),
    'ipv6': (lambda: connection(v6=True), True),
    'reused-port': (lambda: connection() + connection(isn=90000), True),
    'reset': (lambda: connection(close='rst'), True),
    'half-open': (lambda: connection(close='none'), True),
    'unidirectional': (lambda: connection(), False),
}  # type: dict[str, tuple[Callable[[], list[bytes]], bool]]

#: Variant name -> (container, input byte order, input nanosecond, output byte
#: order, output nanosecond). A coarser output keeps the whole microseconds.
VARIANTS = {
    'pcap/little-usec': ('pcap', 'little', False, 'little', False),
    'pcap/big-usec': ('pcap', 'big', False, 'big', False),
    'pcap/little-nsec': ('pcap', 'little', True, 'little', True),
    'pcap/big-nsec': ('pcap', 'big', True, 'big', True),
    'pcap/big-to-little': ('pcap', 'big', False, 'little', False),
    'pcap/usec-to-nsec': ('pcap', 'little', False, 'little', True),
    'pcap/nsec-to-usec': ('pcap', 'little', True, 'little', False),
    'pcapng/usec': ('pcapng', 'little', False, 'little', False),
    'pcapng/nsec': ('pcapng', 'little', True, 'little', True),
    'pcapng/big-usec': ('pcapng', 'big', False, 'big', False),
    'pcapng/usec-to-nsec': ('pcapng', 'little', False, 'little', True),
    'pcapng/nsec-to-usec': ('pcapng', 'little', True, 'little', False),
}


class Case(NamedTuple):
    label: 'str'
    frames: 'tuple[bytes, ...]'
    bidirectional: 'bool'
    variant: 'tuple[str, str, bool, str, bool]'


def _rescale(fraction: 'int', in_nsec: 'bool', out_nsec: 'bool') -> 'int':
    """A timestamp fraction in the output's resolution."""
    if in_nsec == out_nsec:
        return fraction
    return fraction * 1000 if out_nsec else fraction // 1000


CASES = {f'{scenario}/{variant}': Case(f'{scenario}/{variant}', tuple(build()), bidirectional,
                                       VARIANTS[variant])
         for scenario, (build, bidirectional) in SCENARIOS.items() for variant in VARIANTS}


def _is_tcp(frame: 'bytes') -> 'bool':
    ethertype = int.from_bytes(frame[12:14], 'big')
    return (ethertype == 0x0800 and frame[14 + 9] == 6) or (ethertype == 0x86DD and frame[14 + 6] == 6)


def run_case(case: 'Case') -> 'Outcome':
    """Trace ``case`` to PCAP, then read every flow's file back."""
    from pcapkit import extract

    container, in_order, in_nsec, out_order, out_nsec = case.variant
    # the fraction is distinct per frame and, in nanoseconds, finer than a microsecond
    step = 1001 if in_nsec else 1
    records = [(1_500_000_000 + i, (i * 7919 * step) % (10 ** 9 if in_nsec else 10 ** 6), frame)
               for i, frame in enumerate(case.frames)]
    build = pcap if container == 'pcap' else pcapng
    data = build(records, nanosecond=in_nsec, byteorder=in_order)
    source = [(sec, _rescale(frac, in_nsec, out_nsec), len(frame), len(frame), frame)
              for sec, frac, frame in records]

    with warnings.catch_warnings(), tempfile.TemporaryDirectory() as tracedir:
        warnings.simplefilter('ignore')
        try:
            extractor = extract(fin=io.BytesIO(data), nofile=True, store=False, trace=True, tcp=True,
                                trace_fout=tracedir, trace_format='pcap',
                                trace_byteorder=out_order, trace_nanosecond=out_nsec,
                                trace_bidirectional=case.bidirectional)
        except Exception as exc:  # pylint: disable=broad-except
            return Outcome('ERROR', f'{type(exc).__name__}: {exc}')
        close_extractor(extractor)
        flows = list(extractor.trace.tcp)

        seen = []  # type: list[int]
        for flow in flows:
            seen.extend(flow.index)
            if not os.path.isfile(flow.fpout):
                return Outcome('FILE', f'{flow.label}: no file at {flow.fpout}')
            with open(flow.fpout, 'rb') as file:
                written = read_pcap(file.read())
            header = (written.byteorder, written.nanosecond, written.linktype)
            if header != (out_order, out_nsec, 1):
                return Outcome('HEADER', f'{flow.label}: header {header} != {(out_order, out_nsec, 1)}')
            want = tuple(source[number - 1] for number in flow.index)
            if len(written.records) != len(want):
                return Outcome('COUNT', f'{flow.label}: {len(written.records)} records != '
                                        f'{len(want)} indexed {flow.index}')
            for position, (got, expected) in enumerate(zip(written.records, want)):
                if got != expected:
                    fields = ('seconds', 'fraction', 'incl_len', 'orig_len', 'octets')
                    diff = '; '.join(f'{name} {g!r:.60} != {e!r:.60}' for name, g, e
                                     in zip(fields, got, expected) if g != e)
                    return Outcome('RECORD', f'{flow.label} record {position + 1} '
                                             f'(frame {flow.index[position]}): {diff}')
            try:
                reread = extract(fin=flow.fpout, nofile=True, store=False)
            except Exception as exc:  # pylint: disable=broad-except
                return Outcome('REREAD', f'{flow.label}: {type(exc).__name__}: {exc}')
            close_extractor(reread)
            if reread.length != len(want):
                return Outcome('REREAD', f'{flow.label}: pcapkit reads {reread.length} frames != {len(want)}')

    tcp_frames = [number for number, frame in enumerate(case.frames, 1) if _is_tcp(frame)]
    if sorted(seen) != tcp_frames:
        return Outcome('COVER', f'flows index {sorted(seen)} != TCP frames {tcp_frames}')
    return Outcome('OK')


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestTraceFlowRereadRoundTrip(harness.RoundTripBase):
    """Every scenario and variant reads back as exactly its flows' frames."""

    STATUSES = ('ERROR', 'FILE', 'HEADER', 'COUNT', 'RECORD', 'REREAD', 'COVER')
    KNOWN_FAILURES = ()  # type: tuple[Gap, ...]

    def setUp(self) -> None:
        super().setUp()
        reimport_once_per_class(self)

    def labels(self) -> 'list[str]':
        return list(CASES)

    def outcome(self, label: 'str') -> 'Outcome':
        return run_case(CASES[label])

    def test_reference_reader_reads_the_builder(self) -> None:
        """:func:`read_pcap` and :func:`pcap` agree, so the reference is sound."""
        frames = connection()
        for order in ('little', 'big'):
            for nsec in (False, True):
                with self.subTest(order=order, nsec=nsec):
                    records = [(1, 999_999_999 if nsec else 999_999, frame) for frame in frames]
                    saved = read_pcap(pcap(records, byteorder=order, nanosecond=nsec))
                    self.assertEqual((saved.byteorder, saved.nanosecond, saved.linktype), (order, nsec, 1))
                    self.assertEqual(saved.records, tuple((s, f, len(b), len(b), b) for s, f, b in records))


if __name__ == '__main__':
    unittest.main()
