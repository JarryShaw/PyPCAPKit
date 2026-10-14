# -*- coding: utf-8 -*-
"""dpkt and pypcapfile hand over the default engine's capture timestamp. C.f. #1668.

The default engine hands reassembly and flow tracing ``float(time_epoch)``, the
double nearest the exact timestamp. dpkt on a microsecond PCAP, and pypcapfile
on any PCAP, handed over ``ts_sec + frac / divisor``, which rounds twice, so is
an ulp off at a small ``ts_sec``: ``1.0036909999999999`` for ``1.003691``. The
flow label, and the trace file named after it, differed with it.

The default engine computes the timestamp at 64 digits, whatever the caller's
decimal context. dpkt on a microsecond PCAP must too: at ``ts_sec=1500000000`` a
context of 12 digits gave ``1500000000.12``, and of 10 ``1500000000.0``.

Every capture is built here, at ``ts_sec=1`` or ``1500000000``, so the module is
in the unit tier. :func:`~pcapkit.toolkit.pypcapfile.packet2timestamp` is
checked on a stand-in packet, so needs no pypcapfile.

"""
from __future__ import annotations

import contextlib
import decimal
import importlib.util
import os
import random
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import close_extractor, reimport_once_per_class
from tests.foundation import _roundtrip as wire
from tests.toolkit import test_pypcapfile_unit as pypcapfile_unit

if TYPE_CHECKING:
    from typing import Any, Iterator, Optional

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))
HAS_DPKT = importlib.util.find_spec('dpkt') is not None

#: Microseconds past ``ts_sec=1`` of the timestamp #1668 measured.
FRAC_US = 3691
#: Fractions of the sweep, 415 microsecond and 415 nanosecond counts drawn with
#: a fixed seed. The misses cluster, so consecutive ones would hold few.
_RANDOM = random.Random(1668)
SWEEP_US = tuple(_RANDOM.randrange(10 ** 6) for _ in range(415))
SWEEP_NS = tuple(_RANDOM.randrange(10 ** 9) for _ in range(415))
#: Units per second of each resolution.
DIVISOR = {False: 10 ** 6, True: 10 ** 9}
#: ``ts_sec`` and microsecond fraction of the captures read at a low precision:
#: #1668's, and one 10 or 12 digits cannot hold.
LOW_PRECISION_STAMPS = ((1, FRAC_US), (1_500_000_000, 123456))
#: Decimal precisions of the caller's context those are read at.
LOW_PRECISIONS = (10, 12)


@contextlib.contextmanager
def precision(digits: 'Optional[int]') -> 'Iterator[None]':
    """Do decimal arithmetic at ``digits`` digits, or the context's own if :data:`None`.

    The previous context is restored on exit. ``decimal.localcontext(prec=...)``
    is Python 3.11 and later, so the precision is set on the copy instead.

    """
    with decimal.localcontext() as context:
        if digits is not None:
            context.prec = digits
        yield


def exact(seconds: int, fraction: int, nanosecond: bool) -> float:
    """The double nearest the timestamp, as the default engine computes it."""
    with precision(64):
        return float(decimal.Decimal(seconds) + decimal.Decimal(fraction) / DIVISOR[nanosecond])


def double_rounded(fractions: 'tuple[int, ...]', nanosecond: bool) -> int:
    """How many of ``fractions`` past ``ts_sec=1`` ``ts_sec + frac / divisor`` misses."""
    return sum(1 + fraction / DIVISOR[nanosecond] != exact(1, fraction, nanosecond) for fraction in fractions)


def records(fractions: 'tuple[int, ...]', seconds: int = 1) -> 'list[tuple[int, int, bytes]]':
    """Two frames at ``seconds`` and each of ``fractions``, each pair its own flow and datagrams.

    The first is Ethernet, IPv4 with DF clear, and a TCP SYN carrying data, so is
    an IPv4, a TCP and a trace input; the second Ethernet, IPv6 and a first
    Fragment of a UDP datagram, so an IPv6 input.

    """
    out = []  # type: list[tuple[int, int, bytes]]
    for index, fraction in enumerate(fractions):
        segment = wire.tcp(b'payload', seq=1, syn=True, sport=1024 + index)
        out.append((seconds, fraction, wire.ethernet(wire.ipv4(segment, ident=index, proto=6), 0x0800)))
        out.append((seconds, fraction, wire.ethernet(
            wire.ipv6_fragment(wire.udp(b'u' * 16), ident=index, mf=True), 0x86DD)))
    return out


#: Captures by name: the container, and whether it is nanosecond, and the fractions.
CAPTURES = {
    'pcap-us': ('pcap', False, (FRAC_US,)),
    'pcap-ns': ('pcap', True, (FRAC_US * 1000,)),
    'pcapng-us': ('pcapng', False, (FRAC_US,)),
    'pcapng-ns': ('pcapng', True, (FRAC_US * 1000,)),
    'sweep-pcap-us': ('pcap', False, SWEEP_US),
    'sweep-pcap-ns': ('pcap', True, SWEEP_NS),
    'sweep-pcapng-us': ('pcapng', False, SWEEP_US),
    'sweep-pcapng-ns': ('pcapng', True, SWEEP_NS),
}

#: Readings by engine and what :func:`read` builds and reads, kept across the tests.
_READINGS = {}  # type: dict[tuple[Any, ...], dict[str, Any]]


def read(test: unittest.TestCase, engine: str, container: str, nanosecond: bool,
         fractions: 'tuple[int, ...]', seconds: int = 1, digits: 'Optional[int]' = None) -> 'dict[str, Any]':
    """Read the capture of :func:`records` with ``engine``, with every reassembly and flow tracing on.

    Args:
        test: Test case, skipped if the engine does not run.
        engine: Engine to read with.
        container: ``pcap`` or ``pcapng``.
        nanosecond: Whether the capture is of nanosecond resolution.
        fractions: Fractions of the frames, as :func:`records` takes them.
        seconds: ``ts_sec`` of the frames.
        digits: Precision of the decimal context to extract in; see :func:`precision`.

    Returns:
        The capture timestamp of every input to IPv4, IPv6 and TCP reassembly and
        to flow tracing, by kind and keyed by frame number, and the names of the
        trace files, sorted.

    """
    key = (engine, container, nanosecond, fractions, seconds, digits)
    if key in _READINGS:
        return _READINGS[key]

    from pcapkit import extract
    from pcapkit.foundation.reassembly.reassembly import ReassemblyBase
    from pcapkit.foundation.traceflow.traceflow import TraceFlowBase

    build = wire.pcap if container == 'pcap' else wire.pcapng
    seen = {'ipv4': {}, 'ipv6': {}, 'tcp': {}, 'trace': {}}  # type: dict[str, Any]
    reassemble, trace = ReassemblyBase.__call__, TraceFlowBase.__call__

    def spy_reassembly(this: 'Any', packet: 'Any') -> 'Any':
        seen[type(this).__name__.lower()][packet.num] = packet.timestamp
        return reassemble(this, packet)

    def spy_trace(this: 'Any', packet: 'Any') -> 'Any':
        seen['trace'][packet.index] = packet.timestamp
        return trace(this, packet)

    with tempfile.TemporaryDirectory() as tmp, warnings.catch_warnings(), \
            mock.patch.object(ReassemblyBase, '__call__', spy_reassembly), \
            mock.patch.object(TraceFlowBase, '__call__', spy_trace):
        warnings.simplefilter('ignore')
        path = os.path.join(tmp, f'capture.{container}')
        with open(path, 'wb') as file:
            file.write(build(records(fractions, seconds), nanosecond=nanosecond))
        with precision(digits):
            extractor = extract(fin=path, nofile=True, engine=engine, reassembly=True, ipv4=True, ipv6=True,
                                tcp=True, trace=True, trace_fout=os.path.join(tmp, 'trace'),
                                trace_format='json')
        try:
            if extractor._exnam != engine:  # pylint: disable=protected-access
                test.skipTest(f'{engine} did not run')
            seen['names'] = sorted(os.path.basename(flow.fpout) for flow in extractor.trace.tcp)
        finally:
            close_extractor(extractor)
    _READINGS[key] = seen
    return seen


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
@unittest.skipUnless(HAS_DPKT, 'dpkt not installed')
class DPKTTimestampTests(unittest.TestCase):
    """dpkt hands over the double nearest each exact timestamp, on PCAP and PCAP-NG alike."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def check(self, container: str, nanosecond: bool, fractions: 'tuple[int, ...]', seconds: int = 1,
              digits: 'Optional[int]' = None) -> 'list[float]':
        """Assert every input, and every trace file name, carries the exact timestamp of its frame.

        The arguments are what :func:`read` takes after the engine.

        """
        want = sorted(exact(seconds, fraction, nanosecond) for fraction in fractions)
        seen = read(self, 'dpkt', container, nanosecond, fractions, seconds, digits)
        for kind in ('ipv4', 'ipv6', 'tcp', 'trace'):
            self.assertEqual(sorted(seen[kind].values()), want, kind)
        self.assertEqual(sorted(name.rsplit('-', 1)[1] for name in seen['names']),
                         sorted(f'{stamp}.json' for stamp in want))
        return want

    def test_ts_sec_1_hands_over_the_exact_timestamp(self) -> None:
        for name, capture in CAPTURES.items():
            if not name.startswith('sweep-'):
                with self.subTest(capture=name):
                    self.assertEqual(self.check(*capture), [1.003691])

    def test_sweep_hands_over_the_exact_timestamp(self) -> None:
        # the sweeps hold many a fraction ``ts_sec + frac / divisor`` misses
        self.assertGreater(double_rounded(SWEEP_US, False), 50)
        self.assertGreater(double_rounded(SWEEP_NS, True), 50)
        for name, capture in CAPTURES.items():
            if name.startswith('sweep-'):
                with self.subTest(capture=name):
                    self.check(*capture)

    def test_low_decimal_precision_hands_over_the_exact_timestamp(self) -> None:
        before = decimal.getcontext().prec
        for seconds, fraction in LOW_PRECISION_STAMPS:
            for digits in LOW_PRECISIONS:
                with self.subTest(ts_sec=seconds, prec=digits):
                    self.check('pcap', False, (fraction,), seconds, digits)
        self.assertEqual(decimal.getcontext().prec, before)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
@unittest.skipUnless(HAS_DPKT, 'dpkt not installed')
class DPKTAdapterTimestampTests(unittest.TestCase):
    """The dpkt adapters hand over the exact value of a timestamp that carries one."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_adapters_hand_over_the_exact_value(self) -> None:
        import dpkt

        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.dpkt import (DecimalTimestamp, Timestamp, attach_buffer,
                                          ipv4_reassembly, ipv6_reassembly, tcp_reassembly,
                                          tcp_traceflow)

        def frame(octets: bytes) -> 'Any':
            packet = dpkt.ethernet.Ethernet(octets)
            attach_buffer(packet, octets)
            return packet

        built = records((FRAC_US,))
        tcp4, frag6 = frame(built[0][2]), frame(built[1][2])
        adapters = {
            'ipv4': lambda stamp: ipv4_reassembly(tcp4, stamp, count=1),
            'ipv6': lambda stamp: ipv6_reassembly(frag6, stamp, count=2),
            'tcp': lambda stamp: tcp_reassembly(tcp4, stamp, count=1),
            'trace': lambda stamp: tcp_traceflow(tcp4, stamp, data_link=LinkType.ETHERNET, count=1),
        }
        value = 1 + FRAC_US / 10 ** 6  # as dpkt reads a microsecond PCAP
        self.assertNotEqual(value, 1.003691)
        stamps = {
            # what the engine's readers yield: one carries the exact value
            'Timestamp': (Timestamp(value, decimal.Decimal('1.003691'), 10 ** 6, len(built[0][2])), 1.003691),
            'DecimalTimestamp': (DecimalTimestamp(decimal.Decimal('1.003691000'), 10 ** 9), 1.003691),
            # what a dpkt whose reader the engine cannot extend yields, or a
            # caller passes by hand, carries none, so is handed on as it is
            'float': (value, value),
            'Decimal': (decimal.Decimal('1.003691'), 1.003691),
        }
        for kind, adapter in adapters.items():
            for label, (stamp, expected) in stamps.items():
                with self.subTest(adapter=kind, timestamp=label):
                    data = adapter(stamp)
                    self.assertIs(type(data.timestamp), float)
                    self.assertEqual(data.timestamp, expected)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PyPCAPFilePacket2TimestampTests(unittest.TestCase):
    """:func:`~pcapkit.toolkit.pypcapfile.packet2timestamp` rounds once, on a stand-in packet."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_packet2timestamp_is_the_double_nearest_the_timestamp(self) -> None:
        from pcapkit.toolkit.pypcapfile import packet2timestamp

        for nanosecond, fractions in ((False, SWEEP_US), (True, SWEEP_NS)):
            for seconds in (0, 1, 2, 1000, 4095, 86400, 1_500_000_000, 2 ** 32 - 1):
                with self.subTest(nanosecond=nanosecond, seconds=seconds):
                    got = [packet2timestamp(pypcapfile_unit.make_packet(
                        b'raw', timestamp=seconds, timestamp_us=fraction, ns_resolution=nanosecond))
                        for fraction in fractions]
                    self.assertEqual(got, [exact(seconds, fraction, nanosecond) for fraction in fractions])

    def test_packet2timestamp_ignores_the_decimal_context(self) -> None:
        from pcapkit.toolkit.pypcapfile import packet2timestamp

        for nanosecond in (False, True):
            for seconds, fraction in LOW_PRECISION_STAMPS:
                fraction *= DIVISOR[nanosecond] // DIVISOR[False]
                packet = pypcapfile_unit.make_packet(b'raw', timestamp=seconds, timestamp_us=fraction,
                                                     ns_resolution=nanosecond)
                for digits in LOW_PRECISIONS:
                    with self.subTest(nanosecond=nanosecond, ts_sec=seconds, prec=digits), precision(digits):
                        self.assertEqual(packet2timestamp(packet), exact(seconds, fraction, nanosecond))


if __name__ == '__main__':
    unittest.main()
