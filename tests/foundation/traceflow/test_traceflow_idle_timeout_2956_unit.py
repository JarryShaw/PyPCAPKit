# -*- coding: utf-8 -*-
"""A flow idle for a tracer's ``timeout``, on the capture's clock, is finalised (#2956).

A UDP flow or an IP conversation has no connection to end, so it ended only at
``finish()``. A tracer now takes ``timeout``, in seconds on the capture's clock, as
IPFIX's idle timeout ends a flow (flowEndReason ``0x01``, Information Element 136):
:meth:`TraceFlow.advance` finalises every flow whose latest packet is older than that,
each packet advances it, and so does every frame an engine reads. ``None``, the default,
keeps every flow until the end of the capture. The moved helpers (``make_bufid``,
``_unique_label``, ``_output_path``, ``_finalise``) are pinned here to the base.

"""
from __future__ import annotations

import decimal
import fractions
import importlib.util
import io
import os
import struct
import tempfile
import types
import unittest
import warnings
from ipaddress import ip_address
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

ETH_IPV4 = b'\x00\x11\x22\x33\x44\x55' b'\x66\x77\x88\x99\xaa\xbb' b'\x08\x00'
ETH_ARP = b'\xff\xff\xff\xff\xff\xff' b'\x66\x77\x88\x99\xaa\xbb' b'\x08\x06'
SRC, DST = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])


def ipv4_udp(srcport: int, dstport: int, payload: bytes = b'') -> bytes:
    """An Ethernet frame of an IPv4 datagram carrying one UDP datagram, checksum zero."""
    udp = struct.pack('!HHHH', srcport, dstport, 8 + len(payload), 0) + payload
    header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0x4000, 64, 17, 0, SRC, DST))
    total = sum(struct.unpack('!10H', bytes(header)))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    header[10:12] = struct.pack('!H', ~total & 0xFFFF)
    return ETH_IPV4 + bytes(header) + udp


def arp() -> bytes:
    """An Ethernet frame of an ARP request, which no flow tracer reads."""
    return ETH_ARP + struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, b'\x66\x77\x88\x99\xaa\xbb',
                                 SRC, bytes(6), DST)


def pcap(frames: 'list[tuple[float, bytes]]') -> bytes:
    """A microsecond little-endian PCAP savefile of Ethernet ``frames``."""
    octets = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for (timestamp, data) in frames:
        usec = round(timestamp * 1_000_000)
        octets += struct.pack('<IIII', usec // 1_000_000, usec % 1_000_000, len(data), len(data)) + data
    return octets


class TimeoutCase(unittest.TestCase):
    """A fresh import per class, and an output root per test."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name

    def udp(self, index: int, timestamp: float, *, srcport: int = 40000) -> 'Any':
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.traceflow.udp.data import Packet

        return Packet(LinkType.ETHERNET, index, {'frame': index}, ip_address('192.0.2.1'),
                      ip_address('192.0.2.2'), srcport, 53, timestamp, b'')

    def tcp(self, index: int, timestamp: float, **flags: bool) -> 'Any':
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.traceflow.tcp.data import Packet

        return Packet(LinkType.ETHERNET, index, {'frame': index}, flags.get('syn', False),
                      flags.get('fin', False), False, ip_address('192.0.2.1'), ip_address('192.0.2.2'),
                      40000, 80, timestamp, 0, 0, b'', bytearray())

    def ip(self, index: int, timestamp: float) -> 'Any':
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.traceflow.ip.data import Packet

        return Packet(LinkType.ETHERNET, index, {'frame': index}, ip_address('192.0.2.1'),
                      ip_address('192.0.2.2'), timestamp)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IdleTimeoutTests(TimeoutCase):
    """Each built-in tracer finalises a flow once idle for longer than ``timeout``."""

    def test_issue_reproduction(self) -> None:
        """#2956: a UDP flow silent for longer than the timeout ends, and its endpoints open a new one."""
        from pcapkit.foundation.traceflow.udp.traceflow import UDP

        finalised = []  # type: list[Any]
        UDP.register_callback(finalised.append)
        self.addCleanup(UDP.__callback_fn__.remove, finalised.append)

        trace = UDP(fout=self.root, format='json', timeout=30)
        self.assertEqual(trace.timeout, 30.0)
        for (index, timestamp) in ((1, 0.0), (2, 20.0), (3, 50.0)):
            trace(self.udp(index, timestamp))
        # 30 seconds apart is not more than the timeout
        self.assertEqual(finalised, [])
        trace(self.udp(4, 80.5))
        self.assertEqual([flow.index for flow in finalised], [(1, 2, 3)])
        self.assertEqual([flow.index for flow in trace.index], [(4,), (1, 2, 3)])
        # the new flow has a file of its own, as the same endpoints at another time
        self.assertEqual(trace.index[0].label, '192.0.2.1_40000-192.0.2.2_53-80.5')

        trace.finish()
        self.assertEqual([flow.index for flow in finalised], [(1, 2, 3), (4,)])

    def test_a_packet_of_another_flow_times_one_out(self) -> None:
        from pcapkit.foundation.traceflow.udp.traceflow import UDP

        trace = UDP(fout=self.root, format='json', timeout=1)
        trace(self.udp(1, 0.0))
        trace(self.udp(2, 0.5, srcport=40001))
        trace(self.udp(3, 1.25, srcport=40001))
        # the first flow ended at the third packet, which belongs to the second
        self.assertEqual([flow.index for flow in trace.index], [(2, 3), (1,)])

    def test_tcp_and_ip_time_out_as_well(self) -> None:
        from pcapkit.foundation.traceflow.ip.traceflow import IP
        from pcapkit.foundation.traceflow.tcp.traceflow import TCP

        for (klass, make) in ((TCP, self.tcp), (IP, self.ip)):
            with self.subTest(tracer=klass.__name__):
                trace = klass(fout=self.root, format='json', timeout=5)
                trace(make(1, 0.0))
                trace(make(2, 4.0))
                trace(make(3, 9.5))
                self.assertEqual([flow.index for flow in trace.index], [(3,), (1, 2)])

    def test_no_timeout_keeps_every_flow(self) -> None:
        from pcapkit.foundation.traceflow.udp.traceflow import UDP

        trace = UDP(fout=self.root, format='json')
        self.assertEqual(trace.timeout, float('inf'))
        trace(self.udp(1, 0.0))
        trace(self.udp(2, 1e9))
        trace.advance(1e12)
        self.assertEqual([flow.index for flow in trace.index], [(1, 2)])
        # no timestamp is noted when nothing can time out
        self.assertEqual(trace._seen, {})

    def test_a_zero_timeout_ends_a_flow_at_its_next_later_packet(self) -> None:
        from pcapkit.foundation.traceflow.udp.traceflow import UDP

        trace = UDP(fout=self.root, format='json', timeout=0)
        trace(self.udp(1, 1.0))
        trace(self.udp(2, 1.0))
        trace(self.udp(3, 1.5))
        self.assertEqual([flow.index for flow in trace.index], [(3,), (1, 2)])

    def test_a_timestamp_that_steps_back_does_not_age_a_flow(self) -> None:
        from pcapkit.foundation.traceflow.udp.traceflow import UDP

        trace = UDP(fout=self.root, format='json', timeout=10)
        trace(self.udp(1, 100.0))
        trace(self.udp(2, 50.0))
        trace.advance(105.0)
        self.assertEqual([flow.index for flow in trace.index], [(1, 2)])
        self.assertEqual(list(trace._seen.values()), [100.0])

    def test_advance_alone_times_out_and_runs_the_callbacks(self) -> None:
        from pcapkit.foundation.traceflow.ip.traceflow import IP

        finalised = []  # type: list[Any]
        IP.register_callback(finalised.append)
        self.addCleanup(IP.__callback_fn__.remove, finalised.append)

        trace = IP(fout=self.root, format='json', timeout=2)
        trace(self.ip(1, 10.0))
        trace.advance(12.0)
        self.assertEqual(finalised, [])
        trace.advance(12.25)
        self.assertEqual([flow.index for flow in finalised], [(1,)])
        self.assertEqual(trace._seen, {})
        self.assertFalse(trace._buffer)

    def test_a_bad_timeout_is_refused_before_the_root_is_made(self) -> None:
        from pcapkit.foundation.traceflow.udp.traceflow import UDP
        from pcapkit.utilities.exceptions import FieldValueError

        fout = os.path.join(self.root, 'made')
        # NaN never expires anything, and a bool or a str is no number of seconds
        for timeout in (-1, -0.5, float('nan'), decimal.Decimal('NaN'), decimal.Decimal('sNaN'),
                        decimal.Decimal('-1'), True, False, '5', b'5', [5], 1j):
            with self.subTest(timeout=timeout), self.assertRaises(FieldValueError) as caught:
                UDP(fout=fout, format='json', timeout=timeout)
            self.assertEqual(str(caught.exception), 'UDP: flow tracing timeout must be a non-negative '
                                                    f'number of seconds, got {timeout!r}')
            self.assertFalse(os.path.exists(fout))

    def test_every_real_number_of_seconds_is_taken(self) -> None:
        from pcapkit.foundation.traceflow.udp.traceflow import UDP

        for (timeout, seconds) in ((0, 0.0), (30, 30.0), (2.5, 2.5), (decimal.Decimal('0.3'), 0.3),
                                   (fractions.Fraction(1, 2), 0.5), (float('inf'), float('inf'))):
            with self.subTest(timeout=timeout):
                self.assertEqual(UDP(fout=self.root, format='json', timeout=timeout).timeout, seconds)

    def test_exactly_the_timeout_apart_is_not_idle(self) -> None:
        # 0.4 - 0.1 exceeds 0.3 as floats; the capture recorded 0.3 apart, which is not more
        from pcapkit.foundation.traceflow.udp.traceflow import UDP

        for (first, second, timeout) in ((0.1, 0.4, 0.3), (1700000000.1, 1700000000.4, 0.3),
                                         (1700000000.000001, 1700000000.123457, 0.123456),
                                         (0.1, 0.4, decimal.Decimal('0.3'))):
            with self.subTest(first=first, second=second, timeout=timeout):
                self.assertGreater(second - first, float(timeout))
                trace = UDP(fout=self.root, format='json', timeout=timeout)
                trace(self.udp(1, first))
                trace(self.udp(2, second))
                self.assertEqual([flow.index for flow in trace.index], [(1, 2)])
                # a microsecond more is
                trace(self.udp(3, second + float(timeout) + 1e-6))
                self.assertEqual([flow.index for flow in trace.index], [(3,), (1, 2)])

    def test_a_custom_tracer_noting_no_time_times_nothing_out(self) -> None:
        from pcapkit.foundation.traceflow.traceflow import TraceFlow

        class Plain(TraceFlow[str, object, object, object]):
            def dump(self, packet: 'Any') -> None:
                self._buffer['flow'] = packet

            def trace(self, packet: 'Any', *, output: bool = False) -> 'Any':
                return 'flow'

            def submit(self) -> 'tuple[Any, ...]':
                return ()

        trace = Plain(fout=self.root, format='json', timeout=0)
        trace(object())
        trace.advance(1e9)
        self.assertIn('flow', trace._buffer)
        with self.assertRaises(NotImplementedError):
            trace._make_index(object())


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class MovedHelperTests(TimeoutCase):
    """TCP's ``make_bufid``, ``_unique_label``, ``_output_path`` and ``_finalise`` are the base's."""

    def test_defined_on_the_base_alone(self) -> None:
        from pcapkit.foundation.traceflow.ip.traceflow import IP
        from pcapkit.foundation.traceflow.tcp.traceflow import TCP
        from pcapkit.foundation.traceflow.traceflow import TraceFlowBase
        from pcapkit.foundation.traceflow.udp.traceflow import UDP

        for name in ('make_bufid', '_unique_label', '_output_path', '_finalise'):
            with self.subTest(name=name):
                self.assertIn(name, vars(TraceFlowBase))
                for klass in (TCP, UDP, IP):
                    self.assertNotIn(name, vars(klass))

    def test_tcp_keys_and_labels_as_before(self) -> None:
        from pcapkit.foundation.traceflow.tcp.traceflow import TCP

        trace = TCP(fout=self.root, format='json')
        packet = self.tcp(1, 1.5, syn=True)
        self.assertEqual(trace.make_bufid(packet), (ip_address('192.0.2.1'), 40000, ip_address('192.0.2.2'), 80))
        self.assertEqual(trace.trace(packet), '192.0.2.1_40000-192.0.2.2_80-1.5')

    def test_finalise_logs_to_the_tracers_own_module(self) -> None:
        from pcapkit.foundation.traceflow.udp.traceflow import UDP

        trace = UDP(fout=self.root, format='json')
        trace(self.udp(1, 0.0))
        with self.assertLogs('pcapkit.foundation.traceflow.udp.traceflow', 'DEBUG') as logs:
            trace.finish()
        self.assertTrue(any('UDP flow 192.0.2.1_40000-192.0.2.2_53-0.0 finalised after 1 frame(s)' in line
                            for line in logs.output), logs.output)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ExtractionClockTests(TimeoutCase):
    """The ``Extractor`` passes ``timeout`` on, and every frame advances each tracer's clock."""

    def extract(self, frames: 'list[tuple[float, bytes]]', **options: 'Any') -> 'Any':
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.options import TraceFlowOptions

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            return Extractor(io.BytesIO(pcap(frames)), store=False,
                             traceflow=TraceFlowOptions(protocols=['udp', 'ip'], fout=self.root,
                                                        format='json', **options))

    def test_a_frame_no_tracer_reads_still_times_a_flow_out(self) -> None:
        from pcapkit.foundation.traceflow.udp.traceflow import UDP

        finalised = []  # type: list[Any]
        UDP.register_callback(lambda index: finalised.append((index.index, len(seen))))
        self.addCleanup(UDP.__callback_fn__.pop)

        seen = []  # type: list[float]
        advance = UDP.advance

        def spy(self: 'Any', timestamp: float) -> None:
            seen.append(timestamp)
            advance(self, timestamp)

        frames = [(0.0, ipv4_udp(40000, 53)), (1.0, ipv4_udp(40000, 53)), (40.0, arp())]
        with mock.patch.object(UDP, 'advance', spy):
            extractor = self.extract(frames, timeout=30)
        # finalised on the ARP frame, the capture's third, before the end of the capture
        self.assertEqual(finalised, [((1, 2), 5)])
        self.assertEqual([flow.index for flow in extractor.traceflow.udp], [(1, 2)])
        self.assertEqual([flow.index for flow in extractor.traceflow.ip], [(1, 2)])
        self.assertEqual(extractor._trace['udp'].timeout, 30.0)

    def test_the_same_capture_without_a_timeout(self) -> None:
        frames = [(0.0, ipv4_udp(40000, 53)), (100.0, ipv4_udp(40000, 53)), (200.0, arp())]
        self.assertEqual([flow.index for flow in self.extract(frames).traceflow.udp], [(1, 2)])
        self.assertEqual([flow.index for flow in self.extract(frames, timeout=99).traceflow.udp],
                         [(1,), (2,)])

    def test_the_engine_advances_before_it_feeds(self) -> None:
        from pcapkit.foundation.engines.engine import Engine

        order = []  # type: list[str]
        tracer = mock.Mock(side_effect=lambda record: order.append(f'feed {record}'))
        tracer.advance.side_effect = lambda timestamp: order.append(f'advance {timestamp}')

        class Bare(Engine):
            __traceflow__ = {'udp': lambda frame: None if frame == 'skip' else frame}

            def run(self) -> None:
                pass

            def read_frame(self) -> None:
                pass

        from pcapkit.foundation.traceflow import TraceFlowManager

        engine = Bare(types.SimpleNamespace(_trace=TraceFlowManager(udp=tracer)))
        engine._traceflow(1.5, 'frame')
        engine._traceflow(2.5, 'skip')
        self.assertEqual(order, ['advance 1.5', 'feed frame', 'advance 2.5'])

    def test_trace_takes_the_timeout(self) -> None:
        from pcapkit.interface.core import trace

        self.assertEqual(trace('udp', fout=self.root, format='json', timeout=12).timeout, 12.0)
        self.assertEqual(trace('ip', fout=self.root, format='json').timeout, float('inf'))

    def test_trace_finds_the_tracer_a_protocol_class_derives_from(self) -> None:
        # IPv4's first id names no tracer, so it gets the tracer of the IP it derives from
        from pcapkit.foundation.traceflow.ip.traceflow import IP
        from pcapkit.foundation.traceflow.tcp.traceflow import TCP
        from pcapkit.foundation.traceflow.udp.traceflow import UDP
        from pcapkit.interface.core import trace
        from pcapkit.protocols.internet.ip.protocol import IP as IP_Protocol
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.protocols.link.ethernet.protocol import Ethernet
        from pcapkit.protocols.transport.tcp.protocol import TCP as TCP_Protocol
        from pcapkit.protocols.transport.udp.protocol import UDP as UDP_Protocol
        from pcapkit.utilities.exceptions import FormatError

        for (protocol, kind) in ((IPv4, IP), (IPv6, IP), (IP_Protocol, IP), (TCP_Protocol, TCP),
                                 (UDP_Protocol, UDP)):
            with self.subTest(protocol=protocol.__name__):
                self.assertIs(type(trace(protocol, fout=self.root, format='json')), kind)
        with self.assertRaises(FormatError) as caught:
            trace(Ethernet, fout=self.root, format='json')
        self.assertEqual(str(caught.exception), "unsupported flow tracing protocol: 'Ethernet'")


if __name__ == '__main__':
    unittest.main()
