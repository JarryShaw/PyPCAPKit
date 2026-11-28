# -*- coding: utf-8 -*-
"""UDP flows and IP conversations are traced as TCP flows are (#2956).

Flow tracing traced TCP alone. :class:`~pcapkit.foundation.traceflow.udp.traceflow.UDP`
keys a flow on its two ``(address, port)`` endpoints and
:class:`~pcapkit.foundation.traceflow.ip.traceflow.IP` on its two addresses, both
directions as one flow by default. Neither protocol has a connection to end, so a flow
ends at ``finish()``, or once idle for the tracer's ``timeout``, which
:file:`test_traceflow_idle_timeout_2956_unit.py` covers. The packets are built by hand,
so no capture is read.

"""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
import warnings
from ipaddress import ip_address
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: A DNS query for ``a.example``, type A, class IN (RFC 1035 s4.1).
DNS_QUERY = (b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
             b'\x01a\x07example\x00\x00\x01\x00\x01')


class TracerCase(unittest.TestCase):
    """A fresh import per class, and an output root per test."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name

    def udp(self, index: int, *, src: str = '192.0.2.1', dst: str = '198.51.100.2',
            srcport: int = 40000, dstport: int = 53, timestamp: float = 1.25,
            payload: bytes = b'') -> 'Any':
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.traceflow.udp.data import Packet

        return Packet(LinkType.ETHERNET, index, {'frame': index}, ip_address(src), ip_address(dst),
                      srcport, dstport, timestamp, payload)

    def ip(self, index: int, *, src: str = '192.0.2.1', dst: str = '198.51.100.2',
           timestamp: float = 1.25) -> 'Any':
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.traceflow.ip.data import Packet

        return Packet(LinkType.ETHERNET, index, {'frame': index}, ip_address(src), ip_address(dst), timestamp)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class UDPTraceFlowTests(TracerCase):
    """A UDP flow is its two endpoints' datagrams, ended only by ``finish()`` here."""

    def tracer(self, **kwargs: 'Any') -> 'Any':
        from pcapkit.foundation.traceflow.udp.traceflow import UDP

        return UDP(fout=self.root, format='json', **kwargs)

    def test_both_directions_are_one_flow(self) -> None:
        trace = self.tracer()
        label = trace.trace(self.udp(1))
        self.assertEqual(label, '192.0.2.1_40000-198.51.100.2_53-1.25')
        # the reply joins the flow the query opened, under its label
        self.assertEqual(trace.trace(self.udp(2, src='198.51.100.2', dst='192.0.2.1', srcport=53,
                                              dstport=40000, timestamp=1.5)), label)
        # another port pair is another flow
        other = trace.trace(self.udp(3, srcport=40001, timestamp=1.75))
        self.assertEqual(other, '192.0.2.1_40001-198.51.100.2_53-1.75')

        first, second = trace.index
        self.assertEqual((first.index, first.forward, first.reverse), ((1, 2), (1,), (2,)))
        self.assertEqual(second.index, (3,))
        # open flows name the file finalised ones will
        self.assertEqual(first.fpout, f'{self.root}/{label}.json')
        self.assertIsNone(first.packet)

    def test_unidirectional_keeps_each_direction_apart(self) -> None:
        trace = self.tracer(bidirectional=False)
        trace.trace(self.udp(1))
        trace.trace(self.udp(2, src='198.51.100.2', dst='192.0.2.1', srcport=53, dstport=40000))
        self.assertEqual([(flow.index, flow.reverse) for flow in trace.index], [((1,), ()), ((2,), ())])

    def test_no_datagram_ends_a_flow_until_finish(self) -> None:
        from pcapkit.foundation.traceflow.udp.traceflow import UDP

        finalised = []  # type: list[Any]
        UDP.register_callback(finalised.append)
        self.addCleanup(UDP.__callback_fn__.remove, finalised.append)

        trace = self.tracer()
        for number in range(1, 5):
            trace(self.udp(number, timestamp=float(number) * 1000))
        self.assertEqual(finalised, [])
        self.assertEqual([flow.index for flow in trace.index], [(1, 2, 3, 4)])

        trace.finish()
        self.assertEqual([flow.index for flow in finalised], [(1, 2, 3, 4)])
        self.assertEqual(trace.index, tuple(finalised))
        trace.finish()  # idempotent
        self.assertEqual(len(finalised), 1)

    def test_dump_writes_each_frame_to_its_flow(self) -> None:
        import json
        import os

        trace = self.tracer()
        trace(self.udp(1))
        trace(self.udp(2, src='198.51.100.2', dst='192.0.2.1', srcport=53, dstport=40000))
        trace.finish()
        flow, = trace.index
        self.assertEqual(os.listdir(self.root), [os.path.basename(flow.fpout)])
        with open(flow.fpout, encoding='utf-8') as file:
            self.assertEqual(list(json.load(file)), ['Frame 1', 'Frame 2'])

    def test_an_ipv6_label_carries_no_colon(self) -> None:
        trace = self.tracer()
        label = trace.trace(self.udp(1, src='2001:db8::1', dst='2001:db8::2'))
        self.assertEqual(label, '2001.db8..1_40000-2001.db8..2_53-1.25')

    def test_analyze_parses_each_datagram_by_its_ports(self) -> None:
        from pcapkit.protocols.application.dns.protocol import DNS
        from pcapkit.protocols.misc.raw.protocol import Raw

        trace = self.tracer(analyze=True)
        trace(self.udp(1, payload=DNS_QUERY))
        trace(self.udp(2, srcport=40000, dstport=9, payload=b'discard'))
        trace.finish()
        dns, discard = trace.index
        query, = dns.packet
        self.assertIsInstance(query, DNS)
        self.assertEqual(query.info.id, 0x1234)
        self.assertEqual(query.info.question[0].name.name, 'a.example.')
        # an unbound port keeps the payload as Raw, as a frame's UDP layer would
        self.assertIsInstance(discard.packet[0], Raw)
        self.assertEqual(bytes(discard.packet[0]), b'discard')

    def test_analyze_takes_the_engines_stops(self) -> None:
        from pcapkit.protocols.misc.raw.protocol import Raw

        trace = self.tracer(analyze=True)
        trace._parse_keywords = {'layer': 'transport'}
        trace(self.udp(1, payload=DNS_QUERY))
        trace.finish()
        # a stop at the transport layer keeps the application layer raw
        self.assertIsInstance(trace.index[0].packet[0], Raw)

    def test_analyze_off_buffers_no_payload(self) -> None:
        trace = self.tracer()
        trace(self.udp(1, payload=DNS_QUERY))
        self.assertIsNone(next(iter(trace._buffer.values())).payload)

    def test_the_index_round_trips(self) -> None:
        import copy
        import pickle

        from pcapkit.foundation.traceflow.udp.data import Index

        trace = self.tracer()
        trace(self.udp(1))
        trace.finish()
        flow, = trace.index
        for clone in (Index.from_dict(flow.to_dict()), copy.deepcopy(flow), pickle.loads(pickle.dumps(flow))):
            with self.subTest(clone=type(clone).__name__):
                self.assertEqual(clone, flow)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPTraceFlowTests(TracerCase):
    """An IP conversation is its two addresses' datagrams, of whatever protocol."""

    def tracer(self, **kwargs: 'Any') -> 'Any':
        from pcapkit.foundation.traceflow.ip.traceflow import IP

        return IP(fout=self.root, format='json', **kwargs)

    def test_a_conversation_is_keyed_on_the_addresses(self) -> None:
        trace = self.tracer()
        label = trace.trace(self.ip(1))
        self.assertEqual(label, '192.0.2.1-198.51.100.2-1.25')
        self.assertEqual(trace.trace(self.ip(2, src='198.51.100.2', dst='192.0.2.1', timestamp=2.0)), label)
        self.assertEqual(trace.trace(self.ip(3, dst='203.0.113.9', timestamp=3.0)),
                         '192.0.2.1-203.0.113.9-3.0')
        self.assertEqual(trace.make_bufid(self.ip(9, src='198.51.100.2', dst='192.0.2.1')),
                         (ip_address('192.0.2.1'), ip_address('198.51.100.2')))
        self.assertIs(trace.submit(), trace.submit())
        trace.finish()
        first, second = trace.index
        self.assertEqual((first.index, first.forward, first.reverse), ((1, 2), (1,), (2,)))
        self.assertEqual(second.index, (3,))
        self.assertNotIn('packet', first)

    def test_unidirectional_keys_on_source_then_destination(self) -> None:
        trace = self.tracer(bidirectional=False)
        self.assertEqual(trace.make_bufid(self.ip(1, src='198.51.100.2', dst='192.0.2.1')),
                         (ip_address('198.51.100.2'), ip_address('192.0.2.1')))

    def test_an_ipv4_and_an_ipv6_conversation_stay_apart(self) -> None:
        trace = self.tracer()
        trace(self.ip(1))
        trace(self.ip(2, src='2001:db8::1', dst='2001:db8::2'))
        trace.finish()
        self.assertEqual([flow.label for flow in trace.index],
                         ['192.0.2.1-198.51.100.2-1.25', '2001.db8..1-2001.db8..2-1.25'])

    def test_analyze_is_ignored_with_a_warning(self) -> None:
        from pcapkit.utilities.warnings import AttributeWarning

        with self.assertWarns(AttributeWarning) as caught:
            trace = self.tracer(analyze=True)
        self.assertEqual(str(caught.warning), 'IP flow tracing has no application layer to analyze; '
                                              'so analyze=True will be ignored')
        self.assertFalse(trace._analyze)
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            self.assertFalse(self.tracer()._analyze)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class RegistrationTests(TracerCase):
    """Both are built in, registered and exported as TCP's tracer is."""

    def test_registered_and_exported(self) -> None:
        import pcapkit.all
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.traceflow.ip.traceflow import IP
        from pcapkit.foundation.traceflow.udp.traceflow import UDP

        for (name, klass, alias) in (('udp', UDP, 'UDP_TraceFlow'), ('ip', IP, 'IP_TraceFlow')):
            with self.subTest(name=name):
                self.assertIsInstance(Extractor.make_traceflow(name, fout=self.root, format='json'), klass)
                self.assertIs(getattr(pcapkit.all, alias), klass)
                self.assertIs(Extractor.__traceflow__[name], klass)

    def test_traceflow_data_has_a_field_each(self) -> None:
        from pcapkit.foundation.traceflow.data import TraceFlowData

        # each built-in is a field of its own, None while its tracing is off
        self.assertEqual(list(TraceFlowData().items()), [('tcp', None), ('udp', None), ('ip', None)])
        data = TraceFlowData(None, ('u',), ('i',), other=('o',))
        self.assertEqual(list(data.items()), [('tcp', None), ('udp', ('u',)), ('ip', ('i',)), ('other', ('o',))])


if __name__ == '__main__':
    unittest.main()
