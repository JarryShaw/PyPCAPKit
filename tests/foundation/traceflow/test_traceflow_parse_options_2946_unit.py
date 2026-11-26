# -*- coding: utf-8 -*-
"""A flow traced with ``analyze=True`` parses its payloads with the extraction's stops and context (#2946).

TCP flow tracing builds a TCP reassembler per flow. The default engine hands it the
``layer``, ``protocol`` and ``context`` given to ``extract()``, as it hands them to
TCP reassembly (#2933), so a traced datagram's ``packet`` is the one TCP reassembly
gives for the same segments. A third-party engine hands none.

Every capture is built in memory, as PCAP and as PCAP-NG; no sample capture is read.

"""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class
from tests.foundation.reassembly.test_dtls_handshake_reassembly_2440_unit import _extract, _pcap
from tests.foundation.reassembly.test_reassembly_parse_options_2933_unit import (CONTAINERS,
                                                                                 REQUEST, SEGMENTS,
                                                                                 _context)

if TYPE_CHECKING:
    from typing import Any


class TracedParseOptionsTests(unittest.TestCase):
    """A traced flow's datagram parses as TCP reassembly's datagram does."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def extract(self, capture: bytes, **kwargs: 'Any') -> 'Any':
        """Extract ``capture`` with TCP reassembly and TCP flow tracing under ``analyze``."""
        from pcapkit.foundation.options import TraceFlowOptions

        root = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(root.cleanup)
        trace = TraceFlowOptions(protocols=['tcp'], fout=root.name, format='json', analyze=True)
        return _extract(self, capture, traceflow=trace, **kwargs)

    def traced(self, **kwargs: 'Any') -> 'list[tuple[str, Any, Any]]':
        """Each container's name, and the ``packet`` of its traced and its reassembled datagram."""
        packets = []
        for name, build in CONTAINERS:
            extractor = self.extract(build(SEGMENTS), reassembly=['tcp'], **kwargs)
            flow, = extractor.traceflow.tcp
            traced, = flow.packet
            reassembled, = extractor.reassembly.tcp
            packets.append((name, traced.packet, reassembled.packet))
        return packets

    def assertSameParse(self, traced: 'Any', reassembled: 'Any') -> None:  # pylint: disable=invalid-name
        """``traced`` is what TCP reassembly parses the same segments to."""
        self.assertIs(type(traced), type(reassembled))
        self.assertEqual(str(traced.protochain), str(reassembled.protochain))
        self.assertEqual(traced.info, reassembled.info)
        self.assertEqual(bytes(traced), b''.join(REQUEST))

    def test_stop_at_the_transport_layer_keeps_the_payload_raw(self) -> None:
        from pcapkit.protocols.misc.raw.protocol import Raw

        for stop in ({'layer': 'Transport'}, {'protocol': 'TCP'}):
            for container, traced, reassembled in self.traced(**stop):
                with self.subTest(container=container, **stop):
                    self.assertIs(type(traced), Raw)
                    self.assertSameParse(traced, reassembled)

    def test_context_reaches_the_traced_payload(self) -> None:
        context = _context()
        for container, traced, reassembled in self.traced(context=context):
            with self.subTest(container=container):
                self.assertEqual(dict(traced.context), {'ESP': context})
                self.assertEqual(dict(traced.context), dict(reassembled.context))
                self.assertSameParse(traced, reassembled)

    def test_no_stop_parses_the_whole_payload(self) -> None:
        for container, traced, reassembled in self.traced():
            with self.subTest(container=container):
                self.assertEqual(type(traced).__name__, 'HTTPv1')
                self.assertEqual(dict(traced.context), {})
                self.assertSameParse(traced, reassembled)

    @unittest.skipUnless(importlib.util.find_spec('dpkt') is not None, 'dpkt not installed')
    def test_an_engine_ignoring_them_ignores_them_here_too(self) -> None:
        extractor = self.extract(_pcap(SEGMENTS), engine='dpkt', layer='Transport',
                                 context=_context())
        flow, = extractor.traceflow.tcp
        traced, = flow.packet
        self.assertEqual(type(traced.packet).__name__, 'HTTPv1')
        self.assertEqual(dict(traced.packet.context), {})

    def test_a_tracer_outside_an_extraction_parses_with_none(self) -> None:
        from pcapkit.foundation.traceflow.tcp.traceflow import TCP

        root = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(root.cleanup)
        tracer = TCP(fout=root.name, format='json', analyze=True)
        self.assertEqual(tracer._make_reassembly()._parse_keywords, {})  # type: ignore[union-attr]


if __name__ == '__main__':
    unittest.main()
