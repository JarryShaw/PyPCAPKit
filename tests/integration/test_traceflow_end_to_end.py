# -*- coding: utf-8 -*-
"""End-to-end TCP flow tracing.

Translates :file:`examples/legacy_smoke/test_trace.py`, which traced
:file:`http.pcap` and pretty-printed the index, and the ``trace=True`` half of
:file:`test_api.py`. Tracing writes one report per flow into ``trace_fout``, so
what is asserted here is the index the extractor exposes *and* that the reports
on disk hold exactly the frames the index claims.

"""
from __future__ import annotations

import unittest

from tests._support import sample_path
from tests.integration._helpers import HAS_RUNTIME, EndToEndTestCase, read_json

#: The two connections of :file:`tcp.pcap`: concurrent SSH sessions, one over
#: IPv4 and one over IPv6. Tracing keys a flow on the canonical *pair* of
#: endpoints, so a connection is one flow rather than one per direction; the
#: label is that of the direction seen first, and ``forward``/``reverse`` hold
#: that direction's frames and its peer's. Mapped here as
#: ``label: (forward, reverse)``.
TCP_PCAP_FLOWS = {
    '10.20.30.130_22-10.20.30.131_53406-1500000000.000774': ((1, 7), (2, 6)),
    'fe80..a6.87f9.2793.16ee_51774-fe80..1ccd.7c77.bac7.46b7_22-1500000000.002433': ((3,), (4, 5)),
}


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TraceFlowTests(EndToEndTestCase):
    """Flow tracing over :file:`tcp.pcap`, which is seven frames."""

    def trace(self, capture: 'str' = 'tcp.pcap') -> 'tuple':
        extractor = self.extract(fin=sample_path(capture), nofile=True, store=False,
                                 tcp=True, trace=True, trace_format='json',
                                 trace_fout=self.out('trace'))
        return extractor.length, extractor.trace.tcp

    def test_both_directions_of_a_connection_become_one_flow(self) -> None:
        length, flows = self.trace()

        self.assertEqual(length, 7)
        # each connection is a single flow, and both of its halves are still
        # reported separately -- as ``forward`` and ``reverse`` of that one flow
        self.assertEqual({flow.label: (flow.forward, flow.reverse) for flow in flows},
                         TCP_PCAP_FLOWS)
        # ... and the flow's own index is the two halves in wire order, so no
        # frame is dropped by the merge and none is counted twice
        self.assertEqual({flow.label: flow.index for flow in flows},
                         {label: tuple(sorted(forward + reverse))
                          for label, (forward, reverse) in TCP_PCAP_FLOWS.items()})

    def test_flow_labels_carry_both_address_families(self) -> None:
        _, flows = self.trace()
        labels = {flow.label for flow in flows}

        # A label is ``src_port-dst_port-timestamp``, with the dots of an IPv6
        # address doubled so the label stays usable as a file name. One label per
        # connection rather than per direction, so one of each family here.
        self.assertEqual(sum(1 for label in labels if label.startswith('10.20.30.')), 1)
        self.assertEqual(sum(1 for label in labels if label.startswith('fe80..')), 1)

    def test_each_flow_is_dumped_to_its_own_report(self) -> None:
        _, flows = self.trace()

        written = sorted(entry.name for entry in self.tmp_path.joinpath('trace').iterdir())
        self.assertEqual(written, sorted(f'{label}.json' for label in TCP_PCAP_FLOWS))

        for flow in flows:
            with self.subTest(flow=flow.label):
                self.assertEqual(flow.fpout, self.out(f'trace/{flow.label}.json'))
                self.assertTrue(self.tmp_path.joinpath('trace', f'{flow.label}.json').is_file())

    def test_a_flow_report_holds_exactly_the_frames_its_index_names(self) -> None:
        _, flows = self.trace()

        for flow in flows:
            with self.subTest(flow=flow.label):
                report = read_json(flow.fpout)
                self.assertEqual(list(report), [f'Frame {number}' for number in flow.index])
                for number in flow.index:
                    self.assertEqual(report[f'Frame {number}']['number'], number)

    def test_tracing_is_refused_when_it_was_not_requested(self) -> None:
        from pcapkit.utilities.exceptions import UnsupportedCall

        extractor = self.extract(fin=sample_path('tcp.pcap'), nofile=True, store=False, tcp=True)

        with self.assertRaises(UnsupportedCall):
            extractor.trace  # pylint: disable=pointless-statement


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TraceFlowScaleTests(EndToEndTestCase):
    """Flow tracing over :file:`http.pcap`.

    This is the one place in this tier that uses the 1117 frame capture, and it
    is used deliberately: it is the only fixture with hundreds of short
    connections, so it is the only one that shows the tracer partitioning a
    capture rather than handling a handful of flows. It costs roughly three
    seconds, and ``examples/legacy_smoke/test_trace.py`` traced this same file.

    """

    def test_every_frame_lands_in_exactly_one_flow(self) -> None:
        extractor = self.extract(fin=sample_path('http.pcap'), nofile=True, store=False,
                                 tcp=True, trace=True, trace_format='json',
                                 trace_fout=self.out('trace'))
        flows = extractor.trace.tcp

        self.assertEqual(extractor.length, 1117)
        # 220 connections, not the 331 directions they are made of: 111 of them
        # were captured both ways and 109 only one way, and 2 * 111 + 109 == 331,
        # so the drop is the two halves of a connection meeting in one flow and
        # not frames going missing -- which is what the index check below pins
        self.assertEqual(len(flows), 220)

        indexed = [number for flow in flows for number in flow.index]
        self.assertEqual(len(indexed), 1117)
        self.assertEqual(sorted(indexed), list(range(1, 1118)))

    def test_one_report_is_written_per_flow(self) -> None:
        extractor = self.extract(fin=sample_path('http.pcap'), nofile=True, store=False,
                                 tcp=True, trace=True, trace_format='json',
                                 trace_fout=self.out('trace'))
        flows = extractor.trace.tcp

        written = {entry.name for entry in self.tmp_path.joinpath('trace').iterdir()}
        self.assertEqual(written, {f'{flow.label}.json' for flow in flows})
        self.assertEqual(len(written), 220)

        # Spot-check the longest flow rather than re-reading all 220 reports.
        longest = max(flows, key=lambda flow: len(flow.index))
        report = read_json(longest.fpout)
        self.assertEqual(list(report), [f'Frame {number}' for number in longest.index])


if __name__ == '__main__':
    unittest.main()
