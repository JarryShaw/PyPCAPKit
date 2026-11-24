# -*- coding: utf-8 -*-
"""A traced flow keeps its output file open between frames. C.f. #2815.

The TCP flow tracer reopened a flow's file for each frame it wrote. It now keeps
it open, at most :data:`~pcapkit.utilities.config.TRACE_OPEN_FILE_LIMIT` files at
once, closing the one written least recently past that, and closes them all at
``finish()``, on an error, when a flow is finalised, and when the tracer is
collected. A limit of ``0`` takes the per-frame reopen, unchanged, so every other
limit must write the same octets as it does.

Every case builds its own octets and reads no capture. Classes are imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import builtins
import contextlib
import filecmp
import gc
import importlib.util
import io
import os
import struct
import sys
import tempfile
import unittest
import warnings
from ipaddress import ip_address
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import close_extractor, reimport_once_per_class
from tests.foundation._roundtrip import ethernet, ipv4, pcap, tcp

if TYPE_CHECKING:
    from typing import Any, Iterator

#: Test tier (#1958): file handles held open and flushed, and closed by a
#: ``weakref.finalize``, which differ by interpreter.
__tier__ = 'ALL'

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))

SECOND = 1_500_000_000
#: The flow each frame belongs to, by source port offset: three flows, interleaved
#: so that a limit of 2 both hits and evicts.
ORDER = (0, 0, 1, 1, 0, 1, 2, 0, 2)
#: Appending opens of the flow files per limit, for :data:`ORDER`: one per flow
#: when every flow fits, one per frame at 0, and an LRU's misses in between.
OPENS = {64: 3, -1: 3, 2: 4, 1: 7, 0: 9}
#: Modes the dumpers append to a flow's file in.
APPENDING = frozenset({'ab', 'r+'})


def _frames() -> 'list[bytes]':
    """A TCP segment per :data:`ORDER` entry, each flow opening with a SYN."""
    frames, seen = [], set()  # type: list[bytes], set[int]
    for number, flow in enumerate(ORDER):
        segment = tcp(bytes([number]) * (number + 1), seq=1000 * number, syn=flow not in seen,
                      sport=40000 + flow)
        seen.add(flow)
        frames.append(ethernet(ipv4(segment, proto=6), 0x0800))
    return frames


def _capture() -> 'bytes':
    return pcap([(SECOND + number, 0, frame) for number, frame in enumerate(_frames())])


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TraceOpenFileTests(unittest.TestCase):
    """How many flow files are open, and when they close."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.utilities import config

        self.config = config
        self.tmpdir = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(self.tmpdir.cleanup)

    @contextlib.contextmanager
    def opened(self, root: 'str') -> 'Iterator[list[tuple[str, Any]]]':
        """Patch :func:`builtins.open`, recording ``(mode, handle)`` for every file opened under ``root``."""
        real = builtins.open
        handles = []  # type: list[tuple[str, Any]]

        def record(file: 'Any', *args: 'Any', **kwargs: 'Any') -> 'Any':
            handle = real(file, *args, **kwargs)
            if isinstance(file, str) and file.startswith(root):
                handles.append((args[0] if args else kwargs.get('mode', 'r'), handle))
            return handle

        with mock.patch('builtins.open', record):
            yield handles

    def extract(self, fmt: 'str', limit: 'int') -> 'tuple[str, list[tuple[str, Any]], Any]':
        """Trace :func:`_capture` at ``limit``: the output directory, the opens, and the tracer."""
        from pcapkit import extract
        from pcapkit.foundation.options import TraceFlowOptions

        root = tempfile.mkdtemp(dir=self.tmpdir.name)
        # NOTE: ``create``, so the tree without #2815 runs, and fails on what it opens.
        with self.opened(root) as handles, warnings.catch_warnings(), \
                mock.patch.object(self.config, 'TRACE_OPEN_FILE_LIMIT', limit, create=True):
            warnings.simplefilter('ignore')
            extractor = extract(fin=io.BytesIO(_capture()), store=False,
                                traceflow=TraceFlowOptions(protocols=['tcp'], fout=root, format=fmt,
                                                           byteorder='little'))
        close_extractor(extractor)
        self.assertEqual(len(extractor.traceflow.tcp), 3)
        return root, handles, extractor._trace.tcp

    def test_each_flow_opens_its_file_once_while_it_fits(self) -> None:
        """#2815: one appending open per flow, an LRU's misses past the limit."""
        for fmt in ('pcap', 'json'):
            for limit, opens in OPENS.items():
                with self.subTest(fmt=fmt, limit=limit):
                    _, handles, _ = self.extract(fmt, limit)
                    self.assertEqual(sum(mode in APPENDING for mode, _ in handles), opens)

    def test_every_format_writes_the_octets_of_a_reopen_per_frame(self) -> None:
        """#2815: a held file, evicted or not, writes what limit 0's per-frame reopen does."""
        for fmt in ('pcap', 'json', 'tree', 'plist'):
            reopen, _, _ = self.extract(fmt, 0)
            names = sorted(os.listdir(reopen))
            for limit in OPENS:
                with self.subTest(fmt=fmt, limit=limit):
                    root, handles, _ = self.extract(fmt, limit)
                    # NOTE: so the files compared were kept open, not reopened per frame too.
                    self.assertEqual(sum(mode in APPENDING for mode, _ in handles), OPENS[limit])
                    self.assertEqual(sorted(os.listdir(root)), names)
                    _, mismatch, errors = filecmp.cmpfiles(reopen, root, names, shallow=False)
                    self.assertEqual((mismatch, errors), ([], []))

    def test_the_pcap_flow_files_hold_their_frames(self) -> None:
        """#2815: and those octets are each flow's frames, in order, not only a reopen's."""
        root, handles, trace = self.extract('pcap', 2)
        self.assertEqual(sum(mode in APPENDING for mode, _ in handles), OPENS[2])
        frames = _frames()
        for flow in trace.index:
            records = b''.join(struct.pack('<IIII', SECOND + number - 1, 0, len(frames[number - 1]),
                                           len(frames[number - 1])) + frames[number - 1]
                               for number in flow.index)
            with self.subTest(flow=flow.label), open(flow.fpout, 'rb') as file:
                self.assertEqual(file.read()[24:], records)
        self.assertEqual(len(os.listdir(root)), 3)

    def test_no_more_files_are_open_than_the_limit(self) -> None:
        """#2815: at limit 2, two flow files are open at most, and two at once."""
        from pcapkit.foundation.traceflow.tcp.traceflow import TCP

        peak = []
        real = TCP._write

        def write(trace: 'Any', *args: 'Any', **kwargs: 'Any') -> None:
            real(trace, *args, **kwargs)
            peak.append(len(trace._fopen))

        with mock.patch.object(TCP, '_write', write):
            self.extract('pcap', 2)
        self.assertEqual(max(peak), 2)

    def test_every_file_is_closed_at_finish(self) -> None:
        """#2815: a finished extraction leaves no flow file open."""
        for fmt in ('pcap', 'json'):
            with self.subTest(fmt=fmt):
                _, handles, trace = self.extract(fmt, -1)
                self.assertEqual(trace._fopen, {})
                self.assertTrue(all(handle.closed for _, handle in handles))

    def packet(self, index: 'int', sport: 'int', *, syn: 'bool' = False, fin: 'bool' = False) -> 'Any':
        """A flow packet of a JSON-dumpable frame, from port ``sport`` to 9."""
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.traceflow.tcp.data import Packet

        return Packet(LinkType.ETHERNET, index, {'frame': index}, syn, fin, False, ip_address('192.0.2.1'),
                      ip_address('198.51.100.2'), sport, 9, SECOND + index, 0, 0, b'', bytearray())

    def tracer(self, **kwargs: 'Any') -> 'tuple[Any, list[tuple[str, Any]]]':
        """A JSON TCP tracer fed two flows, and the files it opened."""
        from pcapkit.foundation.traceflow.tcp.traceflow import TCP

        root = tempfile.mkdtemp(dir=self.tmpdir.name)
        recorder = self.opened(root)
        handles = recorder.__enter__()  # pylint: disable=unnecessary-dunder-call
        self.addCleanup(recorder.__exit__, None, None, None)
        trace = TCP(fout=root, format='json', **kwargs)
        trace(self.packet(1, 40000, syn=True))
        trace(self.packet(2, 40001, syn=True))
        self.assertEqual(len(trace._fopen), 2)
        return trace, handles

    def test_an_error_closes_every_file(self) -> None:
        """#2815: a frame that fails to write closes the files kept open, then propagates."""
        trace, handles = self.tracer()
        with mock.patch.object(trace._foutio, '_append_value', side_effect=OSError(28, 'No space left')), \
                self.assertRaises(OSError):
            trace(self.packet(3, 40000))
        self.assertEqual(trace._fopen, {})
        self.assertTrue(all(handle.closed for _, handle in handles))
        # NOTE: tracing goes on, reopening the file.
        trace(self.packet(4, 40000))
        self.assertEqual(len(trace._fopen), 1)
        trace.finish()
        self.assertTrue(all(handle.closed for _, handle in handles))

    def test_close_keeps_the_flows(self) -> None:
        """#2815: ``close()`` closes the files and leaves every flow being traced."""
        trace, handles = self.tracer()
        trace.close()
        self.assertEqual((trace._fopen, len(trace._buffer)), ({}, 2))
        self.assertTrue(all(handle.closed for _, handle in handles))
        trace.finish()

    def test_a_collected_tracer_closes_its_files(self) -> None:
        """#2815: a tracer dropped before ``finish()`` closes its files when it is collected."""
        trace, handles = self.tracer()
        finalizer = trace._finalizer
        self.assertEqual((finalizer.peek()[0], finalizer.atexit), (trace, True))
        if sys.implementation.name == 'cpython':
            del trace
            gc.collect()
        else:
            # NOTE: collection is not prompt off CPython, so the finaliser is run by hand.
            finalizer()
        self.assertFalse(finalizer.alive)
        self.assertTrue(all(handle.closed for _, handle in handles))

    def test_a_finalised_flow_is_closed_before_its_callback(self) -> None:
        """#2815: a callback finds its flow's file whole and no longer kept open."""
        from pcapkit.foundation.traceflow.tcp.traceflow import TCP

        trace, _ = self.tracer()
        seen = []

        def callback(index: 'Any') -> None:
            held = [dumper.filename for dumper in trace._fopen.values()]
            with open(index.fpout, 'rb') as file:
                seen.append((index.fpout in held, file.read().count(b'"Frame ')))

        TCP.register_callback(callback)
        self.addCleanup(TCP.__callback_fn__.remove, callback)
        trace.finish()
        self.assertEqual(seen, [(False, 1), (False, 1)])

    def test_a_raising_callback_leaves_no_file_open(self) -> None:
        """#2815: ``finish()`` closes every flow's file though a callback aborts its loop."""
        from pcapkit.foundation.traceflow.tcp.traceflow import TCP

        trace, handles = self.tracer()
        trace(self.packet(3, 40002, syn=True))
        root = os.path.realpath(trace._fproot)

        calls = []

        def callback(index: 'Any') -> None:
            calls.append(index.label)
            if len(calls) == 1:
                raise RuntimeError(f'callback refused {index.label}')

        TCP.register_callback(callback)
        self.addCleanup(TCP.__callback_fn__.remove, callback)
        with self.assertRaisesRegex(RuntimeError, 'callback refused'):
            trace.finish()
        self.assertEqual((trace._fopen, len(trace._buffer)), ({}, 2))
        self.assertEqual([handle.closed for mode, handle in handles if mode in APPENDING], [True] * 3)
        if os.path.isdir('/proc/self/fd'):
            links = []
            for name in os.listdir('/proc/self/fd'):
                with contextlib.suppress(OSError):
                    links.append(os.readlink(os.path.join('/proc/self/fd', name)))
            self.assertEqual([link for link in links if link.startswith(root)], [])
        # NOTE: the flows the callback stranded are finalised by the next call.
        trace.finish()
        self.assertEqual((len(calls), len(trace._buffer)), (3, 0))

    def test_a_unidirectional_fin_is_written_without_keeping_the_file(self) -> None:
        """#2815: the FIN that finalises a flow is written to its held file, then closed (#2855)."""
        trace, handles = self.tracer(bidirectional=False)
        trace(self.packet(3, 40000, fin=True))
        self.assertEqual([dumper.filename for dumper in trace._fopen.values()],
                         [index.fpout for index in trace.index if index.index == (2,)])
        flow, = [index for index in trace.index if index.index == (1, 3)]
        with open(flow.fpout, 'rb') as file:
            self.assertEqual(file.read().count(b'"Frame '), 2)
        self.assertEqual(sum(mode == 'r+' for mode, _ in handles), 2)
        trace.finish()


if __name__ == '__main__':
    unittest.main()
