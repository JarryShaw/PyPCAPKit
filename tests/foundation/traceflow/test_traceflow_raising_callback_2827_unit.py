# -*- coding: utf-8 -*-
"""A flow whose trace callback raises stays in the index. C.f. #2827.

``TCP._finalise`` stores a flow before its callbacks run, so one that raises
propagates and leaves the flow in ``index`` and ``submit()``, whichever path
finalised it: ``finish()``, a new connection's SYN, or a unidirectional FIN. The
flow's file is closed before the callbacks, exactly once, and holds every frame
written to it.

Every case builds its own octets and reads no capture. Classes are imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import builtins
import collections
import contextlib
import filecmp
import importlib.util
import io
import os
import struct
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

#: Test tier (#1958): file handles held open and closed on an exception's path,
#: which differ by interpreter.
__tier__ = 'ALL'

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))

SECOND = 1_500_000_000
#: The flow each frame belongs to, by source port offset: three flows, interleaved,
#: each written more than once, so every file is held open when ``finish()`` runs.
ORDER = (0, 1, 0, 2, 1, 0, 2)
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


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class RaisingCallbackTests(unittest.TestCase):
    """Where a flow goes, and its file, when a callback raises on it."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.utilities import config

        self.tmpdir = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(self.tmpdir.cleanup)
        # NOTE: no limit, so every flow's file is held open and closed by the tracer.
        patcher = mock.patch.object(config, 'TRACE_OPEN_FILE_LIMIT', -1)
        patcher.start()
        self.addCleanup(patcher.stop)

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

    def tracer(self, fmt: 'str' = 'json', **kwargs: 'Any') -> 'tuple[Any, list[tuple[str, Any]], Any]':
        """A TCP tracer, the files it opens, and its ``close()`` calls by output file."""
        from pcapkit.foundation.traceflow.tcp import TCP

        root = tempfile.mkdtemp(dir=self.tmpdir.name)
        recorder = self.opened(root)
        handles = recorder.__enter__()  # pylint: disable=unnecessary-dunder-call
        self.addCleanup(recorder.__exit__, None, None, None)
        trace = TCP(fout=root, format=fmt, byteorder='little', **kwargs)

        closes = collections.Counter()  # type: collections.Counter[str]
        real = trace._foutio.close

        def close(dumper: 'Any') -> None:
            closes[dumper.filename] += 1
            real(dumper)

        patcher = mock.patch.object(trace._foutio, 'close', close)
        patcher.start()
        self.addCleanup(patcher.stop)
        return trace, handles, closes

    def refuse(self, *calls: 'int') -> 'list[tuple[str, bytes]]':
        """Register a callback raising on its ``calls``-th calls; returns each flow's label and file."""
        from pcapkit.foundation.traceflow.tcp import TCP

        seen = []  # type: list[tuple[str, bytes]]

        def callback(index: 'Any') -> None:
            with open(index.fpout, 'rb') as file:
                seen.append((index.label, file.read()))
            if len(seen) in calls:
                raise RuntimeError(f'callback refused {index.label}')

        TCP.register_callback(callback)
        self.addCleanup(TCP.__callback_fn__.remove, callback)
        return seen

    def packet(self, index: 'int', sport: 'int', *, syn: 'bool' = False, fin: 'bool' = False,
               rst: 'bool' = False, reverse: 'bool' = False) -> 'Any':
        """A flow packet of a JSON-dumpable frame, between port ``sport`` and 9."""
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.traceflow.data.tcp import Packet

        near, far = (ip_address('192.0.2.1'), sport), (ip_address('198.51.100.2'), 9)
        if reverse:
            near, far = far, near
        return Packet(LinkType.ETHERNET, index, {'frame': index}, syn, fin, rst, near[0], far[0],
                      near[1], far[1], SECOND + index, 0, 0, b'', bytearray())

    def packets(self) -> 'list[Any]':
        """The flow packets of :func:`_frames`, as the extractor traces them."""
        from pcapkit import extract
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pcap import tcp_traceflow

        capture = pcap([(SECOND + number, 0, frame) for number, frame in enumerate(_frames())])
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = extract(fin=io.BytesIO(capture), store=True)
        close_extractor(extractor)
        return [tcp_traceflow(frame, data_link=LinkType.ETHERNET) for frame in extractor.frame]

    def assertNoFileOpen(self, trace: 'Any', handles: 'list[tuple[str, Any]]') -> None:  # pylint: disable=invalid-name
        """Nothing under the tracer's root is held or open, by handle and, where readable, by fd."""
        self.assertEqual(trace._fopen, {})
        self.assertTrue(all(handle.closed for _, handle in handles))
        if os.path.isdir('/proc/self/fd'):
            root, links = os.path.realpath(trace._fproot), []
            for name in os.listdir('/proc/self/fd'):
                with contextlib.suppress(OSError):
                    links.append(os.readlink(os.path.join('/proc/self/fd', name)))
            self.assertEqual([link for link in links if link.startswith(root)], [])

    def test_finish_keeps_the_flow_whose_callback_raised(self) -> None:
        """#2827: the issue's case -- three flows, the first callback raising, then ``finish()`` again."""
        trace, _, _ = self.tracer()
        for flow in range(3):
            trace(self.packet(flow + 1, 40000 + flow, syn=True))
        labels = sorted(index.label for index in trace.index)
        seen = self.refuse(1)

        with self.assertRaisesRegex(RuntimeError, 'callback refused'):
            trace.finish()
        self.assertEqual([index.label for index in trace._stream], [seen[0][0]])
        self.assertEqual((len(trace._buffer), len(trace.submit())), (2, 3))

        trace.finish()
        self.assertEqual([index.label for index in trace.index], [label for label, _ in seen])
        self.assertEqual(sorted(index.label for index in trace.submit()), labels)
        self.assertEqual(sorted(os.listdir(trace._fproot)),
                         sorted(os.path.basename(index.fpout) for index in trace.index))

    def test_a_callback_finds_its_flow_in_the_index(self) -> None:
        """#2827: the flow is stored before, not after, its callbacks, so each finds the flow it is handed."""
        from pcapkit.foundation.traceflow.tcp import TCP

        trace, _, _ = self.tracer()
        for flow in range(2):
            trace(self.packet(flow + 1, 40000 + flow, syn=True))
        found = []

        def callback(index: 'Any') -> None:
            found.append(index.label in [entry.label for entry in trace.index])

        TCP.register_callback(callback)
        self.addCleanup(TCP.__callback_fn__.remove, callback)
        trace.finish()
        self.assertEqual(found, [True, True])

    def test_a_superseding_syn_keeps_the_superseded_flow(self) -> None:
        """#2827: a callback raising on the flow a new connection's SYN ends propagates from the call."""
        trace, handles, closes = self.tracer()
        trace(self.packet(1, 40000, syn=True))
        trace(self.packet(2, 40000, rst=True, reverse=True))
        trace(self.packet(3, 40001, syn=True))
        seen = self.refuse(1)

        with self.assertRaisesRegex(RuntimeError, 'callback refused'):
            trace(self.packet(4, 40000, syn=True))
        flow, = trace._stream
        self.assertEqual((flow.label, flow.index, flow.forward, flow.reverse), (seen[0][0], (1, 2), (1,), (2,)))
        self.assertEqual([index.index for index in trace.index], [(3,), (1, 2)])
        self.assertNoFileOpen(trace, handles)

        trace.finish()
        self.assertEqual([index.index for index in trace.index], [(1, 2), (3,)])
        self.assertEqual(sorted(closes.values()), [1, 1])

    def test_a_unidirectional_fin_keeps_its_flow(self) -> None:
        """#2827: a callback raising on the flow its FIN ends propagates from the call."""
        trace, handles, _ = self.tracer(bidirectional=False)
        trace(self.packet(1, 40000, syn=True))
        seen = self.refuse(1)

        with self.assertRaisesRegex(RuntimeError, 'callback refused'):
            trace(self.packet(2, 40000, fin=True))
        self.assertEqual([(index.label, index.index) for index in trace.index], [(seen[0][0], (1, 2))])
        self.assertNoFileOpen(trace, handles)

    def closed_once_and_whole(self, fmt: 'str') -> 'tuple[Any, bytes]':
        """Finish a ``fmt`` trace of :func:`_frames` whose first callback raises; the flow and its file."""
        from pcapkit.foundation.traceflow.tcp import TCP

        packets = self.packets()
        reference = TCP(fout=tempfile.mkdtemp(dir=self.tmpdir.name), format=fmt, byteorder='little')
        for packet in packets:
            reference(packet)
        reference.finish()
        names = sorted(os.listdir(reference._fproot))

        trace, handles, closes = self.tracer(fmt)
        for packet in packets:
            trace(packet)
        self.assertEqual(len(trace._fopen), 3)
        seen = self.refuse(1)
        with self.assertRaisesRegex(RuntimeError, 'callback refused'):
            trace.finish()

        flow, = trace._stream
        self.assertEqual(flow.label, seen[0][0])
        self.assertNoFileOpen(trace, handles)
        self.assertEqual(sum(mode in APPENDING for mode, _ in handles), 3)
        self.assertEqual(sorted(closes), [f'{trace._fproot}/{name}' for name in names])
        self.assertEqual(set(closes.values()), {1})
        # NOTE: the callback read the file whole, so it was flushed before it raised.
        with open(flow.fpout, 'rb') as file:
            self.assertEqual(seen[0][1], file.read())
        _, mismatch, errors = filecmp.cmpfiles(reference._fproot, trace._fproot, names, shallow=False)
        self.assertEqual((mismatch, errors), ([], []))

        trace.finish()
        self.assertEqual(len(trace.index), 3)
        self.assertEqual(set(closes.values()), {1})
        return flow, seen[0][1]

    def test_a_refused_pcap_flow_file_is_closed_once_and_whole(self) -> None:
        """#2827: every PCAP file is closed once, and the refused flow's holds its records."""
        flow, data = self.closed_once_and_whole('pcap')
        frames = _frames()
        records = b''.join(struct.pack('<IIII', SECOND + number - 1, 0, len(frames[number - 1]),
                                       len(frames[number - 1])) + frames[number - 1]
                           for number in flow.index)
        self.assertEqual((flow.index, data[24:]), ((1, 3, 6), records))

    def test_a_refused_json_flow_file_is_closed_once_and_whole(self) -> None:
        """#2827: every JSON file is closed once, and the refused flow's holds its frames."""
        flow, data = self.closed_once_and_whole('json')
        self.assertEqual((flow.index, data.count(b'"Frame ')), ((1, 3, 6), 3))


if __name__ == '__main__':
    unittest.main()
