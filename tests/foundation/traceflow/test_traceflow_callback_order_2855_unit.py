# -*- coding: utf-8 -*-
"""A flow's callbacks run once its file holds every frame it lists. C.f. #2855.

``TCP.dump`` writes the FIN that ends a unidirectional flow before finalising it,
so a callback finds the frame in the file, and one that raises cannot keep it
out. Every callback runs on a flow: an :exc:`Exception` from one is re-raised
once the rest have run.

Every case builds its own octets and reads no capture. Classes are imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import importlib.util
import io
import logging
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
    from typing import Any, Callable

#: Test tier (#1958): a flow's file read while its handles are held, flushed and
#: closed, and on an exception's path, which differ by interpreter.
__tier__ = 'ALL'

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))

SECOND = 1_500_000_000


def _frames() -> 'list[bytes]':
    """One direction of a connection: a SYN, a segment of data and a FIN."""
    return [ethernet(ipv4(tcp(payload, seq=seq, syn=syn, fin=fin), proto=6), 0x0800)
            for payload, seq, syn, fin in ((b'', 1000, True, False), (b'data', 1001, False, False),
                                           (b'', 1005, False, True))]


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class CallbackOrderTests(unittest.TestCase):
    """What a flow's file holds when its callbacks run, and which of them run."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        self.tmpdir = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(self.tmpdir.cleanup)

    def tracer(self, fmt: 'str' = 'json', **kwargs: 'Any') -> 'Any':
        """A TCP tracer writing ``fmt`` files to a fresh directory."""
        from pcapkit.foundation.traceflow.tcp import TCP

        return TCP(fout=tempfile.mkdtemp(dir=self.tmpdir.name), format=fmt, byteorder='little', **kwargs)

    def register(self, *callbacks: 'Callable[[Any], None]') -> None:
        """Register ``callbacks`` in order, removed again on cleanup."""
        from pcapkit.foundation.traceflow.tcp import TCP

        for callback in callbacks:
            TCP.register_callback(callback)
            self.addCleanup(TCP.__callback_fn__.remove, callback)

    def reader(self, *, error: 'BaseException | None' = None) -> 'list[tuple[Any, bytes]]':
        """Register a callback reading each flow's file, then raising ``error`` if given."""
        seen = []  # type: list[tuple[Any, bytes]]

        def callback(index: 'Any') -> None:
            with open(index.fpout, 'rb') as file:
                seen.append((index, file.read()))
            if error is not None:
                raise error

        self.register(callback)
        return seen

    def packet(self, index: 'int', sport: 'int' = 40000, *, syn: 'bool' = False, fin: 'bool' = False,
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

    def test_every_finalising_path_writes_the_flow_before_its_callbacks(self) -> None:
        """#2855: a unidirectional FIN, a superseding SYN and ``finish()`` each write first."""
        paths = {
            'unidirectional FIN': ({'bidirectional': False},
                                   [self.packet(1, syn=True), self.packet(2), self.packet(3, fin=True)]),
            'superseding SYN': ({}, [self.packet(1, syn=True), self.packet(2, reverse=True, syn=True),
                                     self.packet(3, fin=True), self.packet(4, reverse=True, fin=True),
                                     self.packet(5), self.packet(6, syn=True)]),
            'finish()': ({}, [self.packet(1, syn=True), self.packet(2, reverse=True, syn=True),
                              self.packet(3)]),
        }
        for path, (kwargs, packets) in paths.items():
            with self.subTest(path=path):
                trace = self.tracer(**kwargs)
                seen = self.reader()
                for packet in packets:
                    trace(packet)
                trace.finish()
                index, data = seen[0]
                self.assertEqual(data.count(b'"Frame '), len(index.index))
                with open(index.fpout, 'rb') as file:
                    self.assertEqual(data, file.read())

    def test_a_unidirectional_pcap_flow_is_whole_when_its_callback_runs(self) -> None:
        """#2855: the callback reads the PCAP file's every record, its file held open or not."""
        from pcapkit.utilities import config

        frames, packets = _frames(), self.packets()
        records = b''.join(struct.pack('<IIII', SECOND + number, 0, len(frame), len(frame)) + frame
                           for number, frame in enumerate(frames))
        for limit in (0, 64):
            with self.subTest(limit=limit), mock.patch.object(config, 'TRACE_OPEN_FILE_LIMIT', limit):
                trace = self.tracer('pcap', bidirectional=False)
                seen = self.reader()
                for packet in packets:
                    trace(packet)
                (index, data), = seen
                self.assertEqual((index.index, data[24:]), ((1, 2, 3), records))

    def test_a_raising_callback_leaves_the_fin_in_the_file(self) -> None:
        """#2855: the FIN ending a unidirectional flow is written though its callback raises."""
        trace = self.tracer(bidirectional=False)
        seen = self.reader(error=RuntimeError('callback refused'))
        trace(self.packet(1, syn=True))
        with self.assertRaisesRegex(RuntimeError, 'callback refused'):
            trace(self.packet(2, fin=True))
        (index, data), = seen
        self.assertEqual(index.index, (1, 2))
        self.assertEqual(data.count(b'"Frame '), 2)
        with open(index.fpout, 'rb') as file:
            self.assertEqual(file.read(), data)

    def test_an_exception_does_not_stop_the_callbacks_after_it(self) -> None:
        """#2855: every callback runs, the first error propagates; a ``KeyboardInterrupt`` stops them."""
        from pcapkit.foundation.traceflow.tcp import TCP, logger

        first, second = RuntimeError('first refused'), ValueError('second refused')
        calls = []  # type: list[str]

        def refuse(error: 'BaseException') -> 'Callable[[Any], None]':
            def callback(index: 'Any') -> None:
                calls.append(f'{type(error).__name__} {index.label}')
                raise error
            return callback

        self.register(refuse(first), refuse(second), lambda index: calls.append(f'last {index.label}'))
        trace = self.tracer()
        trace(self.packet(1, syn=True))
        label = trace.index[0].label
        with self.assertLogs(logger, logging.DEBUG) as logs, self.assertRaises(RuntimeError) as caught:
            trace.finish()
        self.assertIs(caught.exception, first)
        self.assertEqual(calls, [f'RuntimeError {label}', f'ValueError {label}', f'last {label}'])
        later = [record for record in logs.records if 'raised after an earlier one' in record.getMessage()]
        self.assertEqual([record.exc_info[1] for record in later], [second])

        calls.clear()
        interrupt = refuse(KeyboardInterrupt())
        TCP.register_callback(interrupt, index=0)
        self.addCleanup(TCP.__callback_fn__.remove, interrupt)
        trace(self.packet(2, 40001, syn=True))
        label = trace.index[0].label
        with self.assertRaises(KeyboardInterrupt):
            trace.finish()
        self.assertEqual(calls, [f'KeyboardInterrupt {label}'])


if __name__ == '__main__':
    unittest.main()
