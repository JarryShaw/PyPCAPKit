# -*- coding: utf-8 -*-
"""The extractor makes and feeds every enabled flow tracer, not TCP's alone. C.f. #2843.

``Extractor`` built the tracer registered as ``tcp`` and dropped any other name
with a warning, ``TraceFlowData`` had a ``tcp`` field alone, and ``_cleanup``
finished TCP's tracer only, behind an ``Extractor._tcp`` flag. So an engine
adapter registered for another tracer (#2892) had nothing to feed. Now
``Extractor.make_traceflow`` makes each enabled tracer by name, the name-keyed
``TraceFlowManager`` holds them, ``Extractor.traceflow`` reports each, and
``_cleanup`` finishes each.

A test-only tracer and adapter stand in for a second protocol, and the captures are
built in memory. Classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

from __future__ import annotations

import copy
import importlib.util
import inspect
import io
import os
import pickle
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import close_extractor, reimport_once_per_class
from tests.foundation._roundtrip import ethernet, ipv4, pcap, tcp

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): extraction logic, the same on every interpreter.
__tier__ = 'LATEST'

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))

SECOND = 1_500_000_000


def capture() -> bytes:
    """A PCAP savefile of one TCP connection's three frames, opened by a SYN and never closed."""
    return pcap([(SECOND + number, 0, ethernet(ipv4(tcp(bytes([number]) * 4, seq=1000 * number,
                                                         syn=number == 0), proto=6), 0x0800))
                 for number in range(3)])


def counter() -> 'type':
    """A flow tracer, registrable as ``counter``, that keeps every record it is fed as a flow."""
    from pcapkit.foundation.traceflow.traceflow import TraceFlow

    class Counter(TraceFlow[str, object, object, object]):
        __protocol_name__ = 'Counter'

        #: Calls of :meth:`finish`, across instances.
        finished = []  # type: list[Any]

        def dump(self, packet: 'Any') -> None:
            self._stream.append(packet)

        def trace(self, packet: 'Any', *, output: bool = False) -> 'Any':
            return 'counter'

        def submit(self) -> 'tuple[Any, ...]':
            return tuple(self._stream)

        def finish(self) -> None:
            type(self).finished.append(self)
            super().finish()

    return Counter


def adapter(frame: 'Any', *, data_link: 'Any') -> 'Any':
    """A ``counter`` adapter for the PCAP engine: each frame's number, with its link type."""
    return f'frame {frame.info.number} on {data_link.name}'


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TracerCase(unittest.TestCase):
    """A fresh import, a ``counter`` tracer registered for the test, and an output root."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.foundation.engines.pcap import PCAP
        from pcapkit.foundation.extraction import Extractor

        for registry in (Extractor.__traceflow__, PCAP.__traceflow__):
            patcher = mock.patch.dict(registry)
            patcher.start()
            self.addCleanup(patcher.stop)

        self.Counter = counter()
        Extractor.register_traceflow('counter', self.Counter)

        tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name

    def extract(self, protocols: 'list[str]', *, auto: bool = True,
                **kwargs: 'Any') -> 'tuple[Any, list[str]]':
        """Trace :func:`capture` through ``protocols``; the extractor and its warnings."""
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.options import TraceFlowOptions

        options = TraceFlowOptions(protocols=protocols, fout=os.path.join(self.root, 'trace'),
                                   format='json', **kwargs)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            extractor = Extractor(io.BytesIO(capture()), traceflow=options, auto=auto)
        self.addCleanup(close_extractor, extractor)
        return extractor, [str(warning.message) for warning in caught]


class EndToEndTests(TracerCase):
    """A second registered tracer runs through its engine adapter beside TCP's."""

    def test_issue_reproduction(self) -> None:
        """#2843: a registered tracer with an adapter is made, fed and reported."""
        from pcapkit.foundation.engines.pcap import PCAP

        PCAP.register_traceflow('counter', adapter)
        extractor, messages = self.extract(['tcp', 'counter'])

        self.assertFalse([message for message in messages if 'flow tracing' in message], messages)
        self.assertEqual(list(extractor._trace), ['tcp', 'counter'])
        self.assertIsInstance(extractor._trace['counter'], self.Counter)
        self.assertEqual(extractor.traceflow.counter,
                         ('frame 1 on ETHERNET', 'frame 2 on ETHERNET', 'frame 3 on ETHERNET'))
        self.assertEqual([flow.index for flow in extractor.traceflow.tcp], [(1, 2, 3)])
        # the built-ins lead, each None when off (#2956)
        self.assertEqual(list(extractor.traceflow), ['tcp', 'udp', 'ip', 'counter'])
        # the end of the capture finished it, as it finished TCP's
        self.assertEqual(self.Counter.finished, [extractor._trace['counter']])

    def test_each_tracer_takes_the_options(self) -> None:
        from pcapkit.foundation.engines.pcap import PCAP

        PCAP.register_traceflow('counter', adapter)
        extractor, _ = self.extract(['counter', 'tcp'], byteorder='big', nanosecond=True,
                                    bidirectional=False)
        self.assertEqual(list(extractor._trace), ['counter', 'tcp'])
        for (name, tracer) in extractor._trace.items():
            with self.subTest(tracer=name):
                self.assertEqual((tracer._fproot, tracer._fdpext), (os.path.join(self.root, 'trace'), '.json'))
                self.assertEqual((tracer._endian, tracer._nnsecd, tracer._bidir), ('big', True, False))

    def test_tracing_stays_on_when_tcp_alone_is_dropped(self) -> None:
        from pcapkit.foundation.engines.pcap import PCAP

        PCAP.__traceflow__.clear()
        PCAP.register_traceflow('counter', adapter)
        extractor, messages = self.extract(['tcp', 'counter'])

        self.assertIn("'Extractor(engine=default)' object does not support TCP flow tracing; "
                      "so 'tcp' will be ignored", messages)
        self.assertTrue(extractor._flag_t)
        self.assertFalse(getattr(extractor, '_tcp', False))
        self.assertEqual(list(extractor._trace), ['counter'])
        self.assertIsNone(extractor.traceflow.tcp)
        self.assertEqual(len(extractor.traceflow.counter), 3)

    def test_a_tracer_with_no_adapter_is_dropped_and_tcp_kept(self) -> None:
        extractor, messages = self.extract(['tcp', 'counter'])

        self.assertIn("'Extractor(engine=default)' object does not support Counter flow tracing; "
                      "so 'counter' will be ignored", messages)
        self.assertEqual(list(extractor._trace), ['tcp'])
        self.assertEqual(list(extractor.traceflow), ['tcp', 'udp', 'ip'])
        self.assertEqual(self.Counter.finished, [])

    def test_tracing_off_holds_no_tracer(self) -> None:
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.utilities.exceptions import UnsupportedCall

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = Extractor(io.BytesIO(capture()))
        self.addCleanup(close_extractor, extractor)
        self.assertFalse(extractor._flag_t)
        self.assertEqual(list(extractor._trace), [])
        with self.assertRaises(UnsupportedCall):
            _ = extractor.traceflow


class CheckTests(TracerCase):
    """Every enabled tracer's output settings are checked before anything is written."""

    def test_a_format_one_tracer_lacks_raises(self) -> None:
        import collections

        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.options import TraceFlowOptions
        from pcapkit.utilities.exceptions import FormatError

        self.Counter.__output__ = collections.defaultdict(
            lambda: (ModuleDescriptor('pcapkit.dumpkit', 'NotImplementedIO'), None),
            {'json': (ModuleDescriptor('dictdumper', 'JSON'), '.json')})
        trace = os.path.join(self.root, 'trace')
        with self.assertRaises(FormatError) as caught:
            Extractor(io.BytesIO(capture()), traceflow=TraceFlowOptions(protocols=['tcp', 'counter'],
                                                                         fout=trace, format='pcap'))
        self.assertEqual(str(caught.exception), "unknown flow tracing format: 'pcap'")
        self.assertFalse(os.path.exists(trace))
        self.assertNotIn('pcap', self.Counter.__output__)


class MakeTraceflowTests(TracerCase):
    """``Extractor.make_traceflow`` makes any registered tracer by name, ``trace``'s too."""

    def test_makes_a_registered_tracer_by_name(self) -> None:
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.traceflow.tcp.traceflow import TCP

        fout = os.path.join(self.root, 'made')
        for (name, kind) in (('Counter', self.Counter), ('TCP', TCP)):
            with self.subTest(name=name):
                tracer = Extractor.make_traceflow(name, fout=fout, format='json', analyze=True)
                self.assertIsInstance(tracer, kind)
                self.assertEqual((tracer._fproot, tracer._fdpext, tracer._analyze), (fout, '.json', True))
        # the shipped descriptor is replaced by the class it named
        self.assertIs(Extractor.__traceflow__['tcp'], TCP)

    def test_refuses_an_unknown_or_unnamed_protocol(self) -> None:
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.utilities.exceptions import FormatError, RegistryError

        with self.assertRaises(FormatError) as caught:
            Extractor.make_traceflow('no-such-protocol', fout=self.root)
        self.assertEqual(str(caught.exception), "unsupported flow tracing protocol: 'no-such-protocol'")
        with self.assertRaises(RegistryError):
            Extractor.make_traceflow(2843, fout=self.root)  # type: ignore[arg-type]

    def test_mirrors_the_flow_tracing_class(self) -> None:
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.traceflow.traceflow import TraceFlowBase

        first, *rest = inspect.signature(Extractor.make_traceflow).parameters.values()
        self.assertEqual((first.name, first.kind), ('protocol', inspect.Parameter.POSITIONAL_OR_KEYWORD))
        self.assertEqual(rest, list(inspect.signature(TraceFlowBase.__init__).parameters.values())[1:])

    def test_trace_makes_its_tracer_through_it(self) -> None:
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.traceflow.tcp.traceflow import TCP
        from pcapkit.interface.core import trace
        from pcapkit.protocols.transport.tcp.protocol import TCP as TCP_Protocol

        options = {'fout': os.path.join(self.root, 'traced'), 'format': 'json', 'byteorder': 'big',
                   'nanosecond': True, 'bidirectional': False, 'analyze': True, 'timeout': 30.0}
        for (protocol, name, kind) in (('Counter', 'Counter', self.Counter), (TCP_Protocol, 'TCP', TCP)):
            with self.subTest(name=name):
                with mock.patch.object(Extractor, 'make_traceflow', wraps=Extractor.make_traceflow) as make:
                    tracer = trace(protocol, **options)
                make.assert_called_once_with(name, **options)
                self.assertIsInstance(tracer, kind)
                self.assertEqual((tracer._fproot, tracer._fdpext, tracer._endian, tracer._nnsecd, tracer._bidir,
                                  tracer._analyze, tracer.timeout),
                                 (options['fout'], '.json', 'big', True, False, True, 30.0))


class CleanupTests(TracerCase):
    """The end of the capture finishes every tracer, whatever another raises."""

    def tracers(self, *errors: 'Any') -> 'tuple[Any, list[str]]':
        """An extractor short of its end, holding a stand-in tracer per entry of ``errors``.

        Each stand-in's ``finish`` records its name, then raises its entry unless it is :data:`None`.

        """
        from pcapkit.foundation.traceflow import TraceFlowManager

        calls = []  # type: list[str]

        def stand_in(name: str, error: 'Any') -> 'Any':
            def finish() -> None:
                calls.append(name)
                if error is not None:
                    raise error
            return mock.Mock(finish=finish)

        extractor, _ = self.extract(['tcp'], auto=False)
        extractor._trace = TraceFlowManager({f'counter{number}': stand_in(f'counter{number}', error)
                                             for (number, error) in enumerate(errors)})
        return extractor, calls

    def test_a_raising_tracer_leaves_the_rest_finished(self) -> None:
        from pcapkit.foundation.engines.pcap import PCAP

        first = RuntimeError('first refused')
        extractor, calls = self.tracers(first, None, RuntimeError('later refused'))
        with mock.patch.object(PCAP, 'close', autospec=True, side_effect=PCAP.close) as close, \
                self.assertLogs('pcapkit.foundation.extraction', 'DEBUG') as logs, \
                self.assertRaises(RuntimeError) as caught:
            extractor._cleanup()
        self.assertIs(caught.exception, first)
        self.assertEqual(calls, ['counter0', 'counter1', 'counter2'])
        self.assertTrue(any('counter2 flow tracer raised on finish after an earlier one' in line
                            for line in logs.output), logs.output)
        # the input and the engine are released as on any raising finish (#2857)
        close.assert_called_once_with(extractor.engine)
        self.assertTrue(extractor._flag_e)

    def test_a_base_exception_stops_at_once(self) -> None:
        extractor, calls = self.tracers(None, KeyboardInterrupt(), None)
        with self.assertRaises(KeyboardInterrupt):
            extractor._cleanup()
        self.assertEqual(calls, ['counter0', 'counter1'])

    def test_every_tracer_is_finished(self) -> None:
        extractor, calls = self.tracers(None, None)
        extractor._cleanup()
        self.assertEqual(calls, ['counter0', 'counter1'])


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TraceFlowDataTests(unittest.TestCase):
    """``TraceFlowData`` keeps the built-ins first, then a field per other tracer as given."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_tcp_then_the_rest_as_given(self) -> None:
        from pcapkit.foundation.traceflow.data import TraceFlowData

        for extra in ({}, {'late': (), 'early': ('e',)}, {'early': ('e',), 'late': ()}):
            with self.subTest(list(extra)):
                data = TraceFlowData(**extra)
                self.assertEqual(list(data.items()), [('tcp', None), ('udp', None), ('ip', None),
                                                      *extra.items()])
        self.assertEqual(TraceFlowData(('t',)).tcp, ('t',))

    def test_round_trips(self) -> None:
        from pcapkit.foundation.traceflow.data import TraceFlowData

        data = TraceFlowData(tcp=('t',), counter=('c',))
        for clone in (TraceFlowData.from_dict(data.to_dict()), copy.deepcopy(data),
                      pickle.loads(pickle.dumps(data))):
            with self.subTest(clone=type(clone).__name__):
                self.assertIs(type(clone), TraceFlowData)
                self.assertEqual(list(clone.items()), [('tcp', ('t',)), ('udp', None), ('ip', None),
                                                       ('counter', ('c',))])


if __name__ == '__main__':
    unittest.main()
