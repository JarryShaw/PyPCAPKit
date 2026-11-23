# -*- coding: utf-8 -*-
"""``reassemble``, ``trace`` and ``follow_tcp_stream`` mirror the classes they build. C.f. #2837.

Under the convention ruled on #2834 (``public-signatures.rst``), a
:mod:`pcapkit.interface` function takes its primary input positionally and
exactly the keyword-only parameters of the class it builds, pinned here.
``reassemble`` and ``trace`` reach every registered class through
``Reassembly.registry`` and ``TraceFlow.registry``. ``reassemble``'s ``strict``
now defaults to ``True``, as the class does, with no warning: the owner ruled out
the shim in review of #2894.

On ``main`` before this change, ``reassemble`` defaulted ``strict=False`` and
took no ``store``, and ``trace`` took ``fout`` and ``format`` positionally,
had no ``analyze`` and made TCP's tracer only. Classes are imported inside each
test, after :func:`~tests._support.reimport_once_per_class`.

"""

from __future__ import annotations

import importlib.util
import inspect
import tempfile
import unittest
import warnings

from tests._support import reimport_once_per_class

#: Test tier (#1958): signatures and registry dispatch, the same on every interpreter.
__tier__ = 'LATEST'

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class MirrorTests(unittest.TestCase):
    """Each function's parameters after its input are its class's, pinned equal."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _assert_mirrors(self, function: 'object', init: 'object') -> None:
        first, *rest = inspect.signature(function).parameters.values()  # type: ignore[arg-type]
        self.assertEqual((first.name, first.kind), ('protocol', inspect.Parameter.POSITIONAL_OR_KEYWORD))
        self.assertEqual(rest, list(inspect.signature(init).parameters.values())[1:])  # type: ignore[arg-type]

    def test_reassemble_mirrors_the_reassembly_class(self) -> None:
        from pcapkit.foundation.reassembly.reassembly import ReassemblyBase
        from pcapkit.interface.core import reassemble

        self._assert_mirrors(reassemble, ReassemblyBase.__init__)

    def test_trace_mirrors_the_flow_tracing_class(self) -> None:
        from pcapkit.foundation.traceflow.traceflow import TraceFlowBase
        from pcapkit.interface.core import trace

        self._assert_mirrors(trace, TraceFlowBase.__init__)

    def test_follow_tcp_stream_mirrors_the_extractor(self) -> None:
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.interface.misc import follow_tcp_stream

        mine = inspect.signature(follow_tcp_stream).parameters
        theirs = inspect.signature(Extractor.__init__).parameters
        for name in ('verbose', 'engine'):
            with self.subTest(name=name):
                self.assertEqual(mine[name], theirs[name])


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ReassembleTests(unittest.TestCase):

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_strict_defaults_to_the_class_with_no_warning(self) -> None:
        from pcapkit.interface.core import reassemble

        # NOTE: made once first, so the lazy import of the class warns nothing below.
        self.assertIs(reassemble('ipv4', strict=False)._flag_s, False)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            self.assertIs(reassemble('ipv4')._flag_s, True)
        self.assertEqual([str(w.message) for w in caught], [])

    def test_every_keyword_reaches_the_reassembler(self) -> None:
        from pcapkit.foundation.reassembly.dtls import DTLS
        from pcapkit.interface.core import reassemble

        reasm = reassemble('DTLS', strict=False, store=False, timeout=2.5)
        self.assertIsInstance(reasm, DTLS)
        self.assertEqual((reasm._flag_s, reasm._flag_d, reasm.timeout), (False, False, 2.5))

    def test_a_registered_reassembler_is_reached_by_name(self) -> None:
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.reassembly.reassembly import Reassembly
        from pcapkit.interface.core import reassemble

        class Unit(Reassembly, protocol='unit-2837'):  # pylint: disable=abstract-method
            def reassembly(self, info: 'object') -> None:
                pass

            def submit(self, buf: 'object', **kwargs: 'object') -> 'list[object]':
                return []

        self.addCleanup(Extractor.__reassembly__.pop, 'unit-2837', None)
        self.assertIsInstance(reassemble('Unit-2837'), Unit)

    def test_arguments_after_the_protocol_are_keywords_and_closed(self) -> None:
        from pcapkit.interface.core import reassemble
        from pcapkit.utilities.exceptions import FormatError, RegistryError

        for args, kwargs in ((('ipv4', True), {}), (('ipv4',), {'bogus': 1})):
            with self.subTest(args=args, kwargs=kwargs), self.assertRaises(TypeError):
                reassemble(*args, **kwargs)  # type: ignore[misc,arg-type]
        with self.assertRaises(FormatError):
            reassemble('unit-2837-missing')
        with self.assertRaisesRegex(RegistryError, r'^reassembly name must be a str, not 4$'):
            reassemble(4)  # type: ignore[arg-type]


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TraceTests(unittest.TestCase):

    def setUp(self) -> None:
        reimport_once_per_class(self)
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        self.tmp = tempdir.name

    def test_every_keyword_reaches_the_tracer(self) -> None:
        from pcapkit.foundation.traceflow.tcp import TCP
        from pcapkit.interface.core import trace

        tracer = trace('tcp', fout=self.tmp, format='json', byteorder='big', nanosecond=True,
                       bidirectional=False, analyze=True)
        self.assertIsInstance(tracer, TCP)
        self.assertEqual((tracer._fproot, tracer._fdpext, tracer._endian, tracer._nnsecd, tracer._bidir,
                          tracer._analyze), (self.tmp, '.json', 'big', True, False, True))

    def test_a_registered_tracer_is_reached_by_name(self) -> None:
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.traceflow.traceflow import TraceFlow
        from pcapkit.interface.core import trace

        class Unit(TraceFlow, protocol='unit-2837'):  # pylint: disable=abstract-method
            def dump(self, packet: 'object') -> None:
                pass

            def trace(self, packet: 'object', *, output: bool = False) -> 'str':  # type: ignore[override]
                return ''

            def submit(self) -> 'tuple[object, ...]':
                return ()

        self.addCleanup(Extractor.__traceflow__.pop, 'unit-2837', None)
        self.assertIsInstance(trace('Unit-2837', fout=self.tmp, format='json'), Unit)

    def test_arguments_after_the_protocol_are_keywords(self) -> None:
        from pcapkit.interface.core import trace
        from pcapkit.utilities.exceptions import FormatError, RegistryError

        with self.assertRaises(TypeError):
            trace('tcp', self.tmp, 'json')  # type: ignore[misc]
        with self.assertRaises(FormatError):
            trace('unit-2837-missing')
        with self.assertRaisesRegex(RegistryError, r'^traceflow name must be a str, not 4$'):
            trace(4)  # type: ignore[arg-type]


if __name__ == '__main__':
    unittest.main()
