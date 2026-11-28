# -*- coding: utf-8 -*-
"""Reassembly and flow tracing classes take keyword-only arguments, one name per concept. C.f. #2839.

Under the convention ruled on #2834 (``public-signatures.rst``), every argument
after the primary input is keyword-only with its real default in the signature,
and a concept has one name: ``timeout`` is seconds, so ``submit``'s flag is
``expired``; a callback is added by ``register_callback``; a format is
``format``; and the spelling is ``analyze``. ``TraceFlowManager`` holds its
tracers by registered name, as ``ReassemblyManager`` holds reassemblers.

On ``main`` before this change, ``TraceFlow`` took ``fout`` and ``format``
positionally with ``None`` for their defaults, DTLS reassembly took no
``timeout``, and ``TraceFlowManager`` had one ``tcp`` field. Classes are imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

from __future__ import annotations

import importlib.util
import inspect
import math
import sys
import tempfile
import unittest
import warnings

from tests._support import reimport_once_per_class

#: Test tier (#1958): signatures and pure-Python bookkeeping, the same on every interpreter.
__tier__ = 'LATEST'

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))


def _shape(function: 'object', skip: 'int' = 1) -> 'list[tuple[str, object, object]]':
    """Each parameter of ``function`` after the first ``skip``, as ``(name, kind, default)``."""
    return [(param.name, param.kind, param.default)
            for param in list(inspect.signature(function).parameters.values())[skip:]]  # type: ignore[arg-type]


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ReassemblyKeywordTests(unittest.TestCase):

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_every_builtin_reassembler_takes_the_base_keywords(self) -> None:
        from pcapkit.foundation.options import ReassemblyOptions
        from pcapkit.foundation.reassembly.dtls.reassembly import DTLS
        from pcapkit.foundation.reassembly.ipv4.reassembly import IPv4
        from pcapkit.foundation.reassembly.ipv6.reassembly import IPv6
        from pcapkit.foundation.reassembly.reassembly import ReassemblyBase
        from pcapkit.foundation.reassembly.tcp.reassembly import TCP

        base = list(inspect.signature(ReassemblyBase.__init__).parameters.values())[1:]
        self.assertEqual({param.kind for param in base}, {inspect.Parameter.KEYWORD_ONLY})
        for klass in (IPv4, IPv6, TCP, DTLS):
            with self.subTest(klass=klass.__name__):
                self.assertEqual(list(inspect.signature(klass.__init__).parameters.values())[1:], base)
        # NOTE: the options class takes the class's keywords, after the names it enables (#2836).
        self.assertEqual(_shape(ReassemblyOptions, skip=0)[1:], _shape(ReassemblyBase.__init__))

    def test_dtls_takes_a_timeout_and_keeps_none_by_default(self) -> None:
        from pcapkit.foundation.reassembly.dtls.reassembly import DTLS
        from pcapkit.utilities.exceptions import FieldValueError

        self.assertEqual(DTLS().timeout, math.inf)
        self.assertEqual(DTLS(timeout=1.5).timeout, 1.5)
        with self.assertRaises(FieldValueError):
            DTLS(timeout=-1.0)

    def test_dtls_expires_a_buffer_past_its_timeout(self) -> None:
        from pcapkit.const.tls.handshake_type import HandshakeType
        from pcapkit.foundation.reassembly.data import Completion
        from pcapkit.foundation.reassembly.dtls.data import Packet
        from pcapkit.foundation.reassembly.dtls.reassembly import DTLS

        bufid = ('192.0.2.1', 1234, '192.0.2.2', 5684, 0)
        for timeout, after, expired in ((1.0, 12.0, True), (None, 1e9, False)):
            with self.subTest(timeout=timeout):
                engine = DTLS(timeout=timeout)
                engine(Packet(bufid=bufid, num=1, msg_type=HandshakeType.client_hello, length=8,
                              message_seq=0, fragment_offset=0, fragment_length=4,
                              payload=b'\x01\x02\x03\x04', timestamp=10.0))
                gone = engine.expire(after)
                if expired:
                    self.assertEqual([datagram.completed for datagram in gone], [Completion.TIMEOUT])
                    self.assertEqual(engine._buffer, {})
                    self.assertEqual(list(engine.datagram), gone)
                else:
                    self.assertEqual(gone, [])
                    self.assertIn(bufid, engine._buffer)

    def test_submit_flags_an_expired_buffer_as_expired(self) -> None:
        from pcapkit.foundation.reassembly.dtls.reassembly import DTLS
        from pcapkit.foundation.reassembly.ip.reassembly import IP
        from pcapkit.foundation.reassembly.tcp.reassembly import TCP

        for klass in (IP, TCP, DTLS):
            with self.subTest(klass=klass.__name__):
                params = inspect.signature(klass.submit).parameters
                self.assertIs(params['expired'].kind, inspect.Parameter.KEYWORD_ONLY)
                self.assertIs(params['expired'].default, False)
                self.assertNotIn('timeout', params)

    def test_a_callback_is_added_under_one_name(self) -> None:
        from pcapkit.foundation.reassembly.reassembly import ReassemblyBase
        from pcapkit.foundation.traceflow.traceflow import TraceFlowBase

        for klass in (ReassemblyBase, TraceFlowBase):
            with self.subTest(klass=klass.__name__):
                # NOTE: ``register`` is left to ``abc.ABCMeta``, which refuses a function.
                self.assertFalse(any('register' in vars(base) for base in klass.__mro__))
                with self.assertRaises(TypeError):
                    klass.register(print)
                self.assertEqual(_shape(klass.register_callback, skip=0),
                                 [('callback', inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty),
                                  ('index', inspect.Parameter.KEYWORD_ONLY, None)])

    def test_register_callback_reaches_the_reassembler(self) -> None:
        from pcapkit.foundation.reassembly.ipv4.reassembly import IPv4

        calls = []  # type: list[object]
        IPv4.register_callback(calls.append)
        self.addCleanup(IPv4.__callback_fn__.remove, calls.append)
        engine = IPv4(strict=False)
        engine._notify(['datagram'])
        self.assertEqual(calls, [['datagram']])


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TraceFlowKeywordTests(unittest.TestCase):

    def setUp(self) -> None:
        reimport_once_per_class(self)
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        self.tmp = tempdir.name

    def test_every_argument_is_keyword_only_with_its_real_default(self) -> None:
        from pcapkit.foundation.options import TraceFlowOptions
        from pcapkit.foundation.traceflow.traceflow import TraceFlowBase

        kwonly = inspect.Parameter.KEYWORD_ONLY
        self.assertEqual(_shape(TraceFlowBase.__init__), [
            ('fout', kwonly, './tmp'), ('format', kwonly, 'pcap'), ('byteorder', kwonly, sys.byteorder),
            ('nanosecond', kwonly, False), ('bidirectional', kwonly, True), ('analyze', kwonly, False),
            ('timeout', kwonly, None),
        ])
        self.assertEqual(_shape(TraceFlowOptions, skip=0)[1:], _shape(TraceFlowBase.__init__))

    def test_positional_arguments_and_the_old_spelling_are_refused(self) -> None:
        from pcapkit.foundation.traceflow.tcp.traceflow import TCP

        for args, kwargs in (((self.tmp, 'json'), {}),
                             ((), {'fout': self.tmp, 'format': 'json', 'analyse': True})):
            with self.subTest(args=args, kwargs=kwargs), self.assertRaises(TypeError):
                TCP(*args, **kwargs)  # type: ignore[misc,arg-type]

    def test_analyze_buffers_each_flow_for_its_application_layer(self) -> None:
        from pcapkit.foundation.reassembly.tcp.reassembly import TCP as TCP_Reassembly
        from pcapkit.foundation.traceflow.tcp.traceflow import TCP

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            self.assertIsNone(TCP(fout=self.tmp, format='unknown-unit-format')._make_reassembly())
            reasm = TCP(fout=self.tmp, format='unknown-unit-format', analyze=True)._make_reassembly()
        self.assertIsInstance(reasm, TCP_Reassembly)

    def test_make_fout_takes_format_by_keyword(self) -> None:
        from pcapkit.foundation.traceflow.traceflow import TraceFlow

        self.assertEqual(_shape(TraceFlow.make_fout, skip=0),
                         [('fout', inspect.Parameter.POSITIONAL_OR_KEYWORD, './tmp'),
                          ('format', inspect.Parameter.KEYWORD_ONLY, 'pcap')])
        self.assertEqual(TraceFlow.make_fout(self.tmp, format='json')[1], '.json')
        with self.assertRaises(TypeError):
            TraceFlow.make_fout(self.tmp, 'json')  # type: ignore[misc]
        with self.assertRaises(TypeError):
            TraceFlow.make_fout(self.tmp, fmt='json')  # type: ignore[call-arg]

    def test_register_dumper_takes_ext_by_keyword(self) -> None:
        from dictdumper import JSON

        from pcapkit.foundation.traceflow.traceflow import TraceFlow

        self.addCleanup(TraceFlow.__output__.pop, 'unit-2839', None)
        with self.assertRaises(TypeError):
            TraceFlow.register_dumper('unit-2839', JSON, '.unit')  # type: ignore[misc]
        self.assertNotIn('unit-2839', TraceFlow.__output__)
        TraceFlow.register_dumper('unit-2839', JSON, ext='.unit')
        self.assertEqual(TraceFlow.__output__['unit-2839'], (JSON, '.unit'))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TraceFlowManagerTests(unittest.TestCase):

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_tracers_are_held_by_name_and_only_when_enabled(self) -> None:
        from pcapkit.foundation.traceflow import TraceFlowManager

        tcp, dummy = object(), object()
        self.assertEqual(dict(TraceFlowManager(tcp=None)), {})
        manager = TraceFlowManager({'dummy': dummy, 'off': None}, tcp=tcp)
        self.assertEqual(list(manager), ['dummy', 'tcp'])
        self.assertIs(manager.dummy, dummy)
        self.assertIs(manager['tcp'], tcp)
        self.assertEqual(list(TraceFlowManager([('tcp', tcp), ('dummy', dummy)])), ['tcp', 'dummy'])


if __name__ == '__main__':
    unittest.main()
