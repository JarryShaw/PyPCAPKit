from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TraceFlowBaseTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_register_dumper_make_fout_and_metadata_fallbacks(self) -> None:
        from pcapkit.corekit.infoclass import Info, info_final
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.dumpkit.null import NotImplementedIO
        from pcapkit.foundation.traceflow.traceflow import TraceFlowBase
        from pcapkit.utilities.exceptions import FileExists, RegistryError

        @info_final
        class DummyPacket(Info):
            index: int

        @info_final
        class DummyIndex(Info):
            index: tuple[int, ...]

        @info_final
        class DummyBuffer(Info):
            index: list[int]

        class DummyTrace(TraceFlowBase[str, DummyBuffer, DummyIndex, DummyPacket]):
            __protocol_type__ = NotImplementedIO

            def dump(self, packet: DummyPacket) -> None:
                self.trace(packet)

            def trace(self, packet: DummyPacket, *, output: bool = False):
                self._buffer.setdefault('flow', DummyBuffer([])).index.append(packet.index)
                return object() if output else 'flow'

            def submit(self) -> tuple[DummyIndex, ...]:
                ret = tuple(DummyIndex(tuple(buf.index)) for buf in self._buffer.values())
                ret += tuple(self._stream)
                return ret

        class PlainTrace(TraceFlowBase[str, DummyBuffer, DummyIndex, DummyPacket]):
            def dump(self, packet: DummyPacket) -> None:
                self.trace(packet)

            def trace(self, packet: DummyPacket, *, output: bool = False):
                return object() if output else 'flow'

            def submit(self) -> tuple[DummyIndex, ...]:
                return ()

        self.assertEqual(DummyTrace.name, 'DummyTrace')
        self.assertIs(DummyTrace.protocol, NotImplementedIO)
        self.assertEqual(PlainTrace.protocol.__name__, 'Raw')

        with self.assertRaises(RegistryError):
            DummyTrace.register_dumper('bad', object, '.bad')  # type: ignore[arg-type]

        with mock.patch('pcapkit.foundation.traceflow.traceflow.warn') as warn:
            DummyTrace.register_dumper('json', NotImplementedIO, '.unit')
        warn.assert_called_once()
        DummyTrace.register_dumper('unit-descriptor',
                                   ModuleDescriptor('pcapkit.dumpkit', 'NotImplementedIO'),
                                   '.unit')

        with tempfile.TemporaryDirectory() as tempdir:
            fout = pathlib.Path(tempdir) / 'flows'
            dumper, ext = DummyTrace.make_fout(str(fout), 'json')
            self.assertTrue(issubclass(dumper, NotImplementedIO))
            self.assertEqual(ext, '.unit')
            self.assertTrue(fout.is_dir())

            file_path = pathlib.Path(tempdir) / 'file-output'
            file_path.write_text('not a directory')
            with self.assertRaises(FileExists):
                DummyTrace.make_fout(str(file_path), 'json')

            with mock.patch('pcapkit.foundation.traceflow.traceflow.warn') as warn:
                dumper, ext = DummyTrace.make_fout(str(file_path), 'unknown-unit-format')
            self.assertTrue(issubclass(dumper, NotImplementedIO))
            self.assertIsNone(ext)
            self.assertGreaterEqual(warn.call_count, 1)

            default_format = pathlib.Path(tempdir) / 'default-format'
            default_trace = DummyTrace(str(default_format), None)
            self.assertEqual(default_trace._fdpext, '.pcap')

        trace = DummyTrace(None, 'unknown-unit-format')
        self.assertEqual(trace.name, 'DummyTrace')
        self.assertIs(trace.protocol, NotImplementedIO)
        plain = PlainTrace('./tmp', 'unknown-unit-format')
        self.assertEqual(plain.protocol.__name__, 'Raw')
        trace.__protocol_name__ = 'instance'
        trace.__protocol_type__ = NotImplementedIO
        self.assertEqual(trace.name, 'instance')
        self.assertIs(trace.protocol, NotImplementedIO)

        trace(DummyPacket(1))
        self.assertEqual(trace.index[0].index, (1,))

    def test_register_dumper_identity_guard(self) -> None:
        """GitHub issue #739: re-registering the same dumper class is silent.

        Same defect and fix as ``Extractor.register_dumper`` (see
        ``tests/foundation/test_extraction.py``), for
        ``TraceFlowBase.register_dumper``. This class keeps its own
        ``__output__`` -- a separate :class:`collections.defaultdict` of
        ``(dumper, ext)`` pairs from :class:`~pcapkit.foundation.extraction.
        Extractor`'s -- so the same identity-on-the-dumper-not-the-pair
        nuance applies here independently.

        """
        from pcapkit.dumpkit.null import NotImplementedIO
        from pcapkit.foundation.traceflow.traceflow import TraceFlowBase
        from pcapkit.utilities.warnings import RegistryWarning

        class UnitTraceDumperIdentityB(NotImplementedIO):
            pass

        with mock.patch('pcapkit.foundation.traceflow.traceflow.warn'):
            TraceFlowBase.register_dumper('unit-trace-dumper-identity', NotImplementedIO, '.unit-a')

        # 1. Re-registering the same object is silent.
        with mock.patch('pcapkit.foundation.traceflow.traceflow.warn') as warn:
            TraceFlowBase.register_dumper('unit-trace-dumper-identity', NotImplementedIO, '.unit-a')
        warn.assert_not_called()
        # 3. The registry write still happens even when the guard stays quiet.
        self.assertEqual(TraceFlowBase.__output__['unit-trace-dumper-identity'],
                         (NotImplementedIO, '.unit-a'))

        # 2. Replacing with a different object still warns, message unchanged.
        with mock.patch('pcapkit.foundation.traceflow.traceflow.warn') as warn:
            TraceFlowBase.register_dumper('unit-trace-dumper-identity', UnitTraceDumperIdentityB, '.unit-b')
        warn.assert_called_once_with(
            'dumper unit-trace-dumper-identity already registered, overwriting', RegistryWarning)
        # 3. And the write happens on the warning path too.
        self.assertEqual(TraceFlowBase.__output__['unit-trace-dumper-identity'],
                         (UnitTraceDumperIdentityB, '.unit-b'))

    def test_register_callback_and_subclass_registration(self) -> None:
        from pcapkit.corekit.infoclass import Info, info_final
        from pcapkit.foundation.traceflow.traceflow import TraceFlow, TraceFlowBase

        @info_final
        class DummyPacket(Info):
            index: int

        @info_final
        class DummyIndex(Info):
            index: tuple[int, ...]

        @info_final
        class DummyBuffer(Info):
            index: list[int]

        class CallbackTrace(TraceFlowBase[str, DummyBuffer, DummyIndex, DummyPacket]):
            def dump(self, packet: DummyPacket) -> None:
                self.trace(packet)

            def trace(self, packet: DummyPacket, *, output: bool = False):
                index = DummyIndex((packet.index,))
                for callback in self.__callback_fn__:
                    callback(index)
                self._stream.append(index)
                return object() if output else 'flow'

            def submit(self) -> tuple[DummyIndex, ...]:
                return tuple(self._stream)

        callback_calls: list[DummyIndex] = []
        leading_calls: list[DummyIndex] = []
        CallbackTrace.register_callback(callback_calls.append)
        CallbackTrace.register_callback(leading_calls.append, index=0)

        trace = CallbackTrace('./tmp', 'unknown-unit-format')
        trace(DummyPacket(7))
        self.assertEqual(callback_calls[0].index, (7,))
        self.assertEqual(leading_calls[0].index, (7,))

        with mock.patch('pcapkit.foundation.extraction.Extractor.register_traceflow') as register:
            class Explicit(TraceFlow[str, DummyBuffer, DummyIndex, DummyPacket],
                           protocol='TraceProto'):
                def dump(self, packet: DummyPacket) -> None:
                    self.trace(packet)

                def trace(self, packet: DummyPacket, *, output: bool = False):
                    return object() if output else 'flow'

                def submit(self) -> tuple[DummyIndex, ...]:
                    return ()

        register.assert_called_once_with('traceproto', Explicit)

        with mock.patch('pcapkit.foundation.extraction.Extractor.register_traceflow') as register:
            class Default(TraceFlow[str, DummyBuffer, DummyIndex, DummyPacket]):
                __protocol_name__ = 'DefaultTrace'

                def dump(self, packet: DummyPacket) -> None:
                    self.trace(packet)

                def trace(self, packet: DummyPacket, *, output: bool = False):
                    return object() if output else 'flow'

                def submit(self) -> tuple[DummyIndex, ...]:
                    return ()

        # #514: registration is opt-in. Before it, the absent keyword fell back to
        # ``cls.name`` -- i.e. ``__protocol_name__`` here -- and this registered
        # under ``'defaulttrace'``. A class attribute is not a registry key.
        register.assert_not_called()
        self.assertEqual(Default.name, 'DefaultTrace')

    def test_traceflow_subclass_rejects_unrecognised_keyword(self) -> None:
        """A misspelled class keyword raises instead of being swallowed.

        It used to land in ``**kwargs``, get dropped by the bare
        ``super().__init_subclass__()``, and leave the class registered under its
        own class name -- no exception, no warning.

        The keyword used here is deliberately *not* ``name``; see the sibling
        test in ``tests/foundation/reassembly/test_reassembly_base.py`` for why
        four class keyword names collide with :meth:`abc.ABCMeta.__new__` on
        Python 3.10. The colliding case is pinned separately below.

        """
        from pcapkit.corekit.infoclass import Info, info_final
        from pcapkit.foundation.traceflow.traceflow import TraceFlow
        from pcapkit.utilities.exceptions import UnsupportedCall

        @info_final
        class DummyPacket(Info):
            index: int

        @info_final
        class DummyIndex(Info):
            index: tuple[int, ...]

        @info_final
        class DummyBuffer(Info):
            index: list[int]

        with mock.patch('pcapkit.foundation.extraction.Extractor.register_traceflow') as register:
            with self.assertRaises(UnsupportedCall) as caught:
                class Typo(TraceFlow[str, DummyBuffer, DummyIndex, DummyPacket],
                           traceflow='wrong-keyword-for-traceflow'):
                    def dump(self, packet: DummyPacket) -> None:
                        self.trace(packet)

                    def trace(self, packet: DummyPacket, *, output: bool = False):
                        return object() if output else 'flow'

                    def submit(self) -> tuple[DummyIndex, ...]:
                        return ()

        register.assert_not_called()
        self.assertIn('traceflow', str(caught.exception))

        # ``name=`` is the mistake a user actually makes, by analogy with
        # ``Engine``, and it is one of the four colliding names -- so which
        # exception surfaces is version-dependent. Pinned rather than skipped.
        expected = UnsupportedCall if sys.version_info >= (3, 11) else TypeError
        with mock.patch('pcapkit.foundation.extraction.Extractor.register_traceflow') as register:
            with self.assertRaises(expected):
                class Collides(TraceFlow[str, DummyBuffer, DummyIndex, DummyPacket],
                               name='collides-with-ABCMeta-on-3.10'):
                    def dump(self, packet: DummyPacket) -> None:
                        self.trace(packet)

                    def trace(self, packet: DummyPacket, *, output: bool = False):
                        return object() if output else 'flow'

                    def submit(self) -> tuple[DummyIndex, ...]:
                        return ()

        register.assert_not_called()

    def test_traceflow_registry_property_reads_the_extractor_table(self) -> None:
        """``TraceFlow.registry`` is a class-level accessor, as on ``EnumSchema``.

        Note it is the *flow tracing* registry, not
        :attr:`TraceFlow.__output__`, which is the separate output-dumper table
        this same class owns.

        """
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.traceflow.traceflow import TraceFlow

        self.assertIs(TraceFlow.registry, Extractor.__traceflow__)
        self.assertIsNot(TraceFlow.registry, TraceFlow.__output__)


if __name__ == '__main__':
    unittest.main()
