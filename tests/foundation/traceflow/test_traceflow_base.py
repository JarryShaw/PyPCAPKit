from __future__ import annotations

import importlib.util
import pathlib
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

        register.assert_called_once_with('defaulttrace', Default)


if __name__ == '__main__':
    unittest.main()
