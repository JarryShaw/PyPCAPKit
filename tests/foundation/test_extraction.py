from __future__ import annotations

import importlib.util
import io
import pathlib
import sys
import tempfile
import types
import unittest
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class ClosableBytesIO(io.BytesIO):
    def __init__(self, data: bytes = b'') -> None:
        super().__init__(data)
        self.closed_by_test = False

    def close(self) -> None:
        self.closed_by_test = True
        super().close()


class NonSeekableBytesIO(io.BytesIO):
    name = 'stream.pcap'

    def seekable(self) -> bool:
        return False


class NamedBufferedReader(io.BufferedReader):
    def __init__(self, data: bytes, name: str) -> None:
        self._name = name
        super().__init__(io.BytesIO(data))

    @property
    def name(self) -> str:
        return self._name


class FakeEngine:
    name = 'Fake'
    module = 'fake.module'
    MAGIC_NUMBER = (b'fake',)

    def __init__(self, extractor) -> None:
        self.extractor = extractor
        self.run_calls = 0
        self.close_calls = 0
        self.read_frame = mock.Mock(side_effect=StopIteration)

    def run(self) -> None:
        self.run_calls += 1

    def close(self) -> None:
        self.close_calls += 1


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ExtractorTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _bare_extractor(self):
        from pcapkit.foundation.extraction import Extractor

        extractor = object.__new__(Extractor)
        extractor._frnum = 3
        extractor._ifnm = 'input.pcap'
        extractor._ofnm = 'output.txt'
        extractor._offmt = 'tree'
        extractor._flag_q = False
        extractor._flag_d = True
        extractor._flag_r = True
        extractor._flag_t = True
        extractor._ipv4 = True
        extractor._ipv6 = True
        extractor._tcp = True
        extractor._frame = ['frame']
        extractor._reasm = types.SimpleNamespace(
            ipv4=types.SimpleNamespace(datagram=('ipv4',)),
            ipv6=types.SimpleNamespace(datagram=('ipv6',)),
            tcp=types.SimpleNamespace(datagram=('tcp',)),
        )
        extractor._trace = types.SimpleNamespace(
            tcp=types.SimpleNamespace(index=('trace',)),
        )
        extractor._exeng = FakeEngine(extractor)
        extractor._magic = b'fake'
        extractor._ifile = ClosableBytesIO(b'data')
        extractor._flag_s = False
        extractor._flag_e = False
        extractor._flag_a = False
        extractor._flag_n = False
        return extractor

    def test_properties_success_and_unsupported_paths(self) -> None:
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.utilities.exceptions import UnsupportedCall

        extractor = self._bare_extractor()
        self.assertEqual(extractor.length, 3)
        self.assertEqual(extractor.format, 'tree')
        self.assertEqual(extractor.input, 'input.pcap')
        self.assertEqual(extractor.output, 'output.txt')
        self.assertEqual(extractor.frame, ('frame',))
        self.assertEqual(extractor.reassembly.ipv4, ('ipv4',))
        self.assertEqual(extractor.reassembly.ipv6, ('ipv6',))
        self.assertEqual(extractor.reassembly.tcp, ('tcp',))
        self.assertEqual(extractor.trace.tcp, ('trace',))
        self.assertIs(extractor.engine, extractor._exeng)
        self.assertEqual(extractor.magic_number, b'fake')

        extractor._ipv4 = extractor._ipv6 = extractor._tcp = False
        self.assertIsNone(extractor.reassembly.ipv4)
        self.assertIsNone(extractor.trace.tcp)

        unsupported = object.__new__(Extractor)
        unsupported._flag_q = True
        unsupported._flag_d = False
        unsupported._flag_r = False
        unsupported._flag_t = False
        with self.assertRaises(UnsupportedCall):
            _ = unsupported.format
        with self.assertRaises(UnsupportedCall):
            _ = unsupported.output
        with self.assertRaises(UnsupportedCall):
            _ = unsupported.frame
        with self.assertRaises(UnsupportedCall):
            _ = unsupported.reassembly
        with self.assertRaises(UnsupportedCall):
            _ = unsupported.trace

    def test_register_helpers_validate_descriptors_and_overwrite_warnings(self) -> None:
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.dumpkit.null import NotImplementedIO
        from pcapkit.foundation.engines.engine import Engine
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.reassembly.reassembly import Reassembly
        from pcapkit.foundation.traceflow.traceflow import TraceFlow
        from pcapkit.utilities.exceptions import RegistryError

        class UnitEngine(Engine[str]):
            __engine_name__ = 'UnitEngine'
            __engine_module__ = __name__

            def run(self) -> None:
                pass

            def read_frame(self) -> str:
                return 'frame'

        fake_module = types.ModuleType('unit_extraction_engine_mod')
        fake_module.UnitEngine = UnitEngine
        sys.modules['unit_extraction_engine_mod'] = fake_module
        self.addCleanup(lambda: sys.modules.pop('unit_extraction_engine_mod', None))

        with mock.patch('pcapkit.foundation.extraction.Extractor.register_reassembly'):
            class UnitReassembly(Reassembly[object, object, tuple[str], object],
                                 protocol='unit-reassembly'):
                def reassembly(self, info: object) -> None:
                    pass

                def submit(self, buf: object, **kwargs: object) -> list[object]:
                    return []

        with mock.patch('pcapkit.foundation.extraction.Extractor.register_traceflow'):
            class UnitTraceFlow(TraceFlow[str, object, object, object], protocol='unit-trace'):
                def dump(self, packet: object) -> None:
                    pass

                def trace(self, packet: object, *, output: bool = False):
                    return object() if output else 'trace'

                def submit(self) -> tuple[object, ...]:
                    return ()

        fake_reasm_module = types.ModuleType('unit_extraction_reasm_mod')
        fake_reasm_module.UnitReassembly = UnitReassembly
        sys.modules['unit_extraction_reasm_mod'] = fake_reasm_module
        self.addCleanup(lambda: sys.modules.pop('unit_extraction_reasm_mod', None))

        fake_trace_module = types.ModuleType('unit_extraction_trace_mod')
        fake_trace_module.UnitTraceFlow = UnitTraceFlow
        sys.modules['unit_extraction_trace_mod'] = fake_trace_module
        self.addCleanup(lambda: sys.modules.pop('unit_extraction_trace_mod', None))

        with self.assertRaises(RegistryError):
            Extractor.register_dumper('bad', object, '.bad')  # type: ignore[arg-type]
        with self.assertRaises(RegistryError):
            Extractor.register_engine('bad', object)  # type: ignore[arg-type]
        with self.assertRaises(RegistryError):
            Extractor.register_reassembly('bad', object)  # type: ignore[arg-type]
        with self.assertRaises(RegistryError):
            Extractor.register_traceflow('bad', object)  # type: ignore[arg-type]

        with mock.patch('pcapkit.foundation.extraction.warn') as warn:
            Extractor.register_dumper('json', NotImplementedIO, '.unit')
        warn.assert_called_once()
        Extractor.register_dumper('unit-descriptor',
                                  ModuleDescriptor('pcapkit.dumpkit', 'NotImplementedIO'),
                                  '.unit')

        with mock.patch('pcapkit.foundation.extraction.warn') as warn:
            Extractor.register_engine('dpkt', UnitEngine)
        warn.assert_called_once()
        Extractor.register_engine('unit-engine-descriptor',
                                  ModuleDescriptor('unit_extraction_engine_mod', 'UnitEngine'))

        with mock.patch('pcapkit.foundation.extraction.warn') as warn:
            Extractor.register_reassembly('ipv4', UnitReassembly)
        warn.assert_called_once()
        Extractor.register_reassembly('unit-reasm-descriptor',
                                      ModuleDescriptor('unit_extraction_reasm_mod', 'UnitReassembly'))

        with mock.patch('pcapkit.foundation.extraction.warn') as warn:
            Extractor.register_traceflow('tcp', UnitTraceFlow)
        warn.assert_called_once()
        Extractor.register_traceflow('unit-trace-descriptor',
                                     ModuleDescriptor('unit_extraction_trace_mod', 'UnitTraceFlow'))

    def test_import_test_and_make_name_paths(self) -> None:
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.utilities.exceptions import FileNotFound, FormatError

        self.assertIsNotNone(Extractor.import_test('io'))
        with mock.patch('pcapkit.foundation.extraction.warn') as warn:
            self.assertIsNone(Extractor.import_test('missing_engine_for_unit_tests',
                                                   name='MissingEngine'))
        warn.assert_called_once()

        with tempfile.TemporaryDirectory() as tempdir:
            temp = pathlib.Path(tempdir)
            capture = temp / 'capture.pcap'
            capture.write_bytes(b'pcap')
            no_ext_capture = temp / 'capture'
            no_ext_capture.write_bytes(b'pcap')

            self.assertEqual(
                Extractor.make_name(str(capture), str(temp / 'out'), 'json'),
                (str(capture), str(temp / 'out.json'), 'json', '.json', False),
            )
            self.assertEqual(
                Extractor.make_name(str(capture.with_suffix('')), str(temp / 'raw.out'),
                                    'tree', extension=False),
                (str(no_ext_capture), str(temp / 'raw.out'), 'tree', '.txt', False),
            )
            self.assertEqual(
                Extractor.make_name(str(capture), str(temp / 'frames'), 'json', files=True),
                (str(capture), str(temp / 'frames'), 'json', '.json', True),
            )
            self.assertEqual(
                Extractor.make_name(str(capture), str(temp / 'ignored'), 'json', nofile=True),
                (str(capture), None, 'json', None, False),
            )

            stream = io.BytesIO(b'capture')
            stream.name = str(capture)
            self.assertEqual(Extractor.make_name(stream, str(temp / 'out'), 'json')[0],
                             str(capture))

            with self.assertRaises(FileNotFound):
                Extractor.make_name(str(temp / 'missing'), str(temp / 'out'), 'json',
                                    extension=False)
            with self.assertRaises(FormatError):
                Extractor.make_name(str(capture), str(temp / 'out'), 'unknown-unit-format')

    def test_run_selects_registered_default_and_error_engines(self) -> None:
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.utilities.exceptions import FormatError

        extractor = self._bare_extractor()
        extractor._exnam = 'fake'
        extractor.__engine__ = {'fake': FakeEngine}
        extractor.record_frames = mock.Mock()
        with mock.patch.object(Extractor, 'import_test', return_value=object()):
            extractor.run()
        self.assertIsInstance(extractor._exeng, FakeEngine)
        extractor.record_frames.assert_called_once()

        descriptor_module = types.ModuleType('unit_run_engine_mod')
        descriptor_module.FakeEngine = FakeEngine
        sys.modules['unit_run_engine_mod'] = descriptor_module
        self.addCleanup(lambda: sys.modules.pop('unit_run_engine_mod', None))
        descriptor = self._bare_extractor()
        descriptor._exnam = 'fake'
        descriptor.__engine__ = {
            'fake': __import__('pcapkit.corekit.module').corekit.module.ModuleDescriptor(
                'unit_run_engine_mod', 'FakeEngine'
            ),
        }
        descriptor.record_frames = mock.Mock()
        with mock.patch.object(Extractor, 'import_test', return_value=object()):
            descriptor.run()
        self.assertIsInstance(descriptor._exeng, FakeEngine)

        fallback = self._bare_extractor()
        fallback._exnam = 'missing'
        fallback.__engine__ = {'missing': FakeEngine}
        fallback._magic = b'pcap'
        fallback.record_frames = mock.Mock()
        fake_pcap = type('FakePCAP', (FakeEngine,), {'MAGIC_NUMBER': (b'pcap',)})
        with mock.patch.object(Extractor, 'import_test', return_value=None):
            with mock.patch('pcapkit.foundation.extraction.PCAP_Engine', fake_pcap):
                with mock.patch('pcapkit.foundation.extraction.PCAPNG_Engine', types.SimpleNamespace(MAGIC_NUMBER=(b'ng!!',))):
                    fallback.run()
        self.assertEqual(fallback._exnam, 'default')
        self.assertIsInstance(fallback._exeng, fake_pcap)

        unsupported = self._bare_extractor()
        unsupported._exnam = 'weird'
        unsupported.__engine__ = {}
        unsupported._magic = b'ng!!'
        unsupported.record_frames = mock.Mock()
        fake_pcapng = type('FakePCAPNG', (FakeEngine,), {'MAGIC_NUMBER': (b'ng!!',)})
        with mock.patch('pcapkit.foundation.extraction.PCAP_Engine', types.SimpleNamespace(MAGIC_NUMBER=(b'pcap',))):
            with mock.patch('pcapkit.foundation.extraction.PCAPNG_Engine', fake_pcapng):
                unsupported.run()
        self.assertIsInstance(unsupported._exeng, fake_pcapng)

        bad = self._bare_extractor()
        bad._exnam = 'default'
        bad._magic = b'bad!'
        with self.assertRaises(FormatError):
            with mock.patch('pcapkit.foundation.extraction.PCAP_Engine', types.SimpleNamespace(MAGIC_NUMBER=(b'pcap',))):
                with mock.patch('pcapkit.foundation.extraction.PCAPNG_Engine', types.SimpleNamespace(MAGIC_NUMBER=(b'ng!!',))):
                    bad.run()

    def test_record_header_record_frames_iteration_call_and_cleanup(self) -> None:
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.utilities.exceptions import CallableError, FormatError, IterableError

        extractor = self._bare_extractor()
        extractor._magic = b'pcap'
        extractor._ifile = mock.Mock()
        fake_pcap = type('FakePCAP', (FakeEngine,), {'MAGIC_NUMBER': (b'pcap',)})
        with mock.patch('pcapkit.foundation.extraction.PCAP_Engine', fake_pcap):
            engine = extractor.record_header()
        self.assertIsInstance(engine, fake_pcap)
        extractor._ifile.seek.assert_called_once()

        extractor._magic = b'ng!!'
        fake_pcapng = type('FakePCAPNG', (FakeEngine,), {'MAGIC_NUMBER': (b'ng!!',)})
        with mock.patch('pcapkit.foundation.extraction.PCAP_Engine', types.SimpleNamespace(MAGIC_NUMBER=(b'pcap',))):
            with mock.patch('pcapkit.foundation.extraction.PCAPNG_Engine', fake_pcapng):
                self.assertIsInstance(extractor.record_header(), fake_pcapng)

        extractor._magic = b'bad!'
        with self.assertRaises(FormatError):
            with mock.patch('pcapkit.foundation.extraction.PCAP_Engine', types.SimpleNamespace(MAGIC_NUMBER=(b'pcap',))):
                with mock.patch('pcapkit.foundation.extraction.PCAPNG_Engine', types.SimpleNamespace(MAGIC_NUMBER=(b'ng!!',))):
                    extractor.record_header()

        auto = self._bare_extractor()
        auto._flag_a = True
        auto._exeng.read_frame = mock.Mock(side_effect=[object(), StopIteration])
        auto.record_frames()
        self.assertTrue(auto._flag_e)

        manual = self._bare_extractor()
        manual._flag_a = False
        manual.record_frames()
        manual._exeng.read_frame.assert_not_called()
        self.assertIs(iter(manual), manual)
        manual._exeng.read_frame = mock.Mock(return_value='frame')
        self.assertEqual(next(manual), 'frame')
        self.assertEqual(manual(), 'frame')

        manual._exeng.read_frame = mock.Mock(side_effect=StopIteration)
        with self.assertRaises(StopIteration):
            next(manual)
        manual._flag_e = False
        manual._exeng.read_frame = mock.Mock(side_effect=EOFError)
        with self.assertRaises(EOFError):
            manual()

        auto_iter = self._bare_extractor()
        auto_iter._flag_a = True
        with self.assertRaises(IterableError):
            iter(auto_iter)
        with self.assertRaises(CallableError):
            auto_iter()

        interrupted = self._bare_extractor()
        interrupted._flag_a = True
        interrupted._exeng.read_frame = mock.Mock(side_effect=KeyboardInterrupt)
        with self.assertRaises(KeyboardInterrupt):
            interrupted.record_frames()
        self.assertTrue(interrupted._flag_e)

        no_eof = self._bare_extractor()
        no_eof._flag_n = True
        no_eof._exeng.read_frame = mock.Mock(side_effect=[EOFError, KeyboardInterrupt])
        with self.assertRaises(KeyboardInterrupt):
            next(no_eof)
        self.assertTrue(no_eof._flag_e)

        auto_no_eof = self._bare_extractor()
        auto_no_eof._flag_a = True
        auto_no_eof._flag_n = True
        auto_no_eof._exeng.read_frame = mock.Mock(side_effect=[EOFError, KeyboardInterrupt])
        with self.assertRaises(KeyboardInterrupt):
            auto_no_eof.record_frames()
        self.assertTrue(auto_no_eof._flag_e)

        call_no_eof = self._bare_extractor()
        call_no_eof._flag_n = True
        call_no_eof._exeng.read_frame = mock.Mock(side_effect=[EOFError, KeyboardInterrupt])
        with self.assertRaises(KeyboardInterrupt):
            call_no_eof()
        self.assertTrue(call_no_eof._flag_e)

        call_interrupt = self._bare_extractor()
        call_interrupt._exeng.read_frame = mock.Mock(side_effect=KeyboardInterrupt)
        with self.assertRaises(KeyboardInterrupt):
            call_interrupt()
        self.assertTrue(call_interrupt._flag_e)

        named_file = self._bare_extractor()
        named_file._flag_s = True
        named_file._ifile = ClosableBytesIO(b'data')
        named_file._cleanup()
        self.assertFalse(named_file._ifile.closed_by_test)

        with manual as ctx:
            self.assertIs(ctx, manual)
        self.assertTrue(manual._ifile.closed_by_test)
        self.assertGreaterEqual(manual._exeng.close_calls, 1)

    def test_constructor_initialises_without_running_when_patched(self) -> None:
        from pcapkit.foundation.extraction import Extractor

        with tempfile.TemporaryDirectory() as tempdir:
            capture = pathlib.Path(tempdir) / 'sample.pcap'
            capture.write_bytes(b'\xa1\xb2\xc3\xd4payload')
            with mock.patch.object(Extractor, 'run') as run:
                extractor = Extractor(str(capture), str(pathlib.Path(tempdir) / 'out'),
                                      format='json', auto=False, verbose=True, ip=True,
                                      tcp=True, reassembly=False, trace=False)
        run.assert_called_once()
        self.assertEqual(extractor.input, str(capture))
        self.assertTrue(extractor._flag_v)
        self.assertTrue(extractor._ipv4)
        self.assertTrue(extractor._ipv6)
        self.assertTrue(extractor._tcp)
        self.assertEqual(extractor.magic_number, b'\xa1\xb2\xc3\xd4')
        extractor._ifile.close()

    def test_constructor_configuration_branches_with_run_patched(self) -> None:
        from pcapkit.foundation.extraction import Extractor

        with tempfile.TemporaryDirectory() as tempdir:
            temp = pathlib.Path(tempdir)
            capture = temp / 'sample.pcap'
            capture.write_bytes(b'\xa1\xb2\xc3\xd4payload')

            with mock.patch.object(Extractor, 'run') as run:
                with mock.patch.object(Extractor, 'make_name',
                                       return_value=(str(capture), str(temp / 'out.json'),
                                                     'json', '.json', False)):
                    defaulted = Extractor()
            run.assert_called_once()
            self.assertEqual(defaulted._ifnm, str(capture))
            self.assertFalse(defaulted._flag_v)
            defaulted._ifile.close()

            verbose_handler = mock.Mock()
            stream = NamedBufferedReader(b'\xa1\xb2\xc3\xd4payload', str(capture))
            with mock.patch.object(Extractor, 'run'):
                streamed = Extractor(stream, str(temp / 'stream-out'), format='json',
                                     auto=False, verbose=verbose_handler, nofile=True)
            self.assertFalse(streamed._flag_s)
            self.assertTrue(streamed._flag_v)
            self.assertIs(streamed._vfunc, verbose_handler)
            self.assertFalse(hasattr(streamed, '_ofile'))
            streamed._ifile.close()

            nonseekable = NonSeekableBytesIO(b'\xa1\xb2\xc3\xd4payload')
            nonseekable.name = str(capture)
            with mock.patch.object(Extractor, 'run'):
                wrapped = Extractor(nonseekable, str(temp / 'wrapped-out'), format='json',
                                    auto=False, nofile=True)
            self.assertEqual(type(wrapped._ifile).__name__, 'SeekableReader')
            wrapped._ifile.close()

            with mock.patch.object(Extractor, 'run'):
                traced = Extractor(str(capture), str(temp / 'trace-out'), format='json',
                                   auto=False, reassembly=True, ip=True, tcp=True,
                                   trace=True, trace_fout=str(temp / 'flows'),
                                   trace_format='json')
            self.assertIsNotNone(traced._reasm.ipv4)
            self.assertIsNotNone(traced._reasm.ipv6)
            self.assertIsNotNone(traced._reasm.tcp)
            self.assertIsNotNone(traced._trace.tcp)
            traced._ifile.close()

            with mock.patch.object(Extractor, 'run'):
                with mock.patch('pcapkit.foundation.extraction.warn') as warn:
                    pyshark_trace = Extractor(str(capture), str(temp / 'pyshark-out'),
                                              format='json', auto=False, engine='pyshark',
                                              trace=True, tcp=True,
                                              trace_fout=str(temp / 'pyshark-flows'),
                                              trace_format='pcap')
            warn.assert_called_once()
            pyshark_trace._ifile.close()

            with mock.patch.object(Extractor, 'run'):
                with mock.patch.object(Extractor, 'make_name',
                                       return_value=(str(capture), str(temp / 'unknown'),
                                                     'unknown-unit-format', None, False)):
                    with mock.patch('pcapkit.foundation.extraction.warn') as warn:
                        unknown_output = Extractor(str(capture), str(temp / 'unknown'),
                                                   format='json', auto=False)
            warn.assert_called_once()
            self.assertTrue(hasattr(unknown_output, '_ofile'))
            unknown_output._ifile.close()


if __name__ == '__main__':
    unittest.main()
