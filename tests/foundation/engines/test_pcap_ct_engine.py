"""Unit tests for :mod:`pcapkit.foundation.engines.pcap_ct`.

The engine is exercised with a stand-in for :class:`pcap.pcap`, so that the
routing decisions -- format gating, capability warnings, output, storage, close --
are covered whether or not `pcap-ct`_ is installed. One test at the end runs the
real backend against a committed capture, and skips when it is absent.

`pcap-ct`_ and upstream `pypcap`_ both install a top-level :mod:`pcap`, so the
tests here look almost exactly like :mod:`tests.foundation.engines.test_pypcap_engine`.
They are kept apart because the engines are: each names its own toolkit and its
own module marker, and a shared test could not tell which of the two it had
proved anything about.

.. _pcap-ct: https://pypi.org/project/pcap-ct/
.. _pypcap: https://github.com/pynetwork/pypcap

"""
from __future__ import annotations

import importlib
import importlib.util
import io
import os
import tempfile
import types
import unittest
from unittest import mock

from tests._support import close_extractor, purge_modules, sample_path

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


def _importable(*modules: str) -> bool:
    """Test if every named module can actually be imported."""
    for module in modules:
        try:
            importlib.import_module(module)
        except ImportError:
            return False
    return True


#: Whether the `pcap-ct`_ backend is present. Gated on ``pcap._pcap`` rather than
#: on ``pcap``, for the same reason :attr:`PCAP_CT.__engine_module__
#: <pcapkit.foundation.engines.pcap_ct.PCAP_CT.__engine_module__>` names it:
#: upstream `pypcap`_ owns the ``pcap`` name just as legitimately and ships it as
#: a single extension module, so the submodule import is what tells the two
#: distributions apart. Importing rather than :func:`importlib.util.find_spec`,
#: since ``find_spec('pcap._pcap')`` has to import the ``pcap`` parent anyway and
#: raises rather than answering when that parent is not a package.
HAS_PCAP_CT = _importable('pcap._pcap')

#: Magic number of a little-endian, microsecond-resolution PCAP savefile.
PCAP_MAGIC = b'\xd4\xc3\xb2\xa1'
#: Magic number of a PCAP-NG section header block.
PCAPNG_MAGIC = b'\x0a\x0d\x0d\x0a'

#: Frame count of :file:`examples/captures/in.pcap`, and the timestamp and
#: capture length of its first frame. Committed capture, so these are fixed.
IN_PCAP_FRAMES = 6
IN_PCAP_FIRST_TIMESTAMP = 1511106545.471719
IN_PCAP_FIRST_LENGTH = 86


class OutputSink:
    """Stand-in for a :class:`dictdumper.dumper.Dumper`, recording what it is handed."""

    kind = 'unit'

    def __init__(self) -> None:
        self.paths: list[str] = []
        self.records: list[tuple[object, str | None]] = []

    def __call__(self, *args, **kwargs):
        if len(args) == 1 and isinstance(args[0], str) and not kwargs:
            self.paths.append(args[0])
            return self
        self.records.append((args[0] if args else None, kwargs.get('name')))
        return self


class FrameIterator:
    """Iterator over a :class:`FakeHandle`'s frames, and a separate object from it.

    It carries a ``close`` of its own purely so that closing the wrong thing is
    observable. The engine keeps the handle and the iterator apart precisely so
    that :meth:`PCAP_CT.close <pcapkit.foundation.engines.pcap_ct.PCAP_CT.close>`
    does not have to assume ``iter(handle) is handle``, and a stand-in that
    iterated itself would make that distinction untestable.

    """

    def __init__(self, frames) -> None:
        self._iter = iter(frames)
        self.closed = 0

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._iter)

    def close(self) -> None:
        self.closed += 1


class FakeHandle:
    """Stand-in for :class:`pcap.pcap`, yielding ``(timestamp, bytes)`` pairs."""

    def __init__(self, frames=None, datalink: int = 1) -> None:
        self.frames = list(frames if frames is not None else [(1.5, b'payload')])
        self.iterator: FrameIterator | None = None
        self._datalink = datalink
        self.closed = 0
        self.setup = 0

    def datalink(self) -> int:
        return self._datalink

    def __iter__(self) -> FrameIterator:
        self.setup += 1
        self.iterator = FrameIterator(self.frames)
        return self.iterator

    def close(self) -> None:
        self.closed += 1


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PCAP_CTEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

        handle, path = tempfile.mkstemp(suffix='.pcap')
        os.close(handle)
        self.addCleanup(os.unlink, path)
        self.ifnm = path

    def make_extractor(self, **overrides):
        sink = OutputSink()
        reasm = types.SimpleNamespace(ipv4=mock.Mock(), ipv6=mock.Mock(), tcp=mock.Mock())
        trace = types.SimpleNamespace(tcp=mock.Mock())
        values = {
            '_ifile': io.BytesIO(b'capture'),
            '_ifnm': self.ifnm,
            '_ofile': sink,
            '_ofnm': 'out',
            '_fext': 'json',
            '_offmt': None,
            '_flag_q': False,
            '_flag_f': False,
            '_flag_v': False,
            '_flag_r': False,
            '_flag_t': False,
            '_flag_d': True,
            '_ipv4': False,
            '_ipv6': False,
            '_tcp': False,
            '_reasm': reasm,
            '_trace': trace,
            '_frame': [],
            '_frnum': 0,
            '_exlyr': 'none',
            '_exptl': 'null',
            '_vfunc': mock.Mock(),
            'magic_number': PCAP_MAGIC,
        }
        values.update(overrides)
        return types.SimpleNamespace(**values), sink

    def engine(self, extractor):
        from pcapkit.foundation.engines import _pcap_backend
        from pcapkit.foundation.engines.pcap_ct import PCAP_CT

        # ``__new__`` rather than the constructor: ``PCAP_CT.__init__`` insists on
        # the real ``pcap-ct`` being importable, and these tests are meant to run
        # with neither ``pcap-ct`` nor ``pypcap`` installed. The constructor gets
        # its own tests below, against a stand-in module.
        engine = PCAP_CT.__new__(PCAP_CT)
        engine._expkg = types.SimpleNamespace(pcap=FakeHandle)
        engine._handle = None
        engine._extmp = None
        engine._dlink = None
        engine._closed = False
        engine._backend = _pcap_backend.Probe(
            _pcap_backend.PCAP_CT, '1.3.0b3', '/stub/site-packages/pcap/__init__.py',
            None, False, ('pcap-ct',),
        )
        engine._extractor = extractor
        return engine

    ##########################################################################
    # unsupported_reason() and __init__()
    ##########################################################################

    def fake_pcap_module(self, *, is_pcap_ct: bool):
        """A stand-in :mod:`pcap` module, as one distribution or the other.

        ``pcap-ct`` ships :mod:`pcap` as a package whose ``__init__`` does
        ``from ._pcap import *``, so the submodule ends up bound as an attribute;
        upstream ``pypcap`` ships a single extension module with no such
        attribute. That difference is what
        :func:`pcapkit.foundation.engines._pcap_backend.identify` keys on.

        """
        module = types.ModuleType('pcap')
        module.pcap = FakeHandle  # type: ignore[attr-defined]
        module.__version__ = '1.3.0b3' if is_pcap_ct else '1.3.0'  # type: ignore[attr-defined]
        module.__file__ = ('/stub/site-packages/pcap/__init__.py' if is_pcap_ct
                           else '/stub/site-packages/pcap.cpython-310.so')
        if is_pcap_ct:
            module._pcap = types.ModuleType('pcap._pcap')  # type: ignore[attr-defined]
        return module

    def installed(self, *names: str):
        """Patch the distribution metadata to report exactly ``names``."""
        from pcapkit.foundation.engines import _pcap_backend

        return mock.patch.object(_pcap_backend, 'installed_distributions',
                                 return_value=names)

    def test_unsupported_reason_is_silent_on_pcap_ct(self) -> None:
        from pcapkit.foundation.engines.pcap_ct import PCAP_CT

        with mock.patch.dict('sys.modules', {'pcap': self.fake_pcap_module(is_pcap_ct=True)}):
            with self.installed('pcap-ct'):
                self.assertIsNone(PCAP_CT.unsupported_reason())

    def test_unsupported_reason_names_upstream_pypcap_and_its_engine(self) -> None:
        from pcapkit.foundation.engines.pcap_ct import PCAP_CT

        with mock.patch.dict('sys.modules', {'pcap': self.fake_pcap_module(is_pcap_ct=False)}):
            with self.installed('pypcap'):
                reason = PCAP_CT.unsupported_reason()

        self.assertIsNotNone(reason)
        self.assertIn('pypcap', reason)
        self.assertIn('engine=pypcap', reason)

    def test_unsupported_reason_reports_a_missing_system_libpcap(self) -> None:
        from pcapkit.foundation.engines.pcap_ct import PCAP_CT

        # The important case, and measured rather than hypothetical: ``pcap-ct``
        # imports the ``libpcap`` distribution, whose Linux loader raises
        # ``OSError: Cannot find libpcap.so library`` when no system libpcap is
        # findable. OSError is not an ImportError, so ``Extractor.import_test``
        # lets it through and the extraction dies. Reporting it here turns that
        # into the ordinary "engine unavailable" fall back.
        with mock.patch('importlib.import_module',
                        side_effect=OSError('Cannot find libpcap.so library')):
            with self.installed('pcap-ct'):
                reason = PCAP_CT.unsupported_reason()

        self.assertIsNotNone(reason)
        self.assertIn('installed but unusable', reason)
        self.assertIn('Cannot find libpcap.so library', reason)

    def test_unsupported_reason_is_silent_when_no_pcap_is_installed(self) -> None:
        from pcapkit.foundation.engines.pcap_ct import PCAP_CT

        with mock.patch('importlib.import_module', side_effect=ImportError('no pcap')):
            with self.installed():
                self.assertIsNone(PCAP_CT.unsupported_reason())

    def test_unsupported_reason_declares_no_python_version_bound(self) -> None:
        from pcapkit.foundation.engines.pcap_ct import PCAP_CT

        # Verified against real installations on 3.10.20 and 3.14.7, both of which
        # read in.pcap identically, so this engine covers the whole supported
        # range and must not refuse either end of it.
        for version in ((3, 10, 0, 'final', 0), (3, 14, 0, 'final', 0)):
            with self.subTest(version=version):
                with mock.patch.dict('sys.modules',
                                     {'pcap': self.fake_pcap_module(is_pcap_ct=True)}):
                    with self.installed('pcap-ct'):
                        with mock.patch('sys.version_info', version):
                            self.assertIsNone(PCAP_CT.unsupported_reason())

    def test_init_refuses_upstream_pypcap_and_names_the_engine_for_it(self) -> None:
        from pcapkit.foundation.engines.pcap_ct import PCAP_CT
        from pcapkit.utilities.exceptions import UnsupportedCall

        extractor, _ = self.make_extractor()
        with mock.patch.dict('sys.modules', {'pcap': self.fake_pcap_module(is_pcap_ct=False)}):
            with self.installed('pypcap'):
                with self.assertRaises(UnsupportedCall) as caught:
                    PCAP_CT(extractor)

        message = str(caught.exception)
        self.assertIn('pypcap', message)
        self.assertIn('engine=pypcap', message)

    def test_init_accepts_pcap_ct_and_reports_the_backend(self) -> None:
        from pcapkit.foundation.engines.pcap_ct import PCAP_CT

        extractor, _ = self.make_extractor()
        module = self.fake_pcap_module(is_pcap_ct=True)
        with mock.patch.dict('sys.modules', {'pcap': module}):
            with self.installed('pcap-ct'):
                engine = PCAP_CT(extractor)

        self.assertIs(engine._expkg, module)
        self.assertIsNone(engine._handle)
        self.assertFalse(engine._closed)

        self.assertIn('pcap-ct', engine.backend)
        self.assertIn('1.3.0b3', engine.backend)
        self.assertIn('pcap/__init__.py', engine.backend)

    def test_init_warns_when_both_distributions_are_installed(self) -> None:
        from pcapkit.foundation.engines.pcap_ct import PCAP_CT
        from pcapkit.utilities.warnings import EngineWarning

        # This engine still works in that state -- ``pcap-ct`` is the one that wins
        # the import -- so it warns and carries on rather than refusing.
        extractor, _ = self.make_extractor()
        with mock.patch.dict('sys.modules', {'pcap': self.fake_pcap_module(is_pcap_ct=True)}):
            with self.installed('pypcap', 'pcap-ct'):
                with mock.patch('pcapkit.foundation.engines.pcap_ct.warn') as warn:
                    engine = PCAP_CT(extractor)

        collisions = [call.args[0] for call in warn.call_args_list
                      if len(call.args) > 1 and call.args[1] is EngineWarning]
        self.assertEqual(len(collisions), 1, warn.call_args_list)
        self.assertIn('pypcap', collisions[0])
        self.assertIn('pcap-ct', collisions[0])
        self.assertIn('shadowed', collisions[0])
        self.assertIn('pcap-ct', engine.backend)

    def test_init_does_not_warn_when_only_one_is_installed(self) -> None:
        from pcapkit.foundation.engines.pcap_ct import PCAP_CT
        from pcapkit.utilities.warnings import EngineWarning

        extractor, _ = self.make_extractor()
        with mock.patch.dict('sys.modules', {'pcap': self.fake_pcap_module(is_pcap_ct=True)}):
            with self.installed('pcap-ct'):
                with mock.patch('pcapkit.foundation.engines.pcap_ct.warn') as warn:
                    PCAP_CT(extractor)

        self.assertEqual([call for call in warn.call_args_list
                          if len(call.args) > 1 and call.args[1] is EngineWarning], [])

    ##########################################################################
    # run()
    ##########################################################################

    def test_run_opens_handle_and_records_link_type(self) -> None:
        from pcapkit.const.reg.linktype import LinkType

        extractor, _ = self.make_extractor()
        engine = self.engine(extractor)

        handle = FakeHandle()
        with mock.patch.object(engine._expkg, 'pcap', return_value=handle) as ctor:
            engine.run()

        ctor.assert_called_once_with(name=self.ifnm, promisc=False)
        self.assertEqual(engine.dlink, LinkType.ETHERNET)

        # the handle and the iterator are held separately, and it is the iterator
        # that frames are read through
        self.assertIs(engine._handle, handle)
        self.assertEqual(handle.setup, 1)
        self.assertIs(engine._extmp, handle.iterator)
        self.assertIsNot(engine._extmp, handle)
        self.assertEqual(next(engine._extmp), (1.5, b'payload'))

    def test_run_warns_on_layer_and_protocol_threshold(self) -> None:
        from pcapkit.utilities.warnings import AttributeWarning

        # NOTE: ``BaseWarning.__init__`` installs an ``ignore`` filter for its own
        # category outside development mode, so the warning never reaches
        # ``assertWarns``; the ``warn`` call itself is what can be observed.
        for overrides in ({'_exlyr': 'internet'}, {'_exptl': 'tcp'}):
            with self.subTest(overrides=overrides):
                extractor, _ = self.make_extractor(**overrides)
                engine = self.engine(extractor)
                with mock.patch.object(engine._expkg, 'pcap', return_value=FakeHandle()):
                    with mock.patch('pcapkit.foundation.engines.pcap_ct.warn') as warn:
                        engine.run()
                self.assertEqual(warn.call_count, 1)
                self.assertIn('protocol and layer threshold', warn.call_args.args[0])
                self.assertIs(warn.call_args.args[1], AttributeWarning)

    def test_run_rejects_pcapng_rather_than_reading_it_approximately(self) -> None:
        from pcapkit.utilities.exceptions import FormatError

        # the vendored libpcap *can* read a PCAP-NG savefile, but only ever reports
        # one link type for it, so the engine refuses rather than applying one
        # interface's link type to every frame
        extractor, _ = self.make_extractor(magic_number=PCAPNG_MAGIC)
        engine = self.engine(extractor)
        with mock.patch.object(engine._expkg, 'pcap', return_value=FakeHandle()) as ctor:
            with self.assertRaises(FormatError):
                engine.run()
        ctor.assert_not_called()

    def test_run_rejects_input_that_is_not_a_file_on_disk(self) -> None:
        from pcapkit.utilities.exceptions import UnsupportedCall

        extractor, _ = self.make_extractor(_ifnm=os.path.join(self.ifnm, 'nope.pcap'))
        engine = self.engine(extractor)
        with mock.patch.object(engine._expkg, 'pcap', return_value=FakeHandle()) as ctor:
            with self.assertRaises(UnsupportedCall):
                engine.run()
        ctor.assert_not_called()

    def test_run_disables_reassembly_and_flow_tracing(self) -> None:
        from pcapkit.utilities.warnings import AttributeWarning

        extractor, _ = self.make_extractor(_flag_r=True, _flag_t=True, _ipv4=True,
                                           _ipv6=True, _tcp=True)
        engine = self.engine(extractor)
        with mock.patch.object(engine._expkg, 'pcap', return_value=FakeHandle()):
            with mock.patch('pcapkit.foundation.engines.pcap_ct.warn') as warn:
                engine.run()

        messages = [call.args[0] for call in warn.call_args_list
                    if call.args[1] is AttributeWarning]
        self.assertTrue(any('reassembly' in message for message in messages), messages)
        self.assertTrue(any('flow tracing' in message for message in messages), messages)

        self.assertFalse(extractor._flag_r)
        self.assertFalse(extractor._flag_t)
        self.assertIsNone(extractor._reasm.ipv4)
        self.assertIsNone(extractor._reasm.ipv6)
        self.assertIsNone(extractor._reasm.tcp)
        self.assertIsNone(extractor._trace.tcp)

    def test_run_leaves_disabled_reassembly_and_tracing_untouched(self) -> None:
        extractor, _ = self.make_extractor(_flag_r=True, _flag_t=True)
        original_reasm, original_trace = extractor._reasm, extractor._trace
        engine = self.engine(extractor)
        with mock.patch.object(engine._expkg, 'pcap', return_value=FakeHandle()):
            engine.run()

        # no protocol was requested, so there is nothing to warn about or replace
        self.assertTrue(extractor._flag_r)
        self.assertTrue(extractor._flag_t)
        self.assertIs(extractor._reasm, original_reasm)
        self.assertIs(extractor._trace, original_trace)

    def test_run_installs_verbose_handler_reporting_the_raw_chain(self) -> None:
        extractor, _ = self.make_extractor(_flag_v=True)
        engine = self.engine(extractor)
        with mock.patch.object(engine._expkg, 'pcap', return_value=FakeHandle()):
            engine.run()

        with mock.patch('builtins.print') as printer:
            extractor._frnum = 3
            extractor._vfunc(extractor, (1.5, b'payload'))
        printer.assert_called_once()
        self.assertIn('ETHERNET:Raw', printer.call_args.args[0])

    ##########################################################################
    # read_frame()
    ##########################################################################

    def prepared(self, **overrides):
        extractor, sink = self.make_extractor(**overrides)
        engine = self.engine(extractor)
        handle = FakeHandle(frames=[(1.5, b'payload'), (2.5, b'second')])
        with mock.patch.object(engine._expkg, 'pcap', return_value=handle):
            engine.run()
        return extractor, sink, engine

    def test_read_frame_returns_the_pair_and_routes_output_and_storage(self) -> None:
        extractor, sink, engine = self.prepared()

        frame = engine.read_frame()

        self.assertEqual(frame, (1.5, b'payload'))
        self.assertEqual(extractor._frnum, 1)
        extractor._vfunc.assert_called_once_with(extractor, frame)
        self.assertEqual(sink.records[-1][1], 'Frame 1')
        self.assertEqual(sink.records[-1][0]['timestamp'], 1.5)
        self.assertEqual(sink.records[-1][0]['packet'], b'payload')
        self.assertEqual(sink.records[-1][0]['ETHERNET'], {'raw_len': 7, 'raw': b'payload'})
        self.assertEqual(extractor._offmt, 'unit')
        self.assertEqual(extractor._frame, [frame])

        self.assertEqual(engine.read_frame(), (2.5, b'second'))
        self.assertEqual(extractor._frnum, 2)
        with self.assertRaises(StopIteration):
            engine.read_frame()

    def test_read_frame_splits_files_when_asked(self) -> None:
        extractor, sink, engine = self.prepared(_flag_f=True)
        engine.read_frame()
        self.assertEqual(sink.paths[-1], 'out/Frame 1.json')

    def test_read_frame_writes_nothing_and_stores_nothing_when_disabled(self) -> None:
        extractor, sink, engine = self.prepared(_flag_q=True, _flag_d=False)
        engine.read_frame()
        self.assertEqual(sink.records, [])
        self.assertEqual(sink.paths, [])
        self.assertEqual(extractor._frame, [])
        self.assertIsNone(extractor._offmt)

    ##########################################################################
    # close()
    ##########################################################################

    def test_close_is_idempotent_and_tolerates_an_unopened_engine(self) -> None:
        extractor, _, engine = self.prepared()
        handle = engine._handle

        engine.close()
        engine.close()
        self.assertEqual(handle.closed, 1)
        # the savefile belongs to the handle, not to the iterator read off it
        self.assertEqual(handle.iterator.closed, 0)

        extractor, _ = self.make_extractor()
        unopened = self.engine(extractor)
        unopened.close()  # must not raise

    ##########################################################################
    # The real backend.
    ##########################################################################

    @unittest.skipUnless(HAS_PCAP_CT, 'pcap-ct not installed')
    def test_the_real_backend_reads_a_committed_capture(self) -> None:
        from pcapkit.foundation.engines.pcap_ct import PCAP_CT
        from pcapkit.interface import extract
        from pcapkit.utilities.warnings import EngineWarning

        with mock.patch('pcapkit.foundation.extraction.warn') as warn:
            extractor = extract(fin=sample_path('in.pcap'), engine='pcap_ct',
                                store=True, nofile=True)
        self.addCleanup(close_extractor, extractor)

        # A missing engine module only warns and falls back to pcapkit's own
        # parser, so a successful extraction proves nothing on its own -- it is the
        # absence of that warning, plus the engine actually on the extractor, that
        # says this ran through ``pcap-ct``.
        engines = [call.args[0] for call in warn.call_args_list
                   if len(call.args) > 1 and call.args[1] is EngineWarning]
        self.assertEqual(engines, [], "'pcap_ct' was replaced by the fallback engine")
        self.assertEqual(extractor._exnam, 'pcap_ct')
        self.assertIsInstance(extractor.engine, PCAP_CT)
        self.assertEqual(type(extractor.engine).__engine_name__, 'PCAP_CT')

        self.assertEqual(extractor.length, IN_PCAP_FRAMES)
        self.assertEqual(len(extractor.frame), IN_PCAP_FRAMES)

        # a fallback would have produced ``Frame`` objects, not bare pairs
        timestamp, packet = extractor.frame[0]
        self.assertEqual(timestamp, IN_PCAP_FIRST_TIMESTAMP)
        self.assertEqual(len(packet), IN_PCAP_FIRST_LENGTH)


if __name__ == '__main__':
    unittest.main()
