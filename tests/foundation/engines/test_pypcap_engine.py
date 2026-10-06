"""Unit tests for :mod:`pcapkit.foundation.engines.pypcap`.

The engine itself is exercised with a stand-in for :class:`pcap.pcap`, so that the
routing decisions -- format gating, capability warnings, output, storage, close --
are covered whether or not `pypcap`_ is installed. End-to-end agreement with the
``default`` engine lives in :mod:`tests.foundation.engines.test_new_engine_parity`.

.. _pypcap: https://github.com/pynetwork/pypcap

"""
from __future__ import annotations

import importlib.util
import io
import os
import tempfile
import types
import unittest
from unittest import mock

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Magic number of a little-endian, microsecond-resolution PCAP savefile.
PCAP_MAGIC = b'\xd4\xc3\xb2\xa1'
#: Magic number of a PCAP-NG section header block.
PCAPNG_MAGIC = b'\x0a\x0d\x0d\x0a'


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


class FakeHandle:
    """Stand-in for :class:`pcap.pcap`, yielding ``(timestamp, bytes)`` pairs."""

    def __init__(self, frames=None, datalink: int = 1) -> None:
        self.frames = list(frames if frames is not None else [(1.5, b'payload')])
        self._iter = None
        self._datalink = datalink
        self.closed = 0
        self.setup = 0

    def datalink(self) -> int:
        return self._datalink

    def __iter__(self):
        self.setup += 1
        self._iter = iter(self.frames)
        return self

    def __next__(self):
        return next(self._iter)

    def close(self) -> None:
        self.closed += 1


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PyPCAPEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

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
        from pcapkit.foundation.engines.pypcap import PyPCAP

        engine = PyPCAP.__new__(PyPCAP)
        engine._expkg = types.SimpleNamespace(pcap=FakeHandle)
        engine._extmp = None
        engine._dlink = None
        engine._closed = False
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
        :func:`pcapkit.foundation.engines._pcap_backend.identify` keys on, so the
        stand-in only has to reproduce it.

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

    def test_unsupported_reason_is_silent_on_upstream_pypcap(self) -> None:
        from pcapkit.foundation.engines.pypcap import PyPCAP

        with mock.patch.dict('sys.modules', {'pcap': self.fake_pcap_module(is_pcap_ct=False)}):
            with self.installed('pypcap'):
                self.assertIsNone(PyPCAP.unsupported_reason())

    def test_unsupported_reason_names_pcap_ct_and_the_engine_for_it(self) -> None:
        from pcapkit.foundation.engines.pypcap import PyPCAP

        with mock.patch.dict('sys.modules', {'pcap': self.fake_pcap_module(is_pcap_ct=True)}):
            with self.installed('pcap-ct'):
                reason = PyPCAP.unsupported_reason()

        self.assertIsNotNone(reason)
        self.assertIn('pcap-ct', reason)
        self.assertIn('engine=pcap_ct', reason)

    def test_unsupported_reason_is_silent_when_no_pcap_is_installed(self) -> None:
        from pcapkit.foundation.engines.pypcap import PyPCAP

        # Not this hook's business: ``Extractor.import_test`` reports an absent
        # module in its own words, and answering here as well would produce two
        # warnings for one problem.
        with mock.patch('importlib.import_module', side_effect=ImportError('no pcap')):
            with self.installed():
                self.assertIsNone(PyPCAP.unsupported_reason())

    def test_unsupported_reason_is_not_a_python_version_check(self) -> None:
        from pcapkit.foundation.engines.pypcap import PyPCAP

        # Upstream cannot be *installed* on 3.12+, but the verdict is about which
        # distribution is present rather than which interpreter is running: an
        # upstream build that somebody got working on a newer Python must not be
        # refused, and on 3.10/3.11 the version says nothing useful because either
        # distribution could be the one in place.
        with mock.patch.dict('sys.modules', {'pcap': self.fake_pcap_module(is_pcap_ct=False)}):
            with self.installed('pypcap'):
                with mock.patch('sys.version_info', (3, 14, 0, 'final', 0)):
                    self.assertIsNone(PyPCAP.unsupported_reason())

    def test_init_refuses_pcap_ct_and_names_the_engine_that_wants_it(self) -> None:
        from pcapkit.foundation.engines.pypcap import PyPCAP
        from pcapkit.utilities.exceptions import UnsupportedCall

        extractor, _ = self.make_extractor()
        with mock.patch.dict('sys.modules', {'pcap': self.fake_pcap_module(is_pcap_ct=True)}):
            with self.installed('pcap-ct'):
                with self.assertRaises(UnsupportedCall) as caught:
                    PyPCAP(extractor)

        # the message has to be actionable: the whole reason this refuses rather
        # than running is that ``pcap-ct`` has an engine of its own
        message = str(caught.exception)
        self.assertIn('pcap-ct', message)
        self.assertIn('engine=pcap_ct', message)
        self.assertIn('1.3.0b3', message)

    def test_init_accepts_upstream_pypcap_and_reports_the_backend(self) -> None:
        from pcapkit.foundation.engines.pypcap import PyPCAP

        extractor, _ = self.make_extractor()
        module = self.fake_pcap_module(is_pcap_ct=False)
        with mock.patch.dict('sys.modules', {'pcap': module}):
            with self.installed('pypcap'):
                engine = PyPCAP(extractor)

        self.assertIs(engine._expkg, module)
        self.assertIsNone(engine._extmp)
        self.assertFalse(engine._closed)

        # "the PyPCAP engine" is not a complete statement of what ran, since two
        # distributions answer to it -- ``backend`` says which one did
        self.assertIn('pypcap', engine.backend)
        self.assertIn('1.3.0', engine.backend)
        self.assertIn('pcap.cpython-310.so', engine.backend)

    def test_init_warns_when_both_distributions_are_installed(self) -> None:
        from pcapkit.foundation.engines.pypcap import PyPCAP
        from pcapkit.utilities.exceptions import UnsupportedCall
        from pcapkit.utilities.warnings import EngineWarning

        # Measured on Python 3.10 with both installed: the ``pcap-ct`` package
        # wins the import and upstream's extension module is shadowed, so this
        # engine becomes permanently unselectable. Nothing else would say why.
        extractor, _ = self.make_extractor()
        with mock.patch.dict('sys.modules', {'pcap': self.fake_pcap_module(is_pcap_ct=True)}):
            with self.installed('pypcap', 'pcap-ct'):
                with mock.patch('pcapkit.foundation.engines.pypcap.warn') as warn:
                    with self.assertRaises(UnsupportedCall):
                        PyPCAP(extractor)

        collisions = [call.args[0] for call in warn.call_args_list
                      if len(call.args) > 1 and call.args[1] is EngineWarning]
        self.assertEqual(len(collisions), 1, warn.call_args_list)
        self.assertIn('pypcap', collisions[0])
        self.assertIn('pcap-ct', collisions[0])
        self.assertIn('shadowed', collisions[0])

    def test_init_does_not_warn_when_only_one_is_installed(self) -> None:
        from pcapkit.foundation.engines.pypcap import PyPCAP
        from pcapkit.utilities.warnings import EngineWarning

        extractor, _ = self.make_extractor()
        with mock.patch.dict('sys.modules', {'pcap': self.fake_pcap_module(is_pcap_ct=False)}):
            with self.installed('pypcap'):
                with mock.patch('pcapkit.foundation.engines.pypcap.warn') as warn:
                    PyPCAP(extractor)

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
        self.assertIs(engine._extmp, handle)
        self.assertEqual(handle.setup, 1)
        self.assertEqual(engine.dlink, LinkType.ETHERNET)

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
                    with mock.patch('pcapkit.foundation.engines.pypcap.warn') as warn:
                        engine.run()
                self.assertEqual(warn.call_count, 1)
                self.assertIn('protocol and layer threshold', warn.call_args.args[0])
                self.assertIs(warn.call_args.args[1], AttributeWarning)

    def test_run_rejects_pcapng_rather_than_yielding_no_frames(self) -> None:
        from pcapkit.utilities.exceptions import FormatError

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
            with mock.patch('pcapkit.foundation.engines.pypcap.warn') as warn:
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
        handle = engine._extmp

        engine.close()
        engine.close()
        self.assertEqual(handle.closed, 1)

        extractor, _ = self.make_extractor()
        unopened = self.engine(extractor)
        unopened.close()  # must not raise


if __name__ == '__main__':
    unittest.main()
