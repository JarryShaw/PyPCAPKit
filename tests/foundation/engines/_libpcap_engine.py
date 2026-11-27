"""Shared stand-ins and test bodies for the two libpcap engines.

`pcap-ct`_ and upstream `pypcap`_ both install a top-level :mod:`pcap`, so
:mod:`tests.foundation.engines.test_pcap_ct_engine` and
:mod:`tests.foundation.engines.test_pypcap_engine` check the same routing
decisions, as do their toolkit modules. The bodies live here once as plain classes
-- a :class:`unittest.TestCase` base would be collected on its own -- and each test
module mixes them into a case that names its own engine, so a failure still says
which of the two it concerns.

.. _pcap-ct: https://pypi.org/project/pcap-ct/
.. _pypcap: https://pypi.org/project/pypcap/

"""
from __future__ import annotations

import importlib
import importlib.util
import io
import os
import tempfile
import types
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
    """Stand-in for :class:`pcap.pcap`, yielding ``(timestamp, bytes)`` pairs.

    It iterates as itself, as upstream ``pypcap`` does.

    """

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


class FrameIterator:
    """Iterator over an :class:`IteratorHandle`'s frames, and a separate object from it.

    It carries a ``close`` of its own purely so that closing the wrong thing is
    observable. ``pcap-ct``'s engine keeps the handle and the iterator apart so that
    ``close`` does not have to assume ``iter(handle) is handle``, and a stand-in that
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


class IteratorHandle(FakeHandle):
    """A :class:`FakeHandle` that iterates through a :class:`FrameIterator`, as ``pcap-ct`` does."""

    def __init__(self, frames=None, datalink: int = 1) -> None:
        super().__init__(frames, datalink)
        self.iterator: FrameIterator | None = None

    def __iter__(self) -> FrameIterator:  # type: ignore[override]
        self.setup += 1
        self.iterator = FrameIterator(self.frames)
        return self.iterator


class LibpcapEngineMixin:
    """Fixtures and tests shared by the ``pcap_ct`` and ``pypcap`` engine cases.

    A case sets the class attributes below, and supplies :meth:`engine`.

    """

    #: Dotted path of the engine module, and the engine's class name in it.
    MODULE: str
    CLASS: str
    #: Distribution the engine accepts, and the one it points to instead, with the
    #: engine name it gives for it and the version the stand-in reports for it.
    OWN_DIST: str
    OTHER_DIST: str
    OTHER_ENGINE: str
    OTHER_VERSION: str
    #: Whether the engine's own distribution is ``pcap-ct``.
    OWN_IS_PCAP_CT: bool
    #: Handle the stand-in ``pcap.pcap`` builds.
    HANDLE = FakeHandle

    def setUp(self) -> None:
        reimport_once_per_class(self)

        handle, path = tempfile.mkstemp(suffix='.pcap')
        os.close(handle)
        self.addCleanup(os.unlink, path)
        self.ifnm = path

    @property
    def engine_name(self) -> str:
        return self.MODULE.rsplit('.', 1)[1]

    def engine_class(self):
        return getattr(importlib.import_module(self.MODULE), self.CLASS)

    def engine(self, extractor):
        raise NotImplementedError

    def make_extractor(self, **overrides):
        from pcapkit.foundation.reassembly import ReassemblyManager
        from pcapkit.foundation.traceflow import TraceFlowManager

        sink = OutputSink()
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
            '_vfunc_default': False,
            '_flag_r': False,
            '_flag_t': False,
            '_flag_d': True,
            '_ipv4': False,
            '_ipv6': False,
            '_tcp': False,
            '_dtls': False,
            '_frame': [],
            '_frnum': 0,
            '_exlyr': None,
            '_exptl': None,
            '_exnam': self.engine_name,
            '_exctx': {},
            '_vfunc': mock.Mock(),
            'magic_number': PCAP_MAGIC,
        }
        values.update(overrides)
        # NOTE: ``_reasm`` holds a mock for each reassembler the flags enable, as the Extractor
        # builds it (#2814).
        values['_reasm'] = ReassemblyManager((name, mock.Mock()) for name in ('ipv4', 'ipv6', 'tcp', 'dtls')
                                             if values[f'_{name}'])
        # NOTE: ``_trace`` holds the tracer ``_tcp`` enables, as the Extractor builds it (#2843);
        # ``_tracers`` keeps it either way, so a test can check a disabled one was never fed.
        values['_tracers'] = types.SimpleNamespace(tcp=mock.Mock())
        values['_trace'] = TraceFlowManager(tcp=values['_tracers'].tcp if values['_tcp'] else None)
        return types.SimpleNamespace(**values), sink

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
        module.pcap = self.HANDLE  # type: ignore[attr-defined]
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

    def prepared(self, **overrides):
        extractor, sink = self.make_extractor(**overrides)
        engine = self.engine(extractor)
        handle = self.HANDLE(frames=[(1.5, b'payload'), (2.5, b'second')])
        with mock.patch.object(engine._expkg, 'pcap', return_value=handle):
            engine.run()
        return extractor, sink, engine

    def run_warned(self, extractor, engine):
        """Run ``engine`` with ``warn`` observed, and return the mock."""
        with mock.patch.object(engine._expkg, 'pcap', return_value=self.HANDLE()):
            with mock.patch(f'{self.MODULE}.warn') as warn, \
                    mock.patch('pcapkit.foundation.engines.engine.warn', warn):
                engine.run()
        return warn

    ##########################################################################
    # unsupported_reason() and __init__()
    ##########################################################################

    def test_unsupported_reason_is_silent_on_its_own_distribution(self) -> None:
        with mock.patch.dict('sys.modules', {'pcap': self.fake_pcap_module(is_pcap_ct=self.OWN_IS_PCAP_CT)}):
            with self.installed(self.OWN_DIST):
                self.assertIsNone(self.engine_class().unsupported_reason())

    def test_unsupported_reason_names_the_other_distribution_and_its_engine(self) -> None:
        with mock.patch.dict('sys.modules',
                             {'pcap': self.fake_pcap_module(is_pcap_ct=not self.OWN_IS_PCAP_CT)}):
            with self.installed(self.OTHER_DIST):
                reason = self.engine_class().unsupported_reason()

        self.assertIsNotNone(reason)
        self.assertIn(self.OTHER_DIST, reason)
        self.assertIn(self.OTHER_ENGINE, reason)

    def test_unsupported_reason_is_silent_when_no_pcap_is_installed(self) -> None:
        # Not this hook's business: ``Extractor.import_test`` reports an absent
        # module in its own words, and answering here as well would produce two
        # warnings for one problem.
        engine = self.engine_class()
        with mock.patch('importlib.import_module', side_effect=ImportError('no pcap')):
            with self.installed():
                self.assertIsNone(engine.unsupported_reason())

    def test_init_refuses_the_other_distribution_and_names_its_engine(self) -> None:
        from pcapkit.utilities.exceptions import UnsupportedCall

        extractor, _ = self.make_extractor()
        with mock.patch.dict('sys.modules',
                             {'pcap': self.fake_pcap_module(is_pcap_ct=not self.OWN_IS_PCAP_CT)}):
            with self.installed(self.OTHER_DIST):
                with self.assertRaises(UnsupportedCall) as caught:
                    self.engine_class()(extractor)

        # the message has to be actionable: the whole reason this refuses rather
        # than running is that the other distribution has an engine of its own
        message = str(caught.exception)
        self.assertIn(self.OTHER_DIST, message)
        self.assertIn(self.OTHER_ENGINE, message)
        self.assertIn(self.OTHER_VERSION, message)

    def test_init_does_not_warn_when_only_one_is_installed(self) -> None:
        from pcapkit.utilities.warnings import EngineWarning

        extractor, _ = self.make_extractor()
        with mock.patch.dict('sys.modules', {'pcap': self.fake_pcap_module(is_pcap_ct=self.OWN_IS_PCAP_CT)}):
            with self.installed(self.OWN_DIST):
                with mock.patch(f'{self.MODULE}.warn') as warn, \
                        mock.patch('pcapkit.foundation.engines.engine.warn', warn):
                    self.engine_class()(extractor)

        self.assertEqual([call for call in warn.call_args_list
                          if len(call.args) > 1 and call.args[1] is EngineWarning], [])

    ##########################################################################
    # run()
    ##########################################################################

    def test_run_warns_on_layer_and_protocol_threshold(self) -> None:
        from pcapkit.utilities.warnings import AttributeWarning

        # NOTE: outside development mode ``BaseWarning.__init__`` ignores its own
        # category, so the ``warn`` call is observed rather than ``assertWarns``.
        for overrides in ({'_exlyr': 'internet'}, {'_exptl': 'tcp'}):
            with self.subTest(overrides=overrides):
                extractor, _ = self.make_extractor(**overrides)
                warn = self.run_warned(extractor, self.engine(extractor))
                self.assertEqual(warn.call_count, 1)
                self.assertIn('protocol and layer threshold', warn.call_args.args[0])
                self.assertIs(warn.call_args.args[1], AttributeWarning)

    def test_run_warns_that_a_parsing_context_is_ignored(self) -> None:
        from pcapkit.utilities.warnings import AttributeWarning

        # #2313: the engine never parses with pcapkit's own protocols, so a
        # ``context=`` has no effect and the caller is told so, as DPKT, Scapy and
        # PyShark already do. The fixture's empty ``_exctx`` stays silent, which
        # the threshold test above pins through its call count.
        extractor, _ = self.make_extractor(_exctx={'ipv4': mock.sentinel.context})
        warn = self.run_warned(extractor, self.engine(extractor))
        self.assertEqual(warn.call_count, 1)
        self.assertEqual(warn.call_args.args[0],
                         f"'Extractor(engine={self.engine_name})' does not parse with "
                         "pcapkit's own protocol implementations, so the parsing context supplied "
                         "through 'context=' is ignored")
        self.assertIs(warn.call_args.args[1], AttributeWarning)

    def test_run_rejects_pcapng_rather_than_reading_it_wrongly(self) -> None:
        from pcapkit.utilities.exceptions import FormatError

        # the libpcap binding either yields no frames for a PCAP-NG savefile or
        # reports only one link type for it, so the engine refuses rather than
        # applying one interface's link type to every frame
        extractor, _ = self.make_extractor(magic_number=PCAPNG_MAGIC)
        engine = self.engine(extractor)
        with mock.patch.object(engine._expkg, 'pcap', return_value=self.HANDLE()) as ctor:
            with self.assertRaises(FormatError):
                engine.run()
        ctor.assert_not_called()

    def test_run_rejects_input_that_is_not_a_file_on_disk(self) -> None:
        from pcapkit.utilities.exceptions import UnsupportedCall

        extractor, _ = self.make_extractor(_ifnm=os.path.join(self.ifnm, 'nope.pcap'))
        engine = self.engine(extractor)
        with mock.patch.object(engine._expkg, 'pcap', return_value=self.HANDLE()) as ctor:
            with self.assertRaises(UnsupportedCall):
                engine.run()
        ctor.assert_not_called()

    def test_run_disables_reassembly_and_flow_tracing(self) -> None:
        from pcapkit.utilities.warnings import AttributeWarning

        extractor, _ = self.make_extractor(_flag_r=True, _flag_t=True, _ipv4=True,
                                           _ipv6=True, _tcp=True)
        warn = self.run_warned(extractor, self.engine(extractor))

        messages = [call.args[0] for call in warn.call_args_list
                    if call.args[1] is AttributeWarning]
        self.assertTrue(any('reassembly' in message for message in messages), messages)
        self.assertTrue(any('flow tracing' in message for message in messages), messages)

        self.assertFalse(extractor._flag_r)
        self.assertFalse(extractor._flag_t)
        self.assertNotIn('ipv4', extractor._reasm)
        self.assertNotIn('ipv6', extractor._reasm)
        self.assertNotIn('tcp', extractor._reasm)
        self.assertNotIn('dtls', extractor._reasm)
        self.assertEqual(dict(extractor._trace), {})

    def test_run_disables_reassembly_requested_for_dtls_alone(self) -> None:
        from pcapkit.utilities.warnings import AttributeWarning

        extractor, _ = self.make_extractor(_flag_r=True, _dtls=True)
        warn = self.run_warned(extractor, self.engine(extractor))

        messages = [call.args[0] for call in warn.call_args_list
                    if call.args[1] is AttributeWarning]
        self.assertTrue(any("so reassembly=['dtls'] will be ignored" in message for message in messages),
                        messages)
        self.assertFalse(extractor._flag_r)
        self.assertNotIn('dtls', extractor._reasm)

    def test_run_leaves_disabled_reassembly_and_tracing_untouched(self) -> None:
        extractor, _ = self.make_extractor(_flag_r=True, _flag_t=True)
        original_reasm, original_trace = extractor._reasm, extractor._trace
        engine = self.engine(extractor)
        with mock.patch.object(engine._expkg, 'pcap', return_value=self.HANDLE()):
            engine.run()

        # no protocol was requested, so there is nothing to warn about or replace
        self.assertTrue(extractor._flag_r)
        self.assertTrue(extractor._flag_t)
        self.assertIs(extractor._reasm, original_reasm)
        self.assertIs(extractor._trace, original_trace)

    def test_run_installs_verbose_handler_reporting_the_raw_chain(self) -> None:
        extractor, _ = self.make_extractor(_flag_v=True, _vfunc_default=True)
        engine = self.engine(extractor)
        with mock.patch.object(engine._expkg, 'pcap', return_value=self.HANDLE()):
            engine.run()

        with mock.patch('builtins.print') as printer:
            extractor._frnum = 3
            extractor._vfunc(extractor, (1.5, b'payload'))
        printer.assert_called_once()
        self.assertIn('ETHERNET:Raw', printer.call_args.args[0])

    def test_run_keeps_a_callers_verbose_callback(self) -> None:
        # #1874: a callable given as ``verbose`` turns verbose output on without
        # asking for the default printer, so the engine must not replace it
        callback = mock.Mock()
        extractor, _ = self.make_extractor(_flag_v=True, _vfunc_default=False, _vfunc=callback)
        engine = self.engine(extractor)
        with mock.patch.object(engine._expkg, 'pcap', return_value=self.HANDLE()):
            engine.run()
        self.assertIs(extractor._vfunc, callback)

    ##########################################################################
    # read_frame()
    ##########################################################################

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


class LibpcapToolkitMixin:
    """Tests shared by the ``pcap_ct`` and ``pypcap`` toolkit cases.

    A case sets :attr:`MODULE`, :attr:`ENGINE` (the engine's ``__engine_name__``) and
    :attr:`DIST`.

    """

    MODULE: str
    ENGINE: str
    DIST: str

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def toolkit(self):
        return importlib.import_module(self.MODULE)

    def test_packet2chain_reports_the_link_layer_and_raw(self) -> None:
        from pcapkit.const.reg.linktype import LinkType

        packet2chain = self.toolkit().packet2chain
        self.assertEqual(packet2chain(b'\x00' * 20, data_link=LinkType.ETHERNET),
                         'ETHERNET:Raw')
        self.assertEqual(packet2chain(b'', data_link=LinkType.RAW), 'RAW:Raw')

    def test_packet2dict_carries_the_bytes_verbatim(self) -> None:
        from pcapkit.const.reg.linktype import LinkType

        packet2dict = self.toolkit().packet2dict
        info = packet2dict(b'abcd', 1.25, data_link=LinkType.ETHERNET)
        self.assertEqual(info, {
            'timestamp': 1.25,
            'packet': b'abcd',
            'ETHERNET': {'raw_len': 4, 'raw': b'abcd'},
        })

        # the recorded length is of the captured bytes, not of the original frame:
        # libpcap hands over only what it captured
        info = packet2dict(b'', 0.0, data_link=LinkType.RAW)
        self.assertEqual(info['RAW']['raw_len'], 0)

    def test_unsupported_adapters_refuse_loudly(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.utilities.exceptions import UnsupportedCall

        toolkit = self.toolkit()
        for name in ('ipv4_reassembly', 'ipv6_reassembly', 'tcp_reassembly', 'tcp_traceflow'):
            with self.subTest(function=name):
                with self.assertRaises(UnsupportedCall) as caught:
                    getattr(toolkit, name)(b'raw', 1.0, data_link=LinkType.ETHERNET, count=1)
                # the message has to say *why*, since "unsupported" alone reads as
                # an oversight rather than as a property of a libpcap binding
                self.assertIn('no protocol dissection', str(caught.exception))
                self.assertIn(self.DIST, str(caught.exception))
                # the engine's own name leads the message, spelled as
                # ``__engine_name__`` spells it (#2304)
                self.assertTrue(str(caught.exception).startswith(f'{self.ENGINE}: '),
                                str(caught.exception))

    def test_module_exports_the_documented_surface(self) -> None:
        toolkit = self.toolkit()
        self.assertEqual(sorted(toolkit.__all__), [
            'ipv4_reassembly', 'ipv6_reassembly', 'packet2chain', 'packet2dict',
            'tcp_reassembly', 'tcp_traceflow',
        ])
        for name in toolkit.__all__:
            self.assertTrue(callable(getattr(toolkit, name)), name)
