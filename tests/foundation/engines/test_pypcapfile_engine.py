"""Unit tests for :mod:`pcapkit.foundation.engines.pypcapfile`.

The engine is exercised against stand-ins for :func:`pcapfile.savefile.load_savefile`
and :func:`pcapfile.linklayer.clookup`, so that the routing decisions -- format
gating, the IPv6 capability gap, per-frame decoding and its failure path, output,
reassembly, tracing, storage -- are covered whether or not `pypcapfile`_ is
installed. End-to-end agreement with the ``default`` engine lives in
:mod:`tests.foundation.engines.test_new_engine_parity`.

.. _pypcapfile: https://github.com/kisom/pypcapfile

"""
from __future__ import annotations

import importlib.util
import io
import struct
import sys
import types
import unittest
from unittest import mock

from tests._support import purge_modules

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


class FakePacket:
    """Stand-in for :class:`pcapfile.structs.pcap_packet`."""

    def __init__(self, header, timestamp, timestamp_us, capture_len, packet_len, packet) -> None:
        self.header = header
        self.timestamp = timestamp
        self.timestamp_us = timestamp_us
        self.capture_len = capture_len
        self.packet_len = packet_len
        self.packet = packet


class FakeSaveFile:
    """Stand-in for :class:`pcapfile.savefile.pcap_savefile`."""

    def __init__(self, packets, ll_type: int = 1, ns_resolution: bool = False) -> None:
        self.header = types.SimpleNamespace(ll_type=ll_type, ns_resolution=ns_resolution)
        self.packets = packets


class FakeDecoded:
    """Stand-in for a decoded link layer frame."""

    def __init__(self, packet, layers=0) -> None:
        self.raw = packet
        self.layers = layers
        self.payload = b'decoded-payload'


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PyPCAPFileEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def make_extractor(self, **overrides):
        sink = OutputSink()
        reasm = types.SimpleNamespace(ipv4=mock.Mock(), ipv6=mock.Mock(), tcp=mock.Mock())
        trace = types.SimpleNamespace(tcp=mock.Mock())
        values = {
            '_ifile': io.BytesIO(b'capture'),
            '_ifnm': 'capture.pcap',
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

    def engine(self, extractor, savefile=None, decoder=FakeDecoded):
        from pcapkit.foundation.engines.pypcapfile import PyPCAPFile

        if savefile is None:
            savefile = FakeSaveFile([FakePacket(None, 1, 500000, 7, 7, b'payload')])

        engine = PyPCAPFile.__new__(PyPCAPFile)
        engine._expkg = types.SimpleNamespace(
            savefile=types.SimpleNamespace(load_savefile=mock.Mock(return_value=savefile)),
            linklayer=types.SimpleNamespace(clookup=mock.Mock(return_value=decoder)),
            structs=types.SimpleNamespace(pcap_packet=FakePacket),
        )
        engine._extmp = None
        engine._dlink = None
        engine._declf = None
        engine._extractor = extractor
        return engine

    ##########################################################################
    # run()
    ##########################################################################

    def test_run_loads_savefile_undecoded_and_records_link_type(self) -> None:
        from pcapkit.const.reg.linktype import LinkType

        extractor, _ = self.make_extractor()
        engine = self.engine(extractor)
        engine.run()

        load = engine._expkg.savefile.load_savefile
        load.assert_called_once()
        self.assertEqual(load.call_args.kwargs, {'layers': 0, 'lazy': True})
        stream = load.call_args.args[0]
        self.assertEqual(stream.name, 'capture.pcap')
        self.assertEqual(stream.read(3), b'cap')

        self.assertEqual(engine.dlink, LinkType.ETHERNET)
        self.assertIs(engine._declf, FakeDecoded)

    def test_run_warns_on_layer_and_protocol_threshold(self) -> None:
        from pcapkit.utilities.warnings import AttributeWarning

        # NOTE: ``BaseWarning.__init__`` installs an ``ignore`` filter for its own
        # category outside development mode, so the warning never reaches
        # ``assertWarns``; the ``warn`` call itself is what can be observed.
        for overrides in ({'_exlyr': 'transport'}, {'_exptl': 'udp'}):
            with self.subTest(overrides=overrides):
                extractor, _ = self.make_extractor(**overrides)
                engine = self.engine(extractor)
                with mock.patch('pcapkit.foundation.engines.pypcapfile.warn') as warn:
                    engine.run()
                self.assertEqual(warn.call_count, 1)
                self.assertIn('protocol and layer threshold', warn.call_args.args[0])
                self.assertIs(warn.call_args.args[1], AttributeWarning)

    def test_run_rejects_pcapng(self) -> None:
        from pcapkit.utilities.exceptions import FormatError

        extractor, _ = self.make_extractor(magic_number=PCAPNG_MAGIC)
        engine = self.engine(extractor)
        with self.assertRaises(FormatError):
            engine.run()
        engine._expkg.savefile.load_savefile.assert_not_called()

    def test_run_disables_ipv6_reassembly_but_keeps_ipv4_and_tcp(self) -> None:
        from pcapkit.utilities.warnings import AttributeWarning

        extractor, _ = self.make_extractor(_flag_r=True, _ipv4=True, _ipv6=True, _tcp=True)
        ipv4, tcp = extractor._reasm.ipv4, extractor._reasm.tcp
        engine = self.engine(extractor)
        with mock.patch('pcapkit.foundation.engines.pypcapfile.warn') as warn:
            engine.run()

        messages = [call.args[0] for call in warn.call_args_list
                    if call.args[1] is AttributeWarning]
        self.assertTrue(any('IPv6 reassembly' in message for message in messages), messages)

        self.assertTrue(extractor._flag_r)
        self.assertFalse(extractor._ipv6)
        self.assertTrue(extractor._ipv4)
        self.assertIs(extractor._reasm.ipv4, ipv4)
        self.assertIs(extractor._reasm.tcp, tcp)
        self.assertIsNone(extractor._reasm.ipv6)

    def test_run_leaves_reassembly_alone_when_ipv6_was_not_requested(self) -> None:
        extractor, _ = self.make_extractor(_flag_r=True, _ipv4=True, _tcp=True)
        original = extractor._reasm
        engine = self.engine(extractor)
        engine.run()
        self.assertIs(extractor._reasm, original)

    def test_run_warns_and_gives_up_decoding_for_an_unknown_link_layer(self) -> None:
        from pcapkit.utilities.warnings import AttributeWarning

        for decoder in (None, 'not-callable'):
            with self.subTest(decoder=decoder):
                extractor, _ = self.make_extractor()
                engine = self.engine(extractor, decoder=decoder)
                with mock.patch('pcapkit.foundation.engines.pypcapfile.warn') as warn:
                    engine.run()
                self.assertIsNone(engine._declf)
                self.assertIn('unrecognised link layer protocol', warn.call_args.args[0])
                self.assertIs(warn.call_args.args[1], AttributeWarning)

    def test_run_survives_the_malformed_upstream_link_layer_table(self) -> None:
        # ``pcapfile.linklayer.__LL_TYPES__`` carries a three-element entry for
        # LINKTYPE_IEEE802_11_RADIOTAP, so ``clookup`` raises IndexError for it.
        extractor, _ = self.make_extractor()
        engine = self.engine(extractor)
        engine._expkg.linklayer.clookup = mock.Mock(side_effect=IndexError('tuple index'))
        with mock.patch('pcapkit.foundation.engines.pypcapfile.warn'):
            engine.run()
        self.assertIsNone(engine._declf)

    def test_run_installs_verbose_handler_reporting_the_chain(self) -> None:
        extractor, _ = self.make_extractor(_flag_v=True)
        engine = self.engine(extractor)
        engine.run()

        packet = FakePacket(types.SimpleNamespace(ns_resolution=False), 1, 0, 7, 7, b'raw')
        with mock.patch('builtins.print') as printer:
            extractor._frnum = 4
            extractor._vfunc(extractor, packet)
        printer.assert_called_once()
        self.assertIn('ETHERNET:Raw', printer.call_args.args[0])

    ##########################################################################
    # read_frame()
    ##########################################################################

    def prepared(self, packets=None, decoder=FakeDecoded, **overrides):
        if packets is None:
            packets = [FakePacket(types.SimpleNamespace(ns_resolution=False),
                                  1, 500000, 7, 7, b'payload')]
        extractor, sink = self.make_extractor(**overrides)
        engine = self.engine(extractor, savefile=FakeSaveFile(iter(packets)), decoder=decoder)
        with mock.patch('pcapkit.foundation.engines.pypcapfile.warn'):
            engine.run()
        return extractor, sink, engine

    def test_read_frame_decodes_to_layers_depth_and_routes_output(self) -> None:
        extractor, sink, engine = self.prepared()

        with mock.patch('pcapkit.toolkit.pypcapfile.packet2dict', return_value={'ok': True}):
            frame = engine.read_frame()

        self.assertIsInstance(frame.packet, FakeDecoded)
        self.assertEqual(frame.packet.raw, b'payload')
        self.assertEqual(frame.packet.layers, engine.LAYERS - 1)
        self.assertEqual((frame.timestamp, frame.timestamp_us), (1, 500000))
        self.assertEqual((frame.capture_len, frame.packet_len), (7, 7))

        self.assertEqual(extractor._frnum, 1)
        extractor._vfunc.assert_called_once_with(extractor, frame)
        self.assertEqual(sink.records[-1], ({'ok': True}, 'Frame 1'))
        self.assertEqual(extractor._offmt, 'unit')
        self.assertEqual(extractor._frame, [frame])

        with self.assertRaises(StopIteration):
            engine.read_frame()

    def test_read_frame_leaves_the_frame_alone_with_no_decoder(self) -> None:
        extractor, _, engine = self.prepared(decoder=None, _flag_q=True)
        frame = engine.read_frame()
        self.assertEqual(frame.packet, b'payload')

    def test_read_frame_warns_and_falls_back_when_decoding_fails(self) -> None:
        from pcapkit.utilities.warnings import AttributeWarning

        for error in (struct.error('unpack'), AssertionError('not ipv4'),
                      ValueError('bad'), IndexError('short'), KeyError('missing')):
            with self.subTest(error=type(error).__name__):
                extractor, _, engine = self.prepared(
                    decoder=mock.Mock(side_effect=error), _flag_q=True,
                )
                with mock.patch('pcapkit.foundation.engines.pypcapfile.warn') as warn:
                    frame = engine.read_frame()
                self.assertEqual(frame.packet, b'payload')
                self.assertIn('decoding failed', warn.call_args.args[0])
                self.assertIn('Frame 1', warn.call_args.args[0])
                self.assertIs(warn.call_args.args[1], AttributeWarning)

    def test_read_frame_splits_files_when_asked(self) -> None:
        extractor, sink, engine = self.prepared(_flag_f=True)
        with mock.patch('pcapkit.toolkit.pypcapfile.packet2dict', return_value={}):
            engine.read_frame()
        self.assertEqual(sink.paths[-1], 'out/Frame 1.json')

    def test_read_frame_routes_reassembly_and_tracing(self) -> None:
        extractor, _, engine = self.prepared(_flag_q=True, _flag_r=True, _flag_t=True,
                                             _ipv4=True, _tcp=True, _flag_d=False)
        with mock.patch('pcapkit.toolkit.pypcapfile.ipv4_reassembly', return_value='ipv4') as v4:
            with mock.patch('pcapkit.toolkit.pypcapfile.tcp_reassembly', return_value='tcp'):
                with mock.patch('pcapkit.toolkit.pypcapfile.tcp_traceflow',
                                return_value='trace') as trace:
                    frame = engine.read_frame()

        v4.assert_called_once_with(frame, count=1)
        trace.assert_called_once_with(frame, data_link=engine.dlink, count=1)
        extractor._reasm.ipv4.assert_called_once_with('ipv4')
        extractor._reasm.tcp.assert_called_once_with('tcp')
        extractor._trace.tcp.assert_called_once_with('trace')
        # IPv6 is unreachable for this engine, so it must never be consulted
        extractor._reasm.ipv6.assert_not_called()
        self.assertEqual(extractor._frame, [])

    def test_read_frame_skips_reassembly_and_tracing_when_adapters_decline(self) -> None:
        extractor, _, engine = self.prepared(_flag_q=True, _flag_r=True, _flag_t=True,
                                             _ipv4=True, _tcp=True)
        with mock.patch('pcapkit.toolkit.pypcapfile.ipv4_reassembly', return_value=None):
            with mock.patch('pcapkit.toolkit.pypcapfile.tcp_reassembly', return_value=None):
                with mock.patch('pcapkit.toolkit.pypcapfile.tcp_traceflow', return_value=None):
                    engine.read_frame()

        extractor._reasm.ipv4.assert_not_called()
        extractor._reasm.tcp.assert_not_called()
        extractor._trace.tcp.assert_not_called()

    def test_read_frame_ignores_reassembly_and_tracing_when_flags_are_off(self) -> None:
        extractor, _, engine = self.prepared(_flag_q=True, _flag_r=False, _flag_t=False,
                                             _ipv4=True, _tcp=True)
        with mock.patch('pcapkit.toolkit.pypcapfile.ipv4_reassembly', return_value='unused'):
            with mock.patch('pcapkit.toolkit.pypcapfile.tcp_reassembly', return_value='unused'):
                with mock.patch('pcapkit.toolkit.pypcapfile.tcp_traceflow', return_value='unused'):
                    engine.read_frame()

        extractor._reasm.ipv4.assert_not_called()
        extractor._trace.tcp.assert_not_called()

    def test_read_frame_ignores_protocols_that_were_not_requested(self) -> None:
        extractor, _, engine = self.prepared(_flag_q=True, _flag_r=True, _flag_t=True,
                                             _ipv4=False, _tcp=False)
        with mock.patch('pcapkit.toolkit.pypcapfile.ipv4_reassembly', return_value='unused'):
            with mock.patch('pcapkit.toolkit.pypcapfile.tcp_reassembly', return_value='unused'):
                with mock.patch('pcapkit.toolkit.pypcapfile.tcp_traceflow', return_value='unused'):
                    engine.read_frame()

        extractor._reasm.ipv4.assert_not_called()
        extractor._reasm.tcp.assert_not_called()
        extractor._trace.tcp.assert_not_called()

    ##########################################################################
    # _NamedStream
    ##########################################################################

    def test_named_stream_proxies_reads_and_carries_a_name(self) -> None:
        from pcapkit.foundation.engines.pypcapfile import _NamedStream

        stream = _NamedStream(io.BytesIO(b'abcdef'), 'given.pcap')
        self.assertEqual(stream.name, 'given.pcap')
        self.assertEqual(stream.read(2), b'ab')
        self.assertEqual(stream.read(), b'cdef')
        self.assertEqual(stream.read(), b'')


class PyPCAPFilePythonCeilingTests(unittest.TestCase):
    """The engine rules itself out above its dependency's Python ceiling.

    ``pypcapfile`` 0.12.0 installs cleanly on Python 3.12 and newer and *then*
    fails, because :mod:`pcapfile.linklayer` imports :mod:`imp`, which 3.12
    removed, and :mod:`pcapfile.savefile` imports ``linklayer``. An import guard
    that only tries ``import pcapfile`` is therefore satisfied, and the
    :exc:`ModuleNotFoundError` escapes from the engine's constructor as a hard
    error rather than degrading to the default engine.

    """

    def test_the_ceiling_is_declared_and_matches_the_imp_removal(self) -> None:
        from pcapkit.foundation.engines.pypcapfile import PyPCAPFile

        # 3.12 is where :mod:`imp` went, so that is the first unsupported version
        self.assertEqual(PyPCAPFile.PYTHON_CEILING, (3, 12))

    def test_unsupported_reason_tracks_the_running_interpreter(self) -> None:
        from pcapkit.foundation.engines.pypcapfile import PyPCAPFile

        reason = PyPCAPFile.unsupported_reason()
        if sys.version_info[:2] >= PyPCAPFile.PYTHON_CEILING:
            self.assertIsNotNone(reason)
            # the message has to name the cause, not merely refuse: a bare
            # "unsupported" sends the reader to the wrong place
            self.assertIn('imp', reason)  # type: ignore[arg-type]
            self.assertIn(f'{sys.version_info[0]}.{sys.version_info[1]}',
                          reason)  # type: ignore[arg-type]
        else:
            self.assertIsNone(reason)

    def test_the_reason_is_decided_by_version_not_by_the_import(self) -> None:
        """The verdict must not depend on whether ``pcapfile`` is installed.

        Otherwise the answer differs between a machine that has the package and
        one that does not, and the engine would report itself usable on 3.12+
        purely because the failing submodule had not been reached yet.

        """
        from pcapkit.foundation.engines.pypcapfile import PyPCAPFile

        for version, expected in (((3, 11), False), ((3, 12), True), ((3, 14), True)):
            with self.subTest(python=version):
                with mock.patch.object(sys, 'version_info',
                                       (*version, 0, 'final', 0)):
                    self.assertEqual(PyPCAPFile.unsupported_reason() is not None,
                                     expected)


if __name__ == '__main__':
    unittest.main()
