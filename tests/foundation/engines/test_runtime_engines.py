from __future__ import annotations

import importlib.util
import io
from ipaddress import ip_address
import types
import unittest
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper', 'dpkt', 'scapy', 'pyshark')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class OutputSink:
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


def make_extractor(**overrides):
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
        '_flag_r': True,
        '_flag_t': True,
        '_flag_d': True,
        '_ipv4': True,
        '_ipv6': True,
        '_tcp': True,
        '_reasm': reasm,
        '_trace': trace,
        '_frame': [],
        '_frnum': 0,
        '_exlyr': 'none',
        '_exptl': 'null',
        '_vfunc': mock.Mock(),
        'magic_number': b'\xa1\xb2\xc3\xd4',
    }
    values.update(overrides)
    return types.SimpleNamespace(**values), sink


class FakeInfo:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def to_dict(self):
        return dict(self.__dict__)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PCAPEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_pcap_run_writes_global_header_for_file_and_stream_modes(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.corekit.version import VersionInfo
        from pcapkit.foundation.engines.pcap import PCAP

        class FakeHeader:
            def __init__(self, file) -> None:
                self.file = file
                self.version = VersionInfo(2, 4)
                self.protocol = LinkType.ETHERNET
                self.nanosecond = True
                self.info = FakeInfo(header='global')

        for flag_f in (True, False):
            with self.subTest(flag_f=flag_f):
                extractor, sink = make_extractor(_flag_f=flag_f)
                engine = PCAP(extractor)
                with mock.patch('pcapkit.foundation.engines.pcap.Header', FakeHeader):
                    engine.run()
                self.assertEqual(engine.header.info.header, 'global')
                self.assertEqual(engine.version.version, '2.4')
                self.assertEqual(engine.dlink, LinkType.ETHERNET)
                self.assertTrue(engine.nanosecond)
                self.assertEqual(extractor._offmt, 'unit')
                self.assertEqual(sink.records[-1][1], 'Global Header')

        quiet, sink = make_extractor(_flag_q=True)
        engine = PCAP(quiet)
        with mock.patch('pcapkit.foundation.engines.pcap.Header', FakeHeader):
            engine.run()
        self.assertEqual(sink.records, [])

    def test_pcap_read_frame_routes_output_reassembly_trace_and_storage(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.engines.pcap import PCAP

        class FakeFrame:
            def __init__(self, file, **kwargs) -> None:
                self.file = file
                self.kwargs = kwargs
                self.info = FakeInfo(frame='info')

        extractor, sink = make_extractor(_flag_f=True)
        engine = PCAP(extractor)
        engine._gbhdr = types.SimpleNamespace(info=FakeInfo(header='global'))
        engine._nnsec = False
        engine._dlink = LinkType.ETHERNET

        with mock.patch('pcapkit.foundation.engines.pcap.Frame', FakeFrame):
            with mock.patch('pcapkit.toolkit.pcap.ipv4_reassembly', return_value='ipv4'):
                with mock.patch('pcapkit.toolkit.pcap.ipv6_reassembly', return_value='ipv6'):
                    with mock.patch('pcapkit.toolkit.pcap.tcp_reassembly', return_value='tcp'):
                        with mock.patch('pcapkit.toolkit.pcap.tcp_traceflow', return_value='trace'):
                            frame = engine.read_frame()

        self.assertIsInstance(frame, FakeFrame)
        self.assertEqual(extractor._frnum, 1)
        extractor._vfunc.assert_called_once_with(extractor, frame)
        self.assertEqual(sink.paths[-1], 'out/Frame 1.json')
        extractor._reasm.ipv4.assert_called_once_with('ipv4')
        extractor._reasm.ipv6.assert_called_once_with('ipv6')
        extractor._reasm.tcp.assert_called_once_with('tcp')
        extractor._trace.tcp.assert_called_once_with('trace')
        self.assertEqual(extractor._frame, [frame])

        quiet, _ = make_extractor(_flag_q=True, _flag_r=True, _flag_t=True, _flag_d=False,
                                  _ipv4=False, _ipv6=False, _tcp=False)
        engine = PCAP(quiet)
        engine._gbhdr = types.SimpleNamespace(info=FakeInfo(header='global'))
        engine._nnsec = False
        engine._dlink = LinkType.ETHERNET
        with mock.patch('pcapkit.foundation.engines.pcap.Frame', FakeFrame):
            with mock.patch('pcapkit.toolkit.pcap.ipv4_reassembly', return_value=None):
                with mock.patch('pcapkit.toolkit.pcap.ipv6_reassembly', return_value=None):
                    with mock.patch('pcapkit.toolkit.pcap.tcp_reassembly', return_value=None):
                        with mock.patch('pcapkit.toolkit.pcap.tcp_traceflow', return_value=None):
                            self.assertIsInstance(engine.read_frame(), FakeFrame)
        self.assertEqual(quiet._frame, [])

        none_data, none_sink = make_extractor(_flag_f=False, _flag_d=False)
        engine = PCAP(none_data)
        engine._gbhdr = types.SimpleNamespace(info=FakeInfo(header='global'))
        engine._nnsec = False
        engine._dlink = LinkType.ETHERNET
        with mock.patch('pcapkit.foundation.engines.pcap.Frame', FakeFrame):
            with mock.patch('pcapkit.toolkit.pcap.ipv4_reassembly', return_value=None):
                with mock.patch('pcapkit.toolkit.pcap.ipv6_reassembly', return_value=None):
                    with mock.patch('pcapkit.toolkit.pcap.tcp_reassembly', return_value=None):
                        with mock.patch('pcapkit.toolkit.pcap.tcp_traceflow', return_value=None):
                            self.assertIsInstance(engine.read_frame(), FakeFrame)
        self.assertEqual(none_sink.records[-1][1], 'Frame 1')
        none_data._reasm.ipv4.assert_not_called()
        none_data._reasm.ipv6.assert_not_called()
        none_data._reasm.tcp.assert_not_called()
        none_data._trace.tcp.assert_not_called()

        disabled, _ = make_extractor(_flag_r=False, _flag_t=False, _flag_d=False)
        engine = PCAP(disabled)
        engine._gbhdr = types.SimpleNamespace(info=FakeInfo(header='global'))
        engine._nnsec = False
        engine._dlink = LinkType.ETHERNET
        with mock.patch('pcapkit.foundation.engines.pcap.Frame', FakeFrame):
            with mock.patch('pcapkit.toolkit.pcap.ipv4_reassembly', return_value='unused'):
                with mock.patch('pcapkit.toolkit.pcap.ipv6_reassembly', return_value='unused'):
                    with mock.patch('pcapkit.toolkit.pcap.tcp_reassembly', return_value='unused'):
                        with mock.patch('pcapkit.toolkit.pcap.tcp_traceflow', return_value='unused'):
                            self.assertIsInstance(engine.read_frame(), FakeFrame)
        disabled._reasm.ipv4.assert_not_called()
        disabled._trace.tcp.assert_not_called()


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ThirdPartyEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_dpkt_run_magic_selection_get_protocol_and_read_frame(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.engines.dpkt import DPKT
        from pcapkit.foundation.engines.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import FormatError

        class FakeReader:
            def __init__(self) -> None:
                self.items = iter([(1.25, b'payload')])

            def datalink(self) -> int:
                return LinkType.ETHERNET

            def __iter__(self):
                return self

            def __next__(self):
                return next(self.items)

        extractor, sink = make_extractor(_exlyr='link', _flag_v=True)
        engine = DPKT(extractor)
        pcap_reader = FakeReader()
        with mock.patch.object(engine._expkg.pcap, 'Reader', return_value=pcap_reader):
            engine.run()
        self.assertIs(engine._extmp, pcap_reader)
        self.assertTrue(callable(extractor._vfunc))

        pcapng_reader = FakeReader()
        extractor.magic_number = PCAPNG.MAGIC_NUMBER[0]
        with mock.patch.object(engine._expkg.pcapng, 'Reader', return_value=pcapng_reader):
            engine.run()
        self.assertIs(engine._extmp, pcapng_reader)

        extractor.magic_number = b'bad!'
        with self.assertRaises(FormatError):
            engine.run()

        clean_extractor, _ = make_extractor(_flag_v=False)
        clean_engine = DPKT(clean_extractor)
        clean_reader = FakeReader()
        with mock.patch.object(clean_engine._expkg.pcap, 'Reader', return_value=clean_reader):
            clean_engine.run()
        self.assertIs(clean_engine._extmp, clean_reader)

        extractor, sink = make_extractor(_flag_f=False)
        engine = DPKT(extractor)
        engine._extmp = FakeReader()

        class ParsedPacket:
            def __init__(self, data: bytes) -> None:
                self.data = data

        with mock.patch.object(engine, '_get_protocol', return_value=ParsedPacket):
            with mock.patch('pcapkit.toolkit.dpkt.packet2dict', return_value={'packet': True}):
                with mock.patch('pcapkit.toolkit.dpkt.ipv4_reassembly', return_value='ipv4'):
                    with mock.patch('pcapkit.toolkit.dpkt.ipv6_reassembly', return_value='ipv6'):
                        with mock.patch('pcapkit.toolkit.dpkt.tcp_reassembly', return_value='tcp'):
                            with mock.patch('pcapkit.toolkit.dpkt.tcp_traceflow', return_value='trace'):
                                packet = engine.read_frame()

        self.assertIsInstance(packet, ParsedPacket)
        self.assertEqual(extractor._offmt, 'unit')
        extractor._reasm.ipv4.assert_called_once_with('ipv4')
        extractor._reasm.ipv6.assert_called_once_with('ipv6')
        extractor._reasm.tcp.assert_called_once_with('tcp')
        extractor._trace.tcp.assert_called_once_with('trace')
        self.assertEqual(extractor._frame, [packet])

        file_mode, file_sink = make_extractor(_flag_f=True, _flag_r=False,
                                              _flag_t=False, _flag_d=False)
        engine = DPKT(file_mode)
        engine._extmp = FakeReader()
        with mock.patch.object(engine, '_get_protocol', return_value=ParsedPacket):
            with mock.patch('pcapkit.toolkit.dpkt.packet2dict', return_value={'packet': True}):
                with mock.patch('pcapkit.toolkit.dpkt.ipv4_reassembly', return_value='unused'):
                    with mock.patch('pcapkit.toolkit.dpkt.ipv6_reassembly', return_value='unused'):
                        with mock.patch('pcapkit.toolkit.dpkt.tcp_reassembly', return_value='unused'):
                            with mock.patch('pcapkit.toolkit.dpkt.tcp_traceflow', return_value='unused'):
                                self.assertIsInstance(engine.read_frame(), ParsedPacket)
        self.assertEqual(file_sink.paths[-1], 'out/Frame 1.json')

        quiet, quiet_sink = make_extractor(_flag_q=True, _flag_r=True, _flag_t=True,
                                           _flag_d=False)
        engine = DPKT(quiet)
        engine._extmp = FakeReader()
        with mock.patch.object(engine, '_get_protocol', return_value=ParsedPacket):
            with mock.patch('pcapkit.toolkit.dpkt.packet2dict', return_value={'packet': True}):
                with mock.patch('pcapkit.toolkit.dpkt.ipv4_reassembly', return_value=None):
                    with mock.patch('pcapkit.toolkit.dpkt.ipv6_reassembly', return_value=None):
                        with mock.patch('pcapkit.toolkit.dpkt.tcp_reassembly', return_value=None):
                            with mock.patch('pcapkit.toolkit.dpkt.tcp_traceflow', return_value=None):
                                self.assertIsInstance(engine.read_frame(), ParsedPacket)
        self.assertEqual(quiet_sink.records, [])
        quiet._reasm.ipv4.assert_not_called()
        quiet._trace.tcp.assert_not_called()

        no_protocols, _ = make_extractor(_flag_r=True, _flag_t=True, _flag_d=False,
                                         _ipv4=False, _ipv6=False, _tcp=False)
        engine = DPKT(no_protocols)
        engine._extmp = FakeReader()
        with mock.patch.object(engine, '_get_protocol', return_value=ParsedPacket):
            with mock.patch('pcapkit.toolkit.dpkt.packet2dict', return_value={'packet': True}):
                with mock.patch('pcapkit.toolkit.dpkt.ipv4_reassembly', return_value='unused'):
                    with mock.patch('pcapkit.toolkit.dpkt.ipv6_reassembly', return_value='unused'):
                        with mock.patch('pcapkit.toolkit.dpkt.tcp_reassembly', return_value='unused'):
                            with mock.patch('pcapkit.toolkit.dpkt.tcp_traceflow', return_value='unused'):
                                self.assertIsInstance(engine.read_frame(), ParsedPacket)
        no_protocols._reasm.ipv4.assert_not_called()
        no_protocols._trace.tcp.assert_not_called()

        disabled, _ = make_extractor(_flag_r=False, _flag_t=False, _flag_d=False)
        engine = DPKT(disabled)
        engine._extmp = FakeReader()
        with mock.patch.object(engine, '_get_protocol', return_value=ParsedPacket):
            with mock.patch('pcapkit.toolkit.dpkt.packet2dict', return_value={'packet': True}):
                with mock.patch('pcapkit.toolkit.dpkt.ipv4_reassembly', return_value='unused'):
                    with mock.patch('pcapkit.toolkit.dpkt.ipv6_reassembly', return_value='unused'):
                        with mock.patch('pcapkit.toolkit.dpkt.tcp_reassembly', return_value='unused'):
                            with mock.patch('pcapkit.toolkit.dpkt.tcp_traceflow', return_value='unused'):
                                self.assertIsInstance(engine.read_frame(), ParsedPacket)
        disabled._reasm.ipv4.assert_not_called()
        disabled._trace.tcp.assert_not_called()

        engine._extmp = types.SimpleNamespace(datalink=lambda: LinkType.ETHERNET)
        self.assertEqual(engine._get_protocol().__name__, 'Ethernet')
        self.assertEqual(engine._get_protocol(LinkType.ETHERNET).__name__, 'Ethernet')
        self.assertEqual(engine._get_protocol(LinkType.IPV4).__name__, 'IP')
        self.assertEqual(engine._get_protocol(LinkType.IPV6).__name__, 'IP6')
        raw_cls = engine._get_protocol(LinkType.NULL)
        raw = raw_cls(b'raw')
        self.assertEqual(bytes(raw), b'raw')
        self.assertEqual(len(raw), 3)

    def test_scapy_run_and_read_frame(self) -> None:
        from pcapkit.foundation.engines.scapy import Scapy

        packet = object()
        extractor, sink = make_extractor(_exptl='tcp', _flag_v=True)
        engine = Scapy(extractor)
        with mock.patch.object(engine._expkg, 'sniff', return_value=[packet]) as sniff:
            engine.run()
        sniff.assert_called_once_with(offline='capture.pcap')
        self.assertTrue(callable(extractor._vfunc))

        clean_extractor, _ = make_extractor(_flag_v=False)
        clean_engine = Scapy(clean_extractor)
        with mock.patch.object(clean_engine._expkg, 'sniff', return_value=[packet]) as sniff:
            clean_engine.run()
        sniff.assert_called_once_with(offline='capture.pcap')

        extractor, sink = make_extractor(_flag_f=False)
        engine = Scapy(extractor)
        engine._extmp = iter([packet])
        with mock.patch('pcapkit.toolkit.scapy.packet2dict', return_value={'packet': True}):
            with mock.patch('pcapkit.toolkit.scapy.ipv4_reassembly', return_value='ipv4'):
                with mock.patch('pcapkit.toolkit.scapy.ipv6_reassembly', return_value='ipv6'):
                    with mock.patch('pcapkit.toolkit.scapy.tcp_reassembly', return_value='tcp'):
                        with mock.patch('pcapkit.toolkit.scapy.tcp_traceflow', return_value='trace'):
                            self.assertIs(engine.read_frame(), packet)
        self.assertEqual(extractor._frnum, 1)
        extractor._reasm.ipv4.assert_called_once_with('ipv4')
        extractor._trace.tcp.assert_called_once_with('trace')
        self.assertEqual(extractor._frame, [packet])

        file_mode, file_sink = make_extractor(_flag_f=True, _flag_d=False)
        engine = Scapy(file_mode)
        engine._extmp = iter([packet])
        with mock.patch('pcapkit.toolkit.scapy.packet2dict', return_value={'packet': True}):
            with mock.patch('pcapkit.toolkit.scapy.ipv4_reassembly', return_value=None):
                with mock.patch('pcapkit.toolkit.scapy.ipv6_reassembly', return_value=None):
                    with mock.patch('pcapkit.toolkit.scapy.tcp_reassembly', return_value=None):
                        with mock.patch('pcapkit.toolkit.scapy.tcp_traceflow', return_value=None):
                            self.assertIs(engine.read_frame(), packet)
        self.assertEqual(file_sink.paths[-1], 'out/Frame 1.json')
        file_mode._reasm.ipv4.assert_not_called()
        file_mode._trace.tcp.assert_not_called()

        disabled, _ = make_extractor(_flag_q=True, _flag_r=False, _flag_t=False, _flag_d=False)
        engine = Scapy(disabled)
        engine._extmp = iter([packet])
        with mock.patch('pcapkit.toolkit.scapy.packet2dict', return_value={'packet': True}):
            with mock.patch('pcapkit.toolkit.scapy.ipv4_reassembly', return_value='unused'):
                with mock.patch('pcapkit.toolkit.scapy.ipv6_reassembly', return_value='unused'):
                    with mock.patch('pcapkit.toolkit.scapy.tcp_reassembly', return_value='unused'):
                        with mock.patch('pcapkit.toolkit.scapy.tcp_traceflow', return_value='unused'):
                            self.assertIs(engine.read_frame(), packet)
        disabled._reasm.ipv4.assert_not_called()

        no_protocols, _ = make_extractor(_flag_q=True, _flag_r=True, _flag_t=True,
                                         _flag_d=False, _ipv4=False, _ipv6=False,
                                         _tcp=False)
        engine = Scapy(no_protocols)
        engine._extmp = iter([packet])
        with mock.patch('pcapkit.toolkit.scapy.packet2dict', return_value={'packet': True}):
            with mock.patch('pcapkit.toolkit.scapy.ipv4_reassembly', return_value='unused'):
                with mock.patch('pcapkit.toolkit.scapy.ipv6_reassembly', return_value='unused'):
                    with mock.patch('pcapkit.toolkit.scapy.tcp_reassembly', return_value='unused'):
                        with mock.patch('pcapkit.toolkit.scapy.tcp_traceflow', return_value='unused'):
                            self.assertIs(engine.read_frame(), packet)
        no_protocols._reasm.ipv4.assert_not_called()
        no_protocols._trace.tcp.assert_not_called()

    def test_pyshark_run_read_frame_and_close(self) -> None:
        from pcapkit.foundation.engines.pyshark import PyShark

        class FakeCapture:
            def __init__(self) -> None:
                self.closed = False
                self.packet = types.SimpleNamespace(number='7',
                                                    frame_info=types.SimpleNamespace(protocols='eth:ip:tcp'))

            def next(self):
                return self.packet

            def close(self) -> None:
                self.closed = True

        capture = FakeCapture()
        extractor, sink = make_extractor(_exlyr='internet', _flag_v=True)
        engine = PyShark(extractor)
        with mock.patch.object(engine._expkg, 'FileCapture', return_value=capture) as file_capture:
            engine.run()
        file_capture.assert_called_once_with('capture.pcap', keep_packets=False)
        self.assertFalse(extractor._flag_r)
        self.assertIsNone(extractor._reasm.ipv4)
        self.assertTrue(callable(extractor._vfunc))

        clean_extractor, _ = make_extractor(_flag_v=False, _flag_r=False,
                                            _ipv4=False, _ipv6=False, _tcp=False)
        clean_engine = PyShark(clean_extractor)
        with mock.patch.object(clean_engine._expkg, 'FileCapture', return_value=capture):
            clean_engine.run()
        self.assertFalse(callable(getattr(clean_extractor._vfunc, '__name__', None)))

        extractor, sink = make_extractor(_flag_f=True)
        engine = PyShark(extractor)
        engine._extmp = capture
        with mock.patch('pcapkit.toolkit.pyshark.packet2dict', return_value={'packet': True}):
            with mock.patch('pcapkit.toolkit.pyshark.tcp_traceflow', return_value='trace'):
                packet = engine.read_frame()
        self.assertIs(packet, capture.packet)
        self.assertEqual(extractor._frnum, 7)
        self.assertEqual(sink.paths[-1], 'out/Frame 7.json')
        extractor._trace.tcp.assert_called_once_with('trace')
        self.assertEqual(extractor._frame, [packet])

        engine.close()
        self.assertTrue(capture.closed)

        stream_mode, stream_sink = make_extractor(_flag_f=False, _flag_t=True, _flag_d=False)
        engine = PyShark(stream_mode)
        engine._extmp = capture
        with mock.patch('pcapkit.toolkit.pyshark.packet2dict', return_value={'packet': True}):
            with mock.patch('pcapkit.toolkit.pyshark.tcp_traceflow', return_value=None):
                self.assertIs(engine.read_frame(), capture.packet)
        self.assertEqual(stream_sink.records[-1][1], 'Frame 7')
        stream_mode._trace.tcp.assert_not_called()

        disabled, _ = make_extractor(_flag_q=True, _flag_t=False, _flag_d=False)
        engine = PyShark(disabled)
        engine._extmp = capture
        with mock.patch('pcapkit.toolkit.pyshark.packet2dict', return_value={'packet': True}):
            with mock.patch('pcapkit.toolkit.pyshark.tcp_traceflow', return_value='unused'):
                self.assertIs(engine.read_frame(), capture.packet)
        disabled._trace.tcp.assert_not_called()

        no_tcp, _ = make_extractor(_flag_q=True, _flag_t=True, _flag_d=False, _tcp=False)
        engine = PyShark(no_tcp)
        engine._extmp = capture
        with mock.patch('pcapkit.toolkit.pyshark.packet2dict', return_value={'packet': True}):
            with mock.patch('pcapkit.toolkit.pyshark.tcp_traceflow', return_value='unused'):
                self.assertIs(engine.read_frame(), capture.packet)
        no_tcp._trace.tcp.assert_not_called()


if __name__ == '__main__':
    unittest.main()
