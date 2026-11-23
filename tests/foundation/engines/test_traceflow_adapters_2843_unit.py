# -*- coding: utf-8 -*-
"""Every engine feeds flow tracing through the adapters its ``__traceflow__`` names.

GitHub issue #2843. Each engine wired the TCP tracer's input itself, so a flow
tracer could reach an engine only by editing it. Each engine's ``__traceflow__`` now
maps a tracer's registered name to the :mod:`pcapkit.toolkit` adapter feeding it,
written by ``EngineBase.register_traceflow``; ``_setup_traceflow`` drops an enabled
tracer with no adapter, with a warning, and ``_traceflow`` feeds the rest.

The adapter maps are checked against every registered flow tracer and engine. The
extraction cases trace TCP through a spy standing in for each engine's adapter, and
:file:`tests/foundation/test_extraction_tracers_2843_unit.py` traces a second tracer
beside it. Their captures are built in memory, and an engine whose library is missing
or unusable here is skipped. Classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

from __future__ import annotations

import importlib
import importlib.util
import os
import shutil
import struct
import tempfile
import types
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): drives third-party engines whose installable releases vary by
#: interpreter.
__tier__ = 'ALL'

#: ``(engine class, registered flow tracer)`` pairs with no adapter, and why. Any other
#: pair has one, named ``<tracer>_traceflow`` in the engine's toolkit module.
UNSUPPORTED = {
    ('PyPCAP', 'tcp'): 'PyPCAP dissects nothing, so there is no TCP layer to read',
    ('PCAP_CT', 'tcp'): 'pcap-ct dissects nothing, so there is no TCP layer to read',
}

#: How each engine calls a flow tracing adapter: the positional arguments it passes,
#: and the keywords.
CONVENTIONS = {
    'PCAP': (1, {'data_link'}),
    'PCAPNG': (1, {'nanosecond'}),
    'DPKT': (2, {'data_link', 'count'}),
    'Scapy': (1, {'count'}),
    'PyShark': (1, {'count'}),
    'PyPCAPFile': (1, {'data_link', 'count'}),
}

#: Capture timestamps of the frames every extraction case reads.
TIMES = (1000.0, 1000.5, 1001.0)

ETH_IPV4 = b'\x00\x11\x22\x33\x44\x55' b'\x66\x77\x88\x99\xaa\xbb' b'\x08\x00'
SRC, DST = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
SYN, FIN, PSH, ACK = 0x02, 0x01, 0x08, 0x10


def checksum(data: bytes) -> int:
    """The Internet checksum of ``data`` (RFC 1071)."""
    data += bytes(len(data) % 2)
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ipv4_tcp(seq: int, flags: int, payload: bytes = b'') -> bytes:
    """An Ethernet frame of an IPv4 datagram carrying one TCP segment, port 40000 to 80."""
    tcp = bytearray(struct.pack('!HHIIBBHHH', 40000, 80, seq, 0, 5 << 4, flags, 65535, 0, 0) + payload)
    tcp[16:18] = struct.pack('!H', checksum(SRC + DST + struct.pack('!BBH', 0, 6, len(tcp)) + bytes(tcp)))
    header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0, SRC, DST))
    header[10:12] = struct.pack('!H', checksum(bytes(header)))
    return ETH_IPV4 + bytes(header) + bytes(tcp)


#: One TCP connection's frames: SYN, data, FIN.
FRAMES = [(TIMES[0], ipv4_tcp(1000, SYN)),
          (TIMES[1], ipv4_tcp(1001, PSH | ACK, b'data')),
          (TIMES[2], ipv4_tcp(1005, FIN | ACK))]


def pcap(frames: 'list[tuple[float, bytes]]') -> bytes:
    """A microsecond little-endian PCAP savefile of Ethernet ``frames``."""
    octets = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for (timestamp, data) in frames:
        usec = round(timestamp * 1_000_000)
        octets += struct.pack('<IIII', usec // 1_000_000, usec % 1_000_000, len(data), len(data)) + data
    return octets


def pcapng(frames: 'list[tuple[float, bytes]]') -> bytes:
    """A little-endian PCAP-NG section of one Ethernet interface and ``frames`` as EPBs."""
    def block(kind: int, body: bytes) -> bytes:
        body += bytes(-len(body) % 4)
        return struct.pack('<II', kind, 12 + len(body)) + body + struct.pack('<I', 12 + len(body))

    octets = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    octets += block(1, struct.pack('<HHI', 1, 0, 65535))
    for (timestamp, data) in frames:
        usec = round(timestamp * 1_000_000)
        octets += block(6, struct.pack('<IIIII', 0, usec >> 32, usec & 0xFFFFFFFF, len(data), len(data)) + data)
    return octets


def engines() -> 'list[type]':
    """Every engine class: the default engine's readers, then each registered engine."""
    from pcapkit.corekit.module import ModuleDescriptor
    from pcapkit.foundation.engines.pcap import PCAP
    from pcapkit.foundation.engines.pcapng import PCAPNG
    from pcapkit.foundation.extraction import Extractor

    found = [PCAP, PCAPNG]
    for entry in Extractor.__engine__.values():
        found.append(entry.klass if isinstance(entry, ModuleDescriptor) else entry)
    return found


class TraceflowAdapterTestCase(unittest.TestCase):
    """Import once per class, and write captures to files the extractors outlive."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _capture(self, octets: bytes, suffix: str) -> str:
        """Write ``octets`` to a temporary file that outlives the test's extractors."""
        handle = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)  # pylint: disable=consider-using-with
        with handle:
            handle.write(octets)
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def _extract(self, path: str, engine: str, traceflow: 'Any') -> 'tuple[Any, list[str]]':
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.options import TraceFlowOptions

        fout = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, fout, True)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            extractor = Extractor(path, engine=engine,  # type: ignore[arg-type]
                                  traceflow=TraceFlowOptions(protocols=traceflow, fout=fout, format='json'))
        return extractor, [str(warning.message) for warning in caught]


class AdapterMapTests(TraceflowAdapterTestCase):
    """Each engine maps every registered flow tracer to its toolkit adapter, or records why not."""

    def test_every_engine_has_a_calling_convention(self) -> None:
        names = {engine.__name__ for engine in engines()}
        self.assertEqual(set(CONVENTIONS), names - {engine for (engine, _) in UNSUPPORTED})

    def test_every_engine_maps_every_registered_tracer(self) -> None:
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.foundation.extraction import Extractor

        for engine in engines():
            toolkit = engine.__module__.replace('pcapkit.foundation.engines.', 'pcapkit.toolkit.')
            for name in Extractor.__traceflow__:
                with self.subTest(engine=engine.__name__, tracer=name):
                    if (engine.__name__, name) in UNSUPPORTED:
                        self.assertNotIn(name, engine.__traceflow__)
                        continue
                    adapter = engine.__traceflow__[name]
                    self.assertEqual(adapter, ModuleDescriptor(toolkit, f'{name}_traceflow'))
                    self.assertIs(adapter.klass, getattr(importlib.import_module(toolkit), f'{name}_traceflow'))

    def test_unsupported_names_real_engines_and_tracers(self) -> None:
        from pcapkit.foundation.extraction import Extractor

        names = {engine.__name__ for engine in engines()}
        for (engine, tracer) in UNSUPPORTED:
            with self.subTest(engine=engine, tracer=tracer):
                self.assertIn(engine, names)
                self.assertIn(tracer, Extractor.__traceflow__)

    def test_adapters_are_registered_per_class(self) -> None:
        from pcapkit.foundation.engines.engine import Engine
        from pcapkit.foundation.engines.pcap import PCAP
        from pcapkit.utilities.exceptions import RegistryError
        from pcapkit.utilities.warnings import RegistryWarning

        class Derived(PCAP):
            pass

        def adapter(frame: 'Any', *, data_link: 'Any') -> None:
            return None

        Derived.register_traceflow('DUMMY', adapter)
        self.assertIs(Derived.__traceflow__['dummy'], adapter)
        self.assertNotIn('dummy', PCAP.__traceflow__)
        self.assertNotIn('dummy', Engine.__traceflow__)
        # the subclass still inherits the adapters it was derived with
        self.assertEqual(Derived.__traceflow__['tcp'], PCAP.__traceflow__['tcp'])
        # and the reassembly map is a table of its own
        self.assertNotIn('dummy', Derived.__reassembly__)

        with self.assertWarnsRegex(RegistryWarning, 'flow tracing adapter dummy already registered'):
            Derived.register_traceflow('dummy', lambda frame, *, data_link: None)
        with self.assertRaises(RegistryError):
            Derived.register_traceflow('dummy', 'not callable')  # type: ignore[arg-type]


class SetupAndFeedTests(TraceflowAdapterTestCase):
    """``_setup_traceflow`` drops what an engine cannot feed, and ``_traceflow`` feeds the rest."""

    def _bare(self, adapters: 'dict[str, Any]') -> 'type':
        from pcapkit.foundation.engines.engine import Engine

        class Bare(Engine):
            __traceflow__ = adapters

            def run(self) -> None:
                self._setup_traceflow()

            def read_frame(self) -> None:
                self._traceflow('frame', count=1)

        return Bare

    def _extractor(self, tracer: 'Any') -> 'Any':
        from pcapkit.foundation.traceflow import TraceFlowManager

        return types.SimpleNamespace(_flag_t=True, _exnam='bare', _trace=TraceFlowManager(tcp=tracer))

    def test_an_engine_with_no_adapters_turns_tracing_off(self) -> None:
        from pcapkit.utilities.warnings import AttributeWarning

        extractor = self._extractor(mock.Mock())
        with self.assertWarns(AttributeWarning) as caught:
            self._bare({})(extractor).run()
        self.assertEqual(str(caught.warning), "'Extractor(engine=bare)' object does not support "
                                              "flow tracing; so traceflow=['tcp'] will be ignored")
        self.assertFalse(extractor._flag_t)
        self.assertIsNone(dict(extractor._trace.items()).get('tcp'))

    def test_a_tracer_with_no_adapter_is_dropped(self) -> None:
        from pcapkit.foundation.traceflow.tcp import TCP
        from pcapkit.utilities.warnings import AttributeWarning

        tracer = mock.Mock(spec=TCP)
        tracer.name = TCP.name
        extractor = self._extractor(tracer)
        with self.assertWarns(AttributeWarning) as caught:
            self._bare({'udp': lambda frame, *, count: None})(extractor).run()
        self.assertEqual(str(caught.warning), "'Extractor(engine=bare)' object does not support "
                                              "TCP flow tracing; so 'tcp' will be ignored")
        # with no tracer left, tracing is off
        self.assertFalse(extractor._flag_t)
        self.assertIsNone(dict(extractor._trace.items()).get('tcp'))

    def test_a_supported_tracer_is_kept_and_fed(self) -> None:
        tracer = mock.Mock()
        extractor = self._extractor(tracer)
        trace = extractor._trace
        adapter = mock.Mock(side_effect=[('first', 'second'), None, 'third'])
        engine = self._bare({'tcp': adapter})(extractor)

        with warnings.catch_warnings():
            warnings.simplefilter('error')
            engine.run()
        self.assertTrue(extractor._flag_t)
        self.assertIs(extractor._trace, trace)

        for _ in range(3):
            engine.read_frame()
        adapter.assert_called_with('frame', count=1)
        self.assertEqual(adapter.call_count, 3)
        # each of a tuple is fed, and None feeds nothing
        self.assertEqual([call.args for call in tracer.call_args_list], [('first',), ('second',), ('third',)])

    def test_only_the_unsupported_tracer_is_dropped(self) -> None:
        # ReassemblyManager is keyed by name, as TraceFlowManager is, so it holds a
        # second tracer beside TCP's
        from pcapkit.foundation.reassembly import ReassemblyManager
        from pcapkit.utilities.warnings import AttributeWarning

        tcp, dummy = mock.Mock(), mock.Mock()
        tcp.name = 'TCP'
        extractor = types.SimpleNamespace(_flag_t=True, _exnam='bare',
                                          _trace=ReassemblyManager(tcp=tcp, dummy=dummy))
        engine = self._bare({'dummy': mock.Mock(return_value='record')})(extractor)
        with mock.patch('pcapkit.foundation.engines.engine.TraceFlowManager', ReassemblyManager):
            with self.assertWarns(AttributeWarning) as caught:
                engine.run()
        self.assertEqual(str(caught.warning), "'Extractor(engine=bare)' object does not support "
                                              "TCP flow tracing; so 'tcp' will be ignored")
        self.assertTrue(extractor._flag_t)
        self.assertEqual(dict(extractor._trace.items()), {'dummy': dummy})

        engine.read_frame()
        dummy.assert_called_once_with('record')
        tcp.assert_not_called()

    def test_nothing_to_set_up(self) -> None:
        # tracing off, so there may be no manager at all
        extractor = types.SimpleNamespace(_flag_t=False, _exnam='bare')
        self._bare({})(extractor).run()
        self.assertFalse(hasattr(extractor, '_trace'))

        # tracing on with no tracer held, as for a name the Extractor itself dropped
        extractor = self._extractor(None)
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            self._bare({})(extractor).run()
            self._bare({})(extractor).read_frame()
        self.assertTrue(extractor._flag_t)

    def test_libpcap_engines_feed_a_registered_adapter(self) -> None:
        # PyPCAP and pcap-ct ship no adapter, so read_frame is driven with a fake handle
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.engines.pcap_ct import PCAP_CT
        from pcapkit.foundation.engines.pypcap import PyPCAP

        for base in (PyPCAP, PCAP_CT):
            with self.subTest(engine=base.__name__):
                class Derived(base):  # type: ignore[valid-type,misc]
                    pass

                adapter = mock.Mock(return_value='record')
                Derived.register_traceflow('tcp', adapter)
                self.assertEqual(base.__traceflow__, {})

                tracer = mock.Mock()
                extractor = self._extractor(tracer)
                extractor.__dict__.update(_flag_q=True, _flag_r=False, _flag_d=False, _frnum=0,
                                          _vfunc=mock.Mock())
                engine = Derived.__new__(Derived)
                engine._extractor = extractor
                engine._extmp = iter([(TIMES[0], b'raw')])
                engine._dlink = LinkType.ETHERNET

                engine._setup_traceflow()
                self.assertEqual(engine.read_frame(), (TIMES[0], b'raw'))
                adapter.assert_called_once_with(b'raw', TIMES[0], data_link=LinkType.ETHERNET, count=1)
                tracer.assert_called_once_with('record')


class ExtractionTests(TraceflowAdapterTestCase):
    """An extraction traces TCP through whatever adapter its engine maps ``tcp`` to."""

    def _runnable(self) -> 'list[tuple[str, str, str]]':
        """``(engine key, capture suffix, engine class name)`` for each engine that runs here."""
        from pcapkit.foundation.engines.pyshark import PyShark
        from pcapkit.foundation.engines.pypcapfile import PyPCAPFile

        found = [('default', '.pcap', 'PCAP'), ('default', '.pcapng', 'PCAPNG')]
        if importlib.util.find_spec('dpkt') is not None:
            found += [('dpkt', '.pcap', 'DPKT'), ('dpkt', '.pcapng', 'DPKT')]
        if importlib.util.find_spec('scapy') is not None:
            found += [('scapy', '.pcap', 'Scapy'), ('scapy', '.pcapng', 'Scapy')]
        if importlib.util.find_spec('pcapfile') is not None and PyPCAPFile.unsupported_reason() is None:
            found.append(('pypcapfile', '.pcap', 'PyPCAPFile'))
        if importlib.util.find_spec('pyshark') is not None and PyShark.unsupported_reason() is None:
            found += [('pyshark', '.pcap', 'PyShark'), ('pyshark', '.pcapng', 'PyShark')]
        return found

    def _engine_class(self, name: str) -> 'type':
        return {engine.__name__: engine for engine in engines()}[name]

    def test_tcp_is_traced_through_each_engines_adapter(self) -> None:
        captures = {'.pcap': self._capture(pcap(FRAMES), '.pcap'),
                    '.pcapng': self._capture(pcapng(FRAMES), '.pcapng')}

        for (key, suffix, name) in self._runnable():
            with self.subTest(engine=key, capture=suffix):
                engine = self._engine_class(name)
                shipped = engine.__traceflow__['tcp']
                spy = mock.Mock(side_effect=shipped.klass)
                with mock.patch.dict(engine.__traceflow__, {'tcp': spy}):
                    extractor, messages = self._extract(captures[suffix], key, ['tcp'])
                self.assertEqual(type(extractor.engine).__name__, name, messages)

                # one call per frame, in the engine's own calling convention
                (positional, keywords) = CONVENTIONS[name]
                self.assertEqual(spy.call_count, len(FRAMES), messages)
                for (number, call) in enumerate(spy.call_args_list, 1):
                    self.assertEqual((len(call.args), set(call.kwargs)), (positional, keywords))
                    self.assertEqual(call.kwargs.get('count', number), number)
                flows = extractor.traceflow.tcp
                self.assertEqual(len(flows), 1, flows)
                self.assertEqual(flows[0].index, (1, 2, 3))
                self.assertFalse([message for message in messages if 'flow tracing' in message], messages)

    def test_a_spy_declining_every_frame_traces_nothing(self) -> None:
        from pcapkit.foundation.engines.pcap import PCAP

        path = self._capture(pcap(FRAMES), '.pcap')
        spy = mock.Mock(return_value=None)
        with mock.patch.dict(PCAP.__traceflow__, {'tcp': spy}):
            extractor, _ = self._extract(path, 'default', ['tcp'])
        self.assertEqual(spy.call_count, len(FRAMES))
        self.assertEqual(extractor.traceflow.tcp, ())

    def test_libpcap_engines_drop_tcp_tracing(self) -> None:
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.utilities.exceptions import UnsupportedCall

        path = self._capture(pcap(FRAMES), '.pcap')
        ran = False
        for (key, name) in (('pypcap', 'PyPCAP'), ('pcap_ct', 'PCAP_CT')):
            with self.subTest(engine=key):
                if Extractor.import_test(self._engine_class(name).module, name=name) is None:
                    continue
                extractor, messages = self._extract(path, key, ['tcp'])
                if type(extractor.engine).__name__ != name:
                    continue
                ran = True
                self.assertIn(f"'Extractor(engine={key})' object does not support flow tracing; "
                              "so traceflow=['tcp'] will be ignored", messages)
                with self.assertRaises(UnsupportedCall):
                    _ = extractor.traceflow
        if not ran:
            self.skipTest('neither PyPCAP nor pcap-ct is usable here')


if __name__ == '__main__':
    unittest.main()
