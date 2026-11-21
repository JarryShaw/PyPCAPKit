# -*- coding: utf-8 -*-
"""Every registered reassembler is fed, with each frame's timestamp.

GitHub issue #2814. :class:`~pcapkit.foundation.reassembly.ReassemblyManager`
held a field per built-in reassembler, and the extractor, every engine and
:func:`~pcapkit.interface.core.reassemble` named each one, so registering
another was inert. A reassembler's clock moved only when it was fed, so an IPv6
buffer with no later fragment never timed out.

Each engine now feeds every enabled reassembler through its ``__reassembly__``
adapters, after advancing its clock to the frame's timestamp. A dummy
reassembler registered under a name of its own is fed on every engine that
supports reassembly, and an engine without an adapter for it says so.

Every case builds its capture in memory, written to a temporary file for the
engines that open one by name. Classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

from __future__ import annotations

import importlib.util
from ipaddress import ip_address
import os
import struct
import tempfile
import types
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): drives third-party engines whose installable releases vary by
#: interpreter.
__tier__ = 'ALL'

#: The name the dummy reassembler is registered under.
NAME = 'dummy'

#: Capture timestamps of the frames every engine case reads.
TIMES = (1000.0, 1000.5, 1061.0)

ETH_IPV4 = b'\x00\x11\x22\x33\x44\x55' b'\x66\x77\x88\x99\xaa\xbb' b'\x08\x00'
ETH_IPV6 = b'\x00\x11\x22\x33\x44\x55' b'\x66\x77\x88\x99\xaa\xbb' b'\x86\xdd'


def ipv4_udp() -> bytes:
    """An Ethernet frame of an unfragmented IPv4 datagram carrying UDP."""
    udp = struct.pack('!HHHH', 1234, 5678, 12, 0) + b'data'
    header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0x4000, 64, 17, 0,
                                   bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])))
    total = sum(struct.unpack('!10H', header))
    total = (total & 0xFFFF) + (total >> 16)
    header[10:12] = struct.pack('!H', ~((total & 0xFFFF) + (total >> 16)) & 0xFFFF)
    return ETH_IPV4 + bytes(header) + udp


def ipv6_first_fragment() -> bytes:
    """An Ethernet frame of the first IPv6 fragment, **M** set, of a UDP datagram."""
    payload = struct.pack('!HHHH', 1234, 5678, 24, 0) + b'A' * 8
    fragment = struct.pack('!BBHI', 17, 0, 1, 0x2814)
    header = struct.pack('!IHBB16s16s', 6 << 28, len(fragment) + len(payload), 44, 64,
                         bytes(15) + b'\x01', bytes(15) + b'\x02')
    return ETH_IPV6 + header + fragment + payload


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


class RegisteredReassemblerTestCase(unittest.TestCase):
    """Register a dummy reassembler and adapters, and undo both afterwards."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _capture(self, octets: bytes, suffix: str) -> str:
        """Write ``octets`` to a temporary file that outlives the test's extractors."""
        handle = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)  # pylint: disable=consider-using-with
        with handle:
            handle.write(octets)
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def _dummy(self) -> 'type':
        """Register a dummy reassembler recording what it is fed and its clock."""
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.reassembly.reassembly import Reassembly

        class Dummy(Reassembly):
            __protocol_name__ = 'Dummy'

            def __init__(self, **kwargs: 'Any') -> None:
                super().__init__(**kwargs)
                self.options = kwargs
                self.clock = []  # type: list[float]

            def reassembly(self, info: 'Any') -> None:
                self._dtgram.append(info)

            def submit(self, buf: 'Any', **kwargs: 'Any') -> 'list[Any]':
                return []

            def expire(self, timestamp: float) -> 'list[Any]':
                self.clock.append(timestamp)
                return super().expire(timestamp)

        Extractor.register_reassembly(NAME, Dummy)
        self.addCleanup(Extractor.__reassembly__.pop, NAME)
        return Dummy

    def _adapt(self, engine: 'type', adapter: 'Any') -> None:
        """Register ``adapter`` for the dummy on ``engine``, undone after the test."""
        engine.register_reassembly(NAME, adapter)
        self.addCleanup(engine.__reassembly__.pop, NAME)

    def _extract(self, path: str, engine: str, **kwargs: 'Any') -> 'Any':
        from pcapkit.foundation.extraction import Extractor

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            extractor = Extractor(fin=path, nofile=True, engine=engine, reassembly=True, **kwargs)
        return extractor, [str(warning.message) for warning in caught]


class DummyFedOnEveryEngineTests(RegisteredReassemblerTestCase):
    """The dummy is fed through each engine's adapter, and sees every frame's timestamp."""

    def _engines(self) -> 'list[tuple[str, str, str]]':
        """``(engine key, capture suffix, engine class name)`` for each engine that runs here."""
        engines = [('default', '.pcap', 'PCAP'), ('default', '.pcapng', 'PCAPNG')]
        if importlib.util.find_spec('dpkt') is not None:
            engines += [('dpkt', '.pcap', 'DPKT'), ('dpkt', '.pcapng', 'DPKT')]
        if importlib.util.find_spec('scapy') is not None:
            engines += [('scapy', '.pcap', 'Scapy'), ('scapy', '.pcapng', 'Scapy')]

        from pcapkit.foundation.engines.pypcapfile import PyPCAPFile
        if importlib.util.find_spec('pcapfile') is not None and PyPCAPFile.unsupported_reason() is None:
            engines.append(('pypcapfile', '.pcap', 'PyPCAPFile'))
        return engines

    def _register_adapters(self) -> None:
        """One adapter per engine, each in that engine's calling convention, declining frame 2."""
        from pcapkit.foundation.engines.dpkt import DPKT
        from pcapkit.foundation.engines.pcap import PCAP
        from pcapkit.foundation.engines.pcapng import PCAPNG
        from pcapkit.foundation.engines.pypcapfile import PyPCAPFile
        from pcapkit.foundation.engines.scapy import Scapy

        def record(number: int) -> 'Any':
            return None if number == 2 else types.SimpleNamespace(number=number)

        self._adapt(PCAP, lambda frame: record(frame.info.number))
        self._adapt(PCAPNG, lambda block: record(block.info.number))
        self._adapt(DPKT, lambda packet, timestamp, *, count: record(count))
        self._adapt(Scapy, lambda packet, *, count: record(count))
        self._adapt(PyPCAPFile, lambda packet, *, count: record(count))

    def test_dummy_is_fed_and_clocked_on_every_engine(self) -> None:
        Dummy = self._dummy()
        self._register_adapters()
        frames = [(timestamp, ipv4_udp()) for timestamp in TIMES]
        captures = {'.pcap': self._capture(pcap(frames), '.pcap'),
                    '.pcapng': self._capture(pcapng(frames), '.pcapng')}

        for (engine, suffix, klass) in self._engines():
            with self.subTest(engine=engine, capture=suffix):
                extractor, messages = self._extract(captures[suffix], engine, reasm_protocols=[NAME])
                self.assertEqual(type(extractor.engine).__name__, klass, messages)

                dummy = extractor._reasm[NAME]
                self.assertIsInstance(dummy, Dummy)
                # frame 2's adapter declined, but its timestamp still reached the clock
                self.assertEqual(dummy.clock, list(TIMES))
                self.assertEqual([datagram.number for datagram in extractor.reassembly.dummy], [1, 3])
                # the built-ins keep their fields, as disabled
                self.assertIsNone(extractor.reassembly.ipv4)
                self.assertIsNone(extractor.reassembly.dtls)
                self.assertFalse([message for message in messages if 'reassembly' in message], messages)

    def test_extractor_options_reach_the_dummy(self) -> None:
        self._dummy()
        self._register_adapters()
        path = self._capture(pcap([(TIMES[0], ipv4_udp())]), '.pcap')
        # a name given twice, in either case, is made once
        extractor, _ = self._extract(path, 'default', reasm_protocols=['DUMMY', NAME], reasm_strict=False,
                                     reasm_store=True, reasm_timeout=5.0)
        self.assertEqual(list(extractor._reasm), [NAME])
        self.assertEqual(extractor._reasm[NAME].options, {'strict': False, 'store': True, 'timeout': 5.0})
        self.assertEqual(extractor._reasm[NAME].timeout, 5.0)

    def test_an_engine_without_an_adapter_drops_the_dummy(self) -> None:
        from pcapkit.foundation.engines.dpkt import DPKT

        self._dummy()
        # adapted on DPKT alone, so the default engine has nothing to feed it with
        self._adapt(DPKT, lambda packet, timestamp, *, count: None)
        path = self._capture(pcap([(TIMES[0], ipv4_udp())]), '.pcap')
        extractor, messages = self._extract(path, 'default', tcp=True, reasm_protocols=[NAME])

        self.assertIn("'Extractor(engine=default)' object does not support Dummy reassembly; "
                      "so 'dummy=True' will be ignored", messages)
        self.assertEqual(list(extractor._reasm), ['tcp'])
        self.assertNotIn(NAME, extractor.reassembly)
        self.assertEqual(extractor.reassembly.tcp, ())

    @unittest.skipUnless(importlib.util.find_spec('pyshark'), 'PyShark not installed')
    def test_an_engine_with_no_adapters_turns_reassembly_off(self) -> None:
        from pcapkit.foundation.engines.pyshark import PyShark
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.utilities.exceptions import UnsupportedCall

        self._dummy()
        self.assertEqual(PyShark.__reassembly__, {})
        path = self._capture(pcap([(TIMES[0], ipv4_udp())]), '.pcap')
        if Extractor.import_test('pyshark', name='PyShark') is None:
            self.skipTest('PyShark unusable here')
        extractor, messages = self._extract(path, 'pyshark', reasm_protocols=[NAME])
        if type(extractor.engine).__name__ != 'PyShark':
            self.skipTest('PyShark fell back to the default engine')

        self.assertTrue(any("does not support reassembly; so 'dummy=True' will be ignored" in message
                            for message in messages), messages)
        self.assertFalse(extractor._reasm)
        with self.assertRaises(UnsupportedCall):
            _ = extractor.reassembly

    def test_no_adapters_at_all_turns_reassembly_off(self) -> None:
        from pcapkit.foundation.engines.engine import Engine
        from pcapkit.foundation.reassembly import ReassemblyManager
        from pcapkit.utilities.warnings import AttributeWarning

        class Bare(Engine):
            def run(self) -> None:
                self._setup_reassembly()

            def read_frame(self) -> None:
                return None

        Dummy = self._dummy()
        # the reverse layout first, which PyPy would lay the next manager out in (#2814)
        ReassemblyManager(tcp=Dummy(), dummy=Dummy())
        extractor = types.SimpleNamespace(_flag_r=True, _exnam='bare',
                                          _reasm=ReassemblyManager(dummy=Dummy(), tcp=Dummy()))
        with self.assertWarns(AttributeWarning) as caught:
            Bare(extractor).run()
        self.assertEqual(str(caught.warning), "'Extractor(engine=bare)' object does not support "
                                              "reassembly; so 'dummy=True', 'tcp=True' will be ignored")
        self.assertFalse(extractor._flag_r)
        self.assertFalse(extractor._reasm)

    def test_an_unregistered_name_is_refused(self) -> None:
        from pcapkit.utilities.exceptions import FormatError

        path = self._capture(pcap([(TIMES[0], ipv4_udp())]), '.pcap')
        with self.assertRaises(FormatError):
            self._extract(path, 'default', reasm_protocols=['no-such-reassembly'])


class FrameClockTests(RegisteredReassemblerTestCase):
    """A stalled IPv6 buffer times out on later frames that are not IPv6 fragments."""

    def _ipv6_outcome(self, engine: str, gap: float) -> 'Any':
        from pcapkit.foundation.reassembly.data.data import Completion

        frames = [(TIMES[0], ipv6_first_fragment()), (TIMES[0] + gap, ipv4_udp())]
        path = self._capture(pcap(frames), '.pcap')
        extractor, messages = self._extract(path, engine, ipv6=True)
        datagrams = extractor.reassembly.ipv6
        self.assertEqual(len(datagrams), 1, messages)
        self.assertEqual(datagrams[0].index, (1,))
        return Completion, datagrams[0].completed

    def test_a_later_frame_times_the_buffer_out(self) -> None:
        engines = ['default']
        if importlib.util.find_spec('dpkt') is not None:
            engines.append('dpkt')
        if importlib.util.find_spec('scapy') is not None:
            engines.append('scapy')

        for engine in engines:
            with self.subTest(engine=engine):
                # past the 60 seconds of RFC 8200 section 4.5
                Completion, completed = self._ipv6_outcome(engine, 61.0)
                self.assertIs(completed, Completion.TIMEOUT)
                # within them, the buffer is still open when the capture ends
                Completion, completed = self._ipv6_outcome(engine, 30.0)
                self.assertIs(completed, Completion.PARTIAL)

    def test_advance_keeps_what_it_times_out(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.data.ip import Packet
        from pcapkit.foundation.reassembly.ipv6 import IPv6

        reasm = IPv6()
        reasm(Packet((ip_address('2001:db8::1'), ip_address('2001:db8::2'), 7, TransType.UDP), 1, 0,
                     40, True, 56, b'H' * 40, bytearray(16), TIMES[0]))
        reasm.advance(TIMES[0] + 30.0)
        self.assertEqual(len(reasm._buffer), 1)
        reasm.advance(TIMES[0] + 61.0)
        self.assertEqual(reasm._buffer, {})
        self.assertEqual([datagram.completed for datagram in reasm.datagram], [Completion.TIMEOUT])


class LookupTests(RegisteredReassemblerTestCase):
    """The extractor, its manager and :func:`~pcapkit.interface.core.reassemble` share one lookup."""

    def test_reassemble_makes_any_registered_reassembly(self) -> None:
        from pcapkit.foundation.reassembly.dtls import DTLS
        from pcapkit.foundation.reassembly.ipv4 import IPv4
        from pcapkit.interface.core import reassemble
        from pcapkit.protocols.internet.ipv4.protocol import IPv4 as IPv4_Protocol
        from pcapkit.utilities.exceptions import FormatError

        Dummy = self._dummy()
        dummy = reassemble(NAME, strict=True, timeout=7.0)
        self.assertIsInstance(dummy, Dummy)
        self.assertEqual(dummy.options, {'strict': True, 'store': True, 'timeout': 7.0})

        self.assertIsInstance(reassemble(IPv4_Protocol), IPv4)
        self.assertIsInstance(reassemble('ipv4'), IPv4)
        # DTLS takes no timeout, so none is passed, rather than one refused
        self.assertIsInstance(reassemble('DTLS', timeout=7.0), DTLS)
        with self.assertRaises(FormatError):
            reassemble('UDP')

    def test_manager_holds_the_enabled_reassemblers_only(self) -> None:
        from pcapkit.foundation.reassembly import ReassemblyManager

        tcp, dummy = object(), object()
        manager = ReassemblyManager(ipv4=None, tcp=tcp)
        self.assertEqual(list(manager), ['tcp'])
        manager = ReassemblyManager([('tcp', tcp), (NAME, dummy)], ipv6=None)
        self.assertEqual(dict(manager.items()), {'tcp': tcp, NAME: dummy})
        self.assertFalse(ReassemblyManager())

    def test_iteration_follows_the_order_given(self) -> None:
        # PyPy lays an instance's ``__dict__`` out in an earlier instance's order (#2814)
        from pcapkit.foundation.reassembly import ReassemblyManager
        from pcapkit.foundation.reassembly.data.data import ReassemblyData

        tcp, dummy = object(), object()
        self.assertEqual(list(ReassemblyManager(tcp=tcp, dummy=dummy)), ['tcp', NAME])
        manager = ReassemblyManager(dummy=dummy, tcp=tcp)
        self.assertEqual(list(manager), [NAME, 'tcp'])
        self.assertEqual([name for (name, _) in manager.items()], [NAME, 'tcp'])
        self.assertEqual(list(ReassemblyManager(manager)), [NAME, 'tcp'])

        self.assertEqual(list(ReassemblyData(late=(), early=()))[4:], ['late', 'early'])
        self.assertEqual(list(ReassemblyData(early=(), late=())), ['ipv4', 'ipv6', 'tcp', 'dtls', 'early', 'late'])

    def test_data_keeps_the_built_in_fields(self) -> None:
        from pcapkit.foundation.reassembly.data.data import ReassemblyData

        data = ReassemblyData(tcp=(), dummy=('datagram',))
        self.assertEqual(list(data), ['ipv4', 'ipv6', 'tcp', 'dtls', NAME])
        self.assertIsNone(data.ipv4)
        self.assertEqual(data.dummy, ('datagram',))

    def test_engine_adapters_are_registered_per_class(self) -> None:
        from pcapkit.foundation.engines.engine import Engine
        from pcapkit.foundation.engines.pcap import PCAP
        from pcapkit.utilities.exceptions import RegistryError
        from pcapkit.utilities.warnings import RegistryWarning

        class Derived(PCAP):
            pass

        def adapter(frame: 'Any') -> None:
            return None

        Derived.register_reassembly('DUMMY', adapter)
        self.assertIs(Derived.__reassembly__[NAME], adapter)
        self.assertNotIn(NAME, PCAP.__reassembly__)
        self.assertNotIn(NAME, Engine.__reassembly__)
        # the subclass still inherits the built-ins it was derived with
        self.assertEqual(Derived.__reassembly__['ipv4'], PCAP.__reassembly__['ipv4'])

        with self.assertWarns(RegistryWarning):
            Derived.register_reassembly(NAME, lambda frame: None)
        with self.assertRaises(RegistryError):
            Derived.register_reassembly(NAME, 'not callable')


if __name__ == '__main__':
    unittest.main()
