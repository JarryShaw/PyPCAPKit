# -*- coding: utf-8 -*-
"""DTLS reassembly is fed by the toolkit and parsed by the analysis (#2496).

:class:`~pcapkit.protocols.application.dtls.DTLS` stays a parser: the default
engine reads each frame's fragmented handshake messages with
:func:`pcapkit.toolkit.pcap.dtls_reassembly` (or its PCAP-NG twin),
:class:`~pcapkit.foundation.reassembly.dtls.DTLS` reassembles them, and
:func:`pcapkit.foundation.analysis.dtls_handshake` decodes the result. The
engines that do not parse with pcapkit's own protocols turn DTLS reassembly off.

Every capture is built in memory; no sample capture is read.

"""

from __future__ import annotations

import ast
import importlib.util
import inspect
import ipaddress
import struct
import types
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation.reassembly.test_dtls_handshake_reassembly_2440_unit import (
    FLOW, _client_hello_body, _dtls_handshake, _dtls_record, _extract, _frame, _pcap, _pcapng,
    _split)

if TYPE_CHECKING:
    from typing import Any

#: A ``ClientHello`` body, and the two records it is fragmented across.
BODY = _client_hello_body(cookie=b'\xab\xcd\xef\x01')
RECORDS = [
    _dtls_record(22, _dtls_handshake(1, BODY[fo:fo + length], message_seq=4, fragment_offset=fo,
                                     fragment_length=length, total_length=len(BODY)), seq=num)
    for num, (fo, length) in enumerate(_split(BODY, (len(BODY) // 2,)), 1)
]


def _udp(payload: bytes, sport: int = FLOW[1], dport: int = FLOW[3]) -> bytes:
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload


def _ipv4(payload: bytes, src: bytes, dst: bytes, protocol: int) -> bytes:
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0x4000, 64, protocol, 0,
                       src, dst) + payload


def _ether(packet: bytes, ethertype: int = 0x0800) -> bytes:
    return b'\xbb' * 6 + b'\xaa' * 6 + ethertype.to_bytes(2, 'big') + packet


class DTLSToolkitAdapterTests(unittest.TestCase):
    """:func:`dtls_reassembly` reads a frame's fragmented messages, and only those."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _adapt(self, frames: 'list[bytes]', **kwargs: 'Any') -> 'list[Any]':
        """Each frame's PCAP adapter result, checked equal to the PCAP-NG adapter's."""
        from pcapkit.toolkit import pcap as toolkit_pcap
        from pcapkit.toolkit import pcapng as toolkit_pcapng

        pcap_frames = _extract(self, _pcap(frames), **kwargs).frame
        pcapng_frames = _extract(self, _pcapng(frames), **kwargs).frame
        results = [toolkit_pcap.dtls_reassembly(frame) for frame in pcap_frames]
        self.assertEqual(results, [toolkit_pcapng.dtls_reassembly(frame) for frame in pcapng_frames])
        return results

    def test_a_fragmented_message_is_read_off_the_frame(self) -> None:
        packets = self._adapt([_frame(record) for record in RECORDS])
        half = len(BODY) // 2
        for num, (result, (fo, length)) in enumerate(zip(packets, ((0, half), (half, len(BODY) - half))), 1):
            with self.subTest(frame=num):
                packet, = result
                self.assertEqual(packet.bufid, (*FLOW, 0))
                self.assertEqual((packet.num, packet.timestamp), (num, 1500000000.0 + num - 1))
                self.assertEqual((packet.msg_type, packet.length, packet.message_seq), (1, len(BODY), 4))
                self.assertEqual((packet.fragment_offset, packet.fragment_length), (fo, length))
                self.assertEqual(packet.payload, BODY[fo:fo + length])

    def test_every_fragmented_message_of_a_record_is_read_in_order(self) -> None:
        cert, done, whole = b'C' * 40, b'D' * 20, _client_hello_body()
        fragment = (_dtls_handshake(11, cert[:16], message_seq=1, fragment_offset=0,
                                    fragment_length=16, total_length=len(cert))
                    + _dtls_handshake(1, whole, message_seq=2, fragment_offset=0,
                                      fragment_length=len(whole))
                    + _dtls_handshake(14, done[8:], message_seq=3, fragment_offset=8,
                                      fragment_length=12, total_length=len(done)))
        result, = self._adapt([_frame(_dtls_record(22, fragment))])
        self.assertEqual([(p.message_seq, p.payload) for p in result], [(1, cert[:16]), (3, done[8:])])

    def test_frames_without_a_fragmented_message_report_none(self) -> None:
        whole = _client_hello_body()
        unified = bytes([0b00101100]) + b'\x00\x07' + (16).to_bytes(2, 'big') + b'\x5a' * 16
        cases = {
            'whole message': _frame(_dtls_record(22, _dtls_handshake(
                1, whole, message_seq=0, fragment_offset=0, fragment_length=len(whole)))),
            'alert': _frame(_dtls_record(21, bytes([1, 0]))),
            'ciphertext handshake': _frame(_dtls_record(22, b'\xa3' * 32, epoch=1)),
            'unified header': _frame(unified),
            'not DTLS': _ether(_ipv4(_udp(RECORDS[0], dport=53), FLOW[0].packed, FLOW[2].packed, 17)),
            'no UDP': _ether(_ipv4(RECORDS[0], FLOW[0].packed, FLOW[2].packed, 253)),
        }
        for name, frame in cases.items():
            with self.subTest(case=name):
                self.assertEqual(self._adapt([frame]), [None])

    def test_a_dissection_stopped_short_of_dtls_reports_none(self) -> None:
        for kwargs in ({'layer': 'transport'}, {'protocol': 'UDP'}):
            with self.subTest(**kwargs):
                self.assertEqual(self._adapt([_frame(RECORDS[0])], **kwargs), [None])

    def test_the_ip_layer_nearest_the_udp_one_keys_the_buffer(self) -> None:
        inner_src, inner_dst = ipaddress.ip_address('10.0.0.1'), ipaddress.ip_address('10.0.0.2')
        inner = _ipv4(_udp(RECORDS[0]), inner_src.packed, inner_dst.packed, 17)
        tunnelled = _ether(_ipv4(inner, FLOW[0].packed, FLOW[2].packed, 4))

        v6_src, v6_dst = ipaddress.ip_address('2001:db8::1'), ipaddress.ip_address('2001:db8::2')
        segment = _udp(RECORDS[0])
        over_v6 = _ether(struct.pack('!IHBB16s16s', 6 << 28, len(segment), 17, 64,
                                     v6_src.packed, v6_dst.packed) + segment, 0x86DD)

        for name, frame, (src, dst) in (('IPv4 in IPv4', tunnelled, (inner_src, inner_dst)),
                                        ('IPv6', over_v6, (v6_src, v6_dst))):
            with self.subTest(case=name):
                (packet,), = self._adapt([frame])
                self.assertEqual(packet.bufid, (src, FLOW[1], dst, FLOW[3], 0))


class DTLSAnalysisTests(unittest.TestCase):
    """:func:`dtls_handshake` decodes a reassembled message as an unfragmented one."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _datagram(body: 'bytes | tuple[bytes, ...]', *, msg_type: int = 1,
                  completed: str = 'COMPLETE', length: 'int | None' = None) -> 'Any':
        from pcapkit.const.tls.handshake_type import HandshakeType
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.data.dtls import Datagram, DatagramID

        return Datagram(completed=Completion[completed], id=DatagramID(*FLOW, 0), index=(1, 2),
                        message_seq=4, msg_type=HandshakeType.get(msg_type),
                        length=len(body) if length is None else length, body=body)

    def test_a_hello_decodes_as_the_unfragmented_message_does(self) -> None:
        from pcapkit.foundation.analysis import dtls_handshake
        from pcapkit.protocols.application.dtls import DTLS

        for msg_type, body in ((1, BODY), (11, b'C' * 40)):
            with self.subTest(msg_type=msg_type):
                whole = _dtls_record(22, _dtls_handshake(msg_type, body, message_seq=4,
                                                         fragment_offset=0, fragment_length=len(body)))
                expected = DTLS(whole, len(whole)).info.content[0]
                self.assertEqual(dtls_handshake(self._datagram(body, msg_type=msg_type)), expected)

    def test_an_undecodable_body_stays_raw(self) -> None:
        from pcapkit.foundation.analysis import dtls_handshake

        decoded = dtls_handshake(self._datagram(b'\x01\x02\x03\x04\x05'))
        self.assertEqual(decoded.body, b'\x01\x02\x03\x04\x05')
        self.assertEqual((decoded.message_seq, decoded.fragment_offset, decoded.fragment_length,
                          decoded.is_fragmented), (4, 0, 5, False))

    def test_a_message_too_long_for_one_record_stays_raw(self) -> None:
        """A genuine ``ClientHello`` whose extensions take it past what a
        record's 16-bit length holds is reported raw rather than overflowing."""
        from pcapkit.foundation.analysis import dtls_handshake

        body = _client_hello_body(extensions=b'\x00\x15' + (65500).to_bytes(2, 'big') + bytes(65500))
        self.assertGreater(len(body) + 12, 0xFFFF)
        decoded = dtls_handshake(self._datagram(body))
        self.assertEqual(decoded.body, body)
        self.assertFalse(decoded.is_fragmented)

    def test_an_incomplete_message_is_not_decoded(self) -> None:
        from pcapkit.foundation.analysis import dtls_handshake

        for completed, body in (('PARTIAL', (BODY[:10], BODY[20:])), ('PARTIAL', BODY),
                                ('TIMEOUT', BODY)):
            with self.subTest(completed=completed, runs=isinstance(body, tuple)):
                self.assertIsNone(dtls_handshake(self._datagram(body, completed=completed,
                                                                length=len(BODY))))


class DTLSProtocolStaysAParserTests(unittest.TestCase):
    """The protocol class knows nothing of reassembly (convention point 1)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_the_dtls_module_imports_nothing_from_foundation(self) -> None:
        import pcapkit.protocols.application.dtls as module

        tree = ast.parse(inspect.getsource(module))
        imported = [node.module for node in ast.walk(tree)
                    if isinstance(node, ast.ImportFrom) and node.module]
        imported += [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                     for alias in node.names]
        self.assertEqual([name for name in imported if name.startswith('pcapkit.foundation')], [])

    def test_read_takes_no_reassembly_arguments(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS

        self.assertEqual(list(inspect.signature(DTLS.read).parameters), ['self', 'length', 'kwargs'])


class DTLSExtractorWiringTests(unittest.TestCase):
    """The ``dtls`` switch of :class:`~pcapkit.foundation.extraction.Extractor`."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_dtls_reassembly_is_off_unless_asked_for(self) -> None:
        capture = _pcap([_frame(record) for record in RECORDS])
        self.assertIsNone(_extract(self, capture, reassembly=True, ip=True).reassembly.dtls)
        self.assertEqual(len(_extract(self, capture, reassembly=True, dtls=True).reassembly.dtls), 1)

    def test_the_reassembly_timeout_does_not_reach_dtls(self) -> None:
        """The RFC gives DTLS handshake reassembly no timeout, so fragments a
        second apart still complete under a half-second ``reasm_timeout``."""
        extractor = _extract(self, _pcap([_frame(record) for record in RECORDS]),
                             reassembly=True, dtls=True, reasm_timeout=0.5)
        datagram, = extractor.reassembly.dtls
        self.assertTrue(datagram.completed)

    def test_the_shipped_reassembly_entry_names_the_dtls_engine(self) -> None:
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.reassembly.dtls import DTLS

        self.assertIs(Extractor._shipped_reassembly['dtls'].klass, DTLS)


def _extractor(**overrides: 'Any') -> 'Any':
    from tests.foundation.engines.test_runtime_engines import make_extractor

    values = {'_flag_r': True, '_flag_t': False, '_ipv4': True, '_ipv6': False, '_tcp': True,
              '_dtls': True}
    values.update(overrides)
    extractor, _ = make_extractor(**values)
    return extractor


class FakeReader:
    def __iter__(self) -> 'FakeReader':
        return self

    def __next__(self) -> 'Any':
        raise StopIteration

    def datalink(self) -> int:
        return 1


class DTLSThirdPartyEngineTests(unittest.TestCase):
    """DPKT, Scapy and PyShark do not dissect with pcapkit, so DTLS reassembly is off."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _assert_dtls_dropped(self, extractor: 'Any', warn: 'Any', ipv4: 'Any', tcp: 'Any') -> None:
        from pcapkit.utilities.warnings import AttributeWarning

        messages = [call.args[0] for call in warn.call_args_list if call.args[1] is AttributeWarning]
        self.assertTrue(any("'dtls=True' will be ignored" in message for message in messages), messages)
        self.assertFalse(extractor._dtls)
        self.assertTrue(extractor._flag_r)
        self.assertIsNone(extractor._reasm.dtls)
        self.assertIs(extractor._reasm.ipv4, ipv4)
        self.assertIs(extractor._reasm.tcp, tcp)

    @unittest.skipUnless(importlib.util.find_spec('dpkt'), 'DPKT not installed')
    def test_dpkt_turns_dtls_reassembly_off(self) -> None:
        from pcapkit.foundation.engines.dpkt import DPKT

        extractor = _extractor()
        ipv4, tcp = extractor._reasm.ipv4, extractor._reasm.tcp
        engine = DPKT(extractor)
        with mock.patch('pcapkit.foundation.engines.dpkt._pcap_reader',
                        return_value=mock.Mock(return_value=FakeReader())), \
                mock.patch('pcapkit.foundation.engines.dpkt.warn') as warn:
            engine.run()
        self._assert_dtls_dropped(extractor, warn, ipv4, tcp)

    @unittest.skipUnless(importlib.util.find_spec('scapy'), 'Scapy not installed')
    def test_scapy_turns_dtls_reassembly_off(self) -> None:
        from pcapkit.foundation.engines.scapy import Scapy

        extractor = _extractor()
        ipv4, tcp = extractor._reasm.ipv4, extractor._reasm.tcp
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            engine = Scapy(extractor)
        with mock.patch('pcapkit.foundation.engines.scapy._reader_type',
                        return_value=mock.Mock(return_value=mock.Mock())), \
                mock.patch.object(engine._expkg, 'sniff', return_value=[]), \
                mock.patch('pcapkit.foundation.engines.scapy.warn') as warn:
            engine.run()
        self._assert_dtls_dropped(extractor, warn, ipv4, tcp)

    @unittest.skipUnless(importlib.util.find_spec('pyshark'), 'PyShark not installed')
    def test_pyshark_turns_reassembly_off_for_dtls_alone(self) -> None:
        from pcapkit.foundation.engines.pyshark import PyShark
        from pcapkit.utilities.warnings import AttributeWarning

        extractor = _extractor(_ipv4=False, _tcp=False)
        engine = PyShark(extractor)
        capture = types.SimpleNamespace(close=lambda: None)
        with mock.patch.object(engine._expkg, 'FileCapture', return_value=capture), \
                mock.patch('pcapkit.foundation.engines.pyshark.warn') as warn:
            engine.run()
        messages = [call.args[0] for call in warn.call_args_list if call.args[1] is AttributeWarning]
        self.assertTrue(any("'dtls=True' will be ignored" in message for message in messages), messages)
        self.assertFalse(extractor._flag_r)
        self.assertIsNone(extractor._reasm.dtls)


if __name__ == '__main__':
    unittest.main()
