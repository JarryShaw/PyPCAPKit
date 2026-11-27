# -*- coding: utf-8 -*-
"""SCTP user-message reassembly (GitHub issue #2935).

Covers the :class:`~pcapkit.foundation.reassembly.sctp.reassembly.SCTP` engine fed
fragments directly -- DATA messages as runs of consecutive TSNs (RFC 9260, section
6.9), I-DATA messages by stream, U bit and MID, ordered by FSN (RFC 8260, section
2.2.3) -- and the extraction path: the default engine feeds it through
:func:`pcapkit.toolkit.pcap.sctp_reassembly`, and
:func:`pcapkit.foundation.analysis.sctp.sctp_message` parses what it reassembles.

Every case builds its fragments and captures in memory and reads no sample capture.

"""

from __future__ import annotations

import importlib.util
import io
import ipaddress
import struct
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import close_extractor, reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): pure-Python reassembly logic, the same on every interpreter.
__tier__ = 'LATEST'

HAS_PYCRATE = importlib.util.find_spec('pycrate_asn1dir') is not None
HAS_DPKT = importlib.util.find_spec('dpkt') is not None

#: The association direction every fragment below is carried along, and its buffer ID.
FLOW = (ipaddress.ip_address('192.0.2.1'), 2905, ipaddress.ip_address('198.51.100.1'), 38412)
VTAG = 0x1234ABCD
BUFID = (FLOW[1], FLOW[3], VTAG)
#: A second path of the same association, between the endpoints' other addresses.
PATH2 = (ipaddress.ip_address('192.0.2.2'), ipaddress.ip_address('198.51.100.2'))

#: An NGAP ``NGSetupRequest`` in aligned PER, as in ``tests/protocols/application/test_ngap_unit.py``.
NGSETUP_REQUEST = bytes.fromhex(
    '00150036000004001b00080002f839100001020052400d0500706361706b69742d676e62'
    '0066000d00000000010002f839000000080015400140'
)


def _flags(*, U: bool = False, B: bool = False, E: bool = False) -> int:
    """The ``U``, ``B`` and ``E`` bits of a DATA or I-DATA chunk's flags."""
    return (U << 2) | (B << 1) | E


def _data_chunk(tsn: int, data: bytes, *, sid: int = 1, ssn: int = 7, ppid: int = 60, **bits: bool) -> bytes:
    """A DATA chunk (RFC 9260, section 3.3.1), padded."""
    chunk = struct.pack('!BBHIHHI', 0, _flags(**bits), 16 + len(data), tsn, sid, ssn, ppid) + data
    return chunk + b'\x00' * (-len(chunk) % 4)


def _idata_chunk(tsn: int, data: bytes, *, fsn: int = 0, sid: int = 2, mid: int = 9, ppid: int = 60,
                 **bits: bool) -> bytes:
    """An I-DATA chunk (RFC 8260, section 2.1), its PPID on the B fragment, its FSN after."""
    field = ppid if bits.get('B') else fsn
    chunk = struct.pack('!BBHIHHII', 64, _flags(**bits), 20 + len(data), tsn, sid, 0, mid, field) + data
    return chunk + b'\x00' * (-len(chunk) % 4)


def _sctp(*chunks: bytes, vtag: int = VTAG, sport: int = FLOW[1], dport: int = FLOW[3]) -> bytes:
    return struct.pack('!HHII', sport, dport, vtag, 0) + b''.join(chunks)


def _ipv4(payload: bytes, src: bytes, dst: bytes, protocol: int = 132) -> bytes:
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0x4000, 64, protocol, 0,
                       src, dst) + payload


def _ether(packet: bytes, ethertype: int = 0x0800) -> bytes:
    return b'\xbb' * 6 + b'\xaa' * 6 + ethertype.to_bytes(2, 'big') + packet


def _frame(*chunks: bytes, path: 'tuple[Any, Any]' = (FLOW[0], FLOW[2]), **kwargs: 'Any') -> bytes:
    """An Ethernet frame of IPv4 and SCTP bundling ``chunks`` along :data:`FLOW`, over ``path``."""
    return _ether(_ipv4(_sctp(*chunks, **kwargs), path[0].packed, path[1].packed))


def _pcap(frames: 'list[bytes]') -> bytes:
    """A little-endian microsecond Ethernet PCAP holding ``frames``, one second apart."""
    out = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 0xFFFF, 1)
    for num, octets in enumerate(frames):
        out += struct.pack('<IIII', 1500000000 + num, 0, len(octets), len(octets)) + octets
    return out


def _block(block_type: int, body: bytes) -> bytes:
    body += b'\x00' * (-len(body) % 4)
    return struct.pack('<II', block_type, len(body) + 12) + body + struct.pack('<I', len(body) + 12)


def _pcapng(frames: 'list[bytes]') -> bytes:
    """A little-endian PCAP-NG holding ``frames`` on an Ethernet interface, one second apart."""
    out = (_block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
           + _block(1, struct.pack('<HHI', 1, 0, 0xFFFF)))
    for num, octets in enumerate(frames):
        ticks = (1500000000 + num) * 10 ** 6
        out += _block(6, struct.pack('<IIIII', 0, ticks >> 32, ticks & 0xFFFFFFFF,
                                     len(octets), len(octets)) + octets)
    return out


def _extract(test: 'unittest.TestCase', capture: bytes, **kwargs: 'Any') -> 'Any':
    """Run an engine over ``capture``, every frame stored."""
    from pcapkit import extract

    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        extractor = extract(fin=io.BytesIO(capture), store=True, **kwargs)
    test.addCleanup(close_extractor, extractor)
    return extractor


def _data(num: int, tsn: int, payload: bytes, *, B: bool = False, E: bool = False, U: bool = False,
          sid: int = 1, ssn: int = 7, ppid: int = 60, timestamp: float = 0.0,
          path: 'tuple[Any, Any]' = (FLOW[0], FLOW[2])) -> 'Any':
    """A DATA fragment record, as the toolkit builds one."""
    from pcapkit.const.sctp.chunk import Chunk
    from pcapkit.const.sctp.payload_protocol_identifier import PayloadProtocolIdentifier
    from pcapkit.foundation.reassembly.sctp.data import Packet

    return Packet(bufid=BUFID, src=path[0], dst=path[1], num=num, chunk=Chunk.Payload_Data, tsn=tsn,
                  stream_id=sid,
                  unordered=U, beginning=B, ending=E, ssn=ssn, mid=None, fsn=None,
                  ppid=PayloadProtocolIdentifier(ppid), payload=payload, timestamp=timestamp)


def _idata(num: int, tsn: int, fsn: int, payload: bytes, *, B: bool = False, E: bool = False,
           U: bool = False, sid: int = 2, mid: int = 9, ppid: int = 60, timestamp: float = 0.0,
           path: 'tuple[Any, Any]' = (FLOW[0], FLOW[2])) -> 'Any':
    """An I-DATA fragment record, as the toolkit builds one."""
    from pcapkit.const.sctp.chunk import Chunk
    from pcapkit.const.sctp.payload_protocol_identifier import PayloadProtocolIdentifier
    from pcapkit.foundation.reassembly.sctp.data import Packet

    return Packet(bufid=BUFID, src=path[0], dst=path[1], num=num,
                  chunk=Chunk.Payload_Data_supporting_Interleaving, tsn=tsn,
                  stream_id=sid, unordered=U, beginning=B, ending=E, ssn=None, mid=mid, fsn=fsn,
                  ppid=PayloadProtocolIdentifier(ppid) if B else None, payload=payload,
                  timestamp=timestamp)


class _EngineCase(unittest.TestCase):
    """Feeds fragment records to a fresh engine."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _run(packets: 'list[Any]', **kwargs: 'Any') -> 'Any':
        from pcapkit.foundation.reassembly.sctp.reassembly import SCTP

        engine = SCTP(**kwargs)
        for packet in packets:
            engine(packet)
        return engine


class DATAReassemblyTests(_EngineCase):
    """A DATA message is the run of consecutive TSNs from its B to its E fragment."""

    def test_fragments_in_order_complete_one_message(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.foundation.reassembly.data import Completion

        engine = self._run([_data(1, 10, b'abc', B=True), _data(2, 11, b'def'), _data(3, 12, b'gh', E=True)])
        self.assertEqual(engine._buffer, {})
        datagram, = engine.datagram
        self.assertIs(datagram.completed, Completion.COMPLETE)
        self.assertEqual(datagram.payload, b'abcdefgh')
        self.assertEqual((datagram.index, datagram.tsn), ((1, 2, 3), (10, 11, 12)))
        self.assertEqual((datagram.chunk, datagram.stream_id, datagram.unordered, datagram.ssn, datagram.mid),
                         (Chunk.Payload_Data, 1, False, 7, None))
        self.assertEqual(datagram.ppid, 60)
        self.assertEqual((datagram.id.src, datagram.id.sport, datagram.id.dst, datagram.id.dport,
                          datagram.id.vtag), (*FLOW, VTAG))

    def test_any_arrival_order_completes_the_message(self) -> None:
        fragments = [_data(1, 10, b'a', B=True), _data(2, 11, b'b'), _data(3, 12, b'c'), _data(4, 13, b'd', E=True)]
        for order in ((3, 0, 2, 1), (1, 2, 3, 0), (0, 3, 1, 2), (2, 1, 0, 3)):
            with self.subTest(order=order):
                datagram, = self._run([fragments[pos] for pos in order]).datagram
                self.assertTrue(datagram.completed)
                self.assertEqual((datagram.payload, datagram.tsn), (b'abcd', (10, 11, 12, 13)))
                self.assertEqual(datagram.index, (1, 2, 3, 4))

    def test_tsns_wrap_at_two_to_the_thirty_two(self) -> None:
        datagram, = self._run([_data(2, 0, b'b'), _data(1, 0xFFFFFFFF, b'a', B=True),
                               _data(3, 1, b'c', E=True)]).datagram
        self.assertTrue(datagram.completed)
        self.assertEqual((datagram.payload, datagram.tsn), (b'abc', (0xFFFFFFFF, 0, 1)))

    def test_a_tsn_after_the_wrap_finds_the_one_before_it(self) -> None:
        # TSN 0 arrives after 0xFFFFFFFF, so only the lower-neighbour lookup, (TSN-1) % 2**32, joins them.
        for name, packets in (
            ('two fragments', [_data(1, 0xFFFFFFFF, b'a', B=True), _data(2, 0, b'b', E=True)]),
            ('three fragments', [_data(1, 0xFFFFFFFF, b'a', B=True), _data(2, 0, b'b'), _data(3, 1, b'c', E=True)]),
        ):
            with self.subTest(case=name):
                engine = self._run(packets)
                self.assertEqual(engine._buffer, {})
                datagram, = engine.datagram
                self.assertTrue(datagram.completed)
                self.assertEqual(datagram.tsn, tuple(packet.tsn for packet in packets))

    def test_fragments_over_different_paths_join_one_message(self) -> None:
        # RFC 9260, section 6.4: a multi-homed endpoint may retransmit a chunk to an alternate address.
        for name, packets, (src, dst) in (
            ('B on path 1', [_data(1, 10, b'ab', B=True), _data(2, 12, b'ef', E=True),
                             _data(3, 11, b'cd', path=PATH2)], (FLOW[0], FLOW[2])),
            ('B on path 2', [_data(1, 11, b'cd'), _data(2, 12, b'ef', E=True),
                             _data(3, 10, b'ab', B=True, path=PATH2)], PATH2),
        ):
            with self.subTest(case=name):
                engine = self._run(packets)
                self.assertEqual(engine._buffer, {})
                datagram, = engine.datagram
                self.assertTrue(datagram.completed)
                self.assertEqual(datagram.payload, b'abcdef')
                self.assertEqual((datagram.id.src, datagram.id.dst), (src, dst))

    def test_a_duplicate_tsn_keeps_the_data_received_first(self) -> None:
        datagram, = self._run([_data(1, 10, b'ab', B=True), _data(2, 10, b'XY', B=True),
                               _data(3, 11, b'cd', E=True)]).datagram
        self.assertEqual((datagram.payload, datagram.index), (b'abcd', (1, 2, 3)))

    def test_consecutive_messages_do_not_merge(self) -> None:
        # Message A on stream 1 holds TSNs 1-2, message B on stream 3 holds TSNs 3-4.
        engine = self._run([_data(1, 2, b'A2', E=True), _data(2, 3, b'B1', B=True, sid=3, ssn=0),
                            _data(3, 1, b'A1', B=True), _data(4, 4, b'B2', E=True, sid=3, ssn=0)])
        self.assertEqual([(d.stream_id, d.payload, d.tsn) for d in engine.datagram],
                         [(1, b'A1A2', (1, 2)), (3, b'B1B2', (3, 4))])

    def test_a_run_breaks_where_stream_ordering_or_ssn_differ(self) -> None:
        from pcapkit.foundation.reassembly.data import Completion

        cases = {
            'stream': dict(sid=2),
            'U bit': dict(U=True),
            'ordered SSN': dict(ssn=8),
        }
        for name, kwargs in cases.items():
            with self.subTest(differ=name):
                engine = self._run([_data(1, 10, b'ab', B=True), _data(2, 11, b'cd', E=True, **kwargs)])
                self.assertEqual([(d.completed, d.payload) for d in engine.datagram],
                                 [(Completion.PARTIAL, (b'ab',)), (Completion.PARTIAL, (b'cd',))])

    def test_an_unordered_message_ignores_its_stream_sequence_numbers(self) -> None:
        datagram, = self._run([_data(1, 10, b'ab', B=True, U=True, ssn=1),
                               _data(2, 11, b'cd', E=True, U=True, ssn=2)]).datagram
        self.assertTrue(datagram.completed)
        self.assertEqual((datagram.payload, datagram.unordered, datagram.ssn), (b'abcd', True, None))

    def test_a_long_message_merges_from_both_ends(self) -> None:
        count = 64
        packets = [_data(tsn + 1, 100 + tsn, bytes([tsn]), B=not tsn, E=tsn == count - 1)
                   for tsn in range(count)]
        datagram, = self._run(packets[0::2] + packets[1::2][::-1]).datagram
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.payload, bytes(range(count)))
        self.assertEqual(datagram.tsn, tuple(range(100, 100 + count)))


class IDATAReassemblyTests(_EngineCase):
    """An I-DATA message is found by stream, U bit and MID, and ordered by FSN."""

    def test_fragments_complete_one_message_in_fsn_order(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk

        # TSNs run against the FSNs: RFC 8260 has the receiver assume nothing of them.
        engine = self._run([_idata(1, 30, 2, b'gh', E=True), _idata(2, 20, 0, b'abc', B=True, ppid=46),
                            _idata(3, 10, 1, b'def')])
        self.assertEqual(engine._buffer, {})
        datagram, = engine.datagram
        self.assertTrue(datagram.completed)
        self.assertEqual((datagram.payload, datagram.tsn, datagram.index), (b'abcdefgh', (20, 10, 30), (1, 2, 3)))
        self.assertEqual((datagram.chunk, datagram.stream_id, datagram.mid, datagram.ssn),
                         (Chunk.Payload_Data_supporting_Interleaving, 2, 9, None))
        self.assertEqual(datagram.ppid, 46)

    def test_interleaved_messages_are_held_apart(self) -> None:
        engine = self._run([
            _idata(1, 1, 0, b'S2', B=True, sid=2),
            _idata(2, 2, 0, b'S3', B=True, sid=3),
            _idata(3, 3, 0, b'U2', B=True, sid=2, U=True),
            _idata(4, 4, 0, b'M8', B=True, sid=2, mid=8),
            _idata(5, 5, 1, b'-m', E=True, sid=2, mid=8),
            _idata(6, 6, 1, b'-u', E=True, sid=2, U=True),
            _idata(7, 7, 1, b'-3', E=True, sid=3),
            _idata(8, 8, 1, b'-2', E=True, sid=2),
        ])
        self.assertEqual([(d.stream_id, d.unordered, d.mid, d.payload) for d in engine.datagram],
                         [(2, False, 8, b'M8-m'), (2, True, 9, b'U2-u'), (3, False, 9, b'S3-3'),
                          (2, False, 9, b'S2-2')])

    def test_fragments_over_different_paths_join_one_message(self) -> None:
        datagram, = self._run([_idata(1, 1, 1, b'cd'), _idata(2, 2, 0, b'ab', B=True, path=PATH2),
                               _idata(3, 3, 2, b'ef', E=True)]).datagram
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.payload, b'abcdef')
        self.assertEqual((datagram.id.src, datagram.id.dst), PATH2)

    def test_a_duplicate_fsn_keeps_the_data_received_first(self) -> None:
        datagram, = self._run([_idata(1, 1, 0, b'ab', B=True), _idata(2, 2, 1, b'cd'),
                               _idata(3, 3, 1, b'XY'), _idata(4, 4, 2, b'ef', E=True)]).datagram
        self.assertEqual((datagram.payload, datagram.index), (b'abcdef', (1, 2, 3, 4)))

    def test_a_fragment_past_the_last_keeps_the_message_incomplete(self) -> None:
        from pcapkit.foundation.reassembly.data import Completion

        datagram, = self._run([_idata(1, 1, 0, b'ab', B=True), _idata(2, 2, 2, b'ef'),
                               _idata(3, 3, 1, b'cd', E=True)]).datagram
        self.assertIs(datagram.completed, Completion.PARTIAL)
        self.assertEqual(datagram.payload, (b'abcdef',))

    def test_a_message_missing_its_first_fragment_has_no_ppid(self) -> None:
        datagram, = self._run([_idata(1, 2, 1, b'cd'), _idata(2, 3, 2, b'ef', E=True)]).datagram
        self.assertFalse(datagram.completed)
        self.assertIsNone(datagram.ppid)


class IncompleteMessageTests(_EngineCase):
    """What is still held when the buffer is submitted, by ``strict``."""

    @staticmethod
    def _gapped() -> 'list[Any]':
        """A DATA message missing TSN 12."""
        return [_data(1, 10, b'ab', B=True), _data(2, 11, b'cd'), _data(3, 13, b'gh', E=True)]

    def test_strict_reports_each_run_received(self) -> None:
        from pcapkit.foundation.reassembly.data import Completion

        engine = self._run(self._gapped())
        head, tail = engine.datagram
        self.assertEqual([(d.completed, d.payload, d.tsn, d.packet) for d in (head, tail)],
                         [(Completion.PARTIAL, (b'abcd',), (10, 11), None),
                          (Completion.PARTIAL, (b'gh',), (13,), None)])

    def test_strict_reports_the_runs_of_an_idata_message(self) -> None:
        datagram, = self._run([_idata(1, 1, 0, b'ab', B=True), _idata(2, 2, 2, b'ef'),
                               _idata(3, 3, 3, b'gh', E=True)]).datagram
        self.assertEqual((datagram.payload, datagram.tsn), ((b'ab', b'efgh'), (1, 2, 3)))

    def test_not_strict_reports_the_octets_up_to_the_first_hole(self) -> None:
        engine = self._run(self._gapped(), strict=False)
        head, tail = engine.datagram
        self.assertEqual((head.payload, tail.payload), (b'abcd', b''))
        self.assertEqual(type(head.packet).__name__, 'Raw')
        self.assertEqual(type(tail.packet).__name__, 'NoPayload')

    def test_an_expired_buffer_is_reported_as_timed_out(self) -> None:
        from pcapkit.foundation.reassembly.data import Completion

        engine = self._run([_data(1, 10, b'ab', B=True, timestamp=100.0)], timeout=5)
        engine.advance(104.0)
        self.assertIn(BUFID, engine._buffer)
        engine.advance(106.0)
        self.assertEqual(engine._buffer, {})
        datagram, = engine.datagram
        self.assertIs(datagram.completed, Completion.TIMEOUT)

    def test_the_default_timeout_never_expires(self) -> None:
        import math

        engine = self._run([_data(1, 10, b'ab', B=True, timestamp=0.0)])
        self.assertEqual(engine.timeout, math.inf)
        engine.advance(1e9)
        self.assertIn(BUFID, engine._buffer)


class PacketParseTests(_EngineCase):
    """A message's ``packet`` is ``SCTP.analyze`` on its PPID and user data."""

    def test_packet_is_parsed_by_ppid(self) -> None:
        from pcapkit.foundation.analysis import sctp_message
        from pcapkit.protocols.transport.sctp.protocol import SCTP

        datagram, = self._run([_data(1, 10, b'ab', B=True, ppid=46), _data(2, 11, b'cd', E=True, ppid=46)]).datagram
        expected = SCTP.analyze(46, b'abcd')
        for packet in (datagram.packet, sctp_message(datagram)):
            self.assertIs(type(packet), type(expected))
            self.assertEqual(packet.info, expected.info)
            self.assertEqual(packet.info.protocol, 46)

    def test_protocol_type_names_the_parser(self) -> None:
        from pcapkit.foundation.reassembly.sctp.reassembly import SCTP

        calls = []

        class Recorder:
            @staticmethod
            def analyze(ppid: 'Any', payload: bytes, **kwargs: 'Any') -> str:
                calls.append((ppid, payload, kwargs))
                return 'parsed'

        class Custom(SCTP):
            __protocol_type__ = Recorder  # type: ignore[assignment]

        engine = Custom()
        engine._parse_keywords = {'layer': 'transport'}
        for packet in (_idata(1, 1, 0, b'ab', B=True, ppid=46), _idata(2, 2, 1, b'cd', E=True)):
            engine(packet)
        datagram, = engine.datagram
        self.assertEqual(datagram.packet, 'parsed')
        self.assertEqual(calls, [(46, b'abcd', {'layer': 'transport'})])

    def test_sctp_message_forwards_the_stops_and_is_none_for_runs(self) -> None:
        from pcapkit.foundation.analysis import sctp_message
        from pcapkit.protocols.transport.sctp.protocol import SCTP

        complete, = self._run([_data(1, 10, b'ab', B=True), _data(2, 11, b'cd', E=True)]).datagram
        with mock.patch.object(SCTP, 'analyze', return_value='parsed') as analyze:
            self.assertEqual(sctp_message(complete, layer='transport', protocol='Raw'), 'parsed')
        analyze.assert_called_once_with(60, b'abcd', layer='transport', protocol='Raw')

        partial, = self._run([_data(1, 10, b'ab', B=True)]).datagram
        self.assertIsNone(sctp_message(partial))

    @unittest.skipUnless(HAS_PYCRATE, 'pycrate not installed')
    def test_a_fragmented_ngap_message_decodes_once_reassembled(self) -> None:
        from pcapkit.const.ngap.procedure_code import ProcedureCode

        pieces = [NGSETUP_REQUEST[:20], NGSETUP_REQUEST[20:40], NGSETUP_REQUEST[40:]]
        for name, packets in (
            ('DATA', [_data(n, 10 + n, piece, B=n == 0, E=n == 2) for n, piece in enumerate(pieces)]),
            ('I-DATA', [_idata(n, 10 + n, n, piece, B=n == 0, E=n == 2) for n, piece in enumerate(pieces)]),
        ):
            with self.subTest(chunk=name):
                datagram, = self._run(packets).datagram
                self.assertEqual(type(datagram.packet).__name__, 'NGAP')
                self.assertIs(datagram.packet.info.procedure, ProcedureCode.NGSetup)
                self.assertEqual(datagram.packet.info.message, 'NGSetupRequest')


class SCTPToolkitAdapterTests(unittest.TestCase):
    """:func:`sctp_reassembly` reads each fragmented DATA and I-DATA chunk off a frame."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _adapt(self, frames: 'list[bytes]', **kwargs: 'Any') -> 'list[Any]':
        """Each frame's PCAP adapter result, checked equal to the PCAP-NG adapter's."""
        from pcapkit.toolkit import pcap as toolkit_pcap
        from pcapkit.toolkit import pcapng as toolkit_pcapng

        pcap_frames = _extract(self, _pcap(frames), **kwargs).frame
        pcapng_frames = _extract(self, _pcapng(frames), **kwargs).frame
        results = [toolkit_pcap.sctp_reassembly(frame) for frame in pcap_frames]
        self.assertEqual(results, [toolkit_pcapng.sctp_reassembly(frame) for frame in pcapng_frames])
        return results

    def test_every_fragment_bundled_is_read_in_order(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk

        frame = _frame(_data_chunk(10, b'abc', B=True), _data_chunk(50, b'whole', B=True, E=True),
                       _idata_chunk(5, b'xyz', fsn=3, U=True, E=True), b'\x0e\x00\x00\x04')
        (data, idata), = self._adapt([frame])
        for packet in (data, idata):
            self.assertEqual((packet.bufid, packet.src, packet.dst), (BUFID, FLOW[0], FLOW[2]))
            self.assertEqual((packet.num, packet.timestamp), (1, 1500000000.0))
        self.assertEqual((data.chunk, data.tsn, data.stream_id, data.unordered, data.beginning, data.ending),
                         (Chunk.Payload_Data, 10, 1, False, True, False))
        self.assertEqual((data.ssn, data.mid, data.fsn, data.ppid, data.payload), (7, None, None, 60, b'abc'))
        self.assertEqual((idata.chunk, idata.tsn, idata.stream_id, idata.unordered, idata.beginning,
                          idata.ending), (Chunk.Payload_Data_supporting_Interleaving, 5, 2, True, False, True))
        self.assertEqual((idata.ssn, idata.mid, idata.fsn, idata.ppid, idata.payload), (None, 9, 3, None, b'xyz'))

    def test_frames_without_a_fragment_report_none(self) -> None:
        cases = {
            'unfragmented DATA': _frame(_data_chunk(1, b'whole', B=True, E=True)),
            'unfragmented I-DATA': _frame(_idata_chunk(1, b'whole', B=True, E=True)),
            'no DATA': _frame(b'\x0e\x00\x00\x04'),
            'not SCTP': _ether(_ipv4(_sctp(_data_chunk(1, b'a', B=True)), FLOW[0].packed, FLOW[2].packed, 253)),
        }
        for name, frame in cases.items():
            with self.subTest(case=name):
                self.assertEqual(self._adapt([frame]), [None])

    def test_a_dissection_stopped_short_of_sctp_reports_none(self) -> None:
        for kwargs in ({'layer': 'internet'}, {'protocol': 'IPv4'}):
            with self.subTest(**kwargs):
                self.assertEqual(self._adapt([_frame(_data_chunk(1, b'a', B=True))], **kwargs), [None])

    def test_the_ip_layer_nearest_the_sctp_one_keys_the_buffer(self) -> None:
        segment = _sctp(_data_chunk(1, b'a', B=True), vtag=7)
        inner_src, inner_dst = ipaddress.ip_address('10.0.0.1'), ipaddress.ip_address('10.0.0.2')
        tunnelled = _ether(_ipv4(_ipv4(segment, inner_src.packed, inner_dst.packed), FLOW[0].packed,
                                 FLOW[2].packed, 4))
        v6_src, v6_dst = ipaddress.ip_address('2001:db8::1'), ipaddress.ip_address('2001:db8::2')
        over_v6 = _ether(struct.pack('!IHBB16s16s', 6 << 28, len(segment), 132, 64,
                                     v6_src.packed, v6_dst.packed) + segment, 0x86DD)
        for name, frame, (src, dst) in (('IPv4 in IPv4', tunnelled, (inner_src, inner_dst)),
                                        ('IPv6', over_v6, (v6_src, v6_dst))):
            with self.subTest(case=name):
                (packet,), = self._adapt([frame])
                self.assertEqual((packet.bufid, packet.src, packet.dst), ((FLOW[1], FLOW[3], 7), src, dst))


class SCTPExtractorTests(unittest.TestCase):
    """``Extractor(fin, reassembly=['sctp'])`` over real frames."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    FRAMES = [
        _frame(_data_chunk(10, b'abc', B=True), _idata_chunk(7, b'xyz', B=True, ppid=46)),
        _frame(_idata_chunk(9, b'!!', fsn=2, E=True), _data_chunk(12, b'ghi', E=True)),
        _frame(_data_chunk(11, b'def'), _idata_chunk(8, b'uvw', fsn=1)),
    ]

    def test_both_chunk_kinds_are_reassembled_from_a_capture(self) -> None:
        for container, write in (('pcap', _pcap), ('pcapng', _pcapng)):
            with self.subTest(container=container):
                extractor = _extract(self, write(self.FRAMES), reassembly=['sctp'])
                data, idata = extractor.reassembly.sctp
                self.assertEqual((data.payload, data.tsn, data.index, data.ppid),
                                 (b'abcdefghi', (10, 11, 12), (1, 2, 3), 60))
                self.assertEqual((idata.payload, idata.tsn, idata.index, idata.ppid),
                                 (b'xyzuvw!!', (7, 8, 9), (1, 2, 3), 46))
                self.assertTrue(data.completed and idata.completed)
                self.assertIsNone(extractor.reassembly.dtls)

    def test_a_message_split_across_paths_is_reassembled_from_a_capture(self) -> None:
        frames = [
            _frame(_data_chunk(10, b'ab', B=True), vtag=0xAB),
            _frame(_data_chunk(11, b'cd'), vtag=0xAB, path=PATH2),
            _frame(_data_chunk(12, b'ef', E=True), vtag=0xAB),
        ]
        for container, write in (('pcap', _pcap), ('pcapng', _pcapng)):
            with self.subTest(container=container):
                datagram, = _extract(self, write(frames), reassembly=['sctp']).reassembly.sctp
                self.assertTrue(datagram.completed)
                self.assertEqual((datagram.payload, datagram.index), (b'abcdef', (1, 2, 3)))
                self.assertEqual((datagram.id.src, datagram.id.sport, datagram.id.dst, datagram.id.dport,
                                  datagram.id.vtag), (*FLOW, 0xAB))

    def test_the_record_holds_sctp_as_a_builtin(self) -> None:
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.reassembly.data import ReassemblyData
        from pcapkit.foundation.reassembly.sctp.reassembly import SCTP
        from pcapkit.interface import reassemble
        from pcapkit.protocols.transport.sctp.protocol import SCTP as SCTP_Protocol

        self.assertIsNone(ReassemblyData().sctp)
        self.assertEqual(list(ReassemblyData()), ['ipv4', 'ipv6', 'tcp', 'dtls', 'sctp'])
        self.assertIsInstance(Extractor.make_reassembly('sctp'), SCTP)
        for protocol in ('sctp', 'SCTP', SCTP_Protocol):
            with self.subTest(protocol=protocol):
                self.assertIsInstance(reassemble(protocol), SCTP)

    def test_the_default_engines_feed_it_and_no_third_party_one_does(self) -> None:
        from pcapkit.foundation.engines.dpkt import DPKT
        from pcapkit.foundation.engines.pcap import PCAP
        from pcapkit.foundation.engines.pcapng import PCAPNG
        from pcapkit.foundation.engines.pypcapfile import PyPCAPFile
        from pcapkit.foundation.engines.scapy import Scapy

        from pcapkit.toolkit import pcap as toolkit_pcap
        from pcapkit.toolkit import pcapng as toolkit_pcapng

        for engine, adapter in ((PCAP, toolkit_pcap.sctp_reassembly), (PCAPNG, toolkit_pcapng.sctp_reassembly)):
            with self.subTest(engine=engine.__name__):
                entry = engine.__reassembly__['sctp']
                self.assertIs(getattr(entry, 'klass', entry), adapter)
        for engine in (DPKT, Scapy, PyPCAPFile):
            with self.subTest(engine=engine.__name__):
                self.assertNotIn('sctp', engine.__reassembly__)

    @unittest.skipUnless(HAS_DPKT, 'dpkt not installed')
    def test_a_third_party_engine_disables_it_with_a_warning(self) -> None:
        from pcapkit import extract
        from pcapkit.utilities.warnings import AttributeWarning

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            extractor = extract(fin=io.BytesIO(_pcap(self.FRAMES)), engine='dpkt', reassembly=['sctp', 'tcp'])
        self.addCleanup(close_extractor, extractor)
        self.assertTrue(any(issubclass(w.category, AttributeWarning) and "'sctp'" in str(w.message)
                            for w in caught))
        self.assertIsNone(extractor.reassembly.sctp)


if __name__ == '__main__':
    unittest.main()
