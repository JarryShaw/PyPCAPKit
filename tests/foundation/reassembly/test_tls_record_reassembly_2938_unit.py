# -*- coding: utf-8 -*-
"""TLS records split across TCP segments are reassembled (#2938).

:meth:`TLS.record_header <pcapkit.protocols.application.tls.protocol.TLS.record_header>`
frames a stream, :class:`~pcapkit.foundation.reassembly.tls.reassembly.TLS` cuts each
direction of a TCP connection into records, every engine with a TCP adapter feeds it the
segments of a stream on a port TCP binds to TLS through its ``tls_reassembly`` adapter,
and :func:`~pcapkit.foundation.analysis.tls.tls_record` decodes a record with
:meth:`TLS.analyze_record <pcapkit.protocols.application.tls.protocol.TLS.analyze_record>`,
the #2810 extensions included.

Every case builds its segments and captures in memory and reads no sample capture.
Classes are imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

from __future__ import annotations

import importlib.util
import ipaddress
import os
import pickle  # nosec: B403 -- round-trips objects built here
import struct
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import close_extractor, reimport_once_per_class
from tests.foundation.reassembly.test_dtls_handshake_reassembly_2440_unit import (_extract, _pcap,
                                                                                  _pcapng)

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): pure-Python stream bookkeeping, the same on every interpreter.
__tier__ = 'LATEST'

#: The client and server endpoints, the server on the HTTPS port TCP binds TLS to.
CLIENT = (ipaddress.ip_address('192.0.2.1'), 50000)
SERVER = (ipaddress.ip_address('198.51.100.2'), 443)
#: The buffer ID of the client's direction.
BUFID = (CLIENT[0], CLIENT[1], SERVER[0], SERVER[1])


def _record(content_type: int, fragment: bytes, version: int = 0x0303) -> bytes:
    """A TLS record [RFC 9846, section 5.1]."""
    return bytes([content_type]) + version.to_bytes(2, 'big') + len(fragment).to_bytes(2, 'big') + fragment


def _extension(code: int, body: bytes) -> bytes:
    return code.to_bytes(2, 'big') + len(body).to_bytes(2, 'big') + body


def _client_hello(host: bytes = b'example.com', padding: int = 300) -> bytes:
    """A ``ClientHello`` record carrying ``server_name``, ``supported_versions`` and ``padding``."""
    names = b'\x00' + len(host).to_bytes(2, 'big') + host
    extensions = (_extension(0, len(names).to_bytes(2, 'big') + names)
                  + _extension(43, b'\x04\x03\x04\x03\x03') + _extension(21, bytes(padding)))
    body = (b'\x03\x03' + bytes(range(32)) + b'\x00' + b'\x00\x04\x13\x01\x13\x02' + b'\x01\x00'
            + len(extensions).to_bytes(2, 'big') + extensions)
    return _record(22, b'\x01' + len(body).to_bytes(3, 'big') + body, version=0x0301)


#: A ``ClientHello`` too long for one 100-octet segment, then two short records.
HELLO = _client_hello()
ALERT = _record(21, b'\x01\x00')
DATA = _record(23, b'\xa5' * 40)


def _segment(num: int, seq: int, payload: bytes = b'', *, syn: bool = False, fin: bool = False,
             rst: bool = False, bufid: 'tuple[Any, ...]' = BUFID, ts: float = 1000.0) -> 'Any':
    """TCP reassembly's record of a segment, as the adapters build one."""
    from pcapkit.foundation.reassembly.tcp.data import Packet

    return Packet(bufid=bufid, dsn=seq, ack=1, num=num, syn=syn, fin=fin, rst=rst, len=len(payload),
                  first=seq, last=seq + len(payload) - 1, header=b'', payload=bytearray(payload),
                  timestamp=ts + num)


def _split(stream: bytes, *cuts: int) -> 'list[tuple[int, bytes]]':
    """``stream`` cut at ``cuts``, as ``(offset, octets)`` pairs."""
    bounds = (0, *cuts, len(stream))
    return [(lo, stream[lo:hi]) for (lo, hi) in zip(bounds, bounds[1:])]


def _tcp(src: 'tuple[Any, int]', dst: 'tuple[Any, int]', seq: int, flags: int, payload: bytes = b'') -> bytes:
    return struct.pack('!HHIIBBHHH', src[1], dst[1], seq, 1, 5 << 4, flags, 65535, 0, 0) + payload


def _frame(segment: bytes, src: 'tuple[Any, int]' = CLIENT, dst: 'tuple[Any, int]' = SERVER) -> bytes:
    """An Ethernet frame of IPv4 carrying the TCP ``segment``."""
    return (b'\xbb' * 6 + b'\xaa' * 6 + b'\x08\x00'
            + struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(segment), 1, 0x4000, 64, 6, 0,
                          src[0].packed, dst[0].packed)
            + segment)


def _hello_frames(isn: int, src: 'tuple[Any, int]' = CLIENT, dst: 'tuple[Any, int]' = SERVER) -> 'list[bytes]':
    """A SYN, then :data:`HELLO` in three segments, then a FIN."""
    frames = [_frame(_tcp(src, dst, isn, 0x02), src, dst)]
    for (offset, octets) in _split(HELLO, 100, 250):
        frames.append(_frame(_tcp(src, dst, (isn + 1 + offset) % 2 ** 32, 0x10, octets), src, dst))
    frames.append(_frame(_tcp(src, dst, (isn + 1 + len(HELLO)) % 2 ** 32, 0x11), src, dst))
    return frames


class _Case(unittest.TestCase):

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def assertHello(self, packet: 'Any') -> None:  # pylint: disable=invalid-name
        """``packet`` is :data:`HELLO`, decoded down to its ``server_name``."""
        from pcapkit.protocols.application.tls.protocol import TLS

        self.assertIsInstance(packet, TLS)
        self.assertEqual(packet.alias, 'TLS 1.3')
        hello, = packet.info.content
        names = hello.body.extensions[0].data.server_name_list
        self.assertEqual([name.name for name in names], [b'example.com'])
        self.assertEqual(packet.data, HELLO)


class RecordHeaderTests(_Case):
    """:meth:`TLS.record_header` reads the header a stream is delimited by."""

    def test_a_header_is_read(self) -> None:
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.protocols.application.tls.protocol import TLS

        self.assertEqual(TLS.record_header(HELLO), (ContentType.handshake, 0x0301, 5, len(HELLO) - 5))
        self.assertEqual(TLS.record_header(ALERT[:5]), (ContentType.alert, 0x0303, 5, 2))

    def test_too_few_octets_are_no_header_yet(self) -> None:
        from pcapkit.protocols.application.tls.protocol import TLS

        for size in range(5):
            with self.subTest(size=size):
                self.assertIsNone(TLS.record_header(HELLO[:size]))

    def test_octets_opening_no_record_are_refused(self) -> None:
        from pcapkit.protocols.application.tls.protocol import TLS
        from pcapkit.utilities.exceptions import ProtocolError

        for name, octets in (('content type 0', b'\x00\x03\x03\x00\x00'),
                             ('tls12_cid', b'\x19\x03\x03\x00\x00'),
                             ('DTLS version', b'\x17\xfe\xfd\x00\x00'),
                             ('SSLv2 hello', b'\x80\x2e\x01\x00\x02'),
                             ('length past 2 ** 14 + 2048', b'\x17\x03\x03' + (2 ** 14 + 2049).to_bytes(2, 'big')),
                             ('length 0xffff', b'\x17\x03\x03\xff\xff')):
            with self.subTest(case=name), self.assertRaises(ProtocolError):
                TLS.record_header(octets)

    def test_the_longest_record_any_version_allows_is_read(self) -> None:
        # TLSCiphertext of SSLv3 to TLS 1.2 (RFC 6101 section 5.2.3, RFC 5246 section 6.2.3)
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.protocols.application.tls.protocol import TLS

        octets = b'\x17\x03\x03' + (2 ** 14 + 2048).to_bytes(2, 'big')
        self.assertEqual(TLS.record_header(octets), (ContentType.application_data, 0x0303, 5, 2 ** 14 + 2048))


class AnalyzeRecordTests(_Case):
    """:meth:`TLS.analyze_record` parses a record as a segment's first record is."""

    def test_a_record_decodes_and_rebuilds_byte_exact(self) -> None:
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.protocols.application.tls.protocol import TLS

        packet = TLS.analyze_record((ContentType.handshake, 0x0301), HELLO[5:])
        self.assertHello(packet)
        self.assertEqual(TLS.from_data(packet.info).data, HELLO)

    def test_a_record_that_fails_to_decode_is_raw(self) -> None:
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.protocols.application.tls.protocol import TLS
        from pcapkit.protocols.misc.raw.protocol import Raw

        packet = TLS.analyze_record((ContentType.handshake, 0x0303), b'\x01\x00\x00\x02\x03\x03')
        self.assertIsInstance(packet, Raw)
        self.assertEqual(packet.info.protocol, 443)
        self.assertIn('client_hello', packet.info.error)
        self.assertEqual(packet.data, b'\x16\x03\x03\x00\x06\x01\x00\x00\x02\x03\x03')


class ReassemblyTests(_Case):
    """The reassembler, fed TCP reassembly's records of each segment."""

    def _run(self, segments: 'list[Any]', **kwargs: 'Any') -> 'Any':
        from pcapkit.foundation.reassembly.tls.reassembly import TLS

        reasm = TLS(**kwargs)
        for segment in segments:
            reasm(segment)
        return reasm

    def test_records_split_and_coalesced_are_each_reported(self) -> None:
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.foundation.reassembly.data import Completion

        stream = HELLO + ALERT + DATA
        segments = [_segment(1, 999, syn=True)]
        segments += [_segment(num, 1000 + offset, octets)
                     for num, (offset, octets) in enumerate(_split(stream, 100, 250, len(HELLO) + 3), 2)]
        segments.append(_segment(6, 1000 + len(stream), fin=True))
        reasm = self._run(segments)

        hello, alert, data = reasm.datagram
        self.assertEqual([datagram.completed for datagram in reasm.datagram], [Completion.COMPLETE] * 3)
        self.assertEqual([datagram.index for datagram in reasm.datagram], [(2, 3, 4), (4, 5), (5,)])
        self.assertEqual([datagram.id.seq for datagram in reasm.datagram],
                         [1000, 1000 + len(HELLO), 1000 + len(HELLO) + len(ALERT)])
        self.assertEqual((hello.id.src, hello.id.dst), (CLIENT, SERVER))
        self.assertEqual([(datagram.content_type, datagram.version, datagram.length) for datagram in reasm.datagram],
                         [(ContentType.handshake, 0x0301, len(HELLO) - 5), (ContentType.alert, 0x0303, 2),
                          (ContentType.application_data, 0x0303, 40)])
        self.assertEqual([datagram.fragment for datagram in reasm.datagram], [HELLO[5:], ALERT[5:], DATA[5:]])
        self.assertHello(hello.packet)
        self.assertEqual(alert.packet.info.content.description, 0)
        self.assertEqual(data.packet.data, DATA)

    def test_segments_out_of_order_wait_for_those_before_them(self) -> None:
        pieces = _split(HELLO, 100, 250)
        segments = [_segment(1, 999, syn=True)] + [_segment(num, 1000 + pieces[index][0], pieces[index][1])
                                                   for num, index in ((2, 2), (3, 0), (4, 1))]
        reasm = self._run(segments)
        datagram, = reasm.datagram
        self.assertEqual(datagram.index, (2, 3, 4))
        self.assertHello(datagram.packet)

    def test_octets_received_twice_keep_the_first(self) -> None:
        overlap = bytearray(HELLO[50:150])
        overlap[0:50] = b'\xff' * 50  # disagrees with the octets 50 to 100 already held
        segments = [_segment(1, 999, syn=True), _segment(2, 1000, HELLO[:100]),
                    _segment(3, 1050, bytes(overlap)), _segment(4, 1000, HELLO[:100]),
                    _segment(5, 1150, HELLO[150:])]
        datagram, = self._run(segments).datagram
        self.assertEqual(datagram.fragment, HELLO[5:])
        self.assertEqual(datagram.index, (2, 3, 5))
        self.assertHello(datagram.packet)

    def test_a_segment_reaching_into_a_held_run_adds_only_the_octets_before_it(self) -> None:
        overlap = HELLO[:100] + b'\xff' * 50  # its last 50 octets disagree with the run held
        segments = [_segment(1, 999, syn=True), _segment(2, 1100, HELLO[100:]), _segment(3, 1000, overlap)]
        datagram, = self._run(segments).datagram
        self.assertEqual(datagram.index, (2, 3))
        self.assertHello(datagram.packet)

    def test_a_stream_crossing_two_to_the_thirty_second_continues_past_it(self) -> None:
        isn = 2 ** 32 - 120
        segments = [_segment(1, isn, syn=True)]
        segments += [_segment(num, (isn + 1 + offset) % 2 ** 32, octets)
                     for num, (offset, octets) in enumerate(_split(HELLO + DATA, 100, 250), 2)]
        hello, data = self._run(segments).datagram
        self.assertEqual((hello.id.seq, data.id.seq), (isn + 1, (isn + 1 + len(HELLO)) % 2 ** 32))
        self.assertHello(hello.packet)
        self.assertEqual(data.fragment, DATA[5:])

    def test_without_the_syn_the_stream_is_followed_from_a_record_header(self) -> None:
        # the tail of a record before the capture began, then a record opening a segment
        segments = [_segment(1, 5000, b'\x99' * 30), _segment(2, 5030, HELLO[:200]),
                    _segment(3, 5230, HELLO[200:])]
        datagram, = self._run(segments).datagram
        self.assertEqual((datagram.index, datagram.id.seq), ((2, 3), 5030))
        self.assertHello(datagram.packet)

    def test_a_header_declaring_an_overlong_record_does_not_open_the_stream(self) -> None:
        # a record's tail from before the capture, opening as a header declaring 0xffff
        # octets would; the real records behind it must not be swallowed into it
        bogus = b'\x17\x03\x03\xff\xff' + b'\x99' * 100
        segments = [_segment(1, 5000, bogus), _segment(2, 5105, DATA), _segment(3, 5105 + len(DATA), ALERT)]
        reasm = self._run(segments)
        self.assertEqual([(datagram.completed, datagram.index, datagram.id.seq) for datagram in reasm.datagram],
                         [('complete', (2,), 5105), ('complete', (3,), 5105 + len(DATA))])
        self.assertEqual(reasm.datagram[0].fragment, DATA[5:])

    def test_octets_opening_no_record_drop_the_stream_until_one_does(self) -> None:
        segments = [_segment(1, 999, syn=True), _segment(2, 1000, ALERT + b'\x80\x2e\x01\x00\x02'),
                    _segment(3, 1012, b'\x00' * 20), _segment(4, 1032, DATA)]
        reasm = self._run(segments)
        self.assertEqual([datagram.fragment for datagram in reasm.datagram], [ALERT[5:], DATA[5:]])
        self.assertEqual([datagram.index for datagram in reasm.datagram], [(2,), (4,)])

    def test_a_hole_leaves_its_record_incomplete_and_the_next_whole(self) -> None:
        from pcapkit.foundation.reassembly.data import Completion

        stream = HELLO + DATA
        segments = [_segment(1, 999, syn=True), _segment(2, 1000, stream[:100]),
                    _segment(3, 1250, stream[250:])]  # octets 100 to 250 are never captured
        for strict, fragment in ((True, (HELLO[5:100], HELLO[250:])),
                                 (False, HELLO[5:100] + bytes(150) + HELLO[250:])):
            with self.subTest(strict=strict):
                reasm = self._run(segments, strict=strict)
                hello, data = reasm.datagram
                self.assertEqual((hello.completed, hello.index, hello.fragment, hello.packet),
                                 (Completion.PARTIAL, (2, 3), fragment, None))
                self.assertEqual((data.completed, data.index, data.fragment), (Completion.COMPLETE, (3,), DATA[5:]))
                self.assertEqual(data.packet.data, DATA)
                # the read is not destructive, and the hole may still be filled
                self.assertEqual(reasm.datagram, (hello, data))
                reasm(_segment(4, 1100, stream[100:250]))
                filled, again = reasm.datagram
                self.assertEqual((filled.completed, filled.index), (Completion.COMPLETE, (2, 3, 4)))
                self.assertHello(filled.packet)
                self.assertEqual(again.fragment, DATA[5:])

    def test_octets_past_a_hole_over_a_header_are_not_reported(self) -> None:
        from pcapkit.foundation.reassembly.data import Completion

        stream = ALERT + DATA
        segments = [_segment(1, 999, syn=True), _segment(2, 1000, stream[:9]), _segment(3, 1010, stream[10:])]
        alert, = self._run(segments).datagram
        self.assertEqual((alert.completed, alert.index), (Completion.COMPLETE, (2,)))

    def test_octets_opening_no_record_past_a_hole_end_the_records_reported(self) -> None:
        from pcapkit.foundation.reassembly.data import Completion

        segments = [_segment(1, 999, syn=True), _segment(2, 1000, DATA[:10]),
                    _segment(3, 1020, DATA[20:] + bytes(10))]  # a hole, then no record after it
        data, = self._run(segments).datagram
        self.assertEqual((data.completed, data.index, data.fragment), (Completion.PARTIAL, (2, 3), (DATA[5:10], DATA[20:])))

    def test_a_fin_drops_the_octets_held_past_it(self) -> None:
        from pcapkit.foundation.reassembly.data import Completion

        end = 1000 + len(DATA)
        reasm = self._run([_segment(1, 999, syn=True), _segment(2, 1000, DATA[:30]),
                           _segment(3, end + 5, b'\xee' * 10), _segment(4, end, fin=True)])
        self.assertEqual([run.first for run in reasm._buffer[BUFID].runs], [1000])  # pylint: disable=protected-access
        reasm(_segment(5, 1030, DATA[30:] + b'\xee' * 5))
        data, = reasm.datagram
        self.assertEqual((data.completed, data.index, data.fragment), (Completion.COMPLETE, (2, 5), DATA[5:]))
        self.assertTrue(reasm._buffer[BUFID].closed)  # pylint: disable=protected-access

    def test_an_rst_reports_the_record_it_cuts_and_closes_the_stream(self) -> None:
        from pcapkit.foundation.reassembly.data import Completion

        reasm = self._run([_segment(1, 999, syn=True), _segment(2, 1000, HELLO[:100]),
                           _segment(3, 1100, rst=True), _segment(4, 1100, HELLO[100:])])
        hello, = reasm.datagram
        self.assertEqual((hello.completed, hello.index, hello.fragment), (Completion.PARTIAL, (2,), (HELLO[5:100],)))
        self.assertEqual(len(reasm._dtgram), 1)  # pylint: disable=protected-access

        # a SYN opens the endpoints again
        reasm(_segment(5, 7999, syn=True))
        reasm(_segment(6, 8000, DATA))
        self.assertEqual([datagram.index for datagram in reasm.datagram], [(2,), (6,)])

    def test_a_fin_closes_the_stream_once_every_octet_before_it_is_held(self) -> None:
        from pcapkit.foundation.reassembly.data import Completion

        record = DATA[:-10]  # the peer closed before the record's last ten octets
        reasm = self._run([_segment(1, 999, syn=True), _segment(2, 1020, record[20:], fin=True)])
        self.assertEqual(reasm._dtgram, [])  # pylint: disable=protected-access
        reasm(_segment(3, 1000, record[:20]))
        data, = reasm._dtgram  # pylint: disable=protected-access
        self.assertEqual((data.completed, data.index, data.fragment), (Completion.PARTIAL, (2, 3), (DATA[5:-10],)))

        # a late retransmission is not taken for a new stream
        reasm(_segment(4, 1000, DATA))
        self.assertEqual(reasm.datagram, (data,))

    def test_a_buffer_past_its_timeout_reports_its_record_timed_out(self) -> None:
        from pcapkit.foundation.reassembly.data import Completion

        reasm = self._run([_segment(1, 999, syn=True), _segment(2, 1000, HELLO[:100])], timeout=10.0)
        reasm.advance(1000.0 + 12)
        hello, = reasm.datagram
        self.assertEqual((hello.completed, hello.index), (Completion.TIMEOUT, (2,)))
        self.assertEqual(reasm._buffer, {})  # pylint: disable=protected-access

    def test_each_direction_is_a_stream_of_its_own(self) -> None:
        reverse = (SERVER[0], SERVER[1], CLIENT[0], CLIENT[1])
        reasm = self._run([_segment(1, 1000, HELLO[:100]), _segment(2, 7000, DATA[:20], bufid=reverse),
                           _segment(3, 1100, HELLO[100:]), _segment(4, 7020, DATA[20:], bufid=reverse)])
        hello, data = reasm.datagram
        self.assertEqual((hello.id.src, hello.index, data.id.src, data.index), (CLIENT, (1, 3), SERVER, (2, 4)))

    def test_an_open_stream_holding_no_record_runs_no_callback(self) -> None:
        from pcapkit.foundation.reassembly.tls.reassembly import TLS

        seen = []  # type: list[Any]
        TLS.register_callback(seen.append)
        self.addCleanup(TLS.__callback_fn__.remove, seen.append)
        reasm = self._run([_segment(1, 1000, DATA)])
        self.assertEqual(reasm.datagram, tuple(seen[0]))
        self.assertEqual(len(seen), 1)

    def test_a_datagram_pickles_with_its_packet_deferred(self) -> None:
        from pcapkit.foundation.reassembly.data import Deferred

        datagram, = self._run([_segment(1, 1000, HELLO)]).datagram
        held = datagram.__dict__[datagram.__map__['packet']]
        self.assertIsInstance(held, Deferred)
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            with self.subTest(protocol=protocol):
                copy = pickle.loads(pickle.dumps(datagram, protocol=protocol))  # nosec: B301
                self.assertIsInstance(copy.__dict__[copy.__map__['packet']], Deferred)
                self.assertEqual(copy.id, datagram.id)
                self.assertHello(copy.packet)


class AnalysisTests(_Case):
    """:func:`tls_record` decodes a complete record, and nothing else."""

    def test_a_complete_record_decodes_as_its_packet_does(self) -> None:
        from pcapkit.foundation.analysis import tls_record
        from pcapkit.foundation.reassembly.tls.reassembly import TLS

        reasm = TLS()
        for segment in (_segment(1, 1000, HELLO[:100]), _segment(2, 1100, HELLO[100:])):
            reasm(segment)
        datagram, = reasm.datagram
        self.assertHello(tls_record(datagram))
        self.assertEqual(tls_record(datagram).info, datagram.packet.info)

    def test_an_incomplete_record_decodes_to_none(self) -> None:
        from pcapkit.foundation.analysis import tls_record
        from pcapkit.foundation.reassembly.tls.reassembly import TLS

        for strict in (True, False):
            with self.subTest(strict=strict):
                reasm = TLS(strict=strict)
                reasm(_segment(1, 1000, HELLO[:100]))
                datagram, = reasm.datagram
                self.assertIsNone(tls_record(datagram))
                self.assertIsNone(datagram.packet)


class AdapterTests(_Case):
    """Each engine's ``tls_reassembly`` keeps its TCP adapter's record of a TLS stream."""

    def test_the_default_engine_keeps_a_segment_on_a_tls_port(self) -> None:
        from pcapkit.toolkit import pcap as toolkit_pcap
        from pcapkit.toolkit import pcapng as toolkit_pcapng

        frames = _hello_frames(999)
        other = [_frame(_tcp((CLIENT[0], 50001), (SERVER[0], 80), 1, 0x10, HELLO[:100]),
                        (CLIENT[0], 50001), (SERVER[0], 80))]
        for (module, write) in ((toolkit_pcap, _pcap), (toolkit_pcapng, _pcapng)):
            with self.subTest(module=module.__name__):
                parsed = _extract(self, write(frames + other)).frame
                self.assertEqual([module.tls_reassembly(frame) for frame in parsed[:-1]],
                                 [module.tcp_reassembly(frame) for frame in parsed[:-1]])
                self.assertIsNotNone(module.tcp_reassembly(parsed[-1]))
                self.assertIsNone(module.tls_reassembly(parsed[-1]))

    def test_a_port_registered_to_tls_is_kept(self) -> None:
        from pcapkit.protocols.application.tls.protocol import TLS
        from pcapkit.protocols.transport.tcp.protocol import TCP
        from pcapkit.toolkit.pcap import _tls_segment

        packet = _segment(1, 1000, HELLO, bufid=(CLIENT[0], 50000, SERVER[0], 8443))
        self.assertIsNone(_tls_segment(packet))
        with mock.patch.dict(TCP.__proto__, {8443: TLS}):
            self.assertIs(_tls_segment(packet), packet)
        self.assertIsNone(_tls_segment(None))

    def test_every_third_party_adapter_wraps_its_tcp_one(self) -> None:
        import pcapkit.toolkit.pypcapfile as toolkit_pypcapfile

        modules = [toolkit_pypcapfile]
        for name in ('dpkt', 'scapy'):
            if importlib.util.find_spec(name) is not None:
                modules.append(importlib.import_module(f'pcapkit.toolkit.{name}'))
        tls, web = _segment(1, 1000, HELLO), _segment(2, 1000, HELLO, bufid=(CLIENT[0], 50000, SERVER[0], 80))
        for module in modules:
            args = (object(), 1000.0) if module.__name__.endswith('dpkt') else (object(),)
            for (packet, expected) in ((tls, tls), (web, None), (None, None)):
                with self.subTest(module=module.__name__, port=packet and packet.bufid[3]), \
                        mock.patch.object(module, 'tcp_reassembly', return_value=packet) as tcp:
                    self.assertIs(module.tls_reassembly(*args, count=7), expected)
                    tcp.assert_called_once_with(*args, count=7)


class ExtractionTests(_Case):
    """``Extractor(reassembly=['tls'])`` reports the records of every TLS stream."""

    def test_a_record_split_across_segments_decodes_on_every_engine(self) -> None:
        from pcapkit.foundation.reassembly.data import Completion

        frames = _hello_frames(2 ** 32 - 50)
        engines = [('default', _pcap), ('default', _pcapng)]
        engines += [(name, _pcap) for name in ('dpkt', 'scapy') if importlib.util.find_spec(name) is not None]
        for (engine, write) in engines:
            with self.subTest(engine=engine, container=write.__name__):
                extractor = self._extract(write(frames), engine)
                datagram, = extractor.reassembly.tls
                self.assertEqual((datagram.completed, datagram.index, datagram.id.seq),
                                 (Completion.COMPLETE, (2, 3, 4), 2 ** 32 - 49))
                self.assertHello(datagram.packet)
                if engine == 'default':
                    # each segment alone holds part of the record, which a frame keeps raw
                    self.assertEqual([str(frame.protochain) for frame in extractor.frame[1:4]],
                                     ['Ethernet:IPv4:TCP:Raw'] * 3)

    def _extract(self, capture: bytes, engine: str) -> 'Any':
        """Extract ``capture`` with TLS reassembly, from a file for an engine opening one by name."""
        from pcapkit import extract

        if engine != 'scapy':
            return _extract(self, capture, reassembly=['tls'], engine=engine)
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as file:
            file.write(capture)
        self.addCleanup(os.unlink, file.name)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = extract(fin=file.name, store=True, reassembly=['tls'], engine=engine)
        self.addCleanup(close_extractor, extractor)
        return extractor

    def test_the_record_holds_no_field_unless_enabled(self) -> None:
        from pcapkit.foundation.reassembly.data import ReassemblyData

        extractor = _extract(self, _pcap(_hello_frames(999)), reassembly=['tcp'])
        self.assertIsNone(extractor.reassembly.tls)
        self.assertEqual(list(ReassemblyData())[-1], 'tls')

    def test_reassemble_makes_it_by_name_and_by_protocol(self) -> None:
        from pcapkit.foundation.reassembly.tls.reassembly import TLS
        from pcapkit.interface import reassemble
        from pcapkit.protocols.application.tls.protocol import TLS as TLS_Protocol

        for protocol in ('tls', 'TLS', TLS_Protocol):
            with self.subTest(protocol=protocol):
                reasm = reassemble(protocol, strict=False)
                self.assertIsInstance(reasm, TLS)
                self.assertFalse(reasm._flag_s)  # pylint: disable=protected-access


if __name__ == '__main__':
    unittest.main()
