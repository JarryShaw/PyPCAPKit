# -*- coding: utf-8 -*-
"""DTLS handshake-message reassembly (GitHub issues #2440 and #2496).

Covers the :class:`~pcapkit.foundation.reassembly.dtls.DTLS` engine in
isolation, fed fragments directly, and the extraction path: the default engine
feeds it through :func:`pcapkit.toolkit.pcap.dtls_reassembly`, and
:func:`pcapkit.foundation.analysis.dtls_handshake` decodes a fragmented
``ClientHello``/``ServerHello`` once the engine reports the message complete.

Every case builds its fragments and captures in memory and reads no sample
capture. Classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

from __future__ import annotations

import io
import ipaddress
import struct
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import close_extractor, reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): hand-picked round-trip cases, not a sweep.
__tier__ = 'ALL'


def _client_hello_body(cipher_suites: bytes = b'\x13\x01', extensions: 'bytes | None' = b'',
                       cookie: bytes = b'') -> bytes:
    """A genuine DTLS ``ClientHello`` body (:rfc:`6347#section-4.2.1`'s
    ``cookie`` included)."""
    version = b'\xfe\xfd'
    random = bytes(range(32))
    session_id = b''
    compression = b'\x00'
    tail = b'' if extensions is None else len(extensions).to_bytes(2, 'big') + extensions
    return (version + random + bytes([len(session_id)]) + session_id
            + bytes([len(cookie)]) + cookie
            + len(cipher_suites).to_bytes(2, 'big') + cipher_suites
            + bytes([len(compression)]) + compression
            + tail)


def _server_hello_body(extensions: 'bytes | None' = b'') -> bytes:
    version = b'\xfe\xfd'
    random = bytes(range(32, 64))
    session_id = b''
    cipher_suite = b'\x13\x01'
    compression = b'\x00'
    tail = b'' if extensions is None else len(extensions).to_bytes(2, 'big') + extensions
    return (version + random + bytes([len(session_id)]) + session_id
            + cipher_suite + compression + tail)


def _dtls_record(content_type: int, fragment: bytes, version: bytes = b'\xfe\xfd',
                 epoch: int = 0, seq: int = 1) -> bytes:
    return (bytes([content_type]) + version + epoch.to_bytes(2, 'big') + seq.to_bytes(6, 'big')
            + len(fragment).to_bytes(2, 'big') + fragment)


def _dtls_handshake(msg_type: int, body: bytes, *, message_seq: int, fragment_offset: int,
                    fragment_length: int, total_length: 'int | None' = None) -> bytes:
    length = total_length if total_length is not None else len(body)
    header = bytes([msg_type]) + length.to_bytes(3, 'big')
    frag_header = (message_seq.to_bytes(2, 'big') + fragment_offset.to_bytes(3, 'big')
                   + fragment_length.to_bytes(3, 'big'))
    return header + frag_header + body


def _split(body: bytes, bounds: 'tuple[int, ...]') -> 'list[tuple[int, int]]':
    """``bounds`` offsets (not including 0 or ``len(body)``) into ``(offset,
    length)`` pairs covering the whole of ``body``."""
    edges = (0, *bounds, len(body))
    return [(edges[i], edges[i + 1] - edges[i]) for i in range(len(edges) - 1)]


#: ``(src, sport, dst, dport)`` of the UDP association the captures below carry.
FLOW = (ipaddress.ip_address('192.0.2.1'), 1234, ipaddress.ip_address('198.51.100.1'), 5684)


def _frame(record: bytes, flow: 'tuple[Any, int, Any, int]' = FLOW) -> bytes:
    """An Ethernet frame of IPv4 and UDP carrying the DTLS ``record`` along ``flow``."""
    src, sport, dst, dport = flow
    segment = struct.pack('!HHHH', sport, dport, 8 + len(record), 0) + record
    return (b'\xbb' * 6 + b'\xaa' * 6 + b'\x08\x00'
            + struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(segment), 1, 0x4000, 64, 17, 0,
                          src.packed, dst.packed)
            + segment)


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
    """Run the default engine over ``capture``, every frame stored."""
    from pcapkit import extract

    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        extractor = extract(fin=io.BytesIO(capture), nofile=True, store=True, **kwargs)
    test.addCleanup(close_extractor, extractor)
    return extractor


class TestDTLSHandshakeReassembly(unittest.TestCase):
    """The reassembly engine, fed fragments directly."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _engine(strict: bool = True):
        from pcapkit.foundation.reassembly.dtls import DTLS

        return DTLS(strict=strict)

    @staticmethod
    def _packet(bufid, num, msg_type, length, message_seq, fragment_offset, fragment_length,
               payload, timestamp=0.0):
        from pcapkit.foundation.reassembly.data.dtls import Packet

        return Packet(bufid=bufid, num=num, msg_type=msg_type, length=length,
                      message_seq=message_seq, fragment_offset=fragment_offset,
                      fragment_length=fragment_length, payload=payload, timestamp=timestamp)

    def test_two_fragments_reassemble_byte_exact(self) -> None:
        from pcapkit.const.tls.handshake_type import HandshakeType

        body = _client_hello_body(cookie=b'\xab\xcd\xef\x01')
        half = len(body) // 2

        for order in ([0, 1], [1, 0]):
            with self.subTest(order=order):
                engine = self._engine()
                bufid = ('10.0.0.1', 1234, '10.0.0.2', 5684, 0)
                frags = [(0, body[:half]), (half, body[half:])]
                last = None
                for num, idx in enumerate(order, 1):
                    fo, payload = frags[idx]
                    engine(self._packet(bufid, num, HandshakeType.client_hello, len(body),
                                        5, fo, len(payload), payload, float(num)))
                    if engine.last is not None:
                        last = engine.last
                self.assertIsNotNone(last)
                self.assertTrue(last.completed)
                self.assertEqual(last.body, body)
                self.assertEqual(last.message_seq, 5)
                self.assertEqual(sorted(last.index), [1, 2])

    def test_three_fragments_out_of_order_reassemble_byte_exact(self) -> None:
        from pcapkit.const.tls.handshake_type import HandshakeType

        body = _server_hello_body(extensions=b'\x00\x0d\x00\x02\xab\xcd')
        third = len(body) // 3
        frags = _split(body, (third, 2 * third))

        for order in ([0, 1, 2], [2, 0, 1], [1, 2, 0]):
            with self.subTest(order=order):
                engine = self._engine()
                bufid = ('1.1.1.1', 100, '2.2.2.2', 5684, 0)
                last = None
                for num, idx in enumerate(order, 1):
                    fo, length = frags[idx]
                    payload = body[fo:fo + length]
                    engine(self._packet(bufid, num, HandshakeType.server_hello, len(body),
                                        9, fo, length, payload, float(num)))
                    if engine.last is not None:
                        last = engine.last
                self.assertIsNotNone(last)
                self.assertTrue(last.completed)
                self.assertEqual(last.body, body)

    def test_overlapping_fragments_are_accepted_and_complete_byte_exact(self) -> None:
        """Overlapping fragments are accepted, not dropped
        (:rfc:`6347#section-4.2.3`, :rfc:`9147#section-5.5`): a partial
        overlap, a smaller retransmission inside held bytes, and a duplicate
        all leave the message completing byte-exact on its last fragment.
        Dropping overlapping fragments leaves a hole, so it never completes."""
        from pcapkit.const.tls.handshake_type import HandshakeType

        body = bytes(range(16))
        bufid = ('30.0.0.1', 1, '30.0.0.2', 5684, 0)
        # (offset, length): a start, a partial overlap, a smaller
        # retransmission inside held bytes, a duplicate, then the last one.
        sequence = [(0, 8), (6, 6), (2, 4), (6, 6), (12, 4)]

        engine = self._engine()
        for num, (fo, length) in enumerate(sequence, 1):
            engine(self._packet(bufid, num, HandshakeType.client_hello, len(body),
                                7, fo, length, body[fo:fo + length], float(num)))
            if num < len(sequence):
                self.assertIsNone(engine.last)
        self.assertIsNotNone(engine.last)
        self.assertTrue(engine.last.completed)
        self.assertEqual(engine.last.body, body)

    def test_epoch_change_opens_a_fresh_buffer(self) -> None:
        """An epoch change opens a fresh buffer (:rfc:`6347#section-4.1`):
        a fragment at a new epoch must not be folded into the previous
        epoch's -- otherwise unrelated -- buffer, even if its message_seq
        and fragment offsets happen to agree with an incomplete message
        there."""
        from pcapkit.const.tls.handshake_type import HandshakeType

        body = _client_hello_body()
        half = len(body) // 2
        addr = ('5.5.5.5', 1, '6.6.6.6', 5684)

        engine = self._engine()
        # epoch 0: only the first half ever arrives -- never completes.
        engine(self._packet((*addr, 0), 1, HandshakeType.client_hello, len(body),
                            0, 0, half, body[:half], 0.0))
        self.assertIsNone(engine.last)

        # epoch 1 reuses the same message_seq (0) and the same 4-tuple, but a
        # *whole* message in one fragment -- it must complete independently.
        engine(self._packet((*addr, 1), 2, HandshakeType.client_hello, len(body),
                            0, 0, len(body), body, 0.1))
        self.assertIsNotNone(engine.last)
        self.assertTrue(engine.last.completed)
        self.assertEqual(engine.last.id.epoch, 1)
        self.assertEqual(engine.last.body, body)

        # the epoch-0 buffer is still there, untouched and still incomplete.
        remaining = engine.datagram
        partial = [d for d in remaining if d.id.epoch == 0]
        self.assertEqual(len(partial), 1)
        self.assertEqual(partial[0].completed.name, 'PARTIAL')

    def test_incomplete_reassembly_never_completes_and_does_not_crash(self) -> None:
        """A message missing a fragment forever stays unavailable -- reported
        ``PARTIAL`` on fetch, rather than raising or
        fabricating a result."""
        from pcapkit.const.tls.handshake_type import HandshakeType

        body = _server_hello_body()
        third = len(body) // 3
        frags = _split(body, (third, 2 * third))
        bufid = ('7.7.7.7', 1, '8.8.8.8', 5684, 0)

        for strict in (True, False):
            with self.subTest(strict=strict):
                engine = self._engine(strict=strict)
                # only fragments 0 and 2 ever arrive; fragment 1 is lost.
                for num, idx in enumerate((0, 2), 1):
                    fo, length = frags[idx]
                    payload = body[fo:fo + length]
                    engine(self._packet(bufid, num, HandshakeType.server_hello, len(body),
                                        1, fo, length, payload, float(num)))
                    self.assertIsNone(engine.last)

                datagram, = engine.datagram
                self.assertEqual(datagram.completed.name, 'PARTIAL')
                if strict:
                    self.assertIsInstance(datagram.body, tuple)
                    self.assertEqual(b''.join(datagram.body),
                                     body[:frags[0][1]] + body[frags[2][0]:])
                else:
                    self.assertIsInstance(datagram.body, bytes)
                    self.assertEqual(len(datagram.body), len(body))
                    self.assertEqual(datagram.body[:frags[0][1]], body[:frags[0][1]])
                    self.assertEqual(datagram.body[frags[2][0]:], body[frags[2][0]:])

    def test_several_messages_in_flight_under_one_buffer_id(self) -> None:
        """A ``Certificate`` and a ``ServerHelloDone`` fragmenting
        independently in the same flight share a buffer ID but must not
        share -- or complete into -- each other's message."""
        from pcapkit.const.tls.handshake_type import HandshakeType

        cert_body = b'C' * 40
        shd_body = b'D' * 20
        bufid = ('9.9.9.9', 1, '10.10.10.10', 5684, 0)

        engine = self._engine()
        engine(self._packet(bufid, 1, HandshakeType.certificate, len(cert_body),
                            1, 0, 20, cert_body[:20], 0.0))
        self.assertIsNone(engine.last)
        engine(self._packet(bufid, 2, HandshakeType.server_hello_done, len(shd_body),
                            2, 0, 20, shd_body, 0.1))
        self.assertIsNotNone(engine.last)
        self.assertEqual(engine.last.message_seq, 2)
        self.assertEqual(engine.last.body, shd_body)

        engine(self._packet(bufid, 3, HandshakeType.certificate, len(cert_body),
                            1, 20, 20, cert_body[20:], 0.2))
        self.assertIsNotNone(engine.last)
        self.assertEqual(engine.last.message_seq, 1)
        self.assertEqual(engine.last.body, cert_body)

    def test_disagreeing_fragment_restarts_the_message_instead_of_corrupting_it(self) -> None:
        """A fragment that disagrees with the message buffered under
        its ``message_seq`` -- a different ``length`` or ``msg_type`` -- must
        not be merged into it: a stale, abandoned buffer from an earlier
        handshake sharing the same :data:`BufferID` and restarted
        ``message_seq`` (:rfc:`6347#section-4.2.2`) would otherwise combine
        with the new handshake's fragment into one corrupt message."""
        from pcapkit.const.tls.handshake_type import HandshakeType

        old_body = _client_hello_body(cookie=b'\x01' * 4)
        new_body = _client_hello_body(cookie=b'\x02' * 8)
        bufid = ('1.2.3.4', 1, '5.6.7.8', 5684, 0)

        engine = self._engine()
        # the old handshake's message_seq=0 fragment never completes.
        half = len(old_body) // 2
        engine(self._packet(bufid, 1, HandshakeType.client_hello, len(old_body),
                            0, 0, half, old_body[:half], 0.0))
        self.assertIsNone(engine.last)

        # a new handshake reuses the same BufferID and message_seq, but
        # disagrees on length -- the new fragment must start a fresh
        # message, not fill the old one's remaining hole.
        engine(self._packet(bufid, 2, HandshakeType.client_hello, len(new_body),
                            0, 0, len(new_body), new_body, 0.1))
        self.assertIsNotNone(engine.last)
        self.assertTrue(engine.last.completed)
        self.assertEqual(engine.last.body, new_body)

    def test_restart_on_msg_type_disagreement_alone(self) -> None:
        """A fragment disagreeing only on ``msg_type`` -- same ``length`` --
        must restart the message too, not just one disagreeing on
        ``length``."""
        from pcapkit.const.tls.handshake_type import HandshakeType

        length = 20
        old_partial = b'A' * 10
        new_whole = b'B' * length
        bufid = ('15.0.0.1', 1, '15.0.0.2', 5684, 0)

        engine = self._engine()
        # the old handshake's message_seq=0 fragment (a Certificate) never
        # completes -- same length as the new message below, different
        # msg_type.
        engine(self._packet(bufid, 1, HandshakeType.certificate, length,
                            0, 0, 10, old_partial, 0.0))
        self.assertIsNone(engine.last)

        # a new handshake reuses the same BufferID and message_seq, agrees
        # on length, but disagrees on msg_type -- it must still start a
        # fresh message rather than filling the old Certificate's hole.
        engine(self._packet(bufid, 2, HandshakeType.server_hello_done, length,
                            0, 0, length, new_whole, 0.1))
        self.assertIsNotNone(engine.last)
        self.assertTrue(engine.last.completed)
        self.assertEqual(engine.last.msg_type, HandshakeType.server_hello_done)
        self.assertEqual(engine.last.body, new_whole)

    def test_displaced_partial_is_reported_not_silently_dropped(self) -> None:
        """The partial message a disagreeing fragment displaces is reported
        as its own, PARTIAL result rather than vanishing with no trace."""
        from pcapkit.const.tls.handshake_type import HandshakeType

        old_body = _client_hello_body(cookie=b'\x01' * 4)
        new_body = _client_hello_body(cookie=b'\x02' * 8)
        bufid = ('16.0.0.1', 1, '16.0.0.2', 5684, 0)

        engine = self._engine()
        half = len(old_body) // 2
        engine(self._packet(bufid, 1, HandshakeType.client_hello, len(old_body),
                            0, 0, half, old_body[:half], 0.0))
        self.assertIsNone(engine.last)

        engine(self._packet(bufid, 2, HandshakeType.client_hello, len(new_body),
                            0, 0, len(new_body), new_body, 0.1))
        self.assertIsNotNone(engine.last)
        self.assertTrue(engine.last.completed)

        results = engine.fetch()
        self.assertEqual(len(results), 2)
        completed = [d for d in results if d.completed.name == 'COMPLETE']
        partial = [d for d in results if d.completed.name == 'PARTIAL']
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0].body, new_body)
        self.assertEqual(len(partial), 1)
        self.assertEqual(partial[0].index, (1,))

    def test_stale_buffer_is_held_not_expired_by_time(self) -> None:
        """A buffer whose first fragment is arbitrarily old is never abandoned
        as :attr:`~pcapkit.foundation.reassembly.data.data.Completion.TIMEOUT`:
        DTLS handshake reassembly has no time-based deadline
        (:rfc:`6347#section-4.2.3`, :rfc:`9147#section-5.5`). Its late
        fragments still complete it."""
        from pcapkit.const.tls.handshake_type import HandshakeType

        body = _server_hello_body()
        third = len(body) // 3
        frags = _split(body, (third, 2 * third))
        bufid = ('17.0.0.1', 1, '17.0.0.2', 5684, 0)
        other_bufid = ('18.0.0.1', 2, '18.0.0.2', 5684, 0)

        engine = self._engine()
        fo, length = frags[0]
        engine(self._packet(bufid, 1, HandshakeType.server_hello, len(body),
                            1, fo, length, body[fo:fo + length], 0.0))
        self.assertIsNone(engine.last)

        # A fragment under an UNRELATED buffer, a million seconds later, must
        # not abandon the first buffer.
        fo2, length2 = frags[0]
        engine(self._packet(other_bufid, 2, HandshakeType.server_hello, len(body),
                            1, fo2, length2, body[fo2:fo2 + length2], 1e6))

        # The late fragments complete the stale message as COMPLETE. Reading
        # ``engine.datagram`` flushes held buffers, so it is read only after.
        for num, idx in ((3, 1), (4, 2)):
            fo3, length3 = frags[idx]
            engine(self._packet(bufid, num, HandshakeType.server_hello, len(body),
                                1, fo3, length3, body[fo3:fo3 + length3], 1e6 + num))
        self.assertIsNotNone(engine.last)
        self.assertEqual(engine.last.completed.name, 'COMPLETE')
        self.assertEqual(engine.last.body, body)
        stale = [d for d in engine.datagram if d.id.src == '17.0.0.1']
        self.assertEqual([d.completed.name for d in stale], ['COMPLETE'])

    def test_delayed_fragments_complete_with_no_deadline(self) -> None:
        """Fragments arriving minutes apart still complete their message: with
        no time-based deadline, a delay between fragments abandons nothing."""
        from pcapkit.const.tls.handshake_type import HandshakeType

        body = _client_hello_body(cookie=b'\xaa\xbb\xcc\xdd')
        third = len(body) // 3
        frags = _split(body, (third, 2 * third))
        bufid = ('19.0.0.1', 1, '19.0.0.2', 5684, 0)

        # Fragments at t=0, t=100, t=200 seconds of capture time.
        engine = self._engine()
        for i, (fo, length) in enumerate(frags):
            payload = body[fo:fo + length]
            timestamp = float(i * 100)
            engine(self._packet(bufid, i + 1, HandshakeType.client_hello, len(body),
                                0, fo, length, payload, timestamp))
            if engine.last is not None:
                # Message completed on this fragment.
                break

        self.assertIsNotNone(engine.last)
        self.assertTrue(engine.last.completed)
        self.assertEqual(engine.last.body, body)


class TestDTLSExtractorReassembly(unittest.TestCase):
    """``Extractor(reassembly=True, dtls=True)`` over real frames, and
    :func:`~pcapkit.foundation.analysis.dtls_handshake` over what it reassembles."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _records(msg_type: int, body: bytes, frags: 'list[tuple[int, int]]', *,
                 message_seq: int = 5) -> 'list[bytes]':
        """One DTLS record per ``(offset, length)`` fragment of ``body``."""
        return [_dtls_record(22, _dtls_handshake(msg_type, body[fo:fo + length],
                                                 message_seq=message_seq, fragment_offset=fo,
                                                 fragment_length=length, total_length=len(body)),
                             seq=num)
                for num, (fo, length) in enumerate(frags, 1)]

    def test_fragmented_client_hello_decodes_once_reassembled(self) -> None:
        from pcapkit.foundation.analysis import dtls_handshake

        body = _client_hello_body(cookie=b'\xab\xcd\xef\x01')
        records = self._records(1, body, _split(body, (len(body) // 2,)))
        for container, write in (('pcap', _pcap), ('pcapng', _pcapng)):
            with self.subTest(container=container):
                extractor = _extract(self, write([_frame(r) for r in records]),
                                     reassembly=True, dtls=True)

                # the frames themselves keep each fragment's raw octets
                for frame in extractor.frame:
                    message = frame['DTLS'].info.content[0]
                    self.assertTrue(message.is_fragmented)
                    self.assertIsInstance(message.body, bytes)

                datagram, = extractor.reassembly.dtls
                self.assertTrue(datagram.completed)
                self.assertEqual(datagram.index, (1, 2))
                self.assertEqual((datagram.id.src, datagram.id.sport, datagram.id.dst,
                                  datagram.id.dport, datagram.id.epoch), (*FLOW, 0))
                decoded = dtls_handshake(datagram)
                self.assertFalse(decoded.is_fragmented)
                self.assertEqual((decoded.fragment_offset, decoded.fragment_length),
                                 (0, len(body)))
                self.assertEqual(decoded.body.cookie, b'\xab\xcd\xef\x01')

    def test_fragmented_server_hello_decodes_once_reassembled(self) -> None:
        from pcapkit.foundation.analysis import dtls_handshake

        body = _server_hello_body(extensions=b'\x00\x0d\x00\x02\xab\xcd')
        third = len(body) // 3
        frags = _split(body, (third, 2 * third))
        # delivered out of order: [2, 0, 1]
        records = self._records(2, body, [frags[2], frags[0], frags[1]], message_seq=9)
        extractor = _extract(self, _pcap([_frame(r) for r in records]), reassembly=True, dtls=True)

        datagram, = extractor.reassembly.dtls
        self.assertEqual(datagram.body, body)
        self.assertEqual(dtls_handshake(datagram).body.random, bytes(range(32, 64)))

    def test_interleaved_associations_do_not_share_a_buffer(self) -> None:
        """Two associations sending the same ``message_seq`` interleaved each
        reassemble their own message: the buffer ID is read off each frame's
        own IP and UDP layers."""
        from pcapkit.foundation.analysis import dtls_handshake

        other = (FLOW[0], 4321, FLOW[2], FLOW[3])
        body_a = _client_hello_body(cookie=b'\x0a' * 4)
        body_b = _client_hello_body(cookie=b'\x0b' * 4)
        half = len(body_a) // 2
        rec_a = self._records(1, body_a, _split(body_a, (half,)))
        rec_b = self._records(1, body_b, _split(body_b, (half,)))
        frames = [_frame(rec_a[0]), _frame(rec_b[0], other), _frame(rec_a[1]), _frame(rec_b[1], other)]
        extractor = _extract(self, _pcap(frames), reassembly=True, dtls=True)

        cookies = {d.id.sport: dtls_handshake(d).body.cookie for d in extractor.reassembly.dtls}
        self.assertEqual(cookies, {1234: b'\x0a' * 4, 4321: b'\x0b' * 4})

    def test_encrypted_handshake_record_skips_reassembly_unharmed(self) -> None:
        """A ``handshake``-typed record at epoch >= 1 is ciphertext -- every
        real DTLS handshake ends with one, the encrypted ``Finished`` -- so it
        stays raw bytes and feeds nothing."""
        ciphertext = b'\xa3\x5d\x12\xee' * 12
        extractor = _extract(self, _pcap([_frame(_dtls_record(22, ciphertext, epoch=1, seq=7))]),
                             reassembly=True, dtls=True)
        self.assertEqual(extractor.frame[0]['DTLS'].info.content, ciphertext)
        self.assertEqual(extractor.reassembly.dtls, ())

    def test_every_fragment_record_rebuilds_byte_exact(self) -> None:
        """Reassembly leaves the frames alone, so every fragment's record --
        the one completing its message included -- round-trips exactly
        through ``from_data``."""
        from pcapkit.protocols.application.dtls import DTLS

        body = _client_hello_body(cookie=b'\xab\xcd\xef\x01')
        records = self._records(1, body, _split(body, (len(body) // 2,)))
        extractor = _extract(self, _pcap([_frame(r) for r in records]), reassembly=True, dtls=True)

        self.assertTrue(extractor.reassembly.dtls[0].completed)
        for frame, record in zip(extractor.frame, records):
            self.assertEqual(bytes(DTLS.from_data(frame['DTLS'].info)), record)

    def test_overrunning_completing_fragment_keeps_raw_bytes_and_round_trips(self) -> None:
        """A fragment whose ``fragment_offset + fragment_length`` overruns the
        declared ``length`` (5 + 10 > 10) completes its message, clipped, but
        its record stays exactly as it arrived."""
        from pcapkit.protocols.application.dtls import DTLS

        length = 10
        second = b'B' * 10  # this record's own 10 octets, but offset 5 + 10 > length 10
        record1 = _dtls_record(22, _dtls_handshake(11, b'A' * 5, message_seq=3, fragment_offset=0,
                                                   fragment_length=5, total_length=length), seq=2)
        record2 = _dtls_record(22, _dtls_handshake(11, second, message_seq=3, fragment_offset=5,
                                                   fragment_length=10, total_length=length), seq=3)
        extractor = _extract(self, _pcap([_frame(record1), _frame(record2)]),
                             reassembly=True, dtls=True)

        datagram, = extractor.reassembly.dtls
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.body, b'A' * 5 + b'B' * 5)

        message = extractor.frame[1]['DTLS'].info.content[0]
        self.assertEqual((message.body, message.fragment_offset, message.fragment_length),
                         (second, 5, 10))
        self.assertEqual(bytes(DTLS.from_data(extractor.frame[1]['DTLS'].info)), record2)

    def test_undecodable_reassembled_body_falls_back_to_raw_bytes(self) -> None:
        """A completed message whose reassembled bytes do not decode as its
        ``msg_type`` keeps them raw instead of raising."""
        from pcapkit.foundation.analysis import dtls_handshake

        # far too short to be a genuine ClientHello, but in bounds for the reassembler
        body = b'\x01\x02\x03\x04\x05'
        records = self._records(1, body, _split(body, (3,)), message_seq=1)
        extractor = _extract(self, _pcap([_frame(r) for r in records]), reassembly=True, dtls=True)

        datagram, = extractor.reassembly.dtls
        self.assertTrue(datagram.completed)
        decoded = dtls_handshake(datagram)
        self.assertEqual(decoded.body, body)
        self.assertFalse(decoded.is_fragmented)

    def test_records_without_fragmented_messages_feed_nothing(self) -> None:
        """An alert, application data, and a handshake record whose message
        arrives whole reach no reassembly buffer."""
        whole = _client_hello_body()
        records = [
            _dtls_record(21, bytes([1, 0]), seq=2),
            _dtls_record(23, b'\x17' * 16, seq=3),
            _dtls_record(22, _dtls_handshake(1, whole, message_seq=0, fragment_offset=0,
                                             fragment_length=len(whole)), seq=4),
        ]
        extractor = _extract(self, _pcap([_frame(r) for r in records]), reassembly=True, dtls=True)
        self.assertEqual(extractor.reassembly.dtls, ())

    def test_frames_are_the_same_with_and_without_reassembly(self) -> None:
        """What the extractor yields per frame does not depend on DTLS reassembly."""
        body = _client_hello_body(cookie=b'\xab\xcd\xef\x01')
        capture = _pcap([_frame(r) for r in self._records(1, body, _split(body, (len(body) // 2,)))])
        plain = _extract(self, capture)
        reassembled = _extract(self, capture, reassembly=True, dtls=True)
        self.assertEqual([f['DTLS'].info for f in plain.frame],
                         [f['DTLS'].info for f in reassembled.frame])

    def test_without_reassembly_body_stays_raw(self) -> None:
        """Parsed alone, a fragment's body stays raw whatever the fragment."""
        from pcapkit.protocols.application.dtls import DTLS

        body = _client_hello_body()
        half = len(body) // 2
        wire = _dtls_record(22, _dtls_handshake(1, body[half:], message_seq=5, fragment_offset=half,
                                                fragment_length=len(body) - half,
                                                total_length=len(body)), seq=2)

        msg = DTLS(wire, len(wire)).info.content[0]
        self.assertTrue(msg.is_fragmented)
        self.assertIsInstance(msg.body, bytes)

    def test_incomplete_reassembly_stays_raw_and_does_not_crash(self) -> None:
        from pcapkit.foundation.analysis import dtls_handshake

        body = _server_hello_body()
        third = len(body) // 3
        frags = _split(body, (third, 2 * third))
        records = self._records(2, body, [frags[0], frags[2]], message_seq=1)  # fragment 1 lost
        extractor = _extract(self, _pcap([_frame(r) for r in records]), reassembly=True, dtls=True)

        for frame in extractor.frame:
            self.assertIsInstance(frame['DTLS'].info.content[0].body, bytes)
        datagram, = extractor.reassembly.dtls
        self.assertEqual(datagram.completed.name, 'PARTIAL')
        self.assertIsNone(dtls_handshake(datagram))


if __name__ == '__main__':
    unittest.main()
