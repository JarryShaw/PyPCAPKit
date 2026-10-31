# -*- coding: utf-8 -*-
"""DTLS handshake-message reassembly (GitHub issue #2440).

Covers the new :class:`~pcapkit.foundation.reassembly.dtls.DTLS` engine in
isolation, fed fragments directly, and the wiring into
:meth:`~pcapkit.protocols.application.dtls.DTLS.read`, which decodes a
fragmented ``ClientHello``/``ServerHello`` once its reassembly engine reports
the message complete.

Every case builds its fragments in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

from __future__ import annotations

import unittest

from tests._support import reimport_once_per_class

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


class TestDTLSHandshakeReassembly(unittest.TestCase):
    """The reassembly engine, fed fragments directly."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _engine(strict: bool = True, timeout=None):
        from pcapkit.foundation.reassembly.dtls import DTLS

        return DTLS(strict=strict, timeout=timeout)

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

    def test_stale_buffer_expires_as_timeout_not_partial_or_hang(self) -> None:
        """A buffer older than :attr:`~pcapkit.foundation.reassembly.dtls.DTLS.__timeout__`
        reports :attr:`~pcapkit.foundation.reassembly.data.data.Completion.TIMEOUT`
        once abandoned, rather than staying PARTIAL forever or raising
        (``expire``, defined in reassembly/reassembly.py, exercised through
        this engine)."""
        from pcapkit.const.tls.handshake_type import HandshakeType

        body = _server_hello_body()
        third = len(body) // 3
        frags = _split(body, (third, 2 * third))
        bufid = ('17.0.0.1', 1, '17.0.0.2', 5684, 0)
        other_bufid = ('18.0.0.1', 2, '18.0.0.2', 5684, 0)

        engine = self._engine(timeout=5.0)
        fo, length = frags[0]
        engine(self._packet(bufid, 1, HandshakeType.server_hello, len(body),
                            1, fo, length, body[fo:fo + length], 0.0))
        self.assertIsNone(engine.last)

        # A fragment under an UNRELATED buffer, 10 seconds later, is this
        # capture's only evidence that time has passed -- it must still
        # abandon the first buffer under its own 5-second timeout.
        fo2, length2 = frags[0]
        engine(self._packet(other_bufid, 2, HandshakeType.server_hello, len(body),
                            1, fo2, length2, body[fo2:fo2 + length2], 10.0))

        stale = [d for d in engine.datagram if d.id.src == '17.0.0.1']
        self.assertEqual(len(stale), 1)
        self.assertEqual(stale[0].completed.name, 'TIMEOUT')

    def test_idle_deadline_extends_on_each_fragment(self) -> None:
        """Fragments arriving with delays between them extend the reassembly
        deadline (idle timeout): three fragments of one message at default
        engine timeout (120 seconds) arrive at t=0, t=100, t=200 and complete
        successfully, whereas without idle deadline the buffer would expire
        after the first fragment (t=0 + 120 = t=120, and fragments at t=100
        and t=200 arrive after that)."""
        from pcapkit.const.tls.handshake_type import HandshakeType

        body = _client_hello_body(cookie=b'\xaa\xbb\xcc\xdd')
        third = len(body) // 3
        frags = _split(body, (third, 2 * third))
        bufid = ('19.0.0.1', 1, '19.0.0.2', 5684, 0)

        # Default timeout is 120 seconds. Fragments at t=0, t=100, t=200:
        # - t=0: buffer created, deadline = t=0 + timeout (if not idle deadline)
        # - t=100: with idle deadline, deadline = max(0, 100) + 120 = t=220
        # - t=200: with idle deadline, deadline = max(100, 200) + 120 = t=320
        # Message arrives complete on the final fragment.
        engine = self._engine()
        for i, (fo, length) in enumerate(frags):
            payload = body[fo:fo + length]
            timestamp = float(i * 100)
            engine(self._packet(bufid, i + 1, HandshakeType.client_hello, len(body),
                                0, fo, length, payload, timestamp))
            if engine.last is not None:
                # Message completed on this fragment.
                break

        # Should have completed (all three fragments arrived within the
        # idle deadline).
        self.assertIsNotNone(engine.last)
        self.assertTrue(engine.last.completed)
        self.assertEqual(engine.last.body, body)


class TestDTLSReadReassemblyWiring(unittest.TestCase):
    """:meth:`DTLS.read`'s ``reassembly``/``flow`` arguments, exercised
    through the real protocol class rather than the engine alone."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_fragmented_client_hello_decodes_once_reassembled(self) -> None:
        from pcapkit.foundation.reassembly.dtls import DTLS as DTLSReassembly
        from pcapkit.protocols.application.dtls import DTLS

        body = _client_hello_body(cookie=b'\xab\xcd\xef\x01')
        half = len(body) // 2
        wire1 = _dtls_record(22, _dtls_handshake(1, body[:half], message_seq=5, fragment_offset=0,
                            fragment_length=half, total_length=len(body)), seq=2)
        wire2 = _dtls_record(22, _dtls_handshake(1, body[half:], message_seq=5, fragment_offset=half,
                            fragment_length=len(body) - half, total_length=len(body)), seq=3)

        engine = DTLSReassembly()
        flow = ('10.0.0.1', 1234, '10.0.0.2', 5684)

        parsed1 = DTLS(wire1, len(wire1), reassembly=engine, flow=flow, frame_num=1, frame_timestamp=0.0)
        msg1 = parsed1.info.content[0]
        self.assertTrue(msg1.is_fragmented)
        self.assertIsInstance(msg1.body, bytes)

        parsed2 = DTLS(wire2, len(wire2), reassembly=engine, flow=flow, frame_num=2, frame_timestamp=0.1)
        msg2 = parsed2.info.content[0]
        self.assertTrue(msg2.is_fragmented)
        self.assertNotIsInstance(msg2.body, bytes)
        self.assertEqual(msg2.body.cookie, b'\xab\xcd\xef\x01')

    def test_fragmented_server_hello_decodes_once_reassembled(self) -> None:
        from pcapkit.foundation.reassembly.dtls import DTLS as DTLSReassembly
        from pcapkit.protocols.application.dtls import DTLS

        body = _server_hello_body(extensions=b'\x00\x0d\x00\x02\xab\xcd')
        third = len(body) // 3
        frags = _split(body, (third, 2 * third))
        bufid_flow = ('1.1.1.1', 100, '2.2.2.2', 5684)

        engine = DTLSReassembly()
        decoded = None
        # deliver out of order: [2, 0, 1]
        for num, idx in enumerate((2, 0, 1), 1):
            fo, length = frags[idx]
            wire = _dtls_record(22, _dtls_handshake(2, body[fo:fo + length], message_seq=9,
                               fragment_offset=fo, fragment_length=length, total_length=len(body)),
                               seq=10 + num)
            parsed = DTLS(wire, len(wire), reassembly=engine, flow=bufid_flow,
                          frame_num=num, frame_timestamp=float(num))
            msg = parsed.info.content[0]
            if not isinstance(msg.body, bytes):
                decoded = msg.body
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.random, bytes(range(32, 64)))

    def test_reassembly_without_flow_raises_rather_than_corrupting(self) -> None:
        """Omitting ``flow`` while passing ``reassembly`` must not silently
        default onto a shared buffer key -- two interleaved associations
        would otherwise corrupt each other's reassembly."""
        from pcapkit.foundation.reassembly.dtls import DTLS as DTLSReassembly
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.utilities.exceptions import ProtocolError

        body = _client_hello_body()
        half = len(body) // 2
        wire = _dtls_record(22, _dtls_handshake(1, body[:half], message_seq=5, fragment_offset=0,
                           fragment_length=half, total_length=len(body)), seq=2)

        engine = DTLSReassembly()
        with self.assertRaises(ProtocolError):
            DTLS(wire, len(wire), reassembly=engine, frame_num=1, frame_timestamp=0.0)

    def test_encrypted_handshake_record_skips_reassembly_unharmed(self) -> None:
        """A ``handshake``-typed record at epoch >= 1 is ciphertext --
        :meth:`SSL._read_tls_content <pcapkit.protocols.application.ssl.SSL._read_tls_content>`
        returns it as raw :obj:`bytes` rather than parsed messages. Every
        real DTLS handshake ends with exactly such a record (the encrypted
        ``Finished``), so a ``reassembly`` engine must not choke on it."""
        from pcapkit.foundation.reassembly.dtls import DTLS as DTLSReassembly
        from pcapkit.protocols.application.dtls import DTLS

        ciphertext = b'\xa3\x5d\x12\xee' * 12
        wire = _dtls_record(22, ciphertext, epoch=1, seq=7)

        engine = DTLSReassembly()
        flow = ('10.0.0.1', 1234, '10.0.0.2', 5684)

        parsed = DTLS(wire, len(wire), reassembly=engine, flow=flow,
                     frame_num=1, frame_timestamp=0.0)
        self.assertEqual(parsed.info.content, ciphertext)

    def test_completing_record_rebuilds_byte_exact(self) -> None:
        """The record that completes a reassembled message must still
        round-trip exactly through ``from_data``/``make``:
        the fragment header has to keep describing *this* record's own byte
        range even though ``body`` holds the full decoded message, or
        re-encoding it drifts out of sync with the bytes written after it."""
        from pcapkit.foundation.reassembly.dtls import DTLS as DTLSReassembly
        from pcapkit.protocols.application.dtls import DTLS

        body = _client_hello_body(cookie=b'\xab\xcd\xef\x01')
        half = len(body) // 2
        wire1 = _dtls_record(22, _dtls_handshake(1, body[:half], message_seq=5, fragment_offset=0,
                            fragment_length=half, total_length=len(body)), seq=2)
        wire2 = _dtls_record(22, _dtls_handshake(1, body[half:], message_seq=5, fragment_offset=half,
                            fragment_length=len(body) - half, total_length=len(body)), seq=3)

        engine = DTLSReassembly()
        flow = ('10.0.0.1', 1234, '10.0.0.2', 5684)

        DTLS(wire1, len(wire1), reassembly=engine, flow=flow, frame_num=1, frame_timestamp=0.0)
        parsed2 = DTLS(wire2, len(wire2), reassembly=engine, flow=flow, frame_num=2, frame_timestamp=0.1)

        msg2 = parsed2.info.content[0]
        # the completing fragment: decoded in place, not raw bytes.
        self.assertNotIsInstance(msg2.body, bytes)

        rebuilt = bytes(DTLS.from_data(parsed2.info))
        self.assertEqual(rebuilt, wire2)

    def test_overrunning_completing_fragment_keeps_raw_bytes_and_round_trips(self) -> None:
        """A fragment whose ``fragment_offset + fragment_length`` overruns the
        declared ``length`` (5 + 10 > 10) completes its message, but its record
        must stay as it arrived. Replacing its body with the clipped message
        corrupts the round trip, and
        :meth:`SSL._make_tls_handshake_messages
        <pcapkit.protocols.application.ssl.SSL._make_tls_handshake_messages>`'s
        exactness check cannot be relied on to catch it."""
        from pcapkit.foundation.reassembly.dtls import DTLS as DTLSReassembly
        from pcapkit.protocols.application.dtls import DTLS

        length = 10
        first = b'A' * 5
        second = b'B' * 10  # this record's own 10 octets, but offset 5 + 10 > length 10
        wire1 = _dtls_handshake(11, first, message_seq=3, fragment_offset=0,
                                fragment_length=5, total_length=length)
        wire2 = _dtls_handshake(11, second, message_seq=3, fragment_offset=5,
                                fragment_length=10, total_length=length)
        record1 = _dtls_record(22, wire1, seq=2)
        record2 = _dtls_record(22, wire2, seq=3)

        engine = DTLSReassembly()
        flow = ('19.0.0.1', 1, '19.0.0.2', 5684)

        DTLS(record1, len(record1), reassembly=engine, flow=flow, frame_num=1, frame_timestamp=0.0)
        parsed2 = DTLS(record2, len(record2), reassembly=engine, flow=flow, frame_num=2,
                      frame_timestamp=0.1)

        # the engine itself did complete the message (clipping the overrun)
        # but this record is left exactly as it arrived.
        self.assertIsNotNone(engine.last)
        self.assertTrue(engine.last.completed)

        msg2 = parsed2.info.content[0]
        self.assertIsInstance(msg2.body, bytes)
        self.assertEqual(msg2.body, second)
        self.assertEqual(msg2.fragment_offset, 5)
        self.assertEqual(msg2.fragment_length, 10)

        rebuilt = bytes(DTLS.from_data(parsed2.info))
        self.assertEqual(rebuilt, record2)

    def test_undecodable_reassembled_body_falls_back_to_raw_bytes(self) -> None:
        """A completed message whose reassembled bytes do not decode as a
        valid message of its ``msg_type`` keeps those raw bytes instead of
        raising (dtls.py's ``except ProtocolError`` fallback)."""
        from pcapkit.foundation.reassembly.dtls import DTLS as DTLSReassembly
        from pcapkit.protocols.application.dtls import DTLS

        # far too short to be a genuine ClientHello (needs >= 34 octets
        # before even the session_id length is reached), but a perfectly
        # in-bounds pair of fragments for the reassembler itself.
        body = b'\x01\x02\x03\x04\x05'
        wire1 = _dtls_record(22, _dtls_handshake(1, body[:3], message_seq=1, fragment_offset=0,
                            fragment_length=3, total_length=len(body)), seq=2)
        wire2 = _dtls_record(22, _dtls_handshake(1, body[3:], message_seq=1, fragment_offset=3,
                            fragment_length=len(body) - 3, total_length=len(body)), seq=3)

        engine = DTLSReassembly()
        flow = ('20.0.0.1', 1, '20.0.0.2', 5684)

        DTLS(wire1, len(wire1), reassembly=engine, flow=flow, frame_num=1, frame_timestamp=0.0)
        parsed2 = DTLS(wire2, len(wire2), reassembly=engine, flow=flow, frame_num=2, frame_timestamp=0.1)

        self.assertIsNotNone(engine.last)
        self.assertTrue(engine.last.completed)

        msg2 = parsed2.info.content[0]
        # decode was attempted (the fragment is complete and in-bounds) and
        # failed -- raw reassembled bytes kept, not raised.
        self.assertIsInstance(msg2.body, bytes)
        self.assertEqual(msg2.body, body)

    def test_flow_required_check_fires_for_non_handshake_records_too(self) -> None:
        """``flow`` is required the moment ``reassembly`` is given,
        regardless of this record's content type, not only for a
        cleartext ``handshake`` record."""
        from pcapkit.foundation.reassembly.dtls import DTLS as DTLSReassembly
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.utilities.exceptions import ProtocolError

        engine = DTLSReassembly()

        # an ``alert`` record -- never reaches ``_reassemble_dtls_handshake``
        # at all, so a handshake-only check would never see it.
        alert_wire = _dtls_record(21, bytes([1, 0]), seq=2)
        with self.assertRaises(ProtocolError):
            DTLS(alert_wire, len(alert_wire), reassembly=engine, frame_num=1, frame_timestamp=0.0)

        # an encrypted (epoch >= 1) ``handshake`` record -- ``content`` is
        # raw ciphertext :obj:`bytes` here, not a :obj:`tuple`, so a check
        # keyed on the tuple would skip it too.
        encrypted_wire = _dtls_record(22, b'\xaa' * 16, epoch=1, seq=3)
        with self.assertRaises(ProtocolError):
            DTLS(encrypted_wire, len(encrypted_wire), reassembly=engine, frame_num=2,
                frame_timestamp=0.0)

    def test_without_reassembly_argument_body_stays_raw(self) -> None:
        """With no engine, the body stays raw whatever the fragment."""
        from pcapkit.protocols.application.dtls import DTLS

        body = _client_hello_body()
        half = len(body) // 2
        wire = _dtls_record(22, _dtls_handshake(1, body[half:], message_seq=5, fragment_offset=half,
                           fragment_length=len(body) - half, total_length=len(body)), seq=2)

        parsed = DTLS(wire, len(wire))
        msg = parsed.info.content[0]
        self.assertTrue(msg.is_fragmented)
        self.assertIsInstance(msg.body, bytes)

    def test_incomplete_reassembly_through_read_stays_raw_and_does_not_crash(self) -> None:
        from pcapkit.foundation.reassembly.dtls import DTLS as DTLSReassembly
        from pcapkit.protocols.application.dtls import DTLS

        body = _server_hello_body()
        third = len(body) // 3
        frags = _split(body, (third, 2 * third))
        flow = ('3.3.3.3', 200, '4.4.4.4', 5684)

        engine = DTLSReassembly()
        for num, idx in enumerate((0, 2), 1):  # fragment 1 of 3 never arrives
            fo, length = frags[idx]
            wire = _dtls_record(22, _dtls_handshake(2, body[fo:fo + length], message_seq=1,
                               fragment_offset=fo, fragment_length=length, total_length=len(body)),
                               seq=20 + num)
            parsed = DTLS(wire, len(wire), reassembly=engine, flow=flow,
                         frame_num=num, frame_timestamp=float(num))
            msg = parsed.info.content[0]
            self.assertTrue(msg.is_fragmented)
            self.assertIsInstance(msg.body, bytes)

        datagram, = engine.fetch()
        self.assertEqual(datagram.completed.name, 'PARTIAL')


if __name__ == '__main__':
    unittest.main()
