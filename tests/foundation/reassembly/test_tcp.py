from __future__ import annotations

import importlib.util
from ipaddress import ip_address
import sys
import unittest

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Initial sequence number for the coordinate-system tests below. A real
#: connection draws one at random from the whole 32-bit space; the defect those
#: tests cover is invisible at zero, where an absolute sequence number and an
#: offset into a payload buffer happen to be the same number, so none of them
#: uses zero except the one that checks the answer does not depend on the choice.
ISN = 0xC0DE1234


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TCPReassemblyTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _bufid(self):
        return (ip_address('192.0.2.1'), 12345, ip_address('198.51.100.2'), 443)

    def _packet(self, *, num: int, dsn: int, ack: int = 500, payload: bytes = b'',
                syn: bool = False, fin: bool = False, rst: bool = False,
                first: int | None = None, last: int | None = None,
                header: bytes = b'tcp-header', timestamp: float = 1000.0):
        """Build a reassembly packet the way the engine toolkits build one.

        ``first`` defaults to ``dsn`` and ``last`` to ``dsn + len(payload) - 1``
        -- absolute sequence numbers, with ``last`` inclusive -- because that is
        what every :mod:`pcapkit.toolkit` module now passes. Tests that exercise
        the :rfc:`815` interval arithmetic on its own still override both.

        """
        from pcapkit.foundation.reassembly.data.tcp import Packet

        if first is None:
            first = dsn
        if last is None:
            last = first + len(payload) - 1
        return Packet(self._bufid(), dsn, ack, num, syn, fin, rst, len(payload),
                      first, last, header, bytearray(payload), timestamp)

    def test_complete_stream_submits_on_fin_and_analyzes_payload(self) -> None:
        from pcapkit.foundation.reassembly.tcp import TCP

        class Analyzer:
            calls: list[tuple[tuple[int, int], bytes]] = []

            @classmethod
            def analyze(cls, ports: tuple[int, int], payload: bytes) -> dict[str, object]:
                cls.calls.append((ports, payload))
                return {'ports': ports, 'payload': payload}

        class TestTCP(TCP):
            __protocol_type__ = Analyzer

        callback_calls = []
        TestTCP.register(callback_calls.append)

        reasm = TestTCP()
        # A SYN spends a sequence number of its own, so the payload it carries
        # starts at 101 and ends at 105; the segment that continues the stream
        # therefore opens at 106, not at 105.
        reasm(self._packet(num=1, dsn=100, payload=b'hello', syn=True))
        reasm(self._packet(num=2, dsn=106, payload=b' world', fin=True))

        datagram, = reasm.datagram
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.index, (1, 2))
        self.assertEqual(datagram.header, b'tcp-header')
        self.assertEqual(datagram.payload, b'hello world')
        self.assertEqual(datagram.packet, {'ports': (12345, 443), 'payload': b'hello world'})
        self.assertEqual(Analyzer.calls, [((12345, 443), b'hello world')])
        self.assertEqual(len(callback_calls), 1)

    def test_syn_resets_existing_session_and_flushes_previous_payload(self) -> None:
        from pcapkit.foundation.reassembly.tcp import TCP

        class Analyzer:
            @classmethod
            def analyze(cls, ports: tuple[int, int], payload: bytes) -> bytes:
                return payload

        class TestTCP(TCP):
            __protocol_type__ = Analyzer

        reasm = TestTCP()
        reasm(self._packet(num=1, dsn=10, payload=b'old', syn=True, first=0, last=2))
        reasm(self._packet(num=2, dsn=100, payload=b'new', syn=True, first=0, last=2,
                           header=b'new-header'))

        flushed, = reasm._dtgram
        self.assertEqual(flushed.payload, b'old')
        self.assertEqual(reasm._buffer[self._bufid()].hdr, b'new-header')

    def test_fragment_merging_covers_gaps_overlaps_new_acks_and_holes(self) -> None:
        from pcapkit.foundation.reassembly.data.tcp import Buffer, Fragment, HoleDescriptor
        from pcapkit.foundation.reassembly.tcp import TCP

        class Analyzer:
            @classmethod
            def analyze(cls, ports: tuple[int, int], payload: bytes) -> bytes:
                return payload

        class TestTCP(TCP):
            __protocol_type__ = Analyzer

        reasm = TestTCP()
        bufid = self._bufid()
        reasm._buffer[bufid] = Buffer(
            [HoleDescriptor(0, 4), HoleDescriptor(20, 30), HoleDescriptor(40, sys.maxsize)],
            b'',
            {
                500: Fragment([1], 10, 10, bytearray(b'0123456789'), [], []),
            },
            1000.0,
        )

        reasm(self._packet(num=2, dsn=25, payload=b'after-gap', first=10, last=18))
        self.assertEqual(reasm._buffer[bufid].ack[500].raw, bytearray(b'0123456789\x00\x00\x00\x00\x00after-gap'))

        # ``OVERLAP`` (abs 15-21) disagrees with the already-received ``56789``
        # (abs 15-19) -- kept, per first-write-wins, and recorded as a
        # conflict -- but abs 20-21 is still a hole per the seeded HDL, not
        # already-received data, so the arriving segment's bytes there
        # (``AP``) are an ordinary gap fill, not a conflict.
        reasm(self._packet(num=3, dsn=15, payload=b'OVERLAP', first=15, last=21))
        self.assertEqual(reasm._buffer[bufid].ack[500].raw,
                         bytearray(b'0123456789AP\x00\x00\x00after-gap'))
        self.assertEqual(reasm._buffer[bufid].ack[500].conflict, [(15, 19)])

        # The reach-back branch: abs 10-12 (``012``) is already-received data
        # and disagrees with the arriving ``klm`` -- kept, and a second
        # conflict recorded -- while abs 0-9 is genuinely new (before the
        # existing ISN) and merges in untouched.
        reasm(self._packet(num=4, dsn=0, payload=b'abcdefghijklm', first=22, last=24))
        self.assertEqual(reasm._buffer[bufid].ack[500].isn, 0)
        self.assertEqual(reasm._buffer[bufid].ack[500].raw,
                         bytearray(b'abcdefghij0123456789AP\x00\x00\x00after-gap'))
        self.assertEqual(reasm._buffer[bufid].ack[500].conflict, [(15, 19), (10, 12)])
        self.assertEqual([(hole.first, hole.last) for hole in reasm._buffer[bufid].hdl],
                         [(0, 4), (25, 30), (40, sys.maxsize)])

        reasm(self._packet(num=5, dsn=0, ack=501, payload=b'alt', first=50, last=52))
        self.assertEqual(reasm._buffer[bufid].ack[501].raw, bytearray(b'alt'))

        before_gap = TestTCP()
        before_gap._buffer[bufid] = Buffer(
            [HoleDescriptor(50, sys.maxsize)],
            b'',
            {500: Fragment([1], 10, 5, bytearray(b'world'), [], [])},
            1000.0,
        )
        before_gap(self._packet(num=2, dsn=0, payload=b'hello', first=40, last=44))
        self.assertEqual(before_gap._buffer[bufid].ack[500].raw,
                         bytearray(b'hello\x00\x00\x00\x00\x00world'))
        self.assertEqual(before_gap._buffer[bufid].ack[500].conflict, [])

    def test_submit_incomplete_strict_complete_strict_false_and_empty_buffers(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.data.tcp import Buffer, Fragment, HoleDescriptor
        from pcapkit.foundation.reassembly.tcp import TCP

        class Analyzer:
            calls: list[tuple[tuple[int, int], bytes]] = []

            @classmethod
            def analyze(cls, ports: tuple[int, int], payload: bytes) -> bytes:
                cls.calls.append((ports, payload))
                return payload

        class TestTCP(TCP):
            __protocol_type__ = Analyzer

        bufid = self._bufid()
        strict = TestTCP()
        incomplete = strict.submit(
            Buffer(
                [HoleDescriptor(2, 3), HoleDescriptor(7, 8), HoleDescriptor(99, 100)],
                b'tcp-header',
                {500: Fragment([1, 2], 0, 10, bytearray(b'abcdefghij'), [], [])},
                1000.0,
            ),
            bufid=bufid,
        )
        datagram, = incomplete
        self.assertFalse(datagram.completed)
        # PARTIAL rather than TIMEOUT: this buffer was handed to ``submit`` directly,
        # not abandoned by ``expire``
        self.assertIs(datagram.completed, Completion.PARTIAL)
        self.assertEqual(datagram.payload, (bytearray(b'ab'), bytearray(b'efg'), bytearray(b'j')))
        self.assertIsNone(datagram.packet)
        self.assertEqual(datagram.conflict, ())

        mixed = strict.submit(
            Buffer(
                [HoleDescriptor(0, 0), HoleDescriptor(4, 5), HoleDescriptor(7, 7)],
                b'tcp-header',
                {
                    500: Fragment([], 0, 0, bytearray(), [], []),
                    501: Fragment([9], 0, 9, bytearray(b'abcdefghi'), [], [(2, 3)]),
                },
                1000.0,
            ),
            bufid=bufid,
        )
        self.assertEqual(len(mixed), 1)
        self.assertEqual(mixed[0].payload, (bytearray(b'bcd'), bytearray(b'g'), b'i'))
        # ``conflict`` passes through from the fragment untouched -- ``submit``
        # only reads it, the merge logic in ``reassembly`` is what populates it
        self.assertEqual(mixed[0].conflict, ((2, 3),))

        # ``strict=False`` reports the payload buffer as one contiguous blob with
        # its holes zero-filled -- which is what
        # :func:`~pcapkit.interface.misc.follow_tcp_stream` reconstructs a stream
        # from -- rather than the runs that arrived. What it must *not* do is call
        # that blob complete: the holes are still holes, so ``completed`` reads
        # PARTIAL even though the payload is whole-looking.
        loose = TestTCP(strict=False)
        completed = loose.submit(
            Buffer(
                [HoleDescriptor(2, 3), HoleDescriptor(7, 8), HoleDescriptor(99, 100)],
                b'tcp-header',
                {500: Fragment([3], 0, 3, bytearray(b'abc'), [], [])},
                1000.0,
            ),
            bufid=bufid,
        )
        self.assertFalse(completed[0].completed)
        self.assertIs(completed[0].completed, Completion.PARTIAL)
        self.assertEqual(completed[0].payload, bytearray(b'abc'))
        self.assertEqual(completed[0].packet, b'abc')
        self.assertEqual(completed[0].conflict, ())
        self.assertEqual(Analyzer.calls[-1], ((12345, 443), b'abc'))

        self.assertEqual(loose.submit(Buffer([], b'', {500: Fragment([], 0, 0, bytearray(), [], [])},
                                             1000.0),
                                      bufid=bufid), [])


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TCPReassemblyCoordinateTests(unittest.TestCase):
    """Regression tests for GitHub issue #349.

    TCP reassembly keeps its :rfc:`815` hole descriptor list in absolute
    sequence numbers, and each payload buffer indexed from its own initial
    sequence number. Mixing the two produced three separate wrong answers, none
    of which the rest of the suite could see, because they all need an initial
    sequence number that is not zero:

    * a stream with a gap in it yielded **no datagram at all**, silently, since
      every hole bound landed far past the end of a buffer a few kilobytes long;
    * a stream captured without its handshake yielded only its *first* fragment,
      since the completeness test counted hole descriptors instead of asking
      whether any hole fell inside the data;
    * every extracted fragment came out one octet too long, since a hole bound
      was computed as the sequence number *after* the segment while the
      descriptor list treats its bounds as inclusive.

    A fourth, closely related error surfaced while fixing them: the sequence
    number a SYN spends became a NUL octet at the head of the payload, so a
    complete datagram did not compare equal to the octets that were sent.

    Every stream here is driven through :class:`~pcapkit.foundation.reassembly.tcp.TCP`
    with segment descriptors built exactly as the :mod:`pcapkit.toolkit` modules
    build them -- ``first`` the segment's own sequence number and ``last`` the
    sequence number of its final payload octet -- so the tests pin the contract
    between the toolkits and the reassembler, not just the reassembler.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _bufid(self):
        return (ip_address('192.0.2.1'), 12345, ip_address('198.51.100.2'), 443)

    def _reassembly(self, **kwargs):
        """A reassembly object whose payload analyser is a stub.

        The real one picks an application protocol from the port numbers, which
        would drag HTTP parsing into tests about sequence arithmetic.

        """
        from pcapkit.foundation.reassembly.tcp import TCP

        class Analyzer:
            @classmethod
            def analyze(cls, ports: tuple[int, int], payload: bytes) -> bytes:
                return payload

        class TestTCP(TCP):
            __protocol_type__ = Analyzer

        return TestTCP(**kwargs)

    def _segment(self, *, num: int, seq: int, payload: bytes = b'', ack: int = 1000,
                 syn: bool = False, fin: bool = False, rst: bool = False,
                 timestamp: float = 1000.0):
        """One segment, described the way every :mod:`pcapkit.toolkit` describes it."""
        from pcapkit.foundation.reassembly.data.tcp import Packet

        return Packet(self._bufid(), seq, ack, num, syn, fin, rst, len(payload),
                      seq, seq + len(payload) - 1, b'tcp-header', bytearray(payload),
                      timestamp)

    def _stream(self, *, segments, isn: int = ISN, syn: bool = True,
                syn_ack: int = 0, teardown: str | None = 'fin'):
        """Build one direction of a connection.

        Args:
            segments: ``(offset, payload)`` pairs, the offset counted from the
                first octet of application data. Repeat a pair to retransmit it,
                and reorder the list to deliver out of order.
            isn: Initial sequence number, i.e. the sequence number of the SYN.
            syn: Whether the capture caught the handshake.
            syn_ack: Acknowledgement number on the SYN. A real SYN carries 0 and
                so lands in a payload buffer of its own; passing the data
                segments' number instead makes the SYN share their buffer, which
                is what exposes the octet a SYN spends.
            teardown: ``'fin'``, ``'rst'`` or :data:`None` for a stream left
                open, which only :meth:`~pcapkit.foundation.reassembly.reassembly.Reassembly.fetch`
                will submit.

        Returns:
            The segments, in the order given, ready to be fed to the reassembler.

        """
        base = isn + 1 if syn else isn     # a SYN spends a sequence number
        packets = []
        if syn:
            packets.append(self._segment(num=len(packets) + 1, seq=isn, syn=True,
                                         ack=syn_ack))
        for (offset, payload) in segments:
            packets.append(self._segment(num=len(packets) + 1, seq=base + offset,
                                         payload=payload))
        if teardown is not None:
            end = base + max(offset + len(payload) for (offset, payload) in segments)
            packets.append(self._segment(num=len(packets) + 1, seq=end,
                                         fin=teardown == 'fin', rst=teardown == 'rst'))
        return packets

    def _run(self, packets, **kwargs):
        reasm = self._reassembly(**kwargs)
        for packet in packets:
            reasm(packet)
        return reasm

    ##########################################################################
    # An incomplete datagram has to come back, not vanish.
    ##########################################################################

    def test_incomplete_datagram_survives_a_realistic_initial_sequence_number(self) -> None:
        """A permanently missing segment gives ``completed=False``, not silence.

        Two of the five segments never arrive. Before the fix this produced no
        datagram whatsoever: the hole bounds were around 3.2 billion while the
        payload buffer was 50 octets long, so every slice came back empty and
        ``submit`` dropped the datagram at its ``if data:`` guard without a
        word.

        """
        # 10..19 and 30..39 are lost for good
        packets = self._stream(segments=[(0, b'A' * 10), (20, b'C' * 10), (40, b'E' * 10)])
        reasm = self._run(packets)

        datagram, = reasm.datagram
        self.assertFalse(datagram.completed)
        self.assertIsNone(datagram.packet)
        self.assertEqual(datagram.payload, (b'A' * 10, b'C' * 10, b'E' * 10))
        self.assertEqual([len(fragment) for fragment in datagram.payload], [10, 10, 10])
        self.assertEqual(datagram.index, (2, 3, 4, 5))
        self.assertEqual(datagram.header, b'tcp-header')

    def test_the_answer_does_not_depend_on_the_initial_sequence_number(self) -> None:
        """The same stream reassembles the same way whatever ISN it uses.

        This is the property the defect broke: at zero the two coordinate
        systems coincide and the fragments came out one octet long each too
        long; anywhere else the datagram disappeared entirely.

        """
        from pcapkit.foundation.reassembly.data.data import Completion

        segments = [(0, b'A' * 10), (20, b'C' * 10), (40, b'E' * 10)]
        expected = (Completion.PARTIAL, (b'A' * 10, b'C' * 10, b'E' * 10))

        for isn in (0, 1, 0x1000, ISN, 0xFFFF0000):
            with self.subTest(isn=isn):
                reasm = self._run(self._stream(segments=segments, isn=isn))
                datagram, = reasm.datagram
                self.assertEqual((datagram.completed, datagram.payload), expected)

    def test_a_capture_without_the_handshake_reports_every_fragment(self) -> None:
        """A stream picked up mid-flight still reports all of its fragments.

        Before the fix this returned a *partial* answer rather than nothing --
        one fragment out of three -- because the completeness test counted hole
        descriptors (``len(HDL) > 2``) rather than asking whether a hole fell
        inside the received data. Without a SYN the list is one entry shorter,
        so a two-gap stream slipped under the threshold.

        """
        packets = self._stream(syn=False,
                               segments=[(0, b'A' * 10), (20, b'C' * 10), (40, b'E' * 10)])
        reasm = self._run(packets)

        datagram, = reasm.datagram
        self.assertFalse(datagram.completed)
        self.assertEqual(datagram.payload, (b'A' * 10, b'C' * 10, b'E' * 10))

    def test_a_single_gap_is_enough_to_make_a_datagram_incomplete(self) -> None:
        """One hole, not three, and the fragments either side of it come back."""
        packets = self._stream(segments=[(0, b'A' * 10), (20, b'C' * 10)])
        reasm = self._run(packets)

        datagram, = reasm.datagram
        self.assertFalse(datagram.completed)
        self.assertIsNone(datagram.packet)
        self.assertEqual(datagram.payload, (b'A' * 10, b'C' * 10))

    ##########################################################################
    # A complete datagram has to be the octets that were sent.
    ##########################################################################

    def test_complete_datagram_reassembles_byte_exactly(self) -> None:
        """The reassembled payload equals the concatenation of what was sent."""
        segments = [(0, b'A' * 10), (10, b'B' * 1448), (1458, b'C' * 7)]
        reasm = self._run(self._stream(segments=segments))

        datagram, = reasm.datagram
        self.assertTrue(datagram.completed)
        self.assertIsInstance(datagram.payload, bytes)
        self.assertEqual(datagram.payload, b''.join(payload for (_, payload) in segments))
        self.assertEqual(len(datagram.payload), 1465)
        self.assertEqual(datagram.packet, datagram.payload)

    def test_a_syn_sharing_a_payload_buffer_spends_no_payload_octet(self) -> None:
        """The sequence number a SYN occupies must not become a NUL octet.

        A SYN carries no payload but does consume a sequence number (:rfc:`793`),
        so the first octet of application data sits at ``isn + 1``. A real SYN
        acknowledges nothing and therefore gets a payload buffer of its own,
        which hid this; give it the data segments' acknowledgement number -- as
        the reproduction in the issue does, and as happens whenever the peer has
        already sent something -- and seeding that buffer at ``isn`` instead of
        ``isn + 1`` prepends a zero octet to the datagram.

        """
        sent = b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
        reasm = self._run(self._stream(syn_ack=1000, segments=[(0, sent)]))

        datagram, = reasm.datagram
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.payload, sent)
        self.assertNotEqual(datagram.payload[:1], b'\x00')

    ##########################################################################
    # Out-of-order delivery and retransmission.
    ##########################################################################

    def test_out_of_order_and_retransmitted_delivery_reassembles_byte_exactly(self) -> None:
        """Four segments delivered 3, 1, 3, 4, 2 still give the sent octets."""
        first, second, third, fourth = ((0, b'A' * 10), (10, b'B' * 10),
                                        (20, b'C' * 10), (30, b'D' * 10))
        packets = self._stream(segments=[third, first, third, fourth, second])
        reasm = self._run(packets)

        datagram, = reasm.datagram
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.payload, b'A' * 10 + b'B' * 10 + b'C' * 10 + b'D' * 10)

    def test_a_hole_closes_when_the_lost_segment_is_retransmitted(self) -> None:
        """A gap opened by a late segment is closed by the retransmission."""
        packets = self._stream(segments=[(0, b'A' * 10), (20, b'C' * 10), (10, b'B' * 10)])
        reasm = self._run(packets)

        datagram, = reasm.datagram
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.payload, b'A' * 10 + b'B' * 10 + b'C' * 10)

    def test_out_of_order_delivery_around_a_gap_that_is_never_filled(self) -> None:
        """Out of order, retransmitted, *and* one segment lost for good.

        The two fragments that survive are the contiguous runs either side of
        the hole, so the third and fourth segments come back as one 20-octet
        fragment rather than as two.

        """
        packets = self._stream(segments=[(20, b'C' * 10), (0, b'A' * 10),
                                         (20, b'C' * 10), (30, b'D' * 10)])
        reasm = self._run(packets)

        datagram, = reasm.datagram
        self.assertFalse(datagram.completed)
        self.assertEqual(datagram.payload, (b'A' * 10, b'C' * 10 + b'D' * 10))
        self.assertEqual([len(fragment) for fragment in datagram.payload], [10, 20])

    ##########################################################################
    # The two coordinate systems, inspected directly.
    ##########################################################################

    def test_hole_descriptor_bounds_are_absolute_sequence_numbers(self) -> None:
        """The hole list is in sequence space; the payload buffer is not.

        Asserted on the live buffer rather than through a datagram, because this
        is the invariant the defect broke: the list was seeded with
        ``first=info.len`` -- a payload length -- and then extended with absolute
        sequence numbers, so one descriptor held one of each.

        """
        packets = self._stream(segments=[(0, b'A' * 10), (20, b'C' * 10)], teardown=None)
        reasm = self._run(packets)

        buffer = reasm._buffer[self._bufid()]
        self.assertEqual([(hole.first, hole.last) for hole in buffer.hdl],
                         [(ISN + 11, ISN + 20), (ISN + 31, sys.maxsize)])

        # the SYN acknowledges nothing, so it gets a payload buffer of its own
        # and the data lands in the one keyed by the data segments' ACK
        fragment = buffer.ack[1000]
        self.assertEqual(fragment.isn, ISN + 1)
        self.assertEqual(len(fragment.raw), 30)

        # raw[n] holds the octet whose sequence number is isn + n, which is the
        # conversion submit() applies -- and the hole's own octets are the ones
        # the buffer never received
        hole = buffer.hdl[0]
        self.assertEqual(bytes(fragment.raw[hole.first - fragment.isn:
                                            hole.last - fragment.isn + 1]),
                         bytes(10))

    def test_payload_free_segments_leave_the_hole_list_alone(self) -> None:
        """A bare acknowledgement fills no hole, so it must not split one.

        Its ``last`` is one below its ``first``, and running that through the
        :rfc:`815` algorithm splits whichever hole contains it into two adjacent
        holes covering the very same octets -- unbounded list growth on a
        long-lived connection, for no change in what is missing.

        """
        base = ISN + 1
        reasm = self._run([
            self._segment(num=1, seq=ISN, syn=True, ack=0),
            self._segment(num=2, seq=base, payload=b'A' * 10),
            self._segment(num=3, seq=base + 20, payload=b'C' * 10),
        ])

        before = [(hole.first, hole.last) for hole in reasm._buffer[self._bufid()].hdl]
        self.assertEqual(before, [(base + 10, base + 19), (base + 30, sys.maxsize)])

        # one past the data, one *inside* the hole, and one repeated
        for (num, seq) in ((4, base + 30), (5, base + 15), (6, base + 30)):
            reasm(self._segment(num=num, seq=seq))

        after = [(hole.first, hole.last) for hole in reasm._buffer[self._bufid()].hdl]
        self.assertEqual(after, before)
        self.assertEqual(len(reasm._buffer[self._bufid()].ack[1000].raw), 30)

    # The end-to-end case on a generated capture lives in
    # tests/foundation/reassembly/test_tcp_runtime.py, since the unit-test
    # workflow runs without the generated fixtures.


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TCPReassemblyConflictTests(unittest.TestCase):
    """Regression tests for GitHub issue #443.

    Two segments claiming the same sequence range but carrying *different*
    bytes used to resolve last-write-wins, silently, with ``completed`` still
    reporting the datagram whole. Per :rfc:`9293#section-3.10` ("we
    reconstruct the segment to contain just the new data") the resolution is
    first-write-wins instead: the already-buffered bytes are kept, the
    conflicting portion of whichever segment arrived later is discarded, and
    the sequence range on which they disagreed is recorded on
    :attr:`~pcapkit.foundation.reassembly.data.tcp.Datagram.conflict` --
    additive, so ``completed`` is untouched and existing callers are
    unaffected.

    Every test drives the public API only -- build :class:`Packet`, feed
    :class:`TCP`, read back the :class:`Datagram` from
    :meth:`~pcapkit.foundation.reassembly.reassembly.Reassembly.fetch` --
    the same shape as the reproduction in the issue itself, which this class
    starts from verbatim.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _bufid(self):
        return (ip_address('192.0.2.1'), 12345, ip_address('198.51.100.2'), 443)

    def _packet(self, *, num: int, dsn: int, payload: bytes = b'', ack: int = 1000,
                timestamp: float = 0.0):
        """One segment, described exactly as the issue's own reproduction does."""
        from pcapkit.foundation.reassembly.data.tcp import Packet

        return Packet(self._bufid(), dsn, ack, num, False, False, False, len(payload),
                      dsn, dsn + len(payload) - 1, b'hdr', bytearray(payload), timestamp)

    def _run(self, *packets):
        from pcapkit.foundation.reassembly.tcp import TCP

        reasm = TCP()
        for packet in packets:
            reasm(packet)
        datagram, = reasm.fetch()
        return datagram

    #: Base sequence number for every scenario below -- deliberately not
    #: zero, and not the same as the coordinate-system tests' own ``ISN``,
    #: so a conflict range that happened to be computed as an offset rather
    #: than an absolute sequence number would not go unnoticed by accident.
    BASE = 0x7EED0000 + 100

    def test_identical_retransmission_stays_uncontested_and_unchanged(self) -> None:
        """A conforming retransmission -- same bytes -- reports no conflict at all."""
        base = self.BASE
        datagram = self._run(
            self._packet(num=1, dsn=base, payload=b'AAAAAAAA'),
            self._packet(num=2, dsn=base, payload=b'AAAAAAAA'),
            self._packet(num=3, dsn=base + 8, payload=b'CCCC'),
        )
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.payload, b'AAAAAAAACCCC')
        self.assertEqual(datagram.conflict, ())

    def test_conflicting_full_overlap_keeps_the_first_segment(self) -> None:
        """The issue's own reproduction: first-write-wins, and the range is recorded.

        Before the fix this returned ``completed=True`` and
        ``payload=b'BBBBBBBBCCCC'`` -- the later, conflicting segment silently
        won. The RFC-conformant answer keeps the first segment's bytes.

        """
        base = self.BASE
        datagram = self._run(
            self._packet(num=1, dsn=base, payload=b'AAAAAAAA'),
            self._packet(num=2, dsn=base, payload=b'BBBBBBBB'),
            self._packet(num=3, dsn=base + 8, payload=b'CCCC'),
        )
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.payload, b'AAAAAAAACCCC')
        self.assertEqual(datagram.conflict, ((base, base + 7),))
        self.assertEqual(datagram.index, (1, 2, 3))

    def test_conflicting_partial_overlap_on_the_tail_side(self) -> None:
        """A segment that overlaps the buffered tail and then extends past it.

        Exercises the non-reach-back overlap branch
        (:meth:`~pcapkit.foundation.reassembly.tcp.TCP.reassembly`, the branch
        guarded by ``PSN >= ISN``) when the arriving segment's end lies past
        the already-buffered end: the overlapping half is contested and
        resolved first-write-wins, the non-overlapping half is genuinely new
        and is merged in untouched.

        """
        base = self.BASE
        datagram = self._run(
            self._packet(num=1, dsn=base, payload=b'AAAAAAAA'),        # base .. base+7
            self._packet(num=2, dsn=base + 4, payload=b'XXXXXXXX'),    # base+4 .. base+11
        )
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.payload, b'AAAAAAAAXXXX')
        self.assertEqual(datagram.conflict, ((base + 4, base + 7),))

    def test_conflicting_partial_overlap_on_the_head_side_reach_back(self) -> None:
        """The mirrored reach-back branch, at the line the issue calls out at :204.

        A segment arriving with a *lower* sequence number than the buffer's
        current ISN, whose tail overlaps the buffer's head: the overlapping
        half is contested and resolved first-write-wins, and the segment's
        own leading bytes -- which lie before the existing ISN -- are
        genuinely new and are prepended untouched.

        """
        base = self.BASE
        datagram = self._run(
            self._packet(num=1, dsn=base + 4, payload=b'BBBBBBBB'),    # base+4 .. base+11
            self._packet(num=2, dsn=base, payload=b'YYYYYYYY'),        # base .. base+7
        )
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.payload, b'YYYYBBBBBBBB')
        self.assertEqual(datagram.conflict, ((base + 4, base + 7),))

    def test_three_way_conflict_keeps_the_first_and_records_every_disagreement(self) -> None:
        """Three segments claiming the same range, each disagreeing with the buffer.

        First-write-wins is decided once, by the first segment to arrive;
        every later arrival that disagrees with what is already buffered is
        its own conflict, not just the first one.

        """
        base = self.BASE
        datagram = self._run(
            self._packet(num=1, dsn=base, payload=b'AAAAAAAA'),
            self._packet(num=2, dsn=base, payload=b'BBBBBBBB'),
            self._packet(num=3, dsn=base, payload=b'CCCCCCCC'),
            self._packet(num=4, dsn=base + 8, payload=b'DDDD'),
        )
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.payload, b'AAAAAAAADDDD')
        self.assertEqual(datagram.conflict, ((base, base + 7), (base, base + 7)))

    def test_conflict_persists_once_a_later_segment_completes_the_datagram(self) -> None:
        """A conflict recorded while the stream is still partial survives to completion.

        The gap between the two original segments is a real hole -- unlike
        the overlap in the other tests here, filling it is an ordinary gap
        fill, not a conflict -- and once it closes the datagram reports
        :attr:`~pcapkit.foundation.reassembly.data.data.Completion.COMPLETE`,
        per the decision to leave ``completed`` alone: the conflict recorded
        earlier is still there, on the completed datagram, rather than being
        dropped or blocking completion.

        """
        base = self.BASE
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.tcp import TCP

        reasm = TCP()
        reasm(self._packet(num=1, dsn=base, payload=b'AAAAAAAA'))          # base .. base+7
        reasm(self._packet(num=2, dsn=base + 20, payload=b'CCCCCCCC'))     # base+20 .. base+27

        partial, = reasm.fetch()
        self.assertIs(partial.completed, Completion.PARTIAL)
        self.assertEqual(partial.payload, (b'AAAAAAAA', b'CCCCCCCC'))
        self.assertEqual(partial.conflict, ())

        # conflicts with segment 1 over base..base+7 -- already-received data
        reasm(self._packet(num=3, dsn=base, payload=b'BBBBBBBB'))
        # fills the base+8..base+19 gap exactly -- an ordinary gap fill, not a conflict
        reasm(self._packet(num=4, dsn=base + 8, payload=b'D' * 12))

        complete, = reasm.fetch()
        self.assertIs(complete.completed, Completion.COMPLETE)
        self.assertEqual(complete.payload, b'AAAAAAAA' + b'D' * 12 + b'CCCCCCCC')
        self.assertEqual(complete.conflict, ((base, base + 7),))

    def test_a_conflict_in_one_ack_bucket_is_not_reported_in_another(self) -> None:
        """A conflict recorded for one ACK bucket must stay out of every other.

        The sibling test below covers the inverse -- that a *hole* closed in one
        bucket does not look received in another -- and asserts an empty
        ``conflict`` for both. Nothing asserted the case where one bucket
        genuinely *does* record a conflict while another, in flight at the same
        time, must not: the gap lists and conflict records are per
        :attr:`~pcapkit.foundation.reassembly.data.tcp.Fragment`, and this is
        what proves it rather than arguing it from where the field is declared.

        Worth stating why this case in particular. The data loss this whole
        mechanism exists to fix survived six boundary tests precisely because
        every one of them used a *single* ACK bucket, so none could see state
        leaking across buckets. The representation has since changed from a
        per-octet ``received`` mask to
        :attr:`~pcapkit.foundation.reassembly.data.tcp.Fragment.gap`, and that
        change arrived with two more single-bucket tests -- so the same blind
        spot had reopened against the new mechanism.

        Bucket 1000 takes a real conflicting retransmission over ``base..base+3``
        and must report exactly that range. Bucket 2000 is interleaved with it,
        never sees a conflicting byte, and must report nothing at all.

        """
        base = self.BASE
        from pcapkit.foundation.reassembly.tcp import TCP

        reasm = TCP()
        reasm(self._packet(num=1, dsn=base, payload=b'AAAA', ack=1000))         # bucket 1000, first receipt
        reasm(self._packet(num=2, dsn=base, payload=b'XXXX', ack=2000))         # bucket 2000, same range, own first receipt
        reasm(self._packet(num=3, dsn=base, payload=b'BBBB', ack=1000))         # bucket 1000, CONFLICTS with b'AAAA'
        reasm(self._packet(num=4, dsn=base + 4, payload=b'YYYY', ack=2000))     # bucket 2000 completes, cleanly
        reasm(self._packet(num=5, dsn=base + 4, payload=b'CCCC', ack=1000))     # bucket 1000 completes

        datagrams = {d.id.ack: d for d in reasm.fetch()}

        # first-write-wins, so bucket 1000 keeps b'AAAA' and records the range
        self.assertEqual(datagrams[1000].payload, b'AAAACCCC')
        self.assertEqual(datagrams[1000].conflict, ((base, base + 3),))

        # bucket 2000 was in flight across the same absolute range the whole
        # time and never had a conflicting byte -- its record must be empty,
        # not a copy of its sibling's
        self.assertEqual(datagrams[2000].payload, b'XXXXYYYY')
        self.assertEqual(datagrams[2000].conflict, ())

    def test_one_ack_buckets_hole_closing_does_not_leak_receipt_into_another(self) -> None:
        """A hole closed in one ACK bucket must not look received in a different one.

        :attr:`~pcapkit.foundation.reassembly.data.tcp.Buffer.hdl` is one hole
        descriptor list shared by every ACK bucket under the same BUFID, while
        each bucket's own :attr:`~pcapkit.foundation.reassembly.data.tcp.Fragment.raw`
        is private to that bucket. Bucket 2000 here fills the *shared* hole at
        base+4..base+9 with its own, entirely unrelated data; that must not
        make bucket 1000's later, real segment for the very same absolute
        range look like a conflicting retransmission of something bucket 1000
        already had -- it is bucket 1000's *first* receipt there, and it must
        survive intact with no conflict recorded.

        """
        base = self.BASE
        from pcapkit.foundation.reassembly.tcp import TCP

        reasm = TCP()
        reasm(self._packet(num=1, dsn=base, payload=b'AAAA', ack=1000))          # bucket 1000: base..base+3
        reasm(self._packet(num=2, dsn=base + 10, payload=b'DDDD', ack=1000))     # bucket 1000: base+10..base+13,
                                                                                   # gap base+4..base+9 in the shared hdl
        reasm(self._packet(num=3, dsn=base + 4, payload=b'X' * 6, ack=2000))     # bucket 2000 closes the SHARED hole
        reasm(self._packet(num=4, dsn=base + 4, payload=b'C' * 6, ack=1000))     # bucket 1000's own first receipt there
        reasm(self._packet(num=5, dsn=base + 14, payload=b'EEEE', ack=1000))

        datagrams = {d.id.ack: d for d in reasm.fetch()}
        self.assertTrue(datagrams[1000].completed)
        self.assertEqual(datagrams[1000].payload, b'AAAA' + b'C' * 6 + b'DDDDEEEE')
        self.assertEqual(datagrams[1000].conflict, ())
        self.assertTrue(datagrams[2000].completed)
        self.assertEqual(datagrams[2000].payload, b'X' * 6)
        self.assertEqual(datagrams[2000].conflict, ())

    def test_a_genuine_gap_fill_through_the_overlap_merge_is_never_a_conflict(self) -> None:
        """A hole filled by the overlap-merge path is a gap fill, not a conflict.

        The arriving segment here straddles a real hole *and* touches
        already-received bytes on both sides of it in the same merge call --
        the case :meth:`~pcapkit.foundation.reassembly.tcp.TCP._merge_overlap`
        has to get right on a single call, not just across separate ones. The
        already-received edges carry bytes identical to what is buffered (a
        conforming overlap), so nothing there conflicts either; only the
        hole in the middle is genuinely new, and filling it must not appear
        in ``conflict`` at all.

        """
        base = self.BASE
        datagram = self._run(
            self._packet(num=1, dsn=base, payload=b'AAAA'),           # base..base+3
            self._packet(num=2, dsn=base + 10, payload=b'CCCC'),      # base+10..base+13, gap base+4..base+9
            # base+2..base+11: 'AA' matches the buffered tail of segment 1,
            # 'XXXXXX' fills the gap, 'CC' matches the buffered head of
            # segment 2 -- none of the three is a disagreement
            self._packet(num=3, dsn=base + 2, payload=b'AA' + b'X' * 6 + b'CC'),
        )
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.payload, b'AAAA' + b'X' * 6 + b'CCCC')
        self.assertEqual(datagram.conflict, ())

    def test_a_simultaneous_head_prepend_and_tail_extension_in_one_overlap_call(self) -> None:
        """Full engulfment plus extension: a new head *and* a new tail in the same call.

        Corrects a wrong comment that used to sit on the reach-back branch,
        claiming a head-prepend and a tail-append "cannot both happen at
        once". They can: the old buffer (``isn=100``, ``len=10``) is fully
        inside the arriving segment's range (``dsn=90``, ``len=30``), so the
        arriving segment supplies genuinely new bytes *before* ``isn``
        (90..99) and genuinely new bytes *past* the old buffer's end
        (110..119) in the very same :meth:`~pcapkit.foundation.reassembly.tcp.TCP._merge_overlap`
        call. What actually is mutually exclusive is only which one of the
        old buffer's own tail or a genuinely new one survives -- never both --
        and that is unaffected by the head also being new.

        The overlapping middle (100..109) deliberately disagrees with the
        already-buffered bytes there, so the same call also proves
        first-write-wins and the new head/tail merge correctly coexist.

        """
        base = self.BASE
        old_isn = base + 100
        datagram = self._run(
            self._packet(num=1, dsn=old_isn, payload=b'0123456789'),  # isn=base+100, len=10
            self._packet(num=2, dsn=old_isn - 10,                     # dsn=base+90, len=30
                         payload=b'A' * 10 + b'X' * 10 + b'C' * 10),
        )
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.payload, b'A' * 10 + b'0123456789' + b'C' * 10)
        self.assertEqual(datagram.conflict, ((old_isn, old_isn + 9),))

    def test_gap_list_matches_the_zero_filled_positions_across_200_random_trials(self) -> None:
        """Property test: ``gap`` always names exactly the positions ``raw`` still has as fill.

        This is the correctness check the absolute-interval design is meant
        to make trivial: since ``gap`` never shifts when ``isn`` moves, the
        set of octets it names should equal the set of octets in ``raw`` that
        no segment has ever supplied a real byte for -- checked directly
        against ``raw``, not inferred from the merge arithmetic, so a bug
        that got the merged *bytes* right but the *bookkeeping* wrong would
        still be caught. 200 trials, random overlapping and out-of-order
        segments fed into a single ACK bucket, fixed seed for a reproducible
        run.

        Every synthetic payload avoids the zero byte, so an unfilled octet of
        ``raw`` -- ``b'\\x00'`` -- is unambiguous: it is covered by a ``gap``
        entry if and only if no segment has ever placed a real byte there.

        """
        import random

        from pcapkit.foundation.reassembly.tcp import TCP

        rng = random.Random(20260918)
        bufid = self._bufid()

        for trial in range(200):
            with self.subTest(trial=trial):
                base = rng.randrange(0, 2 ** 31)
                reasm = TCP()

                segments = []
                cursor = 0
                for num in range(1, rng.randint(2, 8) + 1):
                    offset = cursor + rng.randint(-5, 10)
                    length = rng.randint(1, 20)
                    payload = bytes(rng.randint(1, 255) for _ in range(length))  # never 0x00
                    segments.append((num, base + offset, payload))
                    cursor = offset + length
                rng.shuffle(segments)  # out of order delivery
                for (num, dsn, payload) in segments:
                    reasm(self._packet(num=num, dsn=dsn, payload=payload))

                fragment = next(iter(reasm._buffer[bufid].ack.values()))
                raw, isn, gap = fragment.raw, fragment.isn, fragment.gap

                # every gap entry is itself all-zero in raw, and the entries
                # are pairwise disjoint
                covered = set()
                for (first, last) in gap:
                    self.assertLessEqual(first, last)
                    for seq in range(first, last + 1):
                        self.assertNotIn(seq, covered, 'gap entries overlap')
                        covered.add(seq)
                        self.assertEqual(raw[seq - isn], 0)

                # and every zero byte in raw is covered by some gap entry --
                # i.e. gap is not merely disjoint from real data, it is
                # *exactly* the zero-filled positions, nothing more and
                # nothing less
                for offset in range(len(raw)):
                    if raw[offset] == 0:
                        self.assertIn(isn + offset, covered)


if __name__ == '__main__':
    unittest.main()
