# -*- coding: utf-8 -*-
"""TCP reassembly reports what arrived: gaps, sequence wrap, and late data.

GitHub issues #1354, #1355 and #1356, from the foundation round-trip audit
(#1202):

* #1354 -- completion was judged from the buffer-wide hole list, which never
  learnt of a gap opened *below* the first segment to arrive, and which another
  acknowledgement number's payload buffer could clear. A zero-filled gap came
  back :attr:`~pcapkit.foundation.reassembly.data.data.Completion.COMPLETE`.
* #1355 -- sequence numbers were compared as plain integers, so a stream
  crossing ``2 ** 32`` read as a gap of about 4 GiB and allocated it.
* #1356 -- a FIN submitted the buffer at once, so data reordered behind it was
  split off into a buffer of its own.

Every case feeds hand-built segments and reads no capture. Classes are imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import unittest
from ipaddress import ip_address

from tests._support import reimport_once_per_class

BUFID = (ip_address('192.0.2.1'), 12345, ip_address('198.51.100.2'), 443)


class TestTCPReassemblyRoundTrip(unittest.TestCase):
    """Pin completion, wrap-around and FIN handling of TCP reassembly."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _seg(seq, payload=b'', *, ack=500, syn=False, fin=False, rst=False):
        """Describe a segment; :meth:`_run` builds it, numbered by position."""
        return (seq, ack, syn, fin, rst, payload)

    @staticmethod
    def _summary(reasm):
        return [(d.completed.name, d.id.ack, d.index, d.payload) for d in reasm.datagram]

    def _run(self, *segments, strict=True):
        from pcapkit.foundation.reassembly.data.tcp import Packet
        from pcapkit.foundation.reassembly.tcp import TCP

        reasm = TCP(strict=strict)
        for num, (seq, ack, syn, fin, rst, payload) in enumerate(segments, 1):
            reasm(Packet(BUFID, seq, ack, num, syn, fin, rst, len(payload), seq,
                         seq + len(payload) - 1, b'H' if syn else b'', bytearray(payload), 1000.0))
        return reasm

    # #1354 ------------------------------------------------------------------

    def test_gap_below_the_first_segment_is_partial(self) -> None:
        for strict, payload in ((True, (b'A' * 100, b'B' * 100)),
                                (False, b'A' * 100 + bytes(100) + b'B' * 100)):
            with self.subTest(strict=strict):
                reasm = self._run(self._seg(200, b'B' * 100), self._seg(0, b'A' * 100),
                                  self._seg(300, fin=True), strict=strict)
                self.assertEqual(self._summary(reasm), [('PARTIAL', 500, (1, 2, 3), payload)])

    def test_another_ack_bucket_does_not_fill_this_ones_gap(self) -> None:
        reasm = self._run(self._seg(0, syn=True, ack=0), self._seg(1, b'A' * 100, ack=1000),
                          self._seg(201, b'C' * 100, ack=1000), self._seg(101, b'B' * 100, ack=1050),
                          self._seg(301, fin=True, ack=1050))
        by_ack = {ack: (completed, payload) for (completed, ack, _, payload) in self._summary(reasm)}
        self.assertEqual(by_ack[1000], ('PARTIAL', (b'A' * 100, b'C' * 100)))
        # the stream as a whole is covered, so the FIN submitted it
        self.assertEqual(reasm._buffer, {})

    def test_one_segment_filling_two_holes_completes_the_stream(self) -> None:
        whole = b''.join(c * 10 for c in (b'A', b'B', b'C', b'D', b'E'))
        reasm = self._run(self._seg(0, syn=True), self._seg(1, whole[:10]), self._seg(21, whole[20:30]),
                          self._seg(41, whole[40:]), self._seg(1, whole), self._seg(51, fin=True))
        # the retransmission closed both holes, so the FIN submitted the stream
        self.assertEqual(reasm._buffer, {})
        self.assertEqual(self._summary(reasm), [('COMPLETE', 500, (1, 2, 3, 4, 5, 6), whole)])

    # #1355 ------------------------------------------------------------------

    def _no_big_allocation(self):
        import pcapkit.foundation.reassembly.tcp as module

        def guarded(*args):
            if args and isinstance(args[0], int) and args[0] > 1 << 20:
                raise MemoryError(f'would allocate bytearray({args[0]})')
            return bytearray(*args)
        module.bytearray = guarded
        self.addCleanup(delattr, module, 'bytearray')

    def test_sequence_numbers_wrap_modulo_2_32(self) -> None:
        self._no_big_allocation()
        for order in ((0, 1, 2), (1, 0, 2), (2, 1, 0)):
            segs = [self._seg(0xFFFFFF00, b'A' * 256), self._seg(0, b'B' * 256), self._seg(256, fin=True)]
            with self.subTest(order=order):
                reasm = self._run(*(segs[i] for i in order))
                self.assertEqual([(c, p) for (c, _, _, p) in self._summary(reasm)],
                                 [('COMPLETE', b'A' * 256 + b'B' * 256)])

    def test_wrap_with_handshake_at_the_top_of_sequence_space(self) -> None:
        self._no_big_allocation()
        reasm = self._run(self._seg(0xFFFFFFFF, syn=True), self._seg(0, b'A' * 10),
                          self._seg(10, b'B' * 10), self._seg(20, fin=True))
        self.assertEqual(self._summary(reasm), [('COMPLETE', 500, (1, 2, 3, 4), b'A' * 10 + b'B' * 10)])

    def test_conflict_past_the_wrap_is_reported_modulo_2_32(self) -> None:
        self._no_big_allocation()
        reasm = self._run(self._seg(0xFFFFFF00, b'A' * 256), self._seg(0, b'B' * 256),
                          self._seg(16, b'X' * 16))
        datagram, = reasm.datagram
        self.assertEqual(datagram.conflict, ((16, 31),))
        self.assertEqual(datagram.payload, b'A' * 256 + b'B' * 256)

    def test_a_segment_half_the_sequence_space_away_starts_a_new_stream(self) -> None:
        self._no_big_allocation()
        for seq in (0x80000000, 0x7FFFFF00, 0x80000100):
            with self.subTest(seq=hex(seq)):
                reasm = self._run(self._seg(0, b'A' * 10), self._seg(seq, b'N' * 5))
                self.assertEqual(sorted(p for (_, _, _, p) in self._summary(reasm)),
                                 [b'A' * 10, b'N' * 5])

    # #1356 ------------------------------------------------------------------

    def test_a_reused_4_tuple_behind_a_pending_fin_does_not_join_it(self) -> None:
        # data, a FIN with a hole below it, then a new stream on the same
        # 4-tuple whose SYN was lost: without a bound the new segment pads the
        # old buffer out by some 768 MiB
        self._no_big_allocation()
        reasm = self._run(self._seg(1, b'A' * 5), self._seg(11, fin=True),
                          self._seg(0x30000000, b'N' * 5))
        self.assertEqual(self._summary(reasm), [('COMPLETE', 500, (3,), b'N' * 5),
                                                ('PARTIAL', 500, (1, 2), (b'A' * 5,))])

    def test_a_far_segment_after_a_captured_syn_splits_both_halves_partial(self) -> None:
        # The SYN proves A and B are one stream with 20 MiB lost between them:
        # neither half may come back COMPLETE, and nothing pads the gap.
        self._no_big_allocation()
        far = 1 + 1000 + 20 * (1 << 20)
        for strict, a, b in ((True, (b'A' * 1000,), (b'B' * 1000,)),
                             (False, b'A' * 1000, b'B' * 1000)):
            with self.subTest(strict=strict):
                reasm = self._run(self._seg(0, syn=True), self._seg(1, b'A' * 1000),
                                  self._seg(far, b'B' * 1000), strict=strict)
                self.assertEqual(self._summary(reasm), [('PARTIAL', 500, (3,), b),
                                                        ('PARTIAL', 500, (1, 2), a)])
                datagram = reasm.datagram[0]
                self.assertEqual(datagram.header, b'H')

    def test_a_split_halfs_missing_range_shrinks_as_data_fills_it(self) -> None:
        # after the split, a segment just below B joins B and must not be
        # mistaken for part of the range still missing
        self._no_big_allocation()
        far = 1 + 1000 + 20 * (1 << 20)
        reasm = self._run(self._seg(0, syn=True), self._seg(1, b'A' * 1000),
                          self._seg(far, b'B' * 10), self._seg(far - 10, b'C' * 10))
        completed, _, index, payload = self._summary(reasm)[0]
        self.assertEqual((completed, index, payload), ('PARTIAL', (3, 4), (b'C' * 10 + b'B' * 10,)))
        self.assertEqual(reasm._buffer[BUFID].ack[500].gap, [(1001, far - 11)])

    def test_a_far_segment_below_a_captured_syn_stream_splits_both_halves_partial(self) -> None:
        self._no_big_allocation()
        start = 0x30000000
        reasm = self._run(self._seg(start - 1, syn=True), self._seg(start, b'A' * 5),
                          self._seg(start - (1 << 25), b'B' * 5))
        self.assertEqual([c for (c, _, _, _) in self._summary(reasm)], ['PARTIAL', 'PARTIAL'])

    def test_a_segment_far_below_the_buffer_starts_a_new_stream(self) -> None:
        self._no_big_allocation()
        reasm = self._run(self._seg(0x30000000, b'A' * 5), self._seg(0x10000000, b'B' * 5))
        self.assertEqual(sorted(p for (_, _, _, p) in self._summary(reasm)), [b'A' * 5, b'B' * 5])

    def test_a_gap_within_the_window_is_still_padded(self) -> None:
        from pcapkit.foundation.reassembly.tcp import TCP

        far = TCP.__window__
        reasm = self._run(self._seg(0, b'A' * 5), self._seg(5 + far, b'B' * 5), strict=False)
        (completed, _, index, payload), = self._summary(reasm)
        self.assertEqual((completed, index, len(payload)), ('PARTIAL', (1, 2), 10 + far))

    def test_data_reordered_behind_the_fin_joins_the_stream(self) -> None:
        reasm = self._run(self._seg(100, syn=True, ack=0), self._seg(101, b'AAAAA'),
                          self._seg(111, fin=True), self._seg(106, b'BBBBB'))
        # the segment that closed the last hole submitted the buffer
        self.assertEqual(reasm._buffer, {})
        self.assertEqual(self._summary(reasm), [('COMPLETE', 500, (2, 3, 4), b'AAAAABBBBB')])

    def test_fin_with_data_that_never_arrives_waits_for_the_end_of_capture(self) -> None:
        reasm = self._run(self._seg(100, syn=True, ack=0), self._seg(101, b'AAAAA'),
                          self._seg(111, fin=True))
        self.assertIn(BUFID, reasm._buffer)
        self.assertEqual(self._summary(reasm), [('PARTIAL', 500, (2, 3), (b'AAAAA',))])

    def test_rst_aborts_at_once(self) -> None:
        # RFC 9293 section 3.10.7.4: an RST flushes the receiver's queues, so
        # data arriving after it is not part of the stream it ended
        reasm = self._run(self._seg(100, syn=True, ack=0), self._seg(101, b'AAAAA'),
                          self._seg(111, rst=True), self._seg(106, b'BBBBB'))
        self.assertEqual(self._summary(reasm), [('COMPLETE', 500, (4,), b'BBBBB'),
                                                ('PARTIAL', 500, (2, 3), (b'AAAAA',))])


if __name__ == '__main__':
    unittest.main()
