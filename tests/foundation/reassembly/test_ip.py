from __future__ import annotations

import importlib.util
from ipaddress import ip_address
import unittest

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPReassemblyTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _packet(self, *, num: int, fo: int, mf: bool, payload: bytes,
                header: bytes = b'ip-header', timestamp: float = 1000.0, ident: int = 42):
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data.ip import Packet

        src = ip_address('192.0.2.1')
        dst = ip_address('198.51.100.2')
        return Packet((src, dst, ident, TransType.UDP), num, fo, 20, mf,
                      20 + len(payload), header, bytearray(payload), timestamp)

    def test_complete_fragmented_datagram_is_submitted_and_analyzed(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.ip import IP
        from pcapkit.foundation.reassembly.ipv4 import IPv4
        from pcapkit.foundation.reassembly.ipv6 import IPv6

        class Analyzer:
            calls: list[tuple[TransType, bytes]] = []

            @classmethod
            def analyze(cls, proto: TransType, payload: bytes) -> dict[str, object]:
                cls.calls.append((proto, payload))
                return {'proto': proto, 'payload': payload}

        class TestIP(IP):
            __protocol_type__ = Analyzer

        reasm = TestIP()
        reasm(self._packet(num=1, fo=0, mf=True, payload=b'abcdefgh'))
        reasm(self._packet(num=2, fo=8, mf=False, payload=b'ijkl'))

        self.assertEqual(IPv4.name, 'IPv4')
        self.assertEqual(IPv6.name, 'IPv6')
        datagram, = reasm.datagram
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.index, (1, 2))
        self.assertEqual(datagram.header, b'ip-header')
        self.assertEqual(datagram.payload, b'abcdefghijkl')
        self.assertEqual(datagram.packet, {'proto': TransType.UDP, 'payload': b'abcdefghijkl'})
        self.assertEqual(Analyzer.calls, [(TransType.UDP, b'abcdefghijkl')])
        self.assertEqual(reasm.count, 1)

        single = TestIP()
        single(self._packet(num=3, fo=0, mf=False, payload=b'whole', header=b'whole-header'))
        datagram, = single.datagram
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.header, b'whole-header')
        self.assertEqual(datagram.payload, b'whole')

    def test_non_fragment_flushes_pending_incomplete_datagram_without_padding(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data.ip import Buffer
        from pcapkit.foundation.reassembly.ip import IP

        class Analyzer:
            @classmethod
            def analyze(cls, proto: object, payload: bytes) -> object:
                raise AssertionError('incomplete datagram should not be analyzed')

        class TestIP(IP):
            __protocol_type__ = Analyzer

        callback_calls = []
        TestIP.register(callback_calls.append)

        reasm = TestIP()
        reasm(self._packet(num=1, fo=0, mf=True, payload=b'abcdefgh'))
        reasm(self._packet(num=2, fo=0, mf=False, payload=b'ignored', header=b'fresh'))

        datagram, = reasm.datagram
        self.assertFalse(datagram.completed)
        self.assertEqual(datagram.index, (1,))
        self.assertEqual(datagram.header, b'ip-header')
        self.assertEqual(datagram.payload, (b'abcdefgh',))
        self.assertIsNone(datagram.packet)
        self.assertEqual(len(callback_calls), 1)

        pending = TestIP()
        pending(self._packet(num=3, fo=8, mf=True, payload=b'ijkl', header=b'ignored'))
        pending(self._packet(num=4, fo=0, mf=True, payload=b'abcdefgh', header=b'updated'))
        self.assertEqual(pending._buffer[self._packet(num=0, fo=0, mf=True, payload=b'').bufid].header,
                         b'updated')

        empty = TestIP()
        src = ip_address('192.0.2.1')
        dst = ip_address('198.51.100.2')
        self.assertEqual(
            empty.submit(
                Buffer(-1, bytearray(b'\x00\x00'), [], b'', bytearray(b''), 1000.0, []),
                bufid=(src, dst, 42, TransType.UDP),
            ),
            [],
        )


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPOverlapConflictTests(unittest.TestCase):
    """:issue:`477` -- an overlapping fragment carrying different bytes must
    have the disagreement recorded, not silently overwrite the earlier one.

    :rfc:`791` resolves *which* bytes win itself: "this procedure will use the
    more recently arrived copy in the data buffer" -- the opposite of TCP's
    first-write-wins (:rfc:`9293#section-3.10`, fixed for TCP by #443/#478).
    So every case below still expects the *arriving* fragment's bytes in the
    reassembled payload; what changes is that ``datagram.conflict`` now
    records where that overwrite disagreed with what was already there.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _packet(self, *, num: int, fo: int, mf: bool, payload: bytes,
                header: bytes = b'ip-header', timestamp: float = 1000.0, ident: int = 42):
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data.ip import Packet

        src = ip_address('192.0.2.1')
        dst = ip_address('198.51.100.2')
        return Packet((src, dst, ident, TransType.UDP), num, fo, 20, mf,
                      20 + len(payload), header, bytearray(payload), timestamp)

    def _reasm(self):
        from pcapkit.foundation.reassembly.ip import IP

        class Analyzer:
            @classmethod
            def analyze(cls, proto: object, payload: bytes) -> object:
                return {'proto': proto, 'payload': payload}

        class TestIP(IP):
            __protocol_type__ = Analyzer

        return TestIP()

    def test_identical_duplicate_fragment_stays_uncontested(self) -> None:
        """A byte-for-byte retransmission is not a conflict."""
        reasm = self._reasm()
        reasm(self._packet(num=1, fo=0, mf=True, payload=b'AAAAAAAA', ident=1))
        reasm(self._packet(num=2, fo=0, mf=True, payload=b'AAAAAAAA', ident=1))
        reasm(self._packet(num=3, fo=8, mf=False, payload=b'ZZZZ', ident=1))

        datagram, = reasm.datagram
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.payload, b'AAAAAAAAZZZZ')
        self.assertEqual(datagram.conflict, ())

    def test_conflicting_full_overlap_records_conflict_and_last_write_wins(self) -> None:
        """Two block-aligned fragments claiming the same octets, with different data."""
        reasm = self._reasm()
        reasm(self._packet(num=1, fo=0, mf=True, payload=b'AAAAAAAA', ident=2))
        reasm(self._packet(num=2, fo=0, mf=True, payload=b'BBBBBBBB', ident=2))
        reasm(self._packet(num=3, fo=8, mf=False, payload=b'ZZZZ', ident=2))

        datagram, = reasm.datagram
        self.assertTrue(datagram.completed)
        # per RFC 791, the more recently arrived copy wins
        self.assertEqual(datagram.payload, b'BBBBBBBBZZZZ')
        self.assertEqual(datagram.conflict, ((0, 7),))

    def test_conflicting_partial_overlap_extending_left(self) -> None:
        """The arriving fragment starts before the buffered one and overlaps its head."""
        reasm = self._reasm()
        # base: octets 8-15
        reasm(self._packet(num=1, fo=8, mf=True, payload=b'CCCCCCCC', ident=3))
        # arriving: octets 0-15 -- overlaps 8-15 with different data
        reasm(self._packet(num=2, fo=0, mf=True, payload=b'0123456789ABCDEF'.replace(
            b'89ABCDEF', b'DDDDDDDD'), ident=3))
        reasm(self._packet(num=3, fo=16, mf=False, payload=b'ZZZZ', ident=3))

        datagram, = reasm.datagram
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.payload, b'01234567DDDDDDDDZZZZ')
        self.assertEqual(datagram.conflict, ((8, 15),))

    def test_conflicting_partial_overlap_extending_right(self) -> None:
        """The arriving fragment starts inside the buffered one and overlaps its tail."""
        reasm = self._reasm()
        # base: octets 0-15
        reasm(self._packet(num=1, fo=0, mf=True, payload=b'E' * 16, ident=4))
        # arriving: octets 8-23 -- overlaps 8-15 with different data
        reasm(self._packet(num=2, fo=8, mf=True, payload=b'F' * 16, ident=4))
        reasm(self._packet(num=3, fo=24, mf=False, payload=b'ZZZZ', ident=4))

        datagram, = reasm.datagram
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.payload, b'E' * 8 + b'F' * 16 + b'ZZZZ')
        self.assertEqual(datagram.conflict, ((8, 15),))

    def test_conflict_inside_final_partial_block_does_not_over_report(self) -> None:
        """The genuinely coarse case: a conflict inside the *final* fragment's
        partial 8-octet block, where ``RCVBT`` rounds a 3-octet tail up to a
        whole 8-octet block.

        Fragment B (the final one) covers only octets 8, 9 and 10, but
        ``RCVBT`` marks the whole block covering octets 8-15 as received.
        Fragment C then claims the full block (octets 8-15): it genuinely
        conflicts with B over 8-10, but 11-15 were never really received by
        anyone before C -- they are past ``TDL`` -- so they must not be
        reported as conflicting, even though their ``RCVBT`` block reads as
        "received".

        """
        reasm = self._reasm()
        # keep the buffer open past fragment B below by leaving octets 0-7
        # unreceived until the very end
        reasm(self._packet(num=1, fo=16, mf=True, payload=b'A' * 8, ident=5))
        # final fragment: octets 8, 9, 10 only -- sets TDL=11, rounds the
        # RCVBT block covering 8-15 to fully "received"
        reasm(self._packet(num=2, fo=8, mf=False, payload=b'BBB', ident=5))
        # conflicts with B at 8, 9, 10; 11-15 is new territory, not a conflict
        reasm(self._packet(num=3, fo=8, mf=True, payload=b'XXXXXXXX', ident=5))
        # completes the datagram
        reasm(self._packet(num=4, fo=0, mf=True, payload=b'D' * 8, ident=5))

        datagram, = reasm.datagram
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.payload, b'D' * 8 + b'XXX')
        # exactly the real conflict, not the whole 8-15 block
        self.assertEqual(datagram.conflict, ((8, 10),))

    def test_three_way_conflict_records_each_disagreement(self) -> None:
        """A third fragment disagreeing with the second's already-resolved overwrite."""
        reasm = self._reasm()
        reasm(self._packet(num=1, fo=0, mf=True, payload=b'A' * 8, ident=6))
        reasm(self._packet(num=2, fo=0, mf=True, payload=b'B' * 8, ident=6))
        reasm(self._packet(num=3, fo=0, mf=True, payload=b'C' * 8, ident=6))
        reasm(self._packet(num=4, fo=8, mf=False, payload=b'ZZZZ', ident=6))

        datagram, = reasm.datagram
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.payload, b'C' * 8 + b'ZZZZ')
        self.assertEqual(datagram.conflict, ((0, 7), (0, 7)))

    def test_conflict_is_recorded_even_when_a_later_fragment_completes_the_datagram(self) -> None:
        """``completed`` and ``conflict`` are independent: a clean completion
        can still carry a recorded conflict from earlier in reassembly."""
        reasm = self._reasm()
        reasm(self._packet(num=1, fo=0, mf=True, payload=b'A' * 8, ident=7))
        reasm(self._packet(num=2, fo=0, mf=True, payload=b'B' * 8, ident=7))
        reasm(self._packet(num=3, fo=8, mf=False, payload=b'ZZZZ', ident=7))

        datagram, = reasm.datagram
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.conflict, ((0, 7),))

    def test_conflict_stays_scoped_to_its_own_bufid(self) -> None:
        """Coverage gap named in #482's review: ``Buffer.conflict`` is created
        fresh per BUFID, but "created fresh" is an argument, not a test --
        nothing exercised two BUFIDs actually in flight at once. This is the
        more valuable of the two gaps: #478's original six boundary cases all
        shared a single ACK bucket, and that is exactly the shape of gap that
        let a genuine cross-bucket data-loss regression through undetected.

        So this interleaves two datagrams' fragments -- neither one completes
        before the other's next fragment arrives -- rather than finishing one
        datagram before starting the next.

        """
        reasm = self._reasm()

        # datagram A (ident=100) and datagram B (ident=200) are both open at once
        reasm(self._packet(num=1, fo=0, mf=True, payload=b'AAAAAAAA', ident=100))
        reasm(self._packet(num=2, fo=0, mf=True, payload=b'PPPPPPPP', ident=200))
        # A's second fragment conflicts with its first; B is untouched by this
        reasm(self._packet(num=3, fo=0, mf=True, payload=b'CCCCCCCC', ident=100))
        # B completes cleanly while A is still open
        reasm(self._packet(num=4, fo=8, mf=False, payload=b'QQQQ', ident=200))
        # A completes afterwards
        reasm(self._packet(num=5, fo=8, mf=False, payload=b'ZZZZ', ident=100))

        by_ident = {datagram.id.id: datagram for datagram in reasm.datagram}
        self.assertEqual(set(by_ident), {100, 200})

        conflicted = by_ident[100]
        self.assertTrue(conflicted.completed)
        self.assertEqual(conflicted.payload, b'CCCCCCCCZZZZ')
        self.assertEqual(conflicted.conflict, ((0, 7),))

        clean = by_ident[200]
        self.assertTrue(clean.completed)
        self.assertEqual(clean.payload, b'PPPPPPPPQQQQ')
        # the leak this test guards against: B must not see A's conflict
        self.assertEqual(clean.conflict, ())

    def test_single_write_produces_two_conflict_runs_separated_by_a_match(self) -> None:
        """Coverage gap named in #482's review: the inner loop of
        :meth:`~pcapkit.foundation.reassembly.ip.IP._detect_conflicts` breaks a
        conflict run on a match and resumes detection afterwards, but no
        existing test drove a single fragment's comparison pass through two
        separate, non-adjacent conflict runs -- only a leading match (or
        mismatch) followed by one trailing run.

        One arriving fragment overlaps a base fragment across three 8-octet
        blocks: octets 8-15 and 24-31 disagree with the base, octets 16-23
        agree with it (the matching region the two conflict runs sandwich).

        The overlapping/completing fragment is placed at ``fo=8``, not ``0``:
        a fragment with ``fo=0`` *and* ``mf=False`` is indistinguishable from
        a whole, never-fragmented packet, and :meth:`IP.reassembly
        <pcapkit.foundation.reassembly.ip.IP.reassembly>` special-cases that by
        flushing the pending buffer unread rather than merging it -- which
        would skip :meth:`_detect_conflicts` entirely and not exercise this
        gap at all.

        """
        reasm = self._reasm()

        # leading block, established separately so the fragment under test
        # does not start at octet 0
        reasm(self._packet(num=1, fo=0, mf=True, payload=b'AAAAAAAA', ident=300))

        base = b'AAAAAAAA' + b'MMMMMMMM' + b'BBBBBBBB'
        reasm(self._packet(num=2, fo=8, mf=True, payload=base, ident=300))

        # the single write under test: conflicts at 8-15 and 24-31, agrees at
        # 16-23, and also completes the datagram (fo=8, mf=False)
        overwrite = b'XXXXXXXX' + b'MMMMMMMM' + b'YYYYYYYY'
        reasm(self._packet(num=3, fo=8, mf=False, payload=overwrite, ident=300))

        datagram, = reasm.datagram
        self.assertTrue(datagram.completed)
        # per RFC 791, the more recently arrived copy wins -- including its
        # untouched middle block, which is why the tested range equals the
        # arriving fragment outright; the leading block is unaffected
        self.assertEqual(datagram.payload, b'AAAAAAAA' + overwrite)
        self.assertEqual(datagram.conflict, ((8, 15), (24, 31)))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class DeferredAnalysisTests(unittest.TestCase):
    """``Datagram.packet`` is analysed on first read, not at submit time.

    The analysis is a second full parse of the reassembled payload, and a
    datagram is submitted for *every* frame -- ``pcapkit/toolkit/pcap.py``
    dismisses an IPv4 frame only when its **DF** flag is set, so a frame with
    ``DF=0, MF=0, FO=0`` is not fragmented in any sense and still arrives here.
    On ``http.pcap``, which holds no fragments at all, that was 1117 re-parses
    per extraction and 86% of the cost of IP reassembly.

    What a caller sees must not change, which is why the assertions below are
    about *when* the analyser runs and not only about what it returns.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _reassemble(self, *, calls: 'list'):
        """One complete, unfragmented datagram, and the analyser's call log."""
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data.ip import Packet
        from pcapkit.foundation.reassembly.ip import IP

        class Analyzer:
            @classmethod
            def analyze(cls, proto: object, payload: bytes) -> object:
                calls.append((proto, payload))
                return {'proto': proto, 'payload': payload}

        class TestIP(IP):
            __protocol_type__ = Analyzer

        src = ip_address('192.0.2.1')
        dst = ip_address('198.51.100.2')
        reasm = TestIP()
        reasm(Packet((src, dst, 42, TransType.UDP), 1, 0, 20, False, 25,
                     b'ip-header', bytearray(b'hello'), 1000.0))
        datagram, = reasm.datagram
        return datagram

    def test_submitting_a_datagram_does_not_analyse_it(self) -> None:
        calls = []  # type: list
        datagram = self._reassemble(calls=calls)

        # the datagram is complete and its payload is there, but nothing has been
        # parsed -- which is the whole point
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.payload, b'hello')
        self.assertEqual(calls, [])

    def test_reading_packet_analyses_once_and_keeps_the_result(self) -> None:
        calls = []  # type: list
        datagram = self._reassemble(calls=calls)

        first = datagram.packet
        self.assertEqual(first, {'proto': datagram.id.proto, 'payload': b'hello'})
        self.assertEqual(len(calls), 1)

        # a second read must not re-parse, and must be the same object rather
        # than an equal one -- a caller holding ``datagram.packet`` and reading it
        # again would otherwise get a different parse tree each time
        self.assertIs(datagram.packet, first)
        self.assertEqual(len(calls), 1)

    def test_the_mapping_view_reports_packet_and_forces_the_analysis(self) -> None:
        """``dict(datagram)`` and friends must not expose the deferral.

        ``Info`` builds its mapping view out of ``__dict__``, so a lazy field is
        one that can silently vanish from ``to_dict()``, ``keys()`` and ``repr()``
        -- or, worse, show up there as the placeholder object.

        """
        for reader in ('to_dict', 'str', 'repr', 'getitem', 'get', 'items'):
            with self.subTest(reader=reader):
                calls = []  # type: list
                datagram = self._reassemble(calls=calls)

                # every view lists the field before anything has been read
                self.assertIn('packet', datagram)
                self.assertIn('packet', sorted(datagram))
                self.assertIn('packet', datagram.keys())
                self.assertEqual(calls, [])

                expected = {'proto': datagram.id.proto, 'payload': b'hello'}
                if reader == 'to_dict':
                    self.assertEqual(datagram.to_dict()['packet'], expected)
                elif reader == 'str':
                    self.assertIn("'payload': b'hello'", str(datagram))
                elif reader == 'repr':
                    self.assertIn("'payload': b'hello'", repr(datagram))
                elif reader == 'getitem':
                    self.assertEqual(datagram['packet'], expected)
                elif reader == 'get':
                    self.assertEqual(datagram.get('packet'), expected)
                else:
                    self.assertEqual(dict(datagram.items())['packet'], expected)
                self.assertEqual(len(calls), 1)

    def test_an_unknown_attribute_still_raises(self) -> None:
        """The lazy read is reached through ``__getattr__``, which must not swallow."""
        calls = []  # type: list
        datagram = self._reassemble(calls=calls)

        self.assertFalse(hasattr(datagram, 'nope'))
        with self.assertRaises(AttributeError):
            datagram.nope  # pylint: disable=pointless-statement
        self.assertEqual(calls, [])

    def test_the_deferred_holder_is_a_plain_callable(self) -> None:
        """It has to be callable and comparable by identity, nothing more."""
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data.ip import Deferred

        seen = []  # type: list
        deferred = Deferred(lambda proto, payload: seen.append((proto, payload)) or 'parsed',
                            TransType.UDP, b'hello')
        self.assertEqual(seen, [])
        self.assertEqual(deferred(), 'parsed')
        self.assertEqual(seen, [(TransType.UDP, b'hello')])


if __name__ == '__main__':
    unittest.main()
