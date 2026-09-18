"""The RFC reassembly timeout, on an offline parser's only clock.

A live stack runs its reassembly timer off the wall clock. A parser replaying a
capture file cannot: wall-clock time says nothing about the capture, and keying on
it would make the same file produce different answers on every run. The clock here
is therefore the **capture's own timestamps**, and a fragment arriving is the only
evidence that capture time has moved on -- which is why expiry is checked when a
packet is handed over rather than on a timer.

Every timestamp below is a literal, so every expectation is exact.
"""

from __future__ import annotations

import importlib.util
from ipaddress import ip_address
import math
import unittest

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Arbitrary but fixed epoch the synthetic captures below start from.
T0 = 1_600_000_000.0


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPReassemblyTimeoutTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _packet(self, *, num: int, fo: int, mf: bool, payload: bytes, timestamp: float,
                id: int = 42):  # pylint: disable=redefined-builtin
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data.ip import Packet

        src = ip_address('192.0.2.1')
        dst = ip_address('198.51.100.2')
        return Packet((src, dst, id, TransType.UDP), num, fo, 20, mf,
                      20 + len(payload), b'ip-header', bytearray(payload), timestamp)

    def test_the_default_deadline_is_the_one_the_rfcs_ask_for(self) -> None:
        """60 seconds for both IPv4 and IPv6, and no deadline at all for TCP.

        :rfc:`8200#section-4.5` mandates 60 seconds for IPv6.
        :rfc:`1122#section-3.3.2` requires a reassembly timeout for IPv4, says it
        SHOULD be a fixed value rather than derived from the remaining TTL, and
        recommends 60 to 120 seconds -- so 60 is the low end of the range and
        agrees with IPv6. :rfc:`791`'s 15 seconds is an *initial* setting that
        ``MAX(TIMER,TTL)`` then raises, and RFC 1122 supersedes it.

        """
        from pcapkit.foundation.reassembly.ipv4 import IPv4
        from pcapkit.foundation.reassembly.ipv6 import IPv6
        from pcapkit.foundation.reassembly.tcp import TCP

        self.assertEqual(IPv4.__timeout__, 60.0)
        self.assertEqual(IPv6.__timeout__, 60.0)
        self.assertEqual(IPv4().timeout, 60.0)
        self.assertEqual(IPv6().timeout, 60.0)

        self.assertTrue(math.isinf(TCP.__timeout__))
        self.assertTrue(math.isinf(TCP().timeout))

    def test_a_stalled_datagram_is_abandoned_once_the_capture_clock_passes_it(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.ipv4 import IPv4

        reasm = IPv4()
        # a first fragment that is never completed
        reasm(self._packet(num=1, fo=0, mf=True, payload=b'abcdefgh', timestamp=T0))
        self.assertEqual(len(reasm._buffer), 1)
        self.assertEqual(reasm._dtgram, [])

        # an unrelated datagram, more than 60 seconds later, advances the clock
        reasm(self._packet(num=2, fo=0, mf=False, payload=b'later', timestamp=T0 + 60.5, id=99))

        self.assertEqual(len(reasm._buffer), 0, 'the stalled buffer was not released')
        expired = reasm._dtgram[0]
        self.assertIs(expired.completed, Completion.TIMEOUT)
        self.assertFalse(expired.completed, 'an abandoned datagram is not complete')
        self.assertEqual(expired.index, (1,))
        self.assertEqual(expired.payload, (b'abcdefgh',))
        self.assertEqual(expired.id.id, 42)

    def test_timeout_is_told_apart_from_merely_unfinished(self) -> None:
        """The two incomplete outcomes must be distinguishable.

        ``PARTIAL`` says "these fragments had not arrived yet"; ``TIMEOUT`` says
        "these fragments are gone, and no further fragment will ever be added".
        Both are falsy, so ``if datagram.completed`` reads as it did while the
        field was a :obj:`bool`.

        """
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.ipv4 import IPv4

        # left unfinished when the capture ended
        unfinished = IPv4()
        unfinished(self._packet(num=1, fo=0, mf=True, payload=b'abcdefgh', timestamp=T0))
        datagram, = unfinished.datagram
        self.assertIs(datagram.completed, Completion.PARTIAL)

        # abandoned under the timeout
        abandoned = IPv4()
        abandoned(self._packet(num=1, fo=0, mf=True, payload=b'abcdefgh', timestamp=T0))
        abandoned(self._packet(num=2, fo=0, mf=True, payload=b'ijklmnop', timestamp=T0 + 61,
                               id=99))
        datagram, = (dtgram for dtgram in abandoned.datagram
                     if dtgram.completed is Completion.TIMEOUT)
        self.assertEqual(datagram.index, (1,))

        self.assertFalse(Completion.PARTIAL)
        self.assertFalse(Completion.TIMEOUT)
        self.assertTrue(Completion.COMPLETE)

    def test_the_deadline_is_inclusive_and_counted_from_the_first_fragment(self) -> None:
        """"within 60 seconds of the reception of the first-arriving fragment".

        Two things follow from that wording, and both are asserted here: at
        exactly 60 seconds the datagram is still *within* the limit, and a later
        fragment does not restart the clock -- otherwise a slow trickle of
        fragments could hold a buffer open indefinitely, which is the resource
        exhaustion the timeout exists to bound.

        """
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.ipv4 import IPv4

        # exactly at the limit: still within it
        boundary = IPv4()
        boundary(self._packet(num=1, fo=0, mf=True, payload=b'abcdefgh', timestamp=T0))
        boundary(self._packet(num=2, fo=0, mf=False, payload=b'x', timestamp=T0 + 60.0, id=99))
        self.assertEqual(len(boundary._buffer), 1)

        # one tick past it: abandoned
        boundary(self._packet(num=3, fo=0, mf=False, payload=b'x', timestamp=T0 + 60.001, id=98))
        self.assertEqual(len(boundary._buffer), 0)

        # a second fragment of the same datagram does not extend the deadline
        trickle = IPv4()
        trickle(self._packet(num=1, fo=0, mf=True, payload=b'abcdefgh', timestamp=T0))
        trickle(self._packet(num=2, fo=16, mf=True, payload=b'ijklmnop', timestamp=T0 + 40))
        bufid, = trickle._buffer
        self.assertEqual(trickle._buffer[bufid].timestamp, T0,
                         'the buffer timer was restarted by a later fragment')
        trickle(self._packet(num=3, fo=0, mf=False, payload=b'x', timestamp=T0 + 61, id=99))
        self.assertEqual(len(trickle._buffer), 0)
        expired, = (dtgram for dtgram in trickle.datagram
                    if dtgram.completed is Completion.TIMEOUT)
        self.assertEqual(expired.index, (1, 2))

    def test_a_datagram_that_completes_in_time_is_untouched(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.ipv4 import IPv4

        reasm = IPv4()
        reasm(self._packet(num=1, fo=0, mf=True, payload=b'A' * 8, timestamp=T0))
        reasm(self._packet(num=2, fo=8, mf=False, payload=b'B' * 8, timestamp=T0 + 59.999))

        datagram, = reasm.datagram
        self.assertIs(datagram.completed, Completion.COMPLETE)
        self.assertEqual(datagram.payload, b'A' * 8 + b'B' * 8)

    def test_an_infinite_timeout_disables_expiry(self) -> None:
        from pcapkit.foundation.reassembly.ipv4 import IPv4

        reasm = IPv4(timeout=math.inf)
        reasm(self._packet(num=1, fo=0, mf=True, payload=b'abcdefgh', timestamp=T0))
        reasm(self._packet(num=2, fo=0, mf=False, payload=b'x', timestamp=T0 + 86_400, id=99))
        self.assertEqual(len(reasm._buffer), 1)

    def test_an_explicit_timeout_overrides_the_protocol_default(self) -> None:
        from pcapkit.foundation.reassembly.ipv4 import IPv4

        reasm = IPv4(timeout=5.0)
        self.assertEqual(reasm.timeout, 5.0)
        reasm(self._packet(num=1, fo=0, mf=True, payload=b'abcdefgh', timestamp=T0))
        reasm(self._packet(num=2, fo=0, mf=False, payload=b'x', timestamp=T0 + 6, id=99))
        self.assertEqual(len(reasm._buffer), 0)

    def test_a_negative_timeout_is_refused(self) -> None:
        from pcapkit.foundation.reassembly.ipv4 import IPv4
        from pcapkit.utilities.exceptions import FieldValueError

        with self.assertRaises(FieldValueError):
            IPv4(timeout=-1.0)

    def test_expire_on_an_empty_buffer_is_a_no_op(self) -> None:
        from pcapkit.foundation.reassembly.ipv4 import IPv4

        self.assertEqual(IPv4().expire(T0), [])
        self.assertEqual(IPv4(timeout=math.inf).expire(T0), [])

    def test_the_answer_depends_only_on_the_capture_timestamps(self) -> None:
        """Replaying the same timestamps twice gives the same answer.

        This is the property that makes the feature usable on a file at all: no
        part of it consults :func:`time.time` or :meth:`datetime.datetime.now`, so
        a capture reassembles identically today, tomorrow and on another machine.

        """
        from pcapkit.foundation.reassembly.ipv4 import IPv4

        def run() -> list:
            reasm = IPv4()
            for num, (fo, mf, ts, id_) in enumerate([
                (0, True, T0, 42),
                (0, True, T0 + 10, 43),
                (0, False, T0 + 75, 44),
                (0, False, T0 + 200, 45),
            ], start=1):
                reasm(self._packet(num=num, fo=fo, mf=mf, payload=b'payload',
                                   timestamp=ts, id=id_))
            return [(dtgram.completed, dtgram.index) for dtgram in reasm.datagram]

        first, second = run(), run()
        self.assertEqual(first, second)
        # and it really did expire something, so the equality above is not vacuous
        self.assertTrue(any(not completed for completed, _ in first))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPLooseModeTests(unittest.TestCase):
    """``strict=False``, where IP reports one contiguous payload, not the runs.

    This branch had no test, and it is the one where the payload -- not merely the
    ``completed`` flag -- changed: an unterminated datagram used to come back as
    65534 octets of preallocated buffer, reported *complete*.
    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _packet(self, *, num: int, fo: int, mf: bool, payload: bytes):
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data.ip import Packet

        src = ip_address('192.0.2.1')
        dst = ip_address('198.51.100.2')
        return Packet((src, dst, 42, TransType.UDP), num, fo, 20, mf,
                      20 + len(payload), b'ip-header', bytearray(payload), T0)

    def test_an_unterminated_datagram_reports_the_prefix_that_arrived(self) -> None:
        """No final fragment means no known length -- but the prefix is known.

        ``TDL`` is still ``-1`` here, and ``datagram[:-1]`` was 65534 octets of the
        preallocated buffer with ``completed=True`` on top. Neither that nor an
        empty payload is right: the octets from offset zero to the first hole did
        genuinely arrive, so they are what a caller asking for one contiguous
        payload gets, and the datagram is reported incomplete.

        """
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.ipv4 import IPv4

        reasm = IPv4(strict=False)
        # 16 octets at offset 0, then nothing -- MF set throughout, so the total
        # length is never learnt
        reasm(self._packet(num=1, fo=0, mf=True, payload=b'A' * 16))

        datagram, = reasm.datagram
        self.assertIs(datagram.completed, Completion.PARTIAL)
        self.assertFalse(datagram.completed)
        self.assertEqual(datagram.payload, b'A' * 16)
        self.assertNotEqual(len(datagram.payload), 65534, 'the whole buffer came back')

    def test_the_prefix_stops_at_the_first_hole(self) -> None:
        """A run after a gap cannot be placed in a blob, so it is not in one.

        Its offset is exactly what a contiguous payload cannot express; ``strict``
        mode lists the runs for that reason. Reporting the later run here would
        misrepresent it as starting at the datagram's beginning.

        """
        from pcapkit.foundation.reassembly.ipv4 import IPv4

        reasm = IPv4(strict=False)
        reasm(self._packet(num=1, fo=0, mf=True, payload=b'A' * 16))
        reasm(self._packet(num=2, fo=64, mf=True, payload=b'C' * 16))

        datagram, = reasm.datagram
        self.assertEqual(datagram.payload, b'A' * 16)

        # ... and strict mode, the default, reports both runs instead
        strict = IPv4()
        strict(self._packet(num=1, fo=0, mf=True, payload=b'A' * 16))
        strict(self._packet(num=2, fo=64, mf=True, payload=b'C' * 16))
        datagram, = strict.datagram
        self.assertEqual(datagram.payload, (b'A' * 16, b'C' * 16))

    def test_a_known_length_still_zero_fills_its_holes(self) -> None:
        """With the last fragment in hand the length is known, so nothing changes.

        This is the case ``strict=False`` exists for, and its payload is exactly
        what it always was -- only ``completed`` stopped claiming the datagram was
        whole.

        """
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.ipv4 import IPv4

        reasm = IPv4(strict=False)
        # a 24-octet datagram missing its middle 8 octets
        reasm(self._packet(num=1, fo=0, mf=True, payload=b'A' * 8))
        reasm(self._packet(num=2, fo=16, mf=False, payload=b'C' * 8))

        datagram, = reasm.datagram
        self.assertIs(datagram.completed, Completion.PARTIAL)
        self.assertEqual(datagram.payload, b'A' * 8 + bytes(8) + b'C' * 8)

    def test_a_complete_datagram_is_unaffected_by_loose_mode(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.ipv4 import IPv4

        reasm = IPv4(strict=False)
        reasm(self._packet(num=1, fo=0, mf=True, payload=b'A' * 8))
        reasm(self._packet(num=2, fo=8, mf=False, payload=b'B' * 8))

        datagram, = reasm.datagram
        self.assertIs(datagram.completed, Completion.COMPLETE)
        self.assertEqual(datagram.payload, b'A' * 8 + b'B' * 8)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TCPReassemblyTimeoutTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _segment(self, *, num: int, seq: int, payload: bytes, timestamp: float,
                 fin: bool = False):
        from pcapkit.foundation.reassembly.data.tcp import Packet

        bufid = (ip_address('192.0.2.1'), 12345, ip_address('198.51.100.2'), 443)
        return Packet(bufid, seq, 500, num, False, fin, False, len(payload),
                      seq, seq + len(payload) - 1, b'tcp-header', bytearray(payload),
                      timestamp)

    def test_tcp_holds_its_buffer_by_default(self) -> None:
        """An idle connection is ordinary, so nothing evicts it unasked."""
        from pcapkit.foundation.reassembly.tcp import TCP

        reasm = TCP()
        reasm(self._segment(num=1, seq=0, payload=b'A' * 10, timestamp=T0))
        reasm(self._segment(num=2, seq=30, payload=b'C' * 10, timestamp=T0 + 86_400))
        self.assertEqual(len(reasm._buffer), 1)

    def test_tcp_honours_a_timeout_when_one_is_asked_for(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.tcp import TCP

        reasm = TCP(timeout=120.0)
        self.assertEqual(reasm.timeout, 120.0)
        # a gap at sequence 10..29 that is never filled
        reasm(self._segment(num=1, seq=0, payload=b'A' * 10, timestamp=T0))
        reasm(self._segment(num=2, seq=30, payload=b'C' * 10, timestamp=T0 + 1))
        self.assertEqual(len(reasm._buffer), 1)

        # a segment of the same connection past the deadline; the buffer it would
        # have joined is abandoned first, so the segment opens a fresh buffer
        reasm(self._segment(num=3, seq=100, payload=b'D' * 4, timestamp=T0 + 121))
        expired, = (dtgram for dtgram in reasm._dtgram
                    if dtgram.completed is Completion.TIMEOUT)
        self.assertEqual(expired.index, (1, 2))
        self.assertEqual(expired.payload, (b'A' * 10, b'C' * 10))
        self.assertEqual(len(reasm._buffer), 1)
        bufid, = reasm._buffer
        self.assertEqual(reasm._buffer[bufid].timestamp, T0 + 121)


if __name__ == '__main__':
    unittest.main()
