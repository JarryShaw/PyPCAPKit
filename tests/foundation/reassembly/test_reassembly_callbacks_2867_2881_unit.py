# -*- coding: utf-8 -*-
"""What a reassembly callback reads, and which callbacks run. C.f. #2867 and #2881.

A callback reading ``datagram`` while another buffer is outstanding gets the
datagrams stored so far, and the callbacks do not run again (#2867). Every
callback runs on a submission: the first :exc:`Exception` is re-raised once the
last has run, a later one is logged, and any other :exc:`BaseException` stops
them at once, as trace callbacks do under #2875 (#2881).

Every case runs on each reassembler ``Extractor`` ships, and builds its own
packets rather than reading a capture. Classes are imported inside each test,
after :func:`~tests._support.reimport_once_per_class`.

"""

from __future__ import annotations

import contextlib
import importlib.util
import inspect
import logging
import unittest
from ipaddress import ip_address
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Callable, Iterator

    #: A builder: the packets of datagram ``ident``, its head or its tail, numbered from ``num``.
    Builder = Callable[[int, int, bool, float], list[Any]]

#: Test tier (#1958): pure-Python bookkeeping around the callbacks, the same on
#: every interpreter.
__tier__ = 'LATEST'

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))

#: Arbitrary but fixed capture epoch the packets start from.
T0 = 1_600_000_000.0


class Refused(Exception):
    """What a raising callback raises."""


class Halted(BaseException):
    """A :exc:`BaseException` that is not an :exc:`Exception`."""


def _indices(datagrams: 'Any') -> 'tuple[tuple[int, ...], ...]':
    """The frame numbers each datagram came from."""
    return tuple(datagram.index for datagram in datagrams)


class Feeder:
    """A reassembler fed the head or tail of each datagram, numbering frames as fed."""

    def __init__(self, reasm: 'Any', build: 'Builder') -> None:
        self.reasm = reasm
        self.build = build
        self.nums = {}  # type: dict[int, list[int]]

    def feed(self, ident: int, tail: bool = False, ts: float = T0) -> None:
        """Feed the head of datagram ``ident``, which leaves it outstanding, or its tail."""
        num = 1 + sum(map(len, self.nums.values()))
        packets = self.build(num, ident, tail, ts)
        self.nums.setdefault(ident, []).extend(range(num, num + len(packets)))
        for packet in packets:
            self.reasm(packet)

    def index(self, ident: int) -> 'tuple[int, ...]':
        """The index datagram ``ident`` reports, from the frames fed so far."""
        return tuple(self.nums[ident])


class ReassemblerCases:
    """Builders for each shipped reassembler, and the harness the test classes share."""

    def setUp(self) -> None:
        reimport_once_per_class(self)  # type: ignore[arg-type]

    # builders: ``build_<name>`` for each name ``Extractor`` ships; a head leaves its
    # datagram outstanding, and the tail completes it

    def build_ipv4(self, num: int, ident: int, tail: bool, ts: float) -> 'list[Any]':
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.ip.data import Packet

        bufid = (ip_address('192.0.2.1'), ip_address('198.51.100.2'), ident, TransType.UDP)
        fo, mf, payload = (8, False, b'z' * 4) if tail else (0, True, bytes([ident]) * 8)
        return [Packet(bufid, num, fo, 20, mf, 20 + len(payload), b'ip-header', bytearray(payload), ts)]

    def build_ipv6(self, num: int, ident: int, tail: bool, ts: float) -> 'list[Any]':
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.ip.data import Packet

        bufid = (ip_address('2001:db8::1'), ip_address('2001:db8::2'), ident, TransType.UDP)
        fo, mf, payload = (8, False, b'z' * 4) if tail else (0, True, bytes([ident]) * 8)
        return [Packet(bufid, num, fo, 40, mf, 40 + len(payload), b'H' * 40, bytearray(payload), ts)]

    def build_tcp(self, num: int, ident: int, tail: bool, ts: float) -> 'list[Any]':
        from pcapkit.foundation.reassembly.tcp.data import Packet

        bufid = (ip_address('192.0.2.1'), ident, ip_address('198.51.100.2'), 443)

        def seg(num: int, dsn: int, payload: bytes = b'', *, syn: bool = False, fin: bool = False) -> 'Any':
            return Packet(bufid, dsn, 500, num, syn, fin, False, len(payload), dsn,
                          dsn + len(payload) - 1, b'tcp-header', bytearray(payload), ts)

        base = 1000 * ident
        if tail:
            return [seg(num, base + 5, fin=True)]
        return [seg(num, base, syn=True), seg(num + 1, base + 1, bytes([ident]) * 4)]

    def build_dtls(self, num: int, ident: int, tail: bool, ts: float) -> 'list[Any]':
        from pcapkit.const.tls.handshake_type import HandshakeType
        from pcapkit.foundation.reassembly.dtls.data import Packet

        offset, payload = (4, b'z' * 4) if tail else (0, bytes([ident]) * 4)
        return [Packet(bufid=(f'10.0.0.{ident}', 1234, '10.0.1.1', 5684, 0), num=num,
                       msg_type=HandshakeType.client_hello, length=8, message_seq=0,
                       fragment_offset=offset, fragment_length=len(payload), payload=payload,
                       timestamp=ts)]

    def build_sctp(self, num: int, ident: int, tail: bool, ts: float) -> 'list[Any]':
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.const.sctp.payload_protocol_identifier import PayloadProtocolIdentifier
        from pcapkit.foundation.reassembly.sctp.data import Packet

        tsn, payload = (11, b'z' * 4) if tail else (10, bytes([ident]) * 4)
        return [Packet(bufid=(2905, 2905, ident), src=f'10.0.0.{ident}', dst='10.0.1.1', num=num,
                       chunk=Chunk.Payload_Data, tsn=tsn, stream_id=0, unordered=False,
                       beginning=not tail, ending=tail, ssn=0, mid=None, fsn=None,
                       ppid=PayloadProtocolIdentifier(0), payload=payload, timestamp=ts)]
    def build_tls(self, num: int, ident: int, tail: bool, ts: float) -> 'list[Any]':
        from pcapkit.foundation.reassembly.tcp.data import Packet

        bufid = (ip_address('192.0.2.1'), ident, ip_address('198.51.100.2'), 443)
        record = b'\x17\x03\x03\x00\x08' + bytes([ident]) * 8  # an 8-octet application_data record
        dsn, payload = (1000 * ident + 9, record[9:]) if tail else (1000 * ident, record[:9])
        return [Packet(bufid, dsn, 500, num, False, False, False, len(payload), dsn,
                       dsn + len(payload) - 1, b'tcp-header', bytearray(payload), ts)]

    # harness

    def shipped(self) -> 'dict[str, type]':
        """Each reassembler ``Extractor`` ships, by its registered name."""
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.foundation.extraction import Extractor

        return {name: entry.klass if isinstance(entry, ModuleDescriptor) else entry
                for (name, entry) in Extractor._shipped_reassembly.items()}

    def cases(self) -> 'list[tuple[str, type, Builder]]':
        """Each shipped reassembler with its builder."""
        return [(name, klass, getattr(self, f'build_{name}'))
                for (name, klass) in self.shipped().items()]

    @contextlib.contextmanager
    def registered(self, klass: type, *callbacks: 'Callable[[list[Any]], None]') -> 'Iterator[None]':
        """Register ``callbacks`` on ``klass`` in order, for the block only."""
        for callback in callbacks:
            klass.register_callback(callback)  # type: ignore[attr-defined]
        try:
            yield
        finally:
            for callback in callbacks:
                klass.__callback_fn__.remove(callback)  # type: ignore[attr-defined]


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class CallbackReadTests(ReassemblerCases, unittest.TestCase):
    """#2867: a callback reading ``datagram`` gets the stored datagrams, and recurses nowhere."""

    def test_every_shipped_reassembler_has_a_builder(self) -> None:
        """#2867, #2881: a reassembler ``Extractor`` ships with no builder here has no case."""
        missing = sorted(name for name in self.shipped() if not hasattr(self, f'build_{name}'))
        self.assertEqual(missing, [])

    def test_a_callback_reading_datagram_gets_the_stored_ones(self) -> None:
        """#2867: the issue's case -- one datagram completes while another is outstanding."""
        for (name, klass, build) in self.cases():
            feeder = Feeder(klass(), build)
            seen = []  # type: list[tuple[Any, ...]]

            def callback(datagrams: 'list[Any]', feeder: 'Feeder' = feeder) -> None:
                reasm = feeder.reasm
                seen.append((_indices(datagrams), _indices(reasm.datagram), reasm.count,
                             _indices(reasm.fetch())))

            with self.subTest(reassembly=name), self.registered(klass, callback):
                feeder.feed(1)
                feeder.feed(2)
                feeder.feed(1, tail=True)
                whole, held = feeder.index(1), feeder.index(2)
                self.assertEqual(seen, [((whole,), (whole,), 1, (whole,))])

                # NOTE: ``count`` first, so a count a callback cached would show here.
                self.assertEqual(feeder.reasm.count, 2)
                self.assertEqual(_indices(feeder.reasm.datagram), (held, whole))
                self.assertEqual(seen[1:], [((held,), (whole,), 1, (whole,))])

    def test_a_callback_run_by_expiry_reads_what_it_stored(self) -> None:
        """#2867: a callback ``advance()`` runs reads the stored datagrams, not an earlier read's cache."""
        for (name, klass, build) in self.cases():
            if 'timeout' not in inspect.signature(klass.__init__).parameters:
                continue  # a reassembler taking no timeout expires nothing
            feeder = Feeder(klass(timeout=60.0), build)
            handed = []  # type: list[tuple[list[Any], tuple[Any, ...], int]]

            def callback(datagrams: 'list[Any]', feeder: 'Feeder' = feeder) -> None:
                handed.append((list(datagrams), feeder.reasm.datagram, feeder.reasm.count))

            with self.subTest(reassembly=name):
                feeder.feed(1)
                feeder.feed(2, ts=T0 + 50)
                feeder.reasm.datagram  # pylint: disable=pointless-statement
                with self.registered(klass, callback):
                    feeder.reasm.advance(T0 + 61)
                (expired, read, count), = handed
                self.assertEqual(_indices(expired), (feeder.index(1),))
                self.assertEqual([id(datagram) for datagram in read], [id(datagram) for datagram in expired])
                self.assertEqual(count, 1)

    def test_a_callback_feeding_a_packet_keeps_reading_the_stored_ones(self) -> None:
        """#2867: a run nested in a callback leaves the outer callback's later reads stored-only."""
        for (name, klass, build) in self.cases():
            feeder = Feeder(klass(), build)
            seen = []  # type: list[tuple[Any, ...]]

            def callback(datagrams: 'list[Any]', feeder: 'Feeder' = feeder) -> None:
                seen.append((_indices(datagrams), _indices(feeder.reasm.datagram)))
                if len(seen) == 1:
                    feeder.feed(2, tail=True)
                    seen.append(('after', _indices(feeder.reasm.datagram)))

            with self.subTest(reassembly=name), self.registered(klass, callback):
                for ident in (1, 2, 3):
                    feeder.feed(ident)
                feeder.feed(1, tail=True)
                first, second = feeder.index(1), feeder.index(2)
                self.assertEqual(seen, [((first,), (first,)), ((second,), (first, second)),
                                        ('after', (first, second))])

    def test_a_callback_that_reads_and_raises_leaves_later_reads_whole(self) -> None:
        """#2867: once a reading callback raises, a read outside the callbacks flushes again."""
        for (name, klass, build) in self.cases():
            feeder = Feeder(klass(), build)
            refused = []  # type: list[bool]

            def callback(datagrams: 'list[Any]', feeder: 'Feeder' = feeder,
                         refused: 'list[bool]' = refused) -> None:
                feeder.reasm.datagram  # pylint: disable=pointless-statement
                if not refused:
                    refused.append(True)
                    raise Refused()

            with self.subTest(reassembly=name), self.registered(klass, callback):
                feeder.feed(1)
                feeder.feed(2)
                with self.assertRaises(Refused):
                    feeder.feed(1, tail=True)
                self.assertEqual(_indices(feeder.reasm.datagram), (feeder.index(2), feeder.index(1)))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class EveryCallbackRunsTests(ReassemblerCases, unittest.TestCase):
    """#2881: an :exc:`Exception` from one callback does not stop the ones after it."""

    def recorder(self, calls: 'list[tuple[str, Any]]', label: str,
                 error: 'BaseException | None' = None) -> 'Callable[[list[Any]], None]':
        """A callback recording ``label`` and the list it is handed, then raising ``error``."""
        def callback(datagrams: 'list[Any]') -> None:
            calls.append((label, datagrams))
            if error is not None:
                raise error
        return callback

    def test_every_callback_runs_and_the_first_error_propagates(self) -> None:
        """#2881: the issue's case -- callbacks 1, 2 (raising) and 3 all run; the error propagates."""
        for (name, klass, build) in self.cases():
            feeder = Feeder(klass(), build)
            feeder.feed(1)
            feeder.feed(2)
            # NOTE: a completed datagram is submitted as its tail is fed, an outstanding one
            # when ``datagram`` is read.
            paths = {
                'completion': lambda feeder=feeder: feeder.feed(1, tail=True),
                'read': lambda feeder=feeder: feeder.reasm.datagram,
            }  # type: dict[str, Callable[[], Any]]
            for (path, run) in paths.items():
                calls = []  # type: list[tuple[str, Any]]
                error = Refused('second')
                callbacks = (self.recorder(calls, '1'), self.recorder(calls, '2', error),
                             self.recorder(calls, '3'))
                with self.subTest(reassembly=name, path=path), self.registered(klass, *callbacks):
                    with self.assertRaises(Refused) as caught:
                        run()
                    self.assertIs(caught.exception, error)
                    self.assertEqual([label for (label, _) in calls], ['1', '2', '3'])
                    self.assertEqual({id(datagrams) for (_, datagrams) in calls}, {id(calls[0][1])})

    def test_a_later_error_is_logged_and_the_first_raised(self) -> None:
        """#2881: with two callbacks raising, the first error propagates and the second is logged."""
        from pcapkit.foundation.reassembly.reassembly import logger

        for (name, klass, build) in self.cases():
            feeder = Feeder(klass(), build)
            calls = []  # type: list[tuple[str, Any]]
            first, second = Refused('first'), ValueError('second')
            callbacks = (self.recorder(calls, '1', first), self.recorder(calls, '2', second),
                         self.recorder(calls, '3'))
            with self.subTest(reassembly=name), self.registered(klass, *callbacks):
                feeder.feed(1)
                with self.assertLogs(logger, logging.DEBUG) as logs, self.assertRaises(Refused) as caught:
                    feeder.feed(1, tail=True)
                self.assertIs(caught.exception, first)
                self.assertEqual([label for (label, _) in calls], ['1', '2', '3'])
                later = [record for record in logs.records if 'raised after an earlier one' in record.getMessage()]
                self.assertEqual([(record.levelno, record.exc_info[1]) for record in later],  # type: ignore[index]
                                 [(logging.DEBUG, second)])

    def test_a_base_exception_stops_the_callbacks_at_once(self) -> None:
        """#2881: a ``KeyboardInterrupt`` or other non-``Exception`` stops the rest, over an earlier error."""
        for (name, klass, build) in self.cases():
            for halt in (KeyboardInterrupt, SystemExit, Halted):
                for earlier in (False, True):
                    feeder = Feeder(klass(), build)
                    calls = []  # type: list[tuple[str, Any]]
                    callbacks = (self.recorder(calls, '1', Refused() if earlier else None),
                                 self.recorder(calls, '2', halt()), self.recorder(calls, '3'))
                    with self.subTest(reassembly=name, halt=halt.__name__, earlier=earlier):
                        feeder.feed(1)
                        feeder.feed(2)
                        with self.registered(klass, *callbacks), self.assertRaises(halt):
                            feeder.feed(1, tail=True)
                        self.assertEqual([label for (label, _) in calls], ['1', '2'])
                        # NOTE: read once the callbacks are gone, so a read still guarded shows.
                        self.assertEqual(_indices(feeder.reasm.datagram), (feeder.index(2), feeder.index(1)))


if __name__ == '__main__':
    unittest.main()
