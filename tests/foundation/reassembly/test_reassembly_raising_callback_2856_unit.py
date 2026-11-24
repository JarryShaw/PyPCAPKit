# -*- coding: utf-8 -*-
"""A raising reassembly callback keeps the reassembled datagram. C.f. #2856.

Every path that releases a buffer for good stores its datagrams before the
callbacks run, so a callback that raises propagates and leaves each datagram it
was handed in ``datagram`` exactly once, stored in the order a run with no raise
stores it. A read with buffers outstanding stores nothing, so one whose callback
raises reads again whole. A custom ``submit`` that drops ``store`` still has each
datagram stored once.

Every case builds its own packets and reads no capture. Classes are imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

from __future__ import annotations

import importlib.util
import unittest
from ipaddress import ip_address
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Callable, Optional

    #: A scenario builder: a reassembler class, its arguments, its body field, and fresh steps.
    Scenario = Callable[[], tuple[type, dict[str, Any], str, list[Any]]]

#: Test tier (#1958): pure-Python bookkeeping on an exception's path, the same on
#: every interpreter.
__tier__ = 'LATEST'

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))

#: Arbitrary but fixed capture epoch the packets start from.
T0 = 1_600_000_000.0


class Refused(Exception):
    """What a raising callback raises."""


def _bytes(payload: 'Any') -> 'Any':
    """A payload as bytes, or as a tuple of bytes for the received runs."""
    if isinstance(payload, tuple):
        return tuple(bytes(run) for run in payload)
    return bytes(payload)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class RaisingCallbackTests(unittest.TestCase):
    """Each reassembler, fed a run covering its paths, with no raise and with one per datagram."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    # scenarios: a reassembler class and its arguments, its body field, and the steps it is
    # fed, where a float step advances the clock to it; built afresh per run, as TCP extends
    # a packet's payload in place

    def ipv4(self) -> 'tuple[type, dict[str, Any], str, list[Any]]':
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.ip.data import Packet
        from pcapkit.foundation.reassembly.ipv4.reassembly import IPv4

        def frag(num: int, ident: int, fo: int, mf: bool, payload: bytes, ts: float = T0) -> 'Any':
            bufid = (ip_address('192.0.2.1'), ip_address('198.51.100.2'), ident, TransType.UDP)
            return Packet(bufid, num, fo, 20, mf, 20 + len(payload), b'ip-header', bytearray(payload), ts)

        return IPv4, {}, 'payload', [
            frag(1, 1, 0, True, b'a' * 8), frag(2, 1, 8, False, b'b' * 4),  # complete
            frag(3, 2, 0, True, b'c' * 8), frag(4, 2, 0, False, b'd' * 4),  # RFC 791 flush
            frag(5, 3, 8, True, b'e' * 8),
            frag(6, 4, 8, True, b'f' * 8, T0 + 61),  # expires the third
            T0 + 122.0,                              # expires the fourth
            frag(7, 5, 0, True, b'g' * 8, T0 + 122),  # outstanding
        ]

    def ipv6(self) -> 'tuple[type, dict[str, Any], str, list[Any]]':
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.ip.data import Packet
        from pcapkit.foundation.reassembly.ipv6.reassembly import IPv6

        def frag(num: int, ident: int, fo: int, mf: bool, payload: bytes, ts: float = T0) -> 'Any':
            bufid = (ip_address('2001:db8::1'), ip_address('2001:db8::2'), ident, TransType.UDP)
            return Packet(bufid, num, fo, 40, mf, 40 + len(payload), b'H' * 40, bytearray(payload), ts)

        return IPv6, {}, 'payload', [
            frag(1, 1, 0, True, b'a' * 8), frag(2, 1, 8, False, b'b' * 4),  # complete
            frag(3, 2, 0, False, b'c' * 4),                                # atomic fragment
            frag(4, 3, 0, True, b'd' * 8), frag(5, 3, 0, True, b'e' * 8),  # overlap
            frag(6, 4, 8, True, b'f' * 8),
            frag(7, 5, 8, True, b'g' * 8, T0 + 61),  # expires the fourth
            T0 + 122.0,                              # expires the fifth
            frag(8, 6, 0, True, b'h' * 8, T0 + 122),  # outstanding
        ]

    def tcp(self) -> 'tuple[type, dict[str, Any], str, list[Any]]':
        from pcapkit.foundation.reassembly.tcp.data import Packet
        from pcapkit.foundation.reassembly.tcp.reassembly import TCP

        def seg(num: int, sport: int, dsn: int, payload: bytes = b'', *, syn: bool = False,
                fin: bool = False, rst: bool = False, ts: float = T0) -> 'Any':
            bufid = (ip_address('192.0.2.1'), sport, ip_address('198.51.100.2'), 443)
            return Packet(bufid, dsn, 500, num, syn, fin, rst, len(payload), dsn,
                          dsn + len(payload) - 1, b'tcp-header', bytearray(payload), ts)

        return TCP, {'timeout': 60.0}, 'payload', [
            seg(1, 1, 100, syn=True), seg(2, 1, 101, b'a' * 4),
            seg(3, 1, 900, syn=True),                         # SYN reset
            seg(4, 1, 901, b'b' * 4, rst=True),               # RST
            seg(5, 2, 100, syn=True), seg(6, 2, 101, b'c' * 4),
            seg(7, 2, 1000, b'd' * 4),                        # gap split
            seg(8, 2, 1004, fin=True),                        # FIN, the stream whole
            seg(9, 3, 5000, b'e' * 4),
            seg(10, 4, 6000, b'f' * 4, ts=T0 + 61),           # expires the third
            T0 + 122.0,                                       # expires the fourth
            seg(11, 5, 7000, b'g' * 4, ts=T0 + 122),          # outstanding
        ]

    def dtls(self) -> 'tuple[type, dict[str, Any], str, list[Any]]':
        from pcapkit.const.tls.handshake_type import HandshakeType
        from pcapkit.foundation.reassembly.dtls.data import Packet
        from pcapkit.foundation.reassembly.dtls.reassembly import DTLS

        def frag(num: int, host: str, msn: int, length: int, payload: bytes,
                 msg_type: 'Any' = HandshakeType.client_hello) -> 'Any':
            return Packet(bufid=(host, 1234, '10.0.0.2', 5684, 0), num=num, msg_type=msg_type,
                          length=length, message_seq=msn, fragment_offset=0,
                          fragment_length=len(payload), payload=payload, timestamp=T0)

        return DTLS, {}, 'body', [
            frag(1, '10.0.0.1', 0, 8, b'a' * 4),
            frag(2, '10.0.0.1', 1, 4, b'b' * 2, HandshakeType.server_hello),
            frag(3, '10.0.0.1', 0, 6, b'c' * 3),  # displaces the first, ahead of the second
            frag(4, '10.0.0.3', 0, 8, b'd' * 4),
            frag(5, '10.0.0.3', 0, 4, b'e' * 4),  # displaces the fourth, and completes
            frag(6, '10.0.0.1', 2, 4, b'f' * 4),  # complete
        ]

    # harness

    def narrow_gap_limit(self) -> None:
        """Split a TCP stream on a short jump, rather than a jump of gigabytes."""
        from pcapkit.utilities import config

        patcher = mock.patch.object(config, 'TCP_GAP_LIMIT', 16)
        patcher.start()
        self.addCleanup(patcher.stop)

    def shape(self, field: str, datagram: 'Any') -> 'tuple[Any, ...]':
        """What a datagram reports, comparable across runs."""
        return (datagram.completed, datagram.index, _bytes(getattr(datagram, field)))

    def run_steps(self, scenario: 'Scenario', target: 'Optional[tuple[int, ...]]' = None, *,
                  dropping: bool = False) -> 'tuple[Any, list[list[Any]], list[bool], Optional[int]]':
        """Feed the scenario's steps, a callback raising once on the datagram indexed ``target``.

        Returns the reassembler, the lists handed to the callback, whether each
        datagram was stored when handed, and the step that raised. ``dropping``
        feeds a subclass whose ``submit`` drops ``store``.

        """
        cls, kwargs, _, steps = scenario()
        if dropping:
            class Dropping(cls):  # type: ignore[valid-type,misc]
                def submit(self, buf: 'Any', *, bufid: 'Any', expired: bool = False,  # type: ignore[override]
                           **kw: 'Any') -> 'list[Any]':
                    kw.pop('store', None)
                    return super().submit(buf, bufid=bufid, expired=expired, **kw)

            cls = Dropping
        reasm = cls(**kwargs)
        handed, stored, fired = [], [], []  # type: list[list[Any]], list[bool], list[bool]

        def callback(datagrams: 'list[Any]') -> None:
            handed.append(list(datagrams))
            stored.append(all(any(kept is datagram for kept in reasm._dtgram) for datagram in datagrams))
            if not fired and any(datagram.index == target for datagram in datagrams):
                fired.append(True)
                raise Refused(target)

        type(reasm).register_callback(callback)
        self.addCleanup(type(reasm).__callback_fn__.remove, callback)

        for (number, step) in enumerate(steps):
            try:
                if isinstance(step, float):
                    reasm.advance(step)
                else:
                    reasm(step)
            except Refused:
                return reasm, handed, stored, number
        return reasm, handed, stored, None

    def read(self, reasm: 'Any', field: str) -> 'list[tuple[Any, ...]]':
        """Read ``datagram`` afresh, as a flush after the capture would."""
        reasm._flag_n = True
        return [self.shape(field, datagram) for datagram in reasm.datagram]

    def check_order(self, scenario: 'Scenario', expected: 'list[tuple[Any, ...]]') -> None:
        """With no raise: the order is the pinned one, and each datagram is stored when handed."""
        field = scenario()[2]
        reasm, handed, stored, raised = self.run_steps(scenario)
        self.assertIsNone(raised)
        self.assertEqual(stored, [True] * len(stored))
        self.assertEqual([datagram for datagrams in handed for datagram in datagrams], reasm._dtgram)
        self.assertEqual(self.read(reasm, field), expected)
        self.assertEqual(self.read(reasm, field), expected)

    def check_raising(self, scenario: 'Scenario', steps_raising: 'dict[tuple[int, ...], int]') -> None:
        """A callback raising on each datagram: propagated, and the datagram kept exactly once."""
        field = scenario()[2]
        reference, _, _, _ = self.run_steps(scenario)
        stored_order = [self.shape(field, datagram) for datagram in reference._dtgram]
        whole = self.read(reference, field)

        for (target, step) in steps_raising.items():
            with self.subTest(target=target):
                reasm, handed, _, raised = self.run_steps(scenario, target)
                self.assertEqual(raised, step)
                refused = handed[-1]
                kept = [self.shape(field, datagram) for datagram in reasm._dtgram]
                self.assertEqual(kept, stored_order[:len(kept)])
                for datagram in refused:
                    self.assertEqual(sum(entry is datagram for entry in reasm._dtgram), 1)

                first, second = self.read(reasm, field), self.read(reasm, field)
                self.assertEqual(first, second)
                self.assertEqual(len(set(first)), len(first))
                self.assertTrue(set(kept) <= set(first))
                for datagram in refused:
                    self.assertIn(self.shape(field, datagram), first)

        # NOTE: the read stores nothing, so a callback raising on an outstanding buffer during
        # it leaves the next read whole.
        outstanding = next(datagram for datagram in whole if datagram not in stored_order)
        with self.subTest(target='read'):
            reasm, _, _, raised = self.run_steps(scenario, outstanding[1])
            self.assertIsNone(raised)
            with self.assertRaises(Refused):
                reasm.datagram  # pylint: disable=pointless-statement
            self.assertEqual(self.read(reasm, field), whole)
            self.assertEqual(self.read(reasm, field), whole)
            self.assertEqual([self.shape(field, datagram) for datagram in reasm._dtgram], stored_order)

    def check_dropping(self, scenario: 'Scenario') -> None:
        """A ``submit`` dropping ``store``: each datagram stored once, read as with one that keeps it."""
        field = scenario()[2]
        reference, _, _, _ = self.run_steps(scenario)
        reasm, handed, _, raised = self.run_steps(scenario, dropping=True)
        self.assertIsNone(raised)
        self.assertEqual([id(datagram) for datagrams in handed for datagram in datagrams],
                         [id(datagram) for datagram in reasm._dtgram])
        self.assertEqual(self.read(reasm, field), self.read(reference, field))

    # cases

    def test_ipv4_order(self) -> None:
        """#2856: with no raise, IPv4 reports the pinned order, each datagram stored before its callbacks."""
        from pcapkit.foundation.reassembly.data import Completion

        self.check_order(self.ipv4, [
            (Completion.PARTIAL, (7,), (b'g' * 8,)),
            (Completion.COMPLETE, (1, 2), b'a' * 8 + b'b' * 4),
            (Completion.PARTIAL, (3,), (b'c' * 8,)),
            (Completion.COMPLETE, (4,), b'd' * 4),
            (Completion.TIMEOUT, (5,), (b'e' * 8,)),
            (Completion.TIMEOUT, (6,), (b'f' * 8,)),
        ])

    def test_ipv4_raising(self) -> None:
        """#2856: IPv4 keeps a datagram whose callback raises, on every path that stores one."""
        self.check_raising(self.ipv4, {(1, 2): 1, (3,): 3, (4,): 3, (5,): 5, (6,): 6})

    def test_ipv6_order(self) -> None:
        """#2856: with no raise, IPv6 reports the pinned order, each datagram stored before its callbacks."""
        from pcapkit.foundation.reassembly.data import Completion

        self.check_order(self.ipv6, [
            (Completion.PARTIAL, (8,), (b'h' * 8,)),
            (Completion.COMPLETE, (1, 2), b'a' * 8 + b'b' * 4),
            (Completion.COMPLETE, (3,), b'c' * 4),
            (Completion.OVERLAP, (4, 5), (b'd' * 8,)),
            (Completion.TIMEOUT, (6,), (b'f' * 8,)),
            (Completion.TIMEOUT, (7,), (b'g' * 8,)),
        ])

    def test_ipv6_raising(self) -> None:
        """#2856: the issue's case and its siblings -- IPv6 keeps a datagram whose callback raises."""
        self.check_raising(self.ipv6, {(1, 2): 1, (3,): 2, (4, 5): 4, (6,): 6, (7,): 7})

    def test_tcp_order(self) -> None:
        """#2856: with no raise, TCP reports the pinned order, each datagram stored before its callbacks."""
        from pcapkit.foundation.reassembly.data import Completion

        self.narrow_gap_limit()
        self.check_order(self.tcp, [
            (Completion.COMPLETE, (11,), b'g' * 4),
            (Completion.COMPLETE, (1, 2), b'a' * 4),
            (Completion.COMPLETE, (3, 4), b'b' * 4),
            (Completion.PARTIAL, (5, 6), (b'c' * 4,)),
            (Completion.PARTIAL, (7, 8), (b'd' * 4,)),
            (Completion.COMPLETE, (9,), b'e' * 4),
            (Completion.COMPLETE, (10,), b'f' * 4),
        ])

    def test_tcp_raising(self) -> None:
        """#2856: TCP keeps a datagram whose callback raises, on every path that stores one."""
        self.narrow_gap_limit()
        self.check_raising(self.tcp, {(1, 2): 2, (3, 4): 3, (5, 6): 6, (7, 8): 7, (9,): 9, (10,): 10})

    def test_dtls_order(self) -> None:
        """#2856: with no raise, DTLS reports the pinned order, each message stored before its callbacks."""
        from pcapkit.foundation.reassembly.data import Completion

        self.check_order(self.dtls, [
            (Completion.PARTIAL, (3,), (b'c' * 3,)),
            (Completion.PARTIAL, (2,), (b'b' * 2,)),
            (Completion.PARTIAL, (1,), (b'a' * 4,)),
            (Completion.PARTIAL, (4,), (b'd' * 4,)),
            (Completion.COMPLETE, (5,), b'e' * 4),
            (Completion.COMPLETE, (6,), b'f' * 4),
        ])

    def test_dtls_raising(self) -> None:
        """#2856: DTLS keeps a message whose callback raises, a displaced one held nowhere else."""
        self.check_raising(self.dtls, {(1,): 2, (4,): 4, (5,): 4, (6,): 5})

    def test_a_submit_dropping_store_keeps_each_datagram_once(self) -> None:
        """#2856: a custom ``submit`` that drops ``store`` has each datagram, expired ones included, stored once."""
        self.narrow_gap_limit()
        for scenario in (self.ipv4, self.ipv6, self.tcp, self.dtls):
            with self.subTest(reassembly=scenario.__name__):
                self.check_dropping(scenario)

    def test_advance_keeps_every_expired_datagram_and_clears_the_cache(self) -> None:
        """#2856: a callback raising on the second buffer one ``advance()`` expires keeps both, read afresh."""
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data import Completion
        from pcapkit.foundation.reassembly.ip.data import Packet
        from pcapkit.foundation.reassembly.ipv6.reassembly import IPv6

        def frag(num: int, ts: float) -> 'Any':
            bufid = (ip_address('2001:db8::1'), ip_address('2001:db8::2'), num, TransType.UDP)
            return Packet(bufid, num, 8, 40, True, 48, b'H' * 40, bytearray(bytes([num]) * 8), ts)

        def callback(datagrams: 'list[Any]') -> None:
            if any(datagram.completed is Completion.TIMEOUT and datagram.index == (2,)
                   for datagram in datagrams):
                raise Refused()

        IPv6.register_callback(callback)
        self.addCleanup(IPv6.__callback_fn__.remove, callback)
        reasm = IPv6()
        for (num, ts) in ((1, T0), (2, T0 + 1), (3, T0 + 50)):
            reasm(frag(num, ts))
        self.assertEqual([datagram.completed for datagram in reasm.datagram], [Completion.PARTIAL] * 3)

        with self.assertRaises(Refused):
            reasm.advance(T0 + 61.5)
        self.assertEqual([(datagram.index, datagram.completed) for datagram in reasm.datagram],
                         [((3,), Completion.PARTIAL), ((1,), Completion.TIMEOUT), ((2,), Completion.TIMEOUT)])


if __name__ == '__main__':
    unittest.main()
