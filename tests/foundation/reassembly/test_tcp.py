from __future__ import annotations

import importlib.util
from ipaddress import ip_address
import sys
import unittest

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TCPReassemblyTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _bufid(self):
        return (ip_address('192.0.2.1'), 12345, ip_address('198.51.100.2'), 443)

    def _packet(self, *, num: int, dsn: int, ack: int = 500, payload: bytes = b'',
                syn: bool = False, fin: bool = False, rst: bool = False,
                first: int = 0, last: int | None = None, header: bytes = b'tcp-header'):
        from pcapkit.foundation.reassembly.data.tcp import Packet

        if last is None:
            last = first + len(payload) - 1
        return Packet(self._bufid(), dsn, ack, num, syn, fin, rst, len(payload),
                      first, last, header, bytearray(payload))

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
        reasm(self._packet(num=1, dsn=100, payload=b'hello', syn=True, first=0, last=4))
        reasm(self._packet(num=2, dsn=105, payload=b' world', fin=True, first=5, last=10))

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
        from pcapkit.foundation.reassembly.data.tcp import Buffer, Fragment, HoleDiscriptor
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
            [HoleDiscriptor(0, 4), HoleDiscriptor(20, 30), HoleDiscriptor(40, sys.maxsize)],
            b'',
            {
                500: Fragment([1], 10, 10, bytearray(b'0123456789')),
            },
        )

        reasm(self._packet(num=2, dsn=25, payload=b'after-gap', first=10, last=18))
        self.assertEqual(reasm._buffer[bufid].ack[500].raw, bytearray(b'0123456789\x00\x00\x00\x00\x00after-gap'))

        reasm(self._packet(num=3, dsn=15, payload=b'OVERLAP', first=15, last=21))
        self.assertEqual(reasm._buffer[bufid].ack[500].raw,
                         bytearray(b'01234OVERLAP\x00\x00\x00after-gap'))

        reasm(self._packet(num=4, dsn=0, payload=b'abcdefghijklm', first=22, last=24))
        self.assertEqual(reasm._buffer[bufid].ack[500].isn, 0)
        self.assertEqual(reasm._buffer[bufid].ack[500].raw,
                         bytearray(b'abcdefghijklm34OVERLAP\x00\x00\x00after-gap'))
        self.assertEqual([(hole.first, hole.last) for hole in reasm._buffer[bufid].hdl],
                         [(0, 4), (25, 30), (40, sys.maxsize)])

        reasm(self._packet(num=5, dsn=0, ack=501, payload=b'alt', first=50, last=52))
        self.assertEqual(reasm._buffer[bufid].ack[501].raw, bytearray(b'alt'))

        before_gap = TestTCP()
        before_gap._buffer[bufid] = Buffer(
            [HoleDiscriptor(50, sys.maxsize)],
            b'',
            {500: Fragment([1], 10, 5, bytearray(b'world'))},
        )
        before_gap(self._packet(num=2, dsn=0, payload=b'hello', first=40, last=44))
        self.assertEqual(before_gap._buffer[bufid].ack[500].raw,
                         bytearray(b'hello\x00\x00\x00\x00\x00world'))

    def test_submit_incomplete_strict_complete_strict_false_and_empty_buffers(self) -> None:
        from pcapkit.foundation.reassembly.data.tcp import Buffer, Fragment, HoleDiscriptor
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
                [HoleDiscriptor(2, 3), HoleDiscriptor(7, 8), HoleDiscriptor(99, 100)],
                b'tcp-header',
                {500: Fragment([1, 2], 0, 10, bytearray(b'abcdefghij'))},
            ),
            bufid=bufid,
        )
        datagram, = incomplete
        self.assertFalse(datagram.completed)
        self.assertEqual(datagram.payload, (bytearray(b'ab'), bytearray(b'efg'), bytearray(b'j')))
        self.assertIsNone(datagram.packet)

        mixed = strict.submit(
            Buffer(
                [HoleDiscriptor(0, 0), HoleDiscriptor(4, 5), HoleDiscriptor(7, 7)],
                b'tcp-header',
                {
                    500: Fragment([], 0, 0, bytearray()),
                    501: Fragment([9], 0, 9, bytearray(b'abcdefghi')),
                },
            ),
            bufid=bufid,
        )
        self.assertEqual(len(mixed), 1)
        self.assertEqual(mixed[0].payload, (bytearray(b'bcd'), bytearray(b'g'), b'i'))

        loose = TestTCP(strict=False)
        completed = loose.submit(
            Buffer(
                [HoleDiscriptor(2, 3), HoleDiscriptor(7, 8), HoleDiscriptor(99, 100)],
                b'tcp-header',
                {500: Fragment([3], 0, 3, bytearray(b'abc'))},
            ),
            bufid=bufid,
        )
        self.assertTrue(completed[0].completed)
        self.assertEqual(completed[0].packet, b'abc')
        self.assertEqual(Analyzer.calls[-1], ((12345, 443), b'abc'))

        self.assertEqual(loose.submit(Buffer([], b'', {500: Fragment([], 0, 0, bytearray())}),
                                      bufid=bufid), [])


if __name__ == '__main__':
    unittest.main()
