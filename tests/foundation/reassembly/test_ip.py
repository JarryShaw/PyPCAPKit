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
                header: bytes = b'ip-header', timestamp: float = 1000.0):
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data.ip import Packet

        src = ip_address('192.0.2.1')
        dst = ip_address('198.51.100.2')
        return Packet((src, dst, 42, TransType.UDP), num, fo, 20, mf,
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
                Buffer(-1, bytearray(b'\x00\x00'), [], b'', bytearray(b''), 1000.0),
                bufid=(src, dst, 42, TransType.UDP),
            ),
            [],
        )


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
