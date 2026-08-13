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
                header: bytes = b'ip-header'):
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data.ip import Packet

        src = ip_address('192.0.2.1')
        dst = ip_address('198.51.100.2')
        return Packet((src, dst, 42, TransType.UDP), num, fo, 20, mf,
                      20 + len(payload), header, bytearray(payload))

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
                Buffer(-1, bytearray(b'\x00\x00'), [], b'', bytearray(b'')),
                bufid=(src, dst, 42, TransType.UDP),
            ),
            [],
        )


if __name__ == '__main__':
    unittest.main()
