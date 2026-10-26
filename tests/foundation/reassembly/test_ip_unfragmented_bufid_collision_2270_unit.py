# -*- coding: utf-8 -*-
"""An unfragmented datagram whose BUFID is already buffered is reported.

GitHub issue #2270. A datagram with fragment offset zero and **MF** clear whose
BUFID matched a buffered one submitted that buffer and returned, so the datagram
itself was never reported. IPv6 inherited this, so a colliding atomic fragment
also flushed the datagram being reassembled, and its final fragment then opened
a buffer of its own that never completed.

:rfc:`791#section-3.2` flushes the buffer and then submits the datagram, so
IPv4 reports both, the flushed one incomplete. :rfc:`6946#section-4` says an
atomic fragment is processed in isolation and the queued fragments are not
discarded, so IPv6 reports the atomic fragment alone and still completes the
datagram it interrupted.

Every case builds its fragments in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

from ipaddress import ip_address
import unittest

from tests._support import reimport_once_per_class


class TestIPReassemblyUnfragmentedBufidCollision(unittest.TestCase):
    """Pin that an unfragmented datagram sharing a buffered BUFID is reported."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _packet(self, *, v6: bool, num: int, fo: int, mf: bool, payload: bytes):
        """A fragment of the one BUFID every case shares."""
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data.ip import Packet

        if v6:
            src, dst, ihl = ip_address('2001:db8::1'), ip_address('2001:db8::2'), 40
        else:
            src, dst, ihl = ip_address('192.0.2.1'), ip_address('192.0.2.2'), 20
        return Packet((src, dst, 9, TransType.UDP), num, fo, ihl, mf, ihl + len(payload),
                      b'H' * ihl, bytearray(payload), 1000.0 + num)

    def _reassemble(self, cls, packets, strict: bool):
        reasm = cls(strict=strict)
        for packet in packets:
            reasm(packet)
        return reasm, [(datagram.index, datagram.completed, datagram.payload) for datagram in reasm.datagram]

    def test_ipv4_flushes_the_buffer_and_reports_the_datagram(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.ipv4 import IPv4

        packets = [self._packet(v6=False, num=1, fo=0, mf=True, payload=b'A' * 16),
                   self._packet(v6=False, num=2, fo=0, mf=False, payload=b'B' * 16)]
        for strict in (True, False):
            with self.subTest(strict=strict):
                reasm, datagrams = self._reassemble(IPv4, packets, strict)
                flushed = (b'A' * 16,) if strict else b'A' * 16
                self.assertEqual(datagrams, [((1,), Completion.PARTIAL, flushed),
                                             ((2,), Completion.COMPLETE, b'B' * 16)])
                self.assertEqual(reasm._buffer, {})

    def test_ipv6_atomic_fragment_leaves_the_buffer_alone(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.ipv6 import IPv6

        packets = [self._packet(v6=True, num=1, fo=0, mf=True, payload=b'A' * 16),
                   self._packet(v6=True, num=2, fo=0, mf=False, payload=b'B' * 16),
                   self._packet(v6=True, num=3, fo=16, mf=False, payload=b'C' * 16)]
        for strict in (True, False):
            with self.subTest(strict=strict):
                reasm, datagrams = self._reassemble(IPv6, packets, strict)
                self.assertEqual(datagrams, [((2,), Completion.COMPLETE, b'B' * 16),
                                             ((1, 3), Completion.COMPLETE, b'A' * 16 + b'C' * 16)])
                self.assertEqual(reasm._buffer, {})


if __name__ == '__main__':
    unittest.main()
