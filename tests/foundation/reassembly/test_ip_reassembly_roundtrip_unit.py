# -*- coding: utf-8 -*-
"""IP reassembly reports exactly the octets it received.

- GitHub issue #1357: a snaplen-truncated fragment shrank the data buffer and
  marked its whole declared range received, so the datagram came out
  ``COMPLETE`` with zeros in it and the rest shifted.
- GitHub issue #1358: ``strict`` runs copied whole 8-octet blocks past the
  total data length, and dropped a run that reached the end of the bit table.
- GitHub issue #1359: a datagram whose total data length is ``0`` never
  completed, because the length was tested for truthiness.

Every case builds its fragments in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

from ipaddress import ip_address
import unittest

from tests._support import reimport_once_per_class

#: A 2000-octet payload with no zero octet in it, so a zero-filled hole shows.
FULL = (bytes(range(1, 256)) * 8)[:2000]


class TestIPReassemblyRoundTrip(unittest.TestCase):
    """Pin what the IP reassembler reports for truncated, sparse and empty datagrams."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _packet(num, fo, mf, payload, *, tl=None):
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data.ip import Packet

        tl = 20 + len(payload) if tl is None else tl
        bufid = (ip_address('192.0.2.1'), ip_address('198.51.100.2'), 42, TransType.UDP)
        return Packet(bufid, num, fo, 20, mf, tl, b'ip-header' if fo == 0 else b'',
                      bytearray(payload), 1000.0)

    @staticmethod
    def _reassembler(strict):
        from pcapkit.foundation.reassembly.ipv4 import IPv4

        return IPv4(strict=strict)

    def _truncated(self, order, strict):
        frags = [(0, True, FULL[0:800]), (800, True, FULL[800:1600]), (1600, False, FULL[1600:])]
        reasm = self._reassembler(strict)
        for num, idx in enumerate(order, 1):
            fo, mf, payload = frags[idx]
            declared = len(payload)
            if idx == 1:
                payload = payload[:500]  # snaplen cut: 500 of 800 octets held
            reasm(self._packet(num, fo, mf, payload, tl=20 + declared))
        return reasm

    def test_truncated_fragment_leaves_a_hole_strict(self) -> None:
        for order in ([0, 1, 2], [2, 1, 0], [0, 2, 1]):
            with self.subTest(order=order):
                datagram, = self._truncated(order, strict=True).datagram
                self.assertEqual(datagram.completed.name, 'PARTIAL')
                # 800 + 500 = 1300 octets held, of which 162 whole blocks
                self.assertEqual(datagram.payload, (FULL[:1296], FULL[1600:]))

    def test_truncated_fragment_keeps_buffer_length_loose(self) -> None:
        for order in ([0, 1, 2], [2, 1, 0], [0, 2, 1]):
            with self.subTest(order=order):
                reasm = self._truncated(order, strict=False)
                datagram, = reasm.datagram
                self.assertEqual(datagram.completed.name, 'PARTIAL')
                self.assertEqual(len(datagram.payload), 2000)
                self.assertEqual(datagram.payload[:1300], FULL[:1300])
                self.assertEqual(datagram.payload[1300:1600], bytes(300))
                self.assertEqual(datagram.payload[1600:], FULL[1600:])

    def test_strict_run_clipped_at_total_data_length(self) -> None:
        reasm = self._reassembler(strict=True)
        reasm(self._packet(1, 0, True, b'A' * 1480))
        reasm(self._packet(2, 2960, False, b'C' * 43))
        datagram, = reasm.datagram
        self.assertEqual(datagram.completed.name, 'PARTIAL')
        self.assertEqual(datagram.payload, (b'A' * 1480, b'C' * 43))

    def test_strict_run_at_end_of_bit_table_is_kept(self) -> None:
        reasm = self._reassembler(strict=True)
        reasm(self._packet(1, 0, True, b'A' * 8))
        reasm(self._packet(2, 65520, False, b'Z' * 7))
        datagram, = reasm.datagram
        self.assertEqual(datagram.payload, (b'A' * 8, b'Z' * 7))

    def test_zero_length_unfragmented_datagram_completes(self) -> None:
        for strict in (True, False):
            with self.subTest(strict=strict):
                reasm = self._reassembler(strict)
                reasm(self._packet(1, 0, False, b''))
                self.assertEqual(dict(reasm._buffer), {})
                datagram, = reasm.datagram
                self.assertEqual(datagram.completed.name, 'COMPLETE')
                self.assertEqual(datagram.payload, b'')

    def test_completes_when_the_last_hole_fills_after_the_final_fragment(self) -> None:
        reasm = self._reassembler(strict=True)
        reasm(self._packet(1, 8, False, b'ijkl'))
        reasm(self._packet(2, 0, True, b'abcdefgh'))
        self.assertEqual(dict(reasm._buffer), {})
        datagram, = reasm.datagram
        self.assertEqual(datagram.completed.name, 'COMPLETE')
        self.assertEqual(datagram.payload, b'abcdefghijkl')


if __name__ == '__main__':
    unittest.main()
