# -*- coding: utf-8 -*-
"""IP reassembly buffers a fragment that reaches octet 65,528.

GitHub issue #1565. The data buffer holds 65,535 octets, but the received-bit
table ``RCVBT`` had only 8,191 entries, one per 8-octet block, which cover
octets 0 to 65,527. A fragment whose data reached octet 65,528 -- the last
fragment at the largest Fragment Offset, 8191, among them -- made
:meth:`IP._detect_conflicts <pcapkit.foundation.reassembly.ip.IP._detect_conflicts>`
index past the table, and the whole extraction raised :exc:`IndexError`. The
table now has 8,192 entries, the partial last block included.

Every case builds its fragments in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

from ipaddress import ip_address
import unittest

from tests._support import reimport_once_per_class

#: The largest Fragment Offset, 8191 eight-octet units, in octets.
LAST = 65528

#: The octets before :data:`LAST`, with no zero octet in them, so a hole shows.
BODY = (bytes(range(1, 256)) * 257)[:LAST]


class TestIPReassemblyLastFragmentOffset(unittest.TestCase):
    """Pin what the IP reassemblers report for a fragment at the largest offset."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _packet(self, *, num: int, fo: int, mf: bool, payload: bytes, tl: 'int | None' = None):
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data.ip import Packet

        bufid = (ip_address('192.0.2.1'), ip_address('198.51.100.2'), 7, TransType.UDP)
        return Packet(bufid, num, fo, 20, mf, 20 + len(payload) if tl is None else tl,
                      b'H' * 20, bytearray(payload), 1000.0 + num)

    def _classes(self):
        from pcapkit.foundation.reassembly.ipv4 import IPv4
        from pcapkit.foundation.reassembly.ipv6 import IPv6

        return IPv4, IPv6

    def _body(self):
        """Fragments carrying :data:`BODY`, each at most 65,515 octets as a Total Length allows."""
        return (self._packet(num=1, fo=0, mf=True, payload=BODY[:32768]),
                self._packet(num=2, fo=32768, mf=True, payload=BODY[32768:]))

    def test_a_lone_fragment_at_the_largest_offset_is_buffered(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion

        for cls in self._classes():
            for size in (1, 7):
                for mf in (False, True):
                    for strict in (True, False):
                        with self.subTest(cls=cls.__name__, size=size, mf=mf, strict=strict):
                            tail = b'A' * size
                            reasm = cls(strict=strict)
                            reasm(self._packet(num=1, fo=LAST, mf=mf, payload=tail))
                            datagram, = reasm.datagram
                            self.assertIs(datagram.completed, Completion.PARTIAL)
                            self.assertEqual(datagram.index, (1,))
                            if strict and mf:
                                # a non-final fragment ending mid-block was cut
                                # or is malformed, so its block is not received
                                # (#1567) -- and the datagram is still reported
                                # (#1566)
                                self.assertEqual(datagram.payload, ())
                            elif strict:
                                run, = datagram.payload
                                self.assertEqual(run[:size], tail)
                            elif mf:
                                # the length is unknown, and the prefix before
                                # the first hole is empty
                                self.assertEqual(datagram.payload, b'')
                            else:
                                self.assertEqual(datagram.payload, bytes(LAST) + tail)

    def test_the_last_fragment_at_the_largest_offset_completes_its_datagram(self) -> None:
        # IPv6 only: an IPv4 datagram reaching octet 65,528 is too long for its
        # Total Length, header included, so it never completes (#1585).
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.ipv6 import IPv6

        for cls in (IPv6,):
            for size in (1, 7):
                for strict in (True, False):
                    with self.subTest(cls=cls.__name__, size=size, strict=strict):
                        tail = b'A' * size
                        reasm = cls(strict=strict)
                        for packet in self._body():
                            reasm(packet)
                        reasm(self._packet(num=3, fo=LAST, mf=False, payload=tail))
                        datagram, = reasm.datagram
                        self.assertIs(datagram.completed, Completion.COMPLETE)
                        self.assertEqual(datagram.index, (1, 2, 3))
                        self.assertEqual(datagram.payload, BODY + tail)
                        self.assertEqual(datagram.conflict, ())

    def test_a_non_final_fragment_at_the_largest_offset_leaves_the_datagram_open(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion

        for cls in self._classes():
            for size in (1, 7):
                for strict in (True, False):
                    with self.subTest(cls=cls.__name__, size=size, strict=strict):
                        tail = b'A' * size
                        reasm = cls(strict=strict)
                        for packet in self._body():
                            reasm(packet)
                        reasm(self._packet(num=3, fo=LAST, mf=True, payload=tail))
                        datagram, = reasm.datagram
                        self.assertIs(datagram.completed, Completion.PARTIAL)
                        self.assertEqual(datagram.index, (1, 2, 3))
                        if strict:
                            run, = datagram.payload
                        else:
                            run = datagram.payload
                        # the tail ends mid-block on a non-final fragment, so
                        # its block is not received (#1567)
                        self.assertEqual(run, BODY)

    def test_a_tso_fragment_at_the_largest_offset_composes_with_the_buffer_growth(self) -> None:
        # Total Length 0 (#1555): 7 octets end exactly at the preallocated
        # buffer's end, 9 run past it and grow it.
        from pcapkit.foundation.reassembly.data.data import Completion

        for size in (7, 9):
            for strict in (True, False):
                with self.subTest(size=size, strict=strict):
                    tail = b'A' * size
                    reasm = self._classes()[0](strict=strict)
                    for packet in self._body():
                        reasm(packet)
                    reasm(self._packet(num=3, fo=LAST, mf=False, payload=tail, tl=0))
                    datagram, = reasm.datagram
                    self.assertIs(datagram.completed, Completion.COMPLETE)
                    self.assertEqual(datagram.payload, BODY + tail)


if __name__ == '__main__':
    unittest.main()
