# -*- coding: utf-8 -*-
"""An IP reassembly buffer is sized to the fragments it holds. C.f. #2957.

The data buffer and ``RCVBT`` start empty and grow to the furthest octet a
fragment reaches, never past ``IP_MAX_LENGTH`` unless a Total Length 0 fragment
grows them past it (#1555). Guards against allocating both at their largest for
every buffer, 72 KiB for each in-flight datagram identifier.

The rest pins what is reported: the octets past the buffer's end, up to the
total data length, read as a hole, zero-filled in a contiguous payload, and a
block past the end of ``RCVBT`` is not received. Reading the datagrams while a
buffer is in flight leaves that buffer as it was.

Every case builds its fragments in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

from ipaddress import ip_address
import unittest

from tests._support import reimport_once_per_class

#: The largest Fragment Offset, 8191 eight-octet units, in octets.
LAST = 65528

#: Datagram octets, with no zero octet in them, so a hole shows.
DATA = (bytes(range(1, 256)) * 18)[:4444]


class TestIPReassemblyBufferSizing(unittest.TestCase):
    """Pin how far an IP reassembly buffer grows, and what it reports."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _packet(self, *, num: int, fo: int, mf: bool, payload: bytes, tl: 'int | None' = None):
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.ip.data import Packet

        bufid = (ip_address('192.0.2.1'), ip_address('198.51.100.2'), 7, TransType.UDP)
        return Packet(bufid, num, fo, 20, mf, 20 + len(payload) if tl is None else tl,
                      b'H' * 20, bytearray(payload), 1000.0 + num)

    def _classes(self):
        from pcapkit.foundation.reassembly.ipv4.reassembly import IPv4
        from pcapkit.foundation.reassembly.ipv6.reassembly import IPv6

        return IPv4, IPv6

    def _sizes(self, reasm):
        buf, = reasm._buffer.values()  # pylint: disable=protected-access
        return len(buf.datagram), len(buf.RCVBT)

    def test_a_buffer_grows_to_the_furthest_octet_its_fragments_reach(self) -> None:
        from pcapkit.foundation.reassembly.data import Completion

        for cls in self._classes():
            with self.subTest(cls=cls.__name__):
                reasm = cls(strict=True)
                reasm(self._packet(num=1, fo=0, mf=True, payload=DATA[:1480]))
                self.assertEqual(self._sizes(reasm), (1480, 185))
                reasm(self._packet(num=2, fo=2960, mf=True, payload=DATA[2960:4440]))
                self.assertEqual(self._sizes(reasm), (4440, 555))
                reasm(self._packet(num=3, fo=1480, mf=True, payload=DATA[1480:2960]))
                self.assertEqual(self._sizes(reasm), (4440, 555))
                reasm(self._packet(num=4, fo=4440, mf=False, payload=DATA[4440:4444]))
                self.assertEqual(reasm._buffer, {})  # pylint: disable=protected-access
                datagram, = reasm.datagram
                self.assertIs(datagram.completed, Completion.COMPLETE)
                self.assertEqual(datagram.payload, DATA)

    def test_a_declared_fragment_never_grows_it_past_ip_max_length(self) -> None:
        # 8 octets at the largest offset are clipped to 7, at the 65,535th
        # octet; with Total Length 0 they grow an IPv4 buffer past it (#1555)
        from pcapkit.corekit.const.ip_header import IP_MAX_LENGTH
        from pcapkit.foundation.reassembly.ipv4.reassembly import IPv4

        for cls in self._classes():
            with self.subTest(cls=cls.__name__):
                reasm = cls(strict=True)
                reasm(self._packet(num=1, fo=LAST, mf=True, payload=b'A' * 8))
                self.assertEqual(self._sizes(reasm), (IP_MAX_LENGTH, 8192))

        reasm = IPv4(strict=True)
        reasm(self._packet(num=1, fo=LAST, mf=True, payload=b'A' * 8, tl=0))
        self.assertEqual(self._sizes(reasm), (LAST + 8, 8192))

    def test_a_held_buffer_is_left_as_it_was_by_reading_the_datagrams(self) -> None:
        # the final fragment declares 32 octets and carries 5, so the buffer
        # ends 27 octets short of the total data length
        for cls in self._classes():
            for strict in (True, False):
                with self.subTest(cls=cls.__name__, strict=strict):
                    reasm = cls(strict=strict)
                    reasm(self._packet(num=1, fo=0, mf=True, payload=DATA[:8]))
                    reasm(self._packet(num=2, fo=8, mf=False, payload=DATA[8:13], tl=52))
                    reasm.datagram  # pylint: disable=pointless-statement
                    self.assertEqual(self._sizes(reasm), (13, 2))

    def test_the_octets_past_the_buffer_up_to_the_total_length_are_a_hole(self) -> None:
        from pcapkit.foundation.reassembly.data import Completion

        for cls in self._classes():
            for strict in (True, False):
                with self.subTest(cls=cls.__name__, strict=strict):
                    reasm = cls(strict=strict)
                    reasm(self._packet(num=1, fo=0, mf=True, payload=DATA[:8]))
                    reasm(self._packet(num=2, fo=8, mf=False, payload=DATA[8:13], tl=52))
                    datagram, = reasm.datagram
                    self.assertIs(datagram.completed, Completion.PARTIAL)
                    self.assertEqual(datagram.payload,
                                     (DATA[:8],) if strict else DATA[:13] + bytes(27))

    def test_a_block_past_the_end_of_rcvbt_is_not_received(self) -> None:
        # a final fragment declaring 100 octets and carrying none marks no
        # block, so the datagram's last 13 blocks are past the end of ``RCVBT``
        from pcapkit.foundation.reassembly.data import Completion

        for cls in self._classes():
            for strict in (True, False):
                with self.subTest(cls=cls.__name__, strict=strict):
                    reasm = cls(strict=strict)
                    reasm(self._packet(num=1, fo=0, mf=True, payload=DATA[:8]))
                    reasm(self._packet(num=2, fo=8, mf=False, payload=b'', tl=120))
                    datagram, = reasm.datagram
                    self.assertIs(datagram.completed, Completion.PARTIAL)
                    self.assertEqual(datagram.payload,
                                     (DATA[:8],) if strict else DATA[:8] + bytes(100))

    def test_a_received_block_reaching_past_the_buffer_reads_zeros_up_to_the_total_length(self) -> None:
        # The 3-octet final fragment at 16 marks its block 16-23, and a later
        # final fragment at 8 declares 16 octets but carries 8, so the total
        # data length is 24 while the buffer ends at octet 19. IPv4 only: IPv6
        # abandons the datagram on the second fragment's overlap (#2547).
        from pcapkit.foundation.reassembly.data import Completion
        from pcapkit.foundation.reassembly.ipv4.reassembly import IPv4

        tail = DATA[8:19] + bytes(5)
        for strict in (True, False):
            with self.subTest(strict=strict):
                reasm = IPv4(strict=strict)
                reasm(self._packet(num=1, fo=16, mf=False, payload=DATA[16:19]))
                reasm(self._packet(num=2, fo=8, mf=False, payload=DATA[8:16], tl=36))
                datagram, = reasm.datagram
                self.assertIs(datagram.completed, Completion.PARTIAL)
                self.assertEqual(datagram.payload, (tail,) if strict else bytes(8) + tail)

                reasm(self._packet(num=3, fo=0, mf=True, payload=DATA[:8]))
                datagram, = reasm.datagram
                self.assertIs(datagram.completed, Completion.COMPLETE)
                self.assertEqual(datagram.payload, DATA[:8] + tail)


if __name__ == '__main__':
    unittest.main()
