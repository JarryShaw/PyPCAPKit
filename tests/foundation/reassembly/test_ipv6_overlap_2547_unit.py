# -*- coding: utf-8 -*-
"""An overlapping IPv6 fragment abandons its datagram.

GitHub issue #2547. IPv6 reassembly inherited IPv4's handling of an overlap,
where the arriving fragment overwrites the octets it overlaps as RFC 791 has it
do, so an overlapped datagram still came out ``COMPLETE``. RFC 8200 section 4.5
says otherwise: "If any of the fragments being reassembled overlap with any
other fragments being reassembled for the same packet, reassembly of that packet
must be abandoned and all the fragments that have been received for that packet
must be discarded". The abandoned datagram is reported as ``OVERLAP``, the way a
timed-out one is reported as ``TIMEOUT``.

The same section lets an implementation "drop exact duplicate fragments while
keeping the other fragments belonging to the same packet", and IPv6 reassembly
does: a fragment matching one already merged in offset, length, **M** flag and
data changes nothing but the datagram's ``index``.

Every case builds its fragments in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

from ipaddress import ip_address
import unittest

from tests._support import reimport_once_per_class

#: Datagram octets, with no zero octet in them, so a hole shows.
DATA = bytes(range(1, 33))


class TestIPv6OverlapAbandonsDatagram(unittest.TestCase):
    """Pin RFC 8200 section 4.5's overlap rule on IPv6, and RFC 791's on IPv4."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _packet(self, *, num: int, fo: int, mf: bool, payload: bytes, v6: bool = True,
                header: bytes = b''):
        """A fragment of the one BUFID every case shares."""
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data.ip import Packet

        if v6:
            src, dst, ihl = ip_address('2001:db8::1'), ip_address('2001:db8::2'), 40
        else:
            src, dst, ihl = ip_address('192.0.2.1'), ip_address('192.0.2.2'), 20
        header = header or b'H' * ihl
        return Packet((src, dst, 7, TransType.UDP), num, fo, len(header), mf,
                      len(header) + len(payload), header, bytearray(payload), 1000.0)

    def _reassemble(self, packets, *, strict: bool = True, v6: bool = True):
        from pcapkit.foundation.reassembly.ipv4 import IPv4
        from pcapkit.foundation.reassembly.ipv6 import IPv6

        reasm = (IPv6 if v6 else IPv4)(strict=strict)
        for packet in packets:
            reasm(packet)
        return reasm

    def test_an_overlapping_first_fragment_abandons_the_datagram(self) -> None:
        # the offset-zero fragment arrives last and reaches into the one at 8
        from pcapkit.foundation.reassembly.data.data import Completion

        reasm = self._reassemble([
            self._packet(num=1, fo=8, mf=True, payload=DATA[8:16]),
            self._packet(num=2, fo=16, mf=False, payload=DATA[16:20]),
            self._packet(num=3, fo=0, mf=True, payload=DATA[:16]),
        ])
        datagram, = reasm.datagram
        self.assertIs(datagram.completed, Completion.OVERLAP)
        self.assertEqual(datagram.index, (1, 2, 3))
        self.assertEqual(datagram.payload, (DATA[8:20],))
        self.assertIsNone(datagram.packet)
        # the discarded fragment's header is not kept either
        self.assertEqual(datagram.header, b'')
        self.assertEqual(reasm._buffer, {})

    def test_an_overlapping_middle_fragment_abandons_the_datagram(self) -> None:
        # the octets it overlaps are the same, which RFC 8200 does not excuse
        from pcapkit.foundation.reassembly.data.data import Completion

        reasm = self._reassemble([
            self._packet(num=1, fo=0, mf=True, payload=DATA[:16]),
            self._packet(num=2, fo=24, mf=False, payload=DATA[24:28]),
            self._packet(num=3, fo=8, mf=True, payload=DATA[8:24]),
        ])
        datagram, = reasm.datagram
        self.assertIs(datagram.completed, Completion.OVERLAP)
        self.assertEqual(datagram.index, (1, 2, 3))
        self.assertEqual(datagram.payload, (DATA[:16], DATA[24:28]))
        self.assertEqual(datagram.conflict, ())

    def test_an_overlapping_last_fragment_abandons_the_datagram(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion

        other = bytes(b ^ 0xFF for b in DATA[8:20])
        for strict in (True, False):
            with self.subTest(strict=strict):
                reasm = self._reassemble([
                    self._packet(num=1, fo=0, mf=True, payload=DATA[:16]),
                    self._packet(num=2, fo=8, mf=False, payload=other),
                ], strict=strict)
                datagram, = reasm.datagram
                self.assertIs(datagram.completed, Completion.OVERLAP)
                self.assertEqual(datagram.index, (1, 2))
                # the first copy stays; the overlapping one is never written
                self.assertEqual(datagram.payload, (DATA[:16],) if strict else DATA[:16])
                self.assertEqual(datagram.conflict, ((8, 15),))

    def test_the_issues_repro_is_abandoned_and_its_last_fragment_starts_anew(self) -> None:
        # two different copies of the offset-zero fragment; the final fragment
        # comes after the abandonment, so it opens a buffer of its own
        from pcapkit.foundation.reassembly.data.data import Completion

        reasm = self._reassemble([
            self._packet(num=1, fo=0, mf=True, payload=b'A' * 8),
            self._packet(num=2, fo=0, mf=True, payload=b'B' * 8),
            self._packet(num=3, fo=8, mf=False, payload=b'ZZZZ'),
        ])
        late, abandoned = reasm.datagram
        self.assertIs(abandoned.completed, Completion.OVERLAP)
        self.assertEqual(abandoned.index, (1, 2))
        self.assertEqual(abandoned.payload, (b'A' * 8,))
        self.assertEqual(abandoned.conflict, ((0, 7),))
        self.assertIs(late.completed, Completion.PARTIAL)
        self.assertEqual(late.index, (3,))
        self.assertEqual(late.payload, (b'ZZZZ',))

    def test_the_same_extent_with_another_m_flag_is_not_a_duplicate(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion

        reasm = self._reassemble([
            self._packet(num=1, fo=8, mf=True, payload=DATA[8:16]),
            self._packet(num=2, fo=8, mf=False, payload=DATA[8:16]),
            self._packet(num=3, fo=0, mf=True, payload=DATA[:8]),
        ])
        late, abandoned = reasm.datagram
        self.assertIs(abandoned.completed, Completion.OVERLAP)
        self.assertEqual(abandoned.index, (1, 2))
        self.assertIs(late.completed, Completion.PARTIAL)
        self.assertEqual(late.index, (3,))

    def test_exact_duplicates_are_dropped_and_the_datagram_completes(self) -> None:
        # a duplicate of the first, a middle and the last fragment, each while
        # the datagram is still open
        from pcapkit.foundation.reassembly.data.data import Completion

        for strict in (True, False):
            with self.subTest(strict=strict):
                reasm = self._reassemble([
                    self._packet(num=1, fo=0, mf=True, payload=DATA[:8]),
                    self._packet(num=2, fo=0, mf=True, payload=DATA[:8]),
                    self._packet(num=3, fo=8, mf=True, payload=DATA[8:16]),
                    self._packet(num=4, fo=8, mf=True, payload=DATA[8:16]),
                    self._packet(num=5, fo=24, mf=False, payload=DATA[24:28]),
                    self._packet(num=6, fo=24, mf=False, payload=DATA[24:28]),
                    self._packet(num=7, fo=16, mf=True, payload=DATA[16:24]),
                ], strict=strict)
                datagram, = reasm.datagram
                self.assertIs(datagram.completed, Completion.COMPLETE)
                self.assertEqual(datagram.payload, DATA[:28])
                self.assertEqual(datagram.index, (1, 2, 3, 4, 5, 6, 7))
                self.assertEqual(datagram.conflict, ())

    def test_a_dropped_duplicate_does_not_replace_the_kept_header(self) -> None:
        # RFC 8200 retains only the offset-zero fragment's headers, and those
        # before the Fragment header may differ between copies
        from pcapkit.foundation.reassembly.data.data import Completion

        kept, other = b'K' * 40, b'D' * 40
        reasm = self._reassemble([
            self._packet(num=1, fo=0, mf=True, payload=DATA[:8], header=kept),
            self._packet(num=2, fo=0, mf=True, payload=DATA[:8], header=other),
            self._packet(num=3, fo=8, mf=False, payload=DATA[8:12]),
        ])
        datagram, = reasm.datagram
        self.assertIs(datagram.completed, Completion.COMPLETE)
        self.assertEqual(datagram.header, kept)

    def test_fragments_that_only_abut_complete_the_datagram(self) -> None:
        # the control: out of order, touching but never sharing an octet
        from pcapkit.foundation.reassembly.data.data import Completion

        for strict in (True, False):
            with self.subTest(strict=strict):
                reasm = self._reassemble([
                    self._packet(num=1, fo=16, mf=False, payload=DATA[16:20]),
                    self._packet(num=2, fo=0, mf=True, payload=DATA[:8]),
                    self._packet(num=3, fo=8, mf=True, payload=DATA[8:16]),
                ], strict=strict)
                datagram, = reasm.datagram
                self.assertIs(datagram.completed, Completion.COMPLETE)
                self.assertEqual(datagram.payload, DATA[:20])
                self.assertEqual(datagram.conflict, ())

    def test_a_fragment_carrying_no_data_overlaps_nothing(self) -> None:
        # an empty final fragment shares no octet, even with a duplicate of itself
        from pcapkit.foundation.reassembly.data.data import Completion

        reasm = self._reassemble([
            self._packet(num=1, fo=8, mf=True, payload=DATA[8:16]),
            self._packet(num=2, fo=16, mf=False, payload=b''),
            self._packet(num=3, fo=16, mf=False, payload=b''),
            self._packet(num=4, fo=0, mf=True, payload=DATA[:8]),
        ])
        datagram, = reasm.datagram
        self.assertIs(datagram.completed, Completion.COMPLETE)
        self.assertEqual(datagram.payload, DATA[:16])

    def test_the_abandonment_is_logged(self) -> None:
        with self.assertLogs('pcapkit.foundation.reassembly.ip', level='DEBUG') as logs:
            self._reassemble([
                self._packet(num=1, fo=0, mf=True, payload=DATA[:16]),
                self._packet(num=2, fo=8, mf=True, payload=DATA[8:16]),
            ])
        self.assertEqual(len(logs.records), 1)
        self.assertIn('on frame 2, which overlaps octets 0-15', logs.output[0])

    def test_ipv4_still_overwrites_as_rfc_791_asks(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion

        reasm = self._reassemble([
            self._packet(num=1, fo=0, mf=True, payload=b'A' * 8, v6=False),
            self._packet(num=2, fo=0, mf=True, payload=b'B' * 8, v6=False),
            self._packet(num=3, fo=8, mf=False, payload=b'ZZZZ', v6=False),
        ], v6=False)
        datagram, = reasm.datagram
        self.assertIs(datagram.completed, Completion.COMPLETE)
        self.assertEqual(datagram.index, (1, 2, 3))
        self.assertEqual(datagram.payload, b'B' * 8 + b'ZZZZ')
        self.assertEqual(datagram.conflict, ((0, 7),))


if __name__ == '__main__':
    unittest.main()
