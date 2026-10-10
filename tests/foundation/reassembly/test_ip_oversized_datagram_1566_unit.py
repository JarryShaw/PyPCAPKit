# -*- coding: utf-8 -*-
"""An IP datagram longer than the data buffer is never complete.

GitHub issue #1566. The data buffer holds 65,535 octets and ``RCVBT`` 8,192
blocks. Both completion checks tested ``all(RCVBT[0:(TDL + 7) // 8])``, and the
slice stops silently at the table's end, so a final fragment declaring more data
than fits completed its datagram short. A datagram now completes only if its
total data length fits the buffer.

A fragment the buffer's end clips counts as cut there: its partial last block is
a hole. An 8-octet non-final fragment at the largest offset therefore received
no block, and strict mode then dropped its datagram, while a 7-octet one was
reported. #1567 leaves the 7-octet one's block clear too, and strict mode now
reports a datagram with no run received, as lax mode does.

Every case builds its fragments in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

from ipaddress import ip_address
import unittest

from tests._support import reimport_once_per_class

#: The largest Fragment Offset, 8191 eight-octet units, in octets.
LAST = 65528

#: The data buffer's length.
BUFFER = 65535

#: Datagram octets, with no zero octet in them, so a hole shows.
DATA = (bytes(range(1, 256)) * 258)[:65579]


class TestIPReassemblyOversizedDatagram(unittest.TestCase):
    """Pin that a datagram longer than the buffer is never ``COMPLETE``."""

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

    def test_a_final_fragment_declaring_more_than_the_buffer_does_not_complete(self) -> None:
        # The 7-octet final fragment marks the last block, so every block
        # reads received once the long one declares a total data length past
        # the buffer: 65579 is the issue's, and 65536 the shortest -- which a
        # check of ``(TDL + 7) // 8`` against ``len(RCVBT)`` lets through.
        from pcapkit.foundation.reassembly.data.data import Completion

        for cls in self._classes():
            for tdl in (65579, 65536):
                for strict in (True, False):
                    with self.subTest(cls=cls.__name__, tdl=tdl, strict=strict):
                        reasm = cls(strict=strict)
                        reasm(self._packet(num=1, fo=LAST, mf=False, payload=DATA[LAST:BUFFER]))
                        reasm(self._packet(num=2, fo=0, mf=True, payload=DATA[:64]))
                        reasm(self._packet(num=3, fo=64, mf=False, payload=DATA[64:tdl]))
                        datagram, = reasm.datagram
                        self.assertIs(datagram.completed, Completion.PARTIAL)
                        self.assertEqual(datagram.index, (1, 2, 3))
                        self.assertEqual(datagram.payload,
                                         (DATA[:BUFFER],) if strict else DATA[:BUFFER])
                        self.assertEqual(datagram.conflict, ())

    def test_the_issues_repro_is_partial(self) -> None:
        # Octets 0-65527, a malformed 7-octet non-final fragment at the largest
        # offset, then a final fragment at 64 declaring Total Length 65535,
        # of which 8 octets were captured.
        from pcapkit.foundation.reassembly.data.data import Completion

        for cls in self._classes():
            for strict in (True, False):
                with self.subTest(cls=cls.__name__, strict=strict):
                    reasm = cls(strict=strict)
                    for num, fo in enumerate(range(0, LAST, 4096), 1):
                        reasm(self._packet(num=num, fo=fo, mf=True, payload=DATA[fo:min(fo + 4096, LAST)]))
                    reasm(self._packet(num=20, fo=LAST, mf=True, payload=b'M' * 7))
                    reasm(self._packet(num=21, fo=64, mf=False, payload=DATA[64:72], tl=65535))
                    datagram, = reasm.datagram
                    self.assertIs(datagram.completed, Completion.PARTIAL)

    def test_a_fragment_the_buffer_clips_counts_like_a_cut_one(self) -> None:
        # 8 octets at the largest offset are clipped to 7; 7 octets on a
        # non-final fragment were cut. Neither receives its block, and both
        # report the same datagram.
        from pcapkit.foundation.reassembly.data.data import Completion

        for cls in self._classes():
            for strict in (True, False):
                with self.subTest(cls=cls.__name__, strict=strict):
                    reported = []
                    for size in (7, 8):
                        reasm = cls(strict=strict)
                        reasm(self._packet(num=1, fo=LAST, mf=True, payload=b'A' * size))
                        datagram, = reasm.datagram
                        self.assertIs(datagram.completed, Completion.PARTIAL)
                        self.assertEqual(datagram.index, (1,))
                        reported.append(datagram.payload)
                    self.assertEqual(reported, [()] * 2 if strict else [b''] * 2)

    def test_a_tso_fragment_past_the_buffer_grows_it_rather_than_being_clipped(self) -> None:
        # Total Length 0 (#1555): 8 octets at the largest offset end one past
        # the preallocated buffer, which grows to hold them, so their block is
        # received and every block reads received with the length still unknown.
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.ipv4 import IPv4

        for strict in (True, False):
            with self.subTest(strict=strict):
                reasm = IPv4(strict=strict)
                reasm(self._packet(num=1, fo=0, mf=True, payload=DATA[:32768]))
                reasm(self._packet(num=2, fo=32768, mf=True, payload=DATA[32768:LAST]))
                reasm(self._packet(num=3, fo=LAST, mf=True, payload=DATA[LAST:LAST + 8], tl=0))
                datagram, = reasm.datagram
                self.assertIs(datagram.completed, Completion.PARTIAL)
                self.assertEqual(datagram.payload,
                                 (DATA[:LAST + 8],) if strict else DATA[:LAST + 8])

    def test_strict_mode_reports_a_datagram_with_no_run_received(self) -> None:
        # a non-final fragment whose capture holds 5 of its 8 octets fills no
        # whole block
        from pcapkit.foundation.reassembly.data.data import Completion

        for cls in self._classes():
            for strict in (True, False):
                with self.subTest(cls=cls.__name__, strict=strict):
                    reasm = cls(strict=strict)
                    reasm(self._packet(num=1, fo=8, mf=True, payload=b'A' * 5, tl=28))
                    datagram, = reasm.datagram
                    self.assertIs(datagram.completed, Completion.PARTIAL)
                    self.assertEqual(datagram.index, (1,))
                    self.assertEqual(datagram.payload, () if strict else b'')


if __name__ == '__main__':
    unittest.main()
