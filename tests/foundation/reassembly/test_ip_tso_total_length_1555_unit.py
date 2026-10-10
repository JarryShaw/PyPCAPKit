# -*- coding: utf-8 -*-
"""IP reassembly reads a Total Length of 0 as the fragment's captured length.

GitHub issue #1555. A capture taken on a host that offloads TCP segmentation
records its IPv4 headers with Total Length 0, and since #1547 the adapters hand
over the rest of the captured frame as the payload. The reassembler still took
the fragment's data length from ``tl - ihl``, i.e. ``-20``, so every such
datagram came out ``PARTIAL`` and empty. It now takes the payload's own length,
as Wireshark 4.6.9 does ("presumed TSO") before it reassembles anything. A
non-final fragment's partial last block can then only be a snaplen cut, so it is
left as a hole.

Every case builds its fragments in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

from ipaddress import ip_address
import unittest

from tests._support import reimport_once_per_class

#: A 104-octet datagram payload with no zero octet in it, so a hole shows.
DATA = (bytes(range(1, 256)) * 2)[:104]

#: Past the 65535 octets a Total Length can declare, as with Linux's BIG TCP.
BIG = (bytes(range(1, 256)) * 300)[:70000]


class TestIPReassemblyTSOTotalLength(unittest.TestCase):
    """Pin what the IP reassembler reports for fragments whose Total Length is 0."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _packet(self, *, num: int, fo: int, mf: bool, payload: bytes, tl: int):
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data.ip import Packet

        bufid = (ip_address('192.0.2.1'), ip_address('198.51.100.2'), 0x1234, TransType.UDP)
        return Packet(bufid, num, fo, 20, mf, tl, b'H' * 20, bytearray(payload), 1000.0 + num)

    def _reassemble(self, *packets, strict: bool):
        from pcapkit.foundation.reassembly.ipv4 import IPv4

        reasm = IPv4(strict=strict)
        for packet in packets:
            reasm(packet)
        # reading ``datagram`` submits whatever is still buffered
        return reasm.datagram

    def test_an_unfragmented_tso_datagram_is_whole(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion

        for strict in (True, False):
            with self.subTest(strict=strict):
                datagram, = self._reassemble(self._packet(num=1, fo=0, mf=False, payload=DATA, tl=0),
                                             strict=strict)
                self.assertIs(datagram.completed, Completion.COMPLETE)
                self.assertEqual(datagram.index, (1,))
                self.assertEqual(datagram.header, b'H' * 20)
                self.assertEqual(datagram.payload, DATA)

                # an empty one is whole too, and empty
                datagram, = self._reassemble(self._packet(num=1, fo=0, mf=False, payload=b'', tl=0),
                                             strict=strict)
                self.assertIs(datagram.completed, Completion.COMPLETE)
                self.assertEqual(datagram.payload, b'')

    def test_a_zero_total_length_on_either_fragment_is_its_captured_length(self) -> None:
        # Measured with Wireshark 4.6.9 on these two fragments, the Total Length
        # of either one zeroed: "Total Length: 68 bytes (reported as 0, presumed
        # to be because of "TCP segmentation offload" (TSO))", then "[2 IPv4
        # Fragments (104 bytes): #1(56), #2(48)]". A malformed fragment is read
        # the same way, so no octet the capture holds is dropped.
        from pcapkit.foundation.reassembly.data.data import Completion

        first, final = DATA[:56], DATA[56:]
        for zeroed in (0, 1):
            for strict in (True, False):
                with self.subTest(zeroed=zeroed, strict=strict):
                    datagram, = self._reassemble(
                        self._packet(num=1, fo=0, mf=True, payload=first, tl=0 if zeroed == 0 else 76),
                        self._packet(num=2, fo=56, mf=False, payload=final, tl=0 if zeroed == 1 else 68),
                        strict=strict,
                    )
                    self.assertIs(datagram.completed, Completion.COMPLETE)
                    self.assertEqual(datagram.index, (1, 2))
                    self.assertEqual(datagram.payload, DATA)
                    self.assertEqual(datagram.conflict, ())

    def test_a_cut_non_final_tso_fragment_leaves_a_hole(self) -> None:
        # The first fragment cut by the snaplen from 56 to 52 octets. A non-final
        # fragment carries a multiple of 8 octets, so with Total Length 0 its
        # partial last block is a cut, and the datagram reads exactly as it does
        # with the real Total Length of 76: octets 52 to 55 are a hole.
        from pcapkit.foundation.reassembly.data.data import Completion

        for final_tl in (68, 0):
            for strict in (True, False):
                with self.subTest(final_tl=final_tl, strict=strict):
                    results = [self._reassemble(
                        self._packet(num=1, fo=0, mf=True, payload=DATA[:52], tl=first_tl),
                        self._packet(num=2, fo=56, mf=False, payload=DATA[56:], tl=final_tl),
                        strict=strict,
                    ) for first_tl in (0, 76)]
                    (zeroed,), (declared,) = results
                    self.assertIs(zeroed.completed, Completion.PARTIAL)
                    self.assertEqual(zeroed.payload, declared.payload)
                    if strict:
                        self.assertEqual(zeroed.payload, (DATA[:48], DATA[56:]))
                    else:
                        self.assertEqual(zeroed.payload, DATA[:52] + bytes(4) + DATA[56:])

    def test_a_tso_datagram_past_65535_octets_is_kept_whole(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion

        for strict in (True, False):
            with self.subTest(strict=strict):
                datagram, = self._reassemble(self._packet(num=1, fo=0, mf=False, payload=BIG, tl=0),
                                             strict=strict)
                self.assertIs(datagram.completed, Completion.COMPLETE)
                self.assertEqual(len(datagram.payload), len(BIG))
                self.assertEqual(datagram.payload, BIG)

                # a final fragment carrying it past the end grows the buffer too
                datagram, = self._reassemble(
                    self._packet(num=1, fo=0, mf=True, payload=DATA[:56], tl=76),
                    self._packet(num=2, fo=56, mf=False, payload=BIG, tl=0),
                    strict=strict,
                )
                self.assertIs(datagram.completed, Completion.COMPLETE)
                self.assertEqual(datagram.payload, DATA[:56] + BIG)

    def test_a_missing_fragment_still_leaves_a_tso_datagram_incomplete(self) -> None:
        # Only the final fragment, with Total Length 0: its own octets are
        # received, but the first 56 never were.
        from pcapkit.foundation.reassembly.data.data import Completion

        datagram, = self._reassemble(self._packet(num=2, fo=56, mf=False, payload=DATA[56:], tl=0),
                                     strict=True)
        self.assertIs(datagram.completed, Completion.PARTIAL)
        self.assertEqual(datagram.payload, (DATA[56:],))

        datagram, = self._reassemble(self._packet(num=2, fo=56, mf=False, payload=DATA[56:], tl=0),
                                     strict=False)
        self.assertIs(datagram.completed, Completion.PARTIAL)
        self.assertEqual(datagram.payload, bytes(56) + DATA[56:])


if __name__ == '__main__':
    unittest.main()
