# -*- coding: utf-8 -*-
"""A non-final IP fragment that ends mid-block leaves a hole, not zeros.

GitHub issue #1567. The IPv6 adapters derive ``tl`` from the captured payload,
so a fragment the snapshot length cut declares exactly what was captured, and
the reassembler marked its partial last block received. A 3-fragment datagram
with its first fragment cut from 64 octets to 60 then came out ``COMPLETE``,
octets 60-63 zero-filled; cut to 52, strict mode's first run carried 4
zero-filled octets.

Every fragment but the last carries a multiple of 8 octets
(:rfc:`8200#section-4.5`, :rfc:`791#section-3.2`), so only the final fragment's
partial last block is now counted received. That covers an IPv4 fragment whose
Total Length declares a non-multiple of 8 on a non-final fragment as well.

Every case builds its fragments in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

from ipaddress import ip_address
from itertools import permutations
import unittest

from tests._support import reimport_once_per_class

#: The datagram, with no zero octet in it, so a hole shows.
DATA = bytes((i * 7 + 3) % 251 + 1 for i in range(200))

#: Its three fragments, as ``(fragment offset, more fragments, payload)``.
FRAGMENTS = ((0, True, DATA[0:64]), (64, True, DATA[64:128]), (128, False, DATA[128:200]))


class TestIPReassemblyCutNonFinalFragment(unittest.TestCase):
    """Pin that a cut non-final fragment leaves the datagram incomplete."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _packet(self, *, num: int, fo: int, mf: bool, payload: bytes, tl: 'int | None' = None):
        """A fragment whose ``tl`` is, as the IPv6 adapters pass it, its captured length."""
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data.ip import Packet

        bufid = (ip_address('2001:db8::1'), ip_address('2001:db8::2'), 9, TransType.UDP)
        return Packet(bufid, num, fo, 40, mf, 40 + len(payload) if tl is None else tl,
                      b'H' * 40, bytearray(payload), 1000.0 + num)

    def _reassemble(self, cls, packets, strict: bool):
        reasm = cls(strict=strict)
        for packet in packets:
            reasm(packet)
        datagram, = reasm.datagram
        return datagram

    def test_a_cut_first_ipv6_fragment_leaves_a_hole(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.ipv6 import IPv6

        for cut in (60, 52):
            for strict in (True, False):
                with self.subTest(cut=cut, strict=strict):
                    packets = [self._packet(num=num, fo=fo, mf=mf, payload=payload[:cut] if fo == 0 else payload)
                               for num, (fo, mf, payload) in enumerate(FRAGMENTS, 1)]
                    datagram = self._reassemble(IPv6, packets, strict)
                    self.assertIs(datagram.completed, Completion.PARTIAL)
                    self.assertEqual(datagram.index, (1, 2, 3))
                    if strict:
                        # the cut fragment's whole blocks only
                        self.assertEqual(datagram.payload, (DATA[:cut // 8 * 8], DATA[64:]))
                    else:
                        # its real octets kept, the rest of the hole zero-filled
                        self.assertEqual(datagram.payload, DATA[:cut] + bytes(64 - cut) + DATA[64:])

    def test_a_non_final_ipv4_fragment_ending_mid_block_leaves_a_hole(self) -> None:
        # Total Length 100 declares 60 octets on a non-final fragment, all of
        # them captured: malformed rather than cut, but nobody sent 60-63.
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.ipv4 import IPv4

        for strict in (True, False):
            with self.subTest(strict=strict):
                packets = [self._packet(num=num, fo=fo, mf=mf, payload=payload[:60] if fo == 0 else payload)
                           for num, (fo, mf, payload) in enumerate(FRAGMENTS, 1)]
                datagram = self._reassemble(IPv4, packets, strict)
                self.assertIs(datagram.completed, Completion.PARTIAL)
                self.assertEqual(datagram.payload,
                                 (DATA[:56], DATA[64:]) if strict else DATA[:60] + bytes(4) + DATA[64:])

    def test_an_uncut_datagram_completes_byte_exact_in_any_order(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.ipv4 import IPv4
        from pcapkit.foundation.reassembly.ipv6 import IPv6

        for cls in (IPv4, IPv6):
            for order in permutations(range(3)):
                for strict in (True, False):
                    with self.subTest(cls=cls.__name__, order=order, strict=strict):
                        packets = [self._packet(num=index + 1, fo=FRAGMENTS[index][0], mf=FRAGMENTS[index][1],
                                                payload=FRAGMENTS[index][2]) for index in order]
                        datagram = self._reassemble(cls, packets, strict)
                        self.assertIs(datagram.completed, Completion.COMPLETE)
                        self.assertEqual(datagram.payload, DATA)
                        self.assertEqual(datagram.conflict, ())


if __name__ == '__main__':
    unittest.main()
