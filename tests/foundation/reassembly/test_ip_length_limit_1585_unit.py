# -*- coding: utf-8 -*-
"""An IP datagram longer than its length field can declare is never complete.

GitHub issue #1585. The data buffer holds 65,535 octets of data, but IPv4's
Total Length counts the header as well, so fragments whose data covered octets
0-65,522 behind a 20-octet header made a 65,543-octet datagram, and it read
``COMPLETE``. Linux's ``ip_frag_reasm`` rejects it. The bound now counts the
header as the family's length field does: IPv4's Total Length counts all of it,
and IPv6's Payload Length counts the extension headers but not the fixed
40-octet header. A Total Length of 0 declares no length (#1555), so a datagram
that outgrows the bound with its header grows the buffer past it instead.

The same issue documents, rather than changes, that the octets of a cut
non-final fragment's partial block, which is not marked received (#1567), are
not checked for conflicts; the last test pins that.

Every case builds its fragments in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

from ipaddress import ip_address
import unittest

from tests._support import reimport_once_per_class

#: The largest Fragment Offset, 8191 eight-octet units, in octets.
LAST = 65528

#: Datagram octets, with no zero octet in them, so a hole shows.
DATA = (bytes(range(1, 256)) * 258)[:65579]


class TestIPReassemblyLengthLimit(unittest.TestCase):
    """Pin the bound on a datagram's length, header included as its family counts it."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _packet(self, *, num: int, fo: int, mf: bool, payload: bytes, ihl: int, tl: 'int | None' = None):
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data.ip import Packet

        bufid = (ip_address('192.0.2.1'), ip_address('198.51.100.2'), 7, TransType.UDP)
        return Packet(bufid, num, fo, ihl, mf, ihl + len(payload) if tl is None else tl,
                      b'H' * ihl, bytearray(payload), 1000.0 + num)

    def _two_fragments(self, cls, *, tdl: int, ihl: int, strict: bool, reverse: bool = False):
        """Reassemble ``DATA[:tdl]`` from two fragments behind an ``ihl``-octet header."""
        packets = [self._packet(num=1, fo=0, mf=True, payload=DATA[:32768], ihl=ihl),
                   self._packet(num=2, fo=32768, mf=False, payload=DATA[32768:tdl], ihl=ihl)]
        reasm = cls(strict=strict)
        for packet in reversed(packets) if reverse else packets:
            reasm(packet)
        datagram, = reasm.datagram
        return datagram

    def test_the_issues_repro_is_partial(self) -> None:
        # case 3c: TDL 65,523 behind a 20-octet header is 65,543 octets
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.ipv4 import IPv4

        for reverse in (False, True):
            for strict in (True, False):
                with self.subTest(reverse=reverse, strict=strict):
                    datagram = self._two_fragments(IPv4, tdl=65523, ihl=20, strict=strict, reverse=reverse)
                    self.assertIs(datagram.completed, Completion.PARTIAL)
                    self.assertEqual(datagram.index, (2, 1) if reverse else (1, 2))
                    # every octet is still reported
                    self.assertEqual(datagram.payload, (DATA[:65523],) if strict else DATA[:65523])
                    self.assertEqual(datagram.conflict, ())

    def test_ipv4_counts_the_whole_header(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.ipv4 import IPv4

        for ihl in (20, 60):
            for strict in (True, False):
                with self.subTest(ihl=ihl, strict=strict):
                    whole = self._two_fragments(IPv4, tdl=65535 - ihl, ihl=ihl, strict=strict)
                    self.assertIs(whole.completed, Completion.COMPLETE)
                    self.assertEqual(whole.payload, DATA[:65535 - ihl])
                    over = self._two_fragments(IPv4, tdl=65536 - ihl, ihl=ihl, strict=strict)
                    self.assertIs(over.completed, Completion.PARTIAL)

    def test_ipv6_counts_only_the_extension_headers(self) -> None:
        # The fixed header is not in the Payload Length, so 65,535 octets of
        # data behind it fit; an 8-octet extension header takes 8 of them.
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.ipv6 import IPv6

        for ihl, tdl in ((40, 65535), (48, 65527)):
            for strict in (True, False):
                with self.subTest(ihl=ihl, strict=strict):
                    whole = self._two_fragments(IPv6, tdl=tdl, ihl=ihl, strict=strict)
                    self.assertIs(whole.completed, Completion.COMPLETE)
                    self.assertEqual(whole.payload, DATA[:tdl])
        for strict in (True, False):
            with self.subTest(ihl=48, strict=strict):
                over = self._two_fragments(IPv6, tdl=65528, ihl=48, strict=strict)
                self.assertIs(over.completed, Completion.PARTIAL)

    def test_an_ipv4_final_fragment_at_the_largest_offset_never_completes(self) -> None:
        # Its data ends past octet 65,528, so no header leaves it room.
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.ipv4 import IPv4

        for size in (1, 7):
            for strict in (True, False):
                with self.subTest(size=size, strict=strict):
                    reasm = IPv4(strict=strict)
                    reasm(self._packet(num=1, fo=0, mf=True, payload=DATA[:32768], ihl=20))
                    reasm(self._packet(num=2, fo=32768, mf=True, payload=DATA[32768:LAST], ihl=20))
                    reasm(self._packet(num=3, fo=LAST, mf=False, payload=DATA[LAST:LAST + size], ihl=20))
                    datagram, = reasm.datagram
                    self.assertIs(datagram.completed, Completion.PARTIAL)
                    self.assertEqual(datagram.index, (1, 2, 3))
                    body = DATA[:LAST + size]
                    self.assertEqual(datagram.payload, (body,) if strict else body)

    def test_a_tso_datagram_is_not_bounded(self) -> None:
        # Total Length 0 declares nothing, as Linux's BIG TCP leaves a datagram
        # over 65,535 octets: 65,523 octets of data fit the preallocated buffer
        # but not with the header, so the buffer still grows past the bound.
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.ipv4 import IPv4

        for strict in (True, False):
            with self.subTest(strict=strict):
                reasm = IPv4(strict=strict)
                reasm(self._packet(num=1, fo=0, mf=False, payload=DATA[:65523], ihl=20, tl=0))
                datagram, = reasm.datagram
                self.assertIs(datagram.completed, Completion.COMPLETE)
                self.assertEqual(datagram.payload, DATA[:65523])

    def test_overwriting_a_cut_fragments_partial_block_records_no_conflict(self) -> None:
        # A non-final fragment of 60 octets, as a cut IPv6 one is passed: its
        # partial block, octets 56-63, is a hole (#1567). The next fragment
        # overwrites 56-59 with other octets. Receipt is tracked in whole
        # blocks only, so they are not compared, and the later octets win as
        # RFC 791 has them do.
        from pcapkit.foundation.reassembly.data.data import Completion
        from pcapkit.foundation.reassembly.ipv4 import IPv4
        from pcapkit.foundation.reassembly.ipv6 import IPv6

        other = bytes(b ^ 0xFF for b in DATA[56:64])
        for cls in (IPv4, IPv6):
            for strict in (True, False):
                with self.subTest(cls=cls.__name__, strict=strict):
                    reasm = cls(strict=strict)
                    reasm(self._packet(num=1, fo=0, mf=True, payload=DATA[:60], ihl=40))
                    reasm(self._packet(num=2, fo=56, mf=True, payload=other, ihl=40))
                    reasm(self._packet(num=3, fo=64, mf=False, payload=DATA[64:72], ihl=40))
                    datagram, = reasm.datagram
                    self.assertIs(datagram.completed, Completion.COMPLETE)
                    self.assertEqual(datagram.payload, DATA[:56] + other + DATA[64:72])
                    self.assertEqual(datagram.conflict, ())


if __name__ == '__main__':
    unittest.main()
