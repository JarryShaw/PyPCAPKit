# -*- coding: utf-8 -*-
"""IP reassembly reads :data:`IP_MAX_LENGTH` as a strict bound at its edge. C.f. #1739.

:class:`pcapkit.foundation.reassembly.ip.IP` reads
:data:`~pcapkit.protocols.schema.internet.ipv6.IP_MAX_LENGTH` from its home. A
fragment with Total Length 0 declares no length (#1555), and grows the buffer
past the bound only when its datagram, header included, is *longer* than
65,535 octets, since growing the buffer is what lifts the bound (#1585). One of
exactly 65,535 octets fits, so it leaves the bound in place, and a declared
final fragment that then runs past it still never completes.

Every case builds its fragments in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

from ipaddress import ip_address
import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): exercises integer, bytes and struct edge cases, whose limits
#: differ by interpreter.
__tier__ = 'ALL'

#: Datagram octets, with no zero octet in them, so a hole shows.
DATA = (bytes(range(1, 256)) * 258)[:65536]

#: Octets of the IPv4 header in front of every fragment.
IHL = 20

#: Fragment Offset of the final fragment, the start of the block a cut
#: fragment ending at octet 65,515 leaves partial.
FINAL = 65512


class TestIPMaxLengthEdge(unittest.TestCase):
    """A Total Length 0 datagram of exactly 65,535 octets does not lift the bound."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _packet(self, *, num: int, fo: int, mf: bool, payload: bytes, tl: 'int | None' = None):
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data.ip import Packet

        bufid = (ip_address('192.0.2.1'), ip_address('198.51.100.2'), 7, TransType.UDP)
        return Packet(bufid, num, fo, IHL, mf, IHL + len(payload) if tl is None else tl,
                      b'H' * IHL, bytearray(payload), 1000.0 + num)

    def _completed(self, *, first: int, strict: bool):
        """Reassemble a Total Length 0 fragment of ``first`` octets, then a declared final one.

        The final fragment declares its data to end at octet 65,536, one past
        what a 20-octet header leaves room for.

        """
        from pcapkit.foundation.reassembly.ipv4 import IPv4

        reasm = IPv4(strict=strict)
        reasm(self._packet(num=1, fo=0, mf=True, payload=DATA[:first], tl=0))
        reasm(self._packet(num=2, fo=FINAL, mf=False, payload=DATA[FINAL:]))
        datagram, = reasm.datagram
        self.assertEqual(datagram.index, (1, 2))
        return datagram.completed

    def test_exactly_the_bound_keeps_it(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion

        for strict in (True, False):
            with self.subTest(strict=strict):
                # 20 + 65,515 is 65,535 octets: the buffer is not grown
                self.assertIs(self._completed(first=65535 - IHL, strict=strict), Completion.PARTIAL)

    def test_one_past_the_bound_lifts_it(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion

        for strict in (True, False):
            with self.subTest(strict=strict):
                # 20 + 65,516 is 65,536 octets: the buffer grows past the bound
                self.assertIs(self._completed(first=65536 - IHL, strict=strict), Completion.COMPLETE)


if __name__ == '__main__':
    unittest.main()
