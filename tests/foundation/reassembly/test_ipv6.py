from __future__ import annotations

import importlib.util
from ipaddress import ip_address
import struct
import unittest

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Next Header values used below (:rfc:`8200#section-4.1`).
NH_HOPOPT = 0
NH_ROUTING = 43
NH_IPV6_FRAG = 44
NH_AH = 51
NH_DSTOPT = 60
NH_UDP = 17


def ipv6_header(next_header: int, payload_len: int = 0) -> bytes:
    """The 40 octet fixed IPv6 header, with ``next_header`` at offset 6."""
    return (struct.pack('>IHBB', 6 << 28, payload_len, next_header, 64)
            + ip_address('2001:db8::1').packed
            + ip_address('2001:db8::2').packed)


def ext_header(next_header: int, octets: int) -> bytes:
    """A Hop-by-Hop/Routing/Destination Options style extension header.

    Args:
        next_header: Value of the header's Next Header field.
        octets: Total length of the header, which must be a positive multiple of
            8 -- the Hdr Ext Len field counts 8-octet units beyond the first
            (:rfc:`8200#section-4.3`).

    Returns:
        ``octets`` octets of extension header, padded with zeroes.

    """
    assert octets >= 8 and octets % 8 == 0
    return bytes((next_header, octets // 8 - 1)) + b'\x00' * (octets - 2)


def ah_header(next_header: int, octets: int) -> bytes:
    """An Authentication Header, whose Payload Len counts 4-octet units less two.

    Args:
        next_header: Value of the header's Next Header field.
        octets: Total length of the header, a positive multiple of 4
            (:rfc:`4302#section-2.2`).

    Returns:
        ``octets`` octets of Authentication Header, padded with zeroes.

    """
    assert octets >= 12 and octets % 4 == 0
    return bytes((next_header, octets // 4 - 2)) + b'\x00' * (octets - 2)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class NextHeaderOffsetTests(unittest.TestCase):
    """Where the Next Header field of a datagram's last header lives.

    :rfc:`8200#section-4.5` hands the Fragment header's Next Header value to *the
    last header of the unfragmentable part*, which is only the fixed IPv6 header
    when nothing precedes the Fragment header. A Hop-by-Hop Options, Routing or
    Destination Options header may, and then the field to rewrite is that
    header's -- so the chain has to be walked rather than assumed.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_a_bare_ipv6_header_answers_with_its_own_field(self) -> None:
        from pcapkit.foundation.reassembly.ipv6 import _next_header_offset

        self.assertEqual(_next_header_offset(ipv6_header(NH_IPV6_FRAG)), 6)

    def test_one_extension_header_moves_the_answer_past_the_fixed_header(self) -> None:
        from pcapkit.foundation.reassembly.ipv6 import _next_header_offset

        header = ipv6_header(NH_HOPOPT) + ext_header(NH_IPV6_FRAG, 8)
        self.assertEqual(len(header), 48)
        self.assertEqual(_next_header_offset(header), 40)

    def test_the_walk_follows_each_header_s_own_length(self) -> None:
        from pcapkit.foundation.reassembly.ipv6 import _next_header_offset

        # a 24 octet Routing header, then an 8 octet Destination Options header
        header = (ipv6_header(NH_ROUTING) + ext_header(NH_DSTOPT, 24)
                  + ext_header(NH_IPV6_FRAG, 8))
        self.assertEqual(len(header), 72)
        self.assertEqual(_next_header_offset(header), 64)

    def test_the_authentication_header_uses_its_own_length_encoding(self) -> None:
        """AH counts 4-octet units less two, not 8-octet units less one.

        This is the case that distinguishes the two encodings: read with the
        8-octet rule, a 24 octet AH advances 40 octets instead of 24, the walk
        overshoots the end of the chain and stops on the wrong header -- so the
        Fragment header the datagram advertises never gets rewritten at all.

        """
        from pcapkit.foundation.reassembly.ipv6 import _next_header_offset

        header = (ipv6_header(NH_AH) + ah_header(NH_DSTOPT, 24)
                  + ext_header(NH_IPV6_FRAG, 8))
        self.assertEqual(len(header), 72)
        self.assertEqual(_next_header_offset(header), 64)
        self.assertEqual(header[64], NH_IPV6_FRAG)
        # what the 8-octet rule would have answered instead
        self.assertNotEqual(_next_header_offset(header), 40)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class RectifyHeaderTests(unittest.TestCase):
    """:meth:`IPv6._rectify_header`, which removes the Fragment header's trace.

    The adapters already stop ``header`` short of the Fragment header's octets;
    what is left is the field pointing at it. Left alone, the reassembled
    datagram advertises a Fragment header (``44``) on a datagram that is by
    definition no longer a fragment (#415).

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def rectify(self, header: bytes) -> bytes:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.ipv6 import IPv6

        return IPv6()._rectify_header(header, TransType.UDP)

    def test_the_fixed_header_s_field_is_replaced_and_nothing_else_is(self) -> None:
        header = ipv6_header(NH_IPV6_FRAG, payload_len=1456)
        rectified = self.rectify(header)

        self.assertEqual(rectified[6], NH_UDP)
        self.assertEqual(len(rectified), len(header))
        # every other octet is untouched, the Payload Length field included: it
        # still describes the fragment, since the reassembled length is not
        # knowable from one fragment
        self.assertEqual(rectified[:6], header[:6])
        self.assertEqual(rectified[7:], header[7:])
        self.assertEqual(struct.unpack_from('>H', rectified, 4)[0], 1456)

    def test_an_extension_header_s_field_is_the_one_replaced(self) -> None:
        header = ipv6_header(NH_HOPOPT) + ext_header(NH_IPV6_FRAG, 8)
        rectified = self.rectify(header)

        # the last header of the unfragmentable part, not the fixed header
        self.assertEqual(rectified[40], NH_UDP)
        self.assertEqual(rectified[6], NH_HOPOPT)

    def test_a_chain_not_ending_in_a_fragment_header_is_returned_unchanged(self) -> None:
        """Which is also what makes the rewrite idempotent."""
        header = ipv6_header(NH_UDP)
        self.assertEqual(self.rectify(header), header)
        self.assertEqual(self.rectify(self.rectify(ipv6_header(NH_IPV6_FRAG))),
                         self.rectify(ipv6_header(NH_IPV6_FRAG)))

    def test_a_header_too_short_to_walk_is_returned_unchanged(self) -> None:
        """A truncated capture must not raise out of the reassembly path."""
        for header in (b'', b'\x60', ipv6_header(NH_IPV6_FRAG)[:39]):
            with self.subTest(length=len(header)):
                self.assertEqual(self.rectify(header), header)

    def test_ipv4_reassembly_leaves_the_header_alone(self) -> None:
        """The base implementation is the identity, which is what IPv4 needs."""
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.ipv4 import IPv4

        header = bytes.fromhex('4500001c007b2000400600000000000000000000')
        self.assertEqual(IPv4()._rectify_header(header, TransType.TCP), header)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPv6ReassemblyHeaderTests(unittest.TestCase):
    """The rewrite reaching the datagram, through the reassembly machinery."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _packet(self, *, num: int, fo: int, mf: bool, payload: bytes, header: bytes):
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data.ip import Packet

        src = ip_address('2001:db8::1')
        dst = ip_address('2001:db8::2')
        return Packet((src, dst, 4321, TransType.UDP), num, fo, len(header), mf,
                      len(header) + len(payload), header, bytearray(payload), 1000.0)

    def test_the_reassembled_datagram_does_not_advertise_a_fragment_header(self) -> None:
        from pcapkit.foundation.reassembly.ipv6 import IPv6

        header = ipv6_header(NH_HOPOPT) + ext_header(NH_IPV6_FRAG, 8)
        reasm = IPv6()
        reasm(self._packet(num=1, fo=0, mf=True, payload=b'a' * 8, header=header))
        reasm(self._packet(num=2, fo=8, mf=False, payload=b'b' * 8, header=b''))

        datagram, = reasm.datagram
        self.assertTrue(datagram.completed)
        self.assertEqual(datagram.payload, b'a' * 8 + b'b' * 8)
        self.assertEqual(datagram.header[40], NH_UDP)
        self.assertNotEqual(datagram.header[40], NH_IPV6_FRAG)
        # only the first fragment carries a header, so the second must not have
        # replaced it with its own empty one
        self.assertEqual(len(datagram.header), len(header))

    def test_a_later_first_fragment_updates_the_stored_header(self) -> None:
        """The ``fo == 0`` fragment may arrive after the ones behind it.

        ``IP.reassembly`` writes the header into an existing buffer in that case,
        which is a second call site for the rewrite -- one that a test feeding the
        fragments in wire order never reaches.

        """
        from pcapkit.foundation.reassembly.ipv6 import IPv6

        header = ipv6_header(NH_IPV6_FRAG)
        reasm = IPv6()
        reasm(self._packet(num=1, fo=8, mf=True, payload=b'b' * 8, header=b''))
        reasm(self._packet(num=2, fo=0, mf=True, payload=b'a' * 8, header=header))

        buffer, = reasm._buffer.values()
        self.assertEqual(buffer.header[6], NH_UDP)


if __name__ == '__main__':
    unittest.main()
