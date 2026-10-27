# -*- coding: utf-8 -*-
"""#2310 -- :class:`~pcapkit.const.tcp.flags.Flags` members are their wire masks.

IANA's TCP Header Flags registry numbers the bits from the most significant end
of the 16-bit Data Offset/flags word, so FIN is offset 15 and CWR offset 8. The
crawler generated ``1 << offset``, bit-reversed against the wire: ``int()`` of a
parsed SYN/ACK's ``connection`` was ``0x4800`` where the header carries
``0x012``. Each member is now ``1 << (15 - offset)``, its mask in the low 12 bits
of that word, and the registry's range guard is that 12-bit field.

"""
from __future__ import annotations

import importlib.util
import struct
import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): enum mechanics and a hand-picked round trip.
__tier__ = 'ALL'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Each member and its mask in the flags field, as :rfc:`9293` section 3.1
#: and :rfc:`9768` lay it out.
WIRE_MASKS = (
    ('FIN', 0x001), ('SYN', 0x002), ('RST', 0x004), ('PSH', 0x008),
    ('ACK', 0x010), ('URG', 0x020), ('ECE', 0x040), ('CWR', 0x080),
    ('AE', 0x100), ('Reserved_6', 0x200), ('Reserved_5', 0x400), ('Reserved_4', 0x800),
)

#: A SYN/ACK as a handshake carries it: data offset 7, flags ``0x012``, and the
#: MSS, NOP, NOP and SACK-permitted options.
SYN_ACK = (struct.pack('!HHIIHHHH', 80, 3372, 0x290E5CE5, 0x38AFFE14, (7 << 12) | 0x012,
                       5840, 0xC20E, 0)
           + bytes.fromhex('020405b4 01010402'))


def _segment(word: 'int') -> 'bytes':
    """A bare 20-octet header whose Data Offset/flags word is ``word``."""
    return struct.pack('!HHIIHHHH', 1, 2, 0, 0, word, 0xFFFF, 0, 0)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TCPFlagsWireMasksTests(unittest.TestCase):
    """The registry's integers mean what the header's bits mean."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_each_member_is_its_wire_mask(self) -> None:
        from pcapkit.const.tcp.flags import Flags

        for name, mask in WIRE_MASKS:
            with self.subTest(member=name):
                self.assertEqual(int(Flags[name]), mask)
                self.assertIs(Flags(mask), Flags[name])

    def test_a_composite_is_the_header_bits(self) -> None:
        from pcapkit.const.tcp.flags import Flags

        self.assertEqual(int(Flags.SYN | Flags.ACK), 0x12)
        self.assertEqual(Flags(0x12), Flags.SYN | Flags.ACK)
        self.assertEqual(int(Flags.FIN | Flags.ACK), 0x11)
        self.assertEqual(int(Flags.CWR | Flags.ECE | Flags.SYN), 0xC2)

    def test_the_guard_is_the_twelve_bit_flags_field(self) -> None:
        """Bits above the flags field are the data offset, so they are refused."""
        from pcapkit.const.tcp.flags import Flags

        self.assertEqual(int(Flags(0xFFF)), 0xFFF)
        for value in (0x1000, 0x4800, 0xFFFF):
            with self.subTest(value=hex(value)):
                with self.assertRaises(ValueError):
                    Flags(value)

    def test_a_parsed_syn_ack_reports_its_header_bits(self) -> None:
        from pcapkit.const.tcp.flags import Flags
        from pcapkit.protocols.transport.tcp import TCP

        tcp = TCP(SYN_ACK, len(SYN_ACK))
        word = struct.unpack('!H', SYN_ACK[12:14])[0]

        self.assertEqual(int(tcp.connection), word & 0x0FFF)
        self.assertEqual(int(tcp.connection), 0x012)
        self.assertEqual(tcp.connection, Flags.SYN | Flags.ACK)
        self.assertEqual(int(tcp.info.connection), 0x012)

        # The round trip stays byte-exact.
        self.assertEqual(TCP.from_data(tcp.info).data, SYN_ACK)

    def test_every_flags_octet_reads_back_as_its_value(self) -> None:
        """The eight flags the parser reports, each combination, as the octet they came from."""
        from pcapkit.protocols.transport.tcp import TCP

        for octet in range(0x100):
            with self.subTest(octet=hex(octet)):
                raw = _segment((5 << 12) | octet)
                tcp = TCP(raw, len(raw))
                self.assertEqual(int(tcp.connection), octet)
                self.assertEqual(TCP.from_data(tcp.info).data, raw)

    def test_make_builds_the_header_bits_its_connection_names(self) -> None:
        from pcapkit.protocols.transport.tcp import TCP

        made = TCP(srcport=1, dstport=2, syn=True, ack=True)
        self.assertEqual(int(made.connection), 0x012)
        self.assertEqual(struct.unpack('!H', made.data[12:14])[0] & 0x0FFF, int(made.connection))


@unittest.skipUnless(importlib.util.find_spec('requests') is not None,
                     'pcapkit.vendor needs requests')
class TCPFlagsCrawlerWireMasksTests(unittest.TestCase):
    """The crawler, not only the committed module, generates the wire masks."""

    def test_the_crawler_generates_wire_masks(self) -> None:
        from pcapkit.vendor.tcp.flags import Flags as VendorFlags

        crawler = object.__new__(VendorFlags)
        crawler.NAME = 'Flags'
        crawler.DOCS = VendorFlags.__doc__
        rows = [
            'Bit,Name,Reference',
            '8,CWR (Congestion Window Reduced),[RFC3168]',
            '11,Acknowledgment field is significant (ACK),[RFC9293]',
            '14,Synchronize sequence numbers (SYN),[RFC9293]',
            '15,No more data from sender (FIN),[RFC9293]',
        ]
        crawler.record = crawler.count(rows)
        lines = [line.splitlines()[-1].strip() for line in crawler.process(rows)]
        self.assertEqual(lines, ['CWR = 1 << 7', 'ACK = 1 << 4', 'SYN = 1 << 1', 'FIN = 1 << 0'])


if __name__ == '__main__':
    unittest.main()
