# -*- coding: utf-8 -*-
"""A rebuilt TCP header reads back the octets after its End of Option List.

GitHub issue #2769: a parse keeps the octets after an End of Option List option
as ``padding``, and :meth:`TCP.make
<pcapkit.protocols.transport.tcp.protocol.TCP.make>` writes them back inside the
options, so the rebuilt octets were exact while its ``info.padding`` read as
empty: ``TCP.read`` took ``padding`` from the schema, which a made schema does
not set. It slices them from the octets instead, as ``IPv4.read`` does. Inside
IPv4 the rebuild parses its payload from the octets, so it read the padding
already; the cases there pin that it still does.

Each option area below is one 32-bit word ending in zero to three octets after
the End of Option List (:rfc:`9293#section-3.1`), zeros and other octets alike,
and each segment carries a payload, so a padding read past the header shows.
Every case builds its own octets in memory and reads no capture. The classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""
# Deferring these is the design: each build runs after the per-class re-import.
# pylint: disable=import-outside-toplevel
from __future__ import annotations

import unittest
import warnings

from tests._support import reimport_once_per_class

#: Test tier (#1958): hand-picked round-trip cases, not a sweep.
__tier__ = 'ALL'

#: Ports 1234 and 80, sequence 1, acknowledgement 0; octet 12 follows.
HEAD = bytes.fromhex('04d2 0050 00000001 00000000')
#: SYN, window 1024, a zero checksum and urgent pointer.
TAIL = bytes.fromhex('02 0400 0000 0000')
#: Payload after the header.
PAYLOAD = b'PAY'
#: Octet values the padding is made of.
FILLS = (0x00, 0xa5)


def _cases() -> 'dict[str, tuple[bytes, bytes]]':
    """Return ``name -> (segment, padding)`` for every padding length and fill."""
    cases = {}
    for size in range(4):
        for fill in FILLS:
            padding = bytes([fill]) * size
            # NOP options fill the word up to the End of Option List.
            area = b'\x01' * (3 - size) + b'\x00' + padding
            segment = HEAD + bytes([6 << 4]) + TAIL + area + PAYLOAD
            cases[f'{size}-octet-{fill:02x}'] = (segment, padding)
    return cases


class TestTCPEOOLPaddingRebuild(unittest.TestCase):
    """Parse and rebuild agree on the octets after the End of Option List."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_parse_reads_the_octets_after_eool(self) -> None:
        """The specification side: Data Offset counts six words, the rest is padding."""
        from pcapkit.protocols.transport.tcp.protocol import TCP

        for name, (segment, padding) in _cases().items():
            with self.subTest(segment=name):
                info = TCP(segment).info
                self.assertEqual(info.hdr_len, 24)
                self.assertEqual(info.padding, padding)
                self.assertEqual(segment[24 - len(padding):24], padding)

    def test_standalone_rebuild_reads_the_padding(self) -> None:
        """``from_data`` over ``info`` or ``to_dict()`` reads the padding its parse did."""
        from pcapkit.protocols.transport.tcp.protocol import TCP

        for name, (segment, padding) in _cases().items():
            parsed = TCP(segment)
            for source in ('info', 'to_dict'):
                with self.subTest(segment=name, source=source):
                    data = parsed.info if source == 'info' else parsed.info.to_dict()
                    rebuilt = TCP.from_data(data)
                    self.assertEqual(rebuilt.info.padding, padding)
                    self.assertEqual(rebuilt.data, segment)

    def test_rebuild_inside_ipv4_reads_the_padding(self) -> None:
        """So does the TCP layer of an IPv4 packet rebuilt the same two ways."""
        from pcapkit.protocols.internet.ipv4.protocol import IPv4

        for name, (segment, padding) in _cases().items():
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')  # the zero TCP checksum is not checked here
                packet = IPv4(src='192.0.2.1', dst='192.0.2.2', protocol=6, payload=segment).data
                parsed = IPv4(packet)
                self.assertEqual(parsed.payload.info.padding, padding)
                for source in ('info', 'to_dict'):
                    with self.subTest(segment=name, source=source):
                        data = parsed.info if source == 'info' else parsed.info.to_dict()
                        rebuilt = IPv4.from_data(data)
                        self.assertEqual(rebuilt.payload.info.padding, padding)
                        self.assertEqual(rebuilt.data, packet)

    def test_made_header_reads_as_its_octets_parse(self) -> None:
        """``make`` with ``padding`` after a lone End of Option List, then alignment zeros."""
        from pcapkit.const.tcp.option import Option
        from pcapkit.protocols.transport.tcp.protocol import TCP

        for size in range(4):
            with self.subTest(size=size):
                made = TCP(options=[(Option.End_of_Option_List, {})], padding=b'\xa5' * size)
                expected = b'\xa5' * size + bytes(3 - size)
                self.assertEqual(made.data[20:24], b'\x00' + expected)
                self.assertEqual(made.info.padding, expected)
                self.assertEqual(TCP(made.data).info.padding, expected)


if __name__ == '__main__':
    unittest.main()
