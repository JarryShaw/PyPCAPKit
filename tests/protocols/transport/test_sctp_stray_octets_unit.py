# -*- coding: utf-8 -*-
"""Octets after the last whole SCTP chunk parse and survive a rebuild.

GitHub issue #1468: SCTP has no packet length field, so octets left after the
last whole chunk -- fewer than a chunk header, or a chunk whose declared length
runs past the data -- cannot be told apart from a chunk cut short. They made
:class:`~pcapkit.protocols.transport.sctp.SCTP` raise ``ProtocolError: Field
chunks has an option that runs past the end of the data``, so the packet had no
round trip at all.

Per the #1458 ruling they are now recorded rather than rejected: the chunk list
stops at the last whole chunk and the rest is kept as ``trailer``, as IPv4,
IPv6 (#1209), L2TPv2 and OSPF (#1455) do. :meth:`make` writes a ``trailer``
after the chunks.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`,
c.f. ``tests/protocols/link/test_ethernet_mac_roundtrip_unit.py``.

"""

import struct
import unittest
import warnings

from tests._support import reimport_once_per_class

#: SCTP common header.
COMMON = struct.pack('!HHII', 1, 2, 0, 0)
#: COOKIE ACK chunk.
COOKIE_ACK = struct.pack('!BBH', 11, 0, 4)
#: DATA chunk carrying ``b'hi'`` under PPID 0, padded to eight octets.
DATA = struct.pack('!BBHIHHI', 0, 3, 18, 1, 0, 0, 0) + b'hi' + bytes(2)
#: INIT chunk declaring 32 octets, 28 present.
INIT_CUT = bytes.fromhex('01000020 00000001 00010000 00010001 00000001 000c0010 00050000')

#: Packets with octets after the last whole chunk: (octets, chunk count, trailer).
STRAY = {
    '1 octet': (COMMON + COOKIE_ACK + b'x', 1, b'x'),
    '3 octets': (COMMON + COOKIE_ACK + b'xyz', 1, b'xyz'),
    '4 octets': (COMMON + COOKIE_ACK + b'wxyz', 1, b'wxyz'),
    '4 zero octets': (COMMON + COOKIE_ACK + bytes(4), 1, bytes(4)),
    '5 octets': (COMMON + COOKIE_ACK + b'vwxyz', 1, b'vwxyz'),
    'after DATA': (COMMON + DATA + b'x', 1, b'x'),
    'chunk length past the data': (COMMON + COOKIE_ACK + struct.pack('!BBH', 11, 0, 40) + b'abcd', 1,
                                   struct.pack('!BBH', 11, 0, 40) + b'abcd'),
    'first chunk past the data': (COMMON + DATA[:14], 0, DATA[:14]),
    'chunk length below its header': (COMMON + COOKIE_ACK + struct.pack('!BBH', 11, 0, 2), 1,
                                      struct.pack('!BBH', 11, 0, 2)),
    'under a chunk header': (COMMON + b'ab', 0, b'ab'),
    # formerly rejected by tests/protocols/test_declared_length_overrun_unit.py
    'INIT past the data': (COMMON + INIT_CUT, 0, INIT_CUT),
}

#: Packets that end on a chunk boundary.
NO_STRAY = {
    'header only': COMMON,
    'COOKIE ACK': COMMON + COOKIE_ACK,
    'DATA then COOKIE ACK': COMMON + DATA + COOKIE_ACK,
}


class TestSCTPStrayOctets(unittest.TestCase):
    """Pin the octets after the last whole SCTP chunk through ``from_data``."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_packet_parses_and_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.transport.sctp import SCTP

        for name, (raw, count, trailer) in STRAY.items():
            with self.subTest(packet=name):
                parsed = SCTP(raw, len(raw))
                self.assertEqual(len(parsed.info.chunks), count)
                self.assertEqual(parsed.info.trailer, trailer)
                self.assertEqual(SCTP.from_data(parsed.info).data, raw)
                self.assertEqual(SCTP.from_data(parsed.info.to_dict()).data, raw)

    def test_schema_keeps_the_trailer(self) -> None:
        from pcapkit.protocols.schema.transport.sctp import SCTP as Schema_SCTP

        for name, (raw, count, trailer) in STRAY.items():
            with self.subTest(packet=name):
                schema = Schema_SCTP.unpack(raw)
                self.assertEqual(len(schema.chunks), count)
                self.assertEqual(schema.trailer, trailer)
                self.assertEqual(schema.pack(), raw)

    def test_no_trailer_key_on_a_chunk_boundary(self) -> None:
        from pcapkit.protocols.transport.sctp import SCTP

        for name, raw in NO_STRAY.items():
            with self.subTest(packet=name):
                parsed = SCTP(raw, len(raw))
                self.assertNotIn('trailer', parsed.info)
                self.assertEqual(SCTP.from_data(parsed.info).data, raw)

    def test_data_chunk_still_dispatches(self) -> None:
        from pcapkit.protocols.transport.sctp import SCTP

        raw = COMMON + DATA + b'x'
        parsed = SCTP(raw, len(raw))
        self.assertEqual(parsed.info.trailer, b'x')
        self.assertEqual(bytes(parsed.payload.data), b'hi')

    def test_parent_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.transport.sctp import SCTP

        for name, (raw, _, trailer) in STRAY.items():
            with self.subTest(packet=name):
                frame = (struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(raw), 1, 0, 64, 132, 0,
                                     bytes(4), bytes(4)) + raw)
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    parsed = IPv4(frame, len(frame))
                self.assertIsInstance(parsed.payload, SCTP)
                self.assertEqual(parsed.payload.info.trailer, trailer)
                self.assertEqual(IPv4.from_data(parsed.info).data, frame)

    def test_raw_chunk_that_is_not_whole_is_rejected(self) -> None:
        from pcapkit.protocols.transport.sctp import SCTP
        from pcapkit.utilities.exceptions import ProtocolError

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with self.assertRaisesRegex(ProtocolError, r"raw chunk b'\\x01' runs past the end of the data"):
                SCTP(chunks=[b'\x01'])

    def test_make_writes_the_trailer_under_the_checksum(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk as Enum_Chunk
        from pcapkit.protocols.transport.sctp import SCTP

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            raw = SCTP(srcport=1, dstport=2, chunks=[(Enum_Chunk.Cookie_Acknowledgement, {})],
                       trailer=b'xyz').data
        self.assertEqual(raw[12:], COOKIE_ACK + b'xyz')
        parsed = SCTP(raw, len(raw))
        self.assertEqual(parsed.info.trailer, b'xyz')
        self.assertTrue(parsed.checksum_valid)


if __name__ == '__main__':
    unittest.main()
