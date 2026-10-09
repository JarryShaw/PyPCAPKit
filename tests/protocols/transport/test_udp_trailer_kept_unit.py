# -*- coding: utf-8 -*-
"""Octets captured past a UDP datagram's own Length field survive a rebuild.

GitHub issue #1461: :class:`~pcapkit.protocols.transport.udp.UDP` reads its
Length field, but the payload ran to the end of the capture and nothing kept
what lay past an empty one, so
:meth:`~pcapkit.protocols.protocol.ProtocolBase.from_data` dropped it: a header
of Length 8 followed by two octets rebuilt as 8 octets of its 10.

The payload now stops at Length and the rest is ``info.trailer``, as IPv4, IPv6
(#1209) and IPX (#1433) do, and :meth:`make` writes a ``trailer`` outside the
length it declares.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`,
c.f. ``tests/protocols/link/test_ethernet_mac_roundtrip_unit.py``.

"""

import unittest
import warnings

from tests._support import reimport_once_per_class


def _udp(length: int, port: int = 53) -> bytes:
    """Return an 8-octet UDP header between ``port`` and itself, of Length ``length``."""
    return port.to_bytes(2, 'big') * 2 + length.to_bytes(2, 'big') + b'\x12\x34'


#: Datagrams with octets past the Length field: (octets, payload, trailer).
TRAILER = {
    'header only': (_udp(8) + b'pp', b'', b'pp'),
    'payload': (_udp(10) + b'ab' + b'pp', b'ab', b'pp'),
    'HTTP port': (_udp(12, 80) + b'GET ' + b'pp', b'GET ', b'pp'),
}

#: Datagrams that end at or before their own Length, or whose Length is below
#: the header: (octets, payload).
NO_TRAILER = {
    'exact': (_udp(10) + b'ab', b'ab'),
    'truncated': (_udp(255) + b'abcd', b'abcd'),
    'Length below header': (_udp(3) + b'abcd', b'abcd'),
    'Length zero': (_udp(0) + b'abcd', b'abcd'),
}


class TestUDPTrailerKept(unittest.TestCase):
    """Pin the octets past a UDP Length field through ``from_data``."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_datagram_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.transport.udp import UDP

        for name, (raw, payload, trailer) in TRAILER.items():
            with self.subTest(datagram=name):
                parsed = UDP(raw, len(raw))
                self.assertEqual(parsed.info.trailer, trailer)
                self.assertEqual(bytes(parsed.__header__.payload), payload)
                self.assertEqual(UDP.from_data(parsed.info).data, raw)
                self.assertEqual(UDP.from_data(parsed.info.to_dict()).data, raw)

    def test_no_trailer_key_without_excess(self) -> None:
        from pcapkit.protocols.transport.udp import UDP

        for name, (raw, payload) in NO_TRAILER.items():
            with self.subTest(datagram=name), warnings.catch_warnings():
                warnings.simplefilter('error')
                parsed = UDP(raw, len(raw))
                self.assertNotIn('trailer', parsed.info)
                self.assertEqual(bytes(parsed.__header__.payload), payload)
                self.assertEqual(UDP.from_data(parsed.info).data, raw)
                self.assertEqual(UDP.from_data(parsed.info.to_dict()).data, raw)

    def test_make_writes_trailer_outside_length(self) -> None:
        from pcapkit.protocols.transport.udp import UDP

        made = UDP(srcport=53, dstport=53, payload=b'ab', trailer=b'pp')
        self.assertEqual(made.data, _udp(10)[:6] + b'\x00\x00' + b'ab' + b'pp')
        self.assertEqual(made.info.len, 10)
        self.assertEqual(made.info.trailer, b'pp')

        parsed = UDP(made.data, len(made.data))
        self.assertEqual(UDP.from_data(parsed.info.to_dict()).data, made.data)

    def test_ipv4_keeps_both_trailers(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4

        udp = _udp(9) + b'a' + b'XYZ'
        total = (20 + len(udp)).to_bytes(2, 'big')
        raw = (b'\x45\x00' + total + bytes(4) + b'\x40\x11' + bytes(2)
               + bytes([10, 0, 0, 1, 10, 0, 0, 2]) + udp + b'\x00\x00')

        parsed = IPv4(raw, len(raw))
        self.assertEqual(parsed.info.trailer, b'\x00\x00')
        self.assertEqual(parsed.info.udp.trailer, b'XYZ')
        self.assertEqual(IPv4.from_data(parsed.info.to_dict()).data, raw)


if __name__ == '__main__':
    unittest.main()
