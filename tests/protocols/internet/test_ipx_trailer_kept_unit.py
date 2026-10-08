# -*- coding: utf-8 -*-
"""Octets captured past an IPX packet's own length survive a rebuild.

GitHub issue #1433: :class:`~pcapkit.protocols.link.ethernet.Ethernet` hands
the whole rest of the frame to the next layer, but
:class:`~pcapkit.protocols.internet.ipx.IPX` reads only its Packet Length. The
octets after that -- most often the padding of a 60-octet minimum Ethernet
frame -- were kept by no ``info``, so
:meth:`~pcapkit.protocols.protocol.ProtocolBase.from_data` dropped them: the
frame below rebuilt as 44 octets of its 60.

The IPX layer owns them as ``trailer``, since its own length field is what
leaves them out of the payload, and so the IPX packet rebuilds byte for byte
on its own as well as inside a frame.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`,
c.f. ``tests/protocols/link/test_ethernet_mac_roundtrip_unit.py``.

"""

import unittest

from tests._support import reimport_once_per_class

#: Destination and source MAC addresses.
MACS = bytes.fromhex('001122334455' '66778899aabb')
#: Destination and source IPX addresses.
ADDRS = bytes(range(1, 25))


def _ipx(length: int) -> bytes:
    """Return a 30-octet IPX header whose Packet Length is ``length``."""
    return bytes(2) + length.to_bytes(2, 'big') + b'\x00\x00' + ADDRS


#: Ethernet frames whose IPX packet is shorter than what the frame carries.
FRAMES = {
    'zero-padding': MACS + b'\x81\x37' + _ipx(30) + bytes(16),
    'junk-padding': MACS + b'\x81\x37' + _ipx(30) + b'\xde\xad' * 8,
}

#: Bare IPX packets that end at or before their own length, and their payload.
NO_TRAILER = {
    'exact': (_ipx(34) + b'abcd', b'abcd'),
    'truncated': (_ipx(40) + b'abcd', b'abcd'),
}


class TestIPXTrailerKept(unittest.TestCase):
    """Pin the octets past an IPX packet's own length through ``from_data``."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_frame_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.link.ethernet import Ethernet

        for name, frame in FRAMES.items():
            with self.subTest(frame=name):
                parsed = Ethernet(frame, len(frame))
                self.assertEqual(len(parsed.data), 60)
                self.assertEqual(parsed.info.ipx.len, 30)
                self.assertEqual(parsed.info.ipx.trailer, frame[44:])
                self.assertNotIn('trailer', parsed.info)
                self.assertEqual(Ethernet.from_data(parsed.info).data, frame)

    def test_packet_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.internet.ipx import IPX

        packet = _ipx(34) + b'abcd' + b'\xee' * 5
        parsed = IPX(packet, len(packet))
        self.assertEqual(parsed.info.trailer, b'\xee' * 5)
        self.assertEqual(bytes(parsed.__header__.payload), b'abcd')
        self.assertEqual(IPX.from_data(parsed.info).data, packet)

    def test_no_trailer_key_without_excess(self) -> None:
        from pcapkit.protocols.internet.ipx import IPX

        for name, (packet, payload) in NO_TRAILER.items():
            with self.subTest(packet=name):
                parsed = IPX(packet, len(packet))
                self.assertNotIn('trailer', parsed.info)
                self.assertEqual(bytes(parsed.__header__.payload), payload)
                self.assertEqual(IPX.from_data(parsed.info).data, packet)

    def test_make_writes_trailer_outside_the_length(self) -> None:
        from pcapkit.protocols.internet.ipx import IPX

        made = IPX(payload=b'abcd', trailer=b'\x00\x01')
        self.assertEqual(made.info.len, 34)
        self.assertEqual(len(made.data), 36)
        self.assertEqual(made.data[-6:], b'abcd\x00\x01')
        self.assertEqual(made.info.trailer, b'\x00\x01')
        self.assertEqual(IPX(made.data, len(made.data)).info.trailer, b'\x00\x01')


if __name__ == '__main__':
    unittest.main()
