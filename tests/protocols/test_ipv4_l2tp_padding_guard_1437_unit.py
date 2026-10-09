# -*- coding: utf-8 -*-
"""GitHub issue #1437 (part B): IPv4 and L2TP padding already rebuild as captured.

The issue listed the IPv4 Quick-Start report "Not Used" octet, the IPv4 octets
after the End of Option List, and the L2TPv2 offset pad as sites that might
still zero-fill on rebuild. Measured on ``main`` at ``16c87f901``, all of them
already round-trip byte for byte, so nothing changed; these cases guard that.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import io
import unittest

from tests._support import reimport_once_per_class


def ipv4(options: 'str') -> 'bytes':
    """An IPv4 header (protocol 59, no payload) carrying ``options``."""
    opts = bytes.fromhex(options)
    ihl = 5 + len(opts) // 4
    return (bytes([0x40 | ihl, 0]) + (ihl * 4).to_bytes(2, 'big') + bytes.fromhex('00010000403b0000')
            + bytes([10, 0, 0, 1, 10, 0, 0, 2]) + opts)


#: IPv4 options -> name.
IPV4 = {
    'Quick-Start report, Not Used octet aa': '19088aaa00000004',
    'Quick-Start request, reserved bits set': '19080aff0000000f',
    'octets after EOOL': '00aabbcc',
    'octets after NOP NOP EOOL': '010100cc',
}

#: L2TPv2 messages whose offset pad is not zero.
L2TPV2 = {
    'data message': '0202000000000003aabbcc7878',
    'with length': '4202000e000000000003aabbcc78',
}


class TestIPv4L2TPPaddingGuard(unittest.TestCase):
    """Pin the wire form of IPv4 and L2TPv2 padding across rebuilds."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_ipv4_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4

        for name, options in IPV4.items():
            with self.subTest(name):
                raw = ipv4(options)
                parsed = IPv4(io.BytesIO(raw), len(raw))
                self.assertEqual(bytes(IPv4.from_data(parsed.info).data).hex(), raw.hex())

    def test_l2tpv2_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.link.l2tpv2 import L2TPv2

        for name, wire in L2TPV2.items():
            with self.subTest(name):
                raw = bytes.fromhex(wire)
                parsed = L2TPv2(io.BytesIO(raw), len(raw))
                self.assertEqual(parsed.info.padding, b'\xaa\xbb\xcc')
                self.assertEqual(bytes(L2TPv2.from_data(parsed.info).data).hex(), raw.hex())


if __name__ == '__main__':
    unittest.main()
