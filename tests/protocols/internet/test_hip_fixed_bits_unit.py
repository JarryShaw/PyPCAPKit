# -*- coding: utf-8 -*-
"""HIP parses and keeps the two fixed header bits, whatever their value.

GitHub issue #1459. The leading bit of the ``Packet Type`` octet and the
low-order bit of the ``Version`` octet are reserved for SHIM6 compatibility:
they "MUST be set as shown when sending and MUST be ignored when receiving"
(:rfc:`7401#section-5.1`). ``HIP.read`` raised ``ProtocolError`` unless they
read ``0`` and ``1``.

The fix stops validating them, carries them as ``packet_fixed`` and
``version_fixed``, and lets ``make()`` write them, defaulting to the
RFC-prescribed values.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.
"""

import unittest

from tests._support import reimport_once_per_class

#: Header fields shared by every HIP packet built here.
HIP_BASE = {
    'next': 59, 'packet': 16, 'version': 2, 'checksum': b'\x00\x00',
    'controls_anonymous': False, 'shit': 0, 'rhit': 0, 'payload': b'',
}

#: The two HITs that follow the 8-octet fixed header.
HITS = b'\x11' * 16 + b'\x22' * 16


def _raw(pkt: int, ver: int) -> bytes:
    """Build a 40-octet HIP header with the given ``Packet Type`` and ``Version`` octets."""
    return bytes([59, 4, pkt, ver]) + bytes(4) + HITS


class TestHIPFixedBits(unittest.TestCase):
    """Pin the two fixed header bits across parse, rebuild and make."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_parse_keeps_fixed_bits(self) -> None:
        from pcapkit.protocols.internet.hip import HIP

        cases = {
            'packet-fixed clear, version-fixed clear': (0x10, 0x20, 0, 0),
            'packet-fixed set, version-fixed set': (0x90, 0x21, 1, 1),
            'both inverted': (0x90, 0x20, 1, 0),
            'as sent': (0x10, 0x21, 0, 1),
            'inverted with reserved bits': (0x90, 0x2e, 1, 0),
        }
        for label, (pkt, ver, pfix, vfix) in cases.items():
            with self.subTest(label):
                raw = _raw(pkt, ver)
                parsed = HIP(raw, len(raw), extension=True)
                self.assertEqual(parsed.info.packet_fixed, pfix)
                self.assertEqual(parsed.info.version_fixed, vfix)
                self.assertEqual(int(parsed.info.type), pkt & 0x7f)
                self.assertEqual(parsed.info.version, ver >> 4)
                self.assertEqual(parsed.info.reserved, (ver >> 1) & 0b111)
                self.assertEqual(HIP.from_data(parsed.info).data, raw)

    def test_make_defaults_to_rfc_values(self) -> None:
        from pcapkit.protocols.internet.hip import HIP

        built = HIP(extension=True, **HIP_BASE).data
        self.assertEqual(built[2], 0x10)
        self.assertEqual(built[3], 0x21)
        parsed = HIP(built, len(built), extension=True)
        self.assertEqual(parsed.info.packet_fixed, 0)
        self.assertEqual(parsed.info.version_fixed, 1)

    def test_make_honours_explicit_values(self) -> None:
        from pcapkit.protocols.internet.hip import HIP

        built = HIP(packet_fixed=1, version_fixed=0, extension=True, **HIP_BASE).data
        self.assertEqual(built[2], 0x90)
        self.assertEqual(built[3], 0x20)
        parsed = HIP(built, len(built), extension=True)
        self.assertEqual(parsed.info.packet_fixed, 1)
        self.assertEqual(parsed.info.version_fixed, 0)
        self.assertEqual(HIP.from_data(parsed.info).data, built)


if __name__ == '__main__':
    unittest.main()
