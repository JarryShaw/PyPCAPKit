# -*- coding: utf-8 -*-
"""HIP rebuilds parsed packets byte for byte, and sizes raw parameters correctly.

GitHub issues from the internet-v4 round-trip audit (#1202):

* #1313 -- :meth:`HIP.make <pcapkit.protocols.internet.hip.HIP.make>` neither
  padded nor validated a raw ``bytes`` parameter, so a 12-octet one gave Header
  Length ``5`` over 52 packed octets.
* #1314 -- a packet with no parameters has no ``parameters`` attribute, and
  :meth:`~pcapkit.protocols.protocol.ProtocolBase.from_data` raised
  :exc:`AttributeError` on it.
* #1323 -- the ``PUZZLE`` ``Lifetime`` octet was kept only as a
  :class:`~datetime.timedelta`, so 197 of the 256 octets could not be rebuilt.
* #1328 -- the reserved bits of ``Controls`` and of ``ESP_INFO`` were written
  back as zero.

Every case builds its own octets in memory and reads no capture. :class:`HIP`
is imported inside each test, after :func:`~tests._support.reimport_once_per_class`,
for the reason :mod:`tests.protocols.link.test_ethernet_mac_roundtrip_unit` gives.

"""

import io
import unittest

from tests._support import reimport_once_per_class


def packet(params: bytes = b'', controls: bytes = b'\x00\x00') -> bytes:
    """Return a HIPv2 I1 packet carrying ``params`` (already 8-octet aligned)."""
    return (bytes([59, 4 + len(params) // 8, 0x01, 0x21]) + b'\x00\x00'
            + controls + bytes(32) + params)


class TestHIPRoundTrip(unittest.TestCase):
    """Pin the rebuilt octets of parsed HIP packets."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def assertRoundTrips(self, wire: bytes) -> None:  # pylint: disable=invalid-name
        from pcapkit.protocols.internet.hip import HIP

        parsed = HIP(io.BytesIO(wire), len(wire), extension=True)
        self.assertEqual(HIP.from_data(parsed.info).data.hex(), wire.hex())

    def test_raw_parameter_is_padded_and_counted(self) -> None:
        """#1313: a raw parameter is padded to 8 octets, and Header Length counts it."""
        from pcapkit.protocols.internet.hip import HIP

        for raw, padded in ((b'\x00\x41\x00\x08' + bytes(8), 16),
                            (b'\x00\x41\x00\x03' + bytes(3), 8),
                            (b'\x00\x41\x00\x04' + bytes(4), 8)):
            with self.subTest(raw=raw.hex()):
                wire = HIP.__new__(HIP).make(parameters=[raw]).pack()
                self.assertEqual(len(wire), 40 + padded)
                self.assertEqual((wire[1] + 1) * 8, len(wire))
                self.assertEqual(wire[40:], raw + bytes(padded - len(raw)))

    def test_parameterless_packet_round_trips(self) -> None:
        """#1314: Header Length 4 and no parameters rebuilds unchanged."""
        self.assertRoundTrips(packet())

    def test_every_puzzle_lifetime_octet_round_trips(self) -> None:
        """#1323: all 256 ``Lifetime`` octets survive, including 0-11 and 79-255."""
        for octet in range(256):
            with self.subTest(octet=octet):
                self.assertRoundTrips(packet(
                    bytes.fromhex('0101000c01') + bytes([octet]) + b'op' + bytes(8)))

    def test_puzzle_lifetime_is_derived_from_the_octet(self) -> None:
        """#1323: ``lifetime`` is informational, ``None`` beyond ``timedelta.max``."""
        import datetime

        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.utilities.exceptions import ProtocolError

        for octet, lifetime in ((32, datetime.timedelta(seconds=1)),
                                (0, datetime.timedelta(0)),
                                (78, datetime.timedelta(seconds=2 ** 46)),
                                (79, None), (255, None)):
            with self.subTest(octet=octet):
                wire = packet(bytes.fromhex('0101000c01') + bytes([octet]) + b'op' + bytes(8))
                param = HIP(io.BytesIO(wire), len(wire), extension=True).info.parameters[Parameter.PUZZLE]
                self.assertEqual(param.lifetime_exponent, octet)
                self.assertEqual(param.lifetime, lifetime)

        proto = HIP.__new__(HIP)
        self.assertEqual(proto._make_param_puzzle(
            Parameter.PUZZLE, version=2, lifetime_exponent=7, random=1 << 63).lifetime, 7)
        with self.assertRaises(ProtocolError):
            proto._make_param_puzzle(Parameter.PUZZLE, version=2, lifetime_exponent=256)

    def test_controls_reserved_bits_round_trip(self) -> None:
        """#1328: Controls ``fffe`` and ``ffff`` rebuild unchanged."""
        for controls in (b'\xff\xfe', b'\xff\xff', b'\x80\x01'):
            with self.subTest(controls=controls.hex()):
                self.assertRoundTrips(packet(controls=controls))

    def test_esp_info_reserved_round_trips(self) -> None:
        """#1328: the two ``ESP_INFO`` reserved octets rebuild unchanged."""
        self.assertRoundTrips(packet(bytes.fromhex('0041000c' 'abcd' '0102')
                                     + bytes.fromhex('0a0b0c0d' '01020304')))


if __name__ == '__main__':
    unittest.main()
