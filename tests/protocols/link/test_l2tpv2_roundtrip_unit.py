# -*- coding: utf-8 -*-
"""L2TPv2 keeps its reserved flag bits, and never drops a lone Ns or Nr.

GitHub issue #1207: the flags :class:`~pcapkit.corekit.fields.strings.BitField`
declared no reserved subfields, so bits 2, 3, 5 and 8-11 were lost on a
``from_data`` rebuild: ``200200010002ff03002145000000`` came back as
``000200010002ff03002145000000``.

GitHub issue #1208: :meth:`~pcapkit.protocols.link.l2tpv2.L2TPv2.make` set ``S``
only when both ``ns`` and ``nr`` were given, so ``L2TPv2(ns=7)`` silently wrote
neither. :rfc:`2661` §3.1 has ``S`` mark the presence of both fields together,
so a lone value is now refused with
:class:`~pcapkit.utilities.exceptions.ProtocolError`.

Every case builds its own octets in memory and reads no capture.

:class:`L2TPv2` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load, for the
reason :mod:`tests.protocols.link.test_ethernet_mac_roundtrip_unit` gives.

"""

import unittest

from tests._support import reimport_once_per_class

#: A PPP frame header and the first IPv4 octet, as the L2TPv2 payload.
PAYLOAD = bytes.fromhex('ff03002145')

#: Each reserved bit group on its own, then all of them at once.
RESERVED_MASKS = (0x2000, 0x1000, 0x0400, 0x00f0, 0x34f0)


class TestL2TPv2RoundTrip(unittest.TestCase):
    """Pin the reserved flag bits and the Ns/Nr pairing."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_issue_1207_reproduction(self) -> None:
        from pcapkit.protocols.link.l2tpv2 import L2TPv2

        raw = bytes.fromhex('200200010002ff03002145000000')
        parsed = L2TPv2(raw)
        self.assertEqual(parsed.info.flags.reserved, 0x2000)
        self.assertEqual(L2TPv2.from_data(parsed.info).data, raw)

    def test_each_reserved_mask_round_trips(self) -> None:
        from pcapkit.protocols.link.l2tpv2 import L2TPv2

        for mask in RESERVED_MASKS:
            raw = (mask | 0x0002).to_bytes(2, 'big') + bytes.fromhex('00010002') + PAYLOAD
            with self.subTest(mask=hex(mask)):
                parsed = L2TPv2(raw)
                self.assertEqual(parsed.info.flags.reserved, mask)
                self.assertEqual(L2TPv2.from_data(parsed.info).data, raw)

    def test_reserved_bits_round_trip_inside_udp(self) -> None:
        from pcapkit.protocols.transport.udp import UDP

        l2tp = bytes.fromhex('34f200010002') + PAYLOAD
        raw = (1701).to_bytes(2, 'big') * 2 + (8 + len(l2tp)).to_bytes(2, 'big') + b'\x00\x00' + l2tp
        parsed = UDP(raw)
        self.assertEqual(parsed.payload.info.flags.reserved, 0x34f0)
        self.assertEqual(UDP.from_data(parsed.info).data, raw)

    def test_make_writes_reserved_and_refuses_other_bits(self) -> None:
        from pcapkit.protocols.link.l2tpv2 import L2TPv2
        from pcapkit.utilities.exceptions import ProtocolError

        self.assertEqual(L2TPv2(type=0, reserved=0x0400).data[:2], bytes.fromhex('0402'))
        self.assertEqual(L2TPv2(type=0).data[:2], bytes.fromhex('0002'))
        for bad in (0x0001, 0x0800, 0x8000):
            with self.subTest(reserved=hex(bad)):
                with self.assertRaises(ProtocolError):
                    L2TPv2(type=0, reserved=bad)

    def test_issue_1208_lone_ns_or_nr_is_refused(self) -> None:
        from pcapkit.protocols.link.l2tpv2 import L2TPv2
        from pcapkit.utilities.exceptions import ProtocolError

        for kwargs in ({'ns': 7}, {'nr': 7}, {'ns': 0}, {'nr': 0}):
            with self.subTest(**kwargs):
                with self.assertRaises(ProtocolError):
                    L2TPv2(**kwargs)

    def test_ns_and_nr_together_round_trip(self) -> None:
        from pcapkit.protocols.link.l2tpv2 import L2TPv2

        made = L2TPv2(type=0, ns=7, nr=0)
        self.assertEqual(made.data, bytes.fromhex('08020000000000070000'))
        self.assertEqual((made.info.ns, made.info.nr), (7, 0))
        self.assertEqual(L2TPv2.from_data(made.info).data, made.data)


if __name__ == '__main__':
    unittest.main()
