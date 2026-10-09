# -*- coding: utf-8 -*-
"""Octets captured past an L2TPv2 or OSPF packet's own length survive a rebuild.

GitHub issue #1455: :class:`~pcapkit.protocols.link.l2tpv2.L2TPv2` reads its
Length field and :class:`~pcapkit.protocols.application.ospf.OSPF` its Packet
Length, but the octets after either were kept by no ``info``, so
:meth:`~pcapkit.protocols.protocol.ProtocolBase.from_data` dropped them: an
L2TPv2 header of Length 8 followed by two octets rebuilt as 8 octets of its 10,
and an OSPF header of Packet Length 24 followed by two as 24 of its 26.

Each layer now owns them as ``trailer``, as IPv4, IPv6 (#1209) and IPX (#1433)
do, and :meth:`make` writes a ``trailer`` outside the length it declares.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`,
c.f. ``tests/protocols/link/test_ethernet_mac_roundtrip_unit.py``.

"""

import unittest
import warnings

from tests._support import reimport_once_per_class


def _ospf(length: int) -> bytes:
    """Return a 24-octet OSPFv2 Hello header whose Packet Length is ``length``."""
    return b'\x02\x01' + length.to_bytes(2, 'big') + bytes(20)


#: L2TPv2 datagrams with octets past the Length field: (octets, trailer).
L2TP_TRAILER = {
    'header only': (bytes.fromhex('4002000800010002') + b'pp', b'pp'),
    'payload': (bytes.fromhex('4002000a00010002') + b'ab' + b'pp', b'pp'),
    'offset pad': (bytes.fromhex('42020010000100020004') + bytes(4) + b'ab' + b'pp', b'pp'),
    'sequence': (bytes.fromhex('4802000c0001000200050006') + b'\xee' * 3, b'\xee' * 3),
}

#: L2TPv2 datagrams that end at or before their own length, or carry none.
L2TP_NO_TRAILER = {
    'exact': bytes.fromhex('4002000a00010002') + b'ab',
    'truncated': bytes.fromhex('4002001000010002') + b'ab',
    'no Length field': bytes.fromhex('0002' '00010002') + b'abpp',
}

#: OSPF packets with octets past the Packet Length: (octets, trailer).
OSPF_TRAILER = {
    'header only': (_ospf(24) + b'zz', b'zz'),
    'payload': (_ospf(28) + b'abcd' + b'zz', b'zz'),
    # RFC 2328 D.4.3: the digest follows the packet and Packet Length omits it.
    'crypto digest': (b'\x02\x01\x00\x1c' + bytes(10) + b'\x00\x02' + bytes.fromhex('0000011000000001')
                      + b'abcd' + bytes(range(16)), bytes(range(16))),
}

#: OSPF packets that end at or before their own length.
OSPF_NO_TRAILER = {
    'exact': _ospf(28) + b'abcd',
    'truncated': _ospf(40) + b'abcd',
}


class TestL2TPv2TrailerKept(unittest.TestCase):
    """Pin the octets past an L2TPv2 Length field through ``from_data``."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_datagram_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.link.l2tpv2 import L2TPv2

        for name, (raw, trailer) in L2TP_TRAILER.items():
            with self.subTest(datagram=name):
                parsed = L2TPv2(raw, len(raw))
                self.assertEqual(parsed.info.trailer, trailer)
                self.assertEqual(bytes(parsed.__header__.payload),
                                 raw[parsed.info.hdr_len:len(raw) - len(trailer)])
                self.assertEqual(L2TPv2.from_data(parsed.info).data, raw)

    def test_no_trailer_key_without_excess(self) -> None:
        from pcapkit.protocols.link.l2tpv2 import L2TPv2

        for name, raw in L2TP_NO_TRAILER.items():
            with self.subTest(datagram=name):
                parsed = L2TPv2(raw, len(raw))
                self.assertNotIn('trailer', parsed.info)
                self.assertEqual(L2TPv2.from_data(parsed.info).data, raw)

    def test_udp_carrier_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.transport.udp import UDP

        l2tp, trailer = L2TP_TRAILER['payload']
        raw = bytes.fromhex('06a506a5') + (8 + len(l2tp)).to_bytes(2, 'big') + b'\x00\x00' + l2tp
        parsed = UDP(raw, len(raw))
        self.assertEqual(parsed.info.l2tp.trailer, trailer)
        self.assertEqual(UDP.from_data(parsed.info).data, raw)

    def test_make_writes_trailer_outside_the_length(self) -> None:
        from pcapkit.protocols.link.l2tpv2 import L2TPv2

        made = L2TPv2(length_flag=True, payload=b'ab', trailer=b'\x00\x01')
        self.assertEqual(made.info.length, 10)
        self.assertEqual(made.data[-4:], b'ab\x00\x01')
        self.assertEqual(made.info.trailer, b'\x00\x01')
        reparsed = L2TPv2(made.data, len(made.data))
        self.assertEqual(reparsed.info.trailer, b'\x00\x01')
        self.assertEqual(L2TPv2.from_data(reparsed.info).data, made.data)


class TestOSPFTrailerKept(unittest.TestCase):
    """Pin the octets past an OSPF Packet Length through ``from_data``."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_packet_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.application.ospf import OSPF

        for name, (raw, trailer) in OSPF_TRAILER.items():
            with self.subTest(packet=name):
                parsed = OSPF(raw, len(raw))
                self.assertEqual(parsed.info.trailer, trailer)
                self.assertEqual(bytes(parsed.__header__.payload), raw[24:len(raw) - len(trailer)])
                self.assertEqual(OSPF.from_data(parsed.info).data, raw)

    def test_no_trailer_key_without_excess(self) -> None:
        from pcapkit.protocols.application.ospf import OSPF

        for name, raw in OSPF_NO_TRAILER.items():
            with self.subTest(packet=name):
                parsed = OSPF(raw, len(raw))
                self.assertNotIn('trailer', parsed.info)
                self.assertEqual(OSPF.from_data(parsed.info).data, raw)

    def test_ipv4_carrier_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4

        ospf, trailer = OSPF_TRAILER['crypto digest']
        raw = (b'\x45\x00' + (20 + len(ospf)).to_bytes(2, 'big') + bytes(4)
               + b'\x01\x59' + bytes(2) + bytes(8) + ospf)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = IPv4(raw, len(raw))
        self.assertEqual(parsed.info.ospf.trailer, trailer)
        self.assertEqual(IPv4.from_data(parsed.info).data, raw)

    def test_make_writes_trailer_outside_the_length(self) -> None:
        from pcapkit.protocols.application.ospf import OSPF

        made = OSPF(payload=b'abcd', trailer=b'\x00\x01')
        self.assertEqual(made.info.len, 28)
        self.assertEqual(made.data[-6:], b'abcd\x00\x01')
        self.assertEqual(made.info.trailer, b'\x00\x01')
        reparsed = OSPF(made.data, len(made.data))
        self.assertEqual(reparsed.info.trailer, b'\x00\x01')
        self.assertEqual(OSPF.from_data(reparsed.info).data, made.data)


if __name__ == '__main__':
    unittest.main()
