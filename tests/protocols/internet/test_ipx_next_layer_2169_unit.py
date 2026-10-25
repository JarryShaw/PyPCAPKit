# -*- coding: utf-8 -*-
"""An IPX payload is dissected by IPX Packet Type, not as an IP protocol number.

GitHub issue #2169: :meth:`IPX.read <pcapkit.protocols.internet.ipx.IPX.read>`
handed the IPX Packet Type to the next-layer lookup it inherits from
:class:`~pcapkit.protocols.internet.internet.Internet`, whose registry is keyed
by IP protocol number. So Packet Type 17 (NCP) parsed as UDP, 4 (PEP) as IPv4
and 6 as TCP; and Packet Type 0 counted as an IPv6 Hop-by-Hop Options header
towards :data:`~pcapkit.utilities.config.EXTENSION_HEADER_LIMIT`.

:class:`~pcapkit.protocols.internet.ipx.IPX` keeps a registry of its own, keyed
by Packet Type, and its payload is Raw unless an IPX-native protocol is
registered there.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import io
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class

#: Destination and source IPX addresses.
ADDRS = bytes(range(1, 25))

#: An IPv4 header carrying nothing, which parses as IPv4 when looked up by IP protocol number 4.
IPV4 = bytes.fromhex('4500' '0014' '0000' '0000' '4011' '0000' '0a000001' '0a000002')
#: A TCP header carrying nothing, which parses as TCP when looked up by IP protocol number 6.
TCP = bytes.fromhex('0050' '1f90' '00000001' '00000000' '5002' 'ffff' '0000' '0000')
#: An 8-octet payload, which parses as UDP when looked up by IP protocol number 17.
UDP = bytes.fromhex('0035' '0035' '0008' '0000')


def _ipx(packet_type: int, payload: bytes) -> bytes:
    """Return an IPX packet of ``packet_type`` carrying ``payload``."""
    length = 30 + len(payload)
    return b'\xff\xff' + length.to_bytes(2, 'big') + b'\x00' + bytes([packet_type]) + ADDRS + payload


#: Packet Types that share a number with a dissected IP protocol, and a payload
#: that protocol would parse.
PACKETS = {
    'NCP-17': _ipx(17, UDP),
    'PEP-4': _ipx(4, IPV4),
    'type-6': _ipx(6, TCP),
}


class TestIPXNextLayer(unittest.TestCase):
    """Pin the IPX next-layer dispatch to its own Packet Type registry."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_payload_is_raw_and_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.internet.ipx import IPX
        from pcapkit.protocols.misc.raw import Raw

        for name, packet in PACKETS.items():
            with self.subTest(packet=name), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                parsed = IPX(io.BytesIO(packet), len(packet))
                self.assertIs(type(parsed.payload), Raw)
                self.assertEqual(IPX.from_data(parsed.info).data, packet)

    def test_registered_ipx_protocol_is_dissected(self) -> None:
        from pcapkit.const.ipx.packet import Packet
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.internet.ipx import IPX
        from pcapkit.protocols.transport.udp import UDP as Proto_UDP

        self.assertIsNot(IPX.__proto__, Internet.__proto__)
        packet = PACKETS['NCP-17']
        with mock.patch.dict(IPX.__proto__, {Packet.NCP: Proto_UDP}), warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = IPX(io.BytesIO(packet), len(packet))
        self.assertIs(type(parsed.payload), Proto_UDP)

    def test_packet_type_zero_is_no_extension_header(self) -> None:
        from pcapkit.protocols.internet.ipx import IPX
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.utilities import config
        from pcapkit.utilities.warnings import ProtocolWarning

        packet = _ipx(0, b'abcd')
        with mock.patch.object(config, 'EXTENSION_HEADER_LIMIT', 0), warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            parsed = IPX(io.BytesIO(packet), len(packet))
        self.assertIs(type(parsed.payload), Raw)
        self.assertIsNone(parsed.payload.info.error)
        self.assertEqual([w for w in caught if issubclass(w.category, ProtocolWarning)], [])

    def test_protocol_is_the_packet_type(self) -> None:
        from pcapkit.const.ipx.packet import Packet
        from pcapkit.protocols.internet.ipx import IPX

        packet = PACKETS['NCP-17']
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = IPX(io.BytesIO(packet), len(packet))
        self.assertIs(parsed.protocol, Packet.NCP)
        self.assertEqual(IPX.protocol.fget.__annotations__['return'], 'Enum_Packet')


if __name__ == '__main__':
    unittest.main()
