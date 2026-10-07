# -*- coding: utf-8 -*-
"""IPv6 ``from_data`` keeps the extension-header chain, byte for byte.

GitHub issue #1177: :meth:`IPv6._make_data
<pcapkit.protocols.internet.ipv6.IPv6._make_data>` rebuilt the payload from
the upper layer alone, so every extension header between the IPv6 header and
that layer was dropped from the rebuild. An IPv6 header followed by an 8-octet
Routing header came back as 40 octets instead of 48.

Every case builds its own octets in memory and reads no capture.

:class:`IPv6` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load, so that
it belongs to the same :mod:`pcapkit` import as the extension-header classes
it dispatches to.

"""

import struct
import unittest

from tests._support import reimport_once_per_class

#: Next header codes.
HOPOPT, UDP, ROUTE, NONXT, OPTS, MH = 0, 17, 43, 59, 60, 135

#: PadN option filling an 8-octet options header.
PADN = bytes.fromhex('0104' '00000000')


def ext(next_: int, body: bytes) -> bytes:
    """Return a generic extension header with ``body`` after ``Hdr Ext Len``."""
    return struct.pack('!BB', next_, (len(body) + 2) // 8 - 1) + body


def ipv6(next_: int, payload: bytes) -> bytes:
    """Return an IPv6 header carrying ``payload``."""
    return (bytes.fromhex('60000000') + struct.pack('!HBB', len(payload), next_, 64)
            + bytes(15) + b'\x01' + bytes(15) + b'\x02' + payload)


#: UDP datagram with an 8-octet payload and no checksum.
UDP_DGRAM = struct.pack('!HHHH', 1234, 5678, 16, 0) + b'payload!'

PACKETS = {
    'hopopt': ipv6(HOPOPT, ext(NONXT, PADN)),
    'routing': ipv6(ROUTE, bytes.fromhex('3b00000000000000')),
    'routing-trailing-raw': ipv6(ROUTE, bytes.fromhex('3b00000000000000') + b'abcd'),
    'destination-options': ipv6(OPTS, ext(NONXT, PADN)),
    'mobility-header': ipv6(MH, bytes.fromhex('3b00000000000000')),
    'chain-with-repeated-header': ipv6(
        HOPOPT,
        ext(OPTS, PADN) + ext(ROUTE, PADN) + bytes.fromhex('3c00000000000000')
        + ext(UDP, PADN) + UDP_DGRAM,
    ),
}


class TestIPv6FromDataExtensionHeaders(unittest.TestCase):
    """Pin that a rebuild re-emits every extension header in wire order."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_from_data_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6

        for name, packet in PACKETS.items():
            with self.subTest(packet=name):
                parsed = IPv6(packet, len(packet))
                self.assertTrue(parsed.extension_headers, 'no extension header parsed')
                self.assertEqual(IPv6.from_data(parsed.info).data, packet)

    def test_repeated_header_keeps_both_instances(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6

        packet = PACKETS['chain-with-repeated-header']
        parsed = IPv6(packet, len(packet))
        self.assertEqual(
            [type(proto).__name__ for _, proto in parsed.extension_headers.items(multi=True)],
            ['HOPOPT', 'IPv6_Opts', 'IPv6_Route', 'IPv6_Opts'],
        )
        self.assertEqual(IPv6.from_data(parsed.info).data, packet)

    def test_chain_is_hidden_from_info_views(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6

        packet = PACKETS['routing']
        info = IPv6(packet, len(packet)).info
        self.assertNotIn('__exthdr__', list(info))
        self.assertNotIn('__exthdr__', info.to_dict())


if __name__ == '__main__':
    unittest.main()
