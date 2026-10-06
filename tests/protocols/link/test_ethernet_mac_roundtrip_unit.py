# -*- coding: utf-8 -*-
"""Ethernet packs MAC addresses as six octets, and rebuilds byte for byte.

GitHub issue #1123: :meth:`Ethernet._make_mac_addr
<pcapkit.protocols.link.ethernet.Ethernet._make_mac_addr>` stripped the
separators from a ``aa:bb:cc:dd:ee:ff`` string and returned the remaining
*hex text*, which the 6-octet schema field then truncated. So ``make()``
wrote the ASCII digits of the address onto the wire, and
:meth:`~pcapkit.protocols.protocol.ProtocolBase.from_data` over a parsed
frame could not reproduce it.

Every case builds its own octets in memory and reads no capture.

"""

import unittest

from pcapkit.protocols.link.ethernet import Ethernet

#: Destination MAC, source MAC, EtherType (IPv4) and a short payload.
FRAMES = {
    'nontrivial': bytes.fromhex('0123456789ab' 'fedcba987654' '0800') + b'payload',
    'all-zero': bytes(12) + bytes.fromhex('0800') + b'payload',
}


class TestEthernetMacRoundTrip(unittest.TestCase):
    """Pin the wire form of the MAC address fields."""

    def test_make_packs_mac_addresses_as_octets(self) -> None:
        proto = Ethernet(dst='01:23:45:67:89:ab', src='fe-dc-ba-98-76-54',
                         payload=b'payload')
        self.assertEqual(proto.data, FRAMES['nontrivial'])
        self.assertEqual(proto.info.dst, '01:23:45:67:89:ab')
        self.assertEqual(proto.info.src, 'fe:dc:ba:98:76:54')

    def test_make_default_mac_is_all_zero_octets(self) -> None:
        proto = Ethernet(payload=b'payload')
        self.assertEqual(proto.data, FRAMES['all-zero'])

    def test_from_data_rebuilds_byte_for_byte(self) -> None:
        for name, frame in FRAMES.items():
            with self.subTest(frame=name):
                parsed = Ethernet(frame)
                rebuilt = Ethernet.from_data(parsed.info)
                self.assertEqual(rebuilt.data, frame)
                self.assertEqual(rebuilt.info.dst, parsed.info.dst)
                self.assertEqual(rebuilt.info.src, parsed.info.src)


if __name__ == '__main__':
    unittest.main()
