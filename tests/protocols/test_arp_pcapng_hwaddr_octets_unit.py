# -*- coding: utf-8 -*-
"""ARP and PCAP-NG pack hardware addresses as raw octets.

GitHub issue #1134: :meth:`ARP._make_addr_resolve
<pcapkit.protocols.link.arp.ARP._make_addr_resolve>`, :meth:`PCAPNG._make_mac_addr
<pcapkit.protocols.misc.pcapng.PCAPNG._make_mac_addr>` and :meth:`PCAPNG._make_eui_addr
<pcapkit.protocols.misc.pcapng.PCAPNG._make_eui_addr>` stripped the separators
from a ``aa:bb:cc:dd:ee:ff`` string and returned the remaining *hex text*, so
``make()`` wrote the ASCII digits of the address onto the wire. ARP did the
same for the plain hex string it parses a non-Ethernet hardware address into.

Every case builds its own octets in memory and reads no capture.

"""

import collections
import unittest

from pcapkit.const.arp.hardware import Hardware
from pcapkit.const.pcapng.block_type import BlockType
from pcapkit.const.pcapng.option_type import OptionType
from pcapkit.protocols.link.arp import ARP
from pcapkit.protocols.misc.pcapng import PCAPNG
from pcapkit.protocols.schema.misc.pcapng import IF_EUIAddrOption, IF_MACAddrOption
from pcapkit.utilities.exceptions import ProtocolError

#: ARP request: htype, ptype (IPv4), hlen, plen, oper, then sha/spa/tha/tpa.
ARP_ETHERNET = bytes.fromhex('0001' '0800' '06' '04' '0001'
                             '0123456789ab' '0a000001' 'fedcba987654' '0a000002')


class TestARPHardwareAddressOctets(unittest.TestCase):
    """Pin the wire form of the ARP hardware address fields."""

    def test_make_packs_mac_addresses_as_octets(self) -> None:
        proto = ARP(sha='01:23:45:67:89:ab', spa='10.0.0.1',
                    tha='fe-dc-ba-98-76-54', tpa='10.0.0.2')
        self.assertEqual(proto.data, ARP_ETHERNET)
        self.assertEqual(proto.info.sha, '01:23:45:67:89:ab')
        self.assertEqual(proto.info.tha, 'fe:dc:ba:98:76:54')

    def test_from_data_rebuilds_byte_for_byte(self) -> None:
        parsed = ARP(ARP_ETHERNET)
        self.assertEqual(ARP.from_data(parsed.info).data, ARP_ETHERNET)

    def test_non_ethernet_hardware_types(self) -> None:
        cases = [
            (Hardware.IEEE_802_Networks, '0123456789ab'),
            (Hardware.Fibre_Channel, 'aabbcc'),
            (Hardware.EUI_64, '0011223344556677'),
        ]
        for htype, addr in cases:
            with self.subTest(htype=htype.name):
                octets = bytes.fromhex(addr)
                # the hex string the parser yields, and raw octets, both pack as octets
                proto = ARP(htype=htype, hlen=len(octets), sha=addr, tha=octets)
                self.assertEqual(proto.__header__.sha, octets)
                self.assertEqual(proto.__header__.tha, octets)
                parsed = ARP(proto.data)
                self.assertEqual(parsed.info.sha, addr)
                self.assertEqual(ARP.from_data(parsed.info).data, proto.data)

    def test_invalid_hardware_address_raises(self) -> None:
        arp = object.__new__(ARP)
        with self.assertRaises(ProtocolError):
            arp._make_addr_resolve('not-a-mac', Hardware.Ethernet)
        with self.assertRaises(ProtocolError):
            arp._make_addr_resolve('not-hex', Hardware.Fibre_Channel)


class TestPCAPNGHardwareAddressOctets(unittest.TestCase):
    """Pin the wire form of the ``if_MACaddr`` and ``if_EUIaddr`` options."""

    def setUp(self) -> None:
        self.pcapng = object.__new__(PCAPNG)
        self.pcapng._type = BlockType.Interface_Description_Block
        self.pcapng._opt = collections.Counter()

    def test_if_macaddr_packs_six_octets(self) -> None:
        for addr in ('01:23:45:67:89:ab', b'01-23-45-67-89-AB'):
            with self.subTest(addr=addr):
                schema = self.pcapng._make_option_if_mac(OptionType.if_MACaddr, interface=addr)
                self.assertEqual(bytes(schema), bytes.fromhex('0600' '0600' '0123456789ab' '0000'))
                unpacked = IF_MACAddrOption.unpack(bytes(schema))
                self.assertEqual(self.pcapng._read_mac_addr(unpacked.interface), '01:23:45:67:89:ab')

    def test_if_euiaddr_packs_eight_octets(self) -> None:
        for addr in ('02:34:56:ff:fe:78:9a:bc', '02-34-56-FF-FE-78-9A-BC'):
            with self.subTest(addr=addr):
                schema = self.pcapng._make_option_if_eui(OptionType.if_EUIaddr, interface=addr)
                self.assertEqual(bytes(schema), bytes.fromhex('0700' '0800' '023456fffe789abc'))
                unpacked = IF_EUIAddrOption.unpack(bytes(schema))
                self.assertEqual(self.pcapng._read_eui_addr(unpacked.interface),
                                 '02:34:56:ff:fe:78:9a:bc')


if __name__ == '__main__':
    unittest.main()
