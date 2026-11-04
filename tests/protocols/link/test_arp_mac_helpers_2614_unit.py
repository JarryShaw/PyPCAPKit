# -*- coding: utf-8 -*-
"""GitHub issue #2614: ARP's Ethernet hardware address goes through the base MAC pair.

:meth:`ARP._read_addr_resolve <pcapkit.protocols.link.arp.protocol.ARP._read_addr_resolve>`
and :meth:`ARP._make_addr_resolve <pcapkit.protocols.link.arp.protocol.ARP._make_addr_resolve>`
read and make an Ethernet address with
:meth:`~pcapkit.protocols.protocol.Protocol._read_mac_addr` and
:meth:`~pcapkit.protocols.protocol.Protocol._make_mac_addr`, of any number of
octets since ``hlen`` is not fixed at 6, rather than with a pattern of the
module's own. The messages keep the class name as their prefix, which
:attr:`~pcapkit.protocols.protocol.Protocol.alias` cannot give before
:meth:`~pcapkit.protocols.link.arp.protocol.ARP.read` has run.

Every case builds its own octets in memory and reads no capture.

The classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import importlib
import unittest
from unittest import mock

from tests._support import reimport_once_per_class

#: ``(module, class)`` for every ARP-family class.
CLASSES = (
    ('pcapkit.protocols.link.arp.protocol', 'ARP'),
    ('pcapkit.protocols.link.inarp.protocol', 'InARP'),
    ('pcapkit.protocols.application.rarp.protocol', 'RARP'),
    ('pcapkit.protocols.application.drarp.protocol', 'DRARP'),
)


class TestARPMacHelpers(unittest.TestCase):
    """Pin the Ethernet branch of ARP's hardware address helpers."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_the_module_keeps_no_address_pattern(self) -> None:
        import pcapkit.protocols.link.arp.protocol as module
        from pcapkit.protocols.link.arp.protocol import ARP
        from pcapkit.protocols.protocol import ProtocolBase

        self.assertFalse(hasattr(module, 'PAT_MAC_ADDR'))
        self.assertIs(ARP._read_mac_addr, ProtocolBase._read_mac_addr)
        self.assertIs(ARP._make_mac_addr, ProtocolBase._make_mac_addr)

    def test_the_ethernet_branch_calls_the_base_pair(self) -> None:
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.protocols.link.arp.protocol import ARP
        from pcapkit.protocols.protocol import ProtocolBase

        arp = object.__new__(ARP)
        with mock.patch.object(ProtocolBase, '_make_mac_addr', autospec=True, return_value=b'made') as make, \
                mock.patch.object(ProtocolBase, '_read_mac_addr', autospec=True, return_value='read') as read:
            self.assertEqual(arp._make_addr_resolve('01:02', Hardware.Ethernet), b'made')
            self.assertEqual(arp._read_addr_resolve(b'\x01\x02', Hardware.Ethernet), 'read')
            # another hardware type keeps ARP's own hex form
            self.assertEqual(arp._make_addr_resolve('0102', Hardware.Frame_Relay), b'\x01\x02')
            self.assertEqual(arp._read_addr_resolve(b'\x01\x02', Hardware.Frame_Relay), '0102')
        make.assert_called_once_with(arp, '01:02', size=None, alias='ARP')
        read.assert_called_once_with(arp, b'\x01\x02')

    def test_any_number_of_octets_packs_and_reads_back(self) -> None:
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.protocols.link.arp.protocol import ARP

        arp = object.__new__(ARP)
        for addr, octets in (('', b''), (b'', b''), ('ab', b'\xab'), ('01-02-03', b'\x01\x02\x03'),
                             (bytearray(b'AA:bb:CC:dd:EE:ff'), bytes.fromhex('aabbccddeeff')),
                             ('01:02:03:04:05:06:07:08', bytes.fromhex('0102030405060708'))):
            with self.subTest(addr=addr):
                self.assertEqual(arp._make_addr_resolve(addr, Hardware.Ethernet), octets)
                self.assertEqual(arp._read_addr_resolve(octets, Hardware.Ethernet), octets.hex(':'))

    def test_the_messages_name_the_class(self) -> None:
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.utilities.exceptions import ProtocolError

        for module, name in CLASSES:
            proto = object.__new__(getattr(importlib.import_module(module), name))
            for addr, message in (('01:2', "invalid MAC address: '01:2'"),
                                  (':', "invalid MAC address: ':'"),
                                  ('01:02:', "invalid MAC address: '01:02:'"),
                                  (None, 'invalid MAC address: must be a str, bytes or bytearray, not None'),
                                  (True, 'invalid MAC address: must be a str, bytes or bytearray, not True')):
                with self.subTest(cls=name, addr=addr):
                    with self.assertRaises(ProtocolError) as context:
                        proto._make_addr_resolve(addr, Hardware.Ethernet)
                    self.assertEqual(str(context.exception), f'{name}: {message}')
            # another hardware type names a hardware address instead
            for addr, message in (('zz', "invalid hardware address: 'zz'"),
                                  (None, 'invalid hardware address: must be a str, bytes or bytearray, '
                                         'not None')):
                with self.subTest(cls=name, addr=addr, htype='Frame_Relay'):
                    with self.assertRaises(ProtocolError) as context:
                        proto._make_addr_resolve(addr, Hardware.Frame_Relay)
                    self.assertEqual(str(context.exception), f'{name}: {message}')


if __name__ == '__main__':
    unittest.main()
