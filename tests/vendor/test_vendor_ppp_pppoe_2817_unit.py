# -*- coding: utf-8 -*-
"""GitHub issue #2817: the PPP and PPPoE crawlers render IANA's own spellings.

Each fixture is an excerpt of the live registry's CSV, read on 2026-11-21:
``ppp-numbers-2.csv`` writes a value in hex and one range as ``028b-1exx``, and
``pppoe-parameters-1.csv`` and ``-2.csv`` write ``7 (0x07)``, a bare ``8`` and a
decimal range. Each is fed through the crawler's own ``request``, ``count`` and
``process``, with no network call.

"""
from __future__ import annotations

import importlib.util
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): renders constant modules from recorded data, which the vendor
#: scripts regenerate on one interpreter.
__tier__ = 'LATEST'

#: Every distribution importing :mod:`pcapkit.vendor` needs.
VENDOR_DEPS = ('requests', 'bs4', 'html5lib')

#: Whether the crawlers are importable at all.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)

#: An excerpt of ``ppp-numbers-2.csv``, PPP DLL Protocol Numbers.
PPP_PROTOCOL = (
    'Value (in hex),Protocol Name,Reference\r\n'
    '0007-001f,Reserved (transparency inefficient),[RFC 1661]\r\n'
    '0021,Internet Protocol version 4,[RFC 1332]\r\n'
    '0043,Ascom Timeplex,\r\n'
    '0201,802.1d Hello Packets,[RFC 3518]\r\n'
    '028b-1exx,Reserved for compression inefficient,\r\n'
    '400B,Cetacean Network Detection Protocol,[Curtis_A_Siller_Jr]\r\n'
    '8043,Ascom Timeplex,\r\n'
    'c021,Link Control Protocol,[RFC 1661]\r\n'
)

#: An excerpt of ``pppoe-parameters-2.csv``, PPPoE Active Discovery Code fields.
PPPOE_CODE = (
    'Code,Name,Description,Reference\r\n'
    '0 (0x00),PPP Session Stage,See the reference,[RFC 2516]\r\n'
    '1-6,Unassigned,,\r\n'
    '7 (0x07),"PADO, Offer",See the reference,[RFC 2516]\r\n'
    '8,Unassigned,,\r\n'
    '211 (0xd3),"PADM, Message",See the reference,"[Carrel D., Simone D., Ho C., Stoner T., ""Extensions\n'
    'to a Method for Transmitting PPP Over Ethernet\n(PPPoE)"", work in progress.]"\r\n'
)

#: An excerpt of ``pppoe-parameters-1.csv``, PPPoE TAG values.
PPPOE_TAG = (
    'Value,Name,Description,Reference\r\n'
    '0 (0x0000),End-Of-List,See the reference,[RFC 2516]\r\n'
    '1-256,Unassigned,,\r\n'
    '257 (0x0101),Service-Name,See the reference,[RFC 2516]\r\n'
    '516-65535,Unassigned,,\r\n'
)


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class PPPCrawlerTests(unittest.TestCase):
    """The rendered members and ranges, line by line."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _process(cls: 'Any', text: 'str') -> 'tuple[list[str], list[str]]':
        """``process`` as ``__init__`` would run it, without the fetch and the write."""
        vendor = cls.__new__(cls)
        vendor.NAME = cls.__name__
        vendor.DOCS = cls.__doc__
        lines = vendor.request(text)
        vendor.record = vendor.count(lines)
        return vendor.process(lines)

    def test_ppp_protocol_numbers(self) -> None:
        from pcapkit.vendor.ppp.protocol import Protocol

        enum, miss = self._process(Protocol, PPP_PROTOCOL)
        self.assertEqual([entry.split('\n    ')[-1] for entry in enum], [
            'Internet_Protocol_version_4 = 0x0021',
            'Ascom_Timeplex_0x0043 = 0x0043',
            'Protocol_802_1d_Hello_Packets = 0x0201',
            'Cetacean_Network_Detection_Protocol = 0x400B',
            'Ascom_Timeplex_0x8043 = 0x8043',
            'Link_Control_Protocol = 0xC021',
        ])
        self.assertEqual(enum[0].split('\n')[0], '#: Internet Protocol version 4 [:rfc:`1332`]')
        self.assertEqual(miss[0::3], ['if 0x0007 <= value <= 0x001F:', 'if 0x028B <= value <= 0x1EFF:'])
        self.assertEqual(miss[2::3], ["    return cls._unregistered_member(value, 'Reserved')",
                                      "    return cls._unregistered_member(value, "
                                      "'Reserved_for_compression_inefficient')"])

    def test_pppoe_codes_and_tags(self) -> None:
        from pcapkit.vendor.pppoe.code import Code
        from pcapkit.vendor.pppoe.tag import Tag

        enum, miss = self._process(Code, PPPOE_CODE)
        self.assertEqual([entry.split('\n    ')[-1] for entry in enum], [
            'PPP_Session_Stage = 0x00', 'PADO_Offer = 0x07', 'Unassigned_0x08 = 0x08', 'PADM_Message = 0xD3',
        ])
        self.assertIn('"Extensions to a\n    #: Method for Transmitting PPP Over Ethernet (PPPoE)"', enum[3])
        self.assertEqual(miss, ['if 0x01 <= value <= 0x06:', '    #: Unassigned',
                                "    return cls._unregistered_member(value, 'Unassigned')"])

        enum, miss = self._process(Tag, PPPOE_TAG)
        self.assertEqual([entry.split('\n    ')[-1] for entry in enum],
                         ['End_Of_List = 0x0000', 'Service_Name = 0x0101'])
        self.assertEqual(miss[0::3], ['if 0x0001 <= value <= 0x0100:', 'if 0x0204 <= value <= 0xFFFF:'])


if __name__ == '__main__':
    unittest.main()
