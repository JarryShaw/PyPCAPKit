# -*- coding: utf-8 -*-
"""The :mod:`pcapkit.vendor.dhcp` crawlers read IANA's BOOTP and DHCP parameter tables (#2959).

Each crawler is fed rows in the shape IANA's CSV export gives them, quirks
included, and the members it renders are checked. Nothing is fetched.

"""
from __future__ import annotations

import unittest

#: Test tier (#1958): the vendor extra is installed on latest alone, as for the
#: other crawler tests.
__tier__ = 'LATEST'


def _render(crawler: 'type', rows: 'list[str]') -> 'str':
    """The module ``crawler`` generates from ``rows``, with no fetch and no write."""
    self = object.__new__(crawler)
    self.NAME = crawler.__name__
    self.DOCS = crawler.__doc__
    self.record = self.count(rows)
    return self.context(rows)


class DHCPCrawlerTests(unittest.TestCase):
    """What each crawler makes of its registry's rows."""

    def test_option_takes_one_member_per_tag(self) -> None:
        from pcapkit.vendor.dhcp.option import Option

        text = _render(Option, [
            'Tag,Name,"Data\n            Length",Meaning,Reference',
            '0,Pad,0,None,[RFC 2132]',
            '1,Subnet Mask,4,Subnet Mask Value,[RFC 2132]',
            '19,Forward On/Off,1,Enable/Disable IP Forwarding,[RFC 2132]',
            '84,REMOVED/Unassigned,,,[RFC 3679]',
            '96,REMOVED/Unassigned,,,[RFC 3679]',
            '102-107,REMOVED/Unassigned,,,[RFC 3679]',
            '128,PXE - undefined (vendor specific),,,[RFC 4578]',
            '128,"Etherboot signature. 6 bytes:\nE4:45:74:68:00:00",,,',
            '129,PXE - undefined (vendor specific),,,[RFC 4578]',
            '175,"Etherboot (Tentatively Assigned -\n2005-06-23)",,,',
            '208,PXELINUX Magic,4,magic string = F1:00:74:7E,[RFC 5071]; [Deprecated]',
            '224-254,Reserved (Private Use),,,',
            '255,End,0,None,[RFC 2132]',
        ])
        for line in ('    Pad = 0', '    Subnet_Mask = 1', '    Forward_On_Off = 19',
                     '    REMOVED_Unassigned_84 = 84', '    REMOVED_Unassigned_96 = 96', '    PXE_undefined_128 = 128', '    PXE_undefined_129 = 129',
                     '    Etherboot = 175', '    PXELINUX_Magic = 208', '    End = 255',
                     '#: Pad [:rfc:`2132`]', '#: Subnet Mask -- Subnet Mask Value [:rfc:`2132`]',
                     '#: PXE - undefined (vendor specific) [:rfc:`4578`]; Etherboot signature. 6',
                     '#: PXELINUX Magic -- magic string = F1:00:74:7E [:rfc:`5071`][Deprecated]',
                     'if 102 <= value <= 107:', "return cls._unregistered_member(value, 'REMOVED_Unassigned')",
                     'if 224 <= value <= 254:', "return cls._unregistered_member(value, 'Reserved')"):
            with self.subTest(line=line):
                self.assertIn(line, text)
        # NOTE: The second row of tag 128 joins its comment, and makes no member.
        self.assertEqual(text.count('= 128'), 1)

    def test_message_type_resolves_unlisted_values(self) -> None:
        from pcapkit.vendor.dhcp.message_type import MessageType

        text = _render(MessageType, [
            'Value,Message Type,Reference',
            '1,DHCPDISCOVER,[RFC 2132]',
            '18,DHCPTLS,[RFC 7724]',
        ])
        for line in ('    DHCPDISCOVER = 1', '    DHCPTLS = 18', '#: DHCPDISCOVER [:rfc:`2132`]',
                     "        return cls._unregistered_member(value, 'Unassigned')"):
            with self.subTest(line=line):
                self.assertIn(line, text)
        self.assertNotIn('return super()._missing_(value)', text)

    def test_relay_agent_suboption_names_the_reserved_code(self) -> None:
        from pcapkit.vendor.dhcp.relay_agent_suboption import RelayAgentSubOption

        text = _render(RelayAgentSubOption, [
            'Code,Sub-Option Description,Reference',
            '1,Agent Circuit ID Sub-option,[RFC 3046]',
            '3,"Sub-option 3 is reserved and should      \nnot be assigned at this time;\nproprietary and '
            'incompatible usages\nof this sub-option value have been\nseen limited deployment.",[Ralph_Droms]',
            '20-150,Unassigned,',
        ])
        for line in ('    Agent_Circuit_ID_Sub_option = 1', '    Reserved_3 = 3',
                     '#: Sub-option 3 is reserved and should not be assigned at this time;',
                     'if 20 <= value <= 150:', "        return cls._unregistered_member(value, 'Unassigned')"):
            with self.subTest(line=line):
                self.assertIn(line, text)

    def test_opcode_reads_its_data(self) -> None:
        from pcapkit.vendor.dhcp.opcode import DATA, Opcode

        text = _render(Opcode, Opcode.request(object.__new__(Opcode)))  # type: ignore[arg-type]
        self.assertEqual(DATA, {1: ('BOOTREQUEST', 'BOOTREQUEST [:rfc:`951`]'),
                                2: ('BOOTREPLY', 'BOOTREPLY [:rfc:`951`]')})
        for line in ('    BOOTREQUEST = 1', '    BOOTREPLY = 2',
                     "        return cls._unregistered_member(value, 'Unassigned')"):
            with self.subTest(line=line):
                self.assertIn(line, text)

    def test_generated_modules_match_the_committed_ones(self) -> None:
        """The crawler that reads a literal reproduces its committed module."""
        import pathlib

        from pcapkit.vendor.dhcp.opcode import Opcode

        crawler = object.__new__(Opcode)
        crawler.NAME, crawler.DOCS = 'Opcode', Opcode.__doc__
        data = crawler.request()
        crawler.record = crawler.count(data)
        rendered = '\n'.join(line.rstrip() for line in crawler.context(data).splitlines()
                             if line == '' or line.strip())
        path = pathlib.Path(__file__).resolve().parents[2] / 'pcapkit' / 'const' / 'dhcp' / 'opcode.py'
        self.assertEqual(rendered + '\n', path.read_text())


if __name__ == '__main__':
    unittest.main()
