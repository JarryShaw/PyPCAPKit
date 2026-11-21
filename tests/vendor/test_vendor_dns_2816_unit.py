# -*- coding: utf-8 -*-
"""The :mod:`pcapkit.vendor.dns` crawlers read IANA's DNS parameter tables (#2816).

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


class DNSCrawlerTests(unittest.TestCase):
    """What each crawler makes of its registry's rows."""

    def test_rr_type_reads_the_mnemonic_column(self) -> None:
        from pcapkit.vendor.dns.rr_type import RRType

        text = _render(RRType, [
            'TYPE,Value,Meaning,Reference,Template,Registration Date',
            'Reserved,0,,[RFC 6895],,2021-03-08',
            'A,1,a host address,[RFC 1035],,',
            'NSAP-PTR,23,"for domain name pointer, NSAP style (DEPRECATED)",[RFC 1706],,',
            '*,255,A request for some or all records,[RFC 1035]; [RFC 8482],,',
            'Unassigned,265-32767,,,,',
            'Private use,65280-65534,,,,',
            'Reserved,65535,,,,',
        ])
        for line in ('    Reserved_0 = 0', '    A = 1', '    NSAP_PTR = 23', '    ANY = 255',
                     '    Reserved_65535 = 65535', '#: A -- a host address [:rfc:`1035`]',
                     "return cls._unregistered_member(value, 'Private_use')",
                     'if 265 <= value <= 32767:'):
            with self.subTest(line=line):
                self.assertIn(line, text)

    def test_rr_class_takes_the_mnemonic(self) -> None:
        from pcapkit.vendor.dns.rr_class import RRClass

        text = _render(RRClass, [
            'Decimal,Hexadecimal,Name,Reference',
            '0,0x0000,Reserved,[RFC 6895]',
            '1,0x0001,Internet (IN),[RFC 1035]',
            '3,0x0003,Chaos (CH),"[D. Moon, ""Chaosnet"", A.I. Memo 628, Massachusetts Institute of\n'
            'Technology Artificial Intelligence Laboratory, June 1981.]"',
            '254,0x00FE,QCLASS NONE,[RFC 2136]',
            '255,0x00FF,QCLASS * (ANY),[RFC 1035]',
            '256-65279,0x0100-0xFEFF,Unassigned,',
        ])
        for line in ('    Reserved_0 = 0', '    IN = 1', '    CH = 3', '    NONE = 254', '    ANY = 255',
                     'Memo 628, Massachusetts Institute of', 'if 256 <= value <= 65279:'):
            with self.subTest(line=line):
                self.assertIn(line, text)

    def test_opcode_takes_an_upper_case_parenthetical(self) -> None:
        from pcapkit.vendor.dns.opcode import Opcode

        text = _render(Opcode, [
            'OpCode,Name,Reference',
            '0,Query,[RFC 1035]',
            '1,"IQuery  (Inverse Query, OBSOLETE)",[RFC 3425]',
            '6,DNS Stateful Operations (DSO),[RFC 8490]',
            '7-15,Unassigned,',
        ])
        for line in ('    Query = 0', '    IQuery = 1', '    DSO = 6', '0 <= value <= 15'):
            with self.subTest(line=line):
                self.assertIn(line, text)

    def test_rcode_merges_and_aliases(self) -> None:
        from pcapkit.vendor.dns.rcode import RCode

        text = _render(RCode, [
            'RCODE,Name,Description,Reference',
            '0,NoError,No Error,[RFC 1035]',
            '9,NotAuth,Server Not Authoritative for zone,[RFC 2136]',
            '9,NotAuth,Not Authorized,[RFC 8945]',
            '12-15,Unassigned,,',
            '16,BADVERS,Bad OPT Version,[RFC 6891]',
            '16,BADSIG,TSIG Signature Failure,[RFC 8945]',
            '3841-4095,Reserved for Private Use,,[RFC 6895]',
            '65535,"Reserved, can be allocated by Standards Action",,[RFC 6895]',
        ])
        self.assertEqual(text.count('    NotAuth = 9'), 1)
        for line in ('#: NotAuth -- Server Not Authoritative for zone [:rfc:`2136`]; Not Authorized',
                     '    BADVERS = 16', '    BADSIG = 16', '    Reserved_65535 = 65535',
                     "return cls._unregistered_member(value, 'Reserved_for_Private_Use')"):
            with self.subTest(line=line):
                self.assertIn(line, text)

    def test_option_reads_the_fourth_column(self) -> None:
        from pcapkit.vendor.dns.option import Option

        text = _render(Option, [
            'Value,Name,Status,Reference',
            '0,Reserved,,[RFC 6891]',
            '8,edns-client-subnet,Optional,[RFC 7871]',
            '15,Extended DNS Error,Standard,[RFC 8914]',
            '20292,Umbrella Ident,Optional,[https://developer.cisco.com/docs/]; [Cisco_CIE_DNS_team]',
            '26946,DeviceID,Optional,[https://developer.cisco.com/docs/cloud-security/'
            '#!network-devices-getting-started/response-codes]; [Cisco_CIE_DNS_team]',
            '27-20291,Unassigned,,',
        ])
        for line in ('    Reserved_0 = 0', '#: edns-client-subnet [:rfc:`7871`]', '    edns_client_subnet = 8',
                     '    Extended_DNS_Error = 15', '    Umbrella_Ident = 20292', 'Cisco CIE DNS team',
                     '#: DeviceID [https://developer.cisco.com/docs/cloud-security/] [Cisco CIE DNS'):
            with self.subTest(line=line):
                self.assertIn(line, text)
        self.assertNotIn('network-devices', text)

    def test_exports(self) -> None:
        import pcapkit.const.dns as const
        import pcapkit.vendor.dns as vendor

        self.assertEqual(vendor.__all__, const.__all__)
        for name in vendor.__all__:
            with self.subTest(name=name):
                self.assertEqual(getattr(vendor, name).__name__, getattr(const, name).__name__)


if __name__ == '__main__':
    unittest.main()
