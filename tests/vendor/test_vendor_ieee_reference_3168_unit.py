# -*- coding: utf-8 -*-
"""GitHub issue #3168: the crawlers render a dated IEEE citation as an ``:ieee:`` role.

:meth:`~pcapkit.vendor.default.Vendor.split_references` turns ``IEEE Std
802.1Q-2014`` into ``:ieee:`802.1Q-2014```, which each crawler brackets as it
brackets any citation it leaves as text, so the generated constant modules cite
the standard as the hand-written docs do. An undated citation names no edition
and stays text, as ``RFC Errata 5748`` does beside :rst:role:`rfc`.

:data:`ETHERTYPE` holds real rows of IANA's ``ieee-802-numbers-1.csv`` as served
with ``Last-Modified: Tue, 13 Oct 2026 20:07:10 GMT``; no network call is made.

"""
from __future__ import annotations

import importlib.util
import unittest

from tests._support import reimport_once_per_class
from tests.vendor._crawler import ROOT, import_from_checkout, make_crawler

#: Test tier (#1958): renders a constant module from recorded data and compares it
#: with the committed file, which the vendor scripts regenerate on one interpreter.
__tier__ = 'LATEST'

#: Every distribution importing :mod:`pcapkit.vendor` needs -- see
#: :mod:`tests.vendor.test_ipx_packet_unit` for why all three are checked.
VENDOR_DEPS = ('requests', 'bs4', 'html5lib')

#: Whether the crawlers are importable at all.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)

#: Rows of the EtherType registry citing the IEEE, dated and not.
ETHERTYPE = (
    'Ethertype (decimal),Ethertype (hex),Exp. Ethernet (decimal),Exp. Ethernet (octal),Description,Reference\r\n'
    '0000-1500,0000-05DC,-,-,IEEE802.3 Length Field,[IEEE Std 802.3]\r\n'
    '34825,8809,-,-,"Slow Protocols (Link Aggregation, OAM, etc.)",[IEEE]\r\n'
    '35047,88E7,-,-,Provider Backbone Bridging Instance tag,[IEEE Std 802.1Q-2014]\r\n'
    '35063,88F7,-,-,Precision Time Protocol,[NIST: IEEE Std 1588]; [Kang_Lee]\r\n'
)


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class IEEEReferenceTests(unittest.TestCase):
    """A dated IEEE citation becomes the role; anything else is left as it was."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_a_dated_designation_becomes_the_role(self) -> None:
        """Either spelling, with or without ``Std``, and with whitespace IANA wraps a cell at."""
        from pcapkit.vendor.default import Vendor

        for cell, expected in (
            ('[IEEE Std 802.1Q-2014]', [':ieee:`802.1Q-2014`']),
            ('[IEEE 802.1D-2004]', [':ieee:`802.1D-2004`']),
            ('[IEEE Std\n          802.11ax-2021]', [':ieee:`802.11ax-2021`']),
            ('[IEEE 802.1D-2004; IEEE 802.1Q-2022]', [':ieee:`802.1D-2004`; :ieee:`802.1Q-2022`']),
        ):
            with self.subTest(cell=cell):
                self.assertEqual(Vendor.split_references(cell), expected)

    def test_text_after_the_designation_follows_the_role(self) -> None:
        """A clause or a table has no anchor on the IEEE SA page, so it stays text."""
        from pcapkit.vendor.default import Vendor

        self.assertEqual(Vendor.split_references('[IEEE Std 802.11-2020, Table 9-1]'),
                         [':ieee:`802.11-2020`, Table 9-1'])

    def test_anything_else_is_left_as_it_was(self) -> None:
        """An undated standard, the IEEE itself, and a number whose hyphen is no year."""
        from pcapkit.vendor.default import Vendor

        for cell in ('[IEEE Std 802.3]', '[IEEE]', '[NIST: IEEE Std 1588]', '[IEEE 802.1B]',
                     '[IEEE 11073-20701]', '[IEEE Registration Authority, LLC Public Listing]'):
            with self.subTest(cell=cell):
                self.assertEqual(Vendor.split_references(cell), [cell[1:-1]])

    def test_ethertype_renders_the_role_and_keeps_the_rest(self) -> None:
        """The crawler brackets the role, as it brackets any citation it leaves as text."""
        (module,) = import_from_checkout(self, 'pcapkit.vendor.reg.ethertype')
        vendor, lines = make_crawler(module.EtherType, ETHERTYPE)
        enum, miss = vendor.process(lines)
        comments = [entry.split('\n    ', 1)[0] for entry in enum]
        self.assertEqual(comments, [
            '#: Slow Protocols (Link Aggregation, OAM, etc.) [IEEE]',
            '#: Provider Backbone Bridging Instance tag [:ieee:`802.1Q-2014`]',
            '#: Precision Time Protocol [NIST: IEEE Std 1588][Kang Lee]',
        ])
        self.assertIn('    #: IEEE802.3 Length Field [IEEE Std 802.3]', miss)

    def test_the_committed_ethertype_module_cites_the_role(self) -> None:
        """The committed module is what the crawler renders from the live registry."""
        committed = (ROOT / 'pcapkit' / 'const' / 'reg' / 'ethertype.py').read_text(encoding='utf-8')
        self.assertIn('#: Provider Backbone Bridging Instance tag [:ieee:`802.1Q-2014`]', committed)
        self.assertNotIn('[IEEE Std 802.1Q-2014]', committed)


if __name__ == '__main__':
    unittest.main()
