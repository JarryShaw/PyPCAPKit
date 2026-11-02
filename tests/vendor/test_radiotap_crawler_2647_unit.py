# -*- coding: utf-8 -*-
"""GitHub issue #2647: the crawlers of radiotap's mixed bitmaps.

The HE field's ``data1`` and ``data2``, the HE-MU field's ``flags1`` and
``flags2`` and the U-SIG field's ``common`` mix value subfields with known bits.
Each has a registry of its known bits, whose crawler scrapes the subfield's table
on its field page as the #2576 flag crawlers do, less the rows of its ``VALUES``.
Regenerating each constant module from the fixtures below, the tables as
radiotap.org served them on 2026-11-02, is a no-op against the committed file.

**The fixtures are built inline and parsed with the same** ``html5lib`` **the
crawlers use**, rather than fetched, as in ``test_radiotap_crawler_2576_unit.py``.
Each page keeps the tables its crawlers read and the one after them, which none
takes; the HE page's RU allocation offset table, under ``data2`` too, is cut to
its first rows, none of which has a mask.

The suite is unit-tier (see :mod:`tests._tiers`): it reads no capture and makes
no network call.

"""
from __future__ import annotations

import html
import importlib
import importlib.util
import pathlib
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): renders the constant modules from recorded data and compares them
#: with the committed files, which the vendor scripts regenerate on one interpreter.
__tier__ = 'LATEST'

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The distributions importing :mod:`pcapkit.vendor` with its crawlers needs.
VENDOR_DEPS = ('requests', 'bs4', 'html5lib')

#: Whether the crawlers are importable at all.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)

#: Each crawler, as ``(module, class, page, subfield, value masks)``.
CRAWLERS = (
    ('he_data1_known', 'HEData1Known', 'HE', 'data1', (0x0003,)),
    ('he_data2_known', 'HEData2Known', 'HE', 'data2', (0x3F00, 0x8000)),
    ('he_mu_flags1_known', 'HEMUFlags1Known', 'HE-MU', 'flags1', (0x000F, 0x0020, 0x2000)),
    ('he_mu_flags2_known', 'HEMUFlags2Known', 'HE-MU', 'flags2', (0x0003, 0x0008, 0x00F0, 0x0300, 0x0800)),
    ('usig_common_known', 'USIGCommonKnown', 'U-SIG', 'common',
     (0x00007000, 0x00038000, 0x00040000, 0x01F80000, 0xFE000000)),
)

#: Prefixes the name maps' macros carry, which the member names drop.
PREFIXES = ('IEEE80211_RADIOTAP_', 'IEEE80211_')

#: The tables of each page, as ``(heading, paragraph, rows)``: the ``<h2>`` before
#: the table, if any, and the paragraph between them, if any.
PAGES = {
    'HE': (
        ('data1', '', (
            ('0x0003', 'HE PPDU Format: 0=HE_SU, 1=HE_EXT_SU, 2=HE_MU, 3=HE_TRIG'),
            ('0x0004', 'BSS Color known'), ('0x0008', 'Beam Change known'), ('0x0010', 'UL/DL known'),
            ('0x0020', 'data MCS known'), ('0x0040', 'data DCM known'), ('0x0080', 'Coding known'),
            ('0x0100', 'LDPC extra symbol segment known'), ('0x0200', 'STBC known'),
            ('0x0400', 'Spatial Reuse known (Spatial Reuse 1 for HE_TRIG format)'),
            ('0x0800', 'Spatial Reuse 2 known (HE_TRIG format), STA-ID known (HE_MU format)'),
            ('0x1000', 'Spatial Reuse 3 known (HE_TRIG format)'), ('0x2000', 'Spatial Reuse 4 known (HE_TRIG format)'),
            ('0x4000', 'data BW/RU allocation known'), ('0x8000', 'Doppler known'),
        )),
        ('data2', '', (
            ('0x0001', 'pri/sec 80 MHz known'), ('0x0002', 'GI known'), ('0x0004', 'number of LTF symbols known'),
            ('0x0008', 'Pre-FEC Padding Factor known'), ('0x0010', 'TxBF known'), ('0x0020', 'PE Disambiguity known'),
            ('0x0040', 'TXOP known'), ('0x0080', 'midamble periodicity known'), ('0x3f00', 'RU allocation offset'),
            ('0x4000', 'RU allocation offset known'), ('0x8000', 'pri/sec 80 MHz (primary=0, secondary=1)'),
        )),
        (None, 'The RU allocation offset is encoded as the offset (within the 80 MHz pri/sec channel) of the '
               'location in the correct tone column.', (
            ('26-tone', '52-tone', '106-tone', '242-tone', '484-tone', '996-tone', '2x996-tone'),
            ('0', '0', '0', '0', '0', '0', '0'), ('1',), ('2', '1'),
        )),
        ('data3', '', (
            ('0x003f', 'BSS Color'), ('0x0040', 'Beam Change'), ('0x0080', 'UL/DL'),
        )),
    ),
    'HE-MU': (
        ('flags1', '', (
            ('0x000f', 'SIG-B MCS (from SIG-A)'), ('0x0010', 'SIG-B MCS known'),
            ('0x0020', 'SIG-B DCM (from SIG-A)'), ('0x0040', 'SIG-B DCM known'),
            ('0x0080', '(Channel 2) Center 26-tone RU bit known'),
            ('0x0100', 'Channel 1 RUs known (which depends on BW)'),
            ('0x0200', 'Channel 2 RUs known (which depends on BW)'), ('0x0c00', '(reserved)'),
            ('0x1000', '(Channel 1) Center 26-tone RU bit known'), ('0x2000', '(Channel 1) Center 26-tone RU value'),
            ('0x4000', 'SIG-B Compression known'), ('0x8000', '# of HE-SIG-B Symbols/MU-MIMO Users known'),
        )),
        ('flags2', '', (
            ('0x0003', 'bandwidth from Bandwidth field in HE-SIG-A (0 - 20 MHz, …, 3 - 160/80+80 MHz)'),
            ('0x0004', 'bandwidth from Bandwidth field in HE-SIG-A known'),
            ('0x0008', 'SIG-B compression from SIG-A'),
            ('0x00f0', '# of HE-SIG-B Symbols - 1 or # of MU-MIMO Users - 1 from SIG-A'),
            ('0x0300', 'preamble puncturing from Bandwidth field in HE-SIG-A (0 - non-puncturing, 1 - punctured '
                       'secondary 20 MHz (in primary 80 MHz if applicable), 2 - punctured but primary 40 MHz is '
                       'present (in primary 80 MHz if applicable)'),
            ('0x0400', 'preamble puncturing from Bandwidth field in HE-SIG-A known'),
            ('0x0800', '(Channel 2) Center 26-tone RU value'), ('0xf000', '(reserved)'),
        )),
    ),
    'U-SIG': (
        ('common', '', (
            ('0x00000001', 'PHY version identifier known'), ('0x00000002', 'BW known'),
            ('0x00000004', 'UL/DL known'), ('0x00000008', 'BSS Color known'), ('0x00000010', 'TXOP known'),
            ('0x00000020', 'bad U-SIG CRC'), ('0x00000040', 'validate bits checked'),
            ('0x00000080', 'validate bits OK'), ('0x00000f00', '(reserved)'),
            ('0x00007000', 'PHY version identifier'), ('0x00038000', 'BW'), ('0x00040000', 'UL/DL'),
            ('0x01f80000', 'BSS Color'), ('0xfe000000', 'TXOP'),
        )),
        ('value / mask', 'An EHT PPDU is an EHT MU PPDU if', (
            ('bits', 'U-SIG reference', 'Content'),
            ('0x0000001f', 'U-SIG-1 B20-B24', 'Disregard (all ones)'),
            ('0x00000020', 'U-SIG-1 B25', 'Validate (must be 1)'),
        )),
    ),
}


def _page(name: 'str') -> 'str':
    """Render the fixture of a field page, in the shape the live one has."""
    parts = [f'<!DOCTYPE html><html><head><title>Radiotap - {name}</title></head><body><h1>{name}</h1>']
    for heading, paragraph, rows in PAGES[name]:
        if heading is not None:
            parts.append(f'<h2 id="{heading}">{heading}</h2>')
        if paragraph:
            parts.append(f'<p>{html.escape(paragraph)}</p>')
        parts.append('<table><tbody>')
        parts.extend('<tr>' + ''.join(f'<td>{html.escape(cell)}</td>' for cell in row) + '</tr>' for row in rows)
        parts.append('</tbody></table>')
    parts.append('</body></html>')
    return ''.join(parts)


def _normalize(context: 'str') -> 'str':
    """Apply the whitespace normalisation the generator writes files through."""
    lines = []  # type: list[str]
    for line in context.splitlines():
        if line:
            if line.strip():
                lines.append(line.rstrip())
        else:
            lines.append(line)
    return '\n'.join(lines) + '\n'


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class RadiotapMixedBitmapCrawlerTests(unittest.TestCase):
    """The known-bit registries of the mixed bitmaps, and their crawlers."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _crawler(self, module: 'str', name: 'str') -> 'Any':
        """The crawler class, skipping when it was imported from another tree."""
        vendor_module = importlib.import_module(f'pcapkit.vendor.radiotap.{module}')
        const_module = importlib.import_module(f'pcapkit.const.radiotap.{module}')
        for found in (vendor_module, const_module):
            resolved = pathlib.Path(found.__file__).resolve()
            if ROOT not in resolved.parents:
                self.skipTest(f'{found.__name__} was imported from {resolved}, which is outside '
                              f'{ROOT}; install this checkout with `pip install -e .`')
        return getattr(vendor_module, name)

    def test_the_registries_regenerate(self) -> None:
        """Rendering each page through its crawler reproduces the committed module."""
        for module, name, page, _, _ in CRAWLERS:
            with self.subTest(crawler=name):
                klass = self._crawler(module, name)
                vendor = klass.__new__(klass)
                vendor.NAME = klass.__name__
                vendor.DOCS = klass.__doc__
                data = vendor.request(_page(page))
                vendor.record = vendor.count(data)
                path = ROOT / 'pcapkit' / 'const' / 'radiotap' / f'{module}.py'
                self.assertEqual(_normalize(vendor.context(data)), path.read_text(encoding='utf-8'),
                                 f'regenerating {path.relative_to(ROOT)} would change it; run '
                                 '`pcapkit-vendor radiotap` and commit the result')

    def test_each_crawler_scrapes_its_subfield(self) -> None:
        """Each crawler names its page and subfield, and takes that subfield's tables alone."""
        for module, name, page, subfield, _ in CRAWLERS:
            with self.subTest(crawler=name):
                klass = self._crawler(module, name)
                self.assertEqual((klass.LINK, klass.SUBFIELD),
                                 (f'https://www.radiotap.org/fields/{page}.html', subfield))
                tables = klass.__new__(klass).request(_page(page))
                # data2's RU allocation offset table is under its heading too
                self.assertEqual(len(tables), 2 if subfield == 'data2' else 1)

    def test_the_value_rows_are_no_members(self) -> None:
        """Every bit but the value subfields' and the reserved ones is a member, under Linux's name."""
        for module, name, page, _, values in CRAWLERS:
            with self.subTest(crawler=name):
                klass = self._crawler(module, name)
                self.assertEqual(klass.VALUES, values)
                registry = getattr(importlib.import_module(f'pcapkit.const.radiotap.{module}'), name)
                members = {int(member): member.name for member in registry}
                rows = {int(row[0], 16) for heading, _, table in PAGES[page] if heading == klass.SUBFIELD
                        for row in table if row[0].startswith('0x')}
                singles = {mask for mask in rows if not mask & (mask - 1)}
                self.assertEqual(set(members), singles - set(values))
                self.assertEqual(set(klass.NAMES), set(members), 'a member falls back to radiotap.org wording')
                for mask, macro in klass.NAMES.items():
                    prefix = next(prefix for prefix in PREFIXES if macro.startswith(prefix))
                    self.assertEqual(members[mask], macro[len(prefix):])

    def test_the_registries_keep_the_bits_they_do_not_name(self) -> None:
        """A reserved bit stays in the value; a value past the word is refused."""
        from pcapkit.const.radiotap.he_mu_flags1_known import HEMUFlags1Known
        from pcapkit.const.radiotap.usig_common_known import USIGCommonKnown

        member = HEMUFlags1Known.get(0x0C10)
        self.assertEqual(int(member), 0x0C10)
        self.assertIn(HEMUFlags1Known.HE_MU_FLAGS1_SIG_B_MCS_KNOWN, member)
        member = USIGCommonKnown.get(0x0F21)
        self.assertEqual(int(member), 0x0F21)
        self.assertIn(USIGCommonKnown.EHT_USIG_COMMON_BAD_USIG_CRC, member)
        for registry, value in ((HEMUFlags1Known, 0x10000), (USIGCommonKnown, 1 << 32)):
            with self.subTest(registry=registry.__name__), self.assertRaises(ValueError):
                registry(value)


if __name__ == '__main__':
    unittest.main()
