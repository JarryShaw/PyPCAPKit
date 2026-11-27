# -*- coding: utf-8 -*-
"""GitHub issue #2936: the LLC address and control field crawlers.

Each crawler under :mod:`pcapkit.vendor.llc` reads a ``DATA`` literal rather
than a URL: the LSAP values from the IEEE Registration Authority's LLC public
listing, and the control field functions from IEEE Std 802.2. Running each is
a no-op against the committed constant module, so an edit to ``DATA`` that was
never regenerated fails here, as ``test_ieee802_11_crawlers_2575_unit.py`` pins
the 802.11 crawlers.

The suite is unit-tier (see :mod:`tests._tiers`): it reads no capture and makes
no network call.

"""
from __future__ import annotations

import importlib
import importlib.util
import pathlib
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): renders each constant module from recorded data and compares
#: it with the committed file, which the vendor scripts regenerate on one interpreter.
__tier__ = 'LATEST'

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The distributions importing :mod:`pcapkit.vendor` with its crawlers needs.
VENDOR_DEPS = ('requests', 'bs4', 'html5lib')

#: Whether the crawlers are importable at all.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)

#: Each crawler module under :mod:`pcapkit.vendor.llc` and its class.
CRAWLERS = (
    ('lsap', 'LSAP'),
    ('supervisory_function', 'SupervisoryFunction'),
    ('modifier_function', 'ModifierFunction'),
)


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
class LLCCrawlerTests(unittest.TestCase):
    """The hand-maintained LLC registries, and the crawlers that do not crawl."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _crawler(self, module: 'str', name: 'str') -> 'Any':
        """The crawler class, skipping when it was imported from another tree."""
        vendor_module = importlib.import_module(f'pcapkit.vendor.llc.{module}')
        const_module = importlib.import_module(f'pcapkit.const.llc.{module}')
        for found in (vendor_module, const_module):
            resolved = pathlib.Path(found.__file__).resolve()
            if ROOT not in resolved.parents:
                self.skipTest(f'{found.__name__} was imported from {resolved}, which is outside '
                              f'{ROOT}; install this checkout with `pip install -e .`')
        return getattr(vendor_module, name)

    @staticmethod
    def _vendor(klass: 'Any') -> 'Any':
        """A crawler instance with the attributes ``__init__`` would set, without its write."""
        vendor = klass.__new__(klass)
        vendor.NAME = klass.__name__
        vendor.DOCS = klass.__doc__
        vendor.record = vendor.count(vendor.request())
        return vendor

    def test_regeneration_reproduces_the_committed_constant_files(self) -> None:
        for module, name in CRAWLERS:
            with self.subTest(crawler=name):
                vendor = self._vendor(self._crawler(module, name))
                generated = _normalize(vendor.context(vendor.request()))
                path = ROOT / 'pcapkit' / 'const' / 'llc' / f'{module}.py'
                self.assertEqual(generated, path.read_text(encoding='utf-8'),
                                 f'regenerating {path.relative_to(ROOT)} would change it; run '
                                 f'the crawler {module} and commit the result')

    def test_no_crawler_has_a_link(self) -> None:
        for module, name in CRAWLERS:
            with self.subTest(crawler=name):
                klass = self._crawler(module, name)
                self.assertIsNone(klass.LINK)
                self.assertIs(self._vendor(klass)._request(),  # pylint: disable=protected-access
                              importlib.import_module(klass.__module__).DATA)


class LLCRegistryTests(unittest.TestCase):
    """The ranges the LLC public listing and IEEE Std 802.2 leave unassigned."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_every_address_octet_resolves(self) -> None:
        """An unassigned value whose second bit is ``0`` is unreserved, any other reserved."""
        from pcapkit.const.llc.lsap import LSAP

        assigned = {member.value for member in LSAP}
        self.assertEqual(sorted(assigned), [0x00, 0x02, 0x06, 0x0A, 0x0E, 0x42, 0x4E, 0x7E, 0x82,
                                            0x8E, 0xA6, 0xAA, 0xE6, 0xFE, 0xFF])
        for value in range(0x100):
            with self.subTest(value=hex(value)):
                member = LSAP(value)
                self.assertEqual(int(member), value)
                if value not in assigned:
                    self.assertEqual(member.name, 'Reserved' if value & 0b10 else 'Unreserved use')
        for value in (-1, 0x100):
            with self.assertRaises(ValueError):
                LSAP(value)
            with self.assertRaises(ValueError):
                LSAP.get(value)

    def test_function_values_are_their_masked_bits(self) -> None:
        from pcapkit.const.llc.modifier_function import ModifierFunction
        from pcapkit.const.llc.supervisory_function import SupervisoryFunction

        # The U-format control octets with P/F clear (IEEE Std 802.2), masked to 0xEC.
        octets = {'UI': 0x03, 'DM': 0x0F, 'DISC': 0x43, 'UA': 0x63, 'AC0': 0x67, 'SABME': 0x6F,
                  'FRMR': 0x87, 'XID': 0xAF, 'TEST': 0xE3, 'AC1': 0xE7}
        self.assertEqual({member.name: member.value | 0x03 for member in ModifierFunction}, octets)
        self.assertEqual({member.name: member.value for member in SupervisoryFunction},
                         {'RR': 0x00, 'RNR': 0x04, 'REJ': 0x08})
        self.assertEqual(SupervisoryFunction(0x0C).name, 'Unassigned')
        self.assertEqual(ModifierFunction(0x2C).name, 'Unassigned')
        for registry, value in ((SupervisoryFunction, 0x01), (SupervisoryFunction, 0x10),
                                (ModifierFunction, 0x03), (ModifierFunction, 0x10)):
            with self.subTest(registry=registry.__name__, value=hex(value)):
                with self.assertRaises(ValueError):
                    registry(value)


if __name__ == '__main__':
    unittest.main()
