# -*- coding: utf-8 -*-
"""GitHub issue #2575: the IEEE 802.11 frame type and subtype crawlers.

Each crawler under :mod:`pcapkit.vendor.ieee802_11` reads a ``DATA`` literal
transcribed from IEEE Std 802.11-2020, Table 9-1, rather than a URL, the shape
of :mod:`pcapkit.vendor.linux.arphrd` and :mod:`pcapkit.vendor.ipx.packet`. What
makes a hand-maintained table trustworthy is that running its crawler is a
no-op against the committed constant module, so an edit to ``DATA`` that was
never regenerated fails here; ``test_ipx_packet_unit.py`` pins the IPX crawler
the same way.

The suite is unit-tier (see :mod:`tests._tiers`): it reads no capture and makes
no network call.

"""
from __future__ import annotations

import importlib
import importlib.util
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class
from tests.vendor._crawler import ROOT, import_from_checkout, make_crawler, normalize

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): renders each constant module from recorded data and compares
#: it with the committed file, which the vendor scripts regenerate on one interpreter.
__tier__ = 'LATEST'

#: The distributions importing :mod:`pcapkit.vendor` with its crawlers needs, as
#: ``test_ipx_packet_unit.py`` names them.
VENDOR_DEPS = ('requests', 'bs4', 'html5lib')

#: Whether the crawlers are importable at all; see ``test_ipx_packet_unit.py``.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)

#: Each crawler module under :mod:`pcapkit.vendor.ieee802_11` and its class.
CRAWLERS = (
    ('type', 'Type'),
    ('management_subtype', 'ManagementSubtype'),
    ('control_subtype', 'ControlSubtype'),
    ('data_subtype', 'DataSubtype'),
    ('extension_subtype', 'ExtensionSubtype'),
)


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class IEEE80211CrawlerTests(unittest.TestCase):
    """The hand-maintained Table 9-1 registries, and the crawlers that do not crawl."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _crawler(self, module: 'str', name: 'str') -> 'Any':
        """The crawler module, skipping when it was imported from another tree."""
        vendor_module, _ = import_from_checkout(self, f'pcapkit.vendor.ieee802_11.{module}',
                                                f'pcapkit.const.ieee802_11.{module}')
        return getattr(vendor_module, name)

    def test_regeneration_reproduces_the_committed_constant_files(self) -> None:
        for module, name in CRAWLERS:
            with self.subTest(crawler=name):
                vendor, data = make_crawler(self._crawler(module, name))
                generated = normalize(vendor.context(data))
                path = ROOT / 'pcapkit' / 'const' / 'ieee802_11' / f'{module}.py'
                self.assertEqual(generated, path.read_text(encoding='utf-8'),
                                 f'regenerating {path.relative_to(ROOT)} would change it; run '
                                 f'`python -m pcapkit.vendor.ieee802_11.{module}` and commit the result')

    def test_no_crawler_has_a_link(self) -> None:
        for module, name in CRAWLERS:
            with self.subTest(crawler=name):
                klass = self._crawler(module, name)
                self.assertIsNone(klass.LINK)
                self.assertIs(make_crawler(klass)[0]._request(),  # pylint: disable=protected-access
                              importlib.import_module(klass.__module__).DATA)

    def test_every_subtype_value_resolves(self) -> None:
        """Every 4-bit value is a member or a reserved range, so none raises."""
        for module, name in CRAWLERS[1:]:
            with self.subTest(registry=name):
                registry = getattr(importlib.import_module(f'pcapkit.const.ieee802_11.{module}'), name)
                for value in range(16):
                    self.assertEqual(int(registry(value)), value)
                with self.assertRaises(ValueError):
                    registry(16)


if __name__ == '__main__':
    unittest.main()
