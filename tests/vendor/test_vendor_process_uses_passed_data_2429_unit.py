# -*- coding: utf-8 -*-
"""Some dict-based crawlers' ``process`` ignored their own ``data`` argument (#2429).

:meth:`~pcapkit.vendor.default.Vendor.process` on the dict-based crawlers listed
in :data:`TARGETS` is meant to render an enumeration from whatever registry
mapping its caller hands it, mirroring :meth:`~pcapkit.vendor.default.Vendor.count`,
which both takes and uses its own ``data``. Those crawlers instead read the
module-level ``DATA`` literal straight out of the closure, silently discarding
the argument. Harmless today, since every real call site passes
``request()``'s own ``DATA``-returning value, so ``data is DATA`` always holds
in practice -- but a caller that ever passes different data would get the
module's table back regardless, with no error.

Each test below builds a crawler with :meth:`~pcapkit.vendor.default.Vendor.count`
and :meth:`~pcapkit.vendor.default.Vendor.process` driven on a fabricated
mapping whose codes and names are both disjoint from the module's own
``DATA`` (see :meth:`ProcessUsesPassedDataTests._vendor`), the same
``cls.__new__(cls)`` bypass
:file:`tests/vendor/test_vendor_mh_lla_code_1848_unit.py` uses to skip
:meth:`Vendor.__init__`'s network fetch and file write. A fixed crawler's
rendered enumeration carries the fabricated names and none of the module's
real ones; the unfixed crawler ignores the argument and renders the module's
real ``DATA`` instead.

"""
from __future__ import annotations

import importlib
import importlib.util
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): drives the vendor crawlers directly, the same reasoning
#: as tests/vendor/test_vendor_mh_lla_code_1848_unit.py.
__tier__ = 'LATEST'

#: Every distribution importing :mod:`pcapkit.vendor` needs, as
#: :file:`tests/vendor/test_user_agent_unit.py` explains.
VENDOR_DEPS = ('requests', 'bs4', 'html5lib')

#: Whether the crawlers are importable at all.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)

#: ``module name -> class name``, the crawlers GitHub issue #2429 found
#: reading the module-level ``DATA`` literal instead of their own ``data``
#: argument in :meth:`~pcapkit.vendor.default.Vendor.process`.
TARGETS = {
    'pcapkit.vendor.ipv4.qs_function': 'QSFunction',
    'pcapkit.vendor.ipv4.tos_del': 'ToSDelay',
    'pcapkit.vendor.ipv4.tos_ecn': 'ToSECN',
    'pcapkit.vendor.ipv4.tos_pre': 'ToSPrecedence',
    'pcapkit.vendor.ipv4.tos_rel': 'ToSReliability',
    'pcapkit.vendor.ipv4.tos_thr': 'ToSThroughput',
    'pcapkit.vendor.ipv4.ts_flag': 'TSFlag',
    'pcapkit.vendor.ipv6.option_action': 'OptionAction',
    'pcapkit.vendor.ipv6.qs_function': 'QSFunction',
    'pcapkit.vendor.ipv6.smf_dpd_mode': 'SMFDPDMode',
    'pcapkit.vendor.mh.binding_error': 'BindingError',
    'pcapkit.vendor.mh.lla_code': 'LLACode',
    'pcapkit.vendor.pcapng.filter_type': 'FilterType',
    'pcapkit.vendor.pcapng.hash_algorithm': 'HashAlgorithm',
    'pcapkit.vendor.pcapng.secrets_type': 'SecretsType',
    'pcapkit.vendor.pcapng.verdict_type': 'VerdictType',
}


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class ProcessUsesPassedDataTests(unittest.TestCase):
    """Each crawler's :meth:`process` renders what it was called with."""

    if TYPE_CHECKING:
        module_cache: 'dict[str, Any]'

    def setUp(self) -> 'None':
        reimport_once_per_class(self)
        self.module_cache = {}

    def _vendor(self, module_name: 'str', class_name: 'str') -> 'tuple[Any, dict[int, str], dict[int, str]]':
        """A crawler with the attributes ``__init__`` sets, but none of its I/O.

        The fabricated registry uses codes well outside any real registry's
        range (the dict-based crawlers here enumerate small bit flags or IANA
        codes, never six-digit values) so it can never coincide with the
        module's own ``DATA``, even for a crawler whose table is empty.

        Returns:
            The crawler, its module's real registry, and a fabricated one.

        """
        module = self.module_cache.get(module_name)
        if module is None:
            module = importlib.import_module(module_name)
            self.module_cache[module_name] = module

        cls = getattr(module, class_name)
        vendor = cls.__new__(cls)
        vendor.NAME = cls.__name__
        vendor.DOCS = cls.__doc__

        real_data = vendor.request()
        fake_data = {900001: 'Sentinel2429MarkerAlpha', 900002: 'Sentinel2429MarkerBeta'}
        return vendor, real_data, fake_data

    def test_process_renders_the_data_it_is_given(self) -> 'None':
        for module_name, class_name in TARGETS.items():
            with self.subTest(module=module_name, cls=class_name):
                vendor, real_data, fake_data = self._vendor(module_name, class_name)

                vendor.record = vendor.count(fake_data)
                enum, _ = vendor.process(fake_data)
                rendered = '\n'.join(enum).upper()

                for name in fake_data.values():
                    with self.subTest(fake_name=name):
                        self.assertIn(name.upper(), rendered)

                for name in real_data.values():
                    safe = vendor.safe_name(name)
                    if safe.upper() in ('RESERVED', 'UNASSIGNED'):
                        continue
                    with self.subTest(real_name=name):
                        self.assertNotIn(safe.upper(), rendered)

    def test_process_does_not_fall_back_to_the_module_table(self) -> 'None':
        # The sharpest form of the regression: process() called with the real
        # DATA produces the committed enumeration, but process() called with
        # anything else must not silently produce that same enumeration too.
        #
        # vendor.record is set once, from the real registry, and left alone
        # across both calls -- the way Vendor.__init__ computes it once from
        # request()'s own return before calling process(). Recomputing it
        # between the two calls would let a crawler whose own rename() keys
        # off self.record (ipv4/tos_ecn folds 'ECT(1)' and 'ECT(0)' to the
        # same safe name and only disambiguates when their count collides)
        # diverge for that reason alone, which would pass this assertion
        # whether or not process() is reading its own data argument.
        for module_name, class_name in TARGETS.items():
            with self.subTest(module=module_name, cls=class_name):
                vendor, real_data, fake_data = self._vendor(module_name, class_name)
                vendor.record = vendor.count(real_data)

                enum_real, _ = vendor.process(real_data)
                enum_fake, _ = vendor.process(fake_data)

                self.assertNotEqual(enum_real, enum_fake)


if __name__ == '__main__':
    unittest.main()
