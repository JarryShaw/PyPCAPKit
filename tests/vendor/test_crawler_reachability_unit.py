# -*- coding: utf-8 -*-
"""Every vendor crawler is reachable from the target list that runs them.

:file:`pcapkit/vendor/__main__.py` does not discover crawlers -- it reads
:attr:`__all__`, both on the ``--target <name>`` path and on the default path,
i.e. a bare ``pcapkit-vendor``:

.. code-block:: python

   # pcapkit.vendor.__main__.main, the `--target <name>` path
   target_list.extend(getattr(module, name) for name in module.__all__)
   # pcapkit.vendor.__main__.main, the default path, i.e. a bare `pcapkit-vendor`
   target_list.extend(getattr(vendor_module, name) for name in vendor_module.__all__)

So a crawler missing from :attr:`__all__` never runs, and
:file:`.github/workflows/cron-vendor.yml` invokes bare ``pcapkit-vendor``, which
is exactly the default path. Guards against :attr:`pcapkit.vendor.__all__`
listing ``'MH_HandoverACKStatus'`` *twice* and ``'MH_HandoverInitiateStatus'``
not at all, in :file:`pcapkit/vendor/__init__.py` and independently in
:file:`pcapkit/vendor/mh/__init__.py` (#531), which leaves
``handover_initiate_status`` out of both the default target list and
``--target mh``, and the constant file it owns stale.

Why the contract is stated over *all* crawlers rather than as a pin on this one.
The defect is a displaced duplicate, and that shape is invisible to the obvious
assertions: every entry of :attr:`__all__` still resolves (the name it repeats is
a real one), every module still imports, and every crawler class still exists on
disk. Only comparing the crawlers that are *defined* against the crawlers that are
*reachable* finds it. Written that way, the same test covers the next crawler
added to a subpackage without being listed -- which is the same mistake, and the
one most likely to be made again, since adding a crawler means editing two
:attr:`__all__` lists in two files that nothing checks against the filesystem.

Relationship to :file:`tests/project/test_public_api.py` (GitHub pull request
#527). That module sweeps :attr:`__all__` across the tree for a related family of
defects, and its ``test_no_duplicate_all_entries`` covers :mod:`pcapkit.vendor`
too (#1772), giving the duplicate a second, cheaper detector. This module stays
separate because its assertion is not the one that module makes: the property
checked here -- defined versus reachable -- is about the crawler *registry*
rather than about :attr:`__all__` hygiene.

The suite is unit-tier (see :mod:`tests._tiers`): it reads no capture, and it
instantiates nothing. That last part is load-bearing rather than incidental.
:meth:`pcapkit.vendor.default.Vendor.__init__` fetches from IANA and *writes* the
constant file as a side effect of construction, so a test that built a crawler
would make a network call and edit the working tree. Only the classes are looked
at here, never called.

"""
from __future__ import annotations

import importlib
import importlib.util
import pkgutil
import unittest
from collections import Counter
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class
from tests.vendor._crawler import defined_crawlers, import_from_checkout, is_crawler

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): checks which crawlers the package reaches, a question about the
#: tree.
__tier__ = 'LATEST'

#: Whether the crawler machinery is importable at all. Importing
#: :mod:`pcapkit.vendor` pulls in every subpackage only when :mod:`requests` and
#: :mod:`bs4` are installed: :mod:`pcapkit.vendor.default` imports
#: :mod:`requests` at module scope and several of the crawlers import :mod:`bs4`
#: at module scope, so both are needed for this file rather than optional to it.
#: (Without either, :mod:`pcapkit.vendor` imports no crawler and raises
#: :exc:`ModuleNotFoundError` for a crawler's name, #1850.)
#:
#: Both ship in the ``test`` extra as well as ``vendor``
#: (:file:`pyproject.toml`), so this guard should not fire in CI; it is kept as
#: belt-and-braces for an environment that lacks them, so the file skips rather
#: than erroring -- the same way :file:`tests/vendor/test_ipx_socket_unit.py`
#: guards the same two dependencies.
HAS_CRAWLER_DEPS = all(importlib.util.find_spec(name) is not None
                       for name in ('requests', 'bs4'))

#: The crawler #531 makes reachable, as ``(module, class, exported name)``.
#: Named explicitly as well as covered by the general contract below, so the
#: failure says which crawler went missing instead of only how many did. A count
#: alone would be satisfied by the right number of the wrong crawlers.
REGRESSION_CRAWLER = (
    'pcapkit.vendor.mh.handover_initiate_status',
    'HandoverInitiateStatus',
    'MH_HandoverInitiateStatus',
)


@unittest.skipUnless(HAS_CRAWLER_DEPS, 'requests and/or beautifulsoup4 not installed')
class CrawlerReachabilityTests(unittest.TestCase):
    """The crawlers on disk and the crawlers ``pcapkit-vendor`` can run."""

    if TYPE_CHECKING:
        vendor: 'Any'
        Vendor: 'Any'

    def setUp(self) -> None:
        reimport_once_per_class(self)
        self.vendor, default = import_from_checkout(self, 'pcapkit.vendor', 'pcapkit.vendor.default')
        self.Vendor = default.Vendor

    def _reachable_from(self, module: 'Any') -> 'dict[str, Any]':
        """The crawlers ``pcapkit-vendor`` would collect from ``module``.

        The expression :func:`pcapkit.vendor.__main__.main` uses on both paths,
        reproduced -- ``getattr(module, name) for name in module.__all__`` --
        keyed by defining module and class name so the result is comparable with
        :func:`~tests.vendor._crawler.defined_crawlers` regardless of the alias
        each is exported under.

        ``main()`` itself is deliberately not called: it does not merely build the
        list, it runs every crawler in it, which fetches from IANA and rewrites
        :file:`pcapkit/const/`.

        """
        reachable = {}  # type: dict[str, Any]
        for name in module.__all__:
            obj = getattr(module, name, None)
            if is_crawler(obj, self.Vendor):
                reachable[f'{obj.__module__}.{obj.__name__}'] = obj
        return reachable

    def _subpackages(self) -> 'tuple[str, ...]':
        """The ``--target`` names, i.e. the public subpackages of :mod:`pcapkit.vendor`."""
        return tuple(sorted(
            info.name for info in pkgutil.iter_modules(self.vendor.__path__)
            if info.ispkg and not info.name.startswith('_')
        ))

    def test_every_crawler_is_reachable_from_the_default_target_list(self) -> None:
        # The bare `pcapkit-vendor` path, which is what cron-vendor.yml runs:
        # every crawler on disk has to be in the list that run() is handed, or it
        # silently never executes and its constant file goes stale.
        defined = defined_crawlers(self.vendor, self.Vendor)
        reachable = self._reachable_from(self.vendor)

        unreachable = sorted(set(defined) - set(reachable))
        self.assertEqual(unreachable, [],
                         f'{len(unreachable)} crawler(s) are defined under pcapkit/vendor/ but '
                         f'absent from pcapkit.vendor.__all__, so `pcapkit-vendor` with no '
                         f'arguments never runs them and the constant files they own go stale')

        # And nothing is exported that does not exist on disk, which is the
        # same list drifting in the other direction.
        self.assertEqual(sorted(set(reachable) - set(defined)), [])

    def test_every_crawler_is_reachable_from_its_own_protocol_target(self) -> None:
        # The `--target <name>` path, which reads the subpackage's __all__ rather
        # than the root's. It is a separate list and can be separately wrong, so a
        # crawler can be reachable one way and not the other.
        defined = defined_crawlers(self.vendor, self.Vendor)

        reachable = {}  # type: dict[str, Any]
        for target in self._subpackages():
            module = importlib.import_module(f'pcapkit.vendor.{target}')
            reachable.update(self._reachable_from(module))

        unreachable = sorted(set(defined) - set(reachable))
        self.assertEqual(unreachable, [],
                         f'{len(unreachable)} crawler(s) cannot be reached by '
                         f'`pcapkit-vendor --target <protocol>` either, because they are absent '
                         f'from their own subpackage\'s __all__')

    def test_the_root_target_list_agrees_with_its_subpackages(self) -> None:
        # pcapkit/vendor/__init__.py re-lists what its subpackages list, by hand,
        # so the root and the union of the parts are two copies of one fact and
        # are allowed to disagree without anything noticing. The duplicate was
        # exactly that: both wrong, and each fixable without the other.
        from_root = self._reachable_from(self.vendor)

        from_parts = {}  # type: dict[str, Any]
        for target in self._subpackages():
            module = importlib.import_module(f'pcapkit.vendor.{target}')
            from_parts.update(self._reachable_from(module))

        self.assertEqual(sorted(from_root), sorted(from_parts))

    def test_no_duplicate_all_entries(self) -> None:
        # The mechanism of the defect, asserted directly. A duplicate is harmless
        # on its own -- what made this one a defect is that it sat in the slot a
        # real name should have held, so the list stayed the right *length* while
        # losing an entry. That is why a count of __all__ would not have caught
        # it and counting the distinct entries does.
        modules = [('pcapkit.vendor', self.vendor)]
        modules.extend(
            (f'pcapkit.vendor.{target}', importlib.import_module(f'pcapkit.vendor.{target}'))
            for target in self._subpackages()
        )

        duplicates = {}  # type: dict[str, list[str]]
        for name, module in modules:
            counts = Counter(module.__all__)
            repeated = sorted(entry for entry, count in counts.items() if count > 1)
            if repeated:
                duplicates[name] = repeated
        self.assertEqual(duplicates, {})

    def test_handover_initiate_status_is_reachable(self) -> None:
        # The lost crawler by name, so a regression says which one went missing
        # rather than only that one did. Asserted at all three levels the
        # `__main__` paths read: the defining module, the subpackage
        # (`--target mh`) and the root (bare `pcapkit-vendor`).
        module_name, class_name, exported = REGRESSION_CRAWLER

        module = importlib.import_module(module_name)
        crawler = getattr(module, class_name)
        self.assertTrue(is_crawler(crawler, self.Vendor))

        import pcapkit.vendor.mh as mh
        self.assertIn(exported, mh.__all__)
        self.assertIs(getattr(mh, exported), crawler)

        self.assertIn(exported, self.vendor.__all__)
        self.assertIs(getattr(self.vendor, exported), crawler)


if __name__ == '__main__':
    unittest.main()
