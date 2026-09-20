# -*- coding: utf-8 -*-
"""Every vendor crawler is reachable from the target list that runs them.

:mod:`pcapkit.vendor` defines 117 crawlers and
:file:`pcapkit/vendor/__main__.py` could only ever run 116 of them, because it
does not discover crawlers -- it reads :attr:`__all__`:

.. code-block:: python

   # pcapkit/vendor/__main__.py:79, the `--target <name>` path
   target_list.extend(getattr(module, name) for name in module.__all__)
   # pcapkit/vendor/__main__.py:87, the default path, i.e. a bare `pcapkit-vendor`
   target_list.extend(getattr(vendor_module, name) for name in vendor_module.__all__)

:attr:`pcapkit.vendor.__all__` listed ``'MH_HandoverACKStatus'`` *twice* and had
no entry for ``'MH_HandoverInitiateStatus'`` at all, in
:file:`pcapkit/vendor/__init__.py` and independently in
:file:`pcapkit/vendor/mh/__init__.py`. So both the default target list and
``--target mh`` were missing ``handover_initiate_status``, and that crawler had
never run: :file:`.github/workflows/cron-vendor.yml` invokes bare
``pcapkit-vendor``, which is exactly the line 87 path.

The corroborating evidence is in the generated file the crawler owns.
:meth:`pcapkit.vendor.default.Vendor.context` emits a ``:meta private:``
directive into every enumeration it writes
(:file:`pcapkit/vendor/default.py:70`), and 116 of the 117 files under
:file:`pcapkit/const/*/` carry it. The one that does not is
:file:`pcapkit/const/mh/handover_initiate_status.py` -- the output of the one
crawler that could not be reached. The duplicate dates to commit ``24edd30d2``
(2023-04-17, "added MH enumerations & vendor cralwers"), so the file has been
stale for the whole life of the crawler.

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
defects and deliberately excludes :mod:`pcapkit.vendor` via its
``EXCLUDED_ROOTS``, because it is unit-tier and the ``vendor`` extra is not part
of ``pip install -e '.[test]'``. Its docstring records the remediation as
"drop ``'vendor'`` from :data:`EXCLUDED_ROOTS`". This module is a separate file
rather than that edit, for two reasons: #527 is not merged, so its file does not
exist on the branch this change is cut from; and the assertion here is not the one
it makes. It needs the ``vendor`` extra, and the property it checks -- defined
versus reachable -- is about the crawler *registry* rather than about
:attr:`__all__` hygiene. Dropping the exclusion is still worth doing on top of
this, and would give the duplicate a second, cheaper detector.

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
import pathlib
import pkgutil
import unittest
from collections import Counter
from typing import TYPE_CHECKING

from tests._support import purge_modules

if TYPE_CHECKING:
    from typing import Any

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Whether the crawler machinery is importable at all. Importing
#: :mod:`pcapkit.vendor` pulls in every subpackage unconditionally:
#: :mod:`pcapkit.vendor.default` imports :mod:`requests` at module scope and
#: seven of the crawlers import :mod:`bs4` at module scope, so both are needed
#: for this file rather than optional to it. (:mod:`pcapkit.vendor`'s own
#: ``try: import bs4`` downgrades the *warning*, not the
#: :exc:`ModuleNotFoundError` raised by the crawler imports below it.)
#:
#: Both ship in the ``test`` extra as well as ``vendor``
#: (:file:`pyproject.toml`), so this guard should not fire in CI; it is kept as
#: belt-and-braces for an environment that lacks them, so the file skips rather
#: than erroring -- the same way :file:`tests/vendor/test_ipx_socket_unit.py`
#: guards the same two dependencies.
HAS_CRAWLER_DEPS = all(importlib.util.find_spec(name) is not None
                       for name in ('requests', 'bs4'))

#: The crawler this change makes reachable, as ``(module, class, exported
#: name)``. Named explicitly as well as covered by the general contract below,
#: so the failure says which crawler went missing instead of only how many did.
#: A count alone would be satisfied by any 117 crawlers, including the wrong 117.
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
        purge_modules(['pcapkit'])

        import pcapkit
        import pcapkit.vendor as vendor
        from pcapkit.vendor.default import Vendor

        # The whole assertion is "what is on disk in *this* checkout is reachable
        # from this checkout's __all__". An installed copy imported from
        # somewhere else would be comparing two trees, which is an environment
        # mismatch rather than a defect -- hence a skip rather than a failure.
        resolved = pathlib.Path(pcapkit.__file__).resolve()
        if ROOT not in resolved.parents:
            self.skipTest(f'pcapkit was imported from {resolved}, which is outside {ROOT}; '
                          f'install this checkout with `pip install -e .`, or set PYTHONPATH to '
                          f'it, to run this suite against it')

        self.vendor = vendor
        self.Vendor = Vendor

    def _is_crawler(self, obj: 'Any') -> 'bool':
        """Whether ``obj`` is a concrete crawler class.

        :class:`~pcapkit.vendor.default.Vendor` itself is excluded: it is the
        abstract base, it is exported from :mod:`pcapkit.vendor` for subclassing
        rather than for running, and it is not in :attr:`__all__`.

        """
        return isinstance(obj, type) and issubclass(obj, self.Vendor) and obj is not self.Vendor

    def _defined_crawlers(self) -> 'dict[str, Any]':
        """Every crawler defined under :file:`pcapkit/vendor/`, by qualified name.

        Discovered from the filesystem with :func:`pkgutil.walk_packages`, which
        is the half of the comparison :attr:`__all__` cannot influence -- the
        point being to find a crawler that exists and is not listed.

        A class is attributed to the module that *defines* it, i.e. where
        ``__module__`` points, so the re-exports every subpackage performs do not
        each count as another crawler.

        """
        found = {}  # type: dict[str, Any]
        for info in pkgutil.walk_packages(self.vendor.__path__, prefix='pcapkit.vendor.'):
            if any(part.startswith('_') for part in info.name.split('.')):
                continue
            module = importlib.import_module(info.name)
            for name in getattr(module, '__all__', ()):
                obj = getattr(module, name, None)
                if self._is_crawler(obj) and obj.__module__ == info.name:
                    found[f'{info.name}.{name}'] = obj
        return found

    def _reachable_from(self, module: 'Any') -> 'dict[str, Any]':
        """The crawlers ``pcapkit-vendor`` would collect from ``module``.

        The expression at :file:`pcapkit/vendor/__main__.py` lines 79 and 87,
        reproduced -- ``getattr(module, name) for name in module.__all__`` --
        keyed by defining module and class name so the result is comparable with
        :meth:`_defined_crawlers` regardless of the alias each is exported under.

        ``main()`` itself is deliberately not called: it does not merely build the
        list, it runs every crawler in it, which fetches from IANA and rewrites
        :file:`pcapkit/const/`.

        """
        reachable = {}  # type: dict[str, Any]
        for name in module.__all__:
            obj = getattr(module, name, None)
            if self._is_crawler(obj):
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
        defined = self._defined_crawlers()
        reachable = self._reachable_from(self.vendor)

        unreachable = sorted(set(defined) - set(reachable))
        self.assertEqual(unreachable, [],
                         f'{len(unreachable)} crawler(s) are defined under pcapkit/vendor/ but '
                         f'absent from pcapkit.vendor.__all__, so `pcapkit-vendor` with no '
                         f'arguments never runs them and the constant files they own go stale')

        # And nothing is exported that no longer exists on disk, which is the
        # same list drifting in the other direction.
        self.assertEqual(sorted(set(reachable) - set(defined)), [])

    def test_every_crawler_is_reachable_from_its_own_protocol_target(self) -> None:
        # The `--target <name>` path, which reads the subpackage's __all__ rather
        # than the root's. It is a separate list and was separately wrong, so a
        # crawler can be reachable one way and not the other.
        defined = self._defined_crawlers()

        reachable = {}  # type: dict[str, Any]
        for target in self._subpackages():
            module = importlib.import_module(f'pcapkit.vendor.{target}')
            reachable.update(self._reachable_from(module))

        unreachable = sorted(set(defined) - set(reachable))
        self.assertEqual(unreachable, [],
                         f'{len(unreachable)} crawler(s) cannot be reached by '
                         f'`pcapkit-vendor --target <protocol>` either, because they are absent '
                         f'from their own subpackage\'s __all__')

    def test_the_two_target_lists_agree(self) -> None:
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
        self.assertTrue(self._is_crawler(crawler))

        import pcapkit.vendor.mh as mh
        self.assertIn(exported, mh.__all__)
        self.assertIs(getattr(mh, exported), crawler)

        self.assertIn(exported, self.vendor.__all__)
        self.assertIs(getattr(self.vendor, exported), crawler)


if __name__ == '__main__':
    unittest.main()
