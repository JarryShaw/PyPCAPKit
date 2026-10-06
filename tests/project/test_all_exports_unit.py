# -*- coding: utf-8 -*-
"""``pcapkit.all.__all__`` lists every name its star-imported packages export.

``pcapkit/all.py`` keeps its :attr:`__all__` by hand, so a name added to one of
the packages it aggregates is silently left out of ``from pcapkit.all import *``
(#1136). The aggregated packages are read from the ``from pcapkit.X import *``
statements in the source with :mod:`ast`, so a package added there is covered
without editing this module.

"""
from __future__ import annotations

import ast
import importlib
import importlib.util
import os
import unittest

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

ALL_PY = os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, 'pcapkit', 'all.py')

#: Names an aggregated package exports and :mod:`pcapkit.all` deliberately does
#: not list, keyed by the package. :mod:`pcapkit.utilities` has been unlisted
#: since ``769a17c78`` (2022-05-29), which commented its group out: its exports
#: are generic helpers -- ``warn``, ``reset``, ``configure``, ``detect`` -- that
#: ``import *`` should not drop into the caller's namespace. A name added here is
#: an API decision.
DELIBERATE_NON_EXPORTS = {
    'pcapkit.utilities': ('logger', 'get_logger', 'configure', 'reset', 'ensure_output',
                          'warn', 'stacklevel', 'detect', 'beholder', 'prepare', 'seekset'),
}


def star_imported() -> 'list[str]':
    """Return the packages ``pcapkit/all.py`` imports with ``from ... import *``."""
    with open(ALL_PY, encoding='utf-8') as file:
        tree = ast.parse(file.read())
    return [node.module for node in tree.body
            if isinstance(node, ast.ImportFrom) and node.module is not None
            and any(alias.name == '*' for alias in node.names)]


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class AllExportsTests(unittest.TestCase):
    """``pcapkit.all.__all__`` keeps in step with the packages it aggregates."""

    def test_star_imports_are_found(self) -> None:
        packages = star_imported()
        self.assertIn('pcapkit.protocols', packages)
        self.assertIn('pcapkit.corekit', packages)
        self.assertIn('pcapkit.foundation', packages)

    def test_every_aggregated_export_is_listed_or_excluded(self) -> None:
        import pcapkit.all

        listed = set(pcapkit.all.__all__)
        for package in star_imported():
            with self.subTest(package=package):
                exported = importlib.import_module(package).__all__
                excluded = set(DELIBERATE_NON_EXPORTS.get(package, ()))
                self.assertEqual(sorted(set(exported) - listed - excluded), [])

    def test_exclusions_are_not_stale(self) -> None:
        import pcapkit.all

        for package, names in DELIBERATE_NON_EXPORTS.items():
            with self.subTest(package=package):
                self.assertIn(package, star_imported())
                exported = set(importlib.import_module(package).__all__)
                self.assertEqual(sorted(set(names) - exported), [])
                self.assertEqual(sorted(set(names) & set(pcapkit.all.__all__)), [])

    def test_every_listed_name_resolves(self) -> None:
        import pcapkit.all

        self.assertEqual([name for name in pcapkit.all.__all__
                          if not hasattr(pcapkit.all, name)], [])


if __name__ == '__main__':
    unittest.main()
