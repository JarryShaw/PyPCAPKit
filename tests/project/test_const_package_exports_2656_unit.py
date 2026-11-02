# -*- coding: utf-8 -*-
"""Every ``pcapkit.const`` subpackage is re-exported and documented (#2656).

A subpackage whose ``from pcapkit.const.<name> import *`` and ``__all__`` entries leave
:file:`pcapkit/const/__init__.py`, or whose line leaves the toctree in
:file:`docs/source/pcapkit/const/index.rst`, fails here. The subpackages are read from
the tree with :func:`pkgutil.iter_modules`, so one added to the tree is held to both
rules without an edit here, as *Round-Trip Invariants* in
:file:`docs/source/contributing/conventions/test-coverage.rst` asks of a sweep.

* :class:`ReaderTests` -- the toctree, ``__all__`` and star-import readers the sweeps use.
* :class:`ConstPackageTests` -- each subpackage is star-imported by
  :mod:`pcapkit.const`, lists every name of its own ``__all__`` in
  :data:`pcapkit.const.__all__`, and is in the toctree of the index page.
* :class:`VendorPackageTests` -- the toctree rule for :mod:`pcapkit.vendor`, which
  mirrors :mod:`pcapkit.const` (*Const-Vendor Pairing* in
  :file:`docs/source/contributing/conventions/const-vendor-pairing.rst`). Its
  re-export is held by ``CrawlerReachabilityTests`` in
  :file:`tests/vendor/test_crawler_reachability_unit.py`, so it is not repeated.

The check is textual and imports nothing.

"""

from __future__ import annotations

import ast
import pathlib
import pkgutil
import re
import tempfile
import unittest

#: Test tier (#1958): reads the package trees and the docs index pages, and imports nothing.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The docs pages of :mod:`pcapkit`'s packages.
DOCS = ROOT / 'docs' / 'source' / 'pcapkit'

#: Modules directly under a checked package that are no registry package, so owe no
#: re-export and no toctree line, keyed by package and then module. Each reason is
#: asserted by a test of its own, so an entry cannot outlive it.
NOT_A_REGISTRY = {
    'vendor': {
        '__main__': 'the pcapkit-vendor command line: it defines main, and the index page '
                    'documents it under a module directive of its own',
        'default': 'the Vendor base class every crawler subclasses: pcapkit.vendor imports it '
                   'by name and keeps it out of __all__',
    },
}

#: Registry packages of :mod:`pcapkit.const` that :file:`pcapkit/const/__init__.py` does not
#: re-export, a recorded defect (#2661). Each reason names what is missing. Wiring a package
#: deletes its entry, which ``test_unwired_entries_hold`` enforces.
KNOWN_UNWIRED = {
    'linux': 'no "from pcapkit.const.linux import *" in pcapkit/const/__init__.py, and the name '
             'is unprefixed: pcapkit.const.linux.__all__ lists ARPHRD, where the house prefix '
             'gives Linux_ARPHRD, as pcapkit.vendor.linux.__all__ lists it',
}

#: A ``.. toctree::`` directive, capturing its indentation.
TOCTREE = re.compile(r'^(\s*)\.\. toctree::\s*$')

#: The target of a ``Title <target>`` toctree entry.
TITLED = re.compile(r'<([^>]+)>\s*$')


def members(package: 'str') -> 'dict[str, bool]':
    """Every module directly under :mod:`pcapkit.<package>`, mapped to whether it is a package."""
    return {info.name: info.ispkg
            for info in pkgutil.iter_modules([str(ROOT / 'pcapkit' / package)])}


def subpackages(package: 'str') -> 'list[str]':
    """The packages directly under :mod:`pcapkit.<package>`, sorted."""
    return sorted(name for name, ispkg in members(package).items() if ispkg)


def parse(path: 'pathlib.Path') -> 'ast.Module':
    """The syntax tree of the module at ``path``."""
    return ast.parse(path.read_text(encoding='utf-8'), filename=str(path))


def literal_all(path: 'pathlib.Path') -> 'list[str]':
    """The names in the literal ``__all__`` of the module at ``path``.

    Raises:
        AssertionError: The module has no ``__all__``, or one that is not a literal list of
            names, which this module cannot read.

    """
    for node in parse(path).body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == '__all__'
                                                for target in node.targets):
            try:
                names = ast.literal_eval(node.value)
            except ValueError:
                names = None
            if not isinstance(names, (list, tuple)) or not all(isinstance(name, str) for name in names):
                raise AssertionError(f'{path} spells __all__ as something other than a literal list of names')
            return list(names)
    raise AssertionError(f'{path} defines no __all__')


def star_imports(path: 'pathlib.Path') -> 'set[str]':
    """The modules the module at ``path`` star-imports, at any depth."""
    return {node.module for node in ast.walk(parse(path))
            if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module is not None
            and any(alias.name == '*' for alias in node.names)}


def toctree_entries(path: 'pathlib.Path') -> 'set[str]':
    """The documents listed by every toctree in the page at ``path``, as written.

    A ``Title <target>`` entry counts as its target. Options and comments are skipped.

    """
    entries = set()  # type: set[str]
    indent = None  # type: int | None
    for line in path.read_text(encoding='utf-8').splitlines():
        directive = TOCTREE.match(line)
        if directive:
            indent = len(directive.group(1))
            continue
        if indent is None or not line.strip():
            continue
        if len(line) - len(line.lstrip()) <= indent:
            indent = None
            continue
        text = line.strip()
        if text.startswith((':', '..')):
            continue
        titled = TITLED.search(text)
        entries.add(titled.group(1) if titled else text)
    return entries


def index_page(package: 'str') -> 'pathlib.Path':
    """The page that documents :mod:`pcapkit.<package>`."""
    return DOCS / package / 'index.rst'


def unlisted(package: 'str') -> 'list[str]':
    """The subpackages of :mod:`pcapkit.<package>` that no toctree of its index page lists."""
    listed = toctree_entries(index_page(package))
    return [name for name in subpackages(package) if name not in listed]


def unexcused(package: 'str') -> 'list[str]':
    """The plain modules directly under :mod:`pcapkit.<package>` that ``NOT_A_REGISTRY`` omits."""
    plain = {name for name, ispkg in members(package).items() if not ispkg}
    return sorted(plain - set(NOT_A_REGISTRY.get(package, ())))


def stale_excuses(package: 'str') -> 'list[str]':
    """The ``NOT_A_REGISTRY`` entries of ``package`` that are not plain modules under it."""
    plain = {name for name, ispkg in members(package).items() if not ispkg}
    return sorted(set(NOT_A_REGISTRY.get(package, ())) - plain)


class ReaderTests(unittest.TestCase):
    """The readers find what the sweeps rely on, so a green sweep is not a reader that saw nothing."""

    def write(self, text: 'str') -> 'pathlib.Path':
        """A scratch file holding ``text``."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = pathlib.Path(directory.name) / 'page'
        path.write_text(text, encoding='utf-8')
        return path

    def test_toctree_entries_read_every_form(self) -> 'None':
        """Plain, titled and nested entries count; options, comments and prose do not."""
        path = self.write('Title\n=====\n\n'
                          '.. toctree::\n   :maxdepth: 2\n   :caption: Layers\n\n'
                          '   plain\n   Shown <titled>\n   .. commented\n\n'
                          'prose after the block\n\n'
                          '.. only:: html\n\n   .. toctree::\n\n      nested\n\n'
                          '.. note::\n\n   not_in_a_toctree\n')
        self.assertEqual(toctree_entries(path), {'plain', 'titled', 'nested'})

    def test_literal_all_reads_a_list_and_refuses_the_rest(self) -> 'None':
        """A missing, computed or non-string ``__all__`` raises instead of reading as empty."""
        self.assertEqual(literal_all(self.write("__all__ = ['a', 'b']\n")), ['a', 'b'])
        for text in ('x = 1\n', '__all__ = sorted(names)\n', '__all__ = [1]\n'):
            with self.subTest(text=text), self.assertRaises(AssertionError):
                literal_all(self.write(text))

    def test_star_imports_read_nested_absolute_ones(self) -> 'None':
        """A star import under ``if``/``else`` counts; a named or relative one does not."""
        path = self.write('from a.b import *\nif x:\n    from c import *\nfrom d import e\nfrom . import *\n')
        self.assertEqual(star_imports(path), {'a.b', 'c'})


class ConstPackageTests(unittest.TestCase):
    """Each :mod:`pcapkit.const` subpackage is re-exported and listed in its index page."""

    init = ROOT / 'pcapkit' / 'const' / '__init__.py'

    def test_the_walk_found_subpackages_and_a_toctree(self) -> 'None':
        """An empty walk or toctree would let every loop below pass without checking a member."""
        self.assertTrue(subpackages('const'))
        self.assertTrue(toctree_entries(index_page('const')))

    def test_every_subpackage_is_star_imported(self) -> 'None':
        """Its ``from pcapkit.const.<name> import *`` is what puts the names on the package."""
        stars = star_imports(self.init)
        missing = [name for name in subpackages('const')
                   if name not in KNOWN_UNWIRED and f'pcapkit.const.{name}' not in stars]
        self.assertEqual(missing, [], 'add a "from pcapkit.const.<name> import *" for each')

    def test_every_subpackage_name_is_in_all(self) -> 'None':
        """Each name of its own ``__all__`` is in :data:`pcapkit.const.__all__`."""
        exported = set(literal_all(self.init))
        missing = {}  # type: dict[str, list[str]]
        for name in subpackages('const'):
            if name in KNOWN_UNWIRED:
                continue
            names = literal_all(self.init.parent / name / '__init__.py')
            self.assertTrue(names, f'pcapkit.const.{name}.__all__ is empty')
            lacking = [item for item in names if item not in exported]
            if lacking:
                missing[name] = lacking
        self.assertEqual(missing, {}, 'add each name to __all__ in pcapkit/const/__init__.py')

    def test_every_subpackage_is_in_the_toctree(self) -> 'None':
        """A package with no toctree line is orphaned from the reference."""
        self.assertEqual(unlisted('const'), [],
                         f'add each to a toctree of {index_page("const").relative_to(ROOT)}')

    def test_every_plain_module_is_excused(self) -> 'None':
        """A module that is no package owes neither a re-export nor a line, and says why."""
        self.assertEqual(unexcused('const'), [],
                         'make each a package, or add it to NOT_A_REGISTRY with the reason')
        self.assertEqual(stale_excuses('const'), [])

    def test_unwired_entries_hold(self) -> 'None':
        """An entry names a real package that is neither star-imported nor listed in ``__all__``."""
        stars = star_imports(self.init)
        exported = set(literal_all(self.init))
        for name in KNOWN_UNWIRED:
            with self.subTest(package=name):
                self.assertTrue(name in subpackages('const'), 'names no subpackage of pcapkit.const')
                self.assertFalse(f'pcapkit.const.{name}' in stars, 'is star-imported; delete the entry')
                listed = [item for item in literal_all(self.init.parent / name / '__init__.py')
                          if item in exported]
                self.assertEqual(listed, [], 'is listed in __all__; delete the entry')


class VendorPackageTests(unittest.TestCase):
    """The :mod:`pcapkit.vendor` index page lists every crawler package."""

    vendor = ROOT / 'pcapkit' / 'vendor'

    def test_the_walk_found_subpackages_and_a_toctree(self) -> 'None':
        """An empty walk or toctree would let the loop below pass without checking a member."""
        self.assertTrue(subpackages('vendor'))
        self.assertTrue(toctree_entries(index_page('vendor')))

    def test_every_subpackage_is_in_the_toctree(self) -> 'None':
        """A crawler package with no toctree line is orphaned from the reference."""
        self.assertEqual(unlisted('vendor'), [],
                         f'add each to a toctree of {index_page("vendor").relative_to(ROOT)}')

    def test_every_plain_module_is_excused(self) -> 'None':
        """A module that is no package owes no toctree line, and says why."""
        self.assertEqual(unexcused('vendor'), [],
                         'make each a package, or add it to NOT_A_REGISTRY with the reason')
        self.assertEqual(stale_excuses('vendor'), [])

    def command_line_is_no_registry(self) -> 'None':
        """``__main__`` defines ``main``, and the index page documents it by a module directive."""
        defined = {node.name for node in parse(self.vendor / '__main__.py').body
                   if isinstance(node, ast.FunctionDef)}
        self.assertIn('main', defined)
        self.assertIn('.. module:: pcapkit.vendor.__main__',
                      index_page('vendor').read_text(encoding='utf-8'))

    def base_class_is_no_registry(self) -> 'None':
        """``default`` defines ``Vendor``, which the package imports by name and does not export."""
        defined = {node.name for node in parse(self.vendor / 'default.py').body
                   if isinstance(node, ast.ClassDef)}
        self.assertIn('Vendor', defined)
        init = self.vendor / '__init__.py'
        imported = [alias.name for node in ast.walk(parse(init))
                    if isinstance(node, ast.ImportFrom) and node.module == 'pcapkit.vendor.default'
                    for alias in node.names]
        self.assertEqual(imported, ['Vendor'])
        self.assertNotIn('Vendor', literal_all(init))

    def test_every_excuse_holds_its_reason(self) -> 'None':
        """Each ``NOT_A_REGISTRY`` entry has an assertion of its reason, and no assertion is orphaned."""
        asserted = {'__main__': self.command_line_is_no_registry,
                    'default': self.base_class_is_no_registry}
        self.assertEqual(sorted(asserted), sorted(NOT_A_REGISTRY['vendor']),
                         'assert the reason of each excuse, and only of those')
        for name, check in asserted.items():
            with self.subTest(module=name):
                check()


if __name__ == '__main__':
    unittest.main()
