# -*- coding: utf-8 -*-
"""No test class undoes its own per-class :mod:`pcapkit` import.

GitHub issue #1538. :func:`tests._support.reimport_once_per_class` (#1065) gives
a class one import of the package, shared by its tests: the first test purges,
and :func:`tests._support._keep_lazy_imports` -- a cleanup, so it runs *after*
``tearDown`` -- records what the test imported for the next one to reuse. A
``tearDown`` that also purges :mod:`pcapkit` empties :data:`sys.modules` before
that cleanup reads it, so the class keeps nothing and every test pays the full
re-import again (about 0.67s and 329 modules, by that helper's docstring) while
the ``setUp`` reads as if it did not. Twelve classes in seven files did this
on ``main`` after #1070 converted their ``setUp`` and left the ``tearDown``.

A class that needs a fresh import for every test should say so by purging in
``setUp`` *instead of* calling :func:`~tests._support.reimport_once_per_class`,
as ``tests.const.test_const_enum_builtin_parity.ConstEnumRegisterFallbackTests``
does. That form is not matched here, and neither is a narrow purge of one
submodule, such as ``tests/toolkit/test_scapy_unit.py`` purging
``pcapkit.toolkit.scapy`` from a test body: only a purge of the whole package
discards the class's import.

This module is unit-tier: it parses source and never imports the package.

"""
from __future__ import annotations

import ast
import textwrap
import unittest
from typing import TYPE_CHECKING

from tests._tiers import ROOT

if TYPE_CHECKING:
    from typing import Iterator, Optional

#: Directory scanned for test classes.
TESTS = ROOT / 'tests'

#: ``(path relative to the repository root, class name)`` -> why the class
#: genuinely needs both. Empty: the deliberate per-test form purges in ``setUp``
#: without the helper, which this guard does not flag. Enforced both ways, so an
#: entry that stops pairing the two has to be removed.
ALLOWED = {}  # type: dict[tuple[str, str], str]

#: Fewest classes the scan must see calling the helper, so that a scan that
#: silently matches nothing cannot pass. It counted 384 when this was written.
MIN_CLASSES = 300


def _callee(node: 'ast.AST') -> 'Optional[str]':
    """The bare name a call is made through: ``f`` for ``f()`` and ``x.f()``."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_whole_package(node: 'ast.AST') -> bool:
    """Whether ``node`` names :mod:`pcapkit` itself among the prefixes to purge."""
    if isinstance(node, ast.Name):
        return node.id == 'ISOLATED_PREFIXES'
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(isinstance(item, ast.Constant) and item.value == 'pcapkit' for item in node.elts)
    return False


def _whole_purges(method: 'ast.FunctionDef') -> 'Iterator[int]':
    """Line numbers in ``method`` that purge, or register a purge of, all of :mod:`pcapkit`."""
    for node in ast.walk(method):
        if not isinstance(node, ast.Call):
            continue
        name = _callee(node.func)
        if name == 'purge_modules' and node.args and _is_whole_package(node.args[0]):
            yield node.lineno
        elif (name == 'addCleanup' and len(node.args) >= 2 and _callee(node.args[0]) == 'purge_modules'
              and _is_whole_package(node.args[1])):
            yield node.lineno


def _helper_calls(method: 'ast.FunctionDef') -> 'list[int]':
    """Line numbers in ``method`` that call ``reimport_once_per_class``."""
    return [node.lineno for node in ast.walk(method)
            if isinstance(node, ast.Call) and _callee(node.func) == 'reimport_once_per_class']


def _resolve(classes: 'dict[str, ast.ClassDef]', cls: 'ast.ClassDef',
             method: str) -> 'Optional[ast.FunctionDef]':
    """``cls.method``, looked up through the bases defined in the same module."""
    seen = set()  # type: set[str]
    stack = [cls]
    while stack:
        current = stack.pop(0)
        if current.name in seen:
            continue
        seen.add(current.name)
        for item in current.body:
            if isinstance(item, ast.FunctionDef) and item.name == method:
                return item
        stack.extend(classes[base.id] for base in current.bases
                     if isinstance(base, ast.Name) and base.id in classes)
    return None


def scan(source: str) -> 'tuple[int, list[tuple[str, int]]]':
    """Classes in ``source`` that call the helper, and those that also undo it.

    Args:
        source: Module source text.

    Returns:
        The number of classes whose ``setUp`` calls ``reimport_once_per_class``,
        and ``(class name, line)`` for each of them that also purges the whole
        package -- anywhere in ``tearDown``, or in ``setUp`` after the call.

    """
    tree = ast.parse(source)
    classes = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)}
    using, offending = 0, []
    for cls in classes.values():
        set_up = _resolve(classes, cls, 'setUp')
        calls = [] if set_up is None else _helper_calls(set_up)
        if set_up is None or not calls:
            continue
        using += 1
        tear_down = _resolve(classes, cls, 'tearDown')
        lines = [line for line in _whole_purges(set_up) if line > min(calls)]
        if tear_down is not None:
            lines.extend(_whole_purges(tear_down))
        if lines:
            offending.append((cls.name, min(lines)))
    return using, offending


def scan_tree() -> 'tuple[int, dict[tuple[str, str], int]]':
    """:func:`scan` over every module under :data:`TESTS`, keyed by relative path."""
    using, found = 0, {}
    for path in sorted(TESTS.rglob('*.py')):
        count, offending = scan(path.read_text(encoding='utf-8'))
        using += count
        relative = path.relative_to(ROOT).as_posix()
        for name, line in offending:
            found[(relative, name)] = line
    return using, found


class PerClassImportGuardTests(unittest.TestCase):
    """The tree-wide check, and the detector's own edges."""

    maxDiff = None

    def test_no_class_purges_the_import_it_keeps(self) -> None:
        using, found = scan_tree()
        self.assertGreaterEqual(using, MIN_CLASSES, 'the scan found too few classes to be trusted')
        unexpected = [f'{path}:{line} {name}' for (path, name), line
                      in sorted(found.items(), key=lambda item: (item[0][0], item[1]))
                      if (path, name) not in ALLOWED]
        self.assertEqual(unexpected, [], 'drop the whole-package purge, or purge in setUp '
                         'instead of calling reimport_once_per_class (GitHub issue #1538)')

    def test_every_allowed_class_still_pairs_the_two(self) -> None:
        _, found = scan_tree()
        self.assertEqual(sorted(key for key in ALLOWED if key not in found), [])

    def test_detector_edges(self) -> None:
        """Matches the whole-package forms and nothing narrower or deliberate."""
        helper = '    def setUp(self): reimport_once_per_class(self)\n'
        cases = {
            # label: (classes flagged, source)
            'tearDown purge': (['T'], 'class T:\n' + helper +
                               "    def tearDown(self): purge_modules(['pcapkit'])\n"),
            'tearDown cleanup, tuple': (['T'], 'class T:\n' + helper +
                                        "    def tearDown(self): self.addCleanup(purge_modules, ('pcapkit',))\n"),
            'setUp purge after the helper': (['T'], textwrap.dedent('''
                class T:
                    def setUp(self):
                        reimport_once_per_class(self)
                        purge_modules(ISOLATED_PREFIXES)
            ''')),
            'inherited setUp': (['T'], 'class Base:\n' + helper +
                                "class T(Base):\n    def tearDown(self): _support.purge_modules(['pcapkit'])\n"),
            'per-test purge, no helper': ([], textwrap.dedent('''
                class T:
                    def setUp(self): purge_modules(['pcapkit'])
                    def tearDown(self): purge_modules(['pcapkit'])
            ''')),
            'narrow purge in a test body': ([], 'class T:\n' + helper + "    def test(self):\n"
                                            "        self.addCleanup(purge_modules, ['pcapkit.toolkit.scapy'])\n"),
            'narrow purge in tearDown': ([], 'class T:\n' + helper +
                                         "    def tearDown(self): purge_modules(['pcapkit.utilities.compat'])\n"),
            'purge before the helper': ([], textwrap.dedent('''
                class T:
                    def setUp(self):
                        purge_modules(['pcapkit'])
                        reimport_once_per_class(self, restore=True)
            ''')),
        }
        for label, (flagged, source) in cases.items():
            with self.subTest(case=label):
                _, offending = scan(source)
                self.assertEqual([name for name, _ in offending], flagged)


if __name__ == '__main__':
    unittest.main()
