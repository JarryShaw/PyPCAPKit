# -*- coding: utf-8 -*-
"""No test calls :func:`ast.unparse` outside a version gate (#1899).

:func:`ast.unparse` is 3.9+, and the unit tier also runs on the
``Python 3.8 (KTLO)`` leg, where the call raises :class:`AttributeError`. That
leg reads green even when a test fails (#1679), so the failure shows only in its
annotations and log, which is how the #1878 engine-stub tests broke there
unnoticed.

A test reads a node back as written with :func:`ast.get_source_segment`,
compares it with :func:`ast.dump`, or matches its fields, all of which 3.8 has.
One that has to render a node puts the call under a gate on
:data:`sys.version_info`: an enclosing ``if``, or a decorator such as
:func:`unittest.skipIf` on the test.

This module is unit-tier: it parses source and imports nothing it scans.

"""
from __future__ import annotations

import ast
import unittest
from typing import TYPE_CHECKING

from tests._tiers import ROOT

if TYPE_CHECKING:
    from typing import Iterator

#: Directory that is scanned: every module of it runs on the 3.8 leg.
TESTS = ROOT / 'tests'


def _reads_version_info(node: 'ast.AST') -> bool:
    """Whether ``node`` reads ``version_info``, as ``sys.version_info`` or imported bare."""
    return any((isinstance(sub, ast.Attribute) and sub.attr == 'version_info')
               or (isinstance(sub, ast.Name) and sub.id == 'version_info') for sub in ast.walk(node))


def _is_gate(node: 'ast.AST') -> bool:
    """Whether ``node`` gates what it holds on the interpreter's version."""
    if isinstance(node, (ast.If, ast.IfExp)):
        return _reads_version_info(node.test)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return any(_reads_version_info(decorator) for decorator in node.decorator_list)
    return False


def ungated(source: str) -> 'Iterator[int]':
    """Yield the line of each use of :func:`ast.unparse` that no version gate encloses.

    A use is ``<name>.unparse`` for a name :mod:`ast` is imported as, an
    ``from ast import unparse``, or a load of the name that import binds. Imports
    are collected from the whole file, function bodies included.

    Args:
        source: Module source text.

    Yields:
        The line number of each ungated use.

    """
    tree = ast.parse(source)
    modules = set()  # type: set[str]
    functions = set()  # type: set[str]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.asname or alias.name for alias in node.names if alias.name == 'ast')
        elif isinstance(node, ast.ImportFrom) and node.module == 'ast' and not node.level:
            functions.update(alias.asname or alias.name for alias in node.names if alias.name == 'unparse')

    def use(node: 'ast.AST') -> bool:
        if isinstance(node, ast.Attribute):
            return node.attr == 'unparse' and isinstance(node.value, ast.Name) and node.value.id in modules
        if isinstance(node, ast.ImportFrom):
            return node.module == 'ast' and not node.level and any(alias.name == 'unparse' for alias in node.names)
        return isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in functions

    def walk(node: 'ast.AST', gated: bool) -> 'Iterator[int]':
        gated = gated or _is_gate(node)
        if not gated and isinstance(node, (ast.expr, ast.stmt)) and use(node):
            yield node.lineno
        for child in ast.iter_child_nodes(node):
            yield from walk(child, gated)

    yield from walk(tree, False)


class UnparseGateTests(unittest.TestCase):
    """Every use of :func:`ast.unparse` under :file:`tests/` is gated to 3.9+."""

    def test_no_test_calls_unparse_outside_a_version_gate(self) -> None:
        found = []  # type: list[str]
        for path in sorted(TESTS.rglob('*.py')):
            relative = path.relative_to(ROOT).as_posix()
            found.extend(f'{relative}:{lineno}' for lineno in ungated(path.read_text(encoding='utf-8')))
        self.assertEqual(found, [], 'ast.unparse is 3.9+, so these fail on the 3.8 leg: read the node with '
                                    'ast.get_source_segment or match its fields, or gate on sys.version_info')

    def test_each_use_and_gate_is_matched(self) -> None:
        """The scan sees each spelling of a use, and each gate, so a pass is not vacuous."""
        source = (
            'import ast\n'
            'import ast as tree\n'
            'import sys\n'
            'import unittest\n'
            'ast.unparse(node)\n'
            'tree.unparse(node)\n'
            'from ast import unparse\n'
            'from ast import unparse as render\n'
            'render(node)\n'
            'if sys.version_info >= (3, 9):\n'
            '    ast.unparse(node)\n'
            'else:\n'
            '    ast.dump(node)\n'
            'text = ast.unparse(node) if sys.version_info >= (3, 9) else ast.dump(node)\n'
            "@unittest.skipIf(sys.version_info < (3, 9), 'ast.unparse is 3.9+')\n"
            'def test():\n'
            '    return ast.unparse(node)\n'
            'def helper(node):\n'
            '    """ast.unparse is 3.9+"""\n'
            '    return ast.get_source_segment(source, node), node.unparse\n'
        )
        self.assertEqual(list(ungated(source)), [5, 6, 7, 8, 9])


if __name__ == '__main__':
    unittest.main()
