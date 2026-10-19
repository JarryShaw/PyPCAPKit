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
:data:`sys.version_info`: the branch of an enclosing ``if`` that runs only on
3.9 or later, or a :func:`unittest.skipIf` or :func:`unittest.skipUnless` on the
test that runs it only there (#1902). The other branch, a gate that points the
wrong way, and a ``getattr(ast, 'unparse')`` all count as ungated.

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


#: The first release with :func:`ast.unparse`.
UNPARSE_SINCE = (3, 9)

#: The comparison each operator becomes with its operands swapped round.
_FLIPPED = {ast.Lt: ast.Gt, ast.LtE: ast.GtE, ast.Gt: ast.Lt, ast.GtE: ast.LtE}


def _is_version_info(node: 'ast.AST') -> bool:
    """Whether ``node`` is ``version_info``, as ``sys.version_info`` or imported bare, or a slice of it."""
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
        node = node.value
    return (isinstance(node, ast.Attribute) and node.attr == 'version_info') \
        or (isinstance(node, ast.Name) and node.id == 'version_info')


def _version(node: 'ast.AST') -> 'tuple[int, ...] | None':
    """The version a tuple of integer literals spells, as in ``(3, 9)``."""
    if isinstance(node, ast.Tuple) and node.elts and all(
            isinstance(elt, ast.Constant) and type(elt.value) is int for elt in node.elts):
        return tuple(elt.value for elt in node.elts)
    return None


def _assures(test: 'ast.AST', outcome: bool) -> bool:
    """Whether ``test`` coming out ``outcome`` means the interpreter has :func:`ast.unparse`.

    A comparison of ``version_info`` with a version of 3.9 or later, such as
    ``(3, 9)``, does: ``>=`` or ``>`` when true, ``<`` or ``<=`` when false, with
    the operands either way round. ``not``, ``and`` and ``or`` combine those as
    they evaluate. Anything else assures nothing.

    """
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return _assures(test.operand, not outcome)
    if isinstance(test, ast.BoolOp):
        # ``and`` is true only when every operand is, ``or`` false only when every one is.
        if isinstance(test.op, ast.And) == outcome:
            return any(_assures(value, outcome) for value in test.values)
        return all(_assures(value, outcome) for value in test.values)
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1):
        return False
    op, left, right = type(test.ops[0]), test.left, test.comparators[0]
    if _is_version_info(right) and not _is_version_info(left):
        op, left, right = _FLIPPED.get(op, op), right, left
    version = _version(right)
    if not _is_version_info(left) or version is None or version < UNPARSE_SINCE:
        return False
    # ``version_info > version`` when true, or ``version_info < version`` when
    # false, puts the interpreter at ``version`` or later: past 3.9 either way.
    if outcome:
        return op in (ast.Gt, ast.GtE)
    return op in (ast.Lt, ast.LtE)


def _skip_condition(decorator: 'ast.AST') -> 'tuple[ast.AST, bool] | None':
    """The condition of a :func:`unittest.skipIf` or :func:`unittest.skipUnless`, and the outcome it runs on."""
    if not (isinstance(decorator, ast.Call) and decorator.args):
        return None
    func = decorator.func
    name = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ''
    if name == 'skipIf':
        return decorator.args[0], False
    if name == 'skipUnless':
        return decorator.args[0], True
    return None


def _gated_children(node: 'ast.AST') -> 'Iterator[tuple[ast.AST, bool]]':
    """Each child of ``node``, and whether a version gate in ``node`` itself encloses it.

    The branch of an ``if``, or of a conditional expression, that runs only on
    3.9 or later is gated, and so is the body of a function or class a skip
    decorator runs only there. The test itself, the other branch, and the
    decorators are not.

    """
    if isinstance(node, (ast.If, ast.IfExp)):
        body, orelse = (node.body, node.orelse) if isinstance(node, ast.If) else ([node.body], [node.orelse])
        yield node.test, False
        for child in body:
            yield child, _assures(node.test, True)
        for child in orelse:
            yield child, _assures(node.test, False)
        return
    gated = False
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        for decorator in node.decorator_list:
            condition = _skip_condition(decorator)
            gated = gated or (condition is not None and _assures(*condition))
    decorators = {id(decorator) for decorator in getattr(node, 'decorator_list', ())}
    for child in ast.iter_child_nodes(node):
        yield child, gated and id(child) not in decorators


def ungated(source: str) -> 'Iterator[int]':
    """Yield the line of each use of :func:`ast.unparse` that no version gate encloses.

    A use is ``<name>.unparse`` or ``getattr(<name>, 'unparse')`` for a name
    :mod:`ast` is imported as, an ``from ast import unparse``, or a load of the
    name that import binds. Imports are collected from the whole file, function
    bodies included.

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
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'getattr':
            return len(node.args) >= 2 and isinstance(node.args[0], ast.Name) and node.args[0].id in modules \
                and isinstance(node.args[1], ast.Constant) and node.args[1].value == 'unparse'
        if isinstance(node, ast.Attribute):
            return node.attr == 'unparse' and isinstance(node.value, ast.Name) and node.value.id in modules
        if isinstance(node, ast.ImportFrom):
            return node.module == 'ast' and not node.level and any(alias.name == 'unparse' for alias in node.names)
        return isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in functions

    def walk(node: 'ast.AST', gated: bool) -> 'Iterator[int]':
        if not gated and isinstance(node, (ast.expr, ast.stmt)) and use(node):
            yield node.lineno
        for child, gate in _gated_children(node):
            yield from walk(child, gated or gate)

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
        """The scan sees each spelling of a use, and each gate, so a pass is not vacuous.

        From line 21 on is #1902: the uses a gate covers only from the branch,
        or the direction, that runs on 3.9 or later, and ``getattr``.

        """
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
            "@unittest.skipUnless(sys.version_info >= (3, 9), 'ast.unparse is 3.9+')\n"
            'def test():\n'
            '    return ast.unparse(node)\n'
            'if sys.version_info >= (3, 9):\n'
            '    pass\n'
            'else:\n'
            '    ast.unparse(node)\n'
            'if sys.version_info < (3, 9):\n'
            '    ast.unparse(node)\n'
            "@unittest.skipIf(sys.version_info >= (3, 9), 'reversed')\n"
            'def test():\n'
            '    return ast.unparse(node)\n'
            "getattr(ast, 'unparse')(node)\n"
            'getattr(tree, "unparse")(node)\n'
            "if sys.version_info >= (3, 9):\n"
            "    getattr(ast, 'unparse')(node)\n"
            'if sys.version_info < (3, 9):\n'
            '    ast.dump(node)\n'
            'else:\n'
            '    ast.unparse(node)\n'
            'from sys import version_info\n'
            'if version_info >= (3, 9):\n'
            '    ast.unparse(node)\n'
            'if (3, 9) <= sys.version_info[:2] and node:\n'
            '    ast.unparse(node)\n'
        )
        self.assertEqual(list(ungated(source)), [5, 6, 7, 8, 9, 27, 29, 32, 33, 34])


if __name__ == '__main__':
    unittest.main()
