# -*- coding: utf-8 -*-
"""No ``setUp`` installs exception-hook sentinels before importing :mod:`pcapkit`.

GitHub issue #2637. Outside development mode, ``import pcapkit`` itself installs
tbtrim's :data:`sys.excepthook` and :data:`threading.excepthook`. Under
:func:`tests._support.reimport_once_per_class` the first test of a class
imports the package afresh, so a ``setUp`` that installs its sentinels before
that import has them replaced by the import, not by the code under test. The
check then fails only for whichever test runs first in its class on a worker,
which is how ``--dist load`` turned the PyPy leg red.

This module is unit-tier: it parses source and never imports the package.

"""
from __future__ import annotations

import ast
import unittest
from typing import TYPE_CHECKING

from tests._tiers import ROOT

if TYPE_CHECKING:
    from typing import Optional

#: Directory scanned for test classes.
TESTS = ROOT / 'tests'

#: Fewest methods the scan must see both re-importing and installing a
#: sentinel, so that a scan that silently matches nothing cannot pass.
MIN_METHODS = 4

#: The hook slots a sentinel is installed into.
HOOKS = frozenset({('sys', 'excepthook'), ('threading', 'excepthook')})


def _purges(stmt: 'ast.stmt') -> bool:
    """Whether ``stmt`` is a call that may drop :mod:`pcapkit` from :data:`sys.modules`."""
    if not (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call)):
        return False
    func = stmt.value.func
    name = func.attr if isinstance(func, ast.Attribute) else getattr(func, 'id', None)
    return name in ('reimport_once_per_class', 'purge_modules')


def _imports_pcapkit(stmt: 'ast.stmt') -> bool:
    """Whether ``stmt`` imports :mod:`pcapkit` or one of its submodules."""
    if isinstance(stmt, ast.Import):
        return any(alias.name.split('.')[0] == 'pcapkit' for alias in stmt.names)
    return isinstance(stmt, ast.ImportFrom) and (stmt.module or '').split('.')[0] == 'pcapkit'


def _sets_hook(stmt: 'ast.stmt') -> bool:
    """Whether ``stmt`` assigns to ``sys.excepthook`` or ``threading.excepthook``."""
    if not isinstance(stmt, ast.Assign):
        return False
    for target in stmt.targets:
        for node in ast.walk(target):
            if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                    and (node.value.id, node.attr) in HOOKS):
                return True
    return False


def _early_sentinel(method: 'ast.FunctionDef') -> 'Optional[int]':
    """The line where ``method`` sets a hook after a purge and before an import, if any.

    Only the method's own statements count, not those of a function it defines,
    such as the cleanup that puts the saved hooks back.

    """
    purged = False
    for stmt in method.body:
        if _purges(stmt):
            purged = True
        elif _imports_pcapkit(stmt):
            purged = False
        elif purged and _sets_hook(stmt):
            return stmt.lineno
    return None


def scan(source: str) -> 'tuple[int, list[tuple[str, int]]]':
    """Methods in ``source`` that purge and set a hook, and those that set it too early.

    Args:
        source: Module source text.

    Returns:
        The number of methods that purge and then set a hook, and ``(qualified
        name, line)`` for each of them that sets it before importing :mod:`pcapkit`.

    """
    pairing, offending = 0, []
    for cls in ast.walk(ast.parse(source)):
        if not isinstance(cls, ast.ClassDef):
            continue
        for method in cls.body:
            if not isinstance(method, ast.FunctionDef):
                continue
            body = method.body
            starts = [index for index, stmt in enumerate(body) if _purges(stmt)]
            if not (starts and any(_sets_hook(stmt) for stmt in body[starts[0]:])):
                continue
            pairing += 1
            line = _early_sentinel(method)
            if line is not None:
                offending.append((f'{cls.name}.{method.name}', line))
    return pairing, offending


class HookSentinelImportOrderTests(unittest.TestCase):
    """The tree-wide check, and the detector's own edges."""

    maxDiff = None

    def test_no_sentinel_precedes_the_import(self) -> None:
        pairing, found = 0, []
        for path in sorted(TESTS.rglob('*.py')):
            count, offending = scan(path.read_text(encoding='utf-8'))
            pairing += count
            found.extend(f'{path.relative_to(ROOT).as_posix()}:{line} {name}' for name, line in offending)
        self.assertGreaterEqual(pairing, MIN_METHODS, 'the scan found too few methods to be trusted')
        self.assertEqual(found, [], 'import pcapkit before installing the sentinels (GitHub issue #2637)')

    def test_detector_edges(self) -> None:
        """Flags a sentinel set between a purge and the import, and nothing else."""
        sentinel = '        sys.excepthook, threading.excepthook = a, b\n'
        cases = {
            # label: (methods flagged, setUp body after the purge)
            'sentinel before the import': (['T.setUp'], sentinel + '        import pcapkit\n'),
            'sentinel, no import': (['T.setUp'], '        threading.excepthook = b\n'),
            'import first': ([], '        import pcapkit\n' + sentinel),
            'submodule import first': ([], '        from pcapkit.utilities import exceptions\n' + sentinel),
            'restore in a nested function': ([], '        def restore():\n    ' + sentinel
                                             + '        self.addCleanup(restore)\n'),
        }
        for label, (flagged, body) in cases.items():
            with self.subTest(case=label):
                source = 'class T:\n    def setUp(self):\n        reimport_once_per_class(self)\n' + body
                _, offending = scan(source)
                self.assertEqual([name for name, _ in offending], flagged)


if __name__ == '__main__':
    unittest.main()
