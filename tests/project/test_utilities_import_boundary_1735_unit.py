# -*- coding: utf-8 -*-
"""Nothing under :mod:`pcapkit.utilities` imports :mod:`pcapkit` outside it.

GitHub issue #1712 settled which of :mod:`pcapkit.utilities` and
:mod:`pcapkit.corekit` a module belongs in: ``utilities`` holds cross-cutting
services, and a service imports nothing from :mod:`pcapkit` outside
``utilities`` -- not at top level, not inside a function, and not under
``TYPE_CHECKING``. So the decorators, which reach :mod:`pcapkit.protocols` both
under ``TYPE_CHECKING`` and lazily inside ``beholder``, belong in
:mod:`pcapkit.corekit.decorators` (#1735), not in ``pcapkit.utilities``.

The check reads each module with :mod:`ast` rather than importing it, so a lazy
import is seen whether or not anything ever calls the function that holds it.
Relative imports are resolved against the module's own package, and a literal
:func:`importlib.import_module` or :func:`__import__` call counts as an import.

The rule is written down on
:file:`docs/source/contributing/conventions/utilities-or-corekit.rst`.

This module is unit-tier and reads no capture.

"""
from __future__ import annotations

import ast
import pathlib
import unittest

#: Repository root.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The package the rule governs.
PACKAGE = 'pcapkit.utilities'

#: Its directory.
UTILITIES = ROOT / 'pcapkit' / 'utilities'

#: Call names that import a module named by their first argument.
DYNAMIC_IMPORTERS = frozenset({'import_module', '__import__'})


def _module_name(path: 'pathlib.Path') -> 'str':
    """Dotted name of ``path``, a source file under :data:`ROOT`."""
    parts = list(path.relative_to(ROOT).with_suffix('').parts)
    if parts[-1] == '__init__':
        parts.pop()
    return '.'.join(parts)


def _relative_base(module: 'str', is_package: 'bool', level: 'int') -> 'str':
    """The package a ``from`` import with ``level`` leading dots names."""
    package = module.split('.') if is_package else module.split('.')[:-1]
    return '.'.join(package[:len(package) - (level - 1)])


def imported_names(source: 'str', module: 'str', is_package: 'bool' = False
                   ) -> 'list[tuple[int, str]]':
    """Every module ``source`` imports, as ``(line, dotted name)`` in line order.

    ``from X import a, b`` yields ``X``, except that ``from pcapkit import a``
    yields ``pcapkit.a``, so ``from pcapkit import utilities`` is told apart from
    ``from pcapkit import protocols``.

    Args:
        source: Python source to read.
        module: Dotted name of the module ``source`` belongs to, for resolving
            relative imports.
        is_package: Whether ``source`` is that package's :file:`__init__.py`.

    """
    found = []  # type: list[tuple[int, str]]
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found.extend((node.lineno, alias.name) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = _relative_base(module, is_package, node.level)
                target = f'{base}.{node.module}' if node.module else base
            else:
                target = node.module or ''
            if target == 'pcapkit' or not node.module:
                found.extend((node.lineno, f'{target}.{alias.name}') for alias in node.names)
            else:
                found.append((node.lineno, target))
        elif isinstance(node, ast.Call) and node.args:
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, 'id', None)
            first = node.args[0]
            if (name in DYNAMIC_IMPORTERS and isinstance(first, ast.Constant)
                    and isinstance(first.value, str)):
                found.append((node.lineno, first.value))
    # ``ast.walk`` is breadth-first, so a nested import would otherwise be
    # reported after every top-level one.
    return sorted(found)


def crosses_the_boundary(name: 'str') -> 'bool':
    """Whether importing ``name`` reaches :mod:`pcapkit` outside :data:`PACKAGE`."""
    if name == PACKAGE or name.startswith(f'{PACKAGE}.'):
        return False
    return name == 'pcapkit' or name.startswith('pcapkit.')


def violations(root: 'pathlib.Path' = UTILITIES) -> 'list[str]':
    """Every import under ``root`` that crosses the boundary, as ``path:line: name``."""
    found = []  # type: list[str]
    for path in sorted(root.rglob('*.py')):
        source = path.read_text(encoding='utf-8')
        for line, name in imported_names(source, _module_name(path),
                                         is_package=path.name == '__init__.py'):
            if crosses_the_boundary(name):
                found.append(f'{path.relative_to(ROOT).as_posix()}:{line}: {name}')
    return found


class UtilitiesImportBoundaryTests(unittest.TestCase):
    """:mod:`pcapkit.utilities` stays below every other :mod:`pcapkit` package."""

    def test_the_walk_found_the_package(self) -> None:
        names = {path.name for path in UTILITIES.rglob('*.py')}
        self.assertIn('__init__.py', names)
        self.assertIn('exceptions.py', names)

    def test_no_module_imports_pcapkit_outside_utilities(self) -> None:
        found = violations()
        self.assertEqual(found, [],
                         'these modules under pcapkit/utilities/ import pcapkit from '
                         'outside pcapkit.utilities, which #1712 rules out at top level, '
                         'inside a function and under TYPE_CHECKING alike; a module that '
                         'needs them belongs in pcapkit.corekit:\n' + '\n'.join(found))

    def test_the_scanner_sees_every_form_of_import(self) -> None:
        source = '\n'.join([
            'from typing import TYPE_CHECKING',               # 1
            'import pcapkit.utilities.logging',               # 2
            'from pcapkit.utilities.compat import final',     # 3
            'from . import warnings',                         # 4
            'from pcapkit import utilities',                  # 5
            'if TYPE_CHECKING:',                              # 6
            '    from pcapkit.protocols.protocol import P',   # 7
            'def f():',                                       # 8
            '    from pcapkit.protocols.misc.raw import Raw', # 9
            '    import pcapkit.const',                       # 10
            '    from ..corekit import fields',               # 11
            '    from .. import protocols',                   # 12
            '    from pcapkit import __version__',            # 13
            '    importlib.import_module("pcapkit.foundation")',  # 14
            '    __import__("pcapkit.dumpkit")',              # 15
            'import pcapkit',                                 # 16
        ])
        crossing = [(line, name)
                    for line, name in imported_names(source, 'pcapkit.utilities.demo')
                    if crosses_the_boundary(name)]
        self.assertEqual(crossing, [
            (7, 'pcapkit.protocols.protocol'),
            (9, 'pcapkit.protocols.misc.raw'),
            (10, 'pcapkit.const'),
            (11, 'pcapkit.corekit'),
            (12, 'pcapkit.protocols'),
            (13, 'pcapkit.__version__'),
            (14, 'pcapkit.foundation'),
            (15, 'pcapkit.dumpkit'),
            (16, 'pcapkit'),
        ])

    def test_relative_imports_resolve_from_the_package_itself(self) -> None:
        source = 'from . import compat\nfrom .. import protocols\n'
        self.assertEqual(imported_names(source, PACKAGE, is_package=True),
                         [(1, 'pcapkit.utilities.compat'), (2, 'pcapkit.protocols')])


if __name__ == '__main__':
    unittest.main()
