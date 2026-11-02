# -*- coding: utf-8 -*-
"""A context variable crosses modules only from :mod:`pcapkit.utilities.contextvars`.

GitHub issue #2616 settled where a :class:`~contextvars.ContextVar` lives: one
that more than one module sets or reads goes in
:mod:`pcapkit.utilities.contextvars`, under a public name in its ``__all__``,
and one that only its own module uses stays there. So this module fails when a
module under :file:`pcapkit/` imports a name bound to a ``ContextVar`` in another
:mod:`pcapkit` module, other than :mod:`pcapkit.utilities.contextvars`. That
covers an import at top level, inside a function and under ``TYPE_CHECKING``,
``from X import name`` and ``X.name`` on an imported module alike, and a name
another module re-binds by importing it. It fails as well on a variable there
that is private, missing from ``__all__``, or read by one module alone.

Each module is read with :mod:`ast` rather than imported, as
:mod:`tests.project.test_utilities_import_boundary_1735_unit` reads them. The
rule is written down on
:file:`docs/source/contributing/conventions/utilities-or-corekit.rst`.

This module is unit-tier and reads no capture.

"""
from __future__ import annotations

import ast
import collections
import unittest
from typing import TYPE_CHECKING, NamedTuple

from tests.project.test_utilities_import_boundary_1735_unit import (ROOT, _module_name,
                                                                    _relative_base)

if TYPE_CHECKING:
    from typing import ClassVar, Iterator

#: The package the rule governs.
PCAPKIT = ROOT / 'pcapkit'

#: The one module a context variable may be imported from.
HOME = 'pcapkit.utilities.contextvars'


class Module(NamedTuple):
    """A parsed source file."""

    #: Its syntax tree.
    tree: 'ast.Module'
    #: Whether it is a package's :file:`__init__.py`.
    is_package: 'bool'
    #: Its path, as a violation names it.
    path: 'str'


class Reference(NamedTuple):
    """One module's use of a context variable bound in another."""

    #: The module that uses it.
    reader: 'str'
    #: The line it is used on.
    line: 'int'
    #: The module it is taken from.
    source: 'str'
    #: Its name there.
    name: 'str'


def parse_tree() -> 'dict[str, Module]':
    """Every module under :data:`PCAPKIT`, by dotted name."""
    return {_module_name(path): Module(ast.parse(path.read_text(encoding='utf-8')),
                                       path.name == '__init__.py',
                                       path.relative_to(ROOT).as_posix())
            for path in sorted(PCAPKIT.rglob('*.py'))}


def _module_level(tree: 'ast.Module') -> 'Iterator[ast.AST]':
    """Statements that bind module-level names, inside ``if``, ``try`` and ``with`` too."""
    stack = list(tree.body)  # type: list[ast.AST]
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield node
        stack.extend(child for child in ast.iter_child_nodes(node)
                     if isinstance(child, (ast.stmt, ast.excepthandler)))


def _is_contextvar(node: 'ast.AST | None') -> 'bool':
    """Whether ``node`` calls ``ContextVar``, bare, as an attribute or subscripted."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func.value if isinstance(node.func, ast.Subscript) else node.func
    return (func.attr if isinstance(func, ast.Attribute) else getattr(func, 'id', None)) == 'ContextVar'


def _target(node: 'ast.ImportFrom', module: 'str', is_package: 'bool') -> 'str':
    """The module a ``from`` import reads from, with relative imports resolved."""
    if not node.level:
        return node.module or ''
    base = _relative_base(module, is_package, node.level)
    return f'{base}.{node.module}' if node.module else base


def bound_names(modules: 'dict[str, Module]') -> 'dict[str, set[str]]':
    """The module-level names each module binds to a context variable.

    A name is bound by assigning ``ContextVar(...)`` to it, or by importing a
    name another module binds, which is how a re-export would hand one on.

    """
    bound = {name: set() for name in modules}  # type: dict[str, set[str]]
    for name, module in modules.items():
        for node in _module_level(module.tree):
            if isinstance(node, ast.Assign) and _is_contextvar(node.value):
                bound[name].update(target.id for target in node.targets if isinstance(target, ast.Name))
            elif (isinstance(node, ast.AnnAssign) and _is_contextvar(node.value)
                    and isinstance(node.target, ast.Name)):
                bound[name].add(node.target.id)
    changed = True
    while changed:
        changed = False
        for name, module in modules.items():
            for node in _module_level(module.tree):
                if not isinstance(node, ast.ImportFrom):
                    continue
                source = _target(node, name, module.is_package)
                for alias in node.names:
                    local = alias.asname or alias.name
                    if alias.name in bound.get(source, ()) and local not in bound[name]:
                        bound[name].add(local)
                        changed = True
    return bound


def _dotted(node: 'ast.AST', aliases: 'dict[str, str]') -> 'str | None':
    """The dotted name ``node`` spells, its first part resolved through ``aliases``."""
    parts = []  # type: list[str]
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name) or node.id not in aliases:
        return None
    return '.'.join([aliases[node.id]] + parts[::-1])


def references(modules: 'dict[str, Module]', bound: 'dict[str, set[str]]') -> 'list[Reference]':
    """Every use of a context variable another module binds, in module and line order."""
    found = []  # type: list[Reference]
    for name, module in modules.items():
        aliases = {}  # type: dict[str, str]
        nodes = sorted((node for node in ast.walk(module.tree) if hasattr(node, 'lineno')),
                       key=lambda node: (getattr(node, 'lineno'), getattr(node, 'col_offset')))
        for node in nodes:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        aliases[alias.asname] = alias.name
                    else:
                        aliases[alias.name.split('.')[0]] = alias.name.split('.')[0]
            elif isinstance(node, ast.ImportFrom):
                source = _target(node, name, module.is_package)
                for alias in node.names:
                    aliases[alias.asname or alias.name] = f'{source}.{alias.name}'
                    if alias.name in bound.get(source, ()) and source != name:
                        found.append(Reference(name, node.lineno, source, alias.name))
            elif isinstance(node, ast.Attribute):
                owner = _dotted(node.value, aliases)
                if owner is not None and node.attr in bound.get(owner, ()) and owner != name:
                    found.append(Reference(name, node.lineno, owner, node.attr))
    return found


def violations(modules: 'dict[str, Module]') -> 'list[str]':
    """Every context variable taken from a module other than :data:`HOME`, as ``path:line: name``."""
    return [f'{modules[ref.reader].path}:{ref.line}: {ref.source}.{ref.name}'
            for ref in references(modules, bound_names(modules)) if ref.source != HOME]


def _exported(tree: 'ast.Module') -> 'set[str]':
    """The names a module's literal ``__all__`` lists."""
    for node in tree.body:
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.List)
                and any(isinstance(target, ast.Name) and target.id == '__all__' for target in node.targets)):
            return {item.value for item in node.value.elts
                    if isinstance(item, ast.Constant) and isinstance(item.value, str)}
    return set()


class SharedContextVarsTests(unittest.TestCase):
    """Context variables are shared through :mod:`pcapkit.utilities.contextvars` alone."""

    #: Every module under :data:`PCAPKIT`.
    modules: 'ClassVar[dict[str, Module]]'
    #: The names each of them binds to a context variable.
    bound: 'ClassVar[dict[str, set[str]]]'

    @classmethod
    def setUpClass(cls) -> None:
        cls.modules = parse_tree()
        cls.bound = bound_names(cls.modules)

    def test_the_walk_found_the_variables(self) -> None:
        self.assertTrue(self.bound[HOME])
        self.assertTrue(any(names for name, names in self.bound.items() if name != HOME),
                        'the walk found no context variable outside pcapkit.utilities.contextvars')

    def test_no_module_imports_a_context_variable_from_elsewhere(self) -> None:
        found = violations(self.modules)
        self.assertEqual(found, [],
                         'these modules under pcapkit/ take a context variable from a module other '
                         'than pcapkit.utilities.contextvars, which #2616 rules out; move a shared '
                         'one there under a public name, with no re-export at its old path:\n'
                         + '\n'.join(found))

    def test_every_shared_variable_is_public_and_exported(self) -> None:
        names = self.bound[HOME]
        self.assertEqual(sorted(names), sorted(_exported(self.modules[HOME].tree)))
        self.assertEqual([name for name in sorted(names) if name.startswith('_')], [])

    def test_every_shared_variable_has_more_than_one_reader(self) -> None:
        readers = collections.defaultdict(set)  # type: collections.defaultdict[str, set[str]]
        for ref in references(self.modules, self.bound):
            if ref.source == HOME:
                readers[ref.name].add(ref.reader)
        lonely = {name: sorted(readers[name]) for name in sorted(self.bound[HOME]) if len(readers[name]) < 2}
        self.assertEqual(lonely, {},
                         'these context variables in pcapkit.utilities.contextvars have at most one '
                         'reader, so #2616 puts each back in that module under a private name')

    def test_the_scanner_sees_every_form_of_import(self) -> None:
        sources = {
            HOME: "import contextvars\nshared = contextvars.ContextVar('shared', default=0)\n",
            'pcapkit.owner': '\n'.join([
                'import contextvars',
                'from contextvars import ContextVar',
                'from pcapkit.utilities.contextvars import shared',
                "_private = contextvars.ContextVar('_private', default=0)",
                "_annotated: 'ContextVar[int]' = ContextVar('_annotated', default=0)",
                "if True:\n    _nested = ContextVar[int]('_nested', default=0)",
                'def f():',
                "    _local = ContextVar('_local', default=0)",
                '    return _private.get()',
            ]),
            'pcapkit.pkg.reader': '\n'.join([
                'from typing import TYPE_CHECKING',                       # 1
                'from pcapkit.utilities.contextvars import shared',       # 2
                'from pcapkit.utilities import contextvars',              # 3
                'from pcapkit.owner import _private',                     # 4
                'import pcapkit.owner',                                   # 5
                'from pcapkit import owner as alias',                     # 6
                'if TYPE_CHECKING:',                                      # 7
                '    from pcapkit.owner import _annotated',               # 8
                'def f():',                                               # 9
                '    from pcapkit.owner import shared as again',          # 10
                '    from .. import owner',                               # 11
                '    return (contextvars.shared, pcapkit.owner._nested,',  # 12
                '            alias._annotated, owner._private, owner.f)',  # 13
            ]),
        }
        modules = {name: Module(ast.parse(source), False, name) for name, source in sources.items()}
        bound = bound_names(modules)
        self.assertEqual(bound['pcapkit.owner'], {'shared', '_private', '_annotated', '_nested'})
        self.assertEqual(violations(modules), [
            'pcapkit.pkg.reader:4: pcapkit.owner._private',
            'pcapkit.pkg.reader:8: pcapkit.owner._annotated',
            'pcapkit.pkg.reader:10: pcapkit.owner.shared',
            'pcapkit.pkg.reader:12: pcapkit.owner._nested',
            'pcapkit.pkg.reader:13: pcapkit.owner._annotated',
            'pcapkit.pkg.reader:13: pcapkit.owner._private',
        ])
        self.assertEqual(sorted({ref.reader for ref in references(modules, bound) if ref.source == HOME}),
                         ['pcapkit.owner', 'pcapkit.pkg.reader'])


if __name__ == '__main__':
    unittest.main()
