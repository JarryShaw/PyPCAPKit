# -*- coding: utf-8 -*-
"""Class annotations resolve from module scope, as autodoc resolves them (#1857).

Autodoc reads a class's annotations out of its *source*, including the ones under
a class-level ``if TYPE_CHECKING:`` that never runs, copies them into
``__annotations__``, and evaluates them with ``typing.get_type_hints(cls, None,
{})``. That is the module's globals with an empty local namespace, so neither the
class body nor a class-level guarded import is in scope. :file:`docs/source/conf.py`
binds the names of each module's *module-level* ``if TYPE_CHECKING:`` block first,
but not those of a class-level one. A ``__flags__: 'Flags'`` naming a nested class
bare, or an engine's ``_expkg`` naming a module imported only inside the class
guard, raises :exc:`NameError`, which fails the whole class: #1857 found autodoc
rendering every annotation of ``FrameType``, its frame schemas and the third-party
engines as raw strings.

This module makes the same evaluation without Sphinx:

* each module-level guard is run one statement at a time, as
  ``sphinx-autodoc-typehints`` runs it, but into a *copy* of the module's
  namespace, so no module is mutated;
* the class annotations are gathered from source the way :mod:`sphinx.pycode`
  gathers them: the class body, including ``if`` and ``try`` bodies, plus the
  annotated assignments in ``__init__``;
* each annotation is evaluated with :func:`typing.get_type_hints` against that
  namespace and an empty local one, for the class and for every ``pcapkit`` base
  in its MRO, since autodoc evaluates those too.

A guarded import of a package outside :mod:`pcapkit` that is not already loaded is
never run. Its names are bound to placeholders instead, which is what
``autodoc_mock_imports`` would do, so the result does not depend on which optional
engines a leg installs and the check imports none of them.

Only :exc:`NameError` and :exc:`AttributeError` are findings: an unbound name, or
a qualified one missing from the object it is looked up on. Python 3.8 and 3.9
cannot evaluate ``X | Y``, and that :exc:`TypeError` says nothing about scope.

This module is unit-tier: it reads source and imports no optional dependency.

"""
from __future__ import annotations

import ast
import importlib
import importlib.util
import pathlib
import sys
import tempfile
import textwrap
import typing
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from types import ModuleType
    from typing import Any, Iterator, Optional

#: Test tier (#1958): resolves annotations as the docs build does, which runs on one
#: interpreter.
__tier__ = 'LATEST'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Module-level guards the documentation build runs. ``TYPE_CHECKING`` is run by
#: :file:`docs/source/conf.py`, and ``SPHINX_TYPE_CHECKING`` at import time, since
#: the build sets ``PCAPKIT_SPHINX``.
GUARDS = frozenset({'TYPE_CHECKING', 'SPHINX_TYPE_CHECKING'})

#: Modules whose classes are checked, each with the classes #1857 reported there.
#: Every class a module defines at top level is checked; the listed ones must be
#: among them, so that a rename cannot quietly shrink the check.
MODULES = {
    'pcapkit.protocols.schema.application.httpv2': ('FrameType', 'RSTStreamFrame', 'GoawayFrame'),
    'pcapkit.foundation.engines.dpkt': ('DPKT',),
    'pcapkit.foundation.engines.scapy': ('Scapy',),
    'pcapkit.foundation.engines.pyshark': ('PyShark',),
    'pcapkit.foundation.engines.pypcap': ('PyPCAP',),
    'pcapkit.foundation.engines.pcap_ct': ('PCAP_CT',),
    'pcapkit.foundation.engines.pypcapfile': ('PyPCAPFile',),
}

#: Engine packages, none of which the check may import.
ENGINE_PACKAGES = ('dpkt', 'scapy', 'pyshark', 'pcap', 'pcapfile')


class Placeholder:
    """Stands in for a name whose guarded import is not run."""

    def __class_getitem__(cls, item: 'Any') -> 'type':
        return cls


def _is_guard(test: 'ast.expr') -> bool:
    """Whether an ``if`` test is one of :data:`GUARDS`, bare or as ``typing.X``."""
    if isinstance(test, ast.Name):
        return test.id in GUARDS
    return isinstance(test, ast.Attribute) and test.attr in GUARDS


def _defined_names(statement: 'ast.stmt') -> 'Iterator[str]':
    """The names ``statement`` binds in the namespace it runs in."""
    if isinstance(statement, (ast.Import, ast.ImportFrom)):
        for alias in statement.names:
            if alias.name != '*':
                yield alias.asname or alias.name.split('.')[0]
    elif isinstance(statement, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
        yield statement.name
    else:
        for node in ast.walk(statement):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                yield node.id


def _loads_a_new_package(statement: 'ast.stmt', package: str) -> bool:
    """Whether running ``statement`` would import a package not yet loaded."""
    if isinstance(statement, ast.Import):
        modules = [alias.name for alias in statement.names]
    elif isinstance(statement, ast.ImportFrom) and not statement.level and statement.module:
        modules = [statement.module]
    else:
        return False
    tops = {name.split('.')[0] for name in modules}
    return any(top != package and top not in sys.modules for top in tops)


def guarded_namespace(module: 'ModuleType', package: str = 'pcapkit') -> 'dict[str, Any]':
    """A copy of ``module``'s namespace with its module-level guards run.

    Args:
        module: Module whose namespace is copied.
        package: Top-level package whose own imports are always run.

    Returns:
        The namespace the documentation build evaluates the module's annotations
        in.

    """
    namespace = dict(vars(module))
    filename = str(module.__file__)
    tree = ast.parse(pathlib.Path(filename).read_text(encoding='utf-8'), filename=filename)
    for node in tree.body:
        if not (isinstance(node, ast.If) and _is_guard(node.test)):
            continue
        for statement in node.body:
            if not _loads_a_new_package(statement, package):
                try:
                    code = compile(ast.Module(body=[statement], type_ignores=[]), filename, 'exec')
                    exec(code, namespace)  # pylint: disable=exec-used
                    continue
                except Exception:  # pylint: disable=broad-except
                    pass
            for name in _defined_names(statement):
                namespace.setdefault(name, type(name, (Placeholder,), {}))
    return namespace


def _class_nodes(tree: 'ast.Module') -> 'dict[str, ast.ClassDef]':
    """Every class statement in ``tree`` outside a function, by qualified name."""
    found = {}  # type: dict[str, ast.ClassDef]

    def visit(body: 'list[ast.stmt]', prefix: str) -> None:
        for statement in body:
            if isinstance(statement, ast.ClassDef):
                found.setdefault(prefix + statement.name, statement)
                visit(statement.body, f'{prefix}{statement.name}.')
            elif isinstance(statement, (ast.If, ast.Try, ast.With, ast.For, ast.While)):
                visit(statement.body, prefix)
                visit(getattr(statement, 'orelse', []), prefix)

    visit(tree.body, '')
    return found


def _annotations_in(body: 'list[ast.stmt]',
                    self_name: 'Optional[str]' = None) -> 'Iterator[tuple[str, ast.expr]]':
    """``(attribute, annotation)`` pairs :mod:`sphinx.pycode` records for a class.

    Args:
        body: Class body, or the body of its ``__init__``.
        self_name: Name of ``__init__``'s first parameter when ``body`` is its
            body, else :data:`None`.

    Yields:
        Each annotated attribute with its annotation node.

    """
    for statement in body:
        if isinstance(statement, ast.AnnAssign):
            target = statement.target
            if isinstance(target, ast.Name):
                yield target.id, statement.annotation
            elif (self_name is not None and isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name) and target.value.id == self_name):
                yield target.attr, statement.annotation
        elif isinstance(statement, (ast.If, ast.With, ast.For, ast.While)):
            yield from _annotations_in(statement.body, self_name)
            yield from _annotations_in(getattr(statement, 'orelse', []), self_name)
        elif isinstance(statement, ast.Try):
            yield from _annotations_in(statement.body, self_name)
            yield from _annotations_in(statement.orelse, self_name)
        elif (self_name is None and isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
                and statement.name == '__init__'):
            arguments = statement.args.args or statement.args.posonlyargs
            if arguments:
                yield from _annotations_in(statement.body, arguments[0].arg)


def class_annotations(cls: type) -> 'list[tuple[str, str]]':
    """``(attribute, annotation)`` pairs autodoc evaluates for ``cls`` itself.

    Args:
        cls: Class whose own source-level annotations are collected.

    Returns:
        Each attribute with its annotation, a quoted annotation unquoted.

    """
    module = sys.modules[cls.__module__]
    source = pathlib.Path(str(module.__file__)).read_text(encoding='utf-8')
    node = _class_nodes(ast.parse(source))[cls.__qualname__]
    pairs = []
    for attribute, annotation in _annotations_in(node.body):
        if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
            text = annotation.value
        else:
            text = ast.get_source_segment(source, annotation) or ''
        pairs.append((attribute, text))
    return pairs


def unresolved_annotations(classes: 'list[type]', package: str = 'pcapkit') -> 'list[str]':
    """Every annotation of ``classes`` and their ``package`` bases autodoc cannot resolve.

    Args:
        classes: Classes to check.
        package: Top-level package whose bases in each MRO are checked as well.

    Returns:
        ``module.Class.attribute: 'annotation' -> error`` strings, sorted, naming the
        class that declares the annotation.

    """
    namespaces = {}  # type: dict[str, dict[str, Any]]
    findings = set()
    for cls in classes:
        for base in cls.__mro__:
            modname = base.__module__
            if modname != package and not modname.startswith(f'{package}.'):
                continue
            if modname not in namespaces:
                namespaces[modname] = guarded_namespace(sys.modules[modname], package)
            for attribute, annotation in class_annotations(base):
                probe = type('Probe', (), {'__annotations__': {attribute: annotation}})
                try:
                    typing.get_type_hints(probe, namespaces[modname], {})
                except (NameError, AttributeError) as error:
                    findings.add(f'{modname}.{base.__qualname__}.{attribute}: {annotation!r}'
                                 f' -> {type(error).__name__}: {error}')
                except Exception:  # pylint: disable=broad-except
                    continue
    return sorted(findings)


def checked_classes() -> 'dict[str, list[type]]':
    """The classes each of :data:`MODULES` defines at top level, by module name."""
    classes = {}
    for modname in MODULES:
        module = importlib.import_module(modname)
        classes[modname] = [value for value in vars(module).values()
                            if isinstance(value, type) and value.__module__ == modname]
    return classes


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ClassGuardAnnotationTests(unittest.TestCase):
    """Annotations of the #1857 classes resolve as autodoc evaluates them."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_class_annotations_resolve_from_module_scope(self) -> None:
        classes = [cls for found in checked_classes().values() for cls in found]

        unresolved = unresolved_annotations(classes)

        self.assertEqual(
            unresolved, [],
            'these class annotations name something the module does not bind, even with '
            'its module-level TYPE_CHECKING block run, so autodoc shows the raw string for '
            'every annotation of the class; qualify a nested class through its outer '
            'class, and import in the module-level guard rather than the class-level one '
            '(#1857):\n  ' + '\n  '.join(unresolved))

    def test_the_reported_classes_and_annotations_are_checked(self) -> None:
        """The check reaches the classes and the guarded annotations of the report.

        Every annotation #1857 found sits under a class-level ``if TYPE_CHECKING:``.
        A collector that skipped ``if`` bodies, or a class list that lost one of
        these, would pass the test above without checking anything that failed.

        """
        classes = checked_classes()
        for modname, names in MODULES.items():
            checked = {cls.__name__ for cls in classes[modname]}
            for name in names:
                with self.subTest(module=modname, cls=name):
                    self.assertIn(name, checked)

        from pcapkit.protocols.schema.application.httpv2 import FrameType  # pylint: disable=import-outside-toplevel
        self.assertIn('__flags__', dict(class_annotations(FrameType)))
        for modname, names in MODULES.items():
            if modname.startswith('pcapkit.foundation.engines.'):
                engine = getattr(sys.modules[modname], names[0])
                with self.subTest(engine=engine.__name__):
                    self.assertIn('_expkg', dict(class_annotations(engine)))

    def test_the_check_imports_no_engine_package(self) -> None:
        """The engines are optional and lazy, so the check must not load them."""
        before = {name for name in ENGINE_PACKAGES if name in sys.modules}

        unresolved_annotations([cls for found in checked_classes().values() for cls in found])

        after = {name for name in ENGINE_PACKAGES if name in sys.modules}
        self.assertEqual(after - before, set())


class PlantedDefectTests(unittest.TestCase):
    """A guard that cannot fail is not a guard.

    The defect shapes of #1857 are planted in a scratch module, beside the
    spellings that fix them, and only the defects may be reported.

    """

    SOURCE = textwrap.dedent('''\
        from typing import TYPE_CHECKING

        if TYPE_CHECKING:
            from types import ModuleType
            from typing import Optional

            from planted_absent_engine import Handle


        class Planted:
            if TYPE_CHECKING:
                import json

                class_guard_only: 'json'
                module_guard: 'ModuleType'
                absent_engine: 'Optional[Handle]'
                nested_bare: 'Nested'
                nested_qualified: 'Planted.Nested'
                nested_misspelt: 'Planted.Nestde'

            class Nested:
                pass

            def __init__(self) -> None:
                self.in_init: 'NeverImported' = None
    ''')

    def test_only_the_planted_defects_are_reported(self) -> None:
        name = '_planted_1857'
        with tempfile.TemporaryDirectory() as scratch:
            path = pathlib.Path(scratch) / f'{name}.py'
            path.write_text(self.SOURCE, encoding='utf-8')
            spec = importlib.util.spec_from_file_location(name, path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            self.addCleanup(sys.modules.pop, name, None)
            spec.loader.exec_module(module)

            findings = unresolved_annotations([module.Planted], package=name)

        reported = sorted(finding.split(':', 1)[0].rsplit('.', 1)[1] for finding in findings)
        self.assertEqual(reported, ['class_guard_only', 'in_init', 'nested_bare', 'nested_misspelt'],
                         findings)
        self.assertNotIn('planted_absent_engine', sys.modules)


if __name__ == '__main__':
    unittest.main()
