# -*- coding: utf-8 -*-
"""No test class undoes its own per-class :mod:`pcapkit` import.

GitHub issue #1538. :func:`tests._support.reimport_once_per_class` (#1065) gives
a class one import of the package, shared by its tests: the first test purges,
and :func:`tests._support._keep_lazy_imports` -- a cleanup, so it runs *after*
``tearDown`` -- records what the test imported for the next one to reuse. A
``tearDown`` that also purges :mod:`pcapkit` empties :data:`sys.modules` before
that cleanup reads it, so the class keeps nothing and every test pays the full
re-import again (about 0.67s and 329 modules, by that helper's docstring) while
the ``setUp`` reads as if it did not.

A class that needs a fresh import for every test should say so by purging in
``setUp`` *instead of* calling :func:`~tests._support.reimport_once_per_class`,
as ``tests.const.test_const_enum_builtin_parity.ConstEnumRegisterFallbackTests``
does. That form is not matched here, and neither is a narrow purge of one
submodule, such as ``tests/toolkit/test_scapy_unit.py`` purging
``pcapkit.toolkit.scapy`` from a test body: only a purge of the whole package
discards the class's import.

A class's ``setUp`` and ``tearDown`` are looked up through its bases, both those
defined in its own module and those imported from another ``tests.*`` module, so
a test case that takes ``setUp`` from a shared mixin is checked too, and a
``super()`` call in either is followed to the next base's (#3165).

This module is unit-tier: it parses source and never imports the package.

"""
from __future__ import annotations

import ast
import pathlib
import shutil
import tempfile
import textwrap
import unittest
from typing import TYPE_CHECKING, NamedTuple
from unittest import mock

from tests import _sources
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
#: silently matches nothing cannot pass. It counted 384 under #1538.
MIN_CLASSES = 300

#: Fewest of those whose helper call is in another module, so that a lookup
#: across modules that silently resolves nothing cannot pass either (#3165).
MIN_ACROSS = 25


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


def _super_calls(method: 'ast.FunctionDef') -> 'list[int]':
    """Line numbers in ``method`` that call it on ``super()``: ``super().setUp()`` in ``setUp``."""
    return [node.lineno for node in ast.walk(method)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == method.name and isinstance(node.func.value, ast.Call)
            and _callee(node.func.value.func) == 'super']


class _Method(NamedTuple):
    """A ``setUp`` or ``tearDown``, reduced to the lines the scan reads."""

    #: Lines calling ``reimport_once_per_class``.
    helper: 'tuple[int, ...]'
    #: Lines purging, or registering a purge of, all of :mod:`pcapkit`.
    purges: 'tuple[int, ...]'
    #: Lines calling the next base's method through ``super()``.
    supers: 'tuple[int, ...]'


class _Class(NamedTuple):
    """A class statement, reduced to what the scan reads."""

    name: 'str'
    line: 'int'
    #: Each base that is a dotted name, split at the dots.
    bases: 'tuple[tuple[str, ...], ...]'
    #: Its own ``setUp`` and ``tearDown``, where it defines them.
    methods: 'dict[str, _Method]'


class _Module(NamedTuple):
    """A module's classes, and the names it binds by importing from ``tests``."""

    classes: 'dict[str, _Class]'
    #: Bound name -> the dotted name it was imported as.
    imports: 'dict[str, str]'


class _Count(NamedTuple):
    """:func:`scan` of one module."""

    #: Classes whose ``setUp`` calls ``reimport_once_per_class``.
    using: 'int'
    #: Those of them whose helper call is in another module.
    across: 'int'
    #: ``(class name, line)`` for each of them that also purges the package.
    offending: 'list[tuple[str, int]]'


def _in_tests(module: 'Optional[str]') -> bool:
    """Whether ``module`` is :mod:`tests` or one of its submodules."""
    return module is not None and (module == 'tests' or module.startswith('tests.'))


def _dotted(node: 'ast.AST') -> 'Optional[tuple[str, ...]]':
    """``('m', 'Mixin')`` for ``m.Mixin``, or ``None`` if ``node`` is not a dotted name."""
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, ast.Attribute):
        head = _dotted(node.value)
        return None if head is None else head + (node.attr,)
    return None


def _summarise(tree: 'ast.Module', _source: 'str') -> '_Module':
    """The classes of a module parsed as ``tree``, for :func:`tests._sources.parsed`."""
    classes, imports = {}, {}  # type: dict[str, _Class], dict[str, str]
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            methods = {}  # type: dict[str, _Method]
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name in ('setUp', 'tearDown'):
                    methods.setdefault(item.name, _Method(tuple(_helper_calls(item)), tuple(_whole_purges(item)),
                                                          tuple(_super_calls(item))))
            bases = tuple(name for name in map(_dotted, node.bases) if name is not None)
            classes[node.name] = _Class(node.name, node.lineno, bases, methods)
        elif isinstance(node, ast.ImportFrom) and not node.level and _in_tests(node.module):
            for alias in node.names:
                imports[alias.asname or alias.name] = f'{node.module}.{alias.name}'
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if _in_tests(alias.name):
                    # ``import tests.x as m`` binds ``m``; ``import tests.x`` binds ``tests``.
                    imports[alias.asname or 'tests'] = alias.name if alias.asname else 'tests'
    return _Module(classes, imports)


def _module(name: 'str') -> 'Optional[_Module]':
    """The checkout's ``tests.*`` module ``name``, if a file under :data:`ROOT` holds it."""
    if not _in_tests(name):
        return None
    base = ROOT.joinpath(*name.split('.'))
    for path in (base.with_name(f'{base.name}.py'), base / '__init__.py'):
        if path.is_file():
            return _sources.parsed(path, _summarise)
    return None


def _imported(target: 'str') -> 'Optional[tuple[str, _Module, _Class]]':
    """The module and class the dotted ``target`` names, through any module re-importing it."""
    seen = set()  # type: set[str]
    while target not in seen:
        seen.add(target)
        name, _, attr = target.rpartition('.')
        module = _module(name)
        if module is None:
            return None
        if attr in module.classes:
            return name, module, module.classes[attr]
        if attr not in module.imports:
            return None
        target = module.imports[attr]
    return None


def _defining(module: '_Module', cls: '_Class',
              method: 'str') -> 'Iterator[tuple[Optional[str], _Method]]':
    """Each ``method`` on ``cls`` and its bases, and the module defining it, ``None`` for ``module``.

    Looked up through the bases ``module`` defines, and those it imports from
    another ``tests.*`` module, where that module's bases are followed in turn.

    """
    # NOTE: breadth-first, which approximates the MRO; a base this module
    # defines wins over an imported name.
    seen = set()  # type: set[tuple[Optional[str], str]]
    queue = [(None, module, cls)]  # type: list[tuple[Optional[str], _Module, _Class]]
    while queue:
        where, home, current = queue.pop(0)
        if (where, current.name) in seen:
            continue
        seen.add((where, current.name))
        if method in current.methods:
            yield where, current.methods[method]
        for base in current.bases:
            if len(base) == 1 and base[0] in home.classes:
                queue.append((where, home, home.classes[base[0]]))
            elif base[0] in home.imports:
                found = _imported('.'.join((home.imports[base[0]],) + base[1:]))
                if found is not None:
                    queue.append(found)


def _resolve(module: '_Module', cls: '_Class', method: 'str') -> 'list[tuple[Optional[str], _Method]]':
    """``cls.method``, then each one a ``super()`` call in the last reaches, with its module."""
    chain = []  # type: list[tuple[Optional[str], _Method]]
    for found in _defining(module, cls, method):
        chain.append(found)
        if not found[1].supers:
            break
    return chain


def _in_order(chain: 'list[tuple[Optional[str], _Method]]') -> 'list[tuple[bool, Optional[str], int]]':
    """``(is a purge, module, line)`` for each helper call and purge of ``chain``, in the order they run.

    A method's lines before its first ``super()`` call run before the next
    method in ``chain``, and the rest after it.

    """
    if not chain:
        return []
    (where, method), rest = chain[0], chain[1:]
    # A purge on the helper's line counts as before it.
    ordered = sorted([(line, False) for line in method.purges] + [(line, True) for line in method.helper])
    events = [(not helper, where, line) for line, helper in ordered]
    if not rest:
        return events
    call = min(method.supers)
    return ([event for event in events if event[2] < call] + _in_order(rest)
            + [event for event in events if event[2] >= call])


def _count(module: '_Module') -> '_Count':
    """:func:`scan` of ``module``, with how many classes call the helper from elsewhere.

    A purge another module defines is reported at the class statement, the one
    line of this module that pairs it with the helper.

    """
    using, across, offending = 0, 0, []
    for cls in module.classes.values():
        set_up = _in_order(_resolve(module, cls, 'setUp'))
        calls = [index for index, (purge, _, _) in enumerate(set_up) if not purge]
        if not calls:
            continue
        using += 1
        across += set_up[calls[0]][1] is not None
        lines = [line if where is None else cls.line for purge, where, line in set_up[calls[0]:] if purge]
        for where, method in _resolve(module, cls, 'tearDown'):
            lines.extend(line if where is None else cls.line for line in method.purges)
        if lines:
            offending.append((cls.name, min(lines)))
    return _Count(using, across, offending)


def scan(source: str) -> 'tuple[int, list[tuple[str, int]]]':
    """Classes in ``source`` that call the helper, and those that also undo it.

    Args:
        source: Module source text. A base it imports from a ``tests.*``
            module is read from that module's file under :data:`ROOT`.

    Returns:
        The number of classes whose ``setUp`` calls ``reimport_once_per_class``,
        and ``(class name, line)`` for each of them that also purges the whole
        package -- anywhere in ``tearDown``, or in ``setUp`` after the call.

    """
    count = _count(_summarise(ast.parse(source), source))
    return count.using, count.offending


def _tree() -> 'Iterator[tuple[str, _Count]]':
    """:func:`_count` of every module under :data:`TESTS`, by path relative to :data:`ROOT`."""
    for path in sorted(TESTS.rglob('*.py')):
        yield path.relative_to(ROOT).as_posix(), _count(_sources.parsed(path, _summarise))


def scan_tree() -> 'tuple[int, dict[tuple[str, str], int]]':
    """:func:`scan` over every module under :data:`TESTS`, keyed by relative path."""
    using, found = 0, {}
    for relative, count in _tree():
        using += count.using
        for name, line in count.offending:
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

    def test_every_allowed_class_is_found_by_the_scan(self) -> None:
        _, found = scan_tree()
        self.assertEqual(sorted(key for key in ALLOWED if key not in found), [])

    def test_the_scan_follows_bases_across_modules(self) -> None:
        across = sum(count.across for _, count in _tree())
        self.assertGreaterEqual(across, MIN_ACROSS, 'the scan followed too few bases across modules')

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

    def test_super_calls_are_followed(self) -> None:
        """A ``setUp`` or ``tearDown`` calling ``super()`` runs the next base's too (#3165)."""
        base = 'class Base:\n    def setUp(self): reimport_once_per_class(self)\n'
        cases = {
            # label: (classes counted, classes flagged, source)
            'setUp through super()': (2, [], base + 'class T(Base):\n    def setUp(self): super().setUp()\n'),
            'purge after super().setUp()': (2, ['T'], base + textwrap.dedent('''
                class T(Base):
                    def setUp(self):
                        super().setUp()
                        purge_modules(['pcapkit'])
            ''')),
            'purge before super().setUp()': (2, [], base + textwrap.dedent('''
                class T(Base):
                    def setUp(self):
                        purge_modules(['pcapkit'])
                        super(T, self).setUp()
            ''')),
            'tearDown through super()': (1, ['T'], textwrap.dedent('''
                class Purge:
                    def tearDown(self): purge_modules(['pcapkit'])
                class T(Purge):
                    def setUp(self): reimport_once_per_class(self)
                    def tearDown(self): super().tearDown()
            ''')),
            'override without super()': (1, [], base + 'class T(Base):\n    def setUp(self): pass\n'),
        }
        for label, (counted, flagged, source) in cases.items():
            with self.subTest(case=label):
                using, offending = scan(source)
                self.assertEqual((using, [name for name, _ in offending]), (counted, flagged))


class CrossModuleBaseTests(unittest.TestCase):
    """A base imported from another ``tests.*`` module is followed (#3165).

    Each test writes its modules under a temporary :file:`tests/`, at which
    :data:`ROOT` and :data:`TESTS` are pointed.

    """

    #: ``(import statement, base)`` for each way a test module can import the mixin.
    FORMS = {
        'name from its module': ('from tests.shared._mixin import Mixin', 'Mixin'),
        'module alias': ('import tests.shared._mixin as shared', 'shared.Mixin'),
        'module from its package': ('from tests.shared import _mixin as shared', 'shared.Mixin'),
        'whole dotted path': ('import tests.shared._mixin', 'tests.shared._mixin.Mixin'),
        'name the package re-imports': ('from tests.shared import Mixin', 'Mixin'),
    }

    def setUp(self) -> None:
        root = pathlib.Path(tempfile.mkdtemp(prefix='pcapkit-3165-')).resolve()
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.shared = root / 'tests' / 'shared'
        self.shared.mkdir(parents=True)
        self._write('__init__.py', 'from tests.shared._mixin import Mixin\n')
        self._write('_mixin.py', 'class Mixin:\n    def setUp(self):\n        reimport_once_per_class(self)\n')
        patcher = mock.patch.dict(globals(), ROOT=root, TESTS=root / 'tests')
        patcher.start()
        self.addCleanup(patcher.stop)

    def _write(self, name: 'str', source: 'str') -> None:
        (self.shared / name).write_text(source, encoding='utf-8')

    def _concrete(self, form: 'str', body: 'str') -> None:
        """Write ``T``, a test case on the mixin imported as ``form``, its body on line 5."""
        statement, base = self.FORMS[form]
        self._write('test_concrete.py', f'{statement}\n\n\nclass T({base}, unittest.TestCase):\n{body}')

    def test_a_purge_undoing_an_imported_set_up_is_flagged(self) -> None:
        for form in self.FORMS:
            with self.subTest(form=form):
                self._concrete(form, "    def tearDown(self):\n        purge_modules(['pcapkit'])\n")
                self.assertEqual(scan_tree(), (2, {('tests/shared/test_concrete.py', 'T'): 6}))

    def test_an_imported_set_up_without_a_purge_is_counted(self) -> None:
        for form in self.FORMS:
            with self.subTest(form=form):
                self._concrete(form, '    def test(self):\n        pass\n')
                self.assertEqual(scan_tree(), (2, {}))

    def test_an_imported_purge_is_reported_at_the_class(self) -> None:
        """Its line is in another file, so the class pairing it with the helper stands in."""
        self._write('_purge.py', "class Purge:\n    def tearDown(self):\n        purge_modules(['pcapkit'])\n")
        self._write('test_concrete.py', 'from tests.shared._mixin import Mixin\n'
                                        'from tests.shared._purge import Purge\n\n\n'
                                        'class T(Mixin, Purge):\n    pass\n')
        self.assertEqual(scan_tree(), (2, {('tests/shared/test_concrete.py', 'T'): 5}))

    def test_super_set_up_over_an_imported_mixin_is_followed(self) -> None:
        self._concrete('name from its module', '    def setUp(self):\n        super().setUp()\n'
                                               "    def tearDown(self):\n        purge_modules(['pcapkit'])\n")
        self.assertEqual(scan_tree(), (2, {('tests/shared/test_concrete.py', 'T'): 8}))

    def test_a_base_from_a_module_not_on_disk_is_not_followed(self) -> None:
        self._write('test_concrete.py', 'from tests.shared._absent import Mixin\n\n\n'
                                        'class T(Mixin):\n    pass\n')
        self.assertEqual(scan_tree(), (1, {}))


if __name__ == '__main__':
    unittest.main()
