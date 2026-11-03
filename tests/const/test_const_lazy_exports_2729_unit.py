# -*- coding: utf-8 -*-
"""Every :mod:`pcapkit.const` package exports what it did eagerly (GitHub issue #2729).

Each package under :mod:`pcapkit.const` imports its enumerations on first use,
through :func:`pcapkit.utilities.importlib.lazy_exports`, and names them only under
:data:`~typing.TYPE_CHECKING`, for the type checkers. These sweeps read the
packages off the tree, so a package the crawlers add is held to them the day it
lands, and hold every one to the eager behaviour that statement describes:

* every name in its ``__all__`` is named by an import under ``TYPE_CHECKING``,
  bar the ones :data:`EAGER` lists, and resolves to the very object that import
  names, or to the subpackage's for a star import;
* ``from <package> import *`` binds every one of them;
* :func:`dir` lists what the eager import bound -- the names the import system
  sets, ``__all__``, and the submodules -- and none of the helpers;
* every member of every exported enumeration survives :mod:`pickle` as itself.

What a cold import loads, and when, is
:mod:`tests.const.test_const_apptype_lazy_1538_unit`'s.

"""

import ast
import importlib
import importlib.util
import pathlib
import pickle
import types
import unittest
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): exercises the import system and pickling, which differ between interpreters.
__tier__ = 'ALL'

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The names a :mod:`pcapkit.const` package imports with itself, keyed by package,
#: and why: the app-type package binds ``__registries__`` on the memberless base, so
#: it needs both at once.
EAGER = {'pcapkit.const.reg.apptype': {'AppType', 'TransportProtocol'}}

#: Every package of :mod:`pcapkit.const`, read off the tree.
PACKAGES = sorted('.'.join(path.relative_to(ROOT).parent.parts)
                  for path in (ROOT / 'pcapkit' / 'const').rglob('__init__.py'))


def init_path(package: 'str') -> 'pathlib.Path':
    """The ``__init__.py`` of ``package``."""
    return ROOT.joinpath(*package.split('.'), '__init__.py')


def declared(package: 'str') -> 'dict[str, tuple[str, str, bool]]':
    """What the ``__init__.py`` of ``package`` imports at module level, ``TYPE_CHECKING`` included.

    Each bound name maps to the module it is imported from, its name there, and
    whether the import is under ``TYPE_CHECKING``; a star import maps each name
    its module's ``__all__`` lists to that module and the same name.

    """
    names = {}  # type: dict[str, tuple[str, str, bool]]

    def visit(body: 'list[ast.stmt]', typing_only: 'bool') -> 'None':
        for node in body:
            if isinstance(node, ast.If):
                guarded = isinstance(node.test, ast.Name) and node.test.id == 'TYPE_CHECKING'
                visit(node.body, typing_only or guarded)
                visit(node.orelse, typing_only)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                for alias in node.names:
                    if alias.name == '*':
                        source = importlib.import_module(node.module)
                        names.update((name, (node.module, name, typing_only)) for name in source.__all__)
                    else:
                        names[alias.asname or alias.name] = (node.module, alias.name, typing_only)

    visit(ast.parse(init_path(package).read_text(encoding='utf-8')).body, False)
    return names


def import_system_names(module: 'types.ModuleType') -> 'set[str]':
    """The names importing ``module`` would leave in it, were its body empty."""
    fresh = importlib.util.module_from_spec(module.__spec__)  # type: ignore[arg-type]
    exec('', vars(fresh))  # pylint: disable=exec-used
    return set(dir(fresh))


def exported_enumerations() -> 'list[type]':
    """Every class a :mod:`pcapkit.const` package exports, each once."""
    found = {}  # type: dict[int, type]
    for package in PACKAGES:
        module = importlib.import_module(package)
        for name in module.__all__:
            value = getattr(module, name)
            if isinstance(value, type):
                found.setdefault(id(value), value)
    return list(found.values())


class LazyExportSweepTests(unittest.TestCase):
    """Each :mod:`pcapkit.const` package, as an eager import of it would leave it."""

    def test_the_sweep_found_the_packages(self) -> 'None':
        """An empty walk would let every loop below pass without checking a package."""
        self.assertIn('pcapkit.const', PACKAGES)
        self.assertIn('pcapkit.const.reg.apptype', PACKAGES)
        self.assertIn('pcapkit.const.tcp', PACKAGES)

    def test_every_name_in_all_resolves_to_what_its_import_names(self) -> 'None':
        for package in PACKAGES:
            module = importlib.import_module(package)
            imports = declared(package)
            with self.subTest(package=package):
                self.assertTrue(module.__all__)
                self.assertEqual([name for name in module.__all__ if name not in imports], [],
                                 'name each export in an import under TYPE_CHECKING')
                eager = sorted(name for name in module.__all__ if not imports[name][2])
                self.assertEqual(eager, sorted(EAGER.get(package, ())),
                                 'import each export under TYPE_CHECKING alone, so that it loads on first use')
                for name in module.__all__:
                    source, attribute, _ = imports[name]
                    self.assertIs(getattr(module, name), getattr(importlib.import_module(source), attribute),
                                  f'{package}.{name}')

    def test_star_import_binds_every_name(self) -> 'None':
        for package in PACKAGES:
            module = importlib.import_module(package)
            namespace = {}  # type: dict[str, Any]
            exec(f'from {package} import *', namespace)  # pylint: disable=exec-used
            namespace.pop('__builtins__')
            with self.subTest(package=package):
                self.assertEqual(sorted(namespace), sorted(module.__all__))
                for name, value in namespace.items():
                    self.assertIs(value, getattr(module, name))

    def test_dir_lists_what_an_eager_import_bound(self) -> 'None':
        # NOTE: the eager import bound every submodule its imports name, and any
        # other one already imported; the first are listed whether imported or
        # not, as they are not on a cold import.
        for package in PACKAGES:
            module = importlib.import_module(package)
            named = {source[len(package) + 1:].split('.')[0] for (source, _, _) in declared(package).values()
                     if source.startswith(f'{package}.')}
            submodules = named | {name for (name, value) in vars(module).items()
                                  if isinstance(value, types.ModuleType) and value.__name__ == f'{package}.{name}'}
            with self.subTest(package=package):
                self.assertTrue(named)
                self.assertEqual(dir(module), sorted({*import_system_names(module), '__all__', *module.__all__,
                                                      *submodules}))
                for helper in ('TYPE_CHECKING', 'lazy_exports', '__getattr__', '__dir__'):
                    self.assertIn(helper, vars(module))
                    self.assertNotIn(helper, dir(module))

    def test_every_member_pickles_as_itself(self) -> 'None':
        enumerations = exported_enumerations()
        self.assertGreater(len(enumerations), 100, 'the sweep found implausibly few enumerations')
        for enumeration in enumerations:
            members = list(enumeration)
            if not members:
                continue
            with self.subTest(enumeration=f'{enumeration.__module__}.{enumeration.__qualname__}'):
                for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
                    self.assertIs(pickle.loads(pickle.dumps(members[0], protocol)), members[0])


if __name__ == '__main__':
    unittest.main()
