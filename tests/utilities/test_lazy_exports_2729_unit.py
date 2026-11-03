# -*- coding: utf-8 -*-
""":func:`pcapkit.utilities.lazy.lazy_exports`, on packages written for the test (GitHub issue #2729).

Every :mod:`pcapkit.const` package uses it, and
:mod:`tests.const.test_const_lazy_exports_2729_unit` sweeps those. Here it runs
on a package tree written to a temporary directory, so each test starts with
nothing imported and can count what every step imports.

"""

import importlib
import pathlib
import sys
import tempfile
import textwrap
import types
import unittest
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): exercises the import system and pickling, which differ between interpreters.
__tier__ = 'ALL'

#: The top-level name of the package tree, unique to this module.
NAME = '_lazy_exports_2729_probe'

#: The package tree, as path to source. ``probe`` exports two names from
#: ``things`` and one from its subpackage ``sub``; the top-level package
#: re-exports ``probe``'s ``__all__``, as :mod:`pcapkit.const` does its
#: subpackages', and records each module the tree imports in ``imported``.
TREE = {
    '__init__.py': '''
        from pcapkit.utilities.lazy import lazy_exports

        imported = []

        __all__ = ['Thing', 'Other', 'Deep']

        __getattr__, __dir__ = lazy_exports(__name__, globals(), packages=('probe',))
    ''',
    'probe/__init__.py': '''
        from typing import TYPE_CHECKING

        from pcapkit.utilities.lazy import lazy_exports

        if TYPE_CHECKING:
            from {NAME}.probe.sub import Deep
            from {NAME}.probe.things import Other, Thing

        __all__ = ['Thing', 'Other', 'Deep']

        _private = 'a helper of the package'

        __getattr__, __dir__ = lazy_exports(__name__, globals(), {{
            'Thing': ('things', 'Thing'),
            'Other': ('things', 'Renamed'),
            'Deep': ('sub', 'Deep'),
        }})
    ''',
    'probe/things.py': '''
        import sys

        sys.modules[{NAME!r}].imported.append(__name__)


        class Thing:
            pass


        class Renamed:
            pass
    ''',
    'probe/extra.py': '''
        VALUE = 1
    ''',
    'probe/sub/__init__.py': '''
        from pcapkit.utilities.lazy import lazy_exports

        __all__ = ['Deep']

        __getattr__, __dir__ = lazy_exports(__name__, globals(), {{'Deep': ('deep', 'Deep')}})
    ''',
    'probe/sub/deep.py': '''
        import sys

        sys.modules[{NAME!r}].imported.append(__name__)


        class Deep:
            pass
    ''',
}


class LazyExportsTests(unittest.TestCase):
    """The two hooks, from a cold import of the package tree."""

    def setUp(self) -> 'None':
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = pathlib.Path(directory.name) / NAME
        for path, source in TREE.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(textwrap.dedent(source.format(NAME=NAME)).lstrip(), encoding='utf-8')
        sys.path.insert(0, directory.name)
        self.addCleanup(sys.path.remove, directory.name)
        self.addCleanup(self.purge)
        self.purge()
        importlib.invalidate_caches()
        self.root = importlib.import_module(NAME)

    @staticmethod
    def purge() -> 'None':
        for name in [name for name in sys.modules if name == NAME or name.startswith(f'{NAME}.')]:
            del sys.modules[name]

    def probe(self) -> 'Any':
        return importlib.import_module(f'{NAME}.probe')

    def test_a_name_is_imported_on_first_use_and_bound(self) -> 'None':
        probe = self.probe()
        self.assertEqual(self.root.imported, [])
        self.assertNotIn('Thing', vars(probe))
        thing = probe.Thing
        self.assertEqual(self.root.imported, [f'{NAME}.probe.things'])
        self.assertIs(thing, sys.modules[f'{NAME}.probe.things'].Thing)
        self.assertIs(vars(probe)['Thing'], thing)
        self.assertIs(probe.Other, sys.modules[f'{NAME}.probe.things'].Renamed)
        self.assertEqual(self.root.imported, [f'{NAME}.probe.things'])

    def test_every_import_form_resolves(self) -> 'None':
        namespace = {}  # type: dict[str, Any]
        exec(f'from {NAME}.probe import Deep', namespace)  # pylint: disable=exec-used
        self.assertEqual(self.root.imported, [f'{NAME}.probe.sub.deep'])
        exec(f'import {NAME}.probe.things', namespace)  # pylint: disable=exec-used
        exec(f'from {NAME}.probe import *', namespace)  # pylint: disable=exec-used
        probe = self.probe()
        self.assertEqual({name: namespace[name] for name in probe.__all__},
                         {name: getattr(probe, name) for name in probe.__all__})
        self.assertIs(namespace['Deep'], sys.modules[f'{NAME}.probe.sub.deep'].Deep)

    def test_a_submodule_is_imported_by_its_name(self) -> 'None':
        probe = self.probe()
        self.assertNotIn(f'{NAME}.probe.things', sys.modules)
        self.assertIs(probe.things, sys.modules[f'{NAME}.probe.things'])
        self.assertIs(vars(probe)['things'], probe.things)
        self.assertIs(probe.sub.deep.Deep, probe.Deep)

    def test_a_missing_name_raises_as_a_module_does(self) -> 'None':
        probe, plain = self.probe(), types.ModuleType(f'{NAME}.probe')
        for name in ('nope', 'thing', 'extra', '_private_'):
            with self.subTest(name=name):
                with self.assertRaises(AttributeError) as lazy:
                    getattr(probe, name)
                with self.assertRaises(AttributeError) as eager:
                    getattr(plain, name)
                self.assertEqual(str(lazy.exception), str(eager.exception))
                self.assertFalse(hasattr(probe, name))
        self.assertEqual(self.root.imported, [])

    def test_dir_lists_what_an_eager_import_binds(self) -> 'None':
        probe = self.probe()
        interpreter = {name for name in vars(probe) if name.startswith('__') and name.endswith('__')}
        interpreter -= {'__getattr__', '__dir__'}
        expected = sorted({*interpreter, 'Thing', 'Other', 'Deep', 'things', 'sub'})
        self.assertEqual(dir(probe), expected)
        self.assertEqual(self.root.imported, [])
        importlib.import_module(f'{NAME}.probe.extra')
        self.assertEqual(dir(probe), sorted({*expected, 'extra'}))
        for name in ('TYPE_CHECKING', 'lazy_exports', '_private', '__getattr__', '__dir__'):
            with self.subTest(name=name):
                self.assertIn(name, vars(probe))
                self.assertNotIn(name, dir(probe))

    def test_packages_re_exports_a_subpackage_s_all(self) -> 'None':
        root = self.root
        self.assertIn(f'{NAME}.probe', sys.modules)
        self.assertEqual(root.imported, [])
        probe = self.probe()
        self.assertIs(root.Deep, probe.Deep)
        self.assertEqual(root.imported, [f'{NAME}.probe.sub.deep'])
        self.assertIs(root.Thing, probe.Thing)
        self.assertIs(vars(root)['Thing'], probe.Thing)
        interpreter = {name for name in vars(root) if name.startswith('__') and name.endswith('__')}
        self.assertEqual(dir(root), sorted({*interpreter - {'__getattr__', '__dir__'},
                                            'Thing', 'Other', 'Deep', 'probe'}))


if __name__ == '__main__':
    unittest.main()
