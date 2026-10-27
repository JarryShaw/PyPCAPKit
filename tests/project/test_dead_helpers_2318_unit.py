# -*- coding: utf-8 -*-
"""Every helper here is one something reads. C.f. #2318.

A helper nothing reads answers a question nobody asks. Each is held to the rule
that makes it worth keeping rather than to its name.

A ``Family`` in ``examples/generators/dispatch.py`` carries an ``enum`` only
where :func:`code_name` can fall back to one, i.e. where the family's registry
holds a key with no ``.name`` of its own; every key of ``Internet.__proto__``
carries one, so the ``internet`` family needs no ``enum``. A ``FAKE_GH`` arm
answers only a query a caller sends, and :file:`util/release_upload.py` sends
``ASSETS_JQ`` rather than a bare-name ``assets`` one. And a module-level
constant of ``test_sweeps_on_latest_only_1732`` is worth keeping only where
something reads it, in its own module or in another.

"""

import ast
import importlib.util
import pathlib
import re
import sys
import types
import unittest

#: Test tier (#1958): reads repository files and the dispatch case table, which
#: do not differ by interpreter.
__tier__ = 'LATEST'

#: Repository root.
ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
#: The generator whose ``Family`` table carries the ``enum`` fall-back.
DISPATCH = ROOT / 'examples' / 'generators' / 'dispatch.py'
#: The workflow test whose ``gh`` stand-in answers the release queries.
RELEASE_TEST = ROOT / 'tests' / 'project' / 'test_release_tags_the_run_sha_1634.py'
#: The workflow test whose module-level constants the other ones import.
SWEEPS_TEST = ROOT / 'tests' / 'project' / 'test_sweeps_on_latest_only_1732.py'
#: Where a query ``FAKE_GH`` answers has to be sent from.
CALLERS = (ROOT / 'util' / 'release_upload.py', *sorted((ROOT / '.github' / 'workflows').glob('*.yml')))


def load_dispatch() -> 'types.ModuleType':
    """Load :file:`examples/generators/dispatch.py` by path.

    Follows :func:`tests.protocols.test_dispatch_registry_unit._load_generator`:
    the directory is not a package and its module name is too generic to put on
    :data:`sys.path`.

    Raises:
        RuntimeError: If the module cannot be found or loaded.

    """
    spec = importlib.util.spec_from_file_location('pcapkit_samples_dispatch_2318', DISPATCH)
    if spec is None or spec.loader is None:  # pragma: no cover
        raise RuntimeError(f'cannot load the dispatch case table from {DISPATCH}')

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def constants(path: 'pathlib.Path') -> 'list[str]':
    """The module-level upper-case constants assigned in ``path``."""
    found = []
    for node in ast.parse(path.read_text(encoding='utf-8')).body:
        if isinstance(node, ast.Assign):
            found.extend(target.id for target in node.targets
                         if isinstance(target, ast.Name) and target.id.isupper())
    return found


def loaded(path: 'pathlib.Path') -> 'set[str]':
    """The names ``path`` reads, whether bare or through a module attribute."""
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            found.add(node.id)
        elif isinstance(node, ast.Attribute):
            found.add(node.attr)
    return found


def imports(path: 'pathlib.Path') -> 'set[str]':
    """The names ``path`` imports from another module."""
    return {alias.name for node in ast.walk(ast.parse(path.read_text(encoding='utf-8')))
            if isinstance(node, ast.ImportFrom) for alias in node.names}


class DispatchEnumTests(unittest.TestCase):
    """A family carries an ``enum`` only where ``code_name`` falls back to one."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.dispatch = load_dispatch()

    def test_an_enum_is_given_only_where_a_key_needs_it(self) -> None:
        for family in self.dispatch.FAMILIES:
            with self.subTest(family=family.label):
                nameless = [code for code in family.registry()
                            if getattr(code, 'name', None) is None]
                if family.enum is None:
                    continue
                # The fall-back is only reachable for a key with no ``.name``,
                # and only useful where an enumeration member equals it.
                self.assertTrue(nameless)
                enum = family.enum()
                self.assertTrue(any(enum(code).name for code in nameless))

    def test_the_fall_back_names_a_key(self) -> None:
        from pcapkit.const.reg.ethertype import EtherType

        self.assertEqual(self.dispatch.code_name(0x8137, EtherType), 'Novell_Inc_0x8137')
        self.assertEqual(self.dispatch.code_name(20, None), '20')


class FakeGHQueryTests(unittest.TestCase):
    """Every ``--json``/``--jq`` pair ``FAKE_GH`` answers is one a caller sends."""

    def test_each_arm_answers_a_real_query(self) -> None:
        source = RELEASE_TEST.read_text(encoding='utf-8')
        asked = '\n'.join(path.read_text(encoding='utf-8') for path in CALLERS if path.is_file())
        arms = re.findall(r"^\s*'--json (\S+) --jq (.+?)'\)", source, re.MULTILINE)
        self.assertTrue(arms)
        for field, query in arms:
            with self.subTest(query=query):
                self.assertIn(field, asked)
                self.assertIn(query, asked)


class SweepsConstantTests(unittest.TestCase):
    """Every constant of the sweeps workflow test is read somewhere.

    The names are counted from the syntax rather than from the text, so that a
    constant named in prose -- in this module's own docstring, for one -- does
    not read as a use of it.

    """

    def test_no_constant_goes_unread(self) -> None:
        read = loaded(SWEEPS_TEST)
        for path in sorted((ROOT / 'tests').rglob('*.py')):
            if path != SWEEPS_TEST:
                read |= loaded(path) | imports(path)
        self.assertEqual([name for name in constants(SWEEPS_TEST) if name not in read], [])


if __name__ == '__main__':
    unittest.main()
