# -*- coding: utf-8 -*-
"""No function body first-imports a module ``import pcapkit`` leaves unloaded (GitHub issue #2771).

Such an import runs without :data:`pcapkit.utilities.importlib.import_lock`, so it can
deadlock the import system against a thread importing the same package under the lock:
one takes a module's import lock before waiting on its package, the other the package's
before the module's. A function body reaches such a module through a
:class:`~pcapkit.corekit.module.ModuleDescriptor` instead, whose first resolution holds
the lock, as the members of HTTP, LinuxSLL, L2TP and IGMP, the port registries, the
IPv4 and IPv6 pseudo-header helpers and the default engines' toolkits do.

The sweep reads every module under :file:`pcapkit/` with :mod:`ast`, so an import is
seen whether or not anything calls the function holding it, and asks a fresh
interpreter which modules ``import pcapkit`` loads. A package the importing module sits
in is always loaded before it runs. ``ALLOWED_MODULES`` and ``ALLOWED_SITES`` hold what
is left as an import, each with its reason, and an entry that matches no import fails.

"""
from __future__ import annotations

import ast
import json
import os
import pathlib
import subprocess
import sys
import unittest
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Iterator

#: Test tier (#1958): reads the sources, and asks one interpreter what ``import pcapkit`` loads.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Modules a function body may import first, and why.
ALLOWED_MODULES = {
    'pcapkit.corekit.checksum.internet': (
        'imports nothing from pcapkit.protocols (#2580), and every import of it names the '
        'module itself, so the import locks it takes always come in one order'),
}

#: Function bodies that may import a module first, by file and function, and why.
ALLOWED_SITES = {
    ('pcapkit/protocols/link/ethernet/schema.py', 'callback_payload'): (
        "its own package's protocol module, which the package imports before its schema"),
    ('pcapkit/interface/misc.py', 'follow_tcp_stream'): (
        'the toolkit of the engine named, as 1.5.1 imported it; the third-party engines are '
        'off the dissection path'),
    **{(f'pcapkit/foundation/engines/{engine}.py', function): (
        'a third-party engine imports its toolkit as 1.5.1 did, off the dissection path')
       for engine, functions in {
           'dpkt': ('_pcap_reader', '_read_packet', '_read_simple', 'read_frame', 'run'),
           'pcap_ct': ('read_frame', 'run'), 'pypcap': ('read_frame', 'run'),
           'pypcapfile': ('read_frame', 'run'), 'pyshark': ('read_frame',),
           'scapy': ('_reader_type', 'read_frame', 'run'),
       }.items() for function in functions},
}


def loaded() -> 'set[str]':
    """The modules a fresh ``import pcapkit`` loads, from this tree."""
    environ = dict(os.environ)
    environ.pop('PYTHONSAFEPATH', None)
    environ['PYTHONPATH'] = os.pathsep.join(
        [str(ROOT), environ['PYTHONPATH']] if environ.get('PYTHONPATH') else [str(ROOT)])
    code = ('import json, sys, pcapkit\n'
            'print(json.dumps([pcapkit.__file__, sorted(sys.modules)]))')
    result = subprocess.run([sys.executable, '-c', code], cwd=str(ROOT), env=environ,  # nosec: B603
                            capture_output=True, text=True, timeout=300, check=True)
    origin, names = json.loads(result.stdout.splitlines()[-1])
    assert origin.startswith(str(ROOT)), origin
    return set(names)


#: Every module under :file:`pcapkit/`, by dotted name, a package by its ``__init__``.
MODULES = frozenset('.'.join(path.relative_to(ROOT).with_suffix('').parts)
                    for path in (ROOT / 'pcapkit').rglob('*.py'))


def _is_type_checking(node: 'ast.AST') -> 'bool':
    """Whether ``node`` is an ``if TYPE_CHECKING:`` or ``if typing.TYPE_CHECKING:`` block."""
    test = getattr(node, 'test', None)
    return isinstance(node, ast.If) and (isinstance(test, ast.Name) and test.id == 'TYPE_CHECKING'
                                         or isinstance(test, ast.Attribute) and test.attr == 'TYPE_CHECKING')


def imports(path: 'pathlib.Path') -> 'Iterator[tuple[str, str]]':
    """Each function in ``path`` with a :mod:`pcapkit` module its body imports, outside ``TYPE_CHECKING``."""
    def walk(node: 'ast.AST', function: 'str') -> 'Iterator[tuple[str, str]]':
        for child in ast.iter_child_nodes(node):
            if _is_type_checking(child):
                continue
            name = function
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = child.name if not function else f'{function}.{child.name}'
            if name and isinstance(child, ast.Import):
                yield from ((name, alias.name) for alias in child.names if alias.name.startswith('pcapkit'))
            if name and isinstance(child, ast.ImportFrom) and not child.level and child.module \
                    and child.module.startswith('pcapkit'):
                yield name, child.module
                yield from ((name, f'{child.module}.{alias.name}') for alias in child.names
                            if f'{child.module}.{alias.name}' in MODULES
                            or f'{child.module}.{alias.name}.__init__' in MODULES)
            yield from walk(child, name)

    yield from walk(ast.parse(path.read_text(encoding='utf-8')), '')


def first_imports() -> 'dict[tuple[str, str], set[str]]':
    """Each function, by file and name, with the modules its body imports first."""
    warm, found = loaded(), {}  # type: set[str], dict[tuple[str, str], set[str]]
    for path in sorted((ROOT / 'pcapkit').rglob('*.py')):
        rel = path.relative_to(ROOT).as_posix()
        parts = path.relative_to(ROOT).with_suffix('').parts
        packages = {'.'.join(parts[:index]) for index in range(1, len(parts))}
        for function, module in imports(path):
            if module not in warm and module not in packages:
                found.setdefault((rel, function), set()).add(module)
    return found


class FunctionLevelFirstImportTests(unittest.TestCase):
    """Every first import a function body makes is a descriptor's, or allowed."""

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.found = first_imports()

    def test_no_function_body_imports_a_module_first(self) -> 'None':
        unexpected = sorted(f'{rel}:{function} imports {module}'
                            for (rel, function), modules in self.found.items()
                            if (rel, function) not in ALLOWED_SITES
                            for module in sorted(modules) if module not in ALLOWED_MODULES)
        self.assertEqual(unexpected, [], 'resolve these through a ModuleDescriptor, whose first '
                                         'resolution holds pcapkit.utilities.importlib.import_lock')

    def test_every_allowance_names_an_import(self) -> 'None':
        modules = set().union(*self.found.values())
        self.assertEqual(sorted(set(ALLOWED_MODULES) - modules), [])
        self.assertEqual(sorted(set(ALLOWED_SITES) - set(self.found)), [])

    def test_the_sweep_sees_function_level_imports(self) -> 'None':
        source = ROOT / 'pcapkit' / 'protocols' / 'link' / 'ethernet' / 'schema.py'
        self.assertIn(('callback_payload', 'pcapkit.protocols.link.ethernet.protocol'), set(imports(source)))


if __name__ == '__main__':
    unittest.main()
