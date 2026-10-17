# -*- coding: utf-8 -*-
"""Each third-party engine types the package it drives (#1878).

An engine keeps that package in ``_expkg``. #1870 annotated it ``'ModuleType'``,
which mypy reads as :data:`~typing.Any` for every attribute, so nothing called
through it was checked. Each engine now annotates it with a
:class:`~typing.Protocol` of its own, defined in its module-level
``if TYPE_CHECKING:`` block and declaring what the engine reads through it.

``scapy`` ships its own types. The other engine packages ship none, so
:file:`typings/` holds stubs for the part of each that :mod:`pcapkit` uses,
registered in :file:`mypy.ini` through ``mypy_path``.

mypy itself is advisory in CI, so these are the parts pinned here: the
annotations, the protocols covering what each engine reads, and the stubs
covering what :mod:`pcapkit` imports.

This module is unit-tier: it parses source and imports no engine package.

"""
from __future__ import annotations

import ast
import configparser
import pathlib
import re
import unittest
from typing import TYPE_CHECKING

from tests._tiers import ROOT

if TYPE_CHECKING:
    from typing import Iterator, Optional

#: Engine module, relative to the repository root -> the engine class in it.
ENGINES = {
    'pcapkit/foundation/engines/dpkt.py': 'DPKT',
    'pcapkit/foundation/engines/scapy.py': 'Scapy',
    'pcapkit/foundation/engines/pyshark.py': 'PyShark',
    'pcapkit/foundation/engines/pypcap.py': 'PyPCAP',
    'pcapkit/foundation/engines/pcap_ct.py': 'PCAP_CT',
    'pcapkit/foundation/engines/pypcapfile.py': 'PyPCAPFile',
}

#: Engine packages that ship no type information, so are stubbed locally.
UNTYPED = ('dpkt', 'pyshark', 'pcap', 'pcapfile')

#: Directory holding the stubs.
TYPINGS = ROOT / 'typings'

#: The mypy configuration that registers :data:`TYPINGS`.
MYPY_INI = ROOT / 'mypy.ini'


def _parse(path: 'pathlib.Path') -> 'ast.Module':
    return ast.parse(path.read_text(encoding='utf-8'), filename=str(path))


def _is_type_checking(test: 'ast.expr') -> bool:
    if isinstance(test, ast.Name):
        return test.id == 'TYPE_CHECKING'
    return isinstance(test, ast.Attribute) and test.attr == 'TYPE_CHECKING'


def _guarded(body: 'list[ast.stmt]') -> 'Iterator[ast.stmt]':
    """The statements of every ``if TYPE_CHECKING:`` directly in ``body``."""
    for statement in body:
        if isinstance(statement, ast.If) and _is_type_checking(statement.test):
            yield from statement.body


def _class(tree: 'ast.Module', name: str) -> 'ast.ClassDef':
    for statement in tree.body:
        if isinstance(statement, ast.ClassDef) and statement.name == name:
            return statement
    raise AssertionError(f'no top-level class {name}')


def _expkg_annotation(cls: 'ast.ClassDef') -> 'Optional[str]':
    """The annotation of ``_expkg`` in the class body, a quoted one unquoted."""
    for statement in [*cls.body, *_guarded(cls.body)]:
        if (isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name)
                and statement.target.id == '_expkg'):
            annotation = statement.annotation
            if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
                return annotation.value
            return ast.unparse(annotation)
    return None


def _guarded_protocols(tree: 'ast.Module') -> 'dict[str, ast.ClassDef]':
    """Every class the module-level guard defines as a ``Protocol``, by name."""
    return {
        statement.name: statement for statement in _guarded(tree.body)
        if isinstance(statement, ast.ClassDef)
        and any(ast.unparse(base) in ('Protocol', 'typing.Protocol') for base in statement.bases)
    }


def _members(cls: 'ast.ClassDef') -> 'dict[str, str]':
    """A protocol's members, each mapped to the annotation of its value."""
    members = {}
    for statement in cls.body:
        if isinstance(statement, ast.FunctionDef):
            members[statement.name] = ast.unparse(statement.returns) if statement.returns else ''
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            members[statement.target.id] = ast.unparse(statement.annotation)
    return {name: value.strip('\'"') for name, value in members.items()}


def _is_expkg(node: 'ast.AST') -> bool:
    return (isinstance(node, ast.Attribute) and node.attr == '_expkg'
            and isinstance(node.value, ast.Name) and node.value.id == 'self')


def _read_paths(cls: 'ast.ClassDef') -> 'set[tuple[str, ...]]':
    """Attribute paths each method reads through ``self._expkg``, or a local bound to it.

    ``self._expkg.ip.IP`` and ``dpkt = self._expkg; dpkt.ip.IP`` both give
    ``('ip', 'IP')``.

    """
    paths = set()
    for method in cls.body:
        if not isinstance(method, ast.FunctionDef):
            continue
        aliases = {target.id for node in ast.walk(method) if isinstance(node, ast.Assign) and _is_expkg(node.value)
                   for target in node.targets if isinstance(target, ast.Name)}
        for node in ast.walk(method):
            if not isinstance(node, ast.Attribute):
                continue
            path = []  # type: list[str]
            current = node  # type: ast.expr
            while isinstance(current, ast.Attribute) and not _is_expkg(current):
                path.append(current.attr)
                current = current.value
            if _is_expkg(current) or (isinstance(current, ast.Name) and current.id in aliases):
                paths.add(tuple(reversed(path)))
    # keep the longest paths only: ``('ip',)`` is a prefix of ``('ip', 'IP')``
    return {path for path in paths if path and not any(
        other[:len(path)] == path and other != path for other in paths)}


def _stub_for(module: str) -> 'Optional[pathlib.Path]':
    """The stub file of a dotted module name under :data:`TYPINGS`, if there is one."""
    parts = module.split('.')
    for candidate in (TYPINGS.joinpath(*parts, '__init__.pyi'), TYPINGS.joinpath(*parts[:-1], f'{parts[-1]}.pyi')):
        if candidate.is_file():
            return candidate
    return None


def _stub_names(path: 'pathlib.Path') -> 'set[str]':
    """The top-level names a stub file declares."""
    names = set()
    for statement in _parse(path).body:
        if isinstance(statement, (ast.ClassDef, ast.FunctionDef)):
            names.add(statement.name)
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            names.add(statement.target.id)
        elif isinstance(statement, ast.ImportFrom):
            names.update(alias.asname or alias.name for alias in statement.names)
    return names


def _untyped_imports() -> 'Iterator[tuple[str, str, Optional[str]]]':
    """``(file, module, name)`` for each import of :data:`UNTYPED` in :mod:`pcapkit`.

    ``name`` is the name a ``from`` import takes, or :data:`None` for ``import``.
    Imports anywhere in a module count, the function-level and the guarded ones
    included.

    """
    pattern = re.compile(rf'\b(?:import|from)\s+(?:{"|".join(UNTYPED)})\b')
    for path in sorted((ROOT / 'pcapkit').rglob('*.py')):
        source = path.read_text(encoding='utf-8')
        if not pattern.search(source):
            continue
        relative = path.relative_to(ROOT).as_posix()
        for node in ast.walk(ast.parse(source, filename=str(path))):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split('.')[0] in UNTYPED:
                        yield relative, alias.name, None
            elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
                if node.module.split('.')[0] in UNTYPED:
                    for alias in node.names:
                        yield relative, node.module, alias.name


class EngineProtocolTests(unittest.TestCase):
    """Each engine's ``_expkg`` is a protocol of its own, covering what it reads."""

    def test_each_expkg_is_its_own_guarded_protocol(self) -> None:
        owners = {}  # type: dict[str, str]
        for relative, engine in ENGINES.items():
            with self.subTest(engine=engine):
                tree = _parse(ROOT / relative)
                annotation = _expkg_annotation(_class(tree, engine))

                self.assertIsNotNone(annotation, f'{engine} declares no _expkg annotation')
                self.assertNotEqual(annotation, 'ModuleType',
                                    f'{engine}._expkg is ModuleType, which types every attribute as Any')
                self.assertIn(annotation, _guarded_protocols(tree),
                              f'{engine}._expkg is {annotation!r}, which is no Protocol defined in '
                              f'the module-level TYPE_CHECKING block of {relative}')
                self.assertNotIn(annotation, owners,
                                 f'{engine} shares its _expkg protocol with {owners.get(annotation)}')
                owners[str(annotation)] = engine

    def test_each_protocol_declares_what_its_engine_reads(self) -> None:
        for relative, engine in ENGINES.items():
            tree = _parse(ROOT / relative)
            cls = _class(tree, engine)
            protocols = _guarded_protocols(tree)
            paths = _read_paths(cls)
            top = protocols.get(str(_expkg_annotation(cls)))
            with self.subTest(engine=engine):
                self.assertTrue(paths, f'{engine} reads nothing through _expkg, so this test checks nothing')
                self.assertIsNotNone(top, f'{engine}._expkg is not annotated with a guarded Protocol')
            if top is None:
                continue
            for path in sorted(paths):
                with self.subTest(engine=engine, path='.'.join(path)):
                    protocol = top
                    for depth, name in enumerate(path):
                        members = _members(protocol)
                        self.assertIn(name, members, f'{engine} reads _expkg.{".".join(path[:depth + 1])}, '
                                                     f'which {protocol.name} does not declare')
                        nested = protocols.get(members[name])
                        if nested is None:
                            break
                        protocol = nested


class StubTests(unittest.TestCase):
    """The stubs exist, are registered, and cover what :mod:`pcapkit` imports."""

    def setUp(self) -> None:
        # A source distribution ships neither, so is not a tree to check. A
        # checkout always has mypy.ini, so a missing typings/ still fails.
        if not MYPY_INI.is_file():
            self.skipTest(f'{MYPY_INI} is not present, e.g. in a source distribution')

    def test_the_stub_directory_is_in_mypy_path(self) -> None:
        config = configparser.ConfigParser(interpolation=None)
        config.read(MYPY_INI, encoding='utf-8')
        # mypy splits the option on either separator, on every platform
        entries = re.split(r'[,:]', config.get('mypy', 'mypy_path', fallback=''))
        paths = {(ROOT / entry.strip().replace('$MYPY_CONFIG_FILE_DIR', str(ROOT))).resolve()
                 for entry in entries if entry.strip()}

        self.assertTrue(TYPINGS.is_dir(), f'{TYPINGS} is missing')
        self.assertIn(TYPINGS.resolve(), paths, f'mypy.ini does not list {TYPINGS} in mypy_path: {paths}')

    def test_each_untyped_engine_package_is_stubbed(self) -> None:
        for package in UNTYPED:
            with self.subTest(package=package):
                self.assertTrue((TYPINGS / package / '__init__.pyi').is_file(),
                                f'typings/{package}/__init__.pyi is missing')

    def test_the_stubs_cover_every_import_of_them(self) -> None:
        imports = list(_untyped_imports())
        self.assertTrue(imports, 'no import of an untyped engine package found, so this test checks nothing')
        for relative, module, name in imports:
            with self.subTest(file=relative, module=module, name=name):
                stub = _stub_for(module)
                self.assertIsNotNone(stub, f'{relative} imports {module}, which typings/ has no stub for')
                if name is not None:
                    self.assertTrue(name in _stub_names(stub) or _stub_for(f'{module}.{name}') is not None,
                                    f'{relative} imports {name} from {module}, which {stub} does not declare')

    def test_each_stub_cites_the_version_it_was_written_against(self) -> None:
        stubs = sorted(TYPINGS.rglob('*.pyi'))
        self.assertTrue(stubs, 'typings/ holds no stubs')
        for stub in stubs:
            with self.subTest(stub=stub.relative_to(ROOT).as_posix()):
                docstring = ast.get_docstring(_parse(stub)) or ''
                self.assertRegex(docstring, r'\b\d+\.\d+', 'the stub names no version of what it describes')


if __name__ == '__main__':
    unittest.main()
