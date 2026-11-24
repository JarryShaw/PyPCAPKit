# -*- coding: utf-8 -*-
"""Each reassembly and flow tracing class is one package holding its class and data models (#2882).

A package under :mod:`pcapkit.foundation.reassembly` or
:mod:`pcapkit.foundation.traceflow` takes its class's name, its ``reassembly`` or
``traceflow`` module holds the class, ``data`` its data models where it has its
own, and the package's ``__init__`` exports the class alone and binds each class
``data`` defines as ``Data_<name>``, outside ``__all__``, as #2534 laid out a
protocol's. The bases stay beside their data models, and the ``data`` packages
are gone with no alias.

The packages are found by walking the two trees, so a class added tomorrow is
checked tomorrow.

"""
import ast
import importlib
import importlib.util
import pathlib
import pkgutil
import subprocess  # nosec: B404
import sys
import types
import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): checks the layout of the reassembly and flow tracing
#: packages, a question about the tree.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Each family package, and the role its members' class module takes.
FAMILIES = (('pcapkit.foundation.reassembly', 'reassembly'), ('pcapkit.foundation.traceflow', 'traceflow'))

#: The modules the ``data`` packages held, which import no more.
OLD_PATHS = (
    'pcapkit.foundation.reassembly.data.data', 'pcapkit.foundation.reassembly.data.ip',
    'pcapkit.foundation.reassembly.data.tcp', 'pcapkit.foundation.reassembly.data.dtls',
    'pcapkit.foundation.traceflow.data.data', 'pcapkit.foundation.traceflow.data.tcp',
)


def packages() -> 'dict[str, tuple[str, str]]':
    """Every member package, by dotted name, to its role and the class its module holds."""
    found = {}  # type: dict[str, tuple[str, str]]
    for family, role in FAMILIES:
        root = importlib.import_module(family)
        for info in pkgutil.iter_modules(root.__path__, f'{family}.'):
            if not info.ispkg:
                continue
            module = importlib.import_module(f'{info.name}.{role}')
            leaf = info.name.rpartition('.')[2].lower()
            names = [name for name in module.__all__ if name.lower() == leaf]
            found[info.name] = (role, names[0] if len(names) == 1 else '')
    return found


def defined_classes(module: 'str') -> 'list[str]':
    """The public classes ``module`` defines at its top level, read from its source."""
    spec = importlib.util.find_spec(module)
    if spec is None or spec.origin is None:
        return []
    tree = ast.parse(pathlib.Path(spec.origin).read_text(encoding='utf-8'))
    return [node.name for node in tree.body if isinstance(node, ast.ClassDef) and not node.name.startswith('_')]


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class FoundationPackageTests(unittest.TestCase):
    """Pin the per-class package layout of reassembly and flow tracing."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_the_walk_finds_the_packages(self) -> None:
        # A broken walk would make every check below pass over nothing.
        found = packages()
        for package in ('pcapkit.foundation.reassembly.ip', 'pcapkit.foundation.reassembly.ipv4',
                        'pcapkit.foundation.reassembly.tcp', 'pcapkit.foundation.traceflow.tcp'):
            self.assertIn(package, found)

    def test_each_module_holds_the_class_named_after_its_package(self) -> None:
        self.assertEqual(sorted(package for package, (_, name) in packages().items() if not name), [])

    def test_each_package_exports_its_class_alone(self) -> None:
        for package, (role, name) in packages().items():
            with self.subTest(package=package):
                init = importlib.import_module(package)
                module = importlib.import_module(f'{package}.{role}')
                self.assertEqual(init.__all__, [name])
                self.assertIs(getattr(init, name), getattr(module, name))
                self.assertEqual(getattr(module, name).__module__, module.__name__)

    def test_each_package_binds_its_data_classes(self) -> None:
        # Each alias is the data module's own class and stays out of __all__, and
        # nothing else public is bound beside the class.
        for package, (_, name) in packages().items():
            with self.subTest(package=package):
                init = importlib.import_module(package)
                aliases = {f'Data_{klass}': getattr(importlib.import_module(f'{package}.data'), klass)
                           for klass in defined_classes(f'{package}.data')}
                for alias, klass in sorted(aliases.items()):
                    self.assertIs(getattr(init, alias, None), klass, alias)
                public = sorted(key for key, value in vars(init).items()
                                if not key.startswith('_') and not isinstance(value, types.ModuleType))
                self.assertEqual(public, sorted({name, *aliases}))

    def test_the_ip_members_share_the_base_data(self) -> None:
        from pcapkit.foundation.reassembly.ip.reassembly import IP

        for member, name in (('ipv4', 'IPv4'), ('ipv6', 'IPv6')):
            with self.subTest(member=member):
                package = f'pcapkit.foundation.reassembly.{member}'
                self.assertIsNone(importlib.util.find_spec(f'{package}.data'))
                self.assertIn(IP, getattr(importlib.import_module(package), name).__mro__)

    def test_the_bases_keep_their_data_beside_them(self) -> None:
        from pcapkit.foundation.reassembly import data as reassembly_data
        from pcapkit.foundation.traceflow import data as traceflow_data

        for module, names in ((reassembly_data, ('ReassemblyData', 'Completion', 'Deferred')),
                              (traceflow_data, ('TraceFlowData', 'Deferred', 'FrameRecord'))):
            with self.subTest(module=module.__name__):
                self.assertFalse(hasattr(module, '__path__'))
                self.assertEqual(sorted(module.__all__), sorted(names))

    def test_the_old_paths_do_not_import(self) -> None:
        for old in OLD_PATHS:
            with self.subTest(path=old):
                with self.assertRaises(ModuleNotFoundError):
                    importlib.import_module(old)

    def test_the_extractor_names_each_defining_module(self) -> None:
        # A descriptor naming a package would still resolve through its
        # __init__, so pin the module the class is defined in.
        from pcapkit.foundation.extraction import Extractor

        for table in (Extractor.__reassembly__, Extractor.__traceflow__):
            for key, descriptor in table.items():
                with self.subTest(key=key):
                    self.assertEqual(descriptor.klass.__module__, descriptor.module)
                    self.assertRegex(descriptor.module, r'\.(reassembly|traceflow)$')

    @unittest.skipUnless(importlib.util.find_spec('isort') is not None, 'isort is not installed')
    def test_isort_leaves_every_init_alone(self) -> None:
        # Sorted as one run, the class import and the Data_* block would merge,
        # so the [tool.isort] skip in pyproject.toml is what keeps the layout.
        paths = [str(pathlib.Path(*package.split('.'), '__init__.py')) for package in packages()]
        command = [sys.executable, '-m', 'isort', '--check-only', '-l100', '-ppcapkit', *paths]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)  # nosec: B603
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f'Skipped {len(paths)} files', result.stdout)


if __name__ == '__main__':
    unittest.main()
