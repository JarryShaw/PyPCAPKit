# -*- coding: utf-8 -*-
"""Each protocol is one package holding its dissector, header schema and data model (#2534).

A package under :mod:`pcapkit.protocols` takes its protocol's name, its
``protocol``, ``schema`` and ``data`` modules take their role, each module holds
the class named after the package, and the package's ``__init__`` exports that
class alone. The ``__init__`` also binds each public class its ``schema`` and
``data`` modules define as ``Schema_<name>`` and ``Data_<name>``, as 1.5.1's
aggregators exposed them, outside ``__all__``: ruled by the owner in review of
#2753. The ``pcapkit.protocols.schema`` and ``pcapkit.protocols.data``
trees are gone with no alias: those names are the framework modules, which hold
the base classes and collect no protocol's. A protocol class defined without a
``schema`` or ``data`` keyword finds them in its own package.

The packages are found by walking the tree, so a protocol added tomorrow is
checked tomorrow.

"""
import ast
import importlib
import importlib.util
import pkgutil
import types
import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): checks the layout of the protocol packages, a question about
#: the tree.
__tier__ = 'LATEST'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Paths that held the old trees, framework modules or aggregations, and import no more.
OLD_PATHS = (
    'pcapkit.protocols.schema.schema', 'pcapkit.protocols.data.data', 'pcapkit.protocols.data.protocol',
    'pcapkit.protocols.schema.link', 'pcapkit.protocols.data.internet',
    'pcapkit.protocols.schema.link.vlan', 'pcapkit.protocols.data.link.vlan',
    'pcapkit.protocols.schema.internet.ipv6_option',
)


def norm(name: 'str') -> 'str':
    """A name as #2529's match reads it, ignoring case and underscores."""
    return name.lower().replace('_', '')


def packages() -> 'dict[str, str]':
    """Every protocol package, by dotted name, to the protocol class its module holds."""
    import pcapkit.protocols as root

    found = {}  # type: dict[str, str]
    for info in pkgutil.walk_packages(root.__path__, f'{root.__name__}.'):
        if not info.name.endswith('.protocol') or info.name == 'pcapkit.protocols.protocol':
            continue
        package = info.name[:-len('.protocol')]
        module = importlib.import_module(info.name)
        leaf = norm(package.rpartition('.')[2])
        names = [name for name in module.__all__ if norm(name) == leaf]
        found[package] = names[0] if len(names) == 1 else ''
    return found


def defined_classes(package: 'str', role: 'str') -> 'list[str]':
    """The public classes a package's ``role`` module defines at its top level, from its source.

    A class bound only under an ``if`` -- a TypedDict bound for Sphinx alone -- is
    left out, as the package's ``__init__`` cannot import it at run time.

    """
    spec = importlib.util.find_spec(f'{package}.{role}')
    if spec is None or spec.origin is None:
        return []
    with open(spec.origin, encoding='utf-8') as file:
        tree = ast.parse(file.read())
    return [node.name for node in tree.body if isinstance(node, ast.ClassDef) and not node.name.startswith('_')]


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ProtocolPackageTests(unittest.TestCase):
    """Pin the per-protocol package layout."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_the_walk_finds_the_packages(self) -> None:
        # A broken walk would make every check below pass over nothing.
        found = packages()
        for package in ('pcapkit.protocols.link.vlan', 'pcapkit.protocols.internet.ipv4',
                        'pcapkit.protocols.misc.raw', 'pcapkit.protocols.misc.pcap.frame'):
            self.assertIn(package, found)

    def test_each_protocol_module_holds_one_class_named_after_its_package(self) -> None:
        self.assertEqual(sorted(package for package, name in packages().items() if not name), [])

    def test_each_package_exports_its_class_alone(self) -> None:
        for package, name in packages().items():
            with self.subTest(package=package):
                init = importlib.import_module(package)
                module = importlib.import_module(f'{package}.protocol')
                self.assertEqual(init.__all__, [name])
                self.assertIs(getattr(init, name), getattr(module, name))
                self.assertEqual(getattr(module, name).__module__, module.__name__)

    def test_each_package_binds_its_schema_and_data_classes(self) -> None:
        # Each alias is there, is the role module's own class and stays out of
        # __all__, and nothing else public is bound beside the protocol class.
        for package, name in packages().items():
            with self.subTest(package=package):
                init = importlib.import_module(package)
                aliases = {}  # type: dict[str, type]
                for role, prefix in (('schema', 'Schema_'), ('data', 'Data_')):
                    for klass in defined_classes(package, role):
                        aliases[prefix + klass] = getattr(importlib.import_module(f'{package}.{role}'), klass)
                for alias, klass in sorted(aliases.items()):
                    self.assertIs(getattr(init, alias, None), klass, alias)
                self.assertEqual(sorted(set(aliases) & set(init.__all__)), [])
                public = sorted(key for key, value in vars(init).items()
                                if not key.startswith('_') and not isinstance(value, types.ModuleType))
                self.assertEqual(public, sorted({name, *aliases}))

    def test_each_schema_and_data_module_holds_the_class_named_after_its_package(self) -> None:
        for package, name in packages().items():
            klass = getattr(importlib.import_module(f'{package}.protocol'), name)
            for role in ('schema', 'data'):
                if importlib.util.find_spec(f'{package}.{role}') is None:
                    continue
                with self.subTest(package=package, role=role):
                    module = importlib.import_module(f'{package}.{role}')
                    if name not in module.__all__:
                        # a family base's module may hold only what its members share
                        self.assertTrue(module.__all__)
                        self.assertNotEqual(getattr(klass, f'__{role}__').__module__, module.__name__)
                        continue
                    self.assertEqual(getattr(module, name).__module__, module.__name__)

    def test_a_base_reads_no_members_schema_or_data(self) -> None:
        # A family's shared pieces live in the base's package: a base whose
        # dissector imported a member's schema or data module would put the two
        # packages in an import cycle, since the member imports the base.
        found = packages()
        classes = {package: getattr(importlib.import_module(f'{package}.protocol'), name)
                   for package, name in found.items()}
        for base, klass in classes.items():
            members = {package for package, other in classes.items()
                       if other is not klass and issubclass(other, klass)}
            path = importlib.util.find_spec(f'{base}.protocol').origin
            with open(path, encoding='utf-8') as file:
                tree = ast.parse(file.read())
            imported = {node.module for node in tree.body if isinstance(node, ast.ImportFrom) and node.module}
            with self.subTest(base=base):
                self.assertEqual(sorted(mod for mod in imported if mod.rpartition('.')[0] in members
                                        and mod.rpartition('.')[2] in ('schema', 'data')), [])

    def test_the_framework_modules_collect_nothing(self) -> None:
        from pcapkit.protocols import data, schema

        for module in (schema, data):
            with self.subTest(module=module.__name__):
                self.assertFalse(hasattr(module, '__path__'))
                self.assertFalse(hasattr(module, 'VLAN'))
                self.assertFalse(hasattr(module, 'IPv4'))
        self.assertIn('Schema', schema.__all__)
        self.assertIn('Data', data.__all__)
        self.assertIn('Packet', data.__all__)

    def test_the_old_paths_do_not_import(self) -> None:
        for old in OLD_PATHS:
            with self.subTest(path=old):
                with self.assertRaises(ModuleNotFoundError):
                    importlib.import_module(old)

    def test_a_class_without_keywords_finds_its_own_packages_models(self) -> None:
        from pcapkit.protocols.link.l2tp import data, protocol, schema

        self.assertIs(protocol.L2TP.__schema__, schema.L2TP)
        self.assertIs(protocol.L2TP.__data__, data.L2TP)

    def test_a_class_outside_a_protocol_module_falls_back_to_raw(self) -> None:
        from pcapkit.protocols.link.link import Link
        from pcapkit.protocols.misc.raw.data import Raw as Data_Raw
        from pcapkit.protocols.misc.raw.schema import Raw as Schema_Raw

        class L2TP(Link):  # pylint: disable=abstract-method
            """Named like a protocol, but outside any protocol package."""

        self.assertIs(L2TP.__schema__, Schema_Raw)
        self.assertIs(L2TP.__data__, Data_Raw)

    def test_an_explicit_keyword_is_used_as_given(self) -> None:
        from pcapkit.protocols.link.link import Link
        from pcapkit.protocols.link.vlan.data import VLAN as Data_VLAN
        from pcapkit.protocols.link.vlan.schema import VLAN as Schema_VLAN

        class Probe(Link, schema=Schema_VLAN, data=Data_VLAN):  # pylint: disable=abstract-method
            """Takes its models from the keywords."""

        self.assertIs(Probe.__schema__, Schema_VLAN)
        self.assertIs(Probe.__data__, Data_VLAN)


if __name__ == '__main__':
    unittest.main()
