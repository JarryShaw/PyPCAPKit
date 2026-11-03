# -*- coding: utf-8 -*-
"""A schema-layer helper is called only where the ruling on #2674 lets it be.

The owner ruled on #2674 that a helper shared beyond where it belongs lives in
:mod:`pcapkit.corekit.schema`, the home of the helpers shared across the schema
layer, which any module may call; the rule is written down on
:file:`docs/source/contributing/conventions/utilities-or-corekit.rst`. Two kinds
of module are checked, by what may call the functions they define:

* **The parts of the schema layer no one protocol owns** -- every field module
  under :file:`pcapkit/corekit/fields/`, and :mod:`pcapkit.protocols.schema.schema`.
  Only the schema layer, :file:`pcapkit/corekit/fields/` and
  :file:`pcapkit/protocols/schema/`, may call their functions.
* **A protocol's own schema module** -- every other module under
  :file:`pcapkit/protocols/schema/`. Only that protocol may call its functions:
  its protocol, data and schema modules, which share a path below
  :mod:`pcapkit.protocols` once ``schema`` or ``data`` is dropped from it. A
  module a protocol family shares, with no protocol of its own, names the
  members that may call it in :data:`SHARED`.

A call is found wherever :mod:`pcapkit`, ``examples`` or ``util`` makes one:

* by importing the function, ``from pcapkit.corekit.fields.ipaddress import
  parse_ip_address``, through a package or a relative import as well;
* by star-importing a module whose ``__all__`` names it;
* or as an attribute of the module imported whole, ``ipaddress.parse_ip_address``.

The shared helpers themselves are held to their home: no function there is also
defined in a module above, and none of them imports a field module, the protocols
or :mod:`pcapkit.foundation` outside an ``if TYPE_CHECKING:`` block, since the
field modules and the protocols import them.

Each module is read with :mod:`ast` rather than imported, as
:mod:`tests.project.test_utilities_import_boundary_1735_unit` reads them.

This module is unit-tier and reads no capture.

"""
from __future__ import annotations

import ast
import pathlib
import unittest

from tests.project.test_protocols_import_boundary_2622_unit import _type_checking_lines
from tests.project.test_utilities_import_boundary_1735_unit import (ROOT, _module_name,
                                                                    _relative_base,
                                                                    imported_names)

#: Test tier (#1958): reads the tree's import graph, a question about the tree.
__tier__ = 'LATEST'

#: The schema layer.
LAYER = (ROOT / 'pcapkit' / 'corekit' / 'fields', ROOT / 'pcapkit' / 'protocols' / 'schema')

#: The schema package of :mod:`pcapkit.protocols`.
SCHEMA = ROOT / 'pcapkit' / 'protocols' / 'schema'

#: The modules of the layer no one protocol owns.
GENERIC = tuple(sorted((ROOT / 'pcapkit' / 'corekit' / 'fields').rglob('*.py'))) + (
    SCHEMA / 'schema.py',
)

#: The home of the helpers shared across the schema layer, which any module may
#: call.
HELPERS = ROOT / 'pcapkit' / 'corekit' / 'schema'

#: What a shared helper may not import outside an ``if TYPE_CHECKING:`` block:
#: each imports a shared helper itself.
ABOVE_HELPERS = ('pcapkit.corekit.fields', 'pcapkit.protocols', 'pcapkit.foundation')

#: The protocols' own schema modules.
PROTOCOL = tuple(path for path in sorted(SCHEMA.rglob('*.py'))
                 if path.name != '__init__.py' and path not in GENERIC)

#: A schema module a protocol family shares, with no protocol of its own, mapped
#: to the protocols of the family, each as :func:`protocol_key` gives it.
SHARED = {
    # The IPv6 options [RFC 8200, section 4.2] both option headers carry.
    'pcapkit.protocols.schema.internet.ipv6_option': ('internet.hopopt', 'internet.ipv6_opts'),
}

#: Where a call is looked for.
CALLERS = ('pcapkit', 'examples', 'util')


def protocol_key(module: 'str') -> 'str | None':
    """The protocol ``module`` belongs to, as its path below :mod:`pcapkit.protocols`.

    A protocol's schema and data modules sit at the same path as its protocol
    module, under ``schema`` and ``data``, so all three give one key. A module
    outside :mod:`pcapkit.protocols` belongs to no protocol.

    """
    parts = module.split('.')
    if parts[:2] != ['pcapkit', 'protocols'] or len(parts) < 3:
        return None
    rest = parts[3:] if parts[2] in ('schema', 'data') else parts[2:]
    return '.'.join(rest) or None


def _in_layer(path: 'pathlib.Path') -> 'bool':
    """Whether ``path`` is a source file of the schema layer."""
    return any(base in path.parents for base in LAYER)


def _all_names(tree: 'ast.Module') -> 'set[str]':
    """The names a module's literal ``__all__`` lists."""
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id == '__all__'
                and isinstance(node.value, (ast.List, ast.Tuple))):
            return {elt.value for elt in node.value.elts
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str)}
    return set()


def helpers(paths: 'tuple[pathlib.Path, ...]') -> 'dict[str, tuple[set[str], set[str]]]':
    """Each module of ``paths``, as its functions and the names its ``__all__`` lists."""
    found = {}  # type: dict[str, tuple[set[str], set[str]]]
    for path in paths:
        tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
        functions = {node.name for node in tree.body
                     if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        found[_module_name(path)] = (functions, _all_names(tree))
    return found


def _dotted(node: 'ast.expr') -> 'str | None':
    """The dotted name an attribute chain spells, or :data:`None`."""
    parts = []  # type: list[str]
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return '.'.join(reversed(parts))


def calls(source: 'str', module: 'str', homes: 'dict[str, tuple[set[str], set[str]]]',
          is_package: 'bool' = False) -> 'list[tuple[int, str, str]]':
    """Every reference in ``source`` to a function of ``homes``.

    Args:
        source: Python source to read.
        module: Dotted name of the module ``source`` belongs to, for resolving
            relative imports.
        homes: The home modules, as :func:`helpers` returns them.
        is_package: Whether ``source`` is that package's :file:`__init__.py`.

    Returns:
        ``(line, home, name)`` in line order, ``home`` being the module that
        defines the function ``name``. A function reached through a package is
        reported against every home under that package defining one of its name.

    """
    found = []  # type: list[tuple[int, str, str]]
    aliases = {}  # type: dict[str, str]
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname is not None and alias.name in homes:
                    aliases[alias.asname] = alias.name
                elif alias.asname is None and alias.name.partition('.')[0] == 'pcapkit':
                    # ``import pcapkit.x`` binds ``pcapkit``, through which every
                    # loaded module reads by its dotted path.
                    for home in homes:
                        aliases.setdefault(home, home)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = _relative_base(module, is_package, node.level)
                target = f'{base}.{node.module}' if node.module else base
            else:
                target = node.module or ''
            for alias in node.names:
                if alias.name == '*':
                    if target in homes:
                        functions, exported = homes[target]
                        found.extend((node.lineno, target, name)
                                     for name in sorted(functions & exported))
                elif target in homes and alias.name in homes[target][0]:
                    found.append((node.lineno, target, alias.name))
                elif f'{target}.{alias.name}' in homes:
                    # Checked whether or not ``target`` is a home itself: a
                    # package whose ``__init__.py`` is one still hands out its
                    # submodules.
                    aliases[alias.asname or alias.name] = f'{target}.{alias.name}'
                else:
                    # A package re-exporting a function is a path to it as well.
                    found.extend((node.lineno, home, alias.name) for home in sorted(homes)
                                 if home.startswith(f'{target}.') and alias.name in homes[home][0])
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute) or not isinstance(node.ctx, ast.Load):
            continue
        base = _dotted(node.value)
        if base is not None and base in aliases and node.attr in homes[aliases[base]][0]:
            found.append((node.lineno, aliases[base], node.attr))
    return sorted(found)


def helper_imports(source: 'str', module: 'str', is_package: 'bool' = False
                   ) -> 'list[tuple[int, str]]':
    """Every import in ``source`` of a module :data:`ABOVE_HELPERS` names, outside an
    ``if TYPE_CHECKING:`` block, as ``(line, dotted name)``."""
    typing_only = _type_checking_lines(source)
    return [(line, name) for line, name in imported_names(source, module, is_package)
            if line not in typing_only
            and any(name == above or name.startswith(f'{above}.') for above in ABOVE_HELPERS)]


def allowed(caller: 'str', in_layer: 'bool', home: 'str', generic: 'set[str]') -> 'bool':
    """Whether module ``caller`` may call a function of ``home``.

    Args:
        caller: Dotted name of the calling module.
        in_layer: Whether ``caller`` is in the schema layer.
        home: Dotted name of the module defining the function.
        generic: The modules of the layer no one protocol owns.

    """
    if home in generic:
        return in_layer
    owners = SHARED.get(home, (protocol_key(home),))
    return caller == home or protocol_key(caller) in owners


def violations() -> 'list[str]':
    """Every call the ruling rules out, as ``path:line: home.name``."""
    homes = helpers(GENERIC + PROTOCOL)
    generic = {_module_name(path) for path in GENERIC}
    found = []  # type: list[str]
    for top in CALLERS:
        for path in sorted((ROOT / top).rglob('*.py')):
            caller = _module_name(path)
            for line, home, name in calls(path.read_text(encoding='utf-8'), caller, homes,
                                          is_package=path.name == '__init__.py'):
                if not allowed(caller, _in_layer(path), home, generic):
                    found.append(f'{path.relative_to(ROOT).as_posix()}:{line}: {home}.{name}')
    return found


class SchemaHelpersBoundaryTests(unittest.TestCase):
    """A schema-layer helper is called from the schema layer, or from its own protocol."""

    def test_the_walk_found_both_kinds(self) -> None:
        generic = helpers(GENERIC)
        self.assertIn('nested_packet_context', generic['pcapkit.corekit.fields.misc'][0])
        self.assertIn('schema_final', generic['pcapkit.protocols.schema.schema'][0])
        self.assertIn('schema_final', generic['pcapkit.protocols.schema.schema'][1])
        protocol = helpers(PROTOCOL)
        self.assertIn('jumbogram_error', protocol['pcapkit.protocols.schema.internet.ipv6'][0])
        self.assertIn('calipso_pad_len', protocol['pcapkit.protocols.schema.internet.ipv6_option'][0])
        self.assertNotIn('pcapkit.protocols.schema.schema', protocol)

    def test_every_call_is_one_the_ruling_allows(self) -> None:
        found = violations()
        self.assertEqual(found, [],
                         'these modules call a schema-layer helper from outside where it belongs; '
                         '#2674 moves a helper used outside the schema layer, or outside its own '
                         'protocol, to pcapkit.corekit.schema, as utilities-or-corekit.rst '
                         'records:\n' + '\n'.join(found))

    def test_the_shared_helpers_live_in_their_home(self) -> None:
        shared = helpers(tuple(sorted(HELPERS.rglob('*.py'))))
        self.assertIn('pad_length', shared['pcapkit.corekit.schema.padding'][0])
        self.assertEqual(shared['pcapkit.corekit.schema.byteorder'][0],
                         {'byteorder_callback', 'packet_byteorder'})
        self.assertIn('keep_short_read', shared['pcapkit.corekit.schema.shortread'][0])
        # No copy is left behind in a module the ruling checks.
        defined = {name for functions, _ in shared.values() for name in functions}
        for home, (functions, _) in helpers(GENERIC + PROTOCOL).items():
            with self.subTest(home=home):
                self.assertEqual(sorted(defined & functions), [])
        # And calling one is no call the ruling checks.
        source = '\n'.join([
            'from pcapkit.corekit.schema.padding import pad_length',
            'from pcapkit.corekit.schema import shortread',
            'shortread.keep_short_read(None)',
        ])
        self.assertEqual(calls(source, 'pcapkit.protocols.internet.hip', helpers(GENERIC + PROTOCOL)), [])

    def test_the_shared_helpers_import_nothing_that_imports_them(self) -> None:
        found = []  # type: list[str]
        for path in sorted(HELPERS.rglob('*.py')):
            for line, name in helper_imports(path.read_text(encoding='utf-8'), _module_name(path),
                                             path.name == '__init__.py'):
                found.append(f'{path.relative_to(ROOT).as_posix()}:{line}: {name}')
        self.assertEqual(found, [], 'these shared helpers import a module that imports them, '
                         'which makes an import cycle:\n' + '\n'.join(found))

    def test_a_helper_importing_the_fields_package_is_caught(self) -> None:
        source = '\n'.join([
            'from typing import TYPE_CHECKING',                           # 1
            'from pcapkit.corekit import fields',                         # 2
            'from pcapkit.corekit import enum as e',                      # 3
            'from pcapkit.corekit import fields as f',                    # 4
            'if TYPE_CHECKING:',                                          # 5
            '    from pcapkit.corekit import fields as typed',            # 6
            '    from pcapkit.protocols.protocol import ProtocolBase',    # 7
            'from pcapkit import protocols',                              # 8
            'def f():',                                                   # 9
            '    from pcapkit.foundation import extraction',              # 10
        ])
        self.assertEqual(helper_imports(source, 'pcapkit.corekit.schema.padding'), [
            (2, 'pcapkit.corekit.fields'),
            (4, 'pcapkit.corekit.fields'),
            (8, 'pcapkit.protocols'),
            (10, 'pcapkit.foundation'),
            (10, 'pcapkit.foundation.extraction'),
        ])

    def test_every_shared_module_is_a_family_module(self) -> None:
        # Both directions: a schema module with no protocol of its own names its
        # family here, and an entry here has no protocol of its own but members
        # that do.
        orphans = sorted(_module_name(path) for path in PROTOCOL
                         if not (ROOT / 'pcapkit' / 'protocols' / path.relative_to(SCHEMA)).exists())
        self.assertEqual(orphans, sorted(SHARED))
        for home, members in SHARED.items():
            for member in members:
                with self.subTest(home=home, member=member):
                    self.assertTrue((ROOT / 'pcapkit' / 'protocols' / f"{member.replace('.', '/')}.py")
                                    .is_file())

    def test_protocol_key(self) -> None:
        self.assertEqual(protocol_key('pcapkit.protocols.internet.ipv6'), 'internet.ipv6')
        self.assertEqual(protocol_key('pcapkit.protocols.schema.internet.ipv6'), 'internet.ipv6')
        self.assertEqual(protocol_key('pcapkit.protocols.data.misc.pcap.header'), 'misc.pcap.header')
        self.assertIsNone(protocol_key('pcapkit.toolkit.scapy'))
        self.assertIsNone(protocol_key('pcapkit.protocols'))

    def test_the_scanner_finds_every_form(self) -> None:
        homes = {
            'pcapkit.corekit.fields.ipaddress': ({'parse_ip_address', '_reject_bool'},
                                                 {'parse_ip_address', 'IPv4AddressField'}),
            'pcapkit.protocols.schema.schema': ({'keep_short_read'}, {'Schema'}),
        }
        source = '\n'.join([
            'from pcapkit.corekit.fields.ipaddress import IPv4AddressField',            # 1
            'from pcapkit.corekit.fields.ipaddress import parse_ip_address as p',       # 2
            'from ..corekit.fields.ipaddress import _reject_bool',                      # 3
            'from pcapkit.protocols.schema import keep_short_read',                     # 4
            'from pcapkit.corekit.fields.ipaddress import *',                           # 5
            'from pcapkit.corekit.fields import ipaddress',                             # 6
            'ipaddress.parse_ip_address(1, "x")',                                       # 7
            'import pcapkit.protocols.schema.schema as base',                           # 8
            'base.Schema, base.keep_short_read',                                        # 9
            'import pcapkit.corekit.fields.ipaddress',                                  # 10
            'pcapkit.corekit.fields.ipaddress.parse_ip_address(1, "x")',                # 11
            'ipaddress.IPv4AddressField',                                               # 12
            'from pcapkit.corekit.schema.ipaddress import parse_ip_address',                 # 13
            'from pcapkit.protocols.schema.schema import *',                            # 14
        ])
        self.assertEqual(calls(source, 'pcapkit.protocols.ipv4', homes), [
            (2, 'pcapkit.corekit.fields.ipaddress', 'parse_ip_address'),
            (3, 'pcapkit.corekit.fields.ipaddress', '_reject_bool'),
            (4, 'pcapkit.protocols.schema.schema', 'keep_short_read'),
            (5, 'pcapkit.corekit.fields.ipaddress', 'parse_ip_address'),
            (7, 'pcapkit.corekit.fields.ipaddress', 'parse_ip_address'),
            (9, 'pcapkit.protocols.schema.schema', 'keep_short_read'),
            (11, 'pcapkit.corekit.fields.ipaddress', 'parse_ip_address'),
        ])

    def test_a_package_that_is_a_home_hands_out_its_submodules(self) -> None:
        # ``pcapkit.corekit.fields`` is a home of its own, its ``__init__.py``
        # being a field module, so a submodule imported through it has to be
        # told apart from a function it defines.
        homes = {
            'pcapkit.corekit.fields': (set(), {'IPv4AddressField'}),
            'pcapkit.corekit.fields.ipaddress': ({'parse_ip_address'}, {'IPv4AddressField'}),
        }
        self.assertIn('pcapkit.corekit.fields', helpers(GENERIC))
        source = '\n'.join([
            'from pcapkit.corekit.fields import ipaddress',               # 1
            'ipaddress.parse_ip_address(1, "x")',                         # 2
            'from pcapkit.corekit.fields import ipaddress as ip',         # 3
            'ip.parse_ip_address(1, "x"), ip.IPv4AddressField',           # 4
            'from pcapkit.corekit.fields import parse_ip_address',        # 5
            'from pcapkit.corekit.fields import IPv4AddressField',        # 6
        ])
        self.assertEqual(calls(source, 'pcapkit.protocols.internet.hip', homes), [
            (2, 'pcapkit.corekit.fields.ipaddress', 'parse_ip_address'),
            (4, 'pcapkit.corekit.fields.ipaddress', 'parse_ip_address'),
            (5, 'pcapkit.corekit.fields.ipaddress', 'parse_ip_address'),
        ])

    def test_who_may_call_what(self) -> None:
        generic = {'pcapkit.corekit.fields.ipaddress', 'pcapkit.protocols.schema.schema'}
        ipv6 = 'pcapkit.protocols.schema.internet.ipv6'
        option = 'pcapkit.protocols.schema.internet.ipv6_option'
        cases = (
            # (caller, in the layer, home, allowed)
            ('pcapkit.protocols.schema.internet.hip', True, 'pcapkit.corekit.fields.ipaddress', True),
            ('pcapkit.protocols.internet.hip', False, 'pcapkit.corekit.fields.ipaddress', False),
            ('pcapkit.protocols.internet.ipv6', False, ipv6, True),
            ('pcapkit.protocols.data.internet.ipv6', False, ipv6, True),
            ('pcapkit.protocols.misc.checksum.ip_pseudo', False, ipv6, False),
            ('pcapkit.toolkit.scapy', False, ipv6, False),
            ('examples.generators.options', False, ipv6, False),
            ('pcapkit.protocols.schema.internet.ipv6_ext', True, ipv6, False),
            ('pcapkit.protocols.schema.internet.hopopt', True, option, True),
            ('pcapkit.protocols.schema.internet.ipv6_opts', True, option, True),
            ('pcapkit.protocols.schema.transport.tcp', True, option, False),
        )
        for caller, in_layer, home, expected in cases:
            with self.subTest(caller=caller, home=home):
                self.assertIs(allowed(caller, in_layer, home, generic), expected)


if __name__ == '__main__':
    unittest.main()
