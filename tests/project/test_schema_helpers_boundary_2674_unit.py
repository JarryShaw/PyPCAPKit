# -*- coding: utf-8 -*-
"""A schema-layer helper is called only where the ruling on #2674 lets it be.

The owner ruled on #2674 that a helper shared beyond where it belongs lives in
:mod:`pcapkit.corekit.schema`, the home of the helpers shared across the schema
layer, which any module may call; the rule is written down on
:file:`docs/source/contributing/conventions/utilities-or-corekit.rst`. Two kinds
of module are checked, by what may call the functions they define:

* **The parts of the schema layer no one protocol owns** -- every field module
  under :file:`pcapkit/corekit/fields/`, and :mod:`pcapkit.protocols.schema`.
  Only the schema layer, :file:`pcapkit/corekit/fields/` and the ``schema``
  modules under :file:`pcapkit/protocols/`, may call their functions.
* **A protocol's own schema module** -- every other ``schema`` module under
  :file:`pcapkit/protocols/`. Only that protocol may call its functions: the
  modules of its package (#2534). A family base's schema module that its
  members share names the members that may call it in :data:`SHARED`.

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

#: The field modules, the part of the schema layer outside :mod:`pcapkit.protocols`.
FIELDS = ROOT / 'pcapkit' / 'corekit' / 'fields'

#: The protocols, whose ``schema`` modules are the rest of the schema layer.
PROTOCOLS = ROOT / 'pcapkit' / 'protocols'

#: The modules of the layer no one protocol owns.
GENERIC = tuple(sorted(FIELDS.rglob('*.py'))) + (PROTOCOLS / 'schema.py',)

#: The home of the helpers shared across the schema layer, which any module may
#: call.
HELPERS = ROOT / 'pcapkit' / 'corekit' / 'schema'

#: What a shared helper may not import outside an ``if TYPE_CHECKING:`` block:
#: each imports a shared helper itself.
ABOVE_HELPERS = ('pcapkit.corekit.fields', 'pcapkit.protocols', 'pcapkit.foundation')

#: The protocols' own schema modules.
PROTOCOL = tuple(path for path in sorted(PROTOCOLS.rglob('schema.py')) if path not in GENERIC)

#: A family base's schema module its members share, mapped to the protocols of
#: the family that may call it, each as :func:`protocol_key` gives it.
SHARED = {
    # The IPv6 options [RFC 8200, section 4.2] both option headers carry.
    'pcapkit.protocols.internet.ipv6_ext.schema': ('internet.ipv6_ext', 'internet.hopopt',
                                                   'internet.ipv6_opts'),
}

#: Where a call is looked for.
CALLERS = ('pcapkit', 'examples', 'util')


def protocol_key(module: 'str') -> 'str | None':
    """The protocol ``module`` belongs to, as its path below :mod:`pcapkit.protocols`.

    A protocol's ``protocol``, ``schema`` and ``data`` modules sit in its package
    (#2534), so all three give the package's key. A module outside
    :mod:`pcapkit.protocols` belongs to no protocol.

    """
    parts = module.split('.')
    if parts[:2] != ['pcapkit', 'protocols'] or len(parts) < 3:
        return None
    rest = parts[2:-1] if len(parts) > 3 and parts[-1] in ('protocol', 'schema', 'data') \
        else parts[2:]
    return '.'.join(rest) or None


def _in_layer(path: 'pathlib.Path') -> 'bool':
    """Whether ``path`` is a source file of the schema layer."""
    return FIELDS in path.parents or (PROTOCOLS in path.parents and path.name == 'schema.py')


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
        self.assertIn('schema_final', generic['pcapkit.protocols.schema'][0])
        self.assertIn('schema_final', generic['pcapkit.protocols.schema'][1])
        protocol = helpers(PROTOCOL)
        self.assertIn('jumbogram_error', protocol['pcapkit.protocols.internet.ipv6.schema'][0])
        self.assertIn('calipso_pad_len', protocol['pcapkit.protocols.internet.ipv6_ext.schema'][0])
        self.assertNotIn('pcapkit.protocols.schema', protocol)

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
        self.assertEqual(calls(source, 'pcapkit.protocols.internet.hip.protocol', helpers(GENERIC + PROTOCOL)), [])

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
        # Every schema module sits in a protocol's package (#2534), and an entry
        # here is a family base's schema module whose members are protocols too.
        orphans = sorted(_module_name(path) for path in PROTOCOL
                         if not (path.parent / 'protocol.py').is_file())
        self.assertEqual(orphans, [])
        for home, members in SHARED.items():
            self.assertIn(home, {_module_name(path) for path in PROTOCOL})
            for member in members:
                with self.subTest(home=home, member=member):
                    self.assertTrue((PROTOCOLS / member.replace('.', '/') / 'protocol.py').is_file())

    def test_protocol_key(self) -> None:
        self.assertEqual(protocol_key('pcapkit.protocols.internet.ipv6.protocol'), 'internet.ipv6')
        self.assertEqual(protocol_key('pcapkit.protocols.internet.ipv6.schema'), 'internet.ipv6')
        self.assertEqual(protocol_key('pcapkit.protocols.misc.pcap.header.data'), 'misc.pcap.header')
        self.assertIsNone(protocol_key('pcapkit.toolkit.scapy'))
        self.assertIsNone(protocol_key('pcapkit.protocols'))

    def test_the_scanner_finds_every_form(self) -> None:
        homes = {
            'pcapkit.corekit.fields.ipaddress': ({'parse_ip_address', '_reject_bool'},
                                                 {'parse_ip_address', 'IPv4AddressField'}),
            'pcapkit.protocols.schema': ({'keep_short_read'}, {'Schema'}),
        }
        source = '\n'.join([
            'from pcapkit.corekit.fields.ipaddress import IPv4AddressField',            # 1
            'from pcapkit.corekit.fields.ipaddress import parse_ip_address as p',       # 2
            'from ..corekit.fields.ipaddress import _reject_bool',                      # 3
            'from pcapkit.protocols.schema import keep_short_read',                     # 4
            'from pcapkit.corekit.fields.ipaddress import *',                           # 5
            'from pcapkit.corekit.fields import ipaddress',                             # 6
            'ipaddress.parse_ip_address(1, "x")',                                       # 7
            'import pcapkit.protocols.schema as base',                           # 8
            'base.Schema, base.keep_short_read',                                        # 9
            'import pcapkit.corekit.fields.ipaddress',                                  # 10
            'pcapkit.corekit.fields.ipaddress.parse_ip_address(1, "x")',                # 11
            'ipaddress.IPv4AddressField',                                               # 12
            'from pcapkit.corekit.schema.ipaddress import parse_ip_address',                 # 13
            'from pcapkit.protocols.schema import *',                            # 14
        ])
        self.assertEqual(calls(source, 'pcapkit.protocols.ipv4', homes), [
            (2, 'pcapkit.corekit.fields.ipaddress', 'parse_ip_address'),
            (3, 'pcapkit.corekit.fields.ipaddress', '_reject_bool'),
            (4, 'pcapkit.protocols.schema', 'keep_short_read'),
            (5, 'pcapkit.corekit.fields.ipaddress', 'parse_ip_address'),
            (7, 'pcapkit.corekit.fields.ipaddress', 'parse_ip_address'),
            (9, 'pcapkit.protocols.schema', 'keep_short_read'),
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
        self.assertEqual(calls(source, 'pcapkit.protocols.internet.hip.protocol', homes), [
            (2, 'pcapkit.corekit.fields.ipaddress', 'parse_ip_address'),
            (4, 'pcapkit.corekit.fields.ipaddress', 'parse_ip_address'),
            (5, 'pcapkit.corekit.fields.ipaddress', 'parse_ip_address'),
        ])

    def test_who_may_call_what(self) -> None:
        generic = {'pcapkit.corekit.fields.ipaddress', 'pcapkit.protocols.schema'}
        ipv6 = 'pcapkit.protocols.internet.ipv6.schema'
        option = 'pcapkit.protocols.internet.ipv6_ext.schema'
        cases = (
            # (caller, in the layer, home, allowed)
            ('pcapkit.protocols.internet.hip.schema', True, 'pcapkit.corekit.fields.ipaddress', True),
            ('pcapkit.protocols.internet.hip.protocol', False, 'pcapkit.corekit.fields.ipaddress', False),
            ('pcapkit.protocols.internet.ipv6.protocol', False, ipv6, True),
            ('pcapkit.protocols.internet.ipv6.data', False, ipv6, True),
            ('pcapkit.protocols.misc.checksum.ip_pseudo.protocol', False, ipv6, False),
            ('pcapkit.toolkit.scapy', False, ipv6, False),
            ('examples.generators.options', False, ipv6, False),
            ('pcapkit.protocols.internet.ipv6_ext.schema', True, ipv6, False),
            ('pcapkit.protocols.internet.hopopt.schema', True, option, True),
            ('pcapkit.protocols.internet.ipv6_opts.schema', True, option, True),
            ('pcapkit.protocols.transport.tcp.schema', True, option, False),
        )
        for caller, in_layer, home, expected in cases:
            with self.subTest(caller=caller, home=home):
                self.assertIs(allowed(caller, in_layer, home, generic), expected)


if __name__ == '__main__':
    unittest.main()
