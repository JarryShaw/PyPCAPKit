# -*- coding: utf-8 -*-
"""Where a protocol's constants and helpers live (#2883, #2896, #2897).

The owner took option 1 on #2883, and ruled in review of #2895 the package, what
counts as a reference, that a helper follows the same rule (#2897), and that a
protocol's other constants go in its own ``const`` module (#2896); the rule is
written down on
:file:`docs/source/contributing/conventions/utilities-or-corekit.rst`. A constant
that any module outside its own protocol references -- another protocol, a
foundation module, a dumper or the toolkit -- lives in the module of
:mod:`pcapkit.corekit.const` for its topic, and such a helper -- a function or
class of a protocol's own modules other than its own structures -- in the module
of :mod:`pcapkit.corekit` or :mod:`pcapkit.utilities` for its topic. A protocol's
own ``protocol``, ``schema``, ``data`` and ``const`` modules count as one place,
and so does a family: a family base's constant or helper that its members
reference stays with the family. Every other constant of a protocol's own modules
is in its package's ``const`` module, or its family base's.

These checks pin that:

* :class:`TestNewHomes` -- each moved constant is defined in its new module, which
  exports exactly the constants moved there and imports nothing from
  :mod:`pcapkit` but :mod:`pcapkit.const`, and each moved helper is defined and
  exported in its new module;
* :class:`TestOldHomes` -- its old module neither defines nor exports it, and does
  not bind one it no longer reads;
* :class:`TestRule` -- no constant or helper a protocol's own modules define is
  referenced from outside that protocol or its family, but the helpers
  :data:`KEPT` names;
* :class:`TestProtocolConstants` -- no ``protocol``, ``schema`` or ``data``
  module of a protocol binds a constant (see :func:`not_a_constant`), and each
  ``const`` module binds constants alone, defines no function or class, exports
  its public constants and imports nothing from :mod:`pcapkit` but the registries
  and the other constant modules.

The moved names' readers and ``versionremoved`` notes are
:mod:`tests.project.test_no_moved_name_re_exports_1744_unit`'s to check, and the
constants' values :mod:`tests.project.test_rfc_constants_one_home_1739_unit`'s.
Each module is read with :mod:`ast`, except where a check asks what a module binds
at run time.

This module is unit-tier and reads no capture.

"""
from __future__ import annotations

import ast
import importlib
import pathlib
import re
import unittest
from typing import TYPE_CHECKING

from tests.project.test_protocols_import_boundary_2622_unit import _type_checking_lines
from tests.project.test_schema_helpers_boundary_2674_unit import _dotted, protocol_key
from tests.project.test_utilities_import_boundary_1735_unit import (ROOT, _module_name,
                                                                    _relative_base, imported_names)

if TYPE_CHECKING:
    from typing import Callable, Iterator, Optional

#: Test tier (#1958): reads the tree's import graph, a question about the tree.
__tier__ = 'LATEST'

#: The package of the shared constants.
CONST = ROOT / 'pcapkit' / 'corekit' / 'const'

#: The PCAP and PCAP-NG constants' home.
CAPTURE_HOME = 'pcapkit.corekit.const.capture'

#: The IPv4, IPv6 and AH header constants' home.
IPHEADER_HOME = 'pcapkit.corekit.const.ip_header'

#: The TCP header constants' home.
TCPHEADER_HOME = 'pcapkit.corekit.const.tcp_header'

#: The domain name constants' home.
DOMAIN_NAME_HOME = 'pcapkit.corekit.const.domain_name'

#: Each moved constant: its new home, its name, its old module, and whether the old
#: module still reads it, so still binds it by import.
MOVED = (
    (CAPTURE_HOME, 'MAGIC_NUMBER', 'pcapkit.protocols.misc.pcap.header.schema', True),
    (CAPTURE_HOME, 'RESOLUTION', 'pcapkit.protocols.misc.pcap.header.schema', False),
    (CAPTURE_HOME, 'RESOLUTION_PLACES', 'pcapkit.protocols.misc.pcap.header.schema', False),
    (CAPTURE_HOME, 'RECORD_HEADER_LEN', 'pcapkit.protocols.misc.pcap.frame.schema', True),
    (CAPTURE_HOME, 'BYTE_ORDER_MAGIC', 'pcapkit.protocols.misc.pcapng.schema', True),
    (CAPTURE_HOME, 'GENERIC_BLOCK_MINIMUM', 'pcapkit.protocols.misc.pcapng.schema', True),
    (CAPTURE_HOME, 'BLOCK_MINIMUM', 'pcapkit.protocols.misc.pcapng.schema', True),
    (CAPTURE_HOME, 'DEFAULT_RESOLUTION', 'pcapkit.protocols.misc.pcapng.schema', False),
    (IPHEADER_HOME, 'IP_MAX_LENGTH', 'pcapkit.protocols.internet.ipv6.schema', True),
    (IPHEADER_HOME, 'IPV4_HEADER_LEN', 'pcapkit.protocols.internet.ipv4.schema', True),
    (IPHEADER_HOME, 'IPV6_HEADER_LEN', 'pcapkit.protocols.internet.ipv6.protocol', True),
    (IPHEADER_HOME, 'IPV6_NEXT_HEADER_OFFSET', 'pcapkit.protocols.internet.ipv6.protocol', False),
    (IPHEADER_HOME, 'AH_HEADER_LEN', 'pcapkit.protocols.internet.ah.schema', True),
    (TCPHEADER_HOME, 'TCP_MIN_HEADER_LEN', 'pcapkit.protocols.transport.tcp.schema', True),
    (TCPHEADER_HOME, 'TCP_DATA_OFFSET_OCTET', 'pcapkit.protocols.transport.tcp.schema', False),
    (DOMAIN_NAME_HOME, 'POINTER_LIMIT', 'pcapkit.protocols.application.dns.const', False),
)

#: Each moved helper, as :data:`MOVED` gives a constant (#2897).
MOVED_HELPERS = (
    ('pcapkit.corekit.schema.byteorder', 'family_byteorder', 'pcapkit.protocols.link.loopback.protocol', True),
    ('pcapkit.corekit.schema.domain_name', 'read_name', 'pcapkit.protocols.application.dns.schema', False),
    ('pcapkit.corekit.schema.domain_name', 'make_name', 'pcapkit.protocols.application.dns.schema', False),
    ('pcapkit.corekit.schema.domain_name', 'name_to_text', 'pcapkit.protocols.application.dns.schema', False),
    ('pcapkit.corekit.schema.domain_name', 'text_to_labels', 'pcapkit.protocols.application.dns.schema', False),
)

#: A family base's module mapped to the members that reference its constants or
#: helpers as their own, as a family base's schema module is shared in
#: :mod:`tests.project.test_schema_helpers_boundary_2674_unit`.
FAMILIES = {
    # BOOTP and DHCPv4 subclass DHCP, whose header layout and magic cookie they share.
    'pcapkit.protocols.application.dhcp.const': ('application.bootp', 'application.dhcpv4'),
    # HTTP/1 and HTTP/2 subclass HTTP, whose patterns and preface they share.
    'pcapkit.protocols.application.http.const': ('application.httpv1', 'application.httpv2'),
    # TLS and DTLS subclass SSL, whose record content types and versions they share.
    'pcapkit.protocols.application.ssl.const': ('application.tls', 'application.dtls'),
    # HOPOPT and IPv6-Opts carry the IPv6 options [RFC 8200, section 4.2], whose
    # length callbacks they share.
    'pcapkit.protocols.internet.ipv6_ext.schema': ('internet.hopopt', 'internet.ipv6_opts'),
    # LinuxSLL1 and LinuxSLL2 subclass LinuxSLL, whose next-layer and link-address
    # checks they share.
    'pcapkit.protocols.link.linux_sll.protocol': ('link.linux_sll1', 'link.linux_sll2'),
}

#: Helpers a ruling keeps beside their protocol whoever references them, by module.
KEPT = {
    # #2580: the IP pseudo-header stays in pcapkit.protocols.misc.checksum, which
    # the IP layers and the layers above them build their checksums through.
    'pcapkit.protocols.misc.checksum.ip_pseudo.protocol': ('compute_upper', 'pseudo_header',
                                                          'verify_upper'),
}

#: Names a protocol's own modules bind that :func:`not_a_constant` cannot tell
#: from a constant but that hold run-time state, by module (#2896).
STATE = {
    # A lock the PDU decoder is held under, not a value.
    'pcapkit.protocols.application.ngap.protocol': ('_PDU_LOCK',),
}

#: The bases of a protocol's own structures: its dissector, header schemas and
#: data models.
STRUCTURES = ('pcapkit.protocols.protocol.ProtocolBase', 'pcapkit.protocols.schema.Schema',
              'pcapkit.corekit.infoclass.Info')

#: A module-level constant's name.
CONSTANT = re.compile(r'^_?[A-Z][A-Z0-9_]*$')

#: The trees read: all of :mod:`pcapkit` but the generated ones.
SKIP = ('vendor', 'const')


def _path(module: 'str') -> 'pathlib.Path':
    """The source file of ``module``."""
    return ROOT / (module.replace('.', '/') + '.py')


def _bindings(tree: 'ast.Module') -> 'Iterator[tuple[str, Optional[ast.expr]]]':
    """Each name a module assigns at its top level, a tuple's included, with the
    value assigned, :class:`~typing.TypeVar` aside."""
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value  # type: list[ast.expr], Optional[ast.expr]
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        else:
            continue
        if isinstance(value, ast.Call) and getattr(value.func, 'id', None) == 'TypeVar':
            continue
        for target in targets:
            elts = target.elts if isinstance(target, (ast.Tuple, ast.List)) else [target]
            yield from ((elt.id, value) for elt in elts if isinstance(elt, ast.Name))


def _assigned(tree: 'ast.Module') -> 'set[str]':
    """Names a module assigns at its top level, :class:`~typing.TypeVar` aside."""
    return {name for name, _ in _bindings(tree)}


def _defined(body: 'list[ast.stmt]') -> 'set[str]':
    """Functions and classes a module body defines, in its top-level ``if`` and
    ``try`` blocks too, as a ``TYPE_CHECKING`` :class:`~typing.TypedDict` is."""
    names = set()  # type: set[str]
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.If):
            names |= _defined(node.body) | _defined(node.orelse)
        elif isinstance(node, ast.Try):
            names |= _defined(node.body) | _defined(node.orelse) | _defined(node.finalbody)
            for handler in node.handlers:
                names |= _defined(handler.body)
    return names


def _all(module: 'str') -> 'list[str]':
    """The ``__all__`` of ``module``, imported."""
    return list(importlib.import_module(module).__all__)


def sources() -> 'dict[str, str]':
    """Every module the rule reads, by dotted name, mapped to its source."""
    found = {}  # type: dict[str, str]
    for path in sorted((ROOT / 'pcapkit').rglob('*.py')):
        if path.relative_to(ROOT / 'pcapkit').parts[0] not in SKIP:
            found[_module_name(path)] = path.read_text(encoding='utf-8')
    return found


def owned(module: 'str') -> 'bool':
    """Whether ``module`` is a protocol's own ``protocol``, ``schema``, ``data`` or ``const`` module."""
    parts = module.split('.')
    return parts[:2] == ['pcapkit', 'protocols'] and len(parts) > 3 \
        and parts[-1] in ('protocol', 'schema', 'data', 'const')


def const_module(module: 'str') -> 'bool':
    """Whether ``module`` is a protocol's own ``const`` module (#2896)."""
    return owned(module) and module.rpartition('.')[2] == 'const'


def constant_source(name: 'str') -> 'bool':
    """Whether a constant may be built from the module or name ``name`` imports: one
    outside :mod:`pcapkit`, a registry, a shared constant or a protocol's constant."""
    parts = name.split('.')
    return parts[0] != 'pcapkit' or parts[:2] == ['pcapkit', 'const'] \
        or parts[:3] == ['pcapkit', 'corekit', 'const'] \
        or any(const_module('.'.join(parts[:end])) for end in range(4, len(parts) + 1))


def constants(trees: 'dict[str, ast.Module]') -> 'dict[str, set[str]]':
    """Each protocol's own module mapped to the constants it defines."""
    return {module: {name for name in _assigned(tree) if CONSTANT.match(name)}
            for module, tree in trees.items() if owned(module)}


def _top_level(body: 'list[ast.stmt]') -> 'Iterator[ast.stmt]':
    """The statements of a module body, in its top-level ``if`` and ``try`` blocks too."""
    for node in body:
        yield node
        if isinstance(node, (ast.If, ast.Try)):
            yield from _top_level(node.body + node.orelse + getattr(node, 'finalbody', []))
            for handler in getattr(node, 'handlers', ()):
                yield from _top_level(handler.body)


def _imports(module: 'str', tree: 'ast.Module') -> 'dict[str, str]':
    """Each name ``tree`` binds by a top-level import mapped to what it imports."""
    found = {}  # type: dict[str, str]
    for node in _top_level(tree.body):
        if isinstance(node, ast.Import):
            found.update((alias.asname or alias.name.partition('.')[0],
                          alias.name if alias.asname else alias.name.partition('.')[0])
                         for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            target = node.module or ''
            if node.level:
                base = _relative_base(module, False, node.level)
                target = f'{base}.{target}' if target else base
            found.update((alias.asname or alias.name, f'{target}.{alias.name}') for alias in node.names)
    return found


def classify(module: 'str', tree: 'ast.Module') -> 'dict[str, Optional[str]]':
    """Each name of :data:`CONSTANT`'s form ``module`` binds at its top level mapped
    to why it is not a constant (#2896), or :data:`None` where it is one.

    It is not one where its value is a lazy import, a
    :class:`~pcapkit.corekit.module.ModuleDescriptor` call; where the module rebinds
    it under ``global`` or :data:`STATE` lists it, as run-time state; or where its
    value reads a function, a class or another name the module assigns that is not
    a constant, or a name the module imports from :mod:`pcapkit` other than a
    :func:`constant_source` -- a field, a schema, a data model -- which a ``const``
    module could not import without importing its own protocol back.

    """
    readable = {name: constant_source(target) for name, target in _imports(module, tree).items()}
    readable.update((name, False) for name in _defined(tree.body))
    rebound = {name for node in ast.walk(tree) if isinstance(node, ast.Global) for name in node.names}
    found = {}  # type: dict[str, Optional[str]]
    for name, value in _bindings(tree):
        reason = None  # type: Optional[str]
        nodes = list(ast.walk(value)) if value is not None else []
        local = {node.id for node in nodes if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)}
        local.update(arg.arg for node in nodes if isinstance(node, ast.Lambda) for arg in node.args.args)
        if any(isinstance(node, ast.Call) and _descriptor(node) is not None for node in nodes):
            reason = 'a lazy import'
        elif name in rebound or name in STATE.get(module, ()):
            reason = 'run-time state'
        else:
            reason = next((f'built from {node.id}' for node in nodes if isinstance(node, ast.Name)
                           and node.id not in local and not readable.get(node.id, True)), None)
        readable[name] = reason is None and CONSTANT.match(name) is not None
        if CONSTANT.match(name):
            found[name] = reason
    return found


def own_constants(trees: 'dict[str, ast.Module]') -> 'dict[str, set[str]]':
    """Each protocol's own ``protocol``, ``schema`` and ``data`` module mapped to the
    constants it binds, which its package's ``const`` module should (#2896)."""
    return {module: {name for name, reason in classify(module, tree).items() if reason is None}
            for module, tree in trees.items() if owned(module) and not const_module(module)}


def helpers(trees: 'dict[str, ast.Module]') -> 'dict[str, set[str]]':
    """Each protocol's own module mapped to the functions and classes it defines,
    its own structures among them, which :func:`kept` tells apart."""
    return {module: _defined(tree.body) for module, tree in trees.items() if owned(module)}


def structure(module: 'str', name: 'str') -> 'bool':
    """Whether ``name`` of ``module`` is one of the classes a protocol is made of:
    a dissector, a header schema or a data model (#2534), imported to tell.

    The bases are matched by name, so a module imported again by an earlier test
    still matches.

    """
    value = getattr(importlib.import_module(module), name, None)
    return isinstance(value, type) and any(f'{base.__module__}.{base.__qualname__}' in STRUCTURES
                                           for base in value.__mro__)


def kept(module: 'str', name: 'str') -> 'bool':
    """Whether helper ``name`` of ``module`` stays beside its protocol whoever reads it."""
    return name in KEPT.get(module, ()) or structure(module, name)


def _descriptor(node: 'ast.Call') -> 'tuple[str, str] | None':
    """The module and name a literal :class:`~pcapkit.corekit.module.ModuleDescriptor` names."""
    if getattr(node.func, 'id', getattr(node.func, 'attr', None)) != 'ModuleDescriptor':
        return None
    args = dict(zip(('module', 'name'), node.args))
    args.update((keyword.arg, keyword.value) for keyword in node.keywords if keyword.arg)
    module, name = args.get('module'), args.get('name')
    if isinstance(module, ast.Constant) and isinstance(name, ast.Constant) \
            and isinstance(module.value, str) and isinstance(name.value, str):
        return module.value, name.value
    return None


def reads(trees: 'dict[str, ast.Module]',
          defined: 'dict[str, set[str]]') -> 'dict[tuple[str, str], set[str]]':
    """Each name of ``defined``, keyed by its module, mapped to the modules referencing it.

    A name is referenced by importing it, absolutely or relatively, by a literal
    :class:`~pcapkit.corekit.module.ModuleDescriptor` naming it, as the lazy
    imports do, or as an attribute of its module reached through any name an
    import binds: ``from pcapkit.protocols.internet.ipv6 import protocol``,
    ``import pcapkit.protocols.internet.ipv6.protocol`` read by its dotted path,
    or ``from pcapkit.protocols.misc.pcap import header`` read as
    ``header.schema.NAME``.

    """
    found = {}  # type: dict[tuple[str, str], set[str]]
    for reader, tree in trees.items():
        is_package = any(other.startswith(f'{reader}.') for other in trees)
        aliases = {}  # type: dict[str, str]
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    bound = alias.asname or alias.name.partition('.')[0]
                    aliases[bound] = alias.name if alias.asname else bound
            elif isinstance(node, ast.ImportFrom):
                target = node.module or ''
                if node.level:
                    base = _relative_base(reader, is_package, node.level)
                    target = f'{base}.{target}' if target else base
                for alias in node.names:
                    if alias.name in defined.get(target, ()):
                        found.setdefault((target, alias.name), set()).add(reader)
                    else:
                        aliases[alias.asname or alias.name] = f'{target}.{alias.name}'
            elif isinstance(node, ast.Call):
                named = _descriptor(node)
                if named is not None and named[1] in defined.get(named[0], ()):
                    found.setdefault(named, set()).add(reader)
        for node in ast.walk(tree):
            base = _dotted(node.value) if isinstance(node, ast.Attribute) else None
            if base is None or base.partition('.')[0] not in aliases:
                continue
            head, _, rest = base.partition('.')
            module = f'{aliases[head]}.{rest}' if rest else aliases[head]
            if node.attr in defined.get(module, ()):
                found.setdefault((module, node.attr), set()).add(reader)
    return found


def offenders(trees: 'dict[str, ast.Module]', defined: 'dict[str, set[str]]',
              exempt: 'Optional[Callable[[str, str], bool]]' = None) -> 'list[str]':
    """Every name of ``defined`` referenced from outside its own protocol or family,
    but those the ``exempt(module, name)`` callable keeps."""
    found = []  # type: list[str]
    for (home, name), readers in sorted(reads(trees, defined).items()):
        place = {protocol_key(home), *FAMILIES.get(home, ())}
        outside = sorted(reader for reader in readers if protocol_key(reader) not in place)
        if outside and not (exempt is not None and exempt(home, name)):
            found.append(f'{home}.{name}: read by {", ".join(outside)}')
    return found


class TestNewHomes(unittest.TestCase):
    """Each moved constant and helper is defined and exported in its new home."""

    def test_defined_there(self) -> 'None':
        for home, name, _, _ in MOVED:
            with self.subTest(home=home, name=name):
                self.assertIn(name, _assigned(ast.parse(_path(home).read_text(encoding='utf-8'))))

    def test_exported_there_and_nothing_else(self) -> 'None':
        for home in (CAPTURE_HOME, IPHEADER_HOME, TCPHEADER_HOME, DOMAIN_NAME_HOME):
            with self.subTest(home=home):
                moved = sorted(name for new, name, _, _ in MOVED if new == home)
                self.assertEqual(sorted(_all(home)), moved)

    def test_helpers_defined_and_exported_there(self) -> 'None':
        for home, name, _, _ in MOVED_HELPERS:
            with self.subTest(home=home, name=name):
                self.assertIn(name, _defined(ast.parse(_path(home).read_text(encoding='utf-8')).body))
                self.assertIn(name, _all(home))

    def test_homes_import_only_the_registries(self) -> 'None':
        # NOTE: every layer imports these modules, so one importing a protocol, a
        # field or the foundation back would make a cycle.
        found = []  # type: list[str]
        for path in sorted(CONST.rglob('*.py')):
            source = path.read_text(encoding='utf-8')
            typing_only = _type_checking_lines(source)
            for line, name in imported_names(source, _module_name(path), path.name == '__init__.py'):
                if (line not in typing_only and name.partition('.')[0] == 'pcapkit'
                        and name != 'pcapkit.const' and not name.startswith('pcapkit.const.')):
                    found.append(f'{path.relative_to(ROOT)}:{line}: {name}')
        self.assertEqual(found, [])
        self.assertEqual(_all('pcapkit.corekit.const'), [])


class TestOldHomes(unittest.TestCase):
    """The old module keeps no definition, export or unread binding of a moved name."""

    def test_not_defined_or_exported(self) -> 'None':
        for _, name, old, _ in MOVED:
            with self.subTest(old=old, name=name):
                self.assertNotIn(name, _assigned(ast.parse(_path(old).read_text(encoding='utf-8'))))
                self.assertNotIn(name, _all(old))
        for _, name, old, _ in MOVED_HELPERS:
            with self.subTest(old=old, name=name):
                self.assertNotIn(name, _defined(ast.parse(_path(old).read_text(encoding='utf-8')).body))
                self.assertNotIn(name, _all(old))

    def test_unread_names_are_not_bound(self) -> 'None':
        for home, name, old, used in MOVED + MOVED_HELPERS:
            with self.subTest(old=old, name=name):
                module = importlib.import_module(old)
                if used:
                    self.assertIs(getattr(module, name), getattr(importlib.import_module(home), name))
                else:
                    self.assertFalse(hasattr(module, name))


class TestRule(unittest.TestCase):
    """No constant or helper referenced beyond its own protocol or family is left beside it."""

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.trees = {module: ast.parse(text) for module, text in sources().items()}

    def test_shared_constants_are_in_corekit_const(self) -> 'None':
        self.assertEqual(offenders(self.trees, constants(self.trees)), [],
                         'move each to pcapkit.corekit.const (#2883)')

    def test_shared_helpers_are_in_a_common_home(self) -> 'None':
        self.assertEqual(offenders(self.trees, helpers(self.trees), kept), [],
                         'move each to a topic module of pcapkit.corekit or pcapkit.utilities, '
                         'as utilities-or-corekit.rst places it (#2897)')

    def test_every_family_exempts_a_read(self) -> 'None':
        # NOTE: also keeps the checks above from passing on a sweep that finds no
        # reference beyond a protocol at all.
        found = {**reads(self.trees, constants(self.trees)), **reads(self.trees, helpers(self.trees))}
        for home, members in FAMILIES.items():
            with self.subTest(home=home):
                self.assertTrue(any(protocol_key(reader) in members
                                    for (module, _), readers in found.items() if module == home
                                    for reader in readers))

    def test_every_kept_helper_is_read_beyond_its_protocol(self) -> 'None':
        # NOTE: an entry nothing outside its protocol reads any more exempts nothing.
        found = reads(self.trees, helpers(self.trees))
        for home, names in KEPT.items():
            for name in names:
                with self.subTest(home=home, name=name):
                    self.assertFalse(structure(home, name))
                    self.assertTrue(any(protocol_key(reader) != protocol_key(home)
                                        for reader in found.get((home, name), ())))

    def test_structures_are_not_helpers(self) -> 'None':
        for home, name in (('pcapkit.protocols.link.loopback.protocol', 'Loopback'),
                           ('pcapkit.protocols.internet.ipv4.schema', 'IPv4'),
                           ('pcapkit.protocols.application.httpv2.data', 'Settings')):
            with self.subTest(home=home, name=name):
                self.assertTrue(structure(home, name))
        for home, name in (('pcapkit.protocols.misc.pcapng.schema', 'OptionAreaField'),
                           ('pcapkit.protocols.misc.pcapng.protocol', 'PacketDirection'),
                           ('pcapkit.protocols.link.linux_sll.protocol', '_validate_link_addr')):
            with self.subTest(home=home, name=name):
                self.assertFalse(structure(home, name))

    def test_the_rule_flags_what_it_should(self) -> 'None':
        texts = {
            'pcapkit.protocols.internet.ipv6.schema': 'LIMIT = 1\nOWN = 2\nRELATIVE = 3\n',
            'pcapkit.protocols.internet.ipv6.protocol': 'from .schema import OWN\n',
            'pcapkit.protocols.internet.icmpv6.schema':
                'from pcapkit.protocols.internet.ipv6 import schema\nschema.LIMIT\n',
            'pcapkit.protocols.internet.icmpv6.protocol': 'from ..ipv6.schema import RELATIVE\n',
            'pcapkit.protocols.application.ssl.const': 'SHARED = 1\nTOOL = 2\n',
            'pcapkit.protocols.application.tls.protocol':
                'from pcapkit.protocols.application.ssl.const import SHARED\n',
            'pcapkit.toolkit.pcap': 'import pcapkit.protocols.application.ssl.const as ssl\nssl.TOOL\n',
            'pcapkit.protocols.transport.tcp.schema': 'WIDTH = 1\n',
            'pcapkit.foundation.reassembly.tcp.reassembly':
                'import pcapkit.protocols.transport.tcp.schema\npcapkit.protocols.transport.tcp.schema.WIDTH\n',
            'pcapkit.protocols.misc.pcap.header.schema': 'MAGIC = 1\n',
            'pcapkit.dumpkit.pcap': 'from pcapkit.protocols.misc.pcap import header\nheader.schema.MAGIC\n',
        }
        trees = {module: ast.parse(text) for module, text in texts.items()}
        self.assertEqual(offenders(trees, constants(trees)), [
            'pcapkit.protocols.application.ssl.const.TOOL: read by pcapkit.toolkit.pcap',
            'pcapkit.protocols.internet.ipv6.schema.LIMIT: read by pcapkit.protocols.internet.icmpv6.schema',
            'pcapkit.protocols.internet.ipv6.schema.RELATIVE: read by pcapkit.protocols.internet.icmpv6.protocol',
            'pcapkit.protocols.misc.pcap.header.schema.MAGIC: read by pcapkit.dumpkit.pcap',
            'pcapkit.protocols.transport.tcp.schema.WIDTH: read by pcapkit.foundation.reassembly.tcp.reassembly',
        ])

    def test_the_helper_rule_flags_what_it_should(self) -> 'None':
        texts = {
            'pcapkit.protocols.link.loopback.protocol':
                'def order(): ...\ndef own(): ...\nclass Loopback: ...\n'
                'if TYPE_CHECKING:\n    class Typed: ...\n',
            'pcapkit.protocols.link.loopback.schema': 'from .protocol import own\n',
            'pcapkit.foundation.engines.dpkt':
                'from pcapkit.protocols.link.loopback.protocol import Loopback, Typed\n'
                'from pcapkit.protocols.link.loopback import protocol\nprotocol.order\n',
            'pcapkit.protocols.link.linux_sll.protocol': 'def _check(): ...\ndef _lazy(): ...\n',
            'pcapkit.protocols.link.linux_sll2.protocol':
                'from pcapkit.protocols.link.linux_sll.protocol import _check\n',
            'pcapkit.protocols.internet.ipv4.protocol':
                'ModuleDescriptor("pcapkit.protocols.link.linux_sll.protocol", "_lazy")\n'
                'ModuleDescriptor(module="pcapkit.protocols.link.loopback.protocol", name="own")\n',
            'pcapkit.protocols.misc.checksum.ip_pseudo.protocol': 'def pseudo_header(): ...\n',
            'pcapkit.protocols.transport.udp.protocol':
                'from pcapkit.corekit.module import ModuleDescriptor\n'
                "ModuleDescriptor('pcapkit.protocols.misc.checksum.ip_pseudo.protocol', 'pseudo_header')\n",
        }
        trees = {module: ast.parse(text) for module, text in texts.items()}

        def exempt(module: 'str', name: 'str') -> 'bool':
            return name == 'Loopback' or name in KEPT.get(module, ())

        self.assertEqual(offenders(trees, helpers(trees), exempt), [
            'pcapkit.protocols.link.linux_sll.protocol._lazy: read by pcapkit.protocols.internet.ipv4.protocol',
            'pcapkit.protocols.link.loopback.protocol.Typed: read by pcapkit.foundation.engines.dpkt',
            'pcapkit.protocols.link.loopback.protocol.order: read by pcapkit.foundation.engines.dpkt',
            'pcapkit.protocols.link.loopback.protocol.own: read by pcapkit.protocols.internet.ipv4.protocol',
        ])


class TestProtocolConstants(unittest.TestCase):
    """A protocol's own constants are in its package's ``const`` module (#2896)."""

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.trees = {module: ast.parse(text) for module, text in sources().items()}
        cls.homes = sorted(module for module in cls.trees if const_module(module))

    def test_constants_are_in_const_modules(self) -> 'None':
        found = sorted(f'{module}.{name}' for module, names in own_constants(self.trees).items()
                       for name in names)
        self.assertEqual(found, [], "move each to its package's const module, or its family "
                                    "base's (#2896)")

    def test_const_modules_bind_constants_alone(self) -> 'None':
        self.assertTrue(self.homes)
        for module in self.homes:
            tree = self.trees[module]
            with self.subTest(module=module):
                self.assertEqual(_defined(tree.body), set())
                self.assertEqual({name for name in _assigned(tree) if not CONSTANT.match(name)},
                                 {'__all__'})
                self.assertEqual({name: reason for name, reason in classify(module, tree).items()
                                  if reason is not None}, {})

    def test_const_modules_export_their_public_constants(self) -> 'None':
        for module in self.homes:
            with self.subTest(module=module):
                public = sorted(name for name in _assigned(self.trees[module]) if not name.startswith('_'))
                self.assertEqual(sorted(_all(module)), public)

    def test_const_modules_import_only_constants(self) -> 'None':
        # NOTE: their protocol, schema and data modules import them, so one
        # importing any of those back would make a cycle.
        found = []  # type: list[str]
        for module in self.homes:
            path = _path(module)
            source = path.read_text(encoding='utf-8')
            typing_only = _type_checking_lines(source)
            for line, name in imported_names(source, module):
                if line not in typing_only and not constant_source(name):
                    found.append(f'{path.relative_to(ROOT)}:{line}: {name}')
        self.assertEqual(found, [])

    def test_every_state_entry_is_bound(self) -> 'None':
        # NOTE: an entry for a name its module no longer binds exempts nothing.
        for module, names in STATE.items():
            for name in names:
                with self.subTest(module=module, name=name):
                    self.assertIn(name, _assigned(self.trees[module]))

    def test_the_const_rule_flags_what_it_should(self) -> 'None':
        texts = {
            'pcapkit.protocols.link.ethernet.schema': (
                'import re\n'
                'from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType\n'
                'from pcapkit.corekit.const.capture import MAGIC_NUMBER\n'
                'from pcapkit.corekit.fields.numbers import EnumField\n'
                'from pcapkit.corekit.module import ModuleDescriptor\n'
                'from pcapkit.protocols.link.ethernet.data import Ethernet as Data_Ethernet\n'
                'from pcapkit.protocols.link.vlan.const import WIDTH\n'
                'LENGTH = 14\n'
                'PAIR, OTHER = 1, 2\n'
                'PATTERN = re.compile(rb"x")\n'
                'TYPES = frozenset({Enum_EtherType.IPv4})\n'
                'TABLE = {key: LENGTH + WIDTH for key in MAGIC_NUMBER}\n'
                '_LAZY = ModuleDescriptor("pcapkit.protocols.misc.raw.protocol", "Raw")\n'
                '_FIELD = EnumField(length=2, namespace=Enum_EtherType)\n'
                '_DATA = Data_Ethernet\n'
                '_FROM_FIELD = _FIELD.length\n'
                '_CACHE = None\n'
                'def load():\n    global _CACHE\n    _CACHE = 1\n'
                'class Suite: ...\n'
                'SUITES = {1: Suite()}\n'
            ),
            'pcapkit.protocols.link.ethernet.const': 'TAG = 6\n',
            'pcapkit.protocols.application.ngap.protocol': 'import threading\n_PDU_LOCK = threading.Lock()\n',
        }
        trees = {module: ast.parse(text) for module, text in texts.items()}
        self.assertEqual({module: sorted(names) for module, names in own_constants(trees).items()}, {
            'pcapkit.protocols.application.ngap.protocol': [],
            'pcapkit.protocols.link.ethernet.schema': ['LENGTH', 'OTHER', 'PAIR', 'PATTERN', 'TABLE', 'TYPES'],
        })
        self.assertEqual(classify('pcapkit.protocols.link.ethernet.schema',
                                  trees['pcapkit.protocols.link.ethernet.schema'])['_FROM_FIELD'],
                         'built from _FIELD')


if __name__ == '__main__':
    unittest.main()
