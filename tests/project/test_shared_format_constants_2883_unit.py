# -*- coding: utf-8 -*-
"""A constant or helper referenced beyond its protocol lives in :mod:`pcapkit.corekit` (#2883, #2897).

The owner took option 1 on #2883, and ruled in review of #2895 the package, what
counts as a reference, and that a helper follows the same rule (#2897); the rule
is written down on
:file:`docs/source/contributing/conventions/utilities-or-corekit.rst`. A constant
that any module outside its own protocol references -- another protocol, a
foundation module, a dumper or the toolkit -- lives in the module of
:mod:`pcapkit.corekit.const` for its topic, and such a helper -- a function or
class of a protocol's own modules other than its own structures -- in the module
of :mod:`pcapkit.corekit` or :mod:`pcapkit.utilities` for its topic. A protocol's
own ``protocol``, ``schema`` and ``data`` modules count as one place, and so does
a family: a family base's constant or helper that its members reference stays
with the family.

These checks pin that:

* :class:`TestNewHomes` -- each moved constant is defined in its new module, which
  exports exactly the constants moved there and imports nothing from
  :mod:`pcapkit` but :mod:`pcapkit.const`, and each moved helper is defined and
  exported in its new module;
* :class:`TestOldHomes` -- its old module neither defines nor exports it, and does
  not bind one it no longer reads;
* :class:`TestRule` -- no constant or helper a protocol's own modules define is
  referenced from outside that protocol or its family, but the helpers
  :data:`KEPT` names.

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
    from typing import Callable, Optional

#: Test tier (#1958): reads the tree's import graph, a question about the tree.
__tier__ = 'LATEST'

#: The package of the shared constants.
CONST = ROOT / 'pcapkit' / 'corekit' / 'const'

#: The PCAP and PCAP-NG constants' home.
CAPTURE_HOME = 'pcapkit.corekit.const.capture'

#: The IPv4, IPv6 and AH header constants' home.
IPHEADER_HOME = 'pcapkit.corekit.const.ipheader'

#: The TCP header constants' home.
TCPHEADER_HOME = 'pcapkit.corekit.const.tcpheader'

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
)

#: Each moved helper, as :data:`MOVED` gives a constant (#2897).
MOVED_HELPERS = (
    ('pcapkit.corekit.schema.byteorder', 'family_byteorder', 'pcapkit.protocols.link.loopback.protocol', True),
)

#: A family base's module mapped to the members that reference its constants or
#: helpers as their own, as a family base's schema module is shared in
#: :mod:`tests.project.test_schema_helpers_boundary_2674_unit`.
FAMILIES = {
    # HTTP/1 and HTTP/2 subclass HTTP, whose patterns and preface they share.
    'pcapkit.protocols.application.http.protocol': ('application.httpv1', 'application.httpv2'),
    # TLS and DTLS subclass SSL, whose record content types and versions they share.
    'pcapkit.protocols.application.ssl.protocol': ('application.tls', 'application.dtls'),
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


def _assigned(tree: 'ast.Module') -> 'set[str]':
    """Names a module assigns at its top level, :class:`~typing.TypeVar` aside."""
    names = set()  # type: set[str]
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        else:
            continue
        if isinstance(value, ast.Call) and getattr(value.func, 'id', None) == 'TypeVar':
            continue
        names.update(target.id for target in targets if isinstance(target, ast.Name))
    return names


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
    """Whether ``module`` is a protocol's own ``protocol``, ``schema`` or ``data`` module."""
    parts = module.split('.')
    return parts[:2] == ['pcapkit', 'protocols'] and len(parts) > 3 \
        and parts[-1] in ('protocol', 'schema', 'data')


def constants(trees: 'dict[str, ast.Module]') -> 'dict[str, set[str]]':
    """Each protocol's own module mapped to the constants it defines."""
    return {module: {name for name in _assigned(tree) if CONSTANT.match(name)}
            for module, tree in trees.items() if owned(module)}


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
        for home in (CAPTURE_HOME, IPHEADER_HOME, TCPHEADER_HOME):
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
            'pcapkit.protocols.application.ssl.protocol': 'SHARED = 1\nTOOL = 2\n',
            'pcapkit.protocols.application.tls.protocol':
                'from pcapkit.protocols.application.ssl.protocol import SHARED\n',
            'pcapkit.toolkit.pcap': 'import pcapkit.protocols.application.ssl.protocol as ssl\nssl.TOOL\n',
            'pcapkit.protocols.transport.tcp.schema': 'WIDTH = 1\n',
            'pcapkit.foundation.reassembly.tcp':
                'import pcapkit.protocols.transport.tcp.schema\npcapkit.protocols.transport.tcp.schema.WIDTH\n',
            'pcapkit.protocols.misc.pcap.header.schema': 'MAGIC = 1\n',
            'pcapkit.dumpkit.pcap': 'from pcapkit.protocols.misc.pcap import header\nheader.schema.MAGIC\n',
        }
        trees = {module: ast.parse(text) for module, text in texts.items()}
        self.assertEqual(offenders(trees, constants(trees)), [
            'pcapkit.protocols.application.ssl.protocol.TOOL: read by pcapkit.toolkit.pcap',
            'pcapkit.protocols.internet.ipv6.schema.LIMIT: read by pcapkit.protocols.internet.icmpv6.schema',
            'pcapkit.protocols.internet.ipv6.schema.RELATIVE: read by pcapkit.protocols.internet.icmpv6.protocol',
            'pcapkit.protocols.misc.pcap.header.schema.MAGIC: read by pcapkit.dumpkit.pcap',
            'pcapkit.protocols.transport.tcp.schema.WIDTH: read by pcapkit.foundation.reassembly.tcp',
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


if __name__ == '__main__':
    unittest.main()
