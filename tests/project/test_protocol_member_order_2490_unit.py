# -*- coding: utf-8 -*-
"""Protocol class bodies keep the member order (GitHub issue #2490).

``protocol-member-order.rst`` rules the order of the members in a protocol class
body; the owner asked on #2490 for a guard that holds it. This module audits every
class under ``pcapkit/protocols``, less the ``NotImplemented`` placeholders,
against :data:`RULES`:

* ``group`` -- properties, then public methods, then data models (every dunder),
  then utilities;
* ``data`` -- ``_make_data()`` is the first utility;
* ``pair`` -- each ``_read_xxx()`` comes before its ``_make_xxx()``;
* ``helpers`` -- rule b: the utilities the bodies of ``read()`` and ``make()`` name
  keep the order of first use, each reader directly followed by its maker. A
  registry fallback, the default of a ``getattr()`` or ``.get()`` there, is a
  specific reader rather than a helper (#2490).

Rule c, the enum-value order of the specific readers and makers, and subgroup d,
the last place of every helper ``read()``, ``make()`` and the registries do not
reach, are checked once their PRs land.

A class that breaks a rule is an entry in :data:`KNOWN_EXCEPTIONS`, with the rules
it breaks and the issue or PR whose reorder removes it. The table is checked in
both directions, as ``test-coverage.rst`` asks of its tables: a new violation fails,
and so does an entry naming a class or a rule that does not exist, or a rule its
class no longer breaks, so a reorder deletes its entry in the same change.

This module is unit-tier: it parses source and imports nothing it scans.

"""
from __future__ import annotations

import ast
import unittest
from typing import TYPE_CHECKING

from tests._tiers import ROOT

if TYPE_CHECKING:
    import pathlib
    from typing import Iterator

#: Test tier (#1958): parses every protocol module for a question about the tree,
#: which does not differ by interpreter.
__tier__ = 'LATEST'

#: The protocol package the audit walks.
PROTOCOLS = ROOT / 'pcapkit' / 'protocols'

#: Directory names the audit does not enter: placeholder sources and caches.
SKIPPED_DIRS = frozenset({'NotImplemented', '__pycache__'})

#: The member groups, in the order a class body holds them.
GROUPS = ('Properties', 'Methods', 'Data models', 'Utilities')

#: Decorators that make a member a property.
PROPERTY_DECORATORS = frozenset({'property', 'cached_property', 'getter', 'setter', 'deleter'})

#: The rules the audit checks, as ``kind: what it asks``.
RULES = {
    'group': 'properties, methods, data models, then utilities',
    'data': '_make_data() is the first utility',
    'pair': 'each _read_xxx() comes before its _make_xxx()',
    'helpers': 'the helpers read() and make() name, in first-use order, each reader then its maker',
}

#: Classes that break the order, as ``qualified name: (rules, remover)``: the
#: :data:`RULES` kinds each breaks, and the issue or PR whose reorder removes the
#: entry. ``#2490`` marks a file deferred from its reorder while another stream
#: edits it; IPv4 and TCP wait for the rule c reorders (#2490).
KNOWN_EXCEPTIONS = {
    'pcapkit.protocols.application.dtls.DTLS': (frozenset({'data'}), '#2490'),
    'pcapkit.protocols.application.ospf.OSPF': (frozenset({'helpers'}), '#2490'),
    'pcapkit.protocols.internet.igmpv3.IGMP': (frozenset({'data'}), '#2490'),
    'pcapkit.protocols.internet.ipv4.IPv4': (frozenset({'helpers'}), '#2490'),
    'pcapkit.protocols.internet.ipx.IPX': (frozenset({'helpers', 'pair'}), '#2490'),
    'pcapkit.protocols.misc.checksum.ip_pseudo.IP_Pseudo': (frozenset({'helpers'}), '#2490'),
    'pcapkit.protocols.schema.internet.igmpv3.IGMP': (frozenset({'group'}), '#2490'),
    'pcapkit.protocols.schema.internet.igmpv3.Query': (frozenset({'group'}), '#2490'),
    'pcapkit.protocols.schema.internet.igmpv3.Report': (frozenset({'group'}), '#2490'),
    'pcapkit.protocols.transport.sctp.SCTP': (frozenset({'helpers'}), '#2490'),
    'pcapkit.protocols.transport.tcp.TCP': (frozenset({'helpers'}), '#2490'),
}  # type: dict[str, tuple[frozenset[str], str]]

_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef)


def _is_dunder(name: 'str') -> 'bool':
    """Whether ``name`` is a dunder, a data-model name."""
    return len(name) > 4 and name.startswith('__') and name.endswith('__')


def _group(node: 'ast.FunctionDef | ast.AsyncFunctionDef') -> 'int':
    """The index in :data:`GROUPS` of the group ``node`` belongs to."""
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Call):
            decorator = decorator.func
        name = decorator.attr if isinstance(decorator, ast.Attribute) else getattr(decorator, 'id', None)
        if name in PROPERTY_DECORATORS:
            return 0
    if _is_dunder(node.name):
        return 2
    if node.name.startswith('_'):
        return 3
    return 1


def members(cls: 'ast.ClassDef') -> 'list[tuple[str, int]]':
    """The members of ``cls`` in body order, as ``(name, group)``.

    A function under an ``if`` in the body, such as a ``TYPE_CHECKING``
    ``__init__``, is a member where the ``if`` stands, and so is a dunder bound to
    another member (``__init__ = __update__``). Consecutive definitions of one
    name -- overloads, a property and its setter -- are one member.

    """
    found = []  # type: list[tuple[str, int]]
    for stmt in cls.body:
        if isinstance(stmt, _DEFS):
            found.append((stmt.name, _group(stmt)))
        elif isinstance(stmt, ast.If):
            found.extend((node.name, _group(node)) for node in stmt.body + stmt.orelse
                         if isinstance(node, _DEFS))
        elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 \
                and isinstance(stmt.targets[0], ast.Name) and _is_dunder(stmt.targets[0].id) \
                and isinstance(stmt.value, ast.Name) and any(name == stmt.value.id for name, _ in found):
            found.append((stmt.targets[0].id, 2))
    return [member for index, member in enumerate(found) if index == 0 or found[index - 1][0] != member[0]]


def _fallbacks(node: 'ast.AST', names: 'set[str]') -> 'set[str]':
    """The members in ``names`` that ``node`` passes as a ``getattr()`` or ``.get()`` default."""
    found = set()  # type: set[str]
    for call in ast.walk(node):
        if not isinstance(call, ast.Call):
            continue
        func = call.func
        if isinstance(func, ast.Name) and func.id == 'getattr' and len(call.args) == 3:
            default = call.args[2]  # type: ast.expr
        elif isinstance(func, ast.Attribute) and func.attr == 'get' and len(call.args) == 2:
            default = call.args[1]
        else:
            continue
        if isinstance(default, ast.Attribute) and default.attr in names:
            found.add(default.attr)
    return found


def _named(node: 'ast.AST', names: 'set[str]') -> 'list[str]':
    """The members in ``names`` that ``node`` names as an attribute, in source order."""
    refs = sorted((sub.lineno, sub.col_offset, sub.attr) for sub in ast.walk(node)
                  if isinstance(sub, ast.Attribute) and sub.attr in names)
    return list(dict.fromkeys(name for _, _, name in refs))


def _stem(name: 'str') -> 'str | None':
    """What follows ``_read_`` or ``_make_`` in ``name``, else :data:`None`."""
    return name[6:] if name.startswith(('_read_', '_make_')) else None


def helpers(cls: 'ast.ClassDef', utilities: 'list[str]') -> 'list[str]':
    """The order rule b asks of the helpers of ``cls``.

    A helper is a utility the body of ``read()`` or ``make()`` names directly,
    other than ``_make_data()`` and a registry fallback. The helpers follow the
    order of first use, ``read()`` before ``make()``, and each brings its
    ``_read_``/``_make_`` partner with it, the reader first.

    """
    bodies = {stmt.name: stmt for stmt in cls.body if isinstance(stmt, _DEFS) and stmt.name in ('read', 'make')}
    names = set(utilities) - {'_make_data'}
    used = []  # type: list[str]
    fallbacks = set()  # type: set[str]
    for entry in ('read', 'make'):
        if entry in bodies:
            used.extend(_named(bodies[entry], names))
            fallbacks |= _fallbacks(bodies[entry], names)
    order = []  # type: list[str]
    for name in used:
        if name in fallbacks:
            continue
        stem = _stem(name)
        unit = [name] if stem is None else [f'_read_{stem}', f'_make_{stem}']
        order.extend(member for member in unit
                     if member in names and member not in fallbacks and member not in order)
    return order


def audit(cls: 'ast.ClassDef') -> 'dict[str, str]':
    """The rules ``cls`` breaks, as ``kind: detail``; empty when it keeps the order."""
    order = members(cls)
    findings = {}  # type: dict[str, str]
    highest = 0
    for name, group in order:
        if group < highest:
            findings.setdefault('group', f'{name} ({GROUPS[group]}) after {GROUPS[highest]}')
        highest = max(highest, group)

    utilities = list(dict.fromkeys(name for name, group in order if group == 3))
    position = {name: index for index, name in enumerate(utilities)}
    if '_make_data' in position and utilities[0] != '_make_data':
        findings['data'] = f'{utilities[0]} before _make_data'

    for name in utilities:
        stem = _stem(name)
        maker = f'_make_{stem}'
        if name.startswith('_read_') and stem != 'data' and maker in position and position[maker] < position[name]:
            findings.setdefault('pair', f'{maker} before {name}')

    expected = helpers(cls, utilities)
    actual = [name for name in utilities if name in expected]
    if actual != expected:
        findings['helpers'] = f'expected {expected}, found {actual}'
    else:
        for name in expected:
            maker = f'_make_{_stem(name)}'
            if name.startswith('_read_') and maker in expected and position[maker] != position[name] + 1:
                findings['helpers'] = f'{name} and {maker} split by {utilities[position[name] + 1]}'
                break
    return findings


def protocol_modules(root: 'pathlib.Path' = PROTOCOLS) -> 'Iterator[pathlib.Path]':
    """Every module under ``root``, outside :data:`SKIPPED_DIRS`."""
    for path in sorted(root.rglob('*.py')):
        if not SKIPPED_DIRS.intersection(path.relative_to(root).parts):
            yield path


def classes(path: 'pathlib.Path', root: 'pathlib.Path' = ROOT) -> 'Iterator[tuple[str, ast.ClassDef]]':
    """Every class defined in ``path``, by qualified name, nested ones included."""
    module = '.'.join(path.relative_to(root).with_suffix('').parts)
    tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))

    def visit(node: 'ast.AST', prefix: 'str') -> 'Iterator[tuple[str, ast.ClassDef]]':
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                yield f'{prefix}.{child.name}', child
                yield from visit(child, f'{prefix}.{child.name}')
            else:
                yield from visit(child, prefix)

    yield from visit(tree, module)


def audit_tree(root: 'pathlib.Path' = ROOT) -> 'dict[str, dict[str, str]]':
    """Every class under ``root``'s protocol package, mapped to what :func:`audit` finds."""
    return {name: audit(node)
            for path in protocol_modules(root / 'pcapkit' / 'protocols')
            for name, node in classes(path, root)}


class TestAudit(unittest.TestCase):
    """The audit finds each rule broken in a planted class body, and nothing in a sound one."""

    #: A class body in the order: Ethernet's utilities, with a registry fallback.
    SOUND = '''
class Sound:
    @property
    def name(self): ...
    def read(self):
        self._read_addr()
        getattr(self, 'x', self._read_unknown)
    def make(self):
        self._make_addr()
    def __index__(self): ...
    @classmethod
    def _make_data(cls, data): ...
    def _read_addr(self): ...
    def _make_addr(self): ...
    def _read_unknown(self): ...
    def _make_unknown(self): ...
'''

    def check(self, source: 'str') -> 'dict[str, str]':
        node = ast.parse(source).body[0]
        assert isinstance(node, ast.ClassDef)
        return audit(node)

    def test_a_sound_class_has_no_finding(self) -> 'None':
        self.assertEqual(self.check(self.SOUND), {})

    def test_each_rule_is_found(self) -> 'None':
        planted = {
            'group': self.SOUND.replace('    def __index__(self): ...\n', '') + '    def __index__(self): ...\n',
            'data': self.SOUND.replace('    @classmethod\n    def _make_data(cls, data): ...\n', '')
            + '    @classmethod\n    def _make_data(cls, data): ...\n',
            'pair': self.SOUND.replace('    def _read_unknown(self): ...\n', '') + '    def _read_unknown(self): ...\n',
            'helpers': self.SOUND.replace('    def _make_addr(self): ...\n', '') + '    def _make_addr(self): ...\n',
        }
        self.assertEqual(sorted(planted), sorted(RULES))
        for kind, source in planted.items():
            with self.subTest(rule=kind):
                self.assertIn(kind, self.check(source))

    def test_a_fallback_is_not_a_helper(self) -> 'None':
        node = ast.parse(self.SOUND).body[0]
        assert isinstance(node, ast.ClassDef)
        utilities = [name for name, group in members(node) if group == 3]
        self.assertEqual(helpers(node, utilities), ['_read_addr', '_make_addr'])


class TestMemberOrder(unittest.TestCase):
    """Every protocol class keeps the member order, or is a recorded exception."""

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.findings = audit_tree()

    def test_every_class_keeps_the_order_or_is_recorded(self) -> 'None':
        unexpected = []  # type: list[str]
        for name, found in sorted(self.findings.items()):
            allowed = KNOWN_EXCEPTIONS.get(name, (frozenset(), ''))[0]
            unexpected.extend(f'{name} [{kind}: {RULES[kind]}] {detail}'
                              for kind, detail in sorted(found.items()) if kind not in allowed)
        self.assertEqual(unexpected, [], 'reorder the class to protocol-member-order.rst')

    def test_exceptions_name_real_classes_and_rules(self) -> 'None':
        for name, (kinds, remover) in KNOWN_EXCEPTIONS.items():
            with self.subTest(name=name):
                self.assertIn(name, self.findings)
                self.assertTrue(kinds)
                self.assertLessEqual(kinds, set(RULES))
                self.assertRegex(remover, r'^#\d+$')

    def test_exceptions_are_a_minority(self) -> 'None':
        self.assertLess(len(KNOWN_EXCEPTIONS) * 2, len(self.findings))

    def test_the_reference_is_in_order(self) -> 'None':
        name = 'pcapkit.protocols.link.ethernet.Ethernet'
        self.assertEqual(self.findings[name], {})
        self.assertNotIn(name, KNOWN_EXCEPTIONS)
        # The page's example: rule b finds the helper pair it shows.
        node = dict(classes(PROTOCOLS / 'link' / 'ethernet.py'))[name]
        utilities = [member for member, group in members(node) if group == 3]
        self.assertEqual(helpers(node, utilities), ['_read_mac_addr', '_make_mac_addr'])

    def test_every_exception_is_still_broken(self) -> 'None':
        stale = sorted(f'{name} [{kind}] ({remover})'
                       for name, (kinds, remover) in KNOWN_EXCEPTIONS.items()
                       for kind in kinds if kind not in self.findings.get(name, {}))
        self.assertEqual(stale, [], 'back in order: delete the rule from KNOWN_EXCEPTIONS')


if __name__ == '__main__':
    unittest.main()
