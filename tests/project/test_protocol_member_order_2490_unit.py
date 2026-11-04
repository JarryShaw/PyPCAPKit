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
  specific reader rather than a helper (#2490);
* ``specific`` -- rule c: the readers and makers of each method registry follow the
  helpers, every registry's readers before any registry's makers (#2772), each set
  opening with the registry's default and then in the registry's order;
* ``unreached`` -- subgroup d: every utility that ``read()``, ``make()`` and the
  registries do not reach comes after all those they do;
* ``registry`` -- a registry map's entries are in the order of their keys' values:
  an enum member's value, an :class:`int` key's own, a PCAP-NG option key's
  namespace and then its value, or a :obj:`str` key alphabetically within the group
  a comment line opens (#2772, #2773);
* ``layer`` -- each entry of ``ProtocolBase.__registry__`` is under the comment of
  its module's layer, the layers in the order of :data:`LAYERS` (#2773).

A method registry is a class-level dunder map, other than ``__proto__``, whose
:obj:`str` values name the ``_read_*`` and ``_make_*`` methods an f-string in the
class builds. Ordered by value, a registry also orders rule c by enum value, as the
page asks. ``registry`` checks ``__proto__``, every method registry and every map
keyed by :obj:`str` alone; a key the audit cannot value leaves its map out, and
rule c then follows the registry's own order.

A class that breaks a rule is an entry in :data:`KNOWN_EXCEPTIONS`, with the rules
it breaks and the issue or PR whose reorder removes it. The table is checked in
both directions, as ``test-coverage.rst`` asks of its tables: a new violation fails,
and so does an entry naming a class or a rule that does not exist, or a rule its
class no longer breaks, so a reorder deletes its entry in the same change.

This module is unit-tier: it parses source and imports nothing it scans. To value
an enum key it imports the :mod:`pcapkit.const` module the scanned module imports
the enum from.

"""
from __future__ import annotations

import ast
import enum
import importlib
import unittest
from typing import TYPE_CHECKING

from tests._tiers import ROOT

if TYPE_CHECKING:
    import pathlib
    from typing import Any, Callable, Iterator, Optional, Sequence

    #: Resolves a name in a scanned module to the object it imports, else :data:`None`.
    Lookup = Callable[[str], Optional[Any]]

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
    'specific': "after the helpers, every registry's readers then every registry's makers, default first, "
                'in registry order',
    'unreached': 'the utilities read(), make() and the registries do not reach come last',
    'registry': "a registry map's entries in the order of their keys: enum or int values, namespace then "
                'value, or str keys alphabetically within each commented group',
    'layer': "each __registry__ entry under its layer's comment, the layers in order",
}

#: The comment each entry of ``ProtocolBase.__registry__`` sits under, by the
#: subpackage of :mod:`pcapkit.protocols` its module is in, in the order of the
#: groups (#2773).
LAYERS = {
    'link': 'Link Layer',
    'internet': 'Internet Layer',
    'transport': 'Transport Layer',
    'application': 'Application Layer',
    'misc': 'Miscellaneous',
}

#: Classes that break the order, as ``qualified name: (rules, remover)``: the
#: :data:`RULES` kinds each breaks, and the issue or PR whose reorder removes the
#: entry.
KNOWN_EXCEPTIONS = {}  # type: dict[str, tuple[frozenset[str], str]]

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


def maps(cls: 'ast.ClassDef') -> 'Iterator[tuple[str, ast.Dict, Optional[str]]]':
    """Every class-level dunder map literal of ``cls``, as ``(name, entries, default)``.

    The map is a :obj:`dict` display, or a call such as a
    :class:`~collections.defaultdict` holding one; ``default`` is the :obj:`str` its
    ``lambda`` factory returns, else :data:`None`.

    """
    for stmt in cls.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target, value = stmt.targets[0], stmt.value  # type: ast.expr, Optional[ast.expr]
        elif isinstance(stmt, ast.AnnAssign):
            target, value = stmt.target, stmt.value
        else:
            continue
        if not isinstance(target, ast.Name) or not _is_dunder(target.id):
            continue
        default = None
        if isinstance(value, ast.Call):
            factory = value.args[0] if value.args else None
            if isinstance(factory, ast.Lambda) and isinstance(factory.body, ast.Constant) \
                    and isinstance(factory.body.value, str):
                default = factory.body.value
            value = next((arg for arg in value.args if isinstance(arg, ast.Dict)), None)
        if isinstance(value, ast.Dict):
            yield target.id, value, default


def _prefixes(cls: 'ast.ClassDef') -> 'set[str]':
    """What follows ``_read_`` or ``_make_`` in each f-string of ``cls`` naming a method."""
    found = set()  # type: set[str]
    for node in ast.walk(cls):
        if isinstance(node, ast.JoinedStr) and len(node.values) > 1 \
                and isinstance(node.values[0], ast.Constant) and isinstance(node.values[1], ast.FormattedValue):
            head = node.values[0].value
            if isinstance(head, str) and _stem(head) is not None:
                found.add(head[6:])
    return found


def registries(cls: 'ast.ClassDef', utilities: 'list[str]') -> 'list[tuple[str, str, list[str]]]':
    """The method registries of ``cls``, as ``(map, prefix, stems)``.

    ``stems`` opens with the registry's default, the ``lambda`` factory's value or the
    stem of the ``getattr()`` fallback, and follows with the stems of its entries in
    their order. ``prefix`` is the f-string prefix that names the most of them.

    """
    prefixes = _prefixes(cls)
    fallbacks = _fallbacks(cls, set(utilities))
    found = []  # type: list[tuple[str, str, list[str]]]
    for name, node, default in maps(cls):
        if name == '__proto__':
            continue
        values = [value.value for value in node.values
                  if isinstance(value, ast.Constant) and isinstance(value.value, str)]
        hits = {prefix: sum(1 for value in values if _method(utilities, '_read_', prefix, value)
                            or _method(utilities, '_make_', prefix, value)) for prefix in prefixes}
        prefix = max(sorted(hits), key=hits.__getitem__, default=None)
        if prefix is None or not hits[prefix]:
            continue
        if default is None:
            default = next((fallback[6 + len(prefix):] for fallback in sorted(fallbacks)
                            if _stem(fallback) is not None and fallback[6:].startswith(prefix)), None)
        stems = [default] if default is not None else []
        found.append((name, prefix, list(dict.fromkeys(stems + values))))
    return found


def _method(utilities: 'list[str]', kind: 'str', prefix: 'str', stem: 'str') -> 'Optional[str]':
    """The utility ``kind + prefix + stem`` names, as written or lower-cased, else :data:`None`."""
    for name in (f'{kind}{prefix}{stem}', f'{kind}{prefix}{stem.lower()}'):
        if name in utilities:
            return name
    return None


def specific(cls: 'ast.ClassDef', utilities: 'list[str]') -> 'list[tuple[str, list[str]]]':
    """Rule c's sets of ``cls``: each registry's readers, then its makers, in the order asked.

    Each set is ``(label, members)``, and ``members`` keeps the registry's order:
    the default first, then each entry's stem, a stem shared by several entries at
    its first.

    """
    sets = []  # type: list[tuple[str, list[str]]]
    for name, prefix, stems in registries(cls, utilities):
        for kind in ('_read_', '_make_'):
            found = (_method(utilities, kind, prefix, stem) for stem in stems)
            sets.append((f'{name} {kind}{prefix}*', list(dict.fromkeys(member for member in found if member))))
    return sets


def _member(node: 'ast.expr', lookup: 'Optional[Lookup]') -> 'Optional[enum.Enum]':
    """The enum member ``node`` names as ``Enum.MEMBER``, else :data:`None`.

    Raises:
        LookupError: If ``Enum`` is not imported from :mod:`pcapkit.const`.
        TypeError: If ``Enum.MEMBER`` is not an enum member.

    """
    if not (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)) or lookup is None:
        return None
    owner = lookup(node.value.id)
    if owner is None:
        raise LookupError(f'{node.value.id} is not imported from pcapkit.const')
    member = getattr(owner, node.attr)
    if not isinstance(member, enum.Enum):
        raise TypeError(f'{node.value.id}.{node.attr} is not an enum member')
    return member


def _key_value(key: 'Optional[ast.expr]', lookup: 'Optional[Lookup]') -> 'Optional[Any]':
    """The value a registry key orders by.

    An :class:`int` literal is its own value, an enum member its member's value and
    a :obj:`str` literal the string itself. A call on a single PCAP-NG option type,
    as ``_option_key()`` builds each key of ``PCAPNG.__option__``, is valued by the
    place of its namespace in :class:`~pcapkit.const.pcapng.option_type.OptionType`
    and then by its value (#2772). :data:`None` for a key of any other shape, which
    no rule on the page orders.

    """
    if isinstance(key, ast.Constant) and isinstance(key.value, (int, str)) and not isinstance(key.value, bool):
        return key.value
    if isinstance(key, ast.Call):
        if len(key.args) != 1 or key.keywords:
            return None
        try:
            member = _member(key.args[0], lookup)
        except (LookupError, TypeError):
            return None
        if member is None or not hasattr(member, 'opt_name'):
            return None
        spaces = list(dict.fromkeys(item.opt_name.split('_', 1)[0] for item in type(member)))
        return spaces.index(member.opt_name.split('_', 1)[0]), member.opt_value
    member = _member(key, lookup) if key is not None else None
    return None if member is None else int(member)


def _groups(node: 'ast.Dict', lines: 'Optional[Sequence[str]]') -> 'list[Optional[str]]':
    """The text of the comment line each entry of ``node`` sits under, else :data:`None`."""
    comments = {}  # type: dict[int, str]
    if lines is not None:
        for number in range(node.lineno, (node.end_lineno or node.lineno) + 1):
            text = lines[number - 1].strip()
            if text.startswith('#'):
                comments[number] = text[1:].strip()
    found = []  # type: list[Optional[str]]
    for key in node.keys:
        above = [number for number in comments if key is not None and number < key.lineno]
        found.append(comments[max(above)] if above else None)
    return found


def _layer(value: 'ast.expr') -> 'Optional[str]':
    """The :data:`LAYERS` comment a ``ModuleDescriptor('pcapkit.protocols.<layer>...', ...)`` entry is under."""
    if isinstance(value, ast.Call) and getattr(value.func, 'id', None) == 'ModuleDescriptor' and value.args \
            and isinstance(value.args[0], ast.Constant) and isinstance(value.args[0].value, str):
        parts = value.args[0].value.split('.')
        if parts[:2] == ['pcapkit', 'protocols'] and len(parts) > 2:
            return LAYERS.get(parts[2])
    return None


def _layer_finding(name: 'str', node: 'ast.Dict', groups: 'list[Optional[str]]') -> 'Optional[str]':
    """What breaks the ``layer`` rule in the ``__registry__`` map ``node``, else :data:`None`."""
    titles = list(LAYERS.values())
    rank = 0
    for key, value, group in zip(node.keys, node.values, groups):
        expected = _layer(value)
        text = _key_text(key) if key is not None else '**'
        if expected is None:
            return f'{name}: {text} names no module of a pcapkit.protocols layer'
        if group != expected:
            return f'{name}: {text} under {group!r}, not {expected!r}'
        if titles.index(group) < rank:
            return f'{name}: {group!r} after {titles[rank]!r}'
        rank = titles.index(group)
    return None


def module_lookup(path: 'pathlib.Path') -> 'Lookup':
    """Resolve each name ``path`` imports from :mod:`pcapkit.const` at its top level."""
    tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    names = {alias.asname or alias.name: (stmt.module, alias.name)
             for stmt in tree.body if isinstance(stmt, ast.ImportFrom) and stmt.module
             and stmt.module.startswith('pcapkit.const.') for alias in stmt.names}

    def lookup(name: 'str') -> 'Optional[Any]':
        if name not in names:
            return None
        module, attr = names[name]
        return getattr(importlib.import_module(module), attr)

    return lookup


def audit(cls: 'ast.ClassDef', lookup: 'Optional[Lookup]' = None,
          lines: 'Optional[Sequence[str]]' = None) -> 'dict[str, str]':
    """The rules ``cls`` breaks, as ``kind: detail``; empty when it keeps the order.

    ``lookup`` resolves the names a registry key takes its enum from; without it,
    only :class:`int` and :obj:`str` keys are valued. ``lines`` is the source
    ``cls`` was parsed from, whose comment lines group a :obj:`str`-keyed map;
    without it, such a map is one group.

    """
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

    sets = specific(cls, utilities)
    registry = {member for _, names in sets for member in names}
    for fallback in _fallbacks(cls, set(utilities)):
        stem = _stem(fallback)
        registry.update([fallback] if stem is None else
                        (name for name in (f'_read_{stem}', f'_make_{stem}') if name in position))
    for label, names in sets:
        actual = [name for name in utilities if name in names]
        if actual != names:
            findings.setdefault('specific', f'{label}: expected {names}, found {actual}')
    for (label, readers), (_, makers) in zip(sets[::2], sets[1::2]):
        if readers and makers and position[readers[-1]] > position[makers[0]]:
            findings.setdefault('specific', f'{label}: {makers[0]} before {readers[-1]}')
    readers = [name for _, names in sets[::2] for name in names]
    makers = [name for _, names in sets[1::2] for name in names]
    if readers and makers:
        reader = max(readers, key=position.__getitem__)
        maker = min(makers, key=position.__getitem__)
        if position[reader] > position[maker]:
            findings.setdefault('specific', f'{maker} before {reader}: every reader comes before every maker')
    helper = [name for name in expected if name not in registry]
    first = min((position[name] for name in registry), default=None)
    if helper and first is not None and position[helper[-1]] > first:
        findings.setdefault('specific', f'{utilities[first]} before the helper {helper[-1]}')

    reached = {'_make_data', *expected, *registry}
    last = max((position[name] for name in reached if name in position), default=0)
    early = [name for name in utilities[:last] if name not in reached]
    if early:
        findings['unreached'] = f'{early[0]} before {utilities[last]}'

    checked = {'__proto__', *(label.split()[0] for label, _ in sets)}
    for name, node, _ in maps(cls):
        keys = [key for key in node.keys if key is not None]
        named = bool(keys) and all(isinstance(key, ast.Constant) and isinstance(key.value, str) for key in keys)
        if (name not in checked and not named) or len(keys) != len(node.keys):
            continue
        values = [_key_value(key, lookup) for key in keys]
        if None in values or len({type(value) for value in values}) > 1:
            continue
        groups = _groups(node, lines) if named else [None] * len(keys)
        out = next((index for index in range(1, len(values))
                    if groups[index] == groups[index - 1] and values[index] < values[index - 1]), None)
        if out is not None:
            findings.setdefault('registry', f'{name}: {_key_text(keys[out])} after {_key_text(keys[out - 1])}')
        if named and name == '__registry__':
            detail = _layer_finding(name, node, groups)
            if detail is not None:
                findings.setdefault('layer', detail)
    return findings


def _key_text(key: 'ast.expr') -> 'str':
    """A valued registry key as written: ``Enum.MEMBER``, ``call(Enum.MEMBER)``, or the literal."""
    if isinstance(key, ast.Attribute) and isinstance(key.value, ast.Name):
        return f'{key.value.id}.{key.attr}'
    if isinstance(key, ast.Call) and isinstance(key.func, ast.Name) and len(key.args) == 1:
        return f'{key.func.id}({_key_text(key.args[0])})'
    return repr(getattr(key, 'value', key))


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
    found = {}  # type: dict[str, dict[str, str]]
    for path in protocol_modules(root / 'pcapkit' / 'protocols'):
        lookup, lines = module_lookup(path), path.read_text(encoding='utf-8').splitlines()
        found.update((name, audit(node, lookup, lines)) for name, node in classes(path, root))
    return found


class TestAudit(unittest.TestCase):
    """The audit finds each rule broken in a planted class body, and nothing in a sound one."""

    #: A class body in the order: a by-name registry grouped by layer, ``_make_data()``,
    #: a helper pair, a registry fallback, the readers of two method registries and
    #: then their makers, and a helper nothing reaches.
    SOUND = '''
class Sound:
    __registry__ = {
        # Link Layer
        'ARP': ModuleDescriptor('pcapkit.protocols.link.arp.protocol', 'ARP'),
        'ETHERNET': ModuleDescriptor('pcapkit.protocols.link.ethernet.protocol', 'Ethernet'),
        # Transport Layer
        'TCP': ModuleDescriptor('pcapkit.protocols.transport.tcp.protocol', 'TCP'),
        # Miscellaneous
        'RAW': ModuleDescriptor('pcapkit.protocols.misc.raw.protocol', 'Raw'),
    }
    __option__ = collections.defaultdict(lambda: 'unknown', {
        E.ALPHA: 'alpha',
        E.BETA: 'beta',
    })
    __type__ = collections.defaultdict(lambda: 'none', {
        1: 'echo',
    })
    @property
    def name(self): ...
    def read(self):
        self._read_addr()
        getattr(self, 'x', self._read_unknown)
        getattr(self, f'_read_opt_{name}')
        getattr(self, f'_read_type_{name}')
    def make(self):
        self._make_addr()
    def __index__(self): ...
    @classmethod
    def _make_data(cls, data): ...
    def _read_addr(self): ...
    def _make_addr(self): ...
    def _read_unknown(self): ...
    def _make_unknown(self): ...
    def _read_opt_unknown(self): ...
    def _read_opt_alpha(self): ...
    def _read_opt_beta(self): ...
    def _read_type_none(self): ...
    def _read_type_echo(self): ...
    def _make_opt_unknown(self): ...
    def _make_opt_alpha(self): ...
    def _make_opt_beta(self): ...
    def _make_type_none(self): ...
    def _make_type_echo(self): ...
    def _decode_text(self): ...
'''

    #: The by-name registry entries of :attr:`SOUND`, by name.
    ENTRY = {
        'ARP': "        'ARP': ModuleDescriptor('pcapkit.protocols.link.arp.protocol', 'ARP'),\n",
        'ETHERNET': "        'ETHERNET': ModuleDescriptor('pcapkit.protocols.link.ethernet.protocol', 'Ethernet'),\n",
        'TCP': "        'TCP': ModuleDescriptor('pcapkit.protocols.transport.tcp.protocol', 'TCP'),\n",
        'RAW': "        'RAW': ModuleDescriptor('pcapkit.protocols.misc.raw.protocol', 'Raw'),\n",
    }

    class Code(enum.IntEnum):
        """The enum :attr:`SOUND`'s registry is keyed by."""

        ALPHA = 1
        BETA = 2

    def check(self, source: 'str') -> 'dict[str, str]':
        node = ast.parse(source).body[0]
        assert isinstance(node, ast.ClassDef)
        return audit(node, {'E': self.Code}.get, source.splitlines())

    def test_a_sound_class_has_no_finding(self) -> 'None':
        self.assertEqual(self.check(self.SOUND), {})

    def test_each_rule_is_found(self) -> 'None':
        readers = '    def _read_opt_alpha(self): ...\n    def _read_opt_beta(self): ...\n'
        transport = '        # Transport Layer\n' + self.ENTRY['TCP']
        planted = {
            'group': self.SOUND.replace('    def __index__(self): ...\n', '') + '    def __index__(self): ...\n',
            'data': self.SOUND.replace('    @classmethod\n    def _make_data(cls, data): ...\n', '')
            + '    @classmethod\n    def _make_data(cls, data): ...\n',
            'pair': self.SOUND.replace('    def _read_unknown(self): ...\n', '') + '    def _read_unknown(self): ...\n',
            'helpers': self.SOUND.replace('    def _make_addr(self): ...\n', '') + '    def _make_addr(self): ...\n',
            'specific': self.SOUND.replace(readers, ''.join(reversed(readers.splitlines(keepends=True)))),
            'unreached': self.SOUND.replace('    def _decode_text(self): ...\n', '').replace(
                '    def _read_addr(self): ...\n', '    def _decode_text(self): ...\n    def _read_addr(self): ...\n'),
            'registry': self.SOUND.replace("        E.ALPHA: 'alpha',\n        E.BETA: 'beta',\n",
                                           "        E.BETA: 'alpha',\n        E.ALPHA: 'beta',\n"),
            # TCP moves into the Link group, where it still sorts last.
            'layer': self.SOUND.replace(transport, self.ENTRY['TCP'] + '        # Transport Layer\n'),
        }
        self.assertEqual(sorted(planted), sorted(RULES))
        for kind, source in planted.items():
            with self.subTest(rule=kind):
                self.assertNotEqual(source, self.SOUND)
                self.assertIn(kind, self.check(source))
        # Each of the checks for rule c, subgroup d, the registry order and the layers fires alone.
        for kind in ('specific', 'unreached', 'registry', 'layer'):
            with self.subTest(alone=kind):
                self.assertEqual(sorted(self.check(planted[kind])), [kind])

    def test_every_reader_comes_before_every_maker(self) -> 'None':
        # Each registry keeps its readers before its makers, but __type__'s readers
        # follow __option__'s makers (#2772).
        types = '    def _read_type_none(self): ...\n    def _read_type_echo(self): ...\n'
        source = self.SOUND.replace(types, '').replace('    def _make_opt_beta(self): ...\n',
                                                       '    def _make_opt_beta(self): ...\n' + types)
        self.assertNotEqual(source, self.SOUND)
        found = self.check(source)
        self.assertEqual(sorted(found), ['specific'])
        self.assertIn('every reader comes before every maker', found['specific'])

    def test_a_name_key_is_ordered_within_its_group(self) -> 'None':
        swapped = self.SOUND.replace(self.ENTRY['ARP'] + self.ENTRY['ETHERNET'],
                                     self.ENTRY['ETHERNET'] + self.ENTRY['ARP'])
        self.assertNotEqual(swapped, self.SOUND)
        self.assertEqual(self.check(swapped), {'registry': "__registry__: 'ARP' after 'ETHERNET'"})
        # Across groups, a name may sort before the one above it: RAW follows TCP.
        self.assertLess(self.SOUND.index(self.ENTRY['TCP']), self.SOUND.index(self.ENTRY['RAW']))

    def test_the_layers_keep_their_order(self) -> 'None':
        transport = '        # Transport Layer\n' + self.ENTRY['TCP']
        misc = '        # Miscellaneous\n' + self.ENTRY['RAW']
        swapped = self.SOUND.replace(transport + misc, misc + transport)
        self.assertNotEqual(swapped, self.SOUND)
        self.assertEqual(self.check(swapped), {'layer': "__registry__: 'Transport Layer' after 'Miscellaneous'"})

    def test_the_specific_sets(self) -> 'None':
        node = ast.parse(self.SOUND).body[0]
        assert isinstance(node, ast.ClassDef)
        utilities = [name for name, group in members(node) if group == 3]
        self.assertEqual(specific(node, utilities), [
            ('__option__ _read_opt_*', ['_read_opt_unknown', '_read_opt_alpha', '_read_opt_beta']),
            ('__option__ _make_opt_*', ['_make_opt_unknown', '_make_opt_alpha', '_make_opt_beta']),
            ('__type__ _read_type_*', ['_read_type_none', '_read_type_echo']),
            ('__type__ _make_type_*', ['_make_type_none', '_make_type_echo']),
        ])

    def test_a_computed_key_is_not_valued(self) -> 'None':
        source = self.SOUND.replace("        E.ALPHA: 'alpha',\n        E.BETA: 'beta',\n",
                                    "        key(E.BETA): 'alpha',\n        key(E.ALPHA): 'beta',\n")
        self.assertEqual(self.check(source), {})

    def test_an_option_key_orders_by_namespace_then_value(self) -> 'None':
        from pcapkit.const.pcapng.option_type import OptionType

        def value(name: 'str') -> 'Any':
            return _key_value(ast.parse(f'key(O.{name})', mode='eval').body, {'O': OptionType}.get)

        # Namespaces in the order OptionType declares them, whatever the values.
        names = ['opt_endofopt', 'opt_custom_19373', 'if_name', 'if_rxspeed', 'epb_flags', 'ns_dnsname',
                 'isb_starttime', 'pack_flags']
        values = [value(name) for name in names]
        self.assertNotIn(None, values)
        self.assertEqual(values, sorted(values))
        self.assertLess(value('if_name'), value('if_description'))
        self.assertLess(value('opt_custom_19373'), value('if_name'))

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
        name = 'pcapkit.protocols.link.arp.protocol.ARP'
        self.assertEqual(self.findings[name], {})
        self.assertNotIn(name, KNOWN_EXCEPTIONS)
        # The page's example: its utilities are _make_data() and the helper pairs rule b finds.
        node = dict(classes(PROTOCOLS / 'link' / 'arp' / 'protocol.py'))[name]
        utilities = [member for member, group in members(node) if group == 3]
        pairs = ['_read_addr_resolve', '_make_addr_resolve', '_read_proto_resolve', '_make_proto_resolve']
        self.assertEqual(helpers(node, utilities), pairs)
        self.assertEqual(utilities, ['_make_data', *pairs])

    def test_the_reference_registries_are_checked(self) -> 'None':
        # Every key of these maps is valued, so the registry rule orders them: by
        # enum or int value, PCAPNG's option keys by namespace then value, and the
        # PCAP-NG option schemas' namespaces alphabetically (#2772).
        cases = {
            ('internet/internet.py', 'Internet'): {'__proto__'},
            ('internet/ipv4/protocol.py', 'IPv4'): {'__option__'},
            ('link/link.py', 'Link'): {'__proto__'},
            ('misc/pcapng/protocol.py', 'PCAPNG'): {'__option__'},
            ('misc/pcapng/schema.py', 'Option'): {'__enum__'},
            ('transport/tcp/protocol.py', 'TCP'): {'__proto__', '__option__', '__mp_option__'},
            ('transport/udp/protocol.py', 'UDP'): {'__proto__'},
        }
        for (rel, name), expected in cases.items():
            with self.subTest(cls=name):
                path = PROTOCOLS / rel
                node = next(node for qual, node in classes(path) if qual.endswith(f'.{name}'))
                found = {label: [_key_value(key, module_lookup(path)) for key in entries.keys]
                         for label, entries, _ in maps(node)}
                self.assertLessEqual(expected, set(found))
                for label in expected:
                    self.assertNotIn(None, found[label], label)
                    self.assertEqual(found[label], sorted(found[label]), label)

    @staticmethod
    def audit_moved(rel: 'str', name: 'str', line: 'str', before: 'str') -> 'dict[str, str]':
        """What :func:`audit` finds in class ``name`` of module ``rel`` once ``line`` moves above ``before``."""
        path = PROTOCOLS / rel
        text = path.read_text(encoding='utf-8')
        assert text.count(line) == 1 and text.count(before) == 1, (line, before)
        text = text.replace(line, '').replace(before, line + before)
        node = next(node for node in ast.parse(text).body if isinstance(node, ast.ClassDef) and node.name == name)
        return audit(node, module_lookup(path), text.splitlines())

    def test_the_by_name_registry_is_grouped_by_layer(self) -> 'None':
        node = dict(classes(PROTOCOLS / 'protocol.py'))['pcapkit.protocols.protocol.ProtocolBase']
        entries = next(entries for label, entries, _ in maps(node) if label == '__registry__')
        lines = (PROTOCOLS / 'protocol.py').read_text(encoding='utf-8').splitlines()
        self.assertEqual(list(dict.fromkeys(_groups(entries, lines))), list(LAYERS.values()))
        self.assertEqual(self.findings['pcapkit.protocols.protocol.ProtocolBase'], {})

        def entry(key: 'str', module: 'str', name: 'str') -> 'str':
            return f"        '{key}': ModuleDescriptor('pcapkit.protocols.{module}.protocol', '{name}'),\n"

        arp, c_tag = entry('ARP', 'link.arp', 'ARP'), entry('C_TAG', 'link.c_tag', 'C_Tag')
        ah = entry('AH', 'internet.ah', 'AH')
        # A misordered entry inside a group fails.
        self.assertEqual(self.audit_moved('protocol.py', 'ProtocolBase', c_tag, arp),
                         {'registry': "__registry__: 'ARP' after 'C_TAG'"})
        # So does an entry in another layer's group, though it sorts first there.
        self.assertEqual(self.audit_moved('protocol.py', 'ProtocolBase', ah, arp),
                         {'layer': "__registry__: 'AH' under 'Link Layer', not 'Internet Layer'"})

    def test_the_pcapng_option_maps_are_checked(self) -> 'None':
        def option(name: 'str', meth: 'str') -> 'str':
            return f"            _option_key(Enum_OptionType.{name}): '{meth}',\n"

        # PCAPNG.__option__: a namespace in OptionType's order, then each value.
        rel = 'misc/pcapng/protocol.py'
        endofopt, if_name = option('opt_endofopt', 'endofopt'), option('if_name', 'if_name')
        found = self.audit_moved(rel, 'PCAPNG', if_name, endofopt)
        self.assertEqual(found.get('registry'), '__option__: _option_key(Enum_OptionType.opt_endofopt) '
                                                'after _option_key(Enum_OptionType.if_name)')
        found = self.audit_moved(rel, 'PCAPNG', option('if_description', 'if_description'), if_name)
        self.assertEqual(found.get('registry'), '__option__: _option_key(Enum_OptionType.if_name) '
                                                'after _option_key(Enum_OptionType.if_description)')
        # Option.__enum__: its namespaces alphabetically.
        space = "            '{}': collections.defaultdict(lambda: UnknownOption),\n"
        self.assertEqual(self.audit_moved('misc/pcapng/schema.py', 'Option', space.format('opt'), space.format('dsb')),
                         {'registry': "__enum__: 'dsb' after 'opt'"})

    def test_the_page_examples(self) -> 'None':
        # Rule c: _read_opt_unassigned() opens the readers of IPv4.
        path = PROTOCOLS / 'internet' / 'ipv4' / 'protocol.py'
        node = dict(classes(path))['pcapkit.protocols.internet.ipv4.protocol.IPv4']
        utilities = [member for member, group in members(node) if group == 3]
        readers = dict(specific(node, utilities))['__option__ _read_opt_*']
        self.assertEqual(readers[0], '_read_opt_unassigned')
        # Subgroup d: _decode_text() of HTTPv1, which only a helper calls, is the last utility.
        path = PROTOCOLS / 'application' / 'httpv1' / 'protocol.py'
        node = dict(classes(path))['pcapkit.protocols.application.httpv1.protocol.HTTPv1']
        self.assertEqual([member for member, group in members(node) if group == 3][-1], '_decode_text')

    def test_every_exception_is_still_broken(self) -> 'None':
        stale = sorted(f'{name} [{kind}] ({remover})'
                       for name, (kinds, remover) in KNOWN_EXCEPTIONS.items()
                       for kind in kinds if kind not in self.findings.get(name, {}))
        self.assertEqual(stale, [], 'back in order: delete the rule from KNOWN_EXCEPTIONS')


if __name__ == '__main__':
    unittest.main()
