# -*- coding: utf-8 -*-
"""Protocol docs pages list their members in class source order (GitHub issue #2780).

A page under :file:`docs/source/pcapkit/protocols/` documents a class with an
``autoclass`` directive and lists its members with ``automethod``,
``autoattribute`` and ``autoproperty`` directives nested under it. #2779 put
those lists in the order the class body defines the members, which
``protocol-member-order.rst`` rules (#2772, item 5); without a guard, the next
member move desyncs a page unnoticed.

* :class:`MemberOrderTests` -- each block lists the members a class body
  defines in the order that body defines them. Only the members a page lists
  count.

A listed member the documented class inherits is held to the body of the class
that defines it, found by method resolution order over the bases the source
names: source order is a fact of one body, so how a page interleaves the members
of two bodies is the page's choice. A name no body binds, such as an instance
attribute set in a method, has no source position and is left out.

A block that keeps an order of its own is an entry in :data:`EXEMPT`, with its
reason. The table is checked in both directions, as ``test-coverage.rst`` asks,
so a realigned block deletes its entry in the same change.

This module is unit-tier: it parses the pages and the source, and imports
nothing it scans.

"""
from __future__ import annotations

import ast
import functools
import re
import unittest
from typing import TYPE_CHECKING, NamedTuple

from tests._tiers import ROOT

if TYPE_CHECKING:
    import pathlib
    from typing import Iterable, Iterator, Optional

#: Test tier (#1958): parses the docs pages and the protocol sources for a
#: question about the tree, which does not differ by interpreter.
__tier__ = 'LATEST'

#: The directory of the pages the guard reads.
PAGES = ROOT / 'docs' / 'source' / 'pcapkit' / 'protocols'

#: A directive the guard reads: ``autoclass`` opens a block, and a member
#: directive in its content lists a member. Captures the indent, the kind and
#: the dotted target, without a signature.
DIRECTIVE = re.compile(r'^(?P<indent> *)\.\. +(?P<kind>autoclass|automethod|autoattribute|autoproperty)'
                       r':: *(?P<target>[\w.]+)')

#: Blocks that keep an order of their own, as ``(page, class): reason``: the
#: page relative to :data:`ROOT`, and the class as its ``autoclass`` names it.
EXEMPT = {
    ('docs/source/pcapkit/protocols/protocol.rst', 'pcapkit.protocols.protocol.Protocol'):
        "lists ProtocolBase's members in the page's own order, kept over ProtocolBase's "
        'source order (#2772, item 3)',
}  # type: dict[tuple[str, str], str]

_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


class Block(NamedTuple):
    """An ``autoclass`` block that lists members."""

    #: The page, relative to :data:`ROOT`.
    page: str
    #: The class, as the directive names it.
    target: str
    #: The listed members, in page order.
    members: tuple[str, ...]


class Class(NamedTuple):
    """A class the repository defines."""

    #: The module file.
    path: pathlib.Path
    #: The ``class`` statement.
    node: ast.ClassDef


def read_blocks(page: 'pathlib.Path') -> 'list[Block]':
    """The blocks on ``page`` that list members, in page order.

    A block is the content of an ``autoclass`` directive: the lines below it up to
    the first non-blank line indented no deeper than the directive.

    """
    found = []  # type: list[Block]
    name = page.relative_to(ROOT).as_posix()
    target = None  # type: Optional[str]
    indent = 0
    members = []  # type: list[str]
    for line in page.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        depth = len(line) - len(line.lstrip(' '))
        if target is not None and depth <= indent:
            if members:
                found.append(Block(name, target, tuple(members)))
            target = None
        match = DIRECTIVE.match(line)
        if match is None:
            continue
        if match.group('kind') == 'autoclass':
            target, indent, members = match.group('target'), depth, []
        elif target is not None:
            members.append(match.group('target'))
    if target is not None and members:
        found.append(Block(name, target, tuple(members)))
    return found


@functools.lru_cache(maxsize=None)
def _parse(path: 'pathlib.Path') -> 'ast.Module':
    """The AST of the module at ``path``, parsed once."""
    return ast.parse(path.read_text(encoding='utf-8'), filename=str(path))


def _statements(body: 'Iterable[ast.stmt]') -> 'Iterator[ast.stmt]':
    """The statements of ``body`` in source order, inside every block that opens no scope."""
    for node in body:
        yield node
        if isinstance(node, _SCOPES):
            continue
        for field in ('body', 'orelse', 'finalbody'):
            yield from _statements(getattr(node, field, ()))
        for handler in getattr(node, 'handlers', ()):
            yield from _statements(handler.body)


def _module(dotted: 'str') -> 'Optional[pathlib.Path]':
    """The file of the repository module ``dotted`` names, if there is one."""
    base = ROOT.joinpath(*dotted.split('.'))
    for path in (base.with_suffix('.py'), base / '__init__.py'):
        if path.is_file():
            return path
    return None


def _source(path: 'pathlib.Path', node: 'ast.ImportFrom') -> 'str':
    """The module ``node`` imports from, made absolute against the module at ``path``."""
    if not node.level:
        return node.module or ''
    package = path.parent.relative_to(ROOT).parts
    package = package[:len(package) - node.level + 1]
    return '.'.join(package + ((node.module,) if node.module else ()))


def _lookup(path: 'pathlib.Path', name: 'str') -> 'Optional[Class]':
    """The class ``name`` means in the module at ``path``, defined there or imported from the repository."""
    for node in _statements(_parse(path).body):
        if isinstance(node, ast.ClassDef) and node.name == name:
            return Class(path, node)
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if (alias.asname or alias.name) == name:
                    module = _module(_source(path, node))
                    return None if module is None else _lookup(module, alias.name)
    return None


def locate(target: 'str') -> 'Optional[Class]':
    """The class the dotted ``target`` of an ``autoclass`` names, if the repository defines it."""
    parts = target.split('.')
    for cut in range(len(parts) - 1, 0, -1):
        path = _module('.'.join(parts[:cut]))
        if path is None:
            continue
        found = _lookup(path, parts[cut])
        for name in parts[cut + 1:]:
            if found is None:
                break
            found = next((Class(found.path, node) for node in _statements(found.node.body)
                          if isinstance(node, ast.ClassDef) and node.name == name), None)
        return found
    return None


def _bases(cls: 'Class') -> 'list[Class]':
    """The bases of ``cls`` the repository defines, in declaration order."""
    found = []  # type: list[Class]
    for base in cls.node.bases:
        if isinstance(base, ast.Subscript):
            base = base.value
        if isinstance(base, ast.Name):
            resolved = _lookup(cls.path, base.id)
            if resolved is not None:
                found.append(resolved)
    return found


@functools.lru_cache(maxsize=None)
def mro(cls: 'Class') -> 'tuple[Class, ...]':
    """``cls`` and its repository bases in method resolution order, by C3 over the source."""
    pending = [list(mro(base)) for base in _bases(cls)] + [_bases(cls)]
    order = [cls]
    while True:
        pending = [chain for chain in pending if chain]
        if not pending:
            return tuple(order)
        head = next(chain[0] for chain in pending if all(chain[0] not in other[1:] for other in pending))
        order.append(head)
        pending = [[base for base in chain if base != head] for chain in pending]


@functools.lru_cache(maxsize=None)
def bindings(cls: 'Class') -> 'dict[str, int]':
    """Each name the body of ``cls`` binds, mapped to the position of its first binding.

    A ``def``, a ``class`` and an assignment to a bare name bind, and so does one
    under an ``if`` or a ``try`` in the body, where that statement stands, as the
    member-order guard reads a ``TYPE_CHECKING`` member (#2490).

    """
    order = {}  # type: dict[str, int]
    for node in _statements(cls.node.body):
        if isinstance(node, _SCOPES):
            names = [node.name]
        elif isinstance(node, ast.Assign):
            names = [target.id for target in node.targets if isinstance(target, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names = [node.target.id]
        else:
            continue
        for name in names:
            order.setdefault(name, len(order))
    return order


def disorder(block: 'Block') -> 'list[str]':
    """Each pair of members ``block`` lists out of the order of the body that defines them."""
    cls = locate(block.target)
    if cls is None:
        return []
    listed = {}  # type: dict[Class, list[tuple[int, str]]]
    for name in block.members:
        owner = next((base for base in mro(cls) if name in bindings(base)), None)
        if owner is not None:
            listed.setdefault(owner, []).append((bindings(owner)[name], name))
    problems = []  # type: list[str]
    for owner, positions in listed.items():
        for (first, earlier), (second, later) in zip(positions, positions[1:]):
            if first > second:
                problems.append(f'{block.page}: the {cls.node.name} block lists {earlier!r} before {later!r}, '
                                f'but {owner.node.name} in {owner.path.relative_to(ROOT).as_posix()} '
                                f'defines {later!r} first')
    return problems


class MemberOrderTests(unittest.TestCase):
    """The member lists on the protocol pages follow class source order."""

    blocks = [block for page in sorted(PAGES.rglob('*.rst')) for block in read_blocks(page)]

    def test_every_listed_class_is_found(self) -> 'None':
        """Each block names a class the source defines, so no block goes unchecked."""
        self.assertTrue(self.blocks, f'no autoclass block under {PAGES} lists a member')
        missing = [f'{block.page}: {block.target}' for block in self.blocks if locate(block.target) is None]
        self.assertEqual(missing, [], 'name each class at the module that defines it')

    def test_members_follow_source_order(self) -> 'None':
        """Each block outside :data:`EXEMPT` lists the members of a body in the body's order."""
        problems = [problem for block in self.blocks if (block.page, block.target) not in EXEMPT
                    for problem in disorder(block)]
        if problems:
            self.fail('reorder the directives to match the class body:\n' + '\n'.join(problems))

    def test_every_exemption_is_needed(self) -> 'None':
        """Each :data:`EXEMPT` entry names a block on its page that is out of order."""
        found = {(block.page, block.target): block for block in self.blocks}
        stale = sorted(f'{page}: {target}' for page, target in EXEMPT
                       if (page, target) not in found or not disorder(found[page, target]))
        self.assertEqual(stale, [], 'delete each of these EXEMPT entries: no such block, or it is in order')


if __name__ == '__main__':
    unittest.main()
