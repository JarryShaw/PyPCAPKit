# -*- coding: utf-8 -*-
"""Docs pages list each class's members in class source order (GitHub issue #2780).

A page under :file:`docs/source/` documents a class with an ``autoclass``
directive and lists its members with ``automethod``, ``autoattribute`` and
``autoproperty`` directives nested under it. #2779 put those lists in the order
the class body defines the members, as #2772 (item 5) ruled and
``documentation.rst`` ("Class Member Lists") records; without a guard, the next
member move desyncs a page unnoticed.

* :class:`MemberOrderTests` -- each block lists the members a class body
  defines in the order that body defines them. Only the members a page lists
  count.

A listed member the documented class inherits is held to the body of the class
that defines it, found by method resolution order over the bases the source
names. How a block interleaves two bodies is not the page's choice: within a
section, the class's own members come first, then its bases' in method
resolution order, which ``util/member_sections.py`` writes and
``test_docs_member_sections_2907_unit`` guards (#2907). A name no body binds, such
as an instance attribute set in a method, has no source position and is left out.

A block that keeps an order of its own is an entry in :data:`EXEMPT`, with its
reason. The table is checked in both directions, as ``test-coverage.rst`` asks,
so a realigned block deletes its entry in the same change.

This module is unit-tier: it parses the pages and the source, with the resolver
:file:`util/member_sections.py` holds, and imports nothing it scans.

"""
from __future__ import annotations

import importlib.util
import re
import unittest
from typing import TYPE_CHECKING, NamedTuple

from tests._tiers import ROOT

if TYPE_CHECKING:
    import pathlib
    from types import ModuleType
    from typing import Optional

#: Test tier (#1958): parses the docs pages and the class sources for a
#: question about the tree, which does not differ by interpreter.
__tier__ = 'LATEST'

#: The directory of the pages the guard reads.
PAGES = ROOT / 'docs' / 'source'

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


def _load_fixer() -> 'ModuleType':
    """Load :file:`util/member_sections.py` by path, since :file:`util/` is not a package."""
    spec = importlib.util.spec_from_file_location('member_sections', ROOT / 'util' / 'member_sections.py')
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


member_sections = _load_fixer()
Class, locate, mro, bindings = member_sections.Class, member_sections.locate, member_sections.mro, \
    member_sections.bindings


class Block(NamedTuple):
    """An ``autoclass`` block that lists members."""

    #: The page, relative to :data:`ROOT`.
    page: str
    #: The class, as the directive names it.
    target: str
    #: The listed members, in page order.
    members: tuple[str, ...]


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
    """The member lists on the docs pages follow class source order."""

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
