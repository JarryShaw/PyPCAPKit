# -*- coding: utf-8 -*-
"""Order each class's member list on the docs pages as its source does, under its section comments (#2907).

``python util/member_sections.py`` checks every page under :file:`docs/source/`,
printing a unified diff of each page out of step and exiting 1; ``--write``
rewrites those pages in place instead.

A member list is the ``automethod``, ``autoattribute`` and ``autoproperty``
directives under an ``autoclass`` or ``autoexception``. A section comment is a
``# Title`` line between two rules of ten or more ``#``, all three at the class
body's indent. The fixer sorts each list by the section comment that files each
member, then by the method resolution order of the body that defines it, then by
source line, and writes a ``.. rubric::`` ahead of each section's run. Sections
run in the order the class's own comments give them, then those only its bases
have.

* A member above its body's first section comment, or one no body binds, leads
  the list without a rubric; a list that falls in one group gets no rubric.
* A member of a body with no section comments takes the section of the nearest
  base that files it under one.
* A block with anything but member directives after its first member is left as
  written, and so is one with an order of its own; each is an entry in
  :data:`HAND`.

Standard library only, in Python 3.8's syntax.

"""

from __future__ import annotations

import argparse
import ast
import difflib
import functools
import pathlib
import re
import sys
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from typing import Iterable, Iterator, Optional

__all__ = [
    'ROOT', 'PAGES', 'HAND', 'TITLES', 'Class', 'Skipped',
    'locate', 'mro', 'bindings', 'banners', 'layout', 'title', 'blocks', 'rewrite_block', 'rewrite_page', 'main',
]

#: The repository root.
ROOT = pathlib.Path(__file__).resolve().parents[1]

#: The pages the fixer reads.
PAGES = ROOT / 'docs' / 'source'

#: Blocks left as written, as ``(page, class): reason``: the page relative to
#: :data:`ROOT`, and the class as its ``autoclass`` names it.
HAND = {
    ('docs/source/pcapkit/corekit/module.rst', 'pcapkit.corekit.module.ModuleDescriptor'):
        'documents module and name with hand-written property directives after klass',
    ('docs/source/pcapkit/corekit/version.rst', 'pcapkit.corekit.version.VersionInfo'):
        'documents major and minor with hand-written property directives after version',
    ('docs/source/pcapkit/protocols/protocol.rst', 'pcapkit.protocols.protocol.ProtocolBase'):
        "groups Protocol's interface in py:* directives after its own members, which #2234 and #2676 pin",
    ('docs/source/pcapkit/protocols/protocol.rst', 'pcapkit.protocols.protocol.Protocol'):
        "lists ProtocolBase's members in the page's own order (#2772, item 3)",
}  # type: dict[tuple[str, str], str]

#: Subtitles worded other than :func:`title` derives them, as ``{section comment: subtitle}``.
TITLES = {}  # type: dict[str, str]

#: The words Title Case leaves lowercase unless they lead (``documentation.rst``, "Heading Case and Shape").
SMALL = frozenset({'a', 'an', 'the', 'and', 'or', 'of', 'in', 'for', 'to'})

#: A block's opening directive: its indent and the dotted class, without a signature.
OPENER = re.compile(r'^(?P<indent> *)\.\. +auto(?:class|exception):: *(?P<target>[\w.]+)')

#: A member directive: its indent, kind and member, without a signature.
MEMBER = re.compile(r'^(?P<indent> *)\.\. +(?P<kind>auto(?:method|attribute|property)):: *(?P<name>[\w.]+)')

#: A subtitle: its indent and text.
RUBRIC = re.compile(r'^(?P<indent> *)\.\. +rubric:: *(?P<text>\S.*?) *$')

#: A section comment's rule and title lines.
RULE = re.compile(r'^(?P<indent> *)#{10,}[ \t]*$')
BANNER = re.compile(r'^(?P<indent> *)# (?P<text>\S.*?)[ \t]*$')

#: A section comment anywhere in a module, indented as a class body's is.
SECTION = re.compile(r'^(?P<indent> +)#{10,}[ \t]*\n(?P=indent)# (?P<text>\S.*?)[ \t]*\n(?P=indent)#{10,}[ \t]*$',
                     re.M)

_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


class Class(NamedTuple):
    """A class the repository defines."""

    #: The module file.
    path: pathlib.Path
    #: The ``class`` statement.
    node: ast.ClassDef


class Item(NamedTuple):
    """A member directive and its content, as the page has it."""

    #: The member, without its class.
    name: str
    #: The directive, such as ``automethod``.
    kind: str
    #: The directive line and every deeper line after it, without trailing blanks.
    lines: 'tuple[str, ...]'
    #: Whether a blank line parts it from the item before it on the page.
    gap: bool


class Skipped(ValueError):
    """A block the fixer cannot rewrite: content other than member directives follows its first member."""


@functools.lru_cache(maxsize=None)
def _parse(path: 'pathlib.Path') -> 'ast.Module':
    """The AST of the module at ``path``, parsed once."""
    return ast.parse(path.read_text(encoding='utf-8'), filename=str(path))


@functools.lru_cache(maxsize=None)
def _lines(path: 'pathlib.Path') -> 'tuple[str, ...]':
    """The lines of the module at ``path``, read once."""
    return tuple(path.read_text(encoding='utf-8').splitlines())


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


def _names(node: 'ast.stmt') -> 'list[str]':
    """The names ``node`` binds: a ``def``, a ``class``, or an assignment to a bare name."""
    if isinstance(node, _SCOPES):
        return [node.name]
    if isinstance(node, ast.Assign):
        return [target.id for target in node.targets if isinstance(target, ast.Name)]
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return [node.target.id]
    return []


@functools.lru_cache(maxsize=None)
def bindings(cls: 'Class') -> 'dict[str, int]':
    """Each name the body of ``cls`` binds, mapped to the position of its first binding.

    A ``def``, a ``class`` and an assignment to a bare name bind, and so does one
    under an ``if`` or a ``try`` in the body, where that statement stands, as the
    member-order guard reads a ``TYPE_CHECKING`` member (#2490).

    """
    order = {}  # type: dict[str, int]
    for node in _statements(cls.node.body):
        for name in _names(node):
            order.setdefault(name, len(order))
    return order


@functools.lru_cache(maxsize=None)
def banners(cls: 'Class') -> 'tuple[tuple[int, str], ...]':
    """The section comments of the body of ``cls``, as ``(title line, text)`` in source order.

    Rules and title sit at the body's indent and inside its lines, so a
    module-level or deeper comment is not the body's.

    """
    lines = _lines(cls.path)
    indent = cls.node.body[0].col_offset
    found = []  # type: list[tuple[int, str]]
    # Index ``at`` is line ``at + 1``: the title, with a rule on each side, all after the class line.
    for at in range(cls.node.lineno + 1, min(cls.node.end_lineno or 0, len(lines)) - 1):
        match = BANNER.match(lines[at])
        if match is None or len(match.group('indent')) != indent:
            continue
        if all(rule is not None and len(rule.group('indent')) == indent
               for rule in (RULE.match(lines[at - 1]), RULE.match(lines[at + 1]))):
            found.append((at + 1, match.group('text')))
    return tuple(found)


@functools.lru_cache(maxsize=None)
def layout(cls: 'Class') -> 'dict[str, tuple[int, Optional[str]]]':
    """Each name the body of ``cls`` binds, mapped to its first line and the section comment that files it.

    The line is the first decorator's, where there is one. The section is the text
    of the last section comment above that line, :data:`None` above the first.

    """
    marks = banners(cls)
    found = {}  # type: dict[str, tuple[int, Optional[str]]]
    for node in _statements(cls.node.body):
        line = min([node.lineno] + [decorator.lineno for decorator in getattr(node, 'decorator_list', ())])
        section = next((text for at, text in reversed(marks) if at < line), None)
        for name in _names(node):
            found.setdefault(name, (line, section))
    return found


def title(banner: 'str') -> 'str':
    """The subtitle for the section comment text ``banner``.

    :data:`TITLES` overrides; otherwise the trailing period goes and the text takes
    Title Case, the words in :data:`SMALL` lowercase unless they lead, so
    ``Data models.`` gives ``Data Models``.

    """
    if banner in TITLES:
        return TITLES[banner]
    words = banner.rstrip('.').split(' ')
    return ' '.join(word.lower() if index and word.lower() in SMALL
                    else '-'.join(part[:1].upper() + part[1:] for part in word.split('-'))
                    for index, word in enumerate(words))


@functools.lru_cache(maxsize=None)
def _titles() -> 'frozenset[str]':
    """Every subtitle a section comment under :file:`pcapkit/` gives, and each :data:`TITLES` value."""
    found = set(TITLES.values())
    for path in (ROOT / 'pcapkit').rglob('*.py'):
        found.update(title(match.group('text')) for match in SECTION.finditer(path.read_text(encoding='utf-8')))
    return frozenset(found)


def _indent(line: 'str') -> 'int':
    """The indent of ``line``."""
    return len(line) - len(line.lstrip(' '))


def blocks(lines: 'list[str]') -> 'Iterator[tuple[int, int, str]]':
    """Each block in a page's ``lines``, as ``(first, end, class)`` slice bounds and the dotted class.

    A block is an ``autoclass`` or ``autoexception`` and the lines below it up to
    the first non-blank line indented no deeper, without trailing blank lines.

    """
    at = 0
    while at < len(lines):
        opener = OPENER.match(lines[at])
        if opener is None:
            at += 1
            continue
        end = at + 1
        while end < len(lines) and (not lines[end].strip() or _indent(lines[end]) > len(opener.group('indent'))):
            end += 1
        while end > at + 1 and not lines[end - 1].strip():
            end -= 1
        yield at, end, opener.group('target')
        at = end


def _split(lines: 'list[str]', known: 'frozenset[str]') -> 'tuple[list[str], list[Item], int]':
    """A block's head, its member items and their indent; each rubric whose text is in ``known`` is dropped.

    Raises:
        Skipped: If another line at the member indent follows the first member.

    """
    indent = next((_indent(line) for line in lines[1:] if line.strip()), 0)
    head, items = [lines[0]], []  # type: list[str], list[Item]
    gap, at = False, 1
    while at < len(lines):
        line = lines[at]
        rubric, member = RUBRIC.match(line), MEMBER.match(line)
        at += 1
        if member is not None and len(member.group('indent')) == indent:
            end = at
            while end < len(lines) and (not lines[end].strip() or _indent(lines[end]) > indent):
                end += 1
            while not lines[end - 1].strip():
                end -= 1
            items.append(Item(member.group('name').rsplit('.', 1)[-1], member.group('kind'),
                              tuple(lines[at - 1:end]), gap))
            gap, at = False, end
        elif not line.strip():
            gap = True
            if not items:
                head.append(line)
        elif rubric is not None and len(rubric.group('indent')) == indent and rubric.group('text') in known:
            # NOTE: a hand-written rubric whose text equals any section-comment title under pcapkit/
            # is taken as derived, so it is dropped here and regenerated.
            continue
        elif items:
            raise Skipped(f'{line.strip()!r} follows its first member')
        else:
            head.append(line)
    while not head[-1].strip():
        head.pop()
    return head, items, indent


def _bucket(item: 'Item') -> 'tuple[str, str]':
    """The directive and visibility of ``item``: a run of either is parted by a blank line."""
    if item.name.startswith('__') and item.name.endswith('__'):
        return item.kind, 'dunder'
    return item.kind, 'private' if item.name.startswith('_') else 'public'


def rewrite_block(lines: 'list[str]', target: 'str | Class') -> 'list[str]':
    """The block ``lines`` with its member list in source order, each section under its rubric.

    Args:
        lines: the block, from its opening directive to its last non-blank line
        target: the class, dotted or located

    Raises:
        Skipped: If content other than member directives follows the first member.

    """
    cls = locate(target) if isinstance(target, str) else target
    chain = () if cls is None else mro(cls)
    head, items, indent = _split(lines, _titles() | {title(text) for body in chain for _, text in banners(body)})
    if cls is None or not items:
        return list(lines)

    # Lead group first, then the class's own sections, then those only bases have, in MRO order.
    ranks = [None]  # type: list[Optional[str]]
    for body in chain:
        ranks.extend(name for name in dict.fromkeys(title(text) for _, text in banners(body)) if name not in ranks)
    order = []  # type: list[tuple[tuple[int, int, int, int], Optional[str], int]]
    for index, item in enumerate(items):
        owner = next((body for body in chain if item.name in layout(body)), None)
        if owner is None:
            order.append(((0, len(chain), 0, index), None, index))
            continue
        line, section = layout(owner)[item.name]
        if not banners(owner):
            section = next((layout(body)[item.name][1] for body in chain
                            if item.name in layout(body) and layout(body)[item.name][1] is not None), None)
        group = None if section is None else title(section)
        order.append(((ranks.index(group), chain.index(owner), line, index), group, index))
    order.sort()
    titled = len({group for _, group, _ in order}) > 1

    out, pad = list(head), ' ' * indent
    for place, (_, group, index) in enumerate(order):
        item, previous = items[index], order[place - 1][2]
        if not place or group != order[place - 1][1]:
            out.append('')
            if titled and group is not None:
                out.extend([f'{pad}.. rubric:: {group}', ''])
        # Neighbours on the page keep their separator; new ones part where the bucket changes.
        elif (items[max(previous, index)].gap if abs(previous - index) == 1
              else _bucket(items[previous]) != _bucket(item)):
            out.append('')
        out.extend(item.lines)
    return out


def rewrite_page(text: 'str', page: 'str') -> 'str':
    """The page ``text`` with each block outside :data:`HAND` rewritten; ``page`` is its path from :data:`ROOT`.

    Raises:
        Skipped: If a block outside :data:`HAND` cannot be rewritten.

    """
    lines = text.split('\n')
    out, last = [], 0  # type: list[str], int
    for first, end, target in blocks(lines):
        out.extend(lines[last:first])
        if (page, target) in HAND:
            out.extend(lines[first:end])
        else:
            try:
                out.extend(rewrite_block(lines[first:end], target))
            except Skipped as error:
                raise Skipped(f'{page}: {target}: {error}') from None
        last = end
    out.extend(lines[last:])
    return '\n'.join(out)


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    """Check or rewrite every page under :data:`PAGES`; the exit status."""
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check', action='store_true', help='print a diff of each page out of step and exit 1 '
                                                           '(the default)')
    mode.add_argument('--write', action='store_true', help='rewrite each page out of step in place')
    args = parser.parse_args(argv)
    status = 0
    for path in sorted(PAGES.rglob('*.rst')):
        page = path.relative_to(ROOT).as_posix()
        text = path.read_text(encoding='utf-8')
        try:
            new = rewrite_page(text, page)
        except Skipped as error:
            print(f'{error}: move that content out of the member list, or add the block to HAND',
                  file=sys.stderr)
            status = 1
            continue
        if new == text:
            continue
        if args.write:
            path.write_text(new, encoding='utf-8')
            print(page, flush=True)
        else:
            sys.stdout.writelines(difflib.unified_diff(text.splitlines(True), new.splitlines(True),
                                                       f'a/{page}', f'b/{page}'))
            status = 1
    return status


if __name__ == '__main__':
    sys.exit(main())
