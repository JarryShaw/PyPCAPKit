# -*- coding: utf-8 -*-
"""Docs pages order each class's members as its source does, under its section comments (GitHub issue #2907).

:file:`util/member_sections.py` sorts each ``autoclass`` member list by the
section comment that files each member, then by the body that defines it, and
writes a ``.. rubric::`` per section, as ``documentation.rst`` ("Class Member
Lists") rules.

* :class:`PageTests` -- every page is already what the fixer would write; no
  class body repeats a section, so no section splits on a page; no ``:members:``
  block documents a class whose body has section comments; and :data:`HAND` is
  checked in both directions, as ``test-coverage.rst`` asks.
* :class:`RewriteTests` -- the fixer on fixture classes.
* :class:`TitleTests` -- a section comment's subtitle.

This module is unit-tier: it parses the pages and the source, and imports
nothing it scans.

"""

from __future__ import annotations

import ast
import importlib.util
import pathlib
import tempfile
import textwrap
import unittest
import unittest.mock
from typing import TYPE_CHECKING

from tests._tiers import ROOT

if TYPE_CHECKING:
    from types import ModuleType

#: Test tier (#1958): parses the docs pages and the class sources for a
#: question about the tree, which does not differ by interpreter.
__tier__ = 'LATEST'

#: The command that brings the pages back in step.
FIX = 'python util/member_sections.py --write'


def _load_fixer() -> 'ModuleType':
    """Load :file:`util/member_sections.py` by path, since :file:`util/` is not a package."""
    spec = importlib.util.spec_from_file_location('member_sections', ROOT / 'util' / 'member_sections.py')
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


member_sections = _load_fixer()

#: Each page under :data:`member_sections.PAGES`, as ``(path from ROOT, text)``.
PAGES = [(path.relative_to(ROOT).as_posix(), path.read_text(encoding='utf-8'))
         for path in sorted(member_sections.PAGES.rglob('*.rst'))]


def _blocks() -> 'list[tuple[str, str, list[str]]]':
    """Every block on every page, as ``(page, class, lines)``."""
    found = []  # type: list[tuple[str, str, list[str]]]
    for page, text in PAGES:
        lines = text.split('\n')
        found.extend((page, target, lines[first:end]) for first, end, target in member_sections.blocks(lines))
    return found


class PageTests(unittest.TestCase):
    """The pages and the source keep the layout the fixer writes."""

    def test_every_page_is_a_fixed_point(self) -> 'None':
        """Each page is what :func:`rewrite_page` makes of it."""
        stale, skipped = [], []  # type: list[str], list[str]
        for page, text in PAGES:
            try:
                if member_sections.rewrite_page(text, page) != text:
                    stale.append(page)
            except member_sections.Skipped as error:
                skipped.append(str(error))
        self.assertEqual(skipped, [], 'move that content out of the member list, or add the block to HAND')
        self.assertEqual(stale, [], f'these pages are out of step with their sources: run {FIX}')

    def test_no_class_body_repeats_a_section(self) -> 'None':
        """No class under :file:`pcapkit/` files members under one subtitle twice, which a page cannot show."""
        repeats = []  # type: list[str]
        for path in sorted((ROOT / 'pcapkit').rglob('*.py')):
            tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                titles = [member_sections.title(text)
                          for _, text in member_sections.banners(member_sections.Class(path, node))]
                repeats.extend(f'{path.relative_to(ROOT).as_posix()}: {node.name} repeats {name!r}'
                               for name in dict.fromkeys(titles) if titles.count(name) > 1)
        self.assertEqual(repeats, [], 'merge each repeated section into one')

    def test_no_members_option_on_a_sectioned_class(self) -> 'None':
        """A class whose body has section comments takes an explicit member list, which can carry its rubrics."""
        found = []  # type: list[str]
        for page, target, lines in _blocks():
            head = lines[:next((at for at, line in enumerate(lines) if member_sections.MEMBER.match(line)),
                               len(lines))]
            if not any(line.strip().startswith(':members:') for line in head):
                continue
            cls = member_sections.locate(target)
            if cls is not None and member_sections.banners(cls):
                found.append(f'{page}: {target}')
        self.assertEqual(found, [], 'list the members with directives in place of :members:')

    def test_every_skipped_block_is_in_hand(self) -> 'None':
        """A block the fixer cannot rewrite is an entry in :data:`HAND`."""
        missing = []  # type: list[str]
        for page, target, lines in _blocks():
            if (page, target) in member_sections.HAND:
                continue
            try:
                member_sections.rewrite_block(lines, target)
            except member_sections.Skipped as error:
                missing.append(f'{page}: {target}: {error}')
        self.assertEqual(missing, [], 'add each of these blocks to HAND, with its reason')

    def test_every_hand_entry_is_needed(self) -> 'None':
        """Each :data:`HAND` entry names a block on its page that the fixer would skip or change."""
        found = {(page, target): lines for page, target, lines in _blocks()}
        stale = []  # type: list[str]
        for page, target in member_sections.HAND:
            if (page, target) not in found:
                stale.append(f'{page}: {target}: no such block')
                continue
            try:
                if member_sections.rewrite_block(found[page, target], target) == found[page, target]:
                    stale.append(f'{page}: {target}: already as the fixer writes it')
            except member_sections.Skipped:
                pass
        self.assertEqual(stale, [], 'delete each of these HAND entries')


#: The fixture module :class:`RewriteTests` documents.
FIXTURE = '''\
from typing import TYPE_CHECKING


class Base:

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def size(self): ...

    ##########################################################################
    # Methods.
    ##########################################################################

    def run(self): ...

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _help(self): ...


class Child(Base):

    lead = 1

    if TYPE_CHECKING:
        typed: int

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self): ...

    def make(self): ...

    ##########################################################################
    # Data models.
    ##########################################################################

    @classmethod
    def __index__(cls): ...


class Plain(Base):

    def run(self): ...


class Bare:

    def b(self): ...

    def a(self): ...

    _c = 1
'''


def _block(text: 'str') -> 'list[str]':
    """The lines of a fixture block."""
    return textwrap.dedent(text).strip('\n').split('\n')


class RewriteTests(unittest.TestCase):
    """:func:`rewrite_block` on the classes of :data:`FIXTURE`."""

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.scratch = tempfile.TemporaryDirectory(prefix='pcapkit-member-sections-')
        cls.path = pathlib.Path(cls.scratch.name) / 'fixture.py'
        cls.path.write_text(FIXTURE, encoding='utf-8')

    @classmethod
    def tearDownClass(cls) -> 'None':
        cls.scratch.cleanup()

    def rewrite(self, name: 'str', text: 'str') -> 'list[str]':
        """The fixer's block for the fixture class ``name``, checked to be a fixed point itself."""
        cls = member_sections._lookup(self.path, name)  # pylint: disable=protected-access
        once = member_sections.rewrite_block(_block(text), cls)
        self.assertEqual(member_sections.rewrite_block(once, cls), once, 'a second pass changes the block')
        return once

    def test_out_of_order_list(self) -> 'None':
        """Members take their source order, each section under its rubric."""
        self.assertEqual(self.rewrite('Child', '''
            .. autoclass:: fixture.Child
               :no-members:

               .. automethod:: __index__
               .. automethod:: make
               .. automethod:: read
            '''), _block('''
            .. autoclass:: fixture.Child
               :no-members:

               .. rubric:: Methods

               .. automethod:: read
               .. automethod:: make

               .. rubric:: Data Models

               .. automethod:: __index__
            '''))

    def test_lead_group_is_untitled(self) -> 'None':
        """A member above the first section comment, a ``TYPE_CHECKING`` one, and an unbound name lead untitled."""
        self.assertEqual(self.rewrite('Child', '''
            .. autoclass:: fixture.Child

               .. automethod:: read
               .. autoattribute:: nobody
               .. autoattribute:: typed
               .. autoattribute:: lead
            '''), _block('''
            .. autoclass:: fixture.Child

               .. autoattribute:: lead
               .. autoattribute:: typed
               .. autoattribute:: nobody

               .. rubric:: Methods

               .. automethod:: read
            '''))

    def test_inherited_member_follows_own(self) -> 'None':
        """A base's member joins its section after the class's own, and a base-only section follows the class's."""
        self.assertEqual(self.rewrite('Child', '''
            .. autoclass:: fixture.Child

               .. autoproperty:: size
               .. automethod:: run
               .. automethod:: read
            '''), _block('''
            .. autoclass:: fixture.Child

               .. rubric:: Methods

               .. automethod:: read
               .. automethod:: run

               .. rubric:: Properties

               .. autoproperty:: size
            '''))

    def test_sectionless_body_takes_base_section(self) -> 'None':
        """A member of a body with no section comments takes the section its base files it under."""
        self.assertEqual(self.rewrite('Plain', '''
            .. autoclass:: fixture.Plain

               .. automethod:: _help
               .. automethod:: run
            '''), _block('''
            .. autoclass:: fixture.Plain

               .. rubric:: Methods

               .. automethod:: run

               .. rubric:: Utilities

               .. automethod:: _help
            '''))

    def test_unsectioned_chain_is_reordered_only(self) -> 'None':
        """A class with no section comment anywhere in its chain gets no rubric."""
        self.assertEqual(self.rewrite('Bare', '''
            .. autoclass:: fixture.Bare

               .. automethod:: a
               .. automethod:: b
            '''), _block('''
            .. autoclass:: fixture.Bare

               .. automethod:: b
               .. automethod:: a
            '''))

    def test_stale_rubric_is_removed(self) -> 'None':
        """A rubric left over from an earlier layout goes: a list in one section takes none."""
        self.assertEqual(self.rewrite('Child', '''
            .. autoclass:: fixture.Child

               .. rubric:: Data Models

               .. automethod:: make

               .. rubric:: Methods

               .. automethod:: read
            '''), _block('''
            .. autoclass:: fixture.Child

               .. automethod:: read

               .. automethod:: make
            '''))

    def test_blank_line_grouping_is_kept(self) -> 'None':
        """A blank line between two members that stay adjacent stays, as does its absence."""
        block = '''
            .. autoclass:: fixture.Child
               :no-members:

               .. autoattribute:: lead

               .. autoattribute:: typed

               .. rubric:: Methods

               .. automethod:: read

               .. automethod:: make

               .. rubric:: Data Models

               .. automethod:: __index__
            '''
        self.assertEqual(self.rewrite('Child', block), _block(block))

    def test_new_neighbours_part_on_kind_or_visibility(self) -> 'None':
        """Members newly side by side take a blank line only where the directive or visibility changes."""
        self.assertEqual(self.rewrite('Bare', '''
            .. autoclass:: fixture.Bare

               .. autoattribute:: _c
               .. automethod:: b
               .. automethod:: a
            '''), _block('''
            .. autoclass:: fixture.Bare

               .. automethod:: b
               .. automethod:: a

               .. autoattribute:: _c
            '''))
        self.assertEqual(self.rewrite('Bare', '''
            .. autoclass:: fixture.Bare

               .. automethod:: a

               .. autoattribute:: _c

               .. automethod:: b
            '''), _block('''
            .. autoclass:: fixture.Bare

               .. automethod:: b
               .. automethod:: a

               .. autoattribute:: _c
            '''))

    def test_trailing_prose_is_skipped(self) -> 'None':
        """Content after the first member stops the rewrite."""
        cls = member_sections._lookup(self.path, 'Child')  # pylint: disable=protected-access
        with self.assertRaises(member_sections.Skipped):
            member_sections.rewrite_block(_block('''
                .. autoclass:: fixture.Child

                   .. automethod:: make
                   .. automethod:: read

                   Prose about both.
                '''), cls)


class TitleTests(unittest.TestCase):
    """:func:`title` gives a section comment's subtitle."""

    def test_title_case(self) -> 'None':
        """Each word is capitalised, the small words only where they lead, and the period goes."""
        for banner, expected in (('Data models.', 'Data Models'), ('Flow tracing.', 'Flow Tracing'),
                                 ('Macros', 'Macros'), ('Helpers for the next layer.', 'Helpers for the Next Layer'),
                                 ('The rest of it.', 'The Rest of It'), ('Next-layer helpers.', 'Next-Layer Helpers')):
            with self.subTest(banner=banner):
                self.assertEqual(member_sections.title(banner), expected)

    def test_override(self) -> 'None':
        """A :data:`TITLES` entry replaces the derived subtitle."""
        with unittest.mock.patch.dict(member_sections.TITLES, {'Data models.': 'Dunders'}):
            self.assertEqual(member_sections.title('Data models.'), 'Dunders')


if __name__ == '__main__':
    unittest.main()
