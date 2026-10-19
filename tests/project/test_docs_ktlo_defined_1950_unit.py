# -*- coding: utf-8 -*-
"""Pins that the KTLO acronym is spelled out where it is defined and linked before that (#1950).

KTLO -- *keep the lights on* -- names the tier of end-of-life Python versions
that stay built and tested on non-blocking legs. The contributor pages use the
acronym ahead of the paragraph on :file:`docs/source/contributing/workflows.rst`
that defines the tier, so that paragraph spells it out and every page links its
first mention there.

* :class:`DefinitionTests` -- the defining paragraph spells the acronym out and
  carries the ``ktlo-tier`` label directly above it, declared on that page only.
* :class:`FirstMentionTests` -- on every reStructuredText page outside the
  changelog, the first mention of KTLO in prose links to that label, unless the
  page is the defining one and the mention comes after the definition; and every
  Markdown file spells the acronym out at its first use, since ``:ref:`` does not
  work there.

A mention inside a literal -- a double-backtick one in reStructuredText, a code
span or fence in Markdown -- such as a job name ending in ``(KTLO)``, is not prose
and is not checked.

"""

from __future__ import annotations

import os
import pathlib
import re
import unittest
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Iterator

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOCS = ROOT / 'docs' / 'source'

#: The page that defines the tier, relative to :data:`DOCS`.
DEFINING_PAGE = 'contributing/workflows.rst'

LABEL = 'ktlo-tier'
LABEL_LINE = re.compile(r'^\.\. _ktlo-tier:[ \t]*$', re.MULTILINE)
EXPANSION = 'keep the lights on'
MENTION = re.compile(r'\bKTLO\b')
LITERAL = re.compile(r'``.+?``', re.DOTALL)
MARKDOWN_CODE = re.compile(r'^```.*?^```|`[^`\n]+`', re.DOTALL | re.MULTILINE)
LINKED = re.compile(r':ref:`[^`<]*<' + re.escape(LABEL) + r'>`')

#: Directories never searched for Markdown: tool state, environments, build output.
SKIPPED_DIRS = frozenset({'.git', '.claude', '.venv', 'venv', 'node_modules', 'build', 'dist', '_build'})


def mask_literals(text: str) -> str:
    """Blank out double-backtick literals, keeping every other offset where it was."""
    return LITERAL.sub(lambda match: ' ' * len(match.group()), text)


def rst_pages() -> Iterator[pathlib.Path]:
    """Every reStructuredText page under :data:`DOCS` outside the changelog."""
    for path in sorted(DOCS.rglob('*.rst')):
        relative = path.relative_to(DOCS).as_posix()
        if relative == 'changelog.rst' or relative.startswith('changelog/'):
            continue
        yield path


def markdown_files() -> Iterator[pathlib.Path]:
    """Every Markdown file in the repository, outside :data:`SKIPPED_DIRS`."""
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = sorted(name for name in dirnames if name not in SKIPPED_DIRS)
        for name in sorted(filenames):
            if name.endswith('.md'):
                yield pathlib.Path(dirpath, name)


class DefinitionTests(unittest.TestCase):
    """The tier's paragraph spells KTLO out, with the label above it."""

    def setUp(self) -> None:
        self.text = (DOCS / DEFINING_PAGE).read_text(encoding='utf-8')

    def test_the_label_is_declared_once_on_the_defining_page(self) -> None:
        self.assertEqual(len(LABEL_LINE.findall(self.text)), 1)
        for path in rst_pages():
            relative = path.relative_to(DOCS).as_posix()
            if relative != DEFINING_PAGE:
                with self.subTest(page=relative):
                    self.assertIsNone(LABEL_LINE.search(path.read_text(encoding='utf-8')))

    def test_the_paragraph_under_the_label_spells_the_acronym_out(self) -> None:
        match = LABEL_LINE.search(self.text)
        self.assertIsNotNone(match, f'no ``.. _{LABEL}:`` label on {DEFINING_PAGE}')
        assert match is not None
        paragraph = self.text[match.end():].lstrip('\n').split('\n\n', 1)[0]
        prose = ' '.join(paragraph.split())
        self.assertIn('**KTLO**', prose)
        self.assertIn(EXPANSION, prose)
        self.assertLess(prose.index('**KTLO**'), prose.index(EXPANSION))


class FirstMentionTests(unittest.TestCase):
    """Each page's first prose mention of KTLO reaches the definition."""

    def test_each_page_links_its_first_mention_or_follows_the_definition(self) -> None:
        pages = 0
        for path in rst_pages():
            text = path.read_text(encoding='utf-8')
            mention = MENTION.search(mask_literals(text))
            if mention is None:
                continue
            pages += 1
            relative = path.relative_to(DOCS).as_posix()
            with self.subTest(page=relative):
                label = LABEL_LINE.search(text)
                if relative == DEFINING_PAGE and label is not None and mention.start() > label.end():
                    continue
                linked = any(link.start() <= mention.start() < link.end() for link in LINKED.finditer(text))
                line = text.count('\n', 0, mention.start()) + 1
                self.assertTrue(linked, f'{relative}:{line}: first KTLO mention does not link to {LABEL!r}')
        self.assertGreater(pages, 0, 'no page mentions KTLO, so this test checks nothing')

    def test_markdown_spells_the_acronym_out_at_first_use(self) -> None:
        for path in markdown_files():
            text = path.read_text(encoding='utf-8', errors='replace')
            prose = MARKDOWN_CODE.sub(lambda match: ' ' * len(match.group()), text)
            mention = MENTION.search(prose)
            if mention is None:
                continue
            with self.subTest(file=path.relative_to(ROOT).as_posix()):
                sentence = ' '.join(prose[mention.start():mention.start() + 200].split())
                self.assertIn(EXPANSION, sentence.lower())


if __name__ == '__main__':
    unittest.main()
