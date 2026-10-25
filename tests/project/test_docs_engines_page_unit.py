# -*- coding: utf-8 -*-
"""Pins the engine comparison on its own page, :file:`docs/source/engines.rst`.

The comparison -- engines, Python ceilings, prerequisites and the benchmark
tables -- moved off the root document, which keeps a summary and a link.

* :class:`PlacementTests` -- the page is in a toctree, the root document links it
  and does not carry the tables, and the prerequisites label is on the page.
* :class:`FootnoteTests` -- the benchmark tables mark their rows with
  reStructuredText footnotes rather than literal symbols and a hand legend.
* :class:`ProvenanceTests` -- the page says where its figures come from.

"""

from __future__ import annotations

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOCS = ROOT / 'docs' / 'source'
INDEX = DOCS / 'index.rst'
PAGE = DOCS / 'engines.rst'

#: The headings that moved, each written once on the page.
MOVED = ('Engine Support by Python Version', 'Engine Prerequisites', 'Test Environment',
         'Test Results', 'Test Results (Relative)')

#: A section heading: a title line, then an underline of one repeated character.
HEADING = re.compile(r'(?m)^(\S[^\n]*)\n([=\-~^])\2+$')

#: ``examples/benchmark/report.py``'s literal row markers, at the end of a table cell.
LITERAL_MARK = re.compile(r'(?m)^``\w+`` [†‡¶]')

#: A footnote reference, and a footnote body, auto-symbol or auto-numbered.
FOOTNOTE_REF = re.compile(r'\[(\*|#[\w-]*)\]_')
FOOTNOTE_BODY = re.compile(r'(?m)^\.\. \[(\*|#[\w-]*)\]')


def headings(text: 'str') -> 'list[str]':
    """Every section title in *text*, in order."""
    return [match.group(1) for match in HEADING.finditer(text)]


def section(text: 'str', title: 'str') -> 'str':
    """The body of the section *title*, up to the next heading."""
    start = text.index(f'\n{title}\n') + len(title) + 2
    following = [match.start() for match in HEADING.finditer(text, start + 1)]
    return text[start:following[0] if following else len(text)]


class PlacementTests(unittest.TestCase):
    """The page exists, is reachable, and holds what moved."""

    def setUp(self) -> 'None':
        self.index = INDEX.read_text(encoding='utf-8')
        self.page = PAGE.read_text(encoding='utf-8')

    def test_page_is_in_the_guides_toctree(self) -> 'None':
        """The root document lists the page, so the sidebar reaches it."""
        match = re.search(r'(?m)^[ \t]+:caption: Guides & Changelog\n(?:[ \t]+:[^\n]*\n)*\n'
                          r'(?P<entries>(?:[ \t]+\S[^\n]*\n)+)', self.index)
        self.assertIsNotNone(match, 'no "Guides & Changelog" toctree in index.rst')
        assert match is not None
        self.assertIn('engines', match.group('entries').split())

    def test_page_carries_every_moved_section_once(self) -> 'None':
        """Under the page's own title."""
        found = headings(self.page)
        self.assertEqual(found[0], 'Engine Comparison')
        for title in MOVED:
            with self.subTest(title=title):
                self.assertEqual(found.count(title), 1)

    def test_index_keeps_a_summary_that_links_the_page(self) -> 'None':
        """Its ``#engine-comparison`` anchor survives, and none of the moved sections do."""
        found = headings(self.index)
        self.assertIn('Engine Comparison', found)
        self.assertIn(':doc:`engines`', section(self.index, 'Engine Comparison'))
        for title in MOVED:
            with self.subTest(title=title):
                self.assertNotIn(title, found)

    def test_prerequisites_label_is_on_the_page_once(self) -> 'None':
        """Directly above its section, and on no other page."""
        label = re.compile(r'(?m)^\.\. _engine-prerequisites:\n\nEngine Prerequisites\n-+$')
        self.assertRegex(self.page, label)
        declared = re.compile(r'(?m)^\.\. _engine-prerequisites:')
        found = [path.relative_to(ROOT).as_posix() for path in sorted(DOCS.rglob('*.rst'))
                 if declared.search(path.read_text(encoding='utf-8'))]
        self.assertEqual(found, ['docs/source/engines.rst'])


class FootnoteTests(unittest.TestCase):
    """Row notes are footnotes, each body directly after its table."""

    def setUp(self) -> 'None':
        self.page = PAGE.read_text(encoding='utf-8')

    def test_no_literal_row_markers(self) -> 'None':
        """No row ends in a symbol, and no legend explains one."""
        self.assertEqual(LITERAL_MARK.findall(self.page), [])
        for title in ('Test Results', 'Test Results (Relative)'):
            with self.subTest(title=title):
                self.assertNotRegex(section(self.page, title), r'``[†‡¶]``')

    def test_every_reference_has_a_body_in_its_own_section(self) -> 'None':
        """So each note renders beside its table rather than at the end of the page."""
        for title in ('Test Results', 'Test Results (Relative)'):
            with self.subTest(title=title):
                body = section(self.page, title)
                refs = FOOTNOTE_REF.findall(body)
                self.assertTrue(refs, f'{title}: no footnote references')
                self.assertEqual(refs.count('*'), FOOTNOTE_BODY.findall(body).count('*'))
                for label in {ref for ref in refs if ref.startswith('#')}:
                    self.assertEqual(FOOTNOTE_BODY.findall(body).count(label), 1, label)


class ProvenanceTests(unittest.TestCase):
    """The page names the report its figures are copied from."""

    def test_names_the_workflow_and_the_discussion_thread(self) -> 'None':
        """And that the figures are copied by hand, not regenerated."""
        text = ' '.join(PAGE.read_text(encoding='utf-8').split())
        for needle in ('.github/workflows/benchmark.yml',
                       '``benchmark: weekly engine benchmark report``',
                       '``CI reports`` Discussions category', 'copied here by hand'):
            with self.subTest(needle=needle):
                self.assertIn(needle, text)


if __name__ == '__main__':
    unittest.main()
