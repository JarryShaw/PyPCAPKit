# -*- coding: utf-8 -*-
"""Tests for :file:`util/changelog_md.py`, the ``CHANGELOG.md`` generator.

``CHANGELOG.md`` is a derived artefact: it is the newest
:file:`docs/source/changelog/<version>.rst` entry converted to Markdown, so that
the ``Create Release`` workflow's release body and the source distribution get
Markdown without a second copy of the history to keep in step by hand.

The conversion is six mechanical rules over a small reStructuredText subset, and
there is one test per rule. Each asserts both halves -- that the Markdown form
arrived *and* that the reStructuredText form is gone -- because a rule that fires
in the wrong place and a rule that does not fire at all both leave markup in a
published release body, and only checking for the new spelling would miss the
second.

The rest cover the two things that are easy to get wrong and invisible when they
are: which entry counts as "newest" (the toctree's first line, not a sort of the
version strings), and ``--check``, which is what a CI gate calls and is worthless
if it cannot fail.

Almost everything here builds its own two-file changelog tree in a temporary
directory rather than reading the repository's. That keeps the rule tests honest
-- each entry is written to exercise one rule, instead of hoping the real
changelog happens to contain the construct -- and it keeps them passing on a
source tarball, where :file:`docs/` has been pruned away.

"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import pathlib
import re
import shutil
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _load_generator():
    """Load :file:`util/changelog_md.py` as a module.

    ``util/`` is a directory of scripts rather than a package, so there is no
    import path to it. The script has no import-time side effects, which is what
    makes loading it by location safe.

    """
    path = ROOT / 'util' / 'changelog_md.py'
    spec = importlib.util.spec_from_file_location('changelog_md', path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


changelog_md = _load_generator()


#: One entry exercising all six rules at once: a setext heading, a wrapped
#: paragraph, ``*`` bullets whose text wraps, an ``:rfc:`` role, a double-backtick
#: literal, and a footnote reference with its definition.
ENTRY = """\
9.9.9 -- 2026-01-02
===================

An entry whose prose is wrapped across
two source lines, so that rule 6 has
something to collapse.

* **Added** -- ESP parsing [:rfc:`4303`], with a ``literal`` in it
  and a continuation line.
* **Fixed** -- PCAP-NG support [1]_.

.. [1] PCAP-NG is specified by a draft, not by an RFC.
"""

INDEX = """\
=========
Changelog
=========

Preamble.

.. toctree::
   :maxdepth: 1

   changelog/9.9.9
"""


class ChangelogTreeMixin:
    """Builds a throwaway changelog tree for one test."""

    def make_tree(self, entry: str = ENTRY, index: str = INDEX,
                  version: str = '9.9.9') -> pathlib.Path:
        """Write *index* and *entry* into a temporary tree; return the index path."""
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)

        (root / 'changelog').mkdir()
        (root / 'changelog' / f'{version}.rst').write_text(entry, encoding='utf-8')
        index_path = root / 'changelog.rst'
        index_path.write_text(index, encoding='utf-8')
        return index_path

    def convert(self, entry: str = ENTRY) -> str:
        """Convert *entry* through the generator, as ``render`` would."""
        return changelog_md.convert(entry)


class ConversionRuleTests(ChangelogTreeMixin, unittest.TestCase):
    """One test per conversion rule."""

    def test_rule_1_setext_heading_becomes_atx(self) -> None:
        markdown = self.convert()

        self.assertTrue(
            markdown.startswith('## 9.9.9 -- 2026-01-02\n'),
            f'expected an ATX heading first, got {markdown[:60]!r}',
        )
        # The underline must be consumed, not merely followed by a heading.
        self.assertNotRegex(markdown, r'(?m)^=+$')

    def test_rule_2_rfc_role_becomes_a_datatracker_link(self) -> None:
        markdown = self.convert()

        self.assertIn('[RFC 4303](https://datatracker.ietf.org/doc/html/rfc4303)', markdown)
        self.assertNotIn(':rfc:', markdown)

    def test_rule_3_double_backtick_literal_becomes_a_code_span(self) -> None:
        markdown = self.convert()

        self.assertIn('`literal`', markdown)
        self.assertNotIn('``', markdown)

    def test_rule_4_star_bullets_become_dash_bullets(self) -> None:
        markdown = self.convert()

        bullets = [line for line in markdown.split('\n') if line.startswith('- ')]
        self.assertEqual(len(bullets), 2, f'expected two dash bullets, got {bullets!r}')
        self.assertNotRegex(markdown, r'(?m)^\*[ \t]')

    def test_rule_5_footnotes_become_github_footnotes(self) -> None:
        markdown = self.convert()

        self.assertIn('[^1]', markdown)
        self.assertRegex(markdown, r'(?m)^\[\^1\]: PCAP-NG is specified by a draft')
        self.assertNotIn('[1]_', markdown)
        self.assertNotRegex(markdown, r'(?m)^\.\. \[1\]')

    def test_rule_6_paragraphs_and_bullets_are_unwrapped(self) -> None:
        markdown = self.convert()

        # A GitHub release body renders a single newline as a hard break, so every
        # block has to be one line: the source's own wrapping must be gone.
        self.assertIn(
            'An entry whose prose is wrapped across two source lines, so that '
            'rule 6 has something to collapse.',
            markdown,
        )
        self.assertIn('with a `literal` in it and a continuation line.', markdown)

        # Nothing but blank lines separates the blocks, so no line may be a bare
        # continuation of the one above it.
        for line in markdown.split('\n'):
            if line and not line.startswith(('## ', '- ', '[^')):
                self.assertTrue(
                    line[0].isupper() or line.startswith('---'),
                    f'{line[:50]!r} looks like a wrapped continuation line',
                )


class NewestEntryTests(ChangelogTreeMixin, unittest.TestCase):
    """How the generator decides which entry is the current release."""

    def test_newest_is_the_toctree_head_not_a_version_sort(self) -> None:
        index = self.make_tree(
            index=textwrap.dedent("""\
                =========
                Changelog
                =========

                .. toctree::
                   :maxdepth: 1

                   changelog/1.10.0
                   changelog/1.9.0
                """),
            version='1.10.0',
        )
        (index.parent / 'changelog' / '1.9.0.rst').write_text(ENTRY, encoding='utf-8')

        version, entry = changelog_md.newest(index)

        # ``1.9.0`` sorts above ``1.10.0`` lexically and below it under PEP 440;
        # the toctree settles it without the generator having to know either rule.
        self.assertEqual(version, '1.10.0')
        self.assertEqual(entry.name, '1.10.0.rst')

    def test_toctree_options_and_blank_lines_are_not_entries(self) -> None:
        index = self.make_tree()

        self.assertEqual(changelog_md.read_toctree(index), ['changelog/9.9.9'])

    def test_explicit_title_form_is_reduced_to_the_docname(self) -> None:
        index = self.make_tree(index=INDEX.replace(
            '   changelog/9.9.9', '   The 9.9.9 release <changelog/9.9.9>'))

        self.assertEqual(changelog_md.read_toctree(index), ['changelog/9.9.9'])

    def test_dotted_version_is_not_mistaken_for_a_file_extension(self) -> None:
        # ``pathlib.Path.with_suffix`` would turn ``changelog/9.9.9`` into
        # ``changelog/9.9.rst``, because a version string ends in what looks like
        # an extension.
        version, entry = changelog_md.newest(self.make_tree())

        self.assertEqual(version, '9.9.9')
        self.assertEqual(entry.name, '9.9.9.rst')

    def test_missing_toctree_is_an_error(self) -> None:
        index = self.make_tree(index='=========\nChangelog\n=========\n')

        with self.assertRaises(ValueError):
            changelog_md.read_toctree(index)

    def test_empty_toctree_is_an_error(self) -> None:
        index = self.make_tree(index='.. toctree::\n   :maxdepth: 1\n')

        with self.assertRaises(ValueError):
            changelog_md.read_toctree(index)

    def test_toctree_head_naming_a_missing_file_is_an_error(self) -> None:
        index = self.make_tree(index=INDEX.replace('9.9.9', '9.9.8'))

        with self.assertRaises(FileNotFoundError):
            changelog_md.newest(index)


class ResidualMarkupTests(ChangelogTreeMixin, unittest.TestCase):
    """The guard against six regexes quietly copying through what they cannot convert."""

    def test_an_unconvertible_directive_is_fatal(self) -> None:
        index = self.make_tree(entry=ENTRY + '\n.. note::\n\n   Not in the subset.\n')

        with self.assertRaises(changelog_md.ResidualMarkupError) as error:
            changelog_md.render(index)

        self.assertIn('directive', str(error.exception))

    def test_an_unconverted_role_is_fatal(self) -> None:
        index = self.make_tree(entry=ENTRY + '\nSee :mod:`pcapkit.const` for more.\n')

        with self.assertRaises(changelog_md.ResidualMarkupError) as error:
            changelog_md.render(index)

        self.assertIn('role', str(error.exception))

    def _reject(self, tail: str, expected: str) -> str:
        """Assert an entry ending in *tail* is refused, naming *expected*."""
        index = self.make_tree(entry=ENTRY + tail)

        with self.assertRaises(changelog_md.ResidualMarkupError) as error:
            changelog_md.render(index)

        message = str(error.exception)
        self.assertIn(expected, message)
        return message

    def test_an_inline_hyperlink_reference_is_fatal(self) -> None:
        # The worst of the five: GFM renders ```text <url>`_`` as broken inline
        # code followed by a stray underscore, so the link target vanishes
        # silently rather than merely looking wrong.
        self._reject('\nSee `the RFC index <https://www.rfc-editor.org/>`_ for more.\n',
                     'hyperlink reference')

    def test_an_anonymous_hyperlink_reference_is_fatal(self) -> None:
        self._reject('\nSee `the RFC index <https://www.rfc-editor.org/>`__ for more.\n',
                     'hyperlink reference')

    def test_a_substitution_reference_is_fatal(self) -> None:
        self._reject('\nShipped in |version| of the library.\n', 'substitution')

    def test_a_field_list_is_fatal(self) -> None:
        self._reject('\n:Author: Jarry Shaw\n:Version: 9.9.9\n', 'field list')

    def test_a_line_block_is_fatal(self) -> None:
        # Rule 6 joins these into ``| One line | Another line``, which GFM can
        # read as a table row.
        self._reject('\n| One line\n| Another line\n', 'line block')

    def test_a_grid_table_is_fatal(self) -> None:
        self._reject(
            '\n'
            '+----------+----------+\n'
            '| Column A | Column B |\n'
            '+==========+==========+\n'
            '| a        | b        |\n'
            '+----------+----------+\n',
            'grid table',
        )

    def test_a_simple_table_is_fatal(self) -> None:
        self._reject(
            '\n'
            '========  ========\n'
            'Column A  Column B\n'
            '========  ========\n'
            'a         b\n'
            '========  ========\n',
            'simple table',
        )

    def test_a_sub_heading_underline_joined_into_the_prose_is_fatal(self) -> None:
        # Rule 1 only consumes ``=`` underlines, so a ``-`` underlined sub-heading
        # is joined onto the heading text by rule 6 and would otherwise disappear
        # into a paragraph.
        self._reject('\nA sub heading\n-------------\n\nSome prose.\n',
                     'setext underline joined')

    def test_an_over_long_equals_underline_is_fatal(self) -> None:
        # Rule 1 fires only when the underline is exactly as long as the title,
        # but reStructuredText merely requires it to be no shorter -- so an
        # over-long one falls past rule 1 and is joined like any other underline.
        self._reject('\nA sub heading\n==================\n\nSome prose.\n',
                     'setext underline joined')

    def test_the_generated_files_own_trailer_is_not_a_leftover(self) -> None:
        # The trailer's ``---`` sits alone on its line, and the joined-underline
        # pattern requires text before the run, so the guard cannot fire on the
        # file it is protecting. Checked on the whole rendered output, trailer
        # included, rather than on the body render() already checks.
        self.assertEqual(changelog_md.residual(changelog_md.render(self.make_tree())), [])

    def test_markup_quoted_inside_a_code_span_is_not_a_leftover(self) -> None:
        # The real 1.5.0 entry says ``a Sphinx-only ``:mod:`` role``, which
        # converts to the code span ```:mod:```. That is prose about a role, not a
        # role that escaped rule 2, and it must not trip the guard.
        markdown = self.convert(
            ENTRY + '\nPyPI rejected a Sphinx-only ``:mod:`` role in ``README.rst``.\n')

        self.assertEqual(changelog_md.residual(markdown), [])

    def test_the_real_entries_are_all_within_the_subset(self) -> None:
        directory = changelog_md.INDEX.parent / 'changelog'
        if not directory.is_dir():
            self.skipTest(f'{directory} is absent (docs/ is pruned from a source tarball)')

        for entry in sorted(directory.glob('*.rst')):
            with self.subTest(entry=entry.name):
                self.assertEqual(
                    changelog_md.residual(changelog_md.convert(
                        entry.read_text(encoding='utf-8'))),
                    [],
                )


class CheckModeTests(ChangelogTreeMixin, unittest.TestCase):
    """``--check`` is what a CI gate calls, so it has to fail when it should."""

    def _run(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = changelog_md.main(list(argv))
        return status, out.getvalue(), err.getvalue()

    def test_check_passes_when_the_file_is_in_step(self) -> None:
        index = self.make_tree()
        output = index.parent / 'CHANGELOG.md'
        output.write_text(changelog_md.render(index), encoding='utf-8')

        status, stdout, _ = self._run('--check', '--index', str(index),
                                     '--output', str(output))

        self.assertEqual(status, 0)
        self.assertIn('in step', stdout)

    def test_check_fails_on_a_one_character_edit(self) -> None:
        index = self.make_tree()
        output = index.parent / 'CHANGELOG.md'
        generated = changelog_md.render(index)
        output.write_text(generated.replace('ESP parsing', 'ESP parsinG', 1), encoding='utf-8')

        status, _, stderr = self._run('--check', '--index', str(index),
                                     '--output', str(output))

        self.assertEqual(status, 1)
        self.assertIn('drifted', stderr)
        self.assertIn('---', stderr)  # a unified diff, so the reviewer sees what moved

    def test_check_fails_when_the_file_is_missing(self) -> None:
        index = self.make_tree()

        status, _, stderr = self._run('--check', '--index', str(index),
                                     '--output', str(index.parent / 'CHANGELOG.md'))

        self.assertEqual(status, 1)
        self.assertIn('drifted', stderr)

    def test_writing_then_checking_round_trips(self) -> None:
        index = self.make_tree()
        output = index.parent / 'CHANGELOG.md'

        write_status, _, _ = self._run('--index', str(index), '--output', str(output))
        check_status, _, _ = self._run('--check', '--index', str(index),
                                      '--output', str(output))

        self.assertEqual((write_status, check_status), (0, 0))

    def test_generated_file_carries_the_trailer(self) -> None:
        markdown = changelog_md.render(self.make_tree())

        self.assertIn(changelog_md.DOCS_URL, markdown)
        self.assertTrue(markdown.endswith('\n'))


class RepositoryStateTests(unittest.TestCase):
    """Checks against the repository rather than a fixture."""

    def test_docs_url_matches_the_pyproject_changelog_url(self) -> None:
        # ``MANIFEST.in`` prunes ``docs/``, so the trailer's link is the only route
        # from the shipped changelog to the rest of the history. If the two drift,
        # the sdist points at a page that may not exist.
        pyproject = (ROOT / 'pyproject.toml').read_text(encoding='utf-8')
        declared = re.search(r'(?m)^changelog\s*=\s*"([^"]+)"', pyproject)

        self.assertIsNotNone(declared, 'pyproject.toml declares no [project.urls].changelog')
        assert declared is not None
        self.assertEqual(changelog_md.DOCS_URL, declared.group(1))

    def test_committed_changelog_is_in_step_with_the_newest_entry(self) -> None:
        if not changelog_md.INDEX.is_file():
            self.skipTest(f'{changelog_md.INDEX} is absent')
        if not changelog_md.OUTPUT.is_file():
            self.skipTest(f'{changelog_md.OUTPUT} is absent')

        self.assertEqual(
            changelog_md.OUTPUT.read_text(encoding='utf-8'),
            changelog_md.render(),
            'CHANGELOG.md is stale; regenerate it with util/changelog_md.py',
        )


if __name__ == '__main__':
    unittest.main()
