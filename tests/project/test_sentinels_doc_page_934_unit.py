# -*- coding: utf-8 -*-
"""Pins the API page for :mod:`pcapkit.corekit.sentinels` existing and reachable.

GitHub issue #934: :file:`docs/source/contributing/conventions.rst` cross-references
:mod:`pcapkit.corekit.sentinels` five times (the ``:mod:`` role, at lines 165, 168, 171,
174 and 261), and none of them used to resolve, because no page under
:file:`docs/source/` documented that module -- confirmed by an explicit nitpicky
``sphinx-build`` before this page existed, and again after, to confirm the fix.

This does **not** re-test Sphinx's cross-reference resolution itself -- as
:file:`tests/project/test_documentation_claims.py` explains at length, whether a
reference resolves is a property of the built inventory rather than of the source, and
the honest check is the rendered HTML from an actual ``sphinx-build`` run, recorded in
the pull request rather than reimplemented here. What this pins instead is the two
purely textual preconditions a later edit could silently break even though a plain
(non-nitpicky) build would keep passing either way: the page has to keep existing and
keep declaring the module it documents, and the ``corekit`` index has to keep listing it
in its toctree so it is not an orphan page -- Sphinx does not fail a plain build over an
orphan page either, so nothing else would catch that regression.

"""

from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The page GitHub issue #934 added.
PAGE = ROOT / 'docs' / 'source' / 'pcapkit' / 'corekit' / 'sentinels.rst'

#: The ``corekit`` API index, whose toctree has to list the page above.
INDEX = ROOT / 'docs' / 'source' / 'pcapkit' / 'corekit' / 'index.rst'


def _toctree_entries(text: 'str') -> 'list[str]':
    """Return the entries of the first ``.. toctree::`` directive in ``text``.

    Parsed structurally -- skip the directive's own options (``:maxdepth:`` and
    the like), then collect non-blank lines until the entry block ends -- rather
    than searched for a literal substring, so a reordering or an added option
    does not make this misreport what the toctree actually names.

    """
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == '.. toctree::':
            break
    else:
        raise AssertionError('no ".. toctree::" directive found')

    entries = []  # type: list[str]
    started = False
    for line in lines[index + 1:]:
        stripped = line.strip()
        if not stripped:
            if started:
                break
            continue
        if stripped.startswith(':'):
            continue
        started = True
        entries.append(stripped)
    return entries


class SentinelsAPIPageTests(unittest.TestCase):
    """The page GitHub issue #934 added, and its registration in the toctree."""

    def test_page_exists(self) -> 'None':
        """The API page itself is present on disk."""
        self.assertTrue(PAGE.is_file(), f'{PAGE} does not exist')

    def test_page_documents_the_sentinels_module(self) -> 'None':
        """The page declares the module it is meant to document.

        Without this directive, ``autoclass``/``autodata`` targets on the page
        would still resolve by their own fully-qualified names, but the plain
        :mod:`pcapkit.corekit.sentinels` reference itself -- the exact role
        GitHub issue #934 is about -- would not.

        Matches either ``.. module::`` or ``.. automodule::``: both register the
        same ``py:module`` target Sphinx resolves ``:mod:`` roles against, so a
        later switch between the two keeps the contract this test pins rather
        than failing over a directive choice that was never the point.

        """
        text = PAGE.read_text(encoding='utf-8')
        self.assertRegex(
            text, r'\.\.\s+(?:auto)?module::\s+pcapkit\.corekit\.sentinels\b',
            f'{PAGE} does not declare "pcapkit.corekit.sentinels" as its module',
        )

    def test_page_is_registered_in_the_corekit_toctree(self) -> 'None':
        """The ``corekit`` index lists the page, so it is not an orphan.

        An orphan page still resolves cross-references -- Sphinx's reference
        inventory does not care whether a page is reachable from a toctree --
        but it produces a distinct "document isn't included in any toctree"
        warning, which is a different defect from the one GitHub issue #934
        reports. Pinning both closes the two ways this fix can go wrong.

        """
        entries = _toctree_entries(INDEX.read_text(encoding='utf-8'))
        self.assertIn(
            'sentinels', entries,
            f'{INDEX} toctree does not list "sentinels": {entries!r}',
        )


if __name__ == '__main__':
    unittest.main()
