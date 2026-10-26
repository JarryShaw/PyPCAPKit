# -*- coding: utf-8 -*-
"""Plain comments cite issues and pull requests as ``#NNN``, not by Sphinx role.

The ``:issue:`` and ``:pr:`` roles render only where Sphinx reads the text: in
docstrings, in ``#:`` attribute doc-comments that autodoc picks up, and in
``.rst`` files. In a plain ``#`` comment nothing renders them, so the role is
noise around the number a reader wants, and ``#NNN`` is what GitHub links.

Comments are read from :mod:`tokenize` ``COMMENT`` tokens, so a docstring that
cites an issue by role is not a comment, and a ``#:`` doc-comment is skipped on
purpose. :data:`META_MENTIONS` holds the comments that talk about the roles
themselves rather than cite an issue with one. This module is unit-tier: it
imports nothing it scans.

"""
from __future__ import annotations

import io
import re
import shutil
import subprocess  # nosec: B404
import tokenize
import unittest
from typing import TYPE_CHECKING

from tests._tiers import ROOT

if TYPE_CHECKING:
    from typing import Iterator

#: A Sphinx issue or pull request role, cited or merely named.
ROLE = re.compile(r':(?:issue|pr):`')

#: Comments that name a role without citing anything by it, as the path and the
#: comment's text. Each is checked to still exist, so the list cannot go stale.
META_MENTIONS = frozenset({
    # Explains that the two roles share one ``#%s`` caption.
    ('docs/source/conf.py',
     '# The caption is ``#%s`` for both ``:issue:`` and ``:pr:`` so that converting a bare'),
    # Explains why a Discussion number cannot be cited with the issue role.
    ('docs/source/conf.py',
     '# ``:issue:`` would link to a page that does not exist.'),
    # Describes the changelog converter's test input, which uses the role.
    ('tests/project/test_changelog_md.py',
     '# unconverted and raises, and the ``:issue:`` half converts, so only'),
})


def tracked() -> 'list[str]':
    """Every ``.py`` path git tracks, or skip when this is not a checkout."""
    if shutil.which('git') is None or not (ROOT / '.git').exists():
        raise unittest.SkipTest('not a git checkout')
    result = subprocess.run(['git', 'ls-files', '-z', '--', '*.py'], cwd=ROOT,  # nosec
                            capture_output=True, check=True)
    return sorted(name for name in result.stdout.decode('utf-8').split('\0') if name)


def role_comments(source: 'bytes') -> 'Iterator[tuple[int, str]]':
    """The line and text of each plain comment in ``source`` that holds a role."""
    for token in tokenize.tokenize(io.BytesIO(source).readline):
        if token.type == tokenize.COMMENT and not token.string.startswith('#:') \
                and ROLE.search(token.string):
            yield token.start[0], token.string


def repository_role_comments() -> 'list[tuple[str, int, str]]':
    """Every plain comment holding a role in a tracked ``.py`` file."""
    return [(path, line, text)
            for path in tracked()
            for line, text in role_comments((ROOT / path).read_bytes())]


class ScannerTests(unittest.TestCase):
    """The scan reads plain comments only."""

    def test_flags_a_plain_comment(self) -> None:
        source = b'x = 1  # see :issue:`12`\n# and :pr:`34`\n'
        self.assertEqual([line for line, _ in role_comments(source)], [1, 2])

    def test_skips_docstrings_and_strings(self) -> None:
        source = b'def f():\n    """Fixed in :issue:`12`."""\n    return ":pr:`34`"  # #56\n'
        self.assertEqual(list(role_comments(source)), [])

    def test_skips_attribute_doc_comments(self) -> None:
        self.assertEqual(list(role_comments(b'#: Added in :issue:`12`.\nx = 1\n')), [])

    def test_meta_mentions_still_exist(self) -> None:
        found = {(path, text) for path, _, text in repository_role_comments()}
        self.assertEqual(sorted(META_MENTIONS - found), [], 'stale META_MENTIONS entries')


class IssueRefTests(unittest.TestCase):
    """No plain comment cites an issue or pull request by Sphinx role."""

    def test_plain_comments_use_hash_numbers(self) -> None:
        offending = [f'{path}:{line}: {text}' for path, line, text in repository_role_comments()
                     if (path, text) not in META_MENTIONS]
        self.assertEqual(offending, [], 'cite issues and pull requests as #NNN in plain comments; '
                                        'the roles belong in docstrings and #: doc-comments')


if __name__ == '__main__':
    unittest.main()
