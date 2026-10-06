# -*- coding: utf-8 -*-
"""Every commit type :file:`CONTRIBUTING.md` allows has a box in the PR template (#1102).

:file:`CONTRIBUTING.md` lists the valid ``type`` prefixes of a commit subject, and
:file:`.github/PULL_REQUEST_TEMPLATE.md` asks the contributor to tick the one their
subject carries. The template had no ``release`` box although ``release`` is a listed
type with commits in the history, so a version-bump pull request had nothing to tick.

"""

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class TestPullRequestTemplateCommitTypes(unittest.TestCase):
    """The template's commit-type boxes match :file:`CONTRIBUTING.md`'s type list."""

    def _contributing_types(self) -> 'list[str]':
        text = ' '.join((ROOT / 'CONTRIBUTING.md').read_text(encoding='utf-8').split())
        match = re.search(r'`type` is one of (.*?) —', text)
        self.assertIsNotNone(match, 'CONTRIBUTING.md no longer states "`type` is one of ..."')
        return re.findall(r'`([a-z]+)`', match.group(1))  # type: ignore[union-attr]

    def _template_types(self) -> 'list[str]':
        text = (ROOT / '.github' / 'PULL_REQUEST_TEMPLATE.md').read_text(encoding='utf-8')
        return re.findall(r'^- \[ \] `([a-z]+)` — ', text, re.MULTILINE)

    def test_every_contributing_type_has_a_template_box(self) -> 'None':
        """Each type :file:`CONTRIBUTING.md` lists is tickable, and nothing else is."""
        listed = self._contributing_types()
        self.assertGreaterEqual(len(listed), 9,
                                f'only {listed!r} parsed out of CONTRIBUTING.md; '
                                'the comparison below would pass vacuously')
        self.assertEqual(sorted(self._template_types()), sorted(listed),
                         'the pull request template\'s commit-type boxes differ from '
                         'the types CONTRIBUTING.md lists')


if __name__ == '__main__':
    unittest.main()
