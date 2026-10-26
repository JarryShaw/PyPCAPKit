# -*- coding: utf-8 -*-
"""Pins :class:`~pcapkit.const.ftp.command.FEATCode` as a documented API target.

GitHub issue #934, part B:
:file:`docs/source/contributing/conventions/registry-protocol.rst`
cross-references :class:`~pcapkit.const.ftp.command.FEATCode` with the
``:class:`` role, and those references resolve only because
:file:`docs/source/pcapkit/const/ftp.rst` carries an ``autoclass`` directive for
the class -- without it no page under :file:`docs/source/` documents it and none
of them resolves, as an explicit nitpicky ``sphinx-build`` with and without the
directive confirmed. ``FEATCode`` is not in
:mod:`pcapkit.const.ftp.command`'s ``__all__`` (only ``Command`` is), which is why the
page's ``autoclass:: pcapkit.const.ftp.command.Command`` directive does not
pull it in as a side effect.

This does **not** re-test Sphinx's cross-reference resolution itself -- as
:file:`tests/project/test_sentinels_doc_page_934_unit.py` explains for the sibling
half of this same issue, whether a reference resolves is a property of the built
inventory rather than of the source, and the honest check is the rendered HTML from
an actual ``sphinx-build`` run, not reimplemented here. What this pins is the
purely textual precondition a later edit could silently break even though a plain
(non-nitpicky) build would keep passing either way: the page has to keep declaring
an ``autoclass`` for the class.

"""

from __future__ import annotations

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The page that carries the ``FEATCode`` entry (GitHub issue #934).
PAGE = ROOT / 'docs' / 'source' / 'pcapkit' / 'const' / 'ftp.rst'


class FEATCodeAPIPageTests(unittest.TestCase):
    """The ``ftp.rst`` page's ``autoclass`` entry for ``FEATCode``."""

    def test_page_exists(self) -> 'None':
        """The API page itself is present on disk."""
        self.assertTrue(PAGE.is_file(), f'{PAGE} does not exist')

    def test_page_documents_the_featcode_class(self) -> 'None':
        """The page declares an ``autoclass`` for the class registry-protocol.rst names.

        Without this directive, ``:class:`~pcapkit.const.ftp.command.FEATCode```
        in :file:`docs/source/contributing/conventions/registry-protocol.rst`
        has no target to resolve against -- the exact defect GitHub issue #934
        reports for this class, distinct from the sibling ``sentinels``
        module-level miss part A of the same issue fixed.

        """
        text = PAGE.read_text(encoding='utf-8')
        self.assertRegex(
            text, r'\.\.\s+autoclass::\s+pcapkit\.const\.ftp\.command\.FEATCode\b',
            f'{PAGE} does not declare an autoclass for '
            '"pcapkit.const.ftp.command.FEATCode"',
        )


if __name__ == '__main__':
    unittest.main()
