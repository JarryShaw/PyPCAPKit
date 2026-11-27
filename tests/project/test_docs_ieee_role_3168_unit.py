# -*- coding: utf-8 -*-
"""Pins the ``:ieee:`` role and its table in :file:`docs/source/conf.py` (#3168).

The role links an IEEE standard by designation, ``:ieee:`802.1Q-2022```, through
``IEEE_STANDARDS``, a table from each designation to its IEEE SA page: the page
URLs carry product ids, so no ``extlinks`` template can build them.

* :class:`TableTests` -- each key of the table, read by AST, is a dated
  designation and each URL that designation's IEEE SA page, and no two share a
  product id.
* :class:`CitationTests` -- every role in the text Sphinx renders names a key of
  the table, so the docs build does not stop on it, and no dated IEEE citation is
  left there as plain text.
* :class:`RoleTests` -- the role and the table check under Sphinx: the role links
  and titles a standard, and an unknown designation or a malformed entry stops
  the build. These need Sphinx and the pinned sphinx-autodoc-typehints, and skip
  without them.

The rendered text is read as :file:`test_docs_epilog_links_1936_unit.py` reads it:
``.rst`` pages under :file:`docs/` apart from the changelog, and docstrings and
``#:`` comments under :file:`pcapkit/`.

"""

from __future__ import annotations

import ast
import io
import pathlib
import re
import tempfile
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests.project.test_docs_ambiguous_xrefs_1775_unit import HAS_SPHINX, SPHINX_SKIP_REASON, load_conf
from tests.project.test_docs_epilog_links_1936_unit import CONF, _line, _rel, _rendered, _sources

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): reads docs/source/conf.py and the rendered text, and drives the
#: role under Sphinx where it is installed.
__tier__ = 'LATEST'

#: A designation: the number, amendment letters included, and the edition's year.
DESIGNATION = re.compile(r'(?P<number>\d+(?:\.\d+)*[A-Za-z]*)-(?P<year>(?:19|20)\d{2})')

#: An ``:ieee:`` role, with or without an explicit title.
ROLE = re.compile(r':ieee:`(?:[^`<]*<(?P<titled>[^`>]*)>|(?P<bare>[^`]*))`')

#: A dated IEEE citation written as text, across a line break too.
PLAIN = re.compile(r'(?<![\w`])IEEE(?:\s+Std)?\s+\d+(?:\.\d+)*[A-Za-z]*-(?:19|20)\d{2}(?![\w-])')


def _table() -> 'dict[str, str]':
    """``IEEE_STANDARDS``, read from :file:`conf.py` without importing it."""
    for node in ast.parse(CONF.read_text(encoding='utf-8')).body:
        if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == 'IEEE_STANDARDS' for target in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError('conf.py assigns no IEEE_STANDARDS')


class TableTests(unittest.TestCase):
    """``IEEE_STANDARDS`` maps dated designations to their IEEE SA pages."""

    def test_every_key_is_a_dated_designation(self) -> None:
        bad = [key for key in _table() if DESIGNATION.fullmatch(key) is None]
        self.assertEqual(bad, [])

    def test_every_url_is_the_designations_page(self) -> None:
        bad = []
        for key, url in _table().items():
            match = DESIGNATION.fullmatch(key)
            number = match['number'] if match else key
            if re.fullmatch(rf'https://standards\.ieee\.org/ieee/{re.escape(number)}/\d+/', url) is None:
                bad.append(f'{key}: {url}')
        self.assertEqual(bad, [])

    def test_no_two_designations_share_a_page(self) -> None:
        """The site serves a page by its id alone, so a shared id is a copying slip."""
        urls = list(_table().values())
        self.assertEqual(sorted(url for url in set(urls) if urls.count(url) > 1), [])


class CitationTests(unittest.TestCase):
    """The rendered text cites IEEE standards through the role, by keys of the table."""

    def test_every_role_names_a_key_of_the_table(self) -> None:
        table = _table()
        unknown = []
        cited = set()
        for path in _sources():
            text = _rendered(path)
            for match in ROLE.finditer(text):
                target = match['titled'] if match['titled'] is not None else match['bare']
                cited.add(target)
                if target not in table:
                    unknown.append(f'{_rel(path)}:{_line(text, match.start())}: {match.group(0)}')
        self.assertEqual(unknown, [])
        self.assertTrue(cited, 'no :ieee: role found, so this test read nothing')

    def test_no_dated_citation_is_left_as_text(self) -> None:
        plain = []
        for path in _sources():
            text = _rendered(path)
            for match in PLAIN.finditer(text):
                plain.append(f'{_rel(path)}:{_line(text, match.start())}: {" ".join(match.group(0).split())}')
        self.assertEqual(plain, [])


PAGE = """\
Index
=====

:ieee:`802.1Q-2022` clause 14.4, and :ieee:`the MAC Bridges standard <802.1D-2004>`.
"""


@unittest.skipUnless(HAS_SPHINX, SPHINX_SKIP_REASON)
class RoleTests(unittest.TestCase):
    """The role and the table check, as ``setup`` in :file:`conf.py` registers them."""

    conf = None  # type: Any

    @classmethod
    def setUpClass(cls) -> None:
        cls.conf = load_conf()

    def build(self, page: 'str') -> 'str':
        """Build ``page`` as the only page, failing on any warning, and return its HTML."""
        # pylint: disable=import-outside-toplevel
        from sphinx.application import Sphinx
        from sphinx.util.docutils import docutils_namespace
        tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        root = pathlib.Path(tmp.name)
        src = root / 'src'
        src.mkdir()
        (src / 'index.rst').write_text(page, encoding='utf-8')
        warnings = io.StringIO()
        # NB: as sphinx-build does, so a second application in this process does
        # not warn that the first registered its nodes already.
        with docutils_namespace():
            app = Sphinx(str(src), None, str(root / 'out'), str(root / 'doctrees'), 'html',
                         confoverrides={'project': 'x'}, status=None, warning=warnings, freshenv=True)
            app.add_role('ieee', self.conf.IEEEStandard())
            app.build()
        self.assertEqual(warnings.getvalue(), '')
        return (root / 'out' / 'index.html').read_text(encoding='utf-8')

    def test_the_role_is_registered_by_setup(self) -> None:
        # pylint: disable=import-outside-toplevel
        from sphinx.application import Sphinx
        app = mock.create_autospec(Sphinx, instance=True)
        self.conf.setup(app)
        roles = {call.args[0]: call.args[1] for call in app.add_role.call_args_list}
        self.assertIsInstance(roles.get('ieee'), self.conf.IEEEStandard)
        self.assertIn(mock.call('config-inited', self.conf.check_ieee_standards), app.connect.call_args_list)

    def test_a_designation_links_its_page(self) -> None:
        html = self.build(PAGE)
        self.assertRegex(html, r'<a class="[^"]*\bieee\b[^"]*" href="https://standards\.ieee\.org/ieee/802\.1Q/10323/">'
                               r'<strong>IEEE Std 802\.1Q-2022</strong></a> clause 14\.4')

    def test_an_explicit_title_replaces_the_text(self) -> None:
        html = self.build(PAGE)
        self.assertRegex(html, r'href="https://standards\.ieee\.org/ieee/802\.1D/3387/">'
                               r'<strong>the MAC Bridges standard</strong></a>')

    def test_an_unknown_designation_stops_the_build(self) -> None:
        # pylint: disable=import-outside-toplevel
        from sphinx.errors import SphinxError
        for target in ('802.1Q-2099', '802.1Q', '802.1Q-2022#clause-14.4'):
            with self.subTest(target=target), self.assertRaisesRegex(SphinxError, re.escape(target)):
                self.build(f'Index\n=====\n\n:ieee:`{target}`\n')

    def test_the_table_passes_its_own_check(self) -> None:
        self.conf.check_ieee_standards(None, None)

    def test_a_malformed_entry_stops_the_build(self) -> None:
        # pylint: disable=import-outside-toplevel
        from sphinx.errors import ConfigError
        for entry in ({'802.1Q': 'https://standards.ieee.org/ieee/802.1Q/10323/'},
                      {'802.1D-2004': 'https://standards.ieee.org/ieee/802.1Q/3387/'},
                      {'802.1D-2004': 'https://standards.ieee.org/ieee/802.1D/3387'},
                      {'802.1Q-2099': 'https://standards.ieee.org/ieee/802.1Q/10323/'}):
            with self.subTest(entry=entry), mock.patch.dict(self.conf.IEEE_STANDARDS, entry), \
                    self.assertRaisesRegex(ConfigError, re.escape(next(iter(entry)))):
                self.conf.check_ieee_standards(None, None)


if __name__ == '__main__':
    unittest.main()
