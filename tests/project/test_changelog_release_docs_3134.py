# -*- coding: utf-8 -*-
"""#3134: each changelog entry links its release's documentation on Read the Docs.

``link_release_docs`` in :file:`docs/source/conf.py` writes the links as each page
is read, so no ``.rst`` source names a URL and a new entry needs no step of its own.

* :class:`TestTheHook` builds a scratch project with the hook connected: the
  changelog's index, an entry's page, an entry in ``UNBUILT_RELEASES``, and a page
  that is neither. It needs Sphinx, and skips without it.
* :class:`TestTheTree` holds the hook to the real changelog: every entry link on
  its index is one the hook reads, ``UNBUILT_RELEASES`` names only real entries,
  and ``setup`` connects the hook.

The hook runs as conf.py defines it, its statements taken by :mod:`ast`, so the
rest of conf.py and its pinned extensions are not needed.

"""

from __future__ import annotations

import ast
import html.parser
import importlib.util
import io
import pathlib
import re
import tempfile
import unittest
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Optional

#: Test tier (#1958): reads the repository's text and runs a hook of its docs build.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONF = ROOT / 'docs' / 'source' / 'conf.py'
CHANGELOG = ROOT / 'docs' / 'source' / 'changelog.rst'
#: The statements of conf.py the hook needs.
NAMES = frozenset({'READ_THE_DOCS', 'UNBUILT_RELEASES', 'CHANGELOG_ENTRY', 'link_release_docs'})
#: Where Read the Docs serves a release's build.
RELEASE_DOCS = 'https://pypcapkit.jarryshaw.me/en/v{}/'
#: A ``:doc:`` role's target, with or without a title.
DOC_ROLE = re.compile(r':doc:`(?:[^`<]*<(?P<titled>[^`>]+)>|(?P<bare>[^`<]+))`')
HAS_SPHINX = all(importlib.util.find_spec(name) is not None for name in ('docutils', 'sphinx'))

#: The scratch project, by document. ``1.4.0`` is in ``UNBUILT_RELEASES``.
PAGES = {
    'index': 'Index\n=====\n\n.. toctree::\n\n   changelog\n   other\n',
    'changelog': (
        'Changelog\n=========\n\n'
        '* **1.9.0** -- A release. :doc:`Full changelog <changelog/1.9.0>`.\n'
        '* **1.4.0** -- A release with no build. :doc:`Full changelog <changelog/1.4.0>`.\n'
        '* **Elsewhere** -- :doc:`other` is no entry.\n\n'
        '.. toctree::\n   :hidden:\n\n   changelog/1.9.0\n   changelog/1.4.0\n'
    ),
    'changelog/1.9.0': '1.9.0 -- 2026-12-01\n===================\n\nIts summary.\n\nAdded\n-----\n\n* A thing.\n',
    'changelog/1.4.0': '1.4.0 -- 2026-08-21\n===================\n\nIts summary.\n',
    'other': 'Other\n=====\n\nSee :doc:`changelog/1.9.0`.\n',
}


def conf_tree() -> 'ast.Module':
    return ast.parse(CONF.read_text(encoding='utf-8'))


def load_hook() -> 'dict[str, Any]':
    """The hook and its constants, run from conf.py's own statements."""
    # pylint: disable=import-outside-toplevel
    from docutils import nodes
    from sphinx import addnodes
    body = [node for node in conf_tree().body
            if getattr(node, 'name', None) in NAMES
            or {getattr(target, 'id', None) for target in getattr(node, 'targets', [])} & NAMES]
    namespace = {'re': re, 'nodes': nodes, 'addnodes': addnodes}  # type: dict[str, Any]
    exec(compile(ast.Module(body=body, type_ignores=[]), str(CONF), 'exec'), namespace)  # nosec: B102
    missing = NAMES - set(namespace)
    if missing:
        raise AssertionError(f'conf.py defines none of {sorted(missing)}')
    return namespace


class Page(html.parser.HTMLParser):
    """A built page's list items and paragraphs, each as its text and its links."""

    def __init__(self, text: 'str') -> None:
        super().__init__()
        self.items = []  # type: list[tuple[str, list[tuple[str, str]]]]
        self.sequence = []  # type: list[tuple[str, str, list[tuple[str, str]]]]
        self.open = []  # type: list[tuple[str, list[str], list[tuple[str, str]]]]
        self.href = None  # type: Optional[str]
        self.feed(text)
        self.close()

    def handle_starttag(self, tag: 'str', attrs: 'list[tuple[str, Optional[str]]]') -> None:
        if tag in ('li', 'p', 'h1', 'h2'):
            self.open.append((tag, [], []))
        elif tag == 'a':
            self.href = dict(attrs).get('href')

    def handle_endtag(self, tag: 'str') -> None:
        if tag == 'a':
            self.href = None
        elif self.open and self.open[-1][0] == tag:
            name, text, links = self.open.pop()
            joined = ' '.join(''.join(text).split())
            self.sequence.append((name, joined, links))
            if name == 'li':
                self.items.append((joined, links))

    def handle_data(self, data: 'str') -> None:
        for _, text, _ in self.open:
            text.append(data)
        if self.href is not None and data.strip():
            for _, _, links in self.open:
                links.append((data, self.href))


@unittest.skipUnless(HAS_SPHINX, 'Sphinx is not installed')
class TestTheHook(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        # pylint: disable=import-outside-toplevel
        from sphinx.application import Sphinx
        from sphinx.util.docutils import docutils_namespace
        hook = load_hook()['link_release_docs']
        tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        cls.addClassCleanup(tmp.cleanup)
        root = pathlib.Path(tmp.name)
        src = root / 'src'
        for name, text in PAGES.items():
            (src / f'{name}.rst').parent.mkdir(parents=True, exist_ok=True)
            (src / f'{name}.rst').write_text(text, encoding='utf-8')
        warnings = io.StringIO()
        # NB: as sphinx-build does, so a second application in this process does
        # not warn that the first registered its nodes already.
        with docutils_namespace():
            app = Sphinx(str(src), None, str(root / 'out'), str(root / 'doctrees'), 'html',
                         confoverrides={'project': 'x', 'html_theme': 'basic', 'smartquotes': False},
                         status=None, warning=warnings, freshenv=True)
            app.connect('doctree-read', hook)
            app.build()
        cls.warnings = warnings.getvalue()
        cls.pages = {name: Page((root / 'out' / f'{name}.html').read_text(encoding='utf-8')) for name in PAGES}

    def item(self, lead: 'str') -> 'tuple[str, list[tuple[str, str]]]':
        return next(item for item in self.pages['changelog'].items if item[0].startswith(lead))

    def test_it_builds_without_a_warning(self) -> None:
        self.assertEqual(self.warnings, '')

    def test_an_index_entry_links_its_release_after_its_page(self) -> None:
        self.assertEqual(self.item('1.9.0'), (
            '1.9.0 -- A release. Full changelog · documentation.',
            [('Full changelog', 'changelog/1.9.0.html'), ('documentation', RELEASE_DOCS.format('1.9.0'))]))

    def test_an_unbuilt_release_and_any_other_link_get_none(self) -> None:
        self.assertEqual(self.item('1.4.0'), ('1.4.0 -- A release with no build. Full changelog.',
                                              [('Full changelog', 'changelog/1.4.0.html')]))
        self.assertEqual(self.item('Elsewhere'), ('Elsewhere -- Other is no entry.', [('Other', 'other.html')]))

    def test_an_entry_page_links_its_release_under_its_title(self) -> None:
        sequence = self.pages['changelog/1.9.0'].sequence
        title = next(index for index, (tag, *_) in enumerate(sequence) if tag == 'h1')
        self.assertEqual(sequence[title + 1], ('p', 'Documentation of this release',
                                               [('Documentation of this release', RELEASE_DOCS.format('1.9.0'))]))
        links = [link for _, _, found in sequence for link in found]
        self.assertEqual([href for _, href in links if href.startswith('https://')], [RELEASE_DOCS.format('1.9.0')])

    def test_no_other_page_gets_a_link(self) -> None:
        for name in ('changelog/1.4.0', 'other', 'index'):
            links = [href for _, _, found in self.pages[name].sequence for _, href in found]
            with self.subTest(page=name):
                self.assertEqual([href for href in links if href.startswith('https://')], [])


class TestTheTree(unittest.TestCase):

    def test_every_entry_link_on_the_index_is_one_the_hook_reads(self) -> None:
        entry = re.compile(r'changelog/(?P<release>\d+(?:\.\d+)*)')
        targets = [match['titled'] or match['bare'] for match in DOC_ROLE.finditer(CHANGELOG.read_text(encoding='utf-8'))]
        pages = sorted(path.stem for path in (CHANGELOG.parent / 'changelog').glob('*.rst'))
        self.assertEqual(sorted(entry.fullmatch(target)['release'] for target in targets), pages)
        if HAS_SPHINX:
            pattern = load_hook()['CHANGELOG_ENTRY']
            self.assertEqual([target for target in targets if not pattern.fullmatch(target)], [])

    @unittest.skipUnless(HAS_SPHINX, 'Sphinx is not installed')
    def test_unbuilt_releases_name_real_entries(self) -> None:
        unbuilt = load_hook()['UNBUILT_RELEASES']
        self.assertIn('1.4.0', unbuilt)
        for release in unbuilt:
            with self.subTest(release=release):
                self.assertTrue((CHANGELOG.parent / 'changelog' / f'{release}.rst').is_file())

    def test_setup_connects_the_hook_as_each_page_is_read(self) -> None:
        setup = next(node for node in conf_tree().body if isinstance(node, ast.FunctionDef) and node.name == 'setup')
        calls = [(call.args[0].value, call.args[1].id) for call in ast.walk(setup)
                 if isinstance(call, ast.Call) and getattr(call.func, 'attr', None) == 'connect'
                 and len(call.args) == 2 and isinstance(call.args[0], ast.Constant)
                 and isinstance(call.args[1], ast.Name)]
        self.assertIn(('doctree-read', 'link_release_docs'), calls)


if __name__ == '__main__':
    unittest.main()
