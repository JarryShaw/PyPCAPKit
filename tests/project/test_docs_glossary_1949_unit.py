# -*- coding: utf-8 -*-
"""Pins the glossary of words that carry several meanings in the docs (#1949).

"Registry", "schema", "data model", "info" and "default engine" each mean
different things on different pages, so a link to any one explanation cannot
resolve them. :file:`docs/source/glossary.rst` says which sense applies where
and links to the page that explains it, and the ambiguous mentions point there
with ``:term:``.

* :class:`PageTests` -- the page exists and sits in the "Guides & Changelog"
  toctree between ``demo`` and ``changelog``.
* :class:`TermTests` -- the page defines exactly the listed terms, each one once
  across the ``.rst`` pages and the :file:`pcapkit/` sources, and each entry links
  to a page or label that exists.
* :class:`RoleTests` -- every ``:term:`` role names a defined term. Sphinx warns
  on an unknown term, but CI's plain ``make html`` does not fail on a warning, so
  a broken role would otherwise build green.
* :class:`DocstringTests` -- :attr:`Protocol.info
  <pcapkit.protocols.protocol.Protocol.info>` says it returns a data model, not
  an "Info dict".

Everything is read as text or parsed with :mod:`ast`; nothing is imported or built.

"""

from __future__ import annotations

import ast
import pathlib
import re
import unittest
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Iterator

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOCS = ROOT / 'docs' / 'source'
PACKAGE = ROOT / 'pcapkit'

GLOSSARY = DOCS / 'glossary.rst'
INDEX = DOCS / 'index.rst'
PROTOCOL = PACKAGE / 'protocols' / 'protocol.py'

#: The terms the glossary page holds, and nothing else.
TERMS = frozenset({'registry', 'schema', 'data model', 'info', 'default engine'})

#: Pages and labels each entry must link to: ``doc:`` names a document relative
#: to :data:`DOCS`, ``ref:`` a label.
REQUIRED_LINKS = {
    'registry': {'doc:pcapkit/const/index', 'doc:pcapkit/vendor/index', 'doc:pcapkit/foundation/registry'},
    'schema': {'ref:ext-new-protocol'},
    'data model': {'ref:ext-new-protocol'},
    'info': {'doc:pcapkit/protocols/protocol', 'doc:pcapkit/corekit/infoclass'},
    'default engine': {'doc:pcapkit/foundation/engines/builtin'},
}

#: Terms defined outside this project and resolved through intersphinx: Python's glossary.
EXTERNAL_TERMS = frozenset({'bytes-like object'})

GLOSSARY_DIRECTIVE = re.compile(r'^(?P<indent>[ \t]*)\.\. glossary::[ \t]*$', re.MULTILINE)
TERM_ROLE = re.compile(r':term:`(?P<body>[^`]+)`')
LINK_ROLE = re.compile(r':(?P<kind>doc|ref):`(?P<body>[^`]+)`')
LABEL = re.compile(r'^[ \t]*\.\. _(?P<name>[^:`]+):[ \t]*$', re.MULTILINE)


def _norm(text: str) -> str:
    """Fold case and whitespace as Sphinx does when matching a term."""
    return ' '.join(text.split()).lower()


def _target(body: str) -> str:
    """The target of a role body: the part in angle brackets, or the whole body."""
    match = re.search(r'<([^<>]+)>\s*$', body)
    return _norm(match.group(1) if match else body)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def sources() -> Iterator[pathlib.Path]:
    """Every ``.rst`` page under :data:`DOCS` and every module under :data:`PACKAGE`."""
    yield from sorted(DOCS.rglob('*.rst'))
    yield from sorted(PACKAGE.rglob('*.py'))


def glossary_entries(text: str) -> Iterator[tuple[str, str]]:
    """Yield ``(term, definition)`` for each term in every ``.. glossary::`` block of ``text``."""
    lines = text.splitlines()
    for match in GLOSSARY_DIRECTIVE.finditer(text):
        base = len(match.group('indent'))
        start = text.count('\n', 0, match.start()) + 1
        block = []
        for line in lines[start:]:
            if line.strip() and _indent(line) <= base:
                break
            block.append(line)
        content = [line for line in block if line.strip() and not line.strip().startswith(':')]
        if not content:
            continue
        level = _indent(content[0])
        # Stacked term lines share the definition that follows them.
        groups = []  # type: list[tuple[list[str], list[str]]]
        for line in block:
            if line.strip() and _indent(line) == level and not line.strip().startswith(':'):
                if not groups or groups[-1][1]:
                    groups.append(([], []))
                groups[-1][0].append(line.strip())
            elif groups and line.strip():
                groups[-1][1].append(line)
        for terms, body in groups:
            for term in terms:
                yield term, '\n'.join(body)


def definitions() -> dict[str, list[str]]:
    """Map each defined term to the files that define it."""
    found = {}  # type: dict[str, list[str]]
    for path in sources():
        text = path.read_text(encoding='utf-8')
        if '.. glossary::' not in text:
            continue
        for term, _ in glossary_entries(text):
            found.setdefault(_norm(term), []).append(path.relative_to(ROOT).as_posix())
    return found


class PageTests(unittest.TestCase):
    """The glossary page exists and is in the guides toctree."""

    def test_page_exists(self) -> None:
        self.assertTrue(GLOSSARY.is_file(), f'{GLOSSARY.relative_to(ROOT)} is missing')

    def test_page_sits_between_demo_and_changelog(self) -> None:
        text = INDEX.read_text(encoding='utf-8')
        match = re.search(r'^\.\. toctree::\n(?:[ \t]+:[^\n]*\n)*?[ \t]+:caption: Guides & Changelog\n'
                          r'(?:[ \t]+:[^\n]*\n)*\n(?P<entries>(?:[ \t]+\S[^\n]*\n)+)', text, re.MULTILINE)
        self.assertIsNotNone(match, 'no "Guides & Changelog" toctree in index.rst')
        assert match is not None
        entries = match.group('entries').split()
        self.assertIn('glossary', entries)
        self.assertEqual(entries[entries.index('glossary') - 1:entries.index('glossary') + 2],
                         ['demo', 'glossary', 'changelog'])


class TermTests(unittest.TestCase):
    """The page defines exactly the listed terms, once each, and every entry links out."""

    def setUp(self) -> None:
        self.assertTrue(GLOSSARY.is_file(), f'{GLOSSARY.relative_to(ROOT)} is missing')
        self.entries = {_norm(term): body for term, body in glossary_entries(GLOSSARY.read_text(encoding='utf-8'))}

    def test_page_holds_only_the_listed_terms(self) -> None:
        self.assertEqual(set(self.entries), set(TERMS))

    def test_each_term_is_defined_once(self) -> None:
        found = definitions()
        for term in sorted(TERMS):
            with self.subTest(term=term):
                self.assertEqual(found.get(term), [GLOSSARY.relative_to(ROOT).as_posix()])

    def test_no_term_is_defined_twice_anywhere(self) -> None:
        for term, files in sorted(definitions().items()):
            with self.subTest(term=term):
                self.assertEqual(len(files), 1, f'{term!r} is defined in {files}')

    def test_each_entry_links_to_the_page_that_explains_it(self) -> None:
        labels = {match.group('name').lower() for path in DOCS.rglob('*.rst')
                  for match in LABEL.finditer(path.read_text(encoding='utf-8'))}
        for term in sorted(TERMS):
            with self.subTest(term=term):
                body = self.entries.get(term, '')
                links = {f"{match.group('kind')}:{_target(match.group('body'))}" for match in LINK_ROLE.finditer(body)}
                self.assertLessEqual(REQUIRED_LINKS[term], links)
                for link in sorted(links):
                    kind, _, target = link.partition(':')
                    if kind == 'doc':
                        self.assertTrue((DOCS / f'{target.lstrip("/")}.rst').is_file(), f'{term}: no page {target}')
                    else:
                        self.assertIn(target, labels, f'{term}: no label {target}')


class RoleTests(unittest.TestCase):
    """Every ``:term:`` role in the docs and the sources names a defined term."""

    def test_every_term_role_resolves(self) -> None:
        defined = set(definitions()) | EXTERNAL_TERMS
        roles = 0
        for path in sources():
            text = path.read_text(encoding='utf-8')
            for match in TERM_ROLE.finditer(text):
                roles += 1
                target = _target(match.group('body'))
                line = text.count('\n', 0, match.start()) + 1
                with self.subTest(site=f'{path.relative_to(ROOT).as_posix()}:{line}'):
                    self.assertIn(target, defined)
        self.assertGreater(roles, 0, 'no :term: role found, so this test checks nothing')

    def test_glossary_terms_are_used(self) -> None:
        used = set()
        for path in sources():
            if path == GLOSSARY:
                continue
            used.update(_target(match.group('body')) for match in TERM_ROLE.finditer(path.read_text(encoding='utf-8')))
        for term in sorted(TERMS):
            with self.subTest(term=term):
                self.assertIn(term, used, f'nothing outside the glossary links to {term!r}')


class DocstringTests(unittest.TestCase):
    """``Protocol.info`` says what it returns."""

    def _docstring(self, name: str) -> str:
        tree = ast.parse(PROTOCOL.read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == 'ProtocolBase':
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and item.name == name:
                        return ast.get_docstring(item) or ''
        self.fail(f'ProtocolBase.{name} not found')

    def test_info_is_not_called_a_dict(self) -> None:
        doc = self._docstring('info')
        self.assertNotIn('info dict', doc.lower())
        self.assertIn(':term:`data model`', doc)


if __name__ == '__main__':
    unittest.main()
