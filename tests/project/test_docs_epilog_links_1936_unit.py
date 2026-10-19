# -*- coding: utf-8 -*-
"""Pins the project links defined once in ``rst_epilog`` (#1936).

A package with no ``py:`` objects to cross-reference (#934, #1919) is linked to
its project page as ``|pkg|_``, and every third-party project target is defined
once, in ``rst_epilog`` in :file:`docs/source/conf.py`. Sphinx appends that to
every page, so a second definition in a page or a docstring is a duplicate: an
error for a substitution, a warning for a target with another URL.

* :class:`EpilogTests` -- the epilog defines a target for each substitution,
  and a substitution for each package this module links.
* :class:`LinkedPackageTests` -- a bare literal of such a package appears only
  where it names an engine, an adapter, a toolkit or a requirement.
* :class:`DefinitionTests` -- each ``|name|_`` used is defined, and no page or
  docstring defines an epilog name again.

Only the text Sphinx renders is read: ``.rst`` pages under :file:`docs/` apart
from the changelog, and docstrings and ``#:`` comments under :file:`pcapkit/`.

"""

from __future__ import annotations

import ast
import io
import pathlib
import re
import tokenize
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONF = ROOT / 'docs' / 'source' / 'conf.py'

#: Packages linked as ``|pkg|_``. ``pcap`` is not one: two distributions install
#: it, so no one project page is its target, and it stays a literal.
LINKED = ('aenum', 'cryptography', 'dpkt', 'emoji', 'pcapfile', 'pyshark')

#: A list of literals that names engines, adapters or toolkits.
ENGINE_LIST = re.compile(r'``\w+``(?:,\s+``\w+``)*(?:,?\s+(?:and|or)\s+``\w+``)?'
                         r'\s+(?:engines?|toolkits?|adapters?)\b')

#: The first cell of a simple-table row, which names an engine.
TABLE_CELL = re.compile(r'(?m)^[ \t]*``\w+``(?:[ \t]+\[[^\]]+\]_)?[ \t]{2,}\S')

#: Literals that name engines or requirements without saying so in the words
#: :data:`ENGINE_LIST` matches, by path.
EXEMPT = {
    'docs/source/contributing/pep.rst': (
        r'``pyshark``, ``pypcap`` and\s+``pcap_ct`` disable',
    ),
    'docs/source/index.rst': (
        r'``pypcap`` and ``pypcapfile`` stop at 3\.11, and ``pyshark`` at 3\.13',
        r'core addons only: ``emoji``, ``cryptography``',
        r'``dpkt``, ``scapy``, ``pyshark``, ``requests``',
    ),
}

TARGET = re.compile(r'(?m)^[ \t]*\.\. _([^:`\n]+):[ \t]*(\S+)[ \t]*$')
SUBST = re.compile(r'(?m)^[ \t]*\.\. \|([^|\n]+)\| replace::')
SUBST_REF = re.compile(r'(?<![\w|])\|([^|\s][^|\n]*?)\|_')


def _norm(name: 'str') -> 'str':
    """A reference name as docutils compares it: case- and whitespace-folded."""
    return ' '.join(name.split()).lower()


def _epilog() -> 'str':
    """The ``rst_epilog`` string, read from :file:`conf.py` without importing it."""
    for node in ast.parse(CONF.read_text(encoding='utf-8')).body:
        if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == 'rst_epilog' for target in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError('conf.py assigns no rst_epilog')


def _rendered(path: 'pathlib.Path') -> 'str':
    """The text of *path* Sphinx renders, everything else blanked in place.

    Offsets into the result are offsets into the file, so a match maps back to
    its line. A ``#:`` prefix is blanked too, so a comment reads as prose.

    """
    text = path.read_text(encoding='utf-8')
    if path.suffix == '.rst':
        return text
    keep = set()
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, str):
            keep.update(range(node.lineno, node.end_lineno + 1))
    comments = {tok.start[0] for tok in tokenize.generate_tokens(io.StringIO(text).readline)
                if tok.type == tokenize.COMMENT and tok.string.startswith('#:')}
    lines = []
    for num, line in enumerate(text.split('\n'), 1):
        if num in keep:
            lines.append(line)
        elif num in comments:
            start = line.index('#:')
            lines.append(' ' * (start + 2) + line[start + 2:])
        else:
            lines.append(' ' * len(line))
    return '\n'.join(lines)


def _sources(*, changelog: 'bool' = False) -> 'list[pathlib.Path]':
    """Every ``.rst`` under :file:`docs/` and ``.py`` under :file:`pcapkit/`."""
    pages = sorted((ROOT / 'docs').rglob('*.rst'))
    if not changelog:
        pages = [page for page in pages if 'changelog' not in page.relative_to(ROOT).parts]
    return pages + sorted((ROOT / 'pcapkit').rglob('*.py'))


def _rel(path: 'pathlib.Path') -> 'str':
    return path.relative_to(ROOT).as_posix()


def _line(text: 'str', offset: 'int') -> 'int':
    return text.count('\n', 0, offset) + 1


class EpilogTests(unittest.TestCase):
    """``rst_epilog`` pairs each substitution with a target."""

    def test_each_substitution_has_a_target(self) -> 'None':
        """``|name|_`` resolves to the target of the same name."""
        epilog = _epilog()
        targets = {_norm(name): url for name, url in TARGET.findall(epilog)}
        for name in SUBST.findall(epilog):
            self.assertIn(_norm(name), targets, name)
        for name, url in targets.items():
            self.assertTrue(url.startswith('https://'), f'{name}: {url}')

    def test_each_linked_package_has_a_substitution(self) -> 'None':
        """Every name in :data:`LINKED`, and not ``pcap``."""
        names = set(SUBST.findall(_epilog()))
        for name in LINKED:
            self.assertIn(name, names)
        self.assertNotIn('pcap', names)

    def test_no_target_is_defined_twice(self) -> 'None':
        """Docutils folds case, so ``_DPKT`` and ``_dpkt`` would be one name."""
        names = [_norm(name) for name, _ in TARGET.findall(_epilog())]
        self.assertEqual(sorted(names), sorted(set(names)))


class LinkedPackageTests(unittest.TestCase):
    """A package in :data:`LINKED` is written ``|pkg|_``."""

    def test_the_scan_reads_the_sources_it_claims_to(self) -> 'None':
        """An empty or misrooted scan would pass the next test vacuously."""
        names = {_rel(path) for path in _sources()}
        for expected in ('docs/source/pcapkit/foundation/engines/3rdparty.rst',
                         'docs/source/index.rst',
                         'pcapkit/corekit/enum.py',
                         'pcapkit/foundation/engines/pypcapfile.py',
                         'pcapkit/toolkit/pyshark.py',
                         'pcapkit/vendor/reg/apptype/apptype.py',
                         'pcapkit/const/reg/apptype/apptype.py'):
            self.assertIn(expected, names)
        self.assertFalse(any(name.startswith('docs/source/changelog/') for name in names))

    def test_rendered_text_blanks_code_and_keeps_doc_comments(self) -> 'None':
        """Only docstrings and ``#:`` comments survive :func:`_rendered`."""
        text = _rendered(ROOT / 'pcapkit' / 'toolkit' / 'pyshark.py')
        self.assertIn('|pyshark|_', text)
        self.assertNotIn('import ', text)
        self.assertNotIn('#:', text)

    def test_no_bare_literal_of_a_linked_package(self) -> 'None':
        """An ``aenum`` or ``pyshark`` literal outside the exempt contexts fails here."""
        literal = re.compile(r'``(%s)``' % '|'.join(LINKED))
        offenders = []
        for path in _sources():
            rel = _rel(path)
            text = _rendered(path)
            spans = [m.span() for m in ENGINE_LIST.finditer(text)]
            spans += [m.span() for m in TABLE_CELL.finditer(text)]
            for pattern in EXEMPT.get(rel, ()):
                found = [m.span() for m in re.finditer(pattern, text)]
                self.assertTrue(found, f'{rel}: stale exemption {pattern!r}')
                spans += found
            for match in literal.finditer(text):
                if not any(start <= match.start() < end for start, end in spans):
                    offenders.append(f'{rel}:{_line(text, match.start())}: {match.group(0)}')
        self.assertEqual(offenders, [], 'write these as |pkg|_, defined in rst_epilog')

    def test_an_engine_name_stays_a_literal(self) -> 'None':
        """The exemptions match engine lists and table cells, not prose."""
        self.assertTrue(ENGINE_LIST.search('The ``pyshark``, ``scapy`` and\n``pypcapfile`` engines'))
        self.assertTrue(ENGINE_LIST.search('the ``dpkt`` toolkit'))
        self.assertIsNone(ENGINE_LIST.search('as ``dpkt`` decodes it'))
        self.assertTrue(TABLE_CELL.search('``pyshark`` [*]_    yes      yes'))
        self.assertIsNone(TABLE_CELL.search('``pyshark`` 0.6 builds its event loop'))


class DefinitionTests(unittest.TestCase):
    """Each ``|name|_`` is defined once."""

    def test_every_substitution_link_is_defined(self) -> 'None':
        """In ``rst_epilog``, or in the file using it for a name that is not a project."""
        epilog = set(SUBST.findall(_epilog()))
        offenders = []
        for path in _sources():
            text = _rendered(path)
            local = set(SUBST.findall(text))
            for match in SUBST_REF.finditer(text):
                if match.group(1) not in epilog | local:
                    offenders.append(f'{_rel(path)}:{_line(text, match.start())}: |{match.group(1)}|_')
        self.assertEqual(offenders, [])

    def test_no_file_defines_an_epilog_name_again(self) -> 'None':
        """A repeated substitution is an error; a repeated target one URL edit from a warning."""
        epilog = _epilog()
        substs = set(SUBST.findall(epilog))
        targets = {_norm(name) for name, _ in TARGET.findall(epilog)}
        offenders = []
        for path in _sources(changelog=True):
            text = path.read_text(encoding='utf-8')
            for match in SUBST.finditer(text):
                if match.group(1) in substs:
                    offenders.append(f'{_rel(path)}:{_line(text, match.start())}: |{match.group(1)}|')
            for match in TARGET.finditer(text):
                if _norm(match.group(1)) in targets:
                    offenders.append(f'{_rel(path)}:{_line(text, match.start())}: _{match.group(1)}')
        self.assertEqual(offenders, [])


if __name__ == '__main__':
    unittest.main()
