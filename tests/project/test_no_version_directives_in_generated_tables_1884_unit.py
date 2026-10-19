# -*- coding: utf-8 -*-
"""Generated tables and their templates carry no version directive (#1884).

The owner ruled on #1872 that the modules under :mod:`pcapkit.const`, and the
template text under :mod:`pcapkit.vendor` that generates them, take no
``versionadded``, ``versionchanged`` or ``versionremoved`` directive, because
the crawlers regenerate them. A change users need to know about is noted on the
hand-written page under :file:`docs/source/pcapkit/const/` instead.

Template text is what a crawler writes into the module it generates: every
string literal in a crawler module that is not a docstring, plus the docstring
of each :class:`~pcapkit.vendor.default.Vendor` subclass, which
``Vendor.__init__`` reads as ``DOCS``. The
crawler framework's own docstrings and ``#:`` comments, and the docstrings of a
crawler's hand-written methods, document that code rather than a generated
table, so they keep their directives.

* :class:`TestGeneratedModules` scans every module under :mod:`pcapkit.const`.
* :class:`TestVendorTemplates` scans the template text of every crawler, and
  checks on a sample module which literals count as template text.
* :class:`TestDocsPages` pins the notes #1884 moved onto the docs pages.

This module is unit-tier and reads no capture.

"""
from __future__ import annotations

import ast
import pathlib
import re
import textwrap
import unittest
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Iterable

#: Repository root.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: A version directive, as Sphinx spells it: reST allows any whitespace after the ``..`` (#1902).
DIRECTIVE = re.compile(r'\.\.\s+version(?:added|changed|removed)::.*')

#: The crawler modules whose templates carried a directive before #1884.
ISSUE_VENDORS = (
    'ftp/command.py',
    'http/method.py',
    'ipv6/extension_header.py',
    'pcapng/option_type.py',
    'pcapng/tls_key_label.py',
    'reg/apptype/apptype.py',
    'tcp/flags.py',
)

#: The notes #1884 moved from a template onto a docs page, as
#: ``(page, directive, text the directive's body must hold)``.
MOVED_NOTES = (
    ('ftp.rst', 'versionchanged:: 1.5.0', ':issue:`860`'),
    ('ftp.rst', 'versionchanged:: 1.5.0', ':issue:`1824`'),
    ('http.rst', 'versionchanged:: 1.5.0', ':issue:`860`'),
    ('http.rst', 'versionchanged:: 1.5.0', ':issue:`908`'),
    ('ipv6.rst', 'versionchanged:: 1.5.0', ':issue:`925`'),
    ('pcapng.rst', 'versionchanged:: 1.1.0.post1', 'option code'),
    ('pcapng.rst', 'versionadded:: 1.5.0', ':issue:`886`'),
    ('reg.rst', 'versionchanged:: 1.1.1', 'port number'),
    ('reg.rst', 'versionchanged:: 1.5.0', ':issue:`732`'),
    ('reg.rst', 'versionchanged:: 1.5.0', ':issue:`808`'),
    ('tcp.rst', 'versionchanged:: 1.5.0', '16-bit'),
)


def _base_name(node: 'ast.expr') -> 'str':
    """The last component of a base class expression, e.g. ``Vendor``."""
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ''


def vendor_classes(trees: 'Iterable[ast.Module]') -> 'frozenset[str]':
    """Names of the classes that subclass ``Vendor``, directly or not.

    Resolved across all of ``trees`` together, since a crawler may subclass one
    defined in another module, as :mod:`pcapkit.vendor.reg.apptype.tcp` does.

    """
    classes = [node for tree in trees for node in tree.body if isinstance(node, ast.ClassDef)]
    names = {'Vendor'}
    while True:
        found = {node.name for node in classes if any(_base_name(base) in names for base in node.bases)}
        if found <= names:
            return frozenset(names)
        names |= found


def _docstring(node: 'ast.AST') -> 'ast.Constant | None':
    """The docstring literal of a module, class or function, if it has one."""
    body = getattr(node, 'body', None)
    if isinstance(body, list) and body and isinstance(body[0], ast.Expr) \
            and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        return body[0].value
    return None


def template_literals(tree: 'ast.Module', crawlers: 'frozenset[str]') -> 'list[ast.Constant]':
    """The string literals of a crawler module a generated module is made from.

    Every string literal, including each literal part of an f-string, except a
    docstring -- but with the docstring of each crawler class put back, as
    ``DOCS`` interpolates it into the generated module.

    """
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            docstring = _docstring(node)
            if docstring is not None:
                docstrings.add(id(docstring))
    literals = [node for node in ast.walk(tree) if isinstance(node, ast.Constant)
                and isinstance(node.value, str) and id(node) not in docstrings]
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and any(_base_name(base) in crawlers for base in node.bases):
            docstring = _docstring(node)
            if docstring is not None:
                literals.append(docstring)
    return literals


def template_directives(tree: 'ast.Module', crawlers: 'frozenset[str]') -> 'list[tuple[int, str]]':
    """Every directive in the template text, as ``(literal's first line, directive)``."""
    return [(node.lineno, match.group().strip())
            for node in template_literals(tree, crawlers)
            for match in DIRECTIVE.finditer(node.value)]


def _vendor_trees() -> 'dict[pathlib.Path, ast.Module]':
    """Every crawler module under :mod:`pcapkit.vendor`, parsed."""
    return {path: ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
            for path in sorted((ROOT / 'pcapkit' / 'vendor').rglob('*.py'))}


class TestGeneratedModules(unittest.TestCase):
    """No module under :mod:`pcapkit.const` carries a version directive."""

    def test_no_const_module_carries_a_directive(self) -> 'None':
        paths = sorted((ROOT / 'pcapkit' / 'const').rglob('*.py'))
        self.assertTrue(paths, 'found no module under pcapkit/const')
        found = []  # type: list[str]
        for path in paths:
            for lineno, line in enumerate(path.read_text(encoding='utf-8').splitlines(), start=1):
                match = DIRECTIVE.search(line)
                if match is not None:
                    found.append(f'{path.relative_to(ROOT)}:{lineno}: {match.group().strip()}')
        self.assertEqual(found, [])


class TestVendorTemplates(unittest.TestCase):
    """No crawler's template text carries a version directive."""

    def test_no_template_carries_a_directive(self) -> 'None':
        trees = _vendor_trees()
        crawlers = vendor_classes(trees.values())
        found = [f'{path.relative_to(ROOT)}:{lineno}: {directive}'
                 for path, tree in trees.items()
                 for lineno, directive in template_directives(tree, crawlers)]
        self.assertEqual(found, [])

    def test_the_issue_templates_are_read(self) -> 'None':
        # Guards the scan above against passing because it read nothing.
        trees = _vendor_trees()
        crawlers = vendor_classes(trees.values())
        for name in ISSUE_VENDORS:
            with self.subTest(vendor=name):
                tree = trees[ROOT / 'pcapkit' / 'vendor' / name]
                text = ''.join(node.value for node in template_literals(tree, crawlers))
                self.assertIn('class ', text)
                self.assertIn('EnumRegistry', text)

    def test_only_template_text_is_scanned(self) -> 'None':
        # A distinct version marks each site, so the result names the ones read.
        sample = textwrap.dedent('''\
            """Crawler framework module.

            .. versionchanged:: 1.0.1
            """
            from pcapkit.vendor.default import Vendor

            #: .. versionchanged:: 1.0.2
            LIMIT = 1

            LINE = lambda NAME: f"class {NAME}:\\n    .. versionadded:: 1.0.3\\n"

            WIDE = "..  versionchanged:: 1.0.10"


            def helper():
                """Hand-written helper.

                .. versionchanged:: 1.0.4
                """


            class Base(Vendor):
                """Crawler, whose docstring is emitted as DOCS.

                .. versionchanged:: 1.0.5
                """

                def method(self):
                    """Hand-written method.

                    .. versionremoved:: 1.0.6
                    """
                    return ".. versionchanged:: 1.0.7"


            class Child(Base):
                """Crawler subclassing a crawler.

                .. versionadded:: 1.0.8
                """


            class Helper:
                """Hand-written class.

                .. versionadded:: 1.0.9
                """
        ''')
        tree = ast.parse(sample)
        crawlers = vendor_classes([tree])
        self.assertEqual(crawlers, frozenset({'Vendor', 'Base', 'Child'}))
        found = sorted(directive for _, directive in template_directives(tree, crawlers))
        self.assertEqual(found, ['..  versionchanged:: 1.0.10', '.. versionadded:: 1.0.3',
                                 '.. versionadded:: 1.0.8', '.. versionchanged:: 1.0.5',
                                 '.. versionchanged:: 1.0.7'])

    def test_a_directive_spaced_wider_is_matched(self) -> 'None':
        # #1902: reST takes any whitespace between ``..`` and the directive name.
        for text in ('..  versionchanged:: 1.5.0', '..\tversionadded:: 1.5.0', '.. versionremoved:: 1.5.0'):
            with self.subTest(text=text):
                self.assertIsNotNone(DIRECTIVE.search(text))
        self.assertIsNone(DIRECTIVE.search('..versionadded:: 1.5.0'))


class TestDocsPages(unittest.TestCase):
    """The notes moved off the templates are on the hand-written docs pages."""

    def test_each_moved_note_is_on_its_page(self) -> 'None':
        for page, directive, text in MOVED_NOTES:
            with self.subTest(page=page, directive=directive, text=text):
                path = ROOT / 'docs' / 'source' / 'pcapkit' / 'const' / page
                blocks = re.findall(rf'(?ms)^\.\. {re.escape(directive)}\n\n(.*?)(?=^\S|\Z)',
                                    path.read_text(encoding='utf-8'))
                self.assertTrue(any(text in block for block in blocks),
                                f'no {directive} block on {page} holds {text!r}')


if __name__ == '__main__':
    unittest.main()
