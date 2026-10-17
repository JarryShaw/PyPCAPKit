# -*- coding: utf-8 -*-
"""Pins the documentation comment and the type of :attr:`Extractor._vfunc`.

GitHub issue #1839: :file:`docs/source/pcapkit/foundation/extraction.rst` asks
for ``.. autoattribute:: _vfunc``, but the annotation under its ``#:`` comment
had been commented out. Sphinx attaches a ``#:`` comment only to the assignment
or annotation directly below it, so the page rendered a bare name with no type
and no description.

The annotation is the ``VerboseHandler`` alias, whose signature is pinned too:
the frame parameter is the whole ``Packet`` union, and the return is
:class:`object`, because every caller discards it.

Every test reads source text and never imports the package. The one that asks
Sphinx itself skips without it; the others run everywhere.

"""

from __future__ import annotations

import ast
import pathlib
import re
import unittest
from typing import TYPE_CHECKING

from tests.project.test_docs_ambiguous_xrefs_1775_unit import HAS_SPHINX

if TYPE_CHECKING:
    from typing import Iterable, Iterator, Optional, Union

    Binding = Union[ast.Assign, ast.AnnAssign]

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The module that declares the attribute, by name and by path.
MODULE = 'pcapkit.foundation.extraction'
SOURCE = ROOT / 'pcapkit' / 'foundation' / 'extraction.py'

#: The documented attribute, and the description its page should render.
CLASS = 'Extractor'
ATTR = '_vfunc'
TEXT = 'Verbose callback function.'

#: The alias that types the attribute, and the signature it should spell.
ALIAS = 'VerboseHandler'
SIGNATURE = "Callable[['Extractor', Packet], object]"

#: A documentation comment line, as :mod:`sphinx.pycode.parser` matches it.
COMMENT = re.compile(r'^\s*#: ?(.*)$')


def scope_statements(body: 'Iterable[ast.stmt]') -> 'Iterator[ast.stmt]':
    """Yield every statement of a module or class body, including nested blocks.

    An ``if TYPE_CHECKING:`` block declares names of the scope it sits in, so the
    walk goes into compound statements; it stops at a function or class, which
    opens a new scope.

    """
    for stmt in body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield stmt
        for field in ('body', 'orelse', 'finalbody'):
            yield from scope_statements(getattr(stmt, field, []))
        for handler in getattr(stmt, 'handlers', []):
            yield from scope_statements(handler.body)


def bindings(body: 'Iterable[ast.stmt]', name: 'str') -> 'list[Binding]':
    """Return every assignment or annotation of ``name`` in a scope, in order."""
    found = []  # type: list[Binding]
    for stmt in scope_statements(body):
        if isinstance(stmt, ast.AnnAssign):
            targets = [stmt.target]  # type: list[ast.expr]
        elif isinstance(stmt, ast.Assign):
            targets = stmt.targets
        else:
            continue
        if any(isinstance(target, ast.Name) and target.id == name for target in targets):
            found.append(stmt)
    return found


def class_body(tree: 'ast.Module', cls: 'str') -> 'list[ast.stmt]':
    """Return the body of the class ``cls`` defined anywhere in ``tree``."""
    classes = [node for node in ast.walk(tree)
               if isinstance(node, ast.ClassDef) and node.name == cls]
    if not classes:
        raise AssertionError(f'no class {cls!r} in {SOURCE}')
    return classes[0].body


def doc_comment(source: 'str', cls: 'str', attr: 'str') -> 'Optional[list[str]]':
    """Return the ``#:`` lines Sphinx would attach to ``cls.attr``.

    These are the consecutive ``#:`` lines directly above the first assignment
    or annotation of ``attr`` in the body of ``cls``. The result is :obj:`None`
    when the class body neither assigns nor annotates ``attr``.

    """
    found = bindings(class_body(ast.parse(source), cls), attr)
    if not found:
        return None

    lines = []  # type: list[str]
    for line in reversed(source.splitlines()[:found[0].lineno - 1]):
        match = COMMENT.match(line)
        if match is None:
            break
        lines.append(match.group(1))
    return lines[::-1]


class VerboseCallbackDocCommentTests(unittest.TestCase):
    """The ``#:`` comment above :attr:`Extractor._vfunc` attaches to it."""

    source = ''

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.source = SOURCE.read_text(encoding='utf-8')

    def test_comment_sits_directly_above_the_annotation(self) -> 'None':
        comment = doc_comment(self.source, CLASS, ATTR)
        self.assertIsNotNone(comment, f'{CLASS} neither annotates nor assigns {ATTR}')
        self.assertIn(TEXT, ' '.join(comment or []))

    @unittest.skipUnless(HAS_SPHINX, 'Sphinx and sphinx-autodoc-typehints are not installed')
    def test_sphinx_attaches_the_comment(self) -> 'None':
        from sphinx.pycode import ModuleAnalyzer  # pylint: disable=import-outside-toplevel

        docs = ModuleAnalyzer.for_string(self.source, MODULE).find_attr_docs()
        lines = docs.get((CLASS, ATTR))
        self.assertIsNotNone(lines, f'Sphinx attaches no comment to {CLASS}.{ATTR}')
        found = '\n'.join(lines or []).strip()
        self.assertIn(TEXT, found)
        # The first test reads the comment the same way, so it is measuring this.
        self.assertEqual('\n'.join(doc_comment(self.source, CLASS, ATTR) or []).strip(), found)


class VerboseHandlerSignatureTests(unittest.TestCase):
    """:attr:`Extractor._vfunc` is typed by the precise ``VerboseHandler`` alias."""

    source = ''
    tree = ast.parse('')

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.source = SOURCE.read_text(encoding='utf-8')
        cls.tree = ast.parse(cls.source)

    def test_attribute_is_annotated_with_the_alias(self) -> 'None':
        annotations = [ast.literal_eval(stmt.annotation)
                       for stmt in bindings(class_body(self.tree, CLASS), ATTR)
                       if isinstance(stmt, ast.AnnAssign)]
        self.assertEqual(annotations, [ALIAS])

    def test_alias_spells_the_precise_signature(self) -> 'None':
        found = bindings(self.tree.body, ALIAS)
        self.assertEqual(len(found), 1, f'{ALIAS} is not bound exactly once in {SOURCE}')
        value = found[0].value
        if value is None:
            self.fail(f'{ALIAS} is annotated but never assigned')
        # Compared as trees, so spacing and quoting do not matter.
        expected = ast.parse(SIGNATURE, mode='eval').body
        self.assertEqual(ast.dump(value), ast.dump(expected),
                         f'{ALIAS} = {ast.get_source_segment(self.source, value)}')


if __name__ == '__main__':
    unittest.main()
