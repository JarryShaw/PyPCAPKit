# -*- coding: utf-8 -*-
"""Pins the documentation comment on :attr:`Extractor._vfunc`.

GitHub issue #1839: :file:`docs/source/pcapkit/foundation/extraction.rst` asks
for ``.. autoattribute:: _vfunc``, but the annotation under its ``#:`` comment
had been commented out. Sphinx attaches a ``#:`` comment only to the assignment
or annotation directly below it, so the page rendered a bare name with no type
and no description.

The first test reads the comment the way :mod:`sphinx.pycode.parser` does and
runs everywhere; it reads source text and never imports the package. The second
asks Sphinx itself, and skips without it.

"""

from __future__ import annotations

import ast
import pathlib
import re
import unittest
from typing import TYPE_CHECKING

from tests.project.test_docs_ambiguous_xrefs_1775_unit import HAS_SPHINX

if TYPE_CHECKING:
    from typing import Iterable, Iterator, Optional

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The module that declares the attribute, by name and by path.
MODULE = 'pcapkit.foundation.extraction'
SOURCE = ROOT / 'pcapkit' / 'foundation' / 'extraction.py'

#: The documented attribute, and the description its page should render.
CLASS = 'Extractor'
ATTR = '_vfunc'
TEXT = 'Verbose callback function.'

#: A documentation comment line, as :mod:`sphinx.pycode.parser` matches it.
COMMENT = re.compile(r'^\s*#: ?(.*)$')


def class_statements(body: 'Iterable[ast.stmt]') -> 'Iterator[ast.stmt]':
    """Yield every statement of a class body, including those nested in a block.

    An ``if TYPE_CHECKING:`` block in a class body declares class attributes,
    so the walk goes into compound statements; it stops at a function or class,
    which opens a new scope.

    """
    for stmt in body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield stmt
        for field in ('body', 'orelse', 'finalbody'):
            yield from class_statements(getattr(stmt, field, []))
        for handler in getattr(stmt, 'handlers', []):
            yield from class_statements(handler.body)


def doc_comment(source: 'str', cls: 'str', attr: 'str') -> 'Optional[list[str]]':
    """Return the ``#:`` lines Sphinx would attach to ``cls.attr``.

    These are the consecutive ``#:`` lines directly above the first assignment
    or annotation of ``attr`` in the body of ``cls``. The result is :obj:`None`
    when the class body neither assigns nor annotates ``attr``.

    """
    lines = source.splitlines()
    classes = [node for node in ast.walk(ast.parse(source))
               if isinstance(node, ast.ClassDef) and node.name == cls]
    if not classes:
        raise AssertionError(f'no class {cls!r} in {SOURCE}')

    for stmt in class_statements(classes[0].body):
        if isinstance(stmt, ast.AnnAssign):
            targets = [stmt.target]  # type: list[ast.expr]
        elif isinstance(stmt, ast.Assign):
            targets = stmt.targets
        else:
            continue
        if not any(isinstance(target, ast.Name) and target.id == attr for target in targets):
            continue

        found = []  # type: list[str]
        for line in reversed(lines[:stmt.lineno - 1]):
            match = COMMENT.match(line)
            if match is None:
                break
            found.append(match.group(1))
        return found[::-1]
    return None


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


if __name__ == '__main__':
    unittest.main()
