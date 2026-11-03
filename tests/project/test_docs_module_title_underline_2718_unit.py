# -*- coding: utf-8 -*-
"""Pins that a module docstring's ``=`` title underline runs six past the title (#2718).

The *Heading Case and Shape* section of
:file:`docs/source/contributing/conventions/documentation.rst` rules that where a
module docstring opens on a title underlined with ``=``, the underline is the
title's length plus six. The title is measured as written, stripped of
surrounding whitespace, with any inline markup counted character for character.

* :class:`ModuleHeadingTests` -- every tracked module under :data:`TREES` whose
  docstring opens on such a heading keeps the rule.
* :class:`CrawlerTemplateTests` -- every crawler template under
  :file:`pcapkit/vendor/` that writes a module heading computes its underline
  from the title it writes, so a regenerated :mod:`pcapkit.const` module keeps
  the rule too.

The check is textual and imports nothing it scans.

"""

from __future__ import annotations

import ast
import pathlib
import re
import shutil
import subprocess  # nosec: B404
import unittest
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional

#: Test tier (#1958): reads the repository's sources, and imports nothing.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The trees whose module docstrings are held to the rule.
TREES = ('pcapkit', 'tests', 'util', 'examples', 'docs')

#: How far the underline runs past the title.
OVERHANG = 6

#: The crawlers, whose templates write the :mod:`pcapkit.const` modules.
VENDOR = ROOT / 'pcapkit' / 'vendor'

#: The underline a template must compute, with ``KEY`` standing for its title.
UNDERLINE_FORM = f"'=' * (len(KEY) + {OVERHANG})"

#: The opening quotes of a docstring, alone at the end of a template's literal part.
OPENING = re.compile(r'(?:^|\n)[rRuU]?(?:"""|\'\'\')\Z')

#: A heading a template writes as literal text: an opening, a title and an underline.
LITERAL_HEADING = re.compile(r'(?m)^[rRuU]?(?:"""|\'\'\')([^\n]+)\n(=+)$')


def tracked() -> 'list[str]':
    """Every ``.py`` path git tracks under :data:`TREES`, or skip when this is not a checkout."""
    if shutil.which('git') is None or not (ROOT / '.git').exists():
        raise unittest.SkipTest('not a git checkout')
    result = subprocess.run(['git', 'ls-files', '-z'], cwd=ROOT, capture_output=True, check=True)  # nosec
    return sorted(name for name in result.stdout.decode('utf-8').split('\0')
                  if name.endswith('.py') and name.split('/', 1)[0] in TREES)


def heading(docstring: 'Optional[str]') -> 'Optional[tuple[str, str]]':
    """The title and ``=`` underline ``docstring`` opens on, or :data:`None` if it opens on neither."""
    lines = (docstring or '').split('\n')
    if len(lines) < 2:
        return None
    title, underline = lines[0].strip(), lines[1].strip()
    if not title or not underline or set(underline) != {'='}:
        return None
    return title, underline


def balanced(title: 'str', underline: 'str') -> 'bool':
    """Whether ``underline`` runs exactly :data:`OVERHANG` past ``title``."""
    return len(underline) == len(title) + OVERHANG


def module_headings() -> 'dict[str, tuple[str, str]]':
    """The heading of every tracked module whose docstring opens on one, by path."""
    found = {}  # type: dict[str, tuple[str, str]]
    for name in tracked():
        source = (ROOT / name).read_text(encoding='utf-8')
        pair = heading(ast.get_docstring(ast.parse(source, name), clean=False))
        if pair is not None:
            found[name] = pair
    return found


class _Key(ast.NodeTransformer):
    """Put a template's title in place of ``KEY`` in :data:`UNDERLINE_FORM`."""

    def __init__(self, key: 'ast.expr') -> 'None':
        self.key = key

    def visit_Name(self, node: 'ast.Name') -> 'ast.expr':  # pylint: disable=invalid-name
        return self.key if node.id == 'KEY' else node


def computes_underline(title: 'ast.expr', underline: 'ast.expr') -> 'bool':
    """Whether ``underline`` is ``'=' * (len(<title>) + 6)``.

    A title written as ``(name := ...)`` is measured through ``name``.
    """
    key = ast.Name(id=title.target.id, ctx=ast.Load()) if isinstance(title, ast.NamedExpr) else title
    want = _Key(key).visit(ast.parse(UNDERLINE_FORM, mode='eval').body)
    return ast.dump(underline) == ast.dump(want)


def docstring_nodes(tree: 'ast.Module') -> 'set[int]':
    """The ids of the module, class and function docstring nodes in ``tree``."""
    found = set()  # type: set[int]
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) \
                    and isinstance(first.value.value, str):
                found.add(id(first.value))
    return found


def template_headings(source: 'str') -> 'list[tuple[int, bool]]':
    """Every module heading a crawler template in ``source`` writes, as its line and whether it keeps the rule.

    A template f-string writes one where a literal part ends on the opening
    quotes of a docstring, and the title and underline that follow are each a
    replacement field on a line of their own; the underline keeps the rule when
    it is computed from the title. A heading of any other shape after those
    quotes is refused rather than passed unread. Any other string that is not a
    docstring writes one as literal text, measured as :class:`ModuleHeadingTests`
    measures a module.
    """
    tree = ast.parse(source)
    skip = docstring_nodes(tree)
    found = []  # type: list[tuple[int, bool]]
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            parts = node.values
            for index, part in enumerate(parts):
                if not (isinstance(part, ast.Constant) and isinstance(part.value, str)
                        and OPENING.search(part.value)):
                    continue
                tail = parts[index + 1:index + 4]
                shaped = (len(tail) == 3 and isinstance(tail[0], ast.FormattedValue)
                          and isinstance(tail[1], ast.Constant) and tail[1].value == '\n'
                          and isinstance(tail[2], ast.FormattedValue)
                          and tail[0].conversion == -1 and tail[0].format_spec is None
                          and tail[2].conversion == -1 and tail[2].format_spec is None)
                found.append((node.lineno, shaped and computes_underline(tail[0].value, tail[2].value)))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip:
            for match in LITERAL_HEADING.finditer(node.value):
                found.append((node.lineno, balanced(match.group(1).strip(), match.group(2))))
    return found


class ModuleHeadingTests(unittest.TestCase):
    """Every module docstring's ``=`` underline runs six past its title."""

    headings = module_headings()

    def test_the_sweep_finds_headings(self) -> 'None':
        """The rule has members to hold, so a broken sweep cannot pass vacuously."""
        self.assertTrue(self.headings, 'no module docstring opens on an = heading')

    def test_every_underline_runs_six_past_its_title(self) -> 'None':
        """An underline of any other length names its module and the length it needs."""
        off = sorted(f'{name}: {len(underline)} for a title of {len(title)}, needs {len(title) + OVERHANG}'
                     for name, (title, underline) in self.headings.items()
                     if not balanced(title, underline))
        self.assertEqual(off, [], 'rewrite each underline to the title length plus six')

    def test_markup_is_counted_as_written(self) -> 'None':
        """A title carrying a role or a literal is measured with its markup, not as it renders."""
        self.assertTrue(balanced(':mod:`pcapkit.const.linux` Vendor Crawlers', '=' * 48))
        self.assertFalse(balanced(':mod:`pcapkit.const.linux` Vendor Crawlers', '=' * 41))

    def test_the_heading_reader(self) -> 'None':
        """Only a non-empty title over a run of ``=`` counts as a heading."""
        self.assertEqual(heading('Some Module\n=================\n'), ('Some Module', '=' * 17))
        self.assertIsNone(heading('Some Module\n-----------------\n'))
        self.assertIsNone(heading('A summary line.\n\nA body.\n'))
        self.assertIsNone(heading('One line'))
        self.assertIsNone(heading(None))


class CrawlerTemplateTests(unittest.TestCase):
    """Every crawler template computes its underline from the title it writes."""

    templates = {path.relative_to(ROOT).as_posix(): template_headings(path.read_text(encoding='utf-8'))
                 for path in sorted(VENDOR.rglob('*.py'))}

    def test_the_sweep_finds_templates(self) -> 'None':
        """:file:`pcapkit/vendor/default.py` writes one, so a broken sweep cannot pass vacuously."""
        self.assertEqual([ok for _, ok in self.templates['pcapkit/vendor/default.py']], [True])

    def test_every_template_underline_is_the_title_length_plus_six(self) -> 'None':
        """A hard-coded underline, another offset or an unreadable heading names its template."""
        off = sorted(f'{name}: template at line {line}'
                     for name, found in self.templates.items()
                     for line, ok in found if not ok)
        self.assertEqual(off, [], "write the underline as {'=' * (len(name) + 6)} after the title")

    def test_the_template_reader(self) -> 'None':
        """The reader accepts the computed form and refuses a hard-coded or other-offset one."""
        def read(underline: 'str', title: 'str' = '{(name := DOCS)}') -> 'list[bool]':
            source = f'LINE = lambda DOCS: f\'\'\'\\\n"""{title}\n{underline}\n"""\n\'\'\'\n'
            return [ok for _, ok in template_headings(source)]

        self.assertEqual(read("{'=' * (len(name) + 6)}"), [True])
        self.assertEqual(read("{'=' * (len(DOCS) + 6)}", title='{DOCS}'), [True])
        self.assertEqual(read("{'=' * (len(name) + 4)}"), [False])
        self.assertEqual(read("{'=' * (len(DOCS) + 6)}"), [False])
        self.assertEqual(read('================='), [False])
        self.assertEqual(read('=================', title='Some Module'), [True])
        self.assertEqual(read('===============', title='Some Module'), [False])


if __name__ == '__main__':
    unittest.main()
