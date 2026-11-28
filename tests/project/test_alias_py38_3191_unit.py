# -*- coding: utf-8 -*-
"""#3191: type aliases under ``TYPE_CHECKING`` stay 3.8-safe for vermin.

``vermin.ini`` targets 3.8 and evaluates annotations, so an alias assigned under
``if TYPE_CHECKING:`` that subscripts a builtin (``dict[...]``) or a name from
:mod:`collections.abc` unquoted reads as a 3.9 minimum. Such an alias spells the
generic as a string, or with a :mod:`typing` alias.

"""

from __future__ import annotations

import ast
import pathlib
import unittest

#: Test tier (#1958): reads the source tree.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2] / 'pcapkit'
BUILTIN_GENERICS = frozenset({'dict', 'frozenset', 'list', 'set', 'tuple', 'type'})


def _is_type_checking(node: 'ast.stmt') -> bool:
    return (isinstance(node, ast.If) and isinstance(node.test, ast.Name)
            and node.test.id == 'TYPE_CHECKING')


def _dotted(node: 'ast.expr') -> 'str':
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return '.'.join(reversed(parts))


def _unquoted_generics(source: 'str', name: 'str' = '<source>') -> 'list[str]':
    tree = ast.parse(source)
    abc_names = {alias.asname or alias.name
                 for node in ast.walk(tree)
                 if isinstance(node, ast.ImportFrom) and node.module == 'collections.abc'
                 for alias in node.names}
    banned = BUILTIN_GENERICS | abc_names
    found = []
    for block in filter(_is_type_checking, tree.body):
        for stmt in block.body:
            if not isinstance(stmt, (ast.Assign, ast.AnnAssign)) or stmt.value is None:
                continue
            for node in ast.walk(stmt.value):
                if not isinstance(node, ast.Subscript):
                    continue
                base = _dotted(node.value)
                if base in banned or base.startswith('collections.abc.'):
                    found.append('%s:%s %s[...]' % (name, node.lineno, base))
    return found


#: Snippets vermin reads as 3.9 (checked with ``--eval-annotations``), each with
#: the name the sweep must report.
FLAGGED = {
    'assign': ('from typing import TYPE_CHECKING\n'
               'if TYPE_CHECKING:\n    X = Callable[[dict[str, int]], None]\n', 'dict'),
    'annotated': ('from typing import TYPE_CHECKING\n'
                  'if TYPE_CHECKING:\n'
                  "    X: 'TypeAlias' = Callable[[dict[str, int]], None]\n", 'dict'),
    'import-in-block': ('from typing import TYPE_CHECKING\n'
                        'if TYPE_CHECKING:\n    from collections.abc import Mapping\n'
                        '    X = Union[int, Mapping[str, int]]\n', 'Mapping'),
    'attribute': ('import collections.abc\nfrom typing import TYPE_CHECKING\n'
                  'if TYPE_CHECKING:\n    X = Union[int, collections.abc.Mapping[str, int]]\n',
                  'collections.abc.Mapping'),
}
#: The quoted spellings, which vermin passes and the sweep must too.
CLEAN = (
    'from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n'
    "    X = Callable[[Optional['dict[str, int]']], None]\n",
    'from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n'
    "    X: 'TypeAlias' = Union[int, 'Mapping[str, int]']\n",
)


class TestTypeCheckingAliases(unittest.TestCase):
    """#3191: no unquoted 3.9 generic in a ``TYPE_CHECKING`` alias."""

    def test_no_unquoted_generic(self) -> 'None':
        found = [hit for path in sorted(ROOT.rglob('*.py'))
                 for hit in _unquoted_generics(path.read_text(encoding='utf-8'),
                                               str(path.relative_to(ROOT.parent)))]
        self.assertEqual(found, [])

    def test_sweep_catches_each_form(self) -> 'None':
        for label, (source, base) in FLAGGED.items():
            with self.subTest(label):
                found = _unquoted_generics(source)
                self.assertEqual(len(found), 1, found)
                self.assertIn('%s[...]' % base, found[0])

    def test_sweep_passes_quoted(self) -> 'None':
        for source in CLEAN:
            with self.subTest(source):
                self.assertEqual(_unquoted_generics(source), [])


if __name__ == '__main__':
    unittest.main()
