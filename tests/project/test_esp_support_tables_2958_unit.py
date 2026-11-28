# -*- coding: utf-8 -*-
"""GitHub issue #2958: ESP's support tables name exactly the suites ESP applies.

The module docstring of :mod:`pcapkit.protocols.internet.esp.protocol` and its API
page each claim that the rows of their support tables marked ``yes`` are exactly the
keys of ``CIPHER_SUITES`` and ``INTEGRITY_SUITES``. This pins both claims against the
tables in the source, read with :mod:`ast` rather than imported, so a suite added or
dropped without its row, or a row without its suite, goes red.

"""
from __future__ import annotations

import ast
import pathlib
import re
import unittest

#: Repository root.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The module defining the suites.
MODULE = ROOT / 'pcapkit' / 'protocols' / 'internet' / 'esp' / 'protocol.py'

#: The module's API page.
PAGE = ROOT / 'docs' / 'source' / 'pcapkit' / 'protocols' / 'internet' / 'esp.rst'


def is_border(line: str) -> bool:
    """Whether ``line`` is a reStructuredText simple table border."""
    return bool(line.strip()) and set(line.strip()) <= {'=', ' '}


def cells(row: str, spans: 'list[tuple[int, int]]') -> 'list[str]':
    """Split a simple table ``row`` at its border's column ``spans``; the last runs on."""
    return [row[start:end if column < len(spans) - 1 else None].strip()
            for column, (start, end) in enumerate(spans)]


def supported_rows(text: str) -> 'set[str]':
    """The transforms the support tables in ``text`` mark ``yes``.

    A support table is a simple table with a column headed ``Implemented``; a row's
    transform is its first column's literal.

    """
    rows = set()  # type: set[str]
    lines = text.splitlines()
    index = 0
    while index < len(lines) - 2:
        if not is_border(lines[index]):
            index += 1
            continue
        spans = [match.span() for match in re.finditer('=+', lines[index])]
        header = cells(lines[index + 1], spans)
        end = index + 3
        while end < len(lines) and not is_border(lines[end]):
            end += 1
        if 'Implemented' in header:
            column = header.index('Implemented')
            for row in lines[index + 3:end]:
                values = cells(row, spans)
                if values[column] == 'yes' and values[0].startswith('``'):
                    rows.add(values[0].strip('`'))
        index = end + 1
    return rows


def suite_keys(tree: 'ast.Module', name: str) -> 'set[str]':
    """The member names keying the dict literal assigned to ``name``."""
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == name
                                                for target in node.targets):
            if not isinstance(node.value, ast.Dict):
                break
            return {key.attr for key in node.value.keys if isinstance(key, ast.Attribute)}
    raise AssertionError(f'{name} is no dict literal in {MODULE.relative_to(ROOT)}')


class SupportTableTests(unittest.TestCase):
    """The ``yes`` rows of both support tables, in both places, are the suites."""

    def test_rows_are_the_suites(self) -> None:
        tree = ast.parse(MODULE.read_text(encoding='utf-8'))
        suites = suite_keys(tree, 'CIPHER_SUITES') | suite_keys(tree, 'INTEGRITY_SUITES')
        self.assertIn('ENCR_AES_CTR', suites)
        self.assertIn('AUTH_AES_CMAC_96', suites)
        for where, text in (('module docstring', ast.get_docstring(tree, clean=False) or ''),
                            ('API page', PAGE.read_text(encoding='utf-8'))):
            with self.subTest(where=where):
                self.assertEqual(supported_rows(text), suites)

    def test_the_scan_is_not_blind(self) -> None:
        """A table with no ``Implemented`` column, as the parameter tables are, adds nothing."""
        text = '\n'.join(('=========== =====', 'Encryption  Other', '=========== =====',
                          '``ENCR_X``  yes', '=========== =====', '',
                          '=========== =========== =====', 'Encryption  Implemented Notes',
                          '=========== =========== =====', '``ENCR_Y``  yes         a note',
                          '``ENCR_Z``  **no**      a note that runs past the border',
                          '=========== =========== ====='))
        self.assertEqual(supported_rows(text), {'ENCR_Y'})


if __name__ == '__main__':
    unittest.main()
