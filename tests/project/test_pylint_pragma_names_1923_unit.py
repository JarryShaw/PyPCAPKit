# -*- coding: utf-8 -*-
"""Every ``# pylint:`` pragma in :mod:`pcapkit` names a real message (#1923).

A pragma that misspells its message, as ``import-outside-top-level`` did for
``import-outside-toplevel``, suppresses nothing. pylint reports ``W0012
unknown-option-value`` on it and still reports the message it was meant to
silence, but Lint's pylint step is advisory, so nothing noticed.

:data:`KNOWN_MESSAGES` pins the names the package's pragmas use, and every
pragma name has to be on it, so that check runs on every leg with nothing
installed. Where pylint is importable, each name in the pragmas and on the list
is also looked up in pylint's own message store, with the plugins ``make
pylint`` loads, so the list cannot pin a misspelling. No test extra installs
pylint, so that lookup skips in CI.

Pragmas are read from comment tokens with :mod:`tokenize`, so a docstring that
quotes one is not a pragma. This module is unit-tier: it imports nothing it
scans.

"""
from __future__ import annotations

import importlib.util
import io
import re
import tokenize
import unittest
from typing import TYPE_CHECKING

from tests._tiers import ROOT

if TYPE_CHECKING:
    from pathlib import Path
    from typing import Iterator

#: Package whose pragmas are checked.
PACKAGE = ROOT / 'pcapkit'

#: The Makefile, whose ``PYLINT_FLAGS`` name the plugins ``make pylint`` loads.
MAKEFILE = ROOT / 'Makefile'

#: A ``pylint:`` pragma in a comment, up to the next ``;`` or ``#``, as
#: :data:`pylint.utils.pragma_parser.OPTION_RGX` reads it.
PRAGMA = re.compile(r'\bpylint:\s*([^;#\n]+)')

#: The pragma keywords that take a list of messages, from
#: :data:`pylint.utils.pragma_parser.MESSAGE_KEYWORDS`.
ASSIGNMENT = re.compile(r'^\s*(disable-next|disable-msg|enable-msg|disable|enable)\s*=\s*(.*)$')

#: The message names the package's pragmas may use. Add a name here only once
#: ``pylint --list-msgs`` lists it.
KNOWN_MESSAGES = frozenset({
    'abstract-method',
    'arguments-differ',
    'arguments-renamed',
    'attribute-defined-outside-init',
    'bad-super-call',
    'broad-except',
    'consider-using-f-string',
    'consider-using-with',
    'else-if-used',
    'exec-used',
    'fixme',
    'global-statement',
    'import-error',
    'import-outside-toplevel',
    'inconsistent-return-statements',
    'invalid-index-returned',
    'invalid-name',
    'line-too-long',
    'logging-fstring-interpolation',
    'multiple-statements',
    'no-else-raise',
    'no-member',
    'no-value-for-parameter',
    'non-parent-init-called',
    'not-callable',
    'protected-access',
    'raise-missing-from',
    'redefined-builtin',
    'redefined-outer-name',
    'signature-differs',
    'super-init-not-called',
    'too-many-arguments',
    'unidiomatic-typecheck',
    'unspecified-encoding',
    'unsubscriptable-object',
    'unused-argument',
    'unused-import',
    'unused-wildcard-import',
    'useless-parent-delegation',
    'wildcard-import',
    'wrong-import-position',
})

#: Whether :mod:`pylint` is importable, for the message-store lookup. Its CI
#: coverage is recorded in :data:`tests._dependency_gates.DEPENDENCY_GATE_EXCLUSIONS`.
HAS_PYLINT = importlib.util.find_spec('pylint') is not None


def _names(comment: 'str') -> 'Iterator[str]':
    """The message names the ``pylint:`` pragmas in ``comment`` list."""
    for pragma in PRAGMA.finditer(comment):
        assignment = ASSIGNMENT.match(pragma.group(1))
        if assignment is None:
            continue
        for name in assignment.group(2).split(','):
            name = name.strip()
            if name:
                yield name


def _pragmas(path: 'Path') -> 'Iterator[tuple[int, str]]':
    """The line and message name of each pragma entry in the comments of ``path``."""
    with path.open('rb') as file:
        for token in tokenize.tokenize(file.readline):
            if token.type == tokenize.COMMENT:
                for name in _names(token.string):
                    yield token.start[0], name


def _package_pragmas() -> 'list[tuple[str, int, str]]':
    """Every pragma entry in :data:`PACKAGE`, as the file, line and message name."""
    return [(path.relative_to(ROOT).as_posix(), line, name)
            for path in sorted(PACKAGE.rglob('*.py'))
            for line, name in _pragmas(path)]


def _plugins() -> 'list[str]':
    """The plugins ``PYLINT_FLAGS`` in the Makefile loads."""
    match = re.search(r'^PYLINT_FLAGS = .*?--load-plugins=(\S+)', MAKEFILE.read_text(encoding='utf-8'), re.MULTILINE)
    if match is None:
        raise AssertionError(f'{MAKEFILE} names no --load-plugins= in PYLINT_FLAGS')
    return match.group(1).split(',')


class PragmaParserTests(unittest.TestCase):
    """The scan reads pragma names the way pylint does."""

    def test_reads_every_name_of_a_pragma(self) -> None:
        comment = '# type: ignore[unreachable] # pylint: disable=import-outside-top-level,no-member # isort:skip'
        self.assertEqual(list(_names(comment)), ['import-outside-top-level', 'no-member'])

    def test_reads_disable_next(self) -> None:
        self.assertEqual(list(_names('# pylint: disable-next=unused-import')), ['unused-import'])

    def test_ignores_prose_about_pragmas(self) -> None:
        self.assertEqual(list(_names('# ``# pylint: disable`` is *line*-scoped')), [])

    def test_ignores_pragmas_in_strings(self) -> None:
        source = b'x = "# pylint: disable=not-a-message"  # pylint: disable=invalid-name\n'
        tokens = tokenize.tokenize(io.BytesIO(source).readline)
        comments = [token.string for token in tokens if token.type == tokenize.COMMENT]
        self.assertEqual([name for comment in comments for name in _names(comment)], ['invalid-name'])

    def test_package_has_pragmas(self) -> None:
        self.assertTrue(_package_pragmas(), f'no pylint pragma found under {PACKAGE}; the scan is broken')


class PragmaNameTests(unittest.TestCase):
    """Every pragma in :data:`PACKAGE` names a real pylint message."""

    def test_pragma_names_are_known(self) -> None:
        unknown = [f'{path}:{line}: {name}' for path, line, name in _package_pragmas()
                   if name not in KNOWN_MESSAGES]
        self.assertEqual(unknown, [], 'pylint pragma names not in KNOWN_MESSAGES; check the spelling '
                                      'against `pylint --list-msgs` before adding one')

    @unittest.skipUnless(HAS_PYLINT, 'pylint is not installed, so its message store cannot be read')
    def test_names_are_pylint_messages(self) -> None:
        from pylint.exceptions import UnknownMessageError  # pylint: disable=import-outside-toplevel
        from pylint.lint import PyLinter  # pylint: disable=import-outside-toplevel

        linter = PyLinter()
        linter.load_default_plugins()
        linter.load_plugin_modules(_plugins())
        entries = [(f'{path}:{line}', name) for path, line, name in _package_pragmas()]
        entries.extend(('KNOWN_MESSAGES', name) for name in sorted(KNOWN_MESSAGES))
        unknown = []
        for where, name in entries:
            try:
                linter.msgs_store.get_message_definitions(name)
            except UnknownMessageError:  # also raised for a deleted or unloaded message
                unknown.append(f'{where}: {name}')
        self.assertEqual(unknown, [], 'names pylint does not know')


if __name__ == '__main__':
    unittest.main()
