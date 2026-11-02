# -*- coding: utf-8 -*-
"""Rendered text cites this repository's issues and pull requests by role (#1103).

Sphinx renders ``.rst`` pages, docstrings and ``#:`` attribute doc-comments, and
there an issue is cited as ``:issue:`NNN``` and a pull request as ``:pr:`NNN```.
The roles render the same ``#NNN`` caption a hand-written link would, from one
template in :file:`docs/source/conf.py`, and they say which of the two the number
is. A bare ``#NNN`` in rendered text is not a link at all. Plain ``#`` comments,
tests and other unrendered files keep ``#NNN``, which
:mod:`tests.project.test_issue_refs_in_comments` pins from the other side.

* :class:`ScannerTests` -- the scanners skip literals, code blocks, comments,
  link targets and URL fragments, and flag the rest.
* :class:`KindTests` -- a role up to :data:`NEWEST` is flagged when :data:`KINDS`
  records its number as the other kind or as neither; one above it is skipped.
* :class:`RefreshScriptTests` -- :file:`util/issue_pr_kinds.py` writes
  :data:`KINDS_FILE` in the form it is committed in, from ``gh api --paginate``.
* :class:`RenderedTextTests` -- no ``.rst`` page under :file:`docs/source`, no
  :file:`pcapkit/` docstring and no ``#:`` doc-comment holds a hand-written link
  to an issue or pull request of this repository, or a bare ``#NNN``, and every
  role there names what its number is.

Links to other repositories, to Discussions and to a comment on an issue keep
their explicit URLs, which a role cannot express; ``GH-NNN`` is a deliberate
issue form and is not matched. Everything is read as text or parsed with
:mod:`ast` and :mod:`tokenize`; :mod:`pcapkit` is not imported, nothing is
built, and the refresh script's ``gh`` call is mocked.

"""

from __future__ import annotations

import ast
import io
import json
import pathlib
import re
import subprocess  # nosec B404
import tempfile
import tokenize
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from util import issue_pr_kinds

if TYPE_CHECKING:
    from typing import Iterator

#: Test tier (#1958): reads the docs sources and the package's docstrings as text.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOCS = ROOT / 'docs' / 'source'
PACKAGE = ROOT / 'pcapkit'

#: A hand-written link, of any caption, to an issue or pull request of this
#: repository. A URL with a fragment or a further path, such as a comment on an
#: issue, is not matched: no role can express it.
HAND_LINK = re.compile(r'`[^`<]*<https://github\.com/JarryShaw/PyPCAPKit/(?:issues|pull)/\d+/?>`_{1,2}')

#: A bare ``#NNN``. The look-behind leaves out URL fragments (``page#12``),
#: character references (``&#12;``) and ``##12``.
BARE_NUMBER = re.compile(r'(?<![\w&#/])#\d+(?![\w-])')

#: An ``:issue:`` or ``:pr:`` role, with or without a caption, and its number.
ROLE = re.compile(r'(?<![\w`]):(issue|pr):`(?:[^`<]*<)?(\d+)>?`')

#: Each issue and pull request number of this repository's tracker, mapped to the
#: role it takes, as ``python util/issue_pr_kinds.py`` last wrote them; re-run it
#: to check a role citing a number above :data:`NEWEST`.
KINDS_FILE = pathlib.Path(__file__).resolve().with_name('issue_pr_roles_fixtures') / 'kinds.json'
KINDS = {number: kind for kind, numbers in json.loads(KINDS_FILE.read_text('utf-8')).items()
         for number in numbers}
#: The highest number :data:`KINDS` records. A lower one it lacks, such as a
#: Discussion's, is neither an issue nor a pull request.
NEWEST = max(KINDS)

#: What each role names, for a failure message.
KIND_NAMES = {'issue': 'an issue', 'pr': 'a pull request'}

#: An inline literal, which renders verbatim.
INLINE_LITERAL = re.compile(r'``.+?``', re.DOTALL)

#: Interpreted text that is already a link or a role: a phrase reference, with
#: or without an embedded target, or a role's argument. Its text is the link's
#: own caption, such as a section title that names an issue, so a ``#NNN`` in it
#: is not a bare number. One to an issue or pull request of this repository is
#: caught as a :data:`HAND_LINK` before this is removed.
INTERPRETED = re.compile(r'(?<![\w`]):[\w:+.-]+:`[^`]*`|(?<![\w:`])`[^`]+`_{1,2}')

#: Directives whose body renders verbatim, or is not text at all.
LITERAL_DIRECTIVES = frozenset({
    'code', 'code-block', 'sourcecode', 'literalinclude', 'highlight', 'doctest',
    'testcode', 'testoutput', 'mermaid', 'math', 'raw', 'graphviz',
})

#: An explicit markup start: a directive, a target, a substitution or a footnote.
DIRECTIVE = re.compile(r'\.\.\s+([\w:-]+)::')

#: Explicit markup that is not a comment: a hyperlink target, a substitution
#: definition or a footnote.
NOT_COMMENT = ('.. _', '.. |', '.. [')

#: Rendered text that is allowed to hold a match, as the path and the matched
#: text. Each is checked to still match, so the list cannot go stale.
ALLOWED = frozenset({
    # Each entry below is pinned in this form by a test that reads the workflows
    # page, so converting it means changing that pin in the same commit. The
    # tests: test_superseded_runs_1938, test_superseded_junit_upload_2073 and
    # test_superseded_containment_summary_2077 pin the hand-written link itself;
    # test_graalpy_worker_heap_1753, test_project_pins_once_1954,
    # test_curated_all_tier_1958 with test_graalpy_shards_1963, and
    # test_pypy_worker_memory_2005 pin the ``#NNN`` its caption renders; and
    # test_memory_error_count_1962 pins the bare ``(#1962)``.
    ('docs/source/contributing/workflows.rst',
     '`#1753 <https://github.com/JarryShaw/PyPCAPKit/issues/1753>`__'),
    ('docs/source/contributing/workflows.rst',
     '`#1938 <https://github.com/JarryShaw/PyPCAPKit/issues/1938>`__'),
    ('docs/source/contributing/workflows.rst',
     '`#1954 <https://github.com/JarryShaw/PyPCAPKit/issues/1954>`__'),
    ('docs/source/contributing/workflows.rst', '#1962'),
    ('docs/source/contributing/workflows.rst',
     '`#1963 <https://github.com/JarryShaw/PyPCAPKit/issues/1963>`__'),
    ('docs/source/contributing/workflows.rst',
     '`#2005 <https://github.com/JarryShaw/PyPCAPKit/issues/2005>`__'),
    ('docs/source/contributing/workflows.rst',
     '`#2073 <https://github.com/JarryShaw/PyPCAPKit/issues/2073>`__'),
    ('docs/source/contributing/workflows.rst',
     '`#2077 <https://github.com/JarryShaw/PyPCAPKit/issues/2077>`__'),
})


def _indent(line: 'str') -> 'int':
    return len(line) - len(line.lstrip())


def rendered_lines(text: 'str') -> 'list[str]':
    """``text`` with comments and literal or code blocks blanked, line for line.

    reST comments do not render, and a literal block or a code directive renders
    verbatim, so neither can hold a role. A blanked line stays in place as an
    empty string, which keeps the line numbers of what is left.

    """
    lines = text.splitlines()
    out = []
    skip_deeper_than: 'int | None' = None
    literal_next, doctest, base = False, False, 0
    for line in lines:
        stripped = line.strip()
        if doctest:
            # A doctest block runs until the next blank line.
            doctest = bool(stripped)
            out.append('')
            continue
        if skip_deeper_than is not None:
            if not stripped or _indent(line) > skip_deeper_than:
                out.append('')
                continue
            skip_deeper_than = None
        if literal_next and stripped:
            literal_next = False
            # The literal block is whatever follows, indented deeper than the
            # paragraph that introduced it.
            if _indent(line) > base:
                skip_deeper_than = base
                out.append('')
                continue
        if stripped.startswith('>>>'):
            doctest = True
            out.append('')
            continue
        directive = DIRECTIVE.match(stripped)
        if directive is not None:
            if directive.group(1) in LITERAL_DIRECTIVES:
                skip_deeper_than = _indent(line)
                out.append('')
                continue
            out.append(line)
            continue
        if (stripped == '..' or stripped.startswith('.. ')) and not stripped.startswith(NOT_COMMENT):
            # A comment: ``..`` followed by anything that is not explicit markup.
            skip_deeper_than = _indent(line)
            out.append('')
            continue
        if stripped.endswith('::'):
            literal_next = True
            base = _indent(line)
            # ``Text::`` renders ``Text:``, so the paragraph itself still counts.
        out.append(line)
    return out


def _blank(match: 're.Match[str]') -> 'str':
    """The newlines of ``match``, so that removing it keeps the line numbers."""
    return '\n' * match.group().count('\n')


def scan_text(text: 'str', first_line: 'int' = 1) -> 'Iterator[tuple[int, str]]':
    """The line and text of each hand-written link and bare ``#NNN`` in ``text``.

    Inline literals render verbatim, so they are removed first; then the
    hand-written links are reported, and every link and role is removed, so
    that a caption is not read as a bare number.

    """
    body = INLINE_LITERAL.sub(_blank, '\n'.join(rendered_lines(text)))
    for match in HAND_LINK.finditer(body):
        yield first_line + body.count('\n', 0, match.start()), ' '.join(match.group().split())
    rest = INTERPRETED.sub(_blank, body)
    for match in BARE_NUMBER.finditer(rest):
        yield first_line + rest.count('\n', 0, match.start()), match.group()


def docstrings(source: 'str') -> 'Iterator[tuple[int, str]]':
    """The first line and text of each docstring, attribute docstrings included."""
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = node.body
        for index, child in enumerate(body):
            if not (isinstance(child, ast.Expr) and isinstance(child.value, ast.Constant)
                    and isinstance(child.value.value, str)):
                continue
            # A docstring, or an attribute docstring right after an assignment.
            if index == 0 or isinstance(body[index - 1], (ast.Assign, ast.AnnAssign)):
                yield child.lineno, child.value.value


def doc_comments(source: 'str') -> 'Iterator[tuple[int, str]]':
    """The first line and joined text of each run of consecutive ``#:`` comments."""
    start, block, last = 0, [], -1
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type != tokenize.COMMENT or not token.string.startswith('#:'):
            continue
        line = token.start[0]
        if block and line != last + 1:
            yield start, '\n'.join(block)
            block = []
        if not block:
            start = line
        block.append(token.string[2:])
        last = line
    if block:
        yield start, '\n'.join(block)


def scan_python(source: 'str') -> 'Iterator[tuple[int, str]]':
    """Every match in the docstrings and ``#:`` doc-comments of ``source``."""
    for line, text in docstrings(source):
        yield from scan_text(text, line)
    for line, text in doc_comments(source):
        yield from scan_text(text, line)


def scan_roles(text: 'str', first_line: 'int' = 1) -> 'Iterator[tuple[int, str, int]]':
    """The line, role and number of each ``:issue:`` and ``:pr:`` role in ``text``."""
    body = INLINE_LITERAL.sub(_blank, '\n'.join(rendered_lines(text)))
    for match in ROLE.finditer(body):
        yield first_line + body.count('\n', 0, match.start()), match.group(1), int(match.group(2))


def rendered_texts() -> 'Iterator[tuple[str, int, str]]':
    """The path, first line and text of each ``.rst`` page, docstring and ``#:`` doc-comment."""
    for path in sorted(DOCS.rglob('*.rst')):
        yield path.relative_to(ROOT).as_posix(), 1, path.read_text('utf-8')
    for path in sorted(PACKAGE.rglob('*.py')):
        name, source = path.relative_to(ROOT).as_posix(), path.read_text('utf-8')
        for line, text in docstrings(source):
            yield name, line, text
        for line, text in doc_comments(source):
            yield name, line, text


def repository_matches() -> 'list[tuple[str, int, str]]':
    """Every match in the rendered text of the repository."""
    return [(name, line, text) for name, first, body in rendered_texts()
            for line, text in scan_text(body, first)]


def repository_roles() -> 'list[tuple[str, int, str, int]]':
    """Every ``:issue:`` and ``:pr:`` role in the rendered text of the repository."""
    return [(name, line, role, number) for name, first, body in rendered_texts()
            for line, role, number in scan_roles(body, first)]


def wrong_kinds(roles: 'list[tuple[str, int, str, int]]',
                kinds: 'dict[int, str]') -> 'list[str]':
    """Each role up to the highest number in ``kinds`` that it records as another kind or lacks.

    A number above that highest is newer than ``kinds`` and is skipped.

    """
    newest = max(kinds)
    return [f'{path}:{line}: :{role}:`{number}` '
            + (f'names {KIND_NAMES[kinds[number]]}' if number in kinds
               else 'is neither an issue nor a pull request')
            for path, line, role, number in roles if number <= newest and kinds.get(number) != role]


class ScannerTests(unittest.TestCase):
    """The scanners flag rendered text only."""

    def matches(self, text: 'str') -> 'list[str]':
        return [match for _, match in scan_text(text)]

    def test_flags_a_hand_written_link(self) -> None:
        text = 'See `#12\n<https://github.com/JarryShaw/PyPCAPKit/issues/12>`__ and\n' \
               '`the fix <https://github.com/JarryShaw/PyPCAPKit/pull/34>`_.\n'
        self.assertEqual([line for line, _ in scan_text(text)], [1, 3])

    def test_flags_a_bare_number(self) -> None:
        self.assertEqual(self.matches('Fixed in #12 (#34).\n'), ['#12', '#34'])

    def test_keeps_roles_and_other_links(self) -> None:
        text = (':issue:`12`, :pr:`34`, GH-56, :discussion:`78`,\n'
                '`a comment <https://github.com/JarryShaw/PyPCAPKit/issues/12#issuecomment-9>`__,\n'
                '`upstream #90 <https://github.com/pallets/werkzeug/issues/90>`__ and &#91;,\n'
                'see `Workflow Scripts (#92)`_.\n')
        self.assertEqual(self.matches(text), [])

    def test_skips_literals_and_code(self) -> None:
        text = ('A ``#12`` literal::\n\n    # see #34\n\nback.\n\n'
                '.. code-block:: yaml\n\n   # #56\n\n.. a comment on #78\n   still #90\n\nEnd.\n')
        self.assertEqual(self.matches(text), [])

    def test_skips_doctest_blocks_only(self) -> None:
        text = 'Example:\n\n>>> f()  # #12\n#34\n\nFixed in #56.\n'
        self.assertEqual(self.matches(text), ['#56'])

    def test_keeps_admonition_bodies(self) -> None:
        self.assertEqual(self.matches('.. note::\n\n   Fixed in #12.\n'), ['#12'])

    def test_reads_docstrings_and_doc_comments(self) -> None:
        source = ('"""Module, #1."""\n#: Doc-comment,\n#: #2.\nX = 1\n"""Attribute, #3."""\n'
                  'def f():\n    """Function, #4."""\n    # plain #5\n    return "#6"\n')
        self.assertEqual([match for _, match in scan_python(source)], ['#1', '#3', '#4', '#2'])

    def test_allowed_entries_still_match(self) -> None:
        found = {(path, text) for path, _, text in repository_matches()}
        self.assertEqual(sorted(ALLOWED - found), [], 'stale ALLOWED entries')

    def test_reads_roles_outside_literals(self) -> None:
        text = (':issue:`12`, :pr:`34`, :issue:`a caption <56>`, :discussion:`78`,\n'
                '``:issue:`90``` and::\n\n    :pr:`91`\n\nend :pr:`92`.\n')
        self.assertEqual(list(scan_roles(text)),
                         [(1, 'issue', 12), (1, 'pr', 34), (1, 'issue', 56), (6, 'pr', 92)])


class KindTests(unittest.TestCase):
    """A role is checked against the kind its number is recorded as."""

    def test_flags_the_other_kind_and_a_gap_and_skips_a_newer_number(self) -> None:
        roles = [('a.rst', 1, 'issue', 2), ('a.rst', 2, 'pr', 3), ('a.rst', 3, 'issue', 4),
                 ('a.rst', 4, 'pr', 5), ('a.rst', 5, 'issue', 7), ('a.rst', 6, 'pr', 8)]
        self.assertEqual(wrong_kinds(roles, {2: 'pr', 3: 'issue', 4: 'issue', 6: 'pr'}),
                         ['a.rst:1: :issue:`2` names a pull request',
                          'a.rst:2: :pr:`3` names an issue',
                          'a.rst:4: :pr:`5` is neither an issue nor a pull request'])

    def test_kinds_file_records_each_number_once(self) -> None:
        data = json.loads(KINDS_FILE.read_text('utf-8'))
        self.assertEqual(sorted(data), sorted(KIND_NAMES))
        for kind, numbers in data.items():
            with self.subTest(kind=kind):
                self.assertEqual(numbers, sorted(set(numbers)))
        self.assertEqual(set(data['issue']) & set(data['pr']), set())


class RefreshScriptTests(unittest.TestCase):
    """:file:`util/issue_pr_kinds.py` writes :data:`KINDS_FILE` from the tracker."""

    def test_render_writes_the_committed_form(self) -> None:
        self.assertEqual(issue_pr_kinds.render(KINDS), KINDS_FILE.read_text('utf-8'))
        self.assertEqual(issue_pr_kinds.OUTPUT, KINDS_FILE)

    def test_fetch_reads_every_page(self) -> None:
        done = subprocess.CompletedProcess([], 0, stdout='2\tissue\n3\tpr\n', stderr='')
        with mock.patch.object(issue_pr_kinds.subprocess, 'run', return_value=done) as run:
            self.assertEqual(issue_pr_kinds.fetch('o/r'), {2: 'issue', 3: 'pr'})
        command = run.call_args.args[0]
        self.assertEqual(command[:3], ['gh', 'api', '--paginate'])
        self.assertIn('repos/o/r/issues?state=all&per_page=100', command)

    def test_fetch_fails_on_an_error_or_an_empty_tracker(self) -> None:
        for done in (subprocess.CompletedProcess([], 1, stdout='', stderr='HTTP 401'),
                     subprocess.CompletedProcess([], 0, stdout='', stderr='')):
            with self.subTest(returncode=done.returncode), \
                    mock.patch.object(issue_pr_kinds.subprocess, 'run', return_value=done), \
                    self.assertRaises(RuntimeError):
                issue_pr_kinds.fetch('o/r')

    def test_main_writes_the_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = pathlib.Path(tmp, 'kinds.json')
            with mock.patch.object(issue_pr_kinds, 'fetch', return_value={3: 'pr', 2: 'issue'}), \
                    mock.patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(issue_pr_kinds.main(['--output', str(output)]), 0)
            self.assertEqual(json.loads(output.read_text('utf-8')), {'issue': [2], 'pr': [3]})


class RenderedTextTests(unittest.TestCase):
    """No rendered text cites an issue or pull request without a role of its kind."""

    def test_rendered_text_uses_roles(self) -> None:
        offending = [f'{path}:{line}: {text}' for path, line, text in repository_matches()
                     if (path, text) not in ALLOWED]
        self.assertEqual(offending, [], 'cite issues as :issue:`NNN` and pull requests as '
                                        ':pr:`NNN` in .rst pages, docstrings and #: doc-comments')

    def test_roles_name_what_the_number_is(self) -> None:
        self.assertEqual(wrong_kinds(repository_roles(), KINDS), [],
                         f'use the role of what the number is, recording an unlisted one in '
                         f'{KINDS_FILE.relative_to(ROOT).as_posix()}')


if __name__ == '__main__':
    unittest.main()
