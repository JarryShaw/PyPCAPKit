# -*- coding: utf-8 -*-
"""Tests for :file:`util/project_status.py` and the workflow that runs it.

:file:`.github/workflows/project-status.yml` sets each item's *Status* on the
project board from its state labels. Three things about it are checkable from the
tree, and each has its own class:

* :class:`TestMapping` -- :func:`status_for` gives the documented status for every
  row of the table, precedence included.
* :class:`TestDocsAgreeWithCode` -- the table under "Milestones and the Project
  Board" in :file:`process.rst` *is* that mapping. The table is parsed rather than
  restated here, so a row reordered or reworded on either side fails.
* :class:`TestWorkflowSafety` -- the workflow runs on ``pull_request_target`` with
  a secret in scope, so it must never check out code, never splice an expression
  into a ``run:`` script, and never read the event payload outside ``env:`` beyond
  the item number. Asserted over the file, because nothing at run time would
  announce the mistake. :class:`TestScannerFailsClosed` holds the line scan those
  assertions read to refusing any YAML it cannot read with certainty.
  :class:`TestConcurrency` evaluates the ``concurrency:``
  expressions per event, so the cancel policy is pinned rather than eyeballed.

:class:`TestBoardSync` drives the script against a fake GraphQL endpoint, which is
as close to the live board as a unit test may get: the tier has no network and no
token, and nothing here may mutate the real project. Whether the queries are
accepted by GitHub's schema is therefore *not* tested -- only that the script
issues the mutations the mapping calls for, and none when the board is already
right.

"""

from __future__ import annotations

import contextlib
import datetime
import importlib.util
import io
import os
import pathlib
import re
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
PROCESS_RST = ROOT / 'docs' / 'source' / 'contributing' / 'conventions' / 'process.rst'
WORKFLOW = ROOT / '.github' / 'workflows' / 'project-status.yml'


def _load_script():
    """Load :file:`util/project_status.py`, which is a script and not a package."""
    path = ROOT / 'util' / 'project_status.py'
    spec = importlib.util.spec_from_file_location('project_status', path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


project_status = _load_script()
status_for = project_status.status_for


class TestMapping(unittest.TestCase):
    """Every row of the table, and the precedence between rows."""

    def test_each_row_on_its_own(self) -> None:
        cases = [
            ((), True, False, 'Done'),
            ((), True, True, 'Done'),
            (('needs: decision',), False, False, 'Needs decision'),
            (('blocked',), False, False, 'Blocked'),
            ((), False, True, 'In review'),
            (('wip',), False, False, 'WIP'),
            (('pending',), False, False, 'Pending'),
            ((), False, False, 'Pending'),
            (('bug', 'design'), False, False, 'Pending'),
        ]
        for labels, closed, pull_request, want in cases:
            with self.subTest(labels=labels, closed=closed, pull_request=pull_request):
                self.assertEqual(status_for(labels, closed=closed, pull_request=pull_request), want)

    def test_precedence(self) -> None:
        cases = [
            (('wip', 'needs: decision'), False, False, 'Needs decision'),
            (('blocked',), True, False, 'Done'),
            (('wip',), False, True, 'In review'),
            (('needs: decision', 'blocked'), False, False, 'Needs decision'),
            (('blocked',), False, True, 'Blocked'),
            (('needs: decision',), False, True, 'Needs decision'),
            (('wip', 'needs: decision', 'blocked'), True, True, 'Done'),
        ]
        for labels, closed, pull_request, want in cases:
            with self.subTest(labels=labels, closed=closed, pull_request=pull_request):
                self.assertEqual(status_for(labels, closed=closed, pull_request=pull_request), want)

    def test_labels_are_matched_exactly(self) -> None:
        # ``needs: review`` and ``wipe`` are not state labels.
        self.assertEqual(status_for(['needs: review', 'wipe'], closed=False, pull_request=False),
                         'Pending')

    def test_every_status_is_reachable(self) -> None:
        reached = {status_for(labels, closed=closed, pull_request=pr)
                   for labels in ((), ('wip',), ('blocked',), ('needs: decision',))
                   for closed in (False, True) for pr in (False, True)}
        self.assertEqual(reached, set(project_status.STATUSES))


def documented_rows() -> 'list[tuple[str, str]]':
    """``(status, when)`` per row of the *Status* table in :file:`process.rst`, in order."""
    text = PROCESS_RST.read_text(encoding='utf-8')
    start = text.index('Status is derived from')
    lines = text[start:].splitlines()
    rules = [i for i, line in enumerate(lines) if re.fullmatch(r'=+\s+=+', line)]
    assert len(rules) >= 3, 'the Status table is no longer a simple rst table'
    header = lines[rules[0] + 1].split()
    assert header[:2] == ['Status', 'When'], header
    rows = []
    for line in lines[rules[1] + 1:rules[2]]:
        match = re.fullmatch(r'\*(?P<status>[^*]+)\*\s{2,}(?P<when>.+)', line.strip())
        assert match is not None, f'unparsed Status table row: {line!r}'
        rows.append((match.group('status'), match.group('when').strip()))
    return rows


def condition(when: 'str') -> 'dict':
    """The input a documented *When* cell describes, as keyword overrides.

    Only the vocabulary the table uses is understood; a cell outside it fails, so
    a reworded row is a test to update rather than a row silently skipped.

    """
    labels = re.findall(r'``([^`]+)``', when)
    if labels:
        assert re.fullmatch(r'it carries ``[^`]+``', when), when
        return {'labels': set(labels)}
    known = {
        'the item is closed or merged': {'closed': True},
        'it is an open pull request': {'pull_request': True},
        'anything else open': {},
    }
    assert when in known, f'unrecognised When cell: {when!r}'
    return known[when]


def evaluate(*conditions: 'dict') -> 'str':
    labels = set()  # type: set[str]
    closed = pull_request = False
    for cond in conditions:
        labels |= cond.get('labels', set())
        closed = closed or cond.get('closed', False)
        pull_request = pull_request or cond.get('pull_request', False)
    return status_for(labels, closed=closed, pull_request=pull_request)


class TestDocsAgreeWithCode(unittest.TestCase):
    """The table in :file:`process.rst` and :func:`status_for` are the same mapping."""

    def setUp(self) -> None:
        self.rows = documented_rows()

    def test_same_statuses(self) -> None:
        self.assertEqual([status for status, _ in self.rows], list(project_status.STATUSES))

    def test_each_row_alone(self) -> None:
        for status, when in self.rows:
            with self.subTest(status=status):
                self.assertEqual(evaluate(condition(when)), status)

    def test_first_match_wins(self) -> None:
        # Row i with every *later* row's condition also true must still give row
        # i: that is what "first match winning" means, and it fails on any swap.
        conds = [condition(when) for _, when in self.rows]
        for i, (status, _) in enumerate(self.rows):
            with self.subTest(status=status):
                self.assertEqual(evaluate(*conds[i:]), status)

    def test_the_docs_say_the_workflow_updates_the_board(self) -> None:
        text = PROCESS_RST.read_text(encoding='utf-8')
        self.assertIn('project-status.yml', text)
        self.assertIn('PROJECT_TOKEN', text)


def strip_comments(text: 'str') -> 'str':
    """``text`` without whole-line ``#`` comments, which may *mention* the forbidden."""
    return '\n'.join(line for line in text.splitlines() if not line.strip().startswith('#'))


#: The one event-payload expression allowed outside an ``env:`` block: the item
#: number, which keys the concurrency group. A number cannot carry a script.
ITEM_NUMBER = 'github.event.issue.number || github.event.pull_request.number'

_KEY_RE = re.compile(r'''(?P<key>[\w-]+|'[^']*'|"[^"\\]*"):(?:[ ]+(?P<rest>.*))?$''')
_BLOCK_INDICATORS = {'|', '|-', '|+', '>', '>-', '>+'}
#: Characters a plain scalar may not start with: anchors, aliases, tags, flow
#: collections, block-scalar headers, comments and directives (YAML 1.2 §5.3).
_NOT_PLAIN = frozenset('&*!{}[],|>#%@`?:')


class UnsupportedYAML(ValueError):
    """A line :func:`scan` cannot read with certainty, so it refuses the file."""


def _scalar(value: 'str', lineno: 'int') -> 'str':
    """``value`` unquoted, or :exc:`UnsupportedYAML` if it is not a one-line scalar.

    Single-quoted, double-quoted without escapes, and plain scalars that YAML would
    read as one string are accepted. Anything else -- an alias, an anchor, a flow
    mapping, an unterminated quote that would continue on the next line, a ``\\``
    escape that could spell ``$`` -- could hide a value from the scan, so it fails.

    """
    value = value.strip()
    if re.fullmatch(r"'(?:[^']|'')*'", value):
        return value[1:-1].replace("''", "'")
    if re.fullmatch(r'"[^"\\]*"', value):
        return value[1:-1]
    if (not value or value[0] in _NOT_PLAIN or value[0] in '\'"'
            or ': ' in value or value.endswith(':') or ' #' in value):
        raise UnsupportedYAML(f'line {lineno}: not a scalar scan() can read: {value!r}')
    return value


def scan(text: 'str') -> 'list[tuple[tuple[str, ...], str]]':
    """Every scalar in a workflow, as ``(key path, value)``; list indices dropped.

    A line scan rather than a YAML parser, because :mod:`yaml` is in no extra of
    :file:`pyproject.toml` and this check has to run everywhere.
    :class:`TestYAMLAgreesWithTheScanner` holds it to :func:`yaml.safe_load`
    wherever PyYAML is installed. It understands the subset these workflows use:
    block mappings, ``- `` sequence items, block scalars (``|``, ``>`` and their
    chomping forms), one-line quoted and plain scalars, ``{}``, and flow sequences
    of such scalars.

    It *fails closed*: any line outside that subset raises :exc:`UnsupportedYAML`
    rather than being read as something it is not. A value the scan misreads is a
    ``run:`` script the safety tests never see -- a flow-mapping step, ``run :``,
    ``run: |2``, or ``run: *alias`` all were (#1060) -- and CI has no PyYAML to
    catch the disagreement, so refusing is the only answer that cannot pass
    vacuously.

    """
    lines = text.splitlines()
    out = []  # type: list[tuple[tuple[str, ...], str]]
    stack = []  # type: list[tuple[int, str]]
    #: Column a line must not be deeper than, when the line before ended in a scalar.
    inline = None  # type: int | None
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        lineno = i
        if not line.strip() or line.strip().startswith('#'):
            continue
        if '\t' in line[:len(line) - len(line.lstrip())]:
            raise UnsupportedYAML(f'line {lineno}: tab in indentation')
        indent = len(line) - len(line.lstrip(' '))
        if inline is not None and indent > inline:
            # Deeper than the line before, which ended in a scalar: YAML folds
            # this line into that scalar -- even a ``- `` line, which the scan
            # would otherwise read as a sequence item of its own.
            raise UnsupportedYAML(f'line {lineno}: continues the scalar on the line above')
        inline = None
        content = line.strip()
        item = False
        while content.startswith('- ') or content == '-':
            content = content[2:].lstrip()
            indent += 2
            item = True
        while stack and stack[-1][0] >= indent:
            stack.pop()
        path = tuple(key for _, key in stack)
        match = _KEY_RE.match(content)
        if match is None:
            # A bare scalar is only a sequence item; on a line of its own it is
            # the continuation of a multi-line scalar, whose key the scan has lost.
            if not item:
                raise UnsupportedYAML(f'line {lineno}: neither a key nor a sequence item: '
                                      f'{content!r}')
            out.append((path, _scalar(content, lineno)))
            inline = indent - 2  # the column of its ``- ``
            continue
        key = match.group('key')
        key = key[1:-1] if key[0] in '\'"' else key
        rest = (match.group('rest') or '').strip()
        if rest[:1] in ('|', '>') and rest not in _BLOCK_INDICATORS:
            # An indentation indicator or a trailing comment: the block that
            # follows would be read as stray scalars, outside this key.
            raise UnsupportedYAML(f'line {lineno}: block scalar header {rest!r}')
        if rest in _BLOCK_INDICATORS:
            block = []
            while i < len(lines) and (not lines[i].strip()
                                      or len(lines[i]) - len(lines[i].lstrip(' ')) > indent):
                block.append(lines[i].strip())
                i += 1
            out.append((path + (key,), '\n'.join(block).strip()))
        elif not rest:
            stack.append((indent, key))
        elif rest.startswith('[') and rest.endswith(']'):
            out.extend((path + (key,), _scalar(entry, lineno))
                       for entry in rest[1:-1].split(',') if entry.strip())
            inline = indent
        elif rest != '{}':
            out.append((path + (key,), _scalar(rest, lineno)))
            inline = indent
        else:
            inline = indent
    return out


def evaluate_expression(value: 'str', context: 'dict') -> 'object':
    """Evaluate a workflow value's ``${{ }}`` parts against ``context``.

    Enough of the expression language for this workflow's ``concurrency:`` --
    context lookups, ``==``, ``&&``, ``||`` and ``format()`` -- with ``&&`` and
    ``||`` returning an operand, as GitHub's do. An unknown context is ``null``.

    """
    def one(expr: 'str') -> 'object':
        expr = re.sub(r'\bgithub\.[\w.]+',
                      lambda m: repr(context.get(m.group(0))), expr)
        expr = expr.replace('&&', ' and ').replace('||', ' or ')
        return eval(expr, {'__builtins__': {}},  # nosec B307 -- test-only, fixed input
                    {'format': lambda fmt, *args: fmt.format(*args)})

    parts = re.split(r'\$\{\{(.*?)\}\}', value)
    if len(parts) == 3 and not parts[0].strip() and not parts[2].strip():
        return one(parts[1])
    if len(parts) == 1:
        return {'true': True, 'false': False}.get(value, value)
    return ''.join(part if n % 2 == 0 else str(one(part)) for n, part in enumerate(parts))


def payload_outside_env(pairs) -> 'list[tuple[str, ...]]':
    """Paths of values reading the event payload, beyond the item number, outside ``env:``."""
    found = []
    for path, value in pairs:
        # The value's own mapping must be an ``env:`` -- not a job named ``env``.
        in_env = len(path) >= 2 and path[-2] == 'env' and path[-3:-2] != ('jobs',)
        if not in_env and 'github.event.' in value.replace(ITEM_NUMBER, ''):
            found.append(path)
    return found


class TestWorkflowSafety(unittest.TestCase):
    """The ``pull_request_target`` job runs no code from the pull request."""

    def setUp(self) -> None:
        self.raw = WORKFLOW.read_text(encoding='utf-8')
        self.text = strip_comments(self.raw)
        self.pairs = scan(self.raw)

    def test_runs_on_pull_request_target(self) -> None:
        # Without this the tests below would pass vacuously on a workflow that
        # had dropped the trigger they exist to guard.
        self.assertRegex(self.text, r'(?m)^  pull_request_target:')

    def test_no_checkout(self) -> None:
        self.assertNotIn('actions/checkout', self.text)
        self.assertNotRegex(self.text, r'(?m)^\s*-?\s*uses:', 'no action may run in this job')

    def test_nothing_from_the_pull_request_head(self) -> None:
        for marker in ('github.event.pull_request.head', 'github.head_ref'):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, self.text)

    def test_no_expression_inside_a_run_script(self) -> None:
        # An expression is substituted into the script text before the shell sees
        # it, so a PR title containing `'; curl … | sh #` becomes code. Values
        # reach the script through `env:` only.
        runs = [(path, value) for path, value in self.pairs if path[-1] == 'run']
        self.assertTrue(runs, 'the scanner found no run: block to check')
        for path, value in runs:
            with self.subTest(path='.'.join(path)):
                self.assertNotIn('${{', value)

    def test_event_payload_only_in_env(self) -> None:
        self.assertEqual(payload_outside_env(self.pairs), [],
                         'an event-payload reference outside env: other than the item number')

    def test_the_env_exemption_is_the_value_s_own_mapping(self) -> None:
        # A job or step key merely *under* something named ``env`` is not in an
        # ``env:`` block; ``'env' in path`` exempted both (#1060).
        text = (f'jobs:\n  env:\n    runs-on: {_TITLE}\n'
                f'    steps:\n      - name: x\n        if: {_TITLE}\n'
                f'        env:\n          T: {_TITLE}\n')
        self.assertEqual(payload_outside_env(scan(text)),
                         [('jobs', 'env', 'runs-on'), ('jobs', 'env', 'steps', 'if')])

    def test_script_fetched_at_the_base_sha(self) -> None:
        self.assertIn('SCRIPT_REF: ${{ github.sha }}', self.text)
        self.assertIn('ref=${SCRIPT_REF}', self.text)

    def test_least_privilege(self) -> None:
        self.assertRegex(self.text, r'(?m)^permissions: \{\}$')
        self.assertRegex(self.text, r'(?m)^\s+timeout-minutes: \d+$')


class TestConcurrency(unittest.TestCase):
    """Per-item runs supersede each other; reconciles never cancel mid-run."""

    def setUp(self) -> None:
        pairs = dict(scan(WORKFLOW.read_text(encoding='utf-8')))
        self.group = pairs[('concurrency', 'group')]
        self.cancel = pairs[('concurrency', 'cancel-in-progress')]

    def resolve(self, context: 'dict') -> 'tuple[object, object]':
        return evaluate_expression(self.group, context), evaluate_expression(self.cancel, context)

    def test_item_events(self) -> None:
        for event, key in (('issues', 'github.event.issue.number'),
                           ('pull_request_target', 'github.event.pull_request.number')):
            with self.subTest(event=event):
                group, cancel = self.resolve({'github.event_name': event, key: 42})
                self.assertEqual(group, 'project-status-item-42')
                self.assertIs(cancel, True)

    def test_reconcile(self) -> None:
        for event in ('schedule', 'workflow_dispatch'):
            with self.subTest(event=event):
                group, cancel = self.resolve({'github.event_name': event})
                self.assertEqual(group, 'project-status-reconcile')
                self.assertIs(cancel, False)


_TITLE = '${{ github.event.issue.title }}'
_STEPS = 'jobs:\n  j:\n    steps:\n'

#: Workflows that splice :data:`_TITLE` into a ``run:`` script in a form the old
#: line scan read as something else (#1060). Each must make :func:`scan` raise.
BYPASSES = {
    'flow-mapping step': f'      - {{name: x, run: "echo {_TITLE}"}}\n',
    'space before the colon': f'      - name: x\n        run : echo {_TITLE}\n',
    'indentation indicator': f'      - name: x\n        run: |2\n          echo {_TITLE}\n',
    'alias': f'      - name: x\n        env:\n          T: &a echo {_TITLE}\n        run: *a\n',
    'block header with a comment': f'      - name: x\n        run: | # c\n          echo {_TITLE}\n',
    'multi-line plain scalar': f'      - name: x\n        run: echo\n          {_TITLE}\n',
    'continuation that looks like an item': f'      - name: x\n        run: echo\n          - {_TITLE}\n',
    'multi-line quoted scalar': f'      - name: x\n        run: "echo\n          {_TITLE}"\n',
    'escaped dollar': '      - name: x\n        run: "echo \\x24{{ github.event.issue.title }}"\n',
    'escaped key': f'      - name: x\n        "r\\x75n": echo {_TITLE}\n',
}

#: The safe shape of the same step: the title reaches the script through ``env:``.
SAFE = f'      - name: x\n        env:\n          T: {_TITLE}\n        run: |\n          echo "$T"\n'


def guard_trips(text: 'str') -> 'bool':
    """Whether :meth:`TestWorkflowSafety.test_no_expression_inside_a_run_script` fails on ``text``."""
    try:
        pairs = scan(text)
    except UnsupportedYAML:
        return True
    return any(path and path[-1] == 'run' and '${{' in value for path, value in pairs)


class TestScannerFailsClosed(unittest.TestCase):
    """:func:`scan` refuses what it cannot read, with or without PyYAML installed."""

    def test_each_bypass_trips_the_guard(self) -> None:
        for form, step in BYPASSES.items():
            with self.subTest(form=form):
                self.assertTrue(guard_trips(_STEPS + step), 'the expression in run: went unseen')

    def test_each_bypass_is_refused(self) -> None:
        for form, step in BYPASSES.items():
            with self.subTest(form=form):
                self.assertRaises(UnsupportedYAML, scan, _STEPS + step)

    def test_the_safe_form_is_read(self) -> None:
        # Without this, a scanner that refused everything would pass the two above.
        pairs = scan(_STEPS + SAFE)
        self.assertFalse(guard_trips(_STEPS + SAFE))
        self.assertIn((('jobs', 'j', 'steps', 'env', 'T'), _TITLE), pairs)
        self.assertIn((('jobs', 'j', 'steps', 'run'), 'echo "$T"'), pairs)

    def test_the_workflow_is_inside_the_subset(self) -> None:
        self.assertTrue(scan(WORKFLOW.read_text(encoding='utf-8')))


def yaml_pairs(node, path=()):
    """:func:`scan`'s output, computed from :func:`yaml.safe_load` instead."""
    if isinstance(node, dict):
        for key, value in node.items():
            key = 'on' if key is True else str(key)
            yield from yaml_pairs(value, path + (key,))
    elif isinstance(node, list):
        for value in node:
            yield from yaml_pairs(value, path)
    elif node is not None:
        yield path, node.strip() if isinstance(node, str) else str(node)


class TestYAMLAgreesWithTheScanner(unittest.TestCase):
    """The hand-rolled :func:`scan` reads the workflow as PyYAML does.

    No CI job installs PyYAML, so this class skips there. It is a cross-check and
    not the guard: :class:`TestScannerFailsClosed` is what holds without it.

    """

    def setUp(self) -> None:
        try:
            import yaml
        except ImportError:  # pragma: no cover
            self.skipTest('PyYAML not installed; scan() fails closed without it (#1060)')
        self.raw = WORKFLOW.read_text(encoding='utf-8')
        self.doc = yaml.safe_load(self.raw)

    def test_same_scalars(self) -> None:
        def norm(pairs):
            return sorted((path, ' '.join(str(value).split()).lower()) for path, value in pairs)
        self.assertEqual(norm(scan(self.raw)), norm(yaml_pairs(self.doc)))

    def test_each_bypass_is_real(self) -> None:
        # Each fixture really does put the expression into a run: script, so
        # TestScannerFailsClosed is testing bypasses and not malformed YAML.
        import yaml
        for form, step in BYPASSES.items():
            with self.subTest(form=form):
                runs = [value for path, value in yaml_pairs(yaml.safe_load(_STEPS + step))
                        if path[-1] == 'run']
                self.assertTrue(any('${{' in value for value in runs), runs)

    def test_no_step_uses_an_action(self) -> None:
        self.assertIn('pull_request_target', self.doc.get('on', self.doc.get(True)))
        for name, job in self.doc['jobs'].items():
            for step in job['steps']:
                with self.subTest(job=name, step=step.get('name')):
                    self.assertNotIn('uses', step)


PROJECT = 'PVT_kwHOAO8M8c4Bl2gH'
FIELD = 'PVTSSF_lAHOAO8M8c4Bl2gHzhkhthA'
OPTIONS = {name: f'opt-{i}' for i, name in enumerate(project_status.STATUSES)}


def item(number, *labels, state='OPEN', kind='Issue', on_board=None):
    """A GraphQL item node; ``on_board`` is its current Status, or None if absent."""
    nodes = []
    if on_board is not None:
        nodes.append({'id': f'PVTI_{number}', 'project': {'id': PROJECT},
                      'fieldValueByName': {'optionId': OPTIONS[on_board]} if on_board else None})
    return {'__typename': kind, 'id': f'node-{number}', 'number': number, 'state': state,
            'labels': {'nodes': [{'name': label} for label in labels]},
            'projectItems': {'nodes': nodes}}


class FakeGraphQL:
    """Answers the script's queries from fixtures and records its mutations."""

    def __init__(self, items, project_id=PROJECT, field_id=FIELD, options=None, issue_count=None):
        self.issue_count = issue_count
        self.items = {it['number']: it for it in items}
        self.project_id = project_id
        self.field_id = field_id
        self.options = OPTIONS if options is None else options
        self.mutations = []
        self.searches = []

    def __call__(self, query, variables):
        if 'user(login' in query:
            return {'user': {'projectV2': {'id': self.project_id}}}
        if 'node(id: $project)' in query:
            return {'node': {'field': {'id': self.field_id, 'options': [
                {'id': oid, 'name': name} for name, oid in self.options.items()]}}}
        if 'issueOrPullRequest' in query:
            return {'repository': {'issueOrPullRequest': self.items.get(variables['number'])}}
        if 'search(' in query:
            self.searches.append(variables['q'])
            want_open = 'is:open' in variables['q']
            nodes = [it for it in self.items.values() if (it['state'] == 'OPEN') == want_open]
            count = len(nodes) if self.issue_count is None else self.issue_count
            return {'search': {'issueCount': count, 'nodes': nodes,
                               'pageInfo': {'hasNextPage': False, 'endCursor': None}}}
        if 'addProjectV2ItemById' in query:
            self.mutations.append(('add', variables['content']))
            return {'addProjectV2ItemById': {'item': {'id': 'PVTI_new'}}}
        if 'updateProjectV2ItemFieldValue' in query:
            self.mutations.append(('set', variables['item'], variables['option']))
            return {'updateProjectV2ItemFieldValue': {'projectV2Item': {'id': variables['item']}}}
        raise AssertionError(f'unexpected query: {query[:80]!r}')


class TestBoardSync(unittest.TestCase):
    """The script against a fake endpoint: what it mutates, and when it skips."""

    def run_main(self, argv, fake, token='x'):
        env = {'GH_TOKEN': token} if token else {}
        out = io.StringIO()
        with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(out):
            code = project_status.main(argv + ['--repo', 'JarryShaw/PyPCAPKit'], graphql=fake,
                                       today=datetime.date(2026, 10, 5))
        return code, out.getvalue()

    def test_missing_token_skips_with_a_notice(self) -> None:
        fake = FakeGraphQL([item(1, 'wip')])
        code, out = self.run_main(['--item', '1'], fake, token=None)
        self.assertEqual(code, 0)
        self.assertIn('::notice', out)
        self.assertEqual(fake.mutations, [])

    def test_item_status_is_corrected(self) -> None:
        fake = FakeGraphQL([item(5, 'wip', 'needs: decision', on_board='WIP')])
        code, _ = self.run_main(['--item', '5'], fake)
        self.assertEqual(code, 0)
        self.assertEqual(fake.mutations, [('set', 'PVTI_5', OPTIONS['Needs decision'])])

    def test_item_already_right_is_left_alone(self) -> None:
        fake = FakeGraphQL([item(5, 'blocked', on_board='Blocked')])
        self.run_main(['--item', '5'], fake)
        self.assertEqual(fake.mutations, [])

    def test_item_not_on_the_board_is_added_first(self) -> None:
        fake = FakeGraphQL([item(7, kind='PullRequest')])
        self.run_main(['--item', '7'], fake)
        self.assertEqual(fake.mutations, [('add', 'node-7'), ('set', 'PVTI_new', OPTIONS['In review'])])

    def test_item_without_a_status_is_set(self) -> None:
        fake = FakeGraphQL([item(8, on_board='')])
        self.run_main(['--item', '8'], fake)
        self.assertEqual(fake.mutations, [('set', 'PVTI_8', OPTIONS['Pending'])])

    def test_merged_is_done(self) -> None:
        fake = FakeGraphQL([item(9, 'wip', state='MERGED', kind='PullRequest', on_board='In review')])
        self.run_main(['--item', '9'], fake)
        self.assertEqual(fake.mutations, [('set', 'PVTI_9', OPTIONS['Done'])])

    def test_dry_run_mutates_nothing(self) -> None:
        fake = FakeGraphQL([item(5, 'wip', on_board='Pending')])
        _, out = self.run_main(['--item', '5', '--dry-run'], fake)
        self.assertEqual(fake.mutations, [])
        self.assertIn("would set Status to 'WIP'", out)

    def test_reconcile_covers_open_and_recently_closed(self) -> None:
        fake = FakeGraphQL([item(1, 'wip', on_board='Pending'),
                            item(2, state='CLOSED', on_board='Blocked'),
                            item(3, 'blocked', on_board='Blocked')])
        self.run_main(['--reconcile'], fake)
        self.assertEqual(fake.searches, ['repo:JarryShaw/PyPCAPKit is:open',
                                         'repo:JarryShaw/PyPCAPKit is:closed closed:>=2026-09-28'])
        self.assertEqual(fake.mutations, [('set', 'PVTI_1', OPTIONS['WIP']),
                                          ('set', 'PVTI_2', OPTIONS['Done'])])

    def test_a_complete_reconcile_does_not_warn(self) -> None:
        _, out = self.run_main(['--reconcile'], FakeGraphQL([item(1, on_board='Pending')]))
        self.assertNotIn('::warning', out)

    def test_a_truncated_reconcile_warns(self) -> None:
        # Search returns at most 1000 results; issueCount still says how many matched.
        for count in (1001, 5):
            with self.subTest(issue_count=count):
                fake = FakeGraphQL([item(1, 'wip', on_board='Pending')], issue_count=count)
                code, out = self.run_main(['--reconcile'], fake)
                self.assertEqual(code, 0)
                self.assertIn('::warning', out)
                self.assertIn('partial', out)
                # The items that did come back are still synced.
                self.assertIn(('set', 'PVTI_1', OPTIONS['WIP']), fake.mutations)

    def test_a_recreated_board_is_refused(self) -> None:
        fake = FakeGraphQL([item(1)], project_id='PVT_other')
        with self.assertRaisesRegex(RuntimeError, 'recreated'):
            self.run_main(['--item', '1'], fake)

    def test_a_missing_option_is_refused(self) -> None:
        options = {k: v for k, v in OPTIONS.items() if k != 'WIP'}
        fake = FakeGraphQL([item(1)], options=options)
        with self.assertRaisesRegex(RuntimeError, 'WIP'):
            self.run_main(['--item', '1'], fake)
        self.assertEqual(fake.mutations, [])

    def test_option_ids_come_from_the_api(self) -> None:
        options = {name: f'live-{name}' for name in project_status.STATUSES}
        fake = FakeGraphQL([item(4, 'blocked', on_board=None)], options=options)
        self.run_main(['--item', '4'], fake)
        self.assertEqual(fake.mutations[-1], ('set', 'PVTI_new', 'live-Blocked'))


if __name__ == '__main__':
    unittest.main()
