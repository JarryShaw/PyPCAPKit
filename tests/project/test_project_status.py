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
  a secret in scope, so it must never check out code or read anything from the
  pull request's head. Asserted over the file, because nothing at run time would
  announce the mistake.

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


class TestWorkflowSafety(unittest.TestCase):
    """The ``pull_request_target`` job runs no code from the pull request."""

    def setUp(self) -> None:
        self.raw = WORKFLOW.read_text(encoding='utf-8')
        self.text = strip_comments(self.raw)

    def test_runs_on_pull_request_target(self) -> None:
        # Without this the two tests below would pass vacuously on a workflow that
        # had dropped the trigger they exist to guard.
        self.assertRegex(self.text, r'(?m)^  pull_request_target:')

    def test_no_checkout(self) -> None:
        self.assertNotIn('actions/checkout', self.text)
        self.assertNotRegex(self.text, r'(?m)^\s*-?\s*uses:', 'no action may run in this job')

    def test_nothing_from_the_pull_request_head(self) -> None:
        for marker in ('github.event.pull_request.head', 'github.head_ref'):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, self.text)

    def test_script_fetched_at_the_base_sha(self) -> None:
        self.assertIn('SCRIPT_REF: ${{ github.sha }}', self.text)
        self.assertIn('ref=${SCRIPT_REF}', self.text)

    def test_least_privilege(self) -> None:
        self.assertRegex(self.text, r'(?m)^permissions: \{\}$')
        self.assertRegex(self.text, r'(?m)^\s+timeout-minutes: \d+$')

    def test_yaml_agrees(self) -> None:
        try:
            import yaml
        except ImportError:  # pragma: no cover
            self.skipTest('PyYAML not installed')
        doc = yaml.safe_load(self.raw)
        on = doc.get('on', doc.get(True))
        self.assertIn('pull_request_target', on)
        for name, job in doc['jobs'].items():
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

    def __init__(self, items, project_id=PROJECT, field_id=FIELD, options=None):
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
            return {'search': {'pageInfo': {'hasNextPage': False, 'endCursor': None}, 'nodes': nodes}}
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
