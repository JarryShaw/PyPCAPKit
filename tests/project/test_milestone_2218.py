# -*- coding: utf-8 -*-
"""#2218: :file:`util/milestone.py` and :file:`.github/workflows/milestone.yml`.

* :class:`TestTitle` and :class:`TestReadVersion` -- the milestone a version maps
  to, and the version read from :file:`pcapkit/__init__.py` as text.
* :class:`TestActionFor` -- the rule: an open item, a merged pull request or an
  issue closed as completed gets the milestone; an unmerged one or one closed as
  not planned loses it; an issue closed with no reason is left alone.
* :class:`TestPrecedence` -- a milestone already on an item, set by hand, wins over
  the one the rule gives, but not over a removal.
* :class:`TestOneItem` and :class:`TestBackfill` drive the script against a fake
  REST endpoint: what it updates, when it updates nothing, and the warning for a
  missing milestone. Nothing here reaches GitHub.
* :class:`TestThrottle` and :class:`TestRateLimit` -- updates a second apart,
  and a request refused for a rate limit retried a bounded number of times, the
  refusal read from a mocked :program:`gh` response.
* :class:`TestWorkflow` -- the triggers, the permissions, the base-only checkout
  and the concurrency groups, asserted over the file, with the scanner
  :mod:`tests.project.test_project_status` holds to failing closed.
  :class:`TestTheStep` runs the step's script with a stand-in ``python3``.

"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import pathlib
import re
import shutil
import subprocess  # nosec B404
import tempfile
import unittest
from unittest import mock
from typing import TYPE_CHECKING

from tests._support import bash_argv
from tests._workflows import job, load, pinned, steps
from tests.project.test_project_status import (evaluate_expression, expression_spliced, payload_outside_env,
                                               scan, strip_comments, yaml_pairs)

if TYPE_CHECKING:
    from typing import Any, Optional

#: Test tier (#1958): reads the workflow file and runs the tree's script, a question about the tree.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = 'milestone.yml'
JOB = 'milestone'
STEP = 'Set the milestone'
DOC = ROOT / 'docs' / 'source' / 'contributing' / 'workflows.rst'
REPO = 'JarryShaw/PyPCAPKit'
#: A pinned ``uses:`` line's version comment, which :func:`scan` refuses as part of a plain scalar.
PIN_COMMENT = re.compile(r'(?m)^(\s*(?:- )?uses: \S+@[0-9a-f]{40}) # v\S+$')


def _load_script():
    """Load :file:`util/milestone.py`, which is a script and not a package."""
    spec = importlib.util.spec_from_file_location('milestone', ROOT / 'util' / 'milestone.py')
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


milestone = _load_script()


class TestTitle(unittest.TestCase):
    """A version's milestone is ``PyPCAPKit v<major>.<minor>``."""

    def test_versions(self) -> None:
        for version, title in (('1.5.0b14', 'PyPCAPKit v1.5'), ('1.5.0', 'PyPCAPKit v1.5'),
                               ('1.10.2', 'PyPCAPKit v1.10'), ('2.0', 'PyPCAPKit v2.0'),
                               ('0.16.3.post1', 'PyPCAPKit v0.16'), ('1.6.0.dev3', 'PyPCAPKit v1.6')):
            with self.subTest(version=version):
                self.assertEqual(milestone.milestone_title(version), title)

    def test_a_version_without_a_minor_is_refused(self) -> None:
        for version in ('1', 'v1.5', '', 'one.two'):
            with self.subTest(version=version):
                self.assertRaises(ValueError, milestone.milestone_title, version)

    def test_titles_read_back(self) -> None:
        self.assertEqual(milestone.title_release('PyPCAPKit v1.4'), (1, 4))
        self.assertEqual(milestone.title_release('PyPCAPKit v0.16'), (0, 16))
        for title in ('PyPCAPKit v1', 'PyPCAPKit v1.5.1', 'pypcapkit v1.5', 'Backlog', 'PyPCAPKit v1.5b'):
            with self.subTest(title=title):
                self.assertIsNone(milestone.title_release(title))


class TestReadVersion(unittest.TestCase):
    """``__version__`` is read as text, so the checkout's code never runs."""

    def write(self, text: 'str') -> 'str':
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-2218-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, '__init__.py')
        with open(path, 'w', encoding='utf-8') as file:
            file.write(text)
        return path

    def test_the_tree_s_version(self) -> None:
        import pcapkit  # pylint: disable=import-outside-toplevel
        self.assertEqual(milestone.read_version(str(ROOT / 'pcapkit' / '__init__.py')), pcapkit.__version__)

    def test_nothing_runs(self) -> None:
        path = self.write("raise SystemExit('ran')\nimport nonexistent\n__version__ = '3.1.4'\n")
        self.assertEqual(milestone.read_version(path), '3.1.4')

    def test_only_a_top_level_string(self) -> None:
        for text in ("def f():\n    __version__ = '1.0'\n", "__version__ = VERSION\n", "version = '1.0'\n"):
            with self.subTest(text=text):
                self.assertRaises(ValueError, milestone.read_version, self.write(text))


def issue(number: 'int', state: 'str' = 'closed', reason: 'Optional[str]' = 'completed',
          current: 'Optional[dict[str, Any]]' = None) -> 'dict[str, Any]':
    """An issue as the REST API returns it."""
    return {'number': number, 'state': state, 'state_reason': reason, 'milestone': current}


def pull(number: 'int', merged: 'bool', state: 'str' = 'closed',
         current: 'Optional[dict[str, Any]]' = None) -> 'dict[str, Any]':
    """A pull request as the REST issues API returns it."""
    return {'number': number, 'state': state, 'state_reason': None, 'milestone': current,
            'pull_request': {'merged_at': '2026-10-25T00:00:00Z' if merged else None}}


class TestActionFor(unittest.TestCase):
    """The rule the milestones followed by hand."""

    def test_each_case(self) -> None:
        cases = [
            ('merged pull request', pull(1, merged=True), milestone.SET),
            ('unmerged pull request', pull(2, merged=False), milestone.REMOVE),
            ('completed issue', issue(3), milestone.SET),
            ('not-planned issue', issue(4, reason='not_planned'), milestone.REMOVE),
            ('duplicate issue', issue(5, reason='duplicate'), milestone.REMOVE),
            ('issue closed with no reason', issue(6, reason=None), None),
            ('issue opened', issue(7, state='open', reason=None), milestone.SET),
            ('issue reopened', issue(8, state='open', reason='reopened'), milestone.SET),
            ('pull request opened', pull(9, merged=False, state='open'), milestone.SET),
        ]
        for case, item, want in cases:
            with self.subTest(case=case):
                self.assertEqual(milestone.action_for(item), want)


V14 = {'number': 9, 'title': 'PyPCAPKit v1.4', 'state': 'closed'}
V15 = {'number': 10, 'title': 'PyPCAPKit v1.5', 'state': 'open'}
V16 = {'number': 12, 'title': 'PyPCAPKit v1.6', 'state': 'open'}
V013 = {'number': 1, 'title': 'PyPCAPKit v0.13', 'state': 'closed'}
OTHER = {'number': 11, 'title': 'Backlog', 'state': 'open'}


class FakeRest:
    """Answers the script's requests from fixtures and records its updates."""

    def __init__(self, items, found=(V013, V14, V15, OTHER), newest=None):
        self.items = {item['number']: item for item in items}
        self.found = list(found)
        #: The highest item number in each milestone, by milestone number.
        self.newest = {9: 336, 1: 12} if newest is None else newest
        self.patches = []  # type: list[tuple[int, Any]]
        self.gets = []  # type: list[str]

    def __call__(self, method, path, body):
        if method == 'PATCH':
            number = int(path.rsplit('/', 1)[1])
            self.patches.append((number, body['milestone']))
            return {}
        assert method == 'GET', method
        self.gets.append(path)
        route, _, query = path.partition('?')
        params = dict(pair.split('=', 1) for pair in query.split('&')) if query else {}
        if route == f'repos/{REPO}/milestones':
            return self.page(self.found, params)
        if route.startswith(f'repos/{REPO}/issues/'):
            return self.items[int(route.rsplit('/', 1)[1])]
        if route == f'repos/{REPO}/issues':
            if params.get('milestone') == 'none':
                states = ('open', 'closed') if params['state'] == 'all' else (params['state'],)
                listed = [item for item in sorted(self.items.values(), key=lambda item: -item['number'])
                          if item['state'] in states and item['milestone'] is None]
                return self.page(listed, params)
            number = self.newest.get(int(params['milestone']))
            return [] if number is None else [issue(number)]
        raise AssertionError(f'unexpected request: {method} {path}')

    @staticmethod
    def page(entries, params):
        size, page = int(params['per_page']), int(params['page'])
        return entries[(page - 1) * size:page * size]


class _Runs(unittest.TestCase):

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-2218-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.version = os.path.join(tmp.name, '__init__.py')
        with open(self.version, 'w', encoding='utf-8') as file:
            file.write("__version__ = '1.5.0b14'\n")

    def run_main(self, argv: 'list[str]', fake: 'FakeRest') -> 'tuple[int, str]':
        #: The waits the run asked for, in order; nothing here really sleeps.
        self.slept = []  # type: list[float]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = milestone.main(argv + ['--repo', REPO, '--version-file', self.version], rest=fake,
                                  sleep=self.slept.append)
        return code, out.getvalue()


class TestOneItem(_Runs):
    """``--item N``: one issue or pull request, re-read from the API."""

    def test_a_merged_pull_request_gets_the_milestone(self) -> None:
        fake = FakeRest([pull(2205, merged=True)])
        code, out = self.run_main(['--item', '2205'], fake)
        self.assertEqual(code, 0)
        self.assertEqual(fake.patches, [(2205, 10)])
        self.assertEqual(out, "#2205: set milestone to 'PyPCAPKit v1.5'\n1 of 1 item(s) changed\n")

    def test_a_completed_issue_gets_it(self) -> None:
        fake = FakeRest([issue(2218)])
        self.run_main(['--item', '2218'], fake)
        self.assertEqual(fake.patches, [(2218, 10)])

    def test_an_opened_or_reopened_item_gets_it(self) -> None:
        for case, item in (('issue opened', issue(2220, state='open', reason=None)),
                           ('issue reopened', issue(2220, state='open', reason='reopened')),
                           ('pull request opened', pull(2220, merged=False, state='open'))):
            with self.subTest(case=case):
                fake = FakeRest([item])
                _, out = self.run_main(['--item', '2220'], fake)
                self.assertEqual(fake.patches, [(2220, 10)])
                self.assertEqual(out, "#2220: set milestone to 'PyPCAPKit v1.5'\n1 of 1 item(s) changed\n")

    def test_an_item_already_right_is_left_alone(self) -> None:
        fake = FakeRest([issue(2218, current=V15)])
        _, out = self.run_main(['--item', '2218'], fake)
        self.assertEqual(fake.patches, [])
        self.assertEqual(out, '0 of 1 item(s) changed\n')

    def test_an_unmerged_pull_request_loses_it(self) -> None:
        fake = FakeRest([pull(707, merged=False, current=V15)])
        _, out = self.run_main(['--item', '707'], fake)
        self.assertEqual(fake.patches, [(707, None)])
        self.assertIn("#707: remove milestone 'PyPCAPKit v1.5'", out)

    def test_a_not_planned_issue_loses_it(self) -> None:
        fake = FakeRest([issue(372, reason='not_planned', current=V15)])
        self.run_main(['--item', '372'], fake)
        self.assertEqual(fake.patches, [(372, None)])

    def test_nothing_to_remove(self) -> None:
        fake = FakeRest([issue(372, reason='not_planned')])
        self.run_main(['--item', '372'], fake)
        self.assertEqual(fake.patches, [])

    def test_a_removal_reads_no_milestone(self) -> None:
        fake = FakeRest([pull(707, merged=False, current=V15)], found=())
        _, out = self.run_main(['--item', '707'], fake)
        self.assertEqual(fake.patches, [(707, None)])
        self.assertNotIn('::warning', out)
        self.assertFalse([path for path in fake.gets if 'milestones' in path])

    def test_a_reopened_item_gets_it_back_after_a_removal(self) -> None:
        fake = FakeRest([issue(372, reason='not_planned', current=V15)])
        self.run_main(['--item', '372'], fake)
        fake.items[372] = issue(372, state='open', reason='reopened')
        self.run_main(['--item', '372'], fake)
        self.assertEqual(fake.patches, [(372, None), (372, 10)])

    def test_a_missing_milestone_warns_and_changes_nothing(self) -> None:
        for case, found in (('absent', (V013, V14, OTHER)),
                            ('closed', (V013, V14, dict(V15, state='closed')))):
            with self.subTest(case=case):
                fake = FakeRest([pull(2205, merged=True)], found=found)
                code, out = self.run_main(['--item', '2205'], fake)
                self.assertEqual(code, 0)
                self.assertEqual(fake.patches, [])
                self.assertEqual(out, "::warning title=Milestone::no open milestone is titled 'PyPCAPKit v1.5', "
                                      'so no item was given one; create it by hand.\n0 of 1 item(s) changed\n')

    def test_the_title_follows_the_version_file(self) -> None:
        with open(self.version, 'w', encoding='utf-8') as file:
            file.write("__version__ = '1.4.2'\n")
        fake = FakeRest([issue(300)], found=(dict(V14, state='open'), V15))
        self.run_main(['--item', '300'], fake)
        self.assertEqual(fake.patches, [(300, 9)])

    def test_a_dry_run_changes_nothing(self) -> None:
        fake = FakeRest([pull(2205, merged=True)])
        _, out = self.run_main(['--item', '2205', '--dry-run'], fake)
        self.assertEqual(fake.patches, [])
        self.assertIn("#2205: would set milestone to 'PyPCAPKit v1.5'", out)


class TestBackfill(_Runs):
    """``--backfill``: closed items without a milestone, above the previous release's."""

    def test_items_above_the_previous_milestone(self) -> None:
        items = [issue(300), issue(336), issue(337), pull(338, merged=True), pull(339, merged=False),
                 issue(340, reason='not_planned'), issue(341, current=V15), issue(342, state='open', reason=None),
                 issue(343, reason=None), issue(344, current=V16)]
        fake = FakeRest(items)
        code, out = self.run_main(['--backfill'], fake)
        self.assertEqual(code, 0)
        # v1.4 is the release before v1.5, and its newest item is #336.
        self.assertEqual(fake.patches, [(337, 10), (338, 10), (342, 10)])
        self.assertEqual(out.splitlines(), ['backfilling items above #336 without a milestone',
                                            "#337: set milestone to 'PyPCAPKit v1.5'",
                                            "#338: set milestone to 'PyPCAPKit v1.5'",
                                            "#342: set milestone to 'PyPCAPKit v1.5'",
                                            '3 of 6 item(s) changed'])

    def test_open_items_are_listed_too(self) -> None:
        items = [issue(337, state='open', reason=None), pull(338, merged=False, state='open'),
                 issue(339, state='open', reason='reopened', current=V16), issue(300, state='open', reason=None)]
        fake = FakeRest(items)
        self.run_main(['--backfill'], fake)
        self.assertEqual(fake.patches, [(337, 10), (338, 10)])
        self.assertEqual([path for path in fake.gets if 'milestone=none' in path],
                         [f'repos/{REPO}/issues?state=all&milestone=none&sort=created&direction=desc'
                          '&per_page=100&page=1'])

    def test_the_listing_stops_at_the_bound(self) -> None:
        items = [issue(number) for number in range(1, 500)]
        fake = FakeRest(items)
        self.run_main(['--backfill', '--dry-run'], fake)
        listed = [path for path in fake.gets if 'milestone=none' in path]
        # 499 down to 400 is the first page; the second reaches #336.
        self.assertEqual(len(listed), 2)
        self.assertEqual(fake.patches, [])

    def test_a_dry_run_changes_nothing(self) -> None:
        fake = FakeRest([issue(400)])
        _, out = self.run_main(['--backfill', '--dry-run'], fake)
        self.assertEqual(fake.patches, [])
        self.assertIn("#400: would set milestone to 'PyPCAPKit v1.5'", out)

    def test_no_earlier_milestone_refuses(self) -> None:
        fake = FakeRest([issue(400)], found=(V15, OTHER))
        code, out = self.run_main(['--backfill'], fake)
        self.assertEqual(code, 0)
        self.assertEqual(fake.patches, [])
        self.assertEqual(out, "::warning title=Milestone::no release milestone before 'PyPCAPKit v1.5', so nothing "
                              'bounds the backfill; no item was changed.\n')

    def test_an_empty_previous_milestone_bounds_at_zero(self) -> None:
        fake = FakeRest([issue(5)], newest={})
        self.run_main(['--backfill'], fake)
        self.assertEqual(fake.patches, [(5, 10)])

    def test_a_missing_milestone_warns_and_changes_nothing(self) -> None:
        fake = FakeRest([issue(400)], found=(V14,))
        _, out = self.run_main(['--backfill'], fake)
        self.assertEqual(fake.patches, [])
        self.assertIn("::warning title=Milestone::no open milestone is titled 'PyPCAPKit v1.5'", out)


class TestPrecedence(_Runs):
    """A milestone already on an item wins over the rule's, on open and on close, but not over a removal."""

    def test_another_milestone_is_kept(self) -> None:
        cases = [('opened', issue(2220, state='open', reason=None, current=V16)),
                 ('reopened', issue(2220, state='open', reason='reopened', current=V16)),
                 ('pull request opened', pull(2220, merged=False, state='open', current=V16)),
                 ('closed as completed', issue(2220, current=V16)),
                 ('merged', pull(2220, merged=True, current=V16)),
                 ('an earlier release', issue(2220, current=V14))]
        for case, item in cases:
            with self.subTest(case=case):
                fake = FakeRest([item], found=(V013, V14, V15, V16, OTHER))
                _, out = self.run_main(['--item', '2220'], fake)
                self.assertEqual(fake.patches, [])
                title = item['milestone']['title']
                self.assertEqual(out, f"#2220: keeps milestone {title!r}\n0 of 1 item(s) changed\n")

    def test_the_current_milestone_is_left_alone(self) -> None:
        for item in (issue(2220, state='open', reason=None, current=V15), pull(2220, merged=True, current=V15)):
            with self.subTest(item=item):
                fake = FakeRest([item])
                _, out = self.run_main(['--item', '2220'], fake)
                self.assertEqual(fake.patches, [])
                self.assertEqual(out, '0 of 1 item(s) changed\n')

    def test_a_removal_takes_whichever_it_holds(self) -> None:
        for case, item in (('unmerged', pull(2220, merged=False, current=V16)),
                           ('not planned', issue(2220, reason='not_planned', current=V16)),
                           ('duplicate', issue(2220, reason='duplicate', current=V14))):
            with self.subTest(case=case):
                fake = FakeRest([item])
                _, out = self.run_main(['--item', '2220'], fake)
                self.assertEqual(fake.patches, [(2220, None)])
                self.assertIn(f"#2220: remove milestone {item['milestone']['title']!r}", out)


class TestThrottle(_Runs):
    """Updates go out :data:`WRITE_INTERVAL` apart, and nothing waits before the first."""

    def test_a_backfill_spaces_its_updates(self) -> None:
        fake = FakeRest([issue(400), issue(401), pull(402, merged=True), issue(403, reason='not_planned')])
        self.run_main(['--backfill'], fake)
        self.assertEqual(fake.patches, [(400, 10), (401, 10), (402, 10)])
        self.assertEqual(self.slept, [milestone.WRITE_INTERVAL] * 2)
        self.assertEqual(milestone.WRITE_INTERVAL, 1.0)

    def test_a_dry_run_and_one_item_do_not_wait(self) -> None:
        for argv, fake in ((['--backfill', '--dry-run'], FakeRest([issue(400), issue(401)])),
                           (['--item', '400'], FakeRest([issue(400)]))):
            with self.subTest(argv=argv):
                self.run_main(argv, fake)
                self.assertEqual(self.slept, [])


def response(status: 'int', reason: 'str', headers: 'dict[str, str]', body: 'str') -> 'str':
    """A response as ``gh api --include`` prints it: the status line, headers, a blank line and the body."""
    return f'HTTP/2.0 {status} {reason}\n' + ''.join(f'{name}: {value}\r\n' for name, value in headers.items()) \
        + '\r\n' + body


SECONDARY = response(403, 'Forbidden', {'Content-Type': 'application/json'},
                     '{"message":"You have exceeded a secondary rate limit. Please wait a few minutes before you '
                     'try again."}')
RETRY_AFTER = response(429, 'Too Many Requests', {'Retry-After': '7'}, '{"message":"Too Many Requests"}')
PRIMARY = response(403, 'Forbidden', {'X-RateLimit-Remaining': '0'}, '{"message":"API rate limit exceeded"}')
FORBIDDEN = response(403, 'Forbidden', {}, '{"message":"Resource not accessible by integration"}')
UPDATED = response(200, 'OK', {'Content-Type': 'application/json'}, '{"number": 400, "milestone": {"number": 10}}')


def completed(stdout: 'str', returncode: 'int' = 0) -> 'subprocess.CompletedProcess':
    return subprocess.CompletedProcess(['gh'], returncode, stdout=stdout,
                                       stderr='' if returncode == 0 else 'gh: refused (HTTP 403)')


class TestRateLimit(unittest.TestCase):
    """A rate-limited request is retried, after GitHub's wait, a bounded number of times."""

    def setUp(self) -> None:
        self.slept = []  # type: list[float]

    def call(self, *outputs: 'subprocess.CompletedProcess') -> 'mock.MagicMock':
        run = mock.MagicMock(side_effect=list(outputs))
        rest = milestone.retrying(milestone.gh_rest, self.slept.append)
        with mock.patch.object(milestone.subprocess, 'run', run), contextlib.redirect_stdout(io.StringIO()):
            self.result = rest('PATCH', f'repos/{REPO}/issues/400', {'milestone': 10})
        return run

    def test_the_response_is_read_past_its_headers(self) -> None:
        run = self.call(completed(UPDATED))
        self.assertEqual(self.result, {'number': 400, 'milestone': {'number': 10}})
        self.assertEqual(run.call_args.args[0], ['gh', 'api', '--include', '-X', 'PATCH',
                                                 f'repos/{REPO}/issues/400', '--input', '-'])
        self.assertEqual(run.call_args.kwargs['input'], '{"milestone": 10}')
        self.assertEqual(self.slept, [])

    def test_a_secondary_limit_backs_off_and_retries(self) -> None:
        run = self.call(completed(SECONDARY, 1), completed(SECONDARY, 1), completed(UPDATED))
        self.assertEqual(run.call_count, 3)
        self.assertEqual(self.slept, [milestone.BACKOFF, milestone.BACKOFF * 2])
        self.assertEqual(self.result['number'], 400)

    def test_retry_after_is_the_wait(self) -> None:
        self.call(completed(RETRY_AFTER, 1), completed(UPDATED))
        self.assertEqual(self.slept, [7.0])

    def test_the_primary_limit_counts_too(self) -> None:
        self.call(completed(PRIMARY, 1), completed(UPDATED))
        self.assertEqual(self.slept, [milestone.BACKOFF])

    def test_the_retries_are_bounded(self) -> None:
        outputs = [completed(SECONDARY, 1)] * (milestone.RETRIES + 1)
        with self.assertRaisesRegex(milestone.RateLimited, 'HTTP 403'):
            self.call(*outputs)
        self.assertEqual(self.slept, [milestone.BACKOFF * 2 ** n for n in range(milestone.RETRIES)])

    def test_another_refusal_is_not_retried(self) -> None:
        with self.assertRaises(RuntimeError) as caught:
            self.call(completed(FORBIDDEN, 1), completed(UPDATED))
        self.assertNotIsInstance(caught.exception, milestone.RateLimited)
        self.assertEqual(self.slept, [])

    def test_the_split(self) -> None:
        self.assertEqual(milestone.split_response(RETRY_AFTER),
                         (429, {'retry-after': '7'}, '{"message":"Too Many Requests"}'))
        self.assertEqual(milestone.split_response('{"a": 1}'), (0, {}, '{"a": 1}'))
        self.assertEqual(milestone.split_response(''), (0, {}, ''))


class TestWorkflow(unittest.TestCase):
    """Triggers, scopes and the base-only checkout, over :file:`milestone.yml`."""

    def setUp(self) -> None:
        self.doc = load(WORKFLOW)
        self.raw = (ROOT / '.github' / 'workflows' / WORKFLOW).read_text(encoding='utf-8')
        # The scanner fails closed on a comment after a plain scalar, so the pin's
        # version comment goes first; test_the_scanner_reads_what_yaml_reads holds
        # the result to the YAML.
        self.pairs = scan(PIN_COMMENT.sub(r'\1', self.raw))

    def test_the_scanner_reads_what_yaml_reads(self) -> None:
        self.assertEqual(PIN_COMMENT.subn('', self.raw)[1], 1)

        def norm(pairs):
            return sorted((path, ' '.join(str(value).split()).lower()) for path, value in pairs)
        self.assertEqual(norm(self.pairs), norm(yaml_pairs(self.doc)))

    def test_triggers(self) -> None:
        on = self.doc['on']
        self.assertEqual(sorted(on), ['issues', 'pull_request_target', 'workflow_dispatch'])
        self.assertEqual(on['issues'], {'types': ['opened', 'reopened', 'closed']})
        self.assertEqual(on['pull_request_target'], {'types': ['opened', 'reopened', 'closed']})
        self.assertEqual(on['workflow_dispatch']['inputs'],
                         {'dry_run': {'description': 'Report what the backfill would change, and change nothing',
                                      'type': 'boolean', 'default': True}})

    def test_permissions(self) -> None:
        self.assertEqual(self.doc['permissions'], {})
        self.assertEqual(list(self.doc['jobs']), [JOB])
        self.assertEqual(job(WORKFLOW, JOB)['permissions'], {'contents': 'read', 'issues': 'write',
                                                               'pull-requests': 'write'})
        self.assertIsInstance(job(WORKFLOW, JOB)['timeout-minutes'], int)

    def test_the_checkout_is_the_base_and_only_what_the_script_reads(self) -> None:
        checkout, run = steps(WORKFLOW, JOB)
        self.assertTrue(pinned(checkout['uses'], 'actions/checkout'), checkout['uses'])
        self.assertEqual(checkout['with']['ref'], '${{ github.sha }}')
        self.assertIs(checkout['with']['persist-credentials'], False)
        self.assertIs(checkout['with']['sparse-checkout-cone-mode'], False)
        self.assertEqual(checkout['with']['sparse-checkout'].split(),
                         ['pcapkit/__init__.py', 'util/_actions.py', 'util/milestone.py'])
        self.assertEqual(run['name'], STEP)
        self.assertNotIn('uses', run)

    def test_nothing_from_the_pull_request_head(self) -> None:
        text = strip_comments(self.raw)
        for marker in ('github.event.pull_request.head', 'github.head_ref', 'merge_commit_sha', 'refs/pull/'):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, text)

    def test_no_expression_inside_a_run_script(self) -> None:
        guarded = [(path, value) for path, value in self.pairs if expression_spliced(path)]
        self.assertTrue([path for path, _ in guarded if path[-1] == 'run'], 'the scanner found no run: block')
        for path, value in guarded:
            with self.subTest(path='.'.join(path)):
                self.assertNotIn('${{', value)

    def test_event_payload_only_in_env(self) -> None:
        self.assertEqual(payload_outside_env(self.pairs), [])

    def test_the_token_is_the_job_s_own(self) -> None:
        _, run = steps(WORKFLOW, JOB)
        self.assertEqual(run['env']['GH_TOKEN'], '${{ github.token }}')
        self.assertNotIn('secrets.', strip_comments(self.raw))

    def test_concurrency(self) -> None:
        concurrency = self.doc['concurrency']
        # As project-status.yml's: nothing cancelled, and `queue` without
        # `cancel-in-progress`, which GitHub rejects beside it.
        self.assertEqual(sorted(concurrency), ['group', 'queue'])
        self.assertEqual(concurrency['queue'], 'max')
        for context, want in (({'github.event.issue.number': 42}, 'milestone-item-42'),
                              ({'github.event.pull_request.number': 7}, 'milestone-item-7'),
                              ({}, 'milestone-backfill')):
            with self.subTest(context=context):
                self.assertEqual(evaluate_expression(concurrency['group'], context), want)

    def test_the_docs_describe_it(self) -> None:
        text = DOC.read_text(encoding='utf-8')
        self.assertIn(':file:`milestone.yml`', text)
        self.assertIn('util/milestone.py', text)


class TestTheStep(unittest.TestCase):
    """The step's script picks the mode, and a dispatch is a dry run unless told otherwise."""

    def setUp(self) -> None:
        if os.name == 'nt' or shutil.which('bash') is None:  # pragma: no cover
            self.skipTest('the step is a bash script')
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-2218-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        (self.tmp / 'python3').write_text('#!/bin/sh\necho "$@"\n', encoding='utf-8')
        (self.tmp / 'python3').chmod(0o755)
        self.script = steps(WORKFLOW, JOB)[1]['run']

    def run_step(self, item: 'str', dry_run: 'str') -> 'str':
        env = {'PATH': f'{self.tmp}{os.pathsep}{os.environ.get("PATH", "")}', 'ITEM': item, 'DRY_RUN': dry_run}
        result = subprocess.run(bash_argv('-e', '-c', self.script), cwd=self.tmp, env=env,  # nosec B603 B607
                                capture_output=True, text=True, check=True, timeout=60)
        return result.stdout.strip()

    def test_modes(self) -> None:
        for item, dry_run, want in (('2218', '', 'util/milestone.py --item 2218'),
                                    ('', 'true', 'util/milestone.py --backfill --dry-run'),
                                    ('', '', 'util/milestone.py --backfill --dry-run'),
                                    ('', 'false', 'util/milestone.py --backfill')):
            with self.subTest(item=item, dry_run=dry_run):
                self.assertEqual(self.run_step(item, dry_run), want)


if __name__ == '__main__':
    unittest.main()
