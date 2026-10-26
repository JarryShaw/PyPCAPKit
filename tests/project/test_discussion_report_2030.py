# -*- coding: utf-8 -*-
"""#2030: :file:`util/discussion_report.py`, and the jobs that post a run's report with it.

* :class:`TestDiscussionReport` runs the script as the ``Post the report to
  Discussions`` step runs it, against a stand-in ``gh`` on ``PATH`` that answers
  the GraphQL calls from a scratch state file and logs each. Nothing reaches
  GitHub.
* :class:`TestTheModes` covers ``--mode``: ``scheduled`` posts every run;
  ``push`` posts a run that warned or failed, then one green run after it.
* :class:`TestTheFailuresWarn` covers every path that posts nothing for a fault:
  one ``::warning`` and exit 0, so reporting never fails a run.
* :class:`TestTheWorkflowsPost` pins the ``discussion`` job of
  :file:`ci-timing.yml` and :file:`cron-vendor.yml`: the only job holding
  ``discussions: write``, every other job's permissions as :data:`PERMISSIONS`
  records them, first-party actions only, the mode each event maps to, the
  script called on the artifact the reporting job uploads, and cron-vendor's
  job running on a failed gate but not on a deliberate skip.
* :class:`TestTheVendorPostStep` runs cron-vendor's post step with a stand-in
  ``python3``: the status it passes, and the report it writes for a failed gate.
* :class:`TestTheVendorReport` runs ``vendor-update``'s ``Write the run report``
  step in a scratch repository.

"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess  # nosec: B404
import sys
import tempfile
import textwrap
import unittest
from typing import TYPE_CHECKING

from tests._workflows import WORKFLOWS, load, pinned
from tests.project.test_release_gates import STATUS, job_blocks, job_runs

if TYPE_CHECKING:
    from typing import Any, Optional

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'util' / 'discussion_report.py'
BASH = shutil.which('bash')

CATEGORY = 'CI reports'
TITLE = 'ci-timing: weekly CI timing report'
REPO = 'JarryShaw/PyPCAPKit'
WARNING = '::warning title=CI report not posted::'
MARKER = re.compile(r'<!-- report-status: (\w+) -->')
STATUSES = ('success', 'warning', 'failure', 'cancelled', 'skipped')

#: The stand-in ``gh``: ``gh api graphql --input -`` only, answered from
#: ``$FAKE_GH_STATE`` and logged, one JSON line a call, to ``$FAKE_GH_LOG``.
FAKE_GH = textwrap.dedent('''\
    import json, os, sys

    state_path, log_path = os.environ['FAKE_GH_STATE'], os.environ['FAKE_GH_LOG']
    if sys.argv[1:] != ['api', 'graphql', '--input', '-']:
        sys.exit('unexpected arguments: %r' % (sys.argv[1:],))
    request = json.load(sys.stdin)
    query, variables = request['query'], request['variables']
    for op in ('createDiscussion', 'addDiscussionComment', 'discussionCategories', 'discussions(', 'node(id'):
        if op in query:
            break
    else:
        sys.exit('unexpected query')
    with open(state_path, encoding='utf-8') as file:
        state = json.load(file)
    with open(log_path, 'a', encoding='utf-8') as file:
        file.write(json.dumps({'op': op, 'variables': variables}) + '\\n')

    fail = state.get('fail') or {}
    if fail.get('op') in (op, '*'):
        if fail.get('kind') == 'garbage':
            print('<html>not json</html>')
            sys.exit(0)
        if fail.get('kind') == 'errors':
            print(json.dumps({'data': None, 'errors': [{'type': 'FORBIDDEN', 'message': fail['message']}]}))
            sys.exit(0)
        print(json.dumps({'errors': [{'type': 'FORBIDDEN', 'message': fail['message']}]}))
        print('gh: ' + fail['message'], file=sys.stderr)
        sys.exit(1)

    def save():
        with open(state_path, 'w', encoding='utf-8') as file:
            json.dump(state, file)

    if op == 'discussionCategories':
        data = {'repository': {'id': state['repo_id'], 'hasDiscussionsEnabled': state['enabled'],
                               'discussionCategories': {'nodes': state['categories']}}}
    elif op == 'discussions(':
        found = [d for d in state['discussions'] if d['category'] == variables['category']]
        page = state.get('page', 100)
        start = int(variables['after'] or 0)
        nodes = [{key: d[key] for key in ('id', 'number', 'title', 'url')} for d in found[start:start + page]]
        more = start + page < len(found)
        data = {'repository': {'discussions': {
            'pageInfo': {'hasNextPage': more, 'endCursor': str(start + page) if more else None},
            'nodes': nodes}}}
    elif op == 'node(id':
        found = [d for d in state['discussions'] if d['id'] == variables['id']]
        comments = found[0]['comments'][-variables['last']:] if found else []
        data = {'node': {'comments': {'nodes': [{'body': body, 'url': 'u'} for body in comments]}}}
    elif op == 'createDiscussion':
        number = len(state['discussions']) + 100
        node = {'id': 'D_%d' % number, 'number': number, 'title': variables['title'],
                'url': 'https://github.com/%s/discussions/%d' % (state['repo'], number),
                'category': variables['category'], 'repository': variables['repository'],
                'body': variables['body'], 'comments': []}
        state['discussions'].append(node)
        save()
        data = {'createDiscussion': {'discussion': {key: node[key] for key in ('id', 'number', 'url')}}}
    else:
        found = [d for d in state['discussions'] if d['id'] == variables['discussion']]
        if not found:
            print(json.dumps({'errors': [{'type': 'NOT_FOUND', 'message': 'no such discussion'}]}))
            sys.exit(1)
        found[0]['comments'].append(variables['body'])
        save()
        url = '%s#discussioncomment-%d' % (found[0]['url'], len(found[0]['comments']))
        data = {'addDiscussionComment': {'comment': {'url': url}}}
    print(json.dumps({'data': data}))
''')

#: A report as ci-timing's ``report.md`` might read.
REPORT = '## CI timing\n\n| Job | p90 |\n| --- | --- |\n| Python 3.14 | 12.1 min |\n'


class _FakeGitHub(unittest.TestCase):
    """A scratch directory holding a stand-in ``gh`` first on ``PATH``, its state and its log."""

    def setUp(self) -> None:
        if os.name == 'nt':  # pragma: no cover
            self.skipTest('the stand-in gh is a POSIX script')
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-2030-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        # A launcher, so the stand-in runs on this interpreter whatever is on PATH.
        (self.bin / 'gh.py').write_text(FAKE_GH, encoding='utf-8')
        launcher = self.bin / 'gh'
        launcher.write_text(f'#!/bin/sh\nexec \'{sys.executable}\' "$(dirname "$0")/gh.py" "$@"\n',
                            encoding='utf-8')
        launcher.chmod(0o755)
        self.state_path = self.tmp / 'state.json'
        self.log_path = self.tmp / 'gh.log'
        self.summary = self.tmp / 'summary.md'
        self.report = self.tmp / 'report.md'
        self.report.write_text(REPORT, encoding='utf-8')
        self.write_state({
            'repo': REPO, 'repo_id': 'R_repo', 'enabled': True,
            'categories': [{'id': 'DIC_general', 'name': 'General'}, {'id': 'DIC_reports', 'name': CATEGORY}],
            'discussions': [],
        })

    def write_state(self, state: 'dict[str, Any]') -> None:
        self.state_path.write_text(json.dumps(state), encoding='utf-8')

    @property
    def state(self) -> 'dict[str, Any]':
        return json.loads(self.state_path.read_text(encoding='utf-8'))

    def update(self, **changes: 'Any') -> None:
        state = self.state
        state.update(changes)
        self.write_state(state)

    def calls(self) -> 'list[str]':
        if not self.log_path.exists():
            return []
        return [json.loads(line)['op'] for line in self.log_path.read_text(encoding='utf-8').splitlines()]

    def env(self, **extra: 'str') -> 'dict[str, str]':
        env = {key: value for key, value in os.environ.items() if not key.startswith(('GITHUB_', 'GH_'))}
        env.update(PATH=f'{self.bin}{os.pathsep}{env.get("PATH", "")}', FAKE_GH_STATE=str(self.state_path),
                   FAKE_GH_LOG=str(self.log_path), GITHUB_REPOSITORY=REPO, GH_TOKEN='token',
                   GITHUB_SERVER_URL='https://github.com', GITHUB_RUN_ID='4242', GITHUB_WORKFLOW='CI Timing',
                   GITHUB_SHA='0' * 40, GITHUB_STEP_SUMMARY=str(self.summary), PYTHONIOENCODING='utf-8')
        env.update(extra)
        return env

    def script(self, *args: 'str', mode: 'str' = 'scheduled', status: 'str' = 'success', title: 'str' = TITLE,
               report: 'Optional[pathlib.Path]' = None,
               env: 'Optional[dict[str, str]]' = None) -> 'subprocess.CompletedProcess[str]':
        """``python3 util/discussion_report.py``, as the step runs it; :meth:`calls` then holds its calls alone."""
        if self.log_path.exists():
            self.log_path.unlink()
        argv = [sys.executable, str(SCRIPT), '--category', CATEGORY, '--title', title,
                '--report', str(report or self.report), '--mode', mode, '--status', status, *args]
        return subprocess.run(argv, cwd=self.tmp, env=self.env() if env is None else env,  # nosec: B603
                              capture_output=True, text=True, check=False, timeout=120)

    def thread(self, title: 'str' = TITLE) -> 'dict[str, Any]':
        found = [entry for entry in self.state['discussions'] if entry['title'] == title]
        self.assertEqual(len(found), 1, self.state['discussions'])
        return found[0]

    def statuses(self) -> 'list[list[str]]':
        """The status markers of each comment in the job's thread."""
        return [MARKER.findall(body) for body in self.thread()['comments']]

    def assert_posted_nothing(self, result: 'subprocess.CompletedProcess[str]') -> None:
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('createDiscussion', self.calls())
        self.assertNotIn('addDiscussionComment', self.calls())

    def assert_one_warning(self, result: 'subprocess.CompletedProcess[str]', *needles: 'str') -> None:
        self.assert_posted_nothing(result)
        warnings = [line for line in result.stdout.splitlines() if line.startswith('::warning')]
        self.assertEqual(len(warnings), 1, result.stdout)
        self.assertTrue(warnings[0].startswith(WARNING), warnings[0])
        for needle in needles:
            self.assertIn(needle, warnings[0])


class TestDiscussionReport(_FakeGitHub):
    """Open the thread once, then one comment per report posted."""

    def test_the_first_post_opens_the_thread_and_comments(self) -> None:
        result = self.script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('::warning', result.stdout)
        self.assertEqual(self.calls(), ['discussionCategories', 'discussions(', 'createDiscussion',
                                        'addDiscussionComment'])
        thread = self.thread()
        # The ids are the ones GraphQL answered with, not written down anywhere.
        self.assertEqual((thread['repository'], thread['category']), ('R_repo', 'DIC_reports'))
        self.assertIn('util/discussion_report.py', thread['body'])
        [comment] = thread['comments']
        self.assertEqual(comment, f'{REPORT.strip()}\n\n---\nPosted from [CI Timing run]'
                                  f'(https://github.com/JarryShaw/PyPCAPKit/actions/runs/4242) at commit '
                                  f'`{"0" * 40}`, which ended `success`.\n<!-- report-status: success -->')
        self.assertIn(thread['url'], self.summary.read_text(encoding='utf-8'))

    def test_another_runs_report_names_that_run(self) -> None:
        """A ``workflow_run`` relay posts a report from another run's artifact."""
        url = 'https://github.com/JarryShaw/PyPCAPKit/actions/runs/777'
        self.script('--run-url', url, '--sha', 'a' * 40, status='failure')
        [comment] = self.thread()['comments']
        self.assertIn(f'[CI Timing run]({url}) at commit `{"a" * 40}`, which ended `failure`.', comment)
        self.assertNotIn('4242', comment)
        self.assertNotIn('0' * 40, comment)

    def test_outside_actions_the_comment_still_names_the_status(self) -> None:
        env = {key: value for key, value in self.env().items()
               if key not in ('GITHUB_SERVER_URL', 'GITHUB_RUN_ID', 'GITHUB_SHA')}
        self.script(status='warning', env=env)
        [comment] = self.thread()['comments']
        self.assertEqual(comment, f'{REPORT.strip()}\n\n---\nThe run ended `warning`.\n'
                                  '<!-- report-status: warning -->')

    def test_the_thread_is_found_by_its_exact_title_in_the_category(self) -> None:
        """A thread of the same title elsewhere, or a near title here, is not the job's thread."""
        def thread(number: 'int', title: 'str', category: 'str') -> 'dict[str, Any]':
            return {'id': f'D_{number}', 'number': number, 'title': title, 'category': category,
                    'url': f'https://github.com/{REPO}/discussions/{number}', 'comments': []}
        self.update(discussions=[
            thread(1, TITLE, 'DIC_general'),
            thread(2, TITLE + ' (old)', 'DIC_reports'),
            thread(3, TITLE.upper(), 'DIC_reports'),
            thread(4, TITLE, 'DIC_reports'),
            thread(5, TITLE, 'DIC_reports'),
        ])
        result = self.script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('createDiscussion', self.calls())
        self.assertEqual([len(entry['comments']) for entry in self.state['discussions']], [0, 0, 0, 1, 0])

    def test_the_threads_are_read_page_by_page(self) -> None:
        self.update(page=2, discussions=[
            {'id': f'D_{number}', 'number': number, 'title': f'other {number}' if number != 5 else TITLE,
             'category': 'DIC_reports', 'url': f'https://github.com/{REPO}/discussions/{number}', 'comments': []}
            for number in range(1, 7)])
        result = self.script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.calls(), ['discussionCategories'] + ['discussions('] * 3 + ['addDiscussionComment'])
        self.assertEqual(len(self.thread()['comments']), 1)

    def test_a_long_report_is_cut_to_fit_and_keeps_its_marker(self) -> None:
        self.report.write_text('x' * 70000, encoding='utf-8')
        self.script(status='failure')
        [comment] = self.thread()['comments']
        self.assertEqual(len(comment), 65536)
        self.assertIn('cut short', comment)
        self.assertTrue(comment.endswith('\n<!-- report-status: failure -->'), comment[-200:])


class TestTheModes(_FakeGitHub):
    """``scheduled`` posts every run; ``push`` posts what warned or failed, and one green run after."""

    def test_a_scheduled_run_posts_every_time(self) -> None:
        """The same report and status twice is still two comments: no dedupe."""
        for status in ('success', 'success', 'failure', 'success'):
            self.assertEqual(self.script(status=status).returncode, 0)
            self.assertNotIn('node(id', self.calls())
        self.assertEqual(self.statuses(), [['success'], ['success'], ['failure'], ['success']])

    def test_a_first_green_push_run_posts_nothing(self) -> None:
        """No thread yet counts as green, so none is opened."""
        result = self.script(mode='push')
        self.assert_posted_nothing(result)
        self.assertNotIn('::warning', result.stdout)
        self.assertEqual(self.calls(), ['discussionCategories', 'discussions('])
        self.assertEqual(self.state['discussions'], [])

    def test_a_flagged_push_run_posts_every_time(self) -> None:
        for status in ('warning', 'failure', 'cancelled', 'skipped', 'failure'):
            with self.subTest(status=status):
                result = self.script(mode='push', status=status)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('addDiscussionComment', self.calls())
                self.assertNotIn('node(id', self.calls())
        self.assertEqual(self.statuses(), [['warning'], ['failure'], ['cancelled'], ['skipped'], ['failure']])

    def test_one_back_to_green_post_then_silence(self) -> None:
        sequence = (('success', False), ('failure', True), ('success', True), ('success', False),
                    ('warning', True), ('warning', True), ('success', True), ('success', False))
        for index, (status, posts) in enumerate(sequence):
            with self.subTest(index=index, status=status):
                result = self.script(mode='push', status=status)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn('::warning', result.stdout)
                self.assertEqual('addDiscussionComment' in self.calls(), posts, self.calls())
        self.assertEqual(self.statuses(), [['failure'], ['success'], ['warning'], ['warning'], ['success']])

    def test_a_green_push_run_reads_the_newest_marker_past_replies(self) -> None:
        """Replies carry no marker, and a scheduled post's marker counts like any other."""
        self.script(status='failure')
        state = self.state
        state['discussions'][0]['comments'].append('Looking into it.')
        self.write_state(state)
        self.script(mode='push')
        self.assertIn('addDiscussionComment', self.calls())
        state = self.state
        state['discussions'][0]['comments'].append('Fixed, thanks.')
        self.write_state(state)
        self.assert_posted_nothing(self.script(mode='push'))
        self.assertEqual(self.statuses(), [['failure'], [], ['success'], []])

    def test_a_marker_in_the_report_text_is_not_mistaken_for_the_last_one(self) -> None:
        """The footer's marker comes last, so a report quoting one does not decide the next run."""
        self.report.write_text(REPORT + '\n<!-- report-status: failure -->\n', encoding='utf-8')
        self.script(status='success')
        self.assert_posted_nothing(self.script(mode='push'))

    def test_only_the_newest_markers_are_read(self) -> None:
        """A failure further back than the comments read does not make a green run post."""
        self.script(status='failure')
        state = self.state
        state['discussions'][0]['comments'].extend(['a reply'] * 20)
        self.write_state(state)
        self.assert_posted_nothing(self.script(mode='push'))


class TestTheFailuresWarn(_FakeGitHub):
    """Whatever goes wrong, one ``::warning`` and exit 0."""

    def test_a_missing_category_warns_and_exits_0(self) -> None:
        self.update(categories=[{'id': 'DIC_general', 'name': 'General'}])
        result = self.script()
        self.assert_one_warning(result, f"no Discussions category named '{CATEGORY}'", REPO)
        self.assertEqual(self.calls(), ['discussionCategories'])

    def test_discussions_turned_off_warn(self) -> None:
        self.update(enabled=False)
        self.assert_one_warning(self.script(), 'Discussions turned off')

    def test_an_api_failure_warns_and_exits_0(self) -> None:
        message = 'Resource not accessible by integration'
        for op in ('discussionCategories', 'discussions(', 'createDiscussion', 'addDiscussionComment', 'node(id'):
            with self.subTest(op=op):
                state = self.state
                state['fail'] = {'op': op, 'message': message}
                # `node(id` is read only for a green push run with a thread.
                state['discussions'] = [] if op != 'node(id' else [
                    {'id': 'D_1', 'number': 1, 'title': TITLE, 'category': 'DIC_reports',
                     'url': f'https://github.com/{REPO}/discussions/1', 'comments': []}]
                self.write_state(state)
                result = self.script(mode='push' if op == 'node(id' else 'scheduled')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                warnings = [line for line in result.stdout.splitlines() if line.startswith('::warning')]
                self.assertEqual(len(warnings), 1, result.stdout)
                self.assertTrue(warnings[0].startswith(WARNING), warnings[0])
                self.assertIn(message, warnings[0])
                self.assertEqual(self.calls()[-1], op)
                self.assertTrue(all(not entry['comments'] for entry in self.state['discussions']))

    def test_errors_in_a_zero_exit_answer_warn(self) -> None:
        self.update(fail={'op': 'addDiscussionComment', 'kind': 'errors', 'message': 'was submitted too quickly'})
        result = self.script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(WARNING, result.stdout)
        self.assertIn('was submitted too quickly', result.stdout)

    def test_an_answer_that_is_not_json_warns(self) -> None:
        self.update(fail={'op': '*', 'kind': 'garbage', 'message': ''})
        self.assert_one_warning(self.script(), 'no JSON')

    def test_no_gh_warns(self) -> None:
        empty = self.tmp / 'empty'
        empty.mkdir()
        self.assert_one_warning(self.script(env=self.env(PATH=str(empty))), 'could not run gh')

    def test_a_missing_or_empty_report_warns_before_any_call(self) -> None:
        blank = self.tmp / 'blank.md'
        blank.write_text(' \n\n', encoding='utf-8')
        for report, needle in ((self.tmp / 'missing.md', 'could not be read'), (blank, 'is empty')):
            with self.subTest(report=report.name):
                self.assert_one_warning(self.script(report=report), needle, report.name)
                self.assertEqual(self.calls(), [])

    def test_a_missing_token_or_repository_warns_before_any_call(self) -> None:
        for key, value, needle in (('GH_TOKEN', '', 'GH_TOKEN'), ('GITHUB_REPOSITORY', '', 'GITHUB_REPOSITORY'),
                                   ('GITHUB_REPOSITORY', 'no-slash', 'GITHUB_REPOSITORY')):
            with self.subTest(key=key, value=value):
                env = self.env()
                env[key] = value
                self.assert_one_warning(self.script(env=env), needle)
                self.assertEqual(self.calls(), [])

    def test_a_bad_command_line_exits_2(self) -> None:
        """A missing or unknown mode or status."""
        base = [sys.executable, str(SCRIPT), '--category', CATEGORY, '--title', TITLE, '--report', str(self.report)]
        for args in ((), ('--mode', 'scheduled'), ('--status', 'success'), ('--mode', 'nightly', '--status', 'success'),
                     ('--mode', 'push', '--status', 'passed')):
            with self.subTest(args=args):
                if self.log_path.exists():
                    self.log_path.unlink()
                result = subprocess.run([*base, *args], cwd=self.tmp, env=self.env(),  # nosec: B603
                                        capture_output=True, text=True, check=False, timeout=60)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(self.calls(), [])


class TestTheWorkflowCommands(_FakeGitHub):
    """#2047: the whole of what the script prints and appends to the summary, byte for byte.

    The tests above read the warning with ``assertIn``; these pin each run's whole
    standard output and summary file, with text each escape changes, so any change
    to what is written fails here.

    """

    def test_a_post_prints_two_lines_and_appends_one(self) -> None:
        title = 'ci-timing: 50% [odd], title'
        self.summary.write_bytes(b'before\n')
        result = self.script(title=title)
        url = f'https://github.com/{REPO}/discussions/100'
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (0, f"Opened the thread {title!r}: {url}\nPosted the report: {url}#discussioncomment-1\n", ''))
        self.assertEqual(self.summary.read_bytes(),
                         f'before\nThe report was posted to [{title}]({url}#discussioncomment-1).\n'.encode())
        # A second post finds the thread, and appends a second line.
        result = self.script(title=title)
        self.assertEqual(result.stdout, f'Posted the report: {url}#discussioncomment-2\n')
        self.assertEqual(self.summary.read_bytes().count(b'\n'), 3)

    def test_no_summary_file_or_one_that_will_not_open(self) -> None:
        """Unset or empty, nothing is written; a directory, the post still succeeds, silently."""
        url = f'https://github.com/{REPO}/discussions/100'
        for name, value in (('unset', None), ('empty', ''), ('a directory', str(self.tmp))):
            with self.subTest(summary=name):
                self.update(discussions=[])
                env = self.env()
                if value is None:
                    del env['GITHUB_STEP_SUMMARY']
                else:
                    env['GITHUB_STEP_SUMMARY'] = value
                result = self.script(env=env)
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (0, f"Opened the thread {TITLE!r}: {url}\nPosted the report: {url}"
                                     '#discussioncomment-1\n', ''))
                self.assertFalse(self.summary.exists())

    def test_each_warning_is_one_escaped_line(self) -> None:
        """``%`` and LF in the message escape; the title, which holds neither ``:`` nor ``,``, is as written.

        The stand-in's standard error reaches the script through universal
        newlines, so a CR arrives as LF; the helper's own tests pin CR.

        """
        self.update(fail={'op': 'discussionCategories', 'message': 'a 50%\nb: c, d'})
        self.summary.write_bytes(b'before\n')
        result = self.script()
        self.assertEqual((result.returncode, result.stdout),
                         (0, '::warning title=CI report not posted::gh api graphql exited 1: gh: a 50%25%0Ab: '
                             'c, d. The report was not posted.\n'))
        self.assertEqual(self.summary.read_bytes(), b'before\n')
        missing = self.tmp / '50%.md'
        result = self.script(report=missing)
        self.assertEqual(result.stdout, f"::warning title=CI report not posted::the report '{self.tmp}/50%25.md' "
                                        'could not be read (No such file or directory), so nothing was posted.\n')


#: ``(workflow, reporting job, the thread's title, the artifact, the file in it)``.
POSTERS = (
    ('ci-timing.yml', 'report', 'ci-timing: weekly CI timing report', 'ci-timing-report', 'report.md'),
    ('cron-vendor.yml', 'vendor-update', 'cron-vendor: vendor constant update report', 'vendor-report',
     'vendor-report.md'),
)
#: Every job's own ``permissions:`` but ``discussion``'s, and the top-level block,
#: so that only ``discussion`` may write discussions (#2030); ``None`` for a job
#: with none of its own.
PERMISSIONS = {
    'ci-timing.yml': {None: {'actions': 'read', 'contents': 'read'}, 'report': None},
    'cron-vendor.yml': {None: {}, 'head': {'contents': 'read'}, 'vendor-update': {'contents': 'write'}},
}
POSTER = {'contents': 'read', 'discussions': 'write'}
FIRST_PARTY = ('actions/checkout', 'actions/download-artifact', 'actions/upload-artifact')
RUN = 'python3 util/discussion_report.py'
#: The ``--mode`` and ``--status`` each workflow passes, and the step's ``env:``
#: beside ``GH_TOKEN``.
ARGS = {
    'ci-timing.yml': ('--mode scheduled --status "$STATUS"', {'STATUS': '${{ needs.report.result }}'}),
    'cron-vendor.yml': ('--mode "$MODE" --status "$status"', {
        'MODE': "${{ github.event_name == 'workflow_run' && 'push' || 'scheduled' }}",
        'HEAD_RESULT': '${{ needs.head.result }}',
        'VENDOR_RESULT': '${{ needs.vendor-update.result }}',
        'VENDOR_STATUS': '${{ needs.vendor-update.outputs.status }}',
    }),
}
#: Each ``discussion`` job's ``needs:``.
NEEDS = {'ci-timing.yml': ['report'], 'cron-vendor.yml': ['head', 'vendor-update']}


def evaluate(expression: 'str', context: 'dict[str, Any]') -> 'str':
    """``expression``, a ``${{ a == 'b' && x || y }}`` of the shape ``MODE`` holds, under ``context``."""
    match = re.fullmatch(r"\$\{\{ ([\w.-]+) == '(\w+)' && ('?[\w.-]+'?) \|\| ('?[\w.-]+'?) \}\}", expression)
    assert match, expression  # nosec: B101

    def value(term: 'str') -> 'str':
        if term.startswith("'"):
            return term.strip("'")
        node = context  # type: Any
        for part in term.split('.'):
            node = node.get(part, '') if isinstance(node, dict) else ''
        return node

    left, right, then, otherwise = match.groups()
    chosen = value(then) if value(left) == right else ''
    return chosen or value(otherwise)


def post_step(name: 'str') -> 'dict[str, Any]':
    [post] = [entry for entry in load(name)['jobs']['discussion']['steps'] if RUN in entry.get('run', '')]
    return post


class TestTheWorkflowsPost(unittest.TestCase):
    """The ``discussion`` job of each workflow, and every other job's permissions per :data:`PERMISSIONS`."""

    def test_only_the_posting_job_may_write_discussions(self) -> None:
        for name, permissions in PERMISSIONS.items():
            spec = load(name)
            with self.subTest(workflow=name):
                self.assertEqual(spec['permissions'], permissions[None])
                self.assertEqual(sorted(spec['jobs']), sorted([*filter(None, permissions), 'discussion']))
                self.assertEqual(spec['jobs']['discussion']['permissions'], POSTER)
                for job_id, expected in permissions.items():
                    if job_id is None:
                        continue
                    with self.subTest(job=job_id):
                        self.assertEqual(spec['jobs'][job_id].get('permissions'), expected)
                        self.assertNotIn('discussions', str(spec['jobs'][job_id].get('permissions')))

    def test_the_posting_job_runs_first_party_actions_only(self) -> None:
        for name, *_ in POSTERS:
            for entry in load(name)['jobs']['discussion']['steps']:
                if 'uses' not in entry:
                    continue
                with self.subTest(workflow=name, step=entry.get('name') or entry['uses']):
                    self.assertTrue(any(pinned(entry['uses'], action) for action in FIRST_PARTY), entry['uses'])

    def test_each_workflow_posts_its_report_with_the_script(self) -> None:
        for name, reporter, title, artifact, file in POSTERS:
            spec = load(name)
            job = spec['jobs']['discussion']
            with self.subTest(workflow=name):
                self.assertEqual(spec['env'], {'REPORT_CATEGORY': CATEGORY})
                self.assertEqual(job['needs'], NEEDS[name])
                self.assertIn(f"needs.{reporter}.result != 'skipped'", job['if'])
                self.assertIs(job['continue-on-error'], True)
                self.assertTrue(title.startswith(name[:-len('.yml')] + ': '), title)

                [upload] = [entry for entry in spec['jobs'][reporter]['steps']
                            if pinned(entry.get('uses'), 'actions/upload-artifact')]
                self.assertEqual(upload['with']['name'], artifact)
                self.assertIn(file, upload['with']['path'])

                [download] = [entry for entry in job['steps'] if pinned(entry.get('uses'), 'actions/download-artifact')]
                self.assertEqual(download['with'], {'name': artifact, 'path': 'report'})
                self.assertIs(download['continue-on-error'], True)

                post = post_step(name)
                self.assertEqual(post['name'], 'Post the report to Discussions')
                self.assertIs(post['continue-on-error'], True)
                args, env = ARGS[name]
                self.assertEqual(post['env'], {'GH_TOKEN': '${{ github.token }}', **env})
                command = ' '.join(post['run'][post['run'].index(RUN):].replace('\\\n', ' ').split())
                self.assertEqual(command, f'{RUN} --category "$REPORT_CATEGORY" --title \'{title}\' '
                                          f'--report report/{file} {args}')

    def test_the_mode_follows_the_event(self) -> None:
        """ci-timing is always ``scheduled``; cron-vendor's ``workflow_run`` follows a push, so ``push``."""
        self.assertEqual(sorted(load('ci-timing.yml')['on']), ['schedule', 'workflow_dispatch'])
        # A manual run posts nothing; tests/project/test_build_only_dispatch.py pins it.
        self.assertEqual(sorted(load('cron-vendor.yml')['on']), ['schedule', 'workflow_dispatch', 'workflow_run'])
        expression = post_step('cron-vendor.yml')['env']['MODE']
        for event, mode in (('schedule', 'scheduled'), ('workflow_dispatch', 'scheduled'), ('workflow_run', 'push')):
            with self.subTest(event=event):
                self.assertEqual(evaluate(expression, {'github': {'event_name': event}}), mode)

    def test_vendor_update_hands_on_its_status(self) -> None:
        job = load('cron-vendor.yml')['jobs']['vendor-update']
        self.assertEqual(job['outputs'], {'status': '${{ steps.run-report.outputs.status }}'})

    def test_no_other_job_runs_the_script(self) -> None:
        for name, *_ in POSTERS:
            for job_id, job in load(name)['jobs'].items():
                if job_id == 'discussion':
                    continue
                with self.subTest(workflow=name, job=job_id):
                    self.assertNotIn('discussion_report', json.dumps(job))

    def test_the_timing_report_is_posted_however_its_job_ended(self) -> None:
        """``always()``, as the report's own upload: a HARD threshold fails the job on purpose."""
        job = load('ci-timing.yml')['jobs']['discussion']
        self.assertEqual(job['if'], "${{ always() && needs.report.result != 'skipped' }}")

    def test_the_vendor_report_runs_on_a_failed_gate_but_not_a_deliberate_skip(self) -> None:
        """A failed or cancelled gate skips ``vendor-update``, and is the run most worth posting.

        A skip on purpose -- a pull request's ``workflow_run``, or a verdict for
        another commit (#1748) -- skips this job too, so a run whose every job
        skipped still concludes ``skipped`` for Create Release.

        """
        jobs = job_blocks((WORKFLOWS / 'cron-vendor.yml').read_text(encoding='utf-8'))
        # `(event, head, vendor-update, whether discussion runs)`.
        rows = (
            ('schedule', 'success', 'success', True),
            ('schedule', 'success', 'failure', True),
            ('schedule', 'failure', 'skipped', True),
            ('schedule', 'cancelled', 'skipped', True),
            ('workflow_run', 'success', 'success', True),
            ('workflow_run', 'failure', 'skipped', True),
            ('workflow_run', 'success', 'skipped', False),
            ('workflow_run', 'skipped', 'skipped', False),
        )
        for event, head, vendor, expected in rows:
            context = {STATUS: {'cancelled': False}, 'github': {'event_name': event, 'event': {}}, 'needs': {
                'head': {'result': head}, 'vendor-update': {'result': vendor, 'outputs': {}}}}  # type: dict[str, Any]
            with self.subTest(event=event, head=head, vendor_update=vendor):
                self.assertEqual(job_runs(jobs, 'discussion', context), expected)

    def test_create_release_still_reads_vendor_update_alone(self) -> None:
        """It selects the job named ``vendor-update``, so no other job may carry that name."""
        spec = load('cron-vendor.yml')
        self.assertNotIn('name', spec['jobs']['vendor-update'])
        self.assertEqual([job.get('name', job_id) for job_id, job in spec['jobs'].items()].count('vendor-update'), 1)
        release = (WORKFLOWS / 'create-release.yml').read_text(encoding='utf-8')
        self.assertIn('select(.name == "vendor-update")', release)

    def test_the_vendor_report_steps_never_fail_the_job(self) -> None:
        spec = load('cron-vendor.yml')
        steps = {entry.get('name'): entry for entry in spec['jobs']['vendor-update']['steps']}
        for name in ('Write the run report', 'Upload the run report'):
            with self.subTest(step=name):
                self.assertEqual(steps[name]['if'], '${{ !cancelled() }}')
                self.assertIs(steps[name]['continue-on-error'], True)
        names = [entry.get('name') for entry in spec['jobs']['vendor-update']['steps']]
        self.assertEqual(names[-3:], ['Push changes', 'Write the run report', 'Upload the run report'])
        [download] = [entry for entry in spec['jobs']['discussion']['steps']
                      if pinned(entry.get('uses'), 'actions/download-artifact')]
        self.assertEqual(download['if'], "needs.vendor-update.result != 'skipped'")


#: A stand-in ``python3`` for the post step: it records its arguments and the report.
FAKE_PYTHON = textwrap.dedent('''\
    import json, os, sys
    args = sys.argv[1:]
    report = args[args.index('--report') + 1]
    with open(report, encoding='utf-8') as file:
        text = file.read()
    with open(os.environ['FAKE_PYTHON_LOG'], 'w', encoding='utf-8') as file:
        json.dump({'args': args, 'report': text}, file)
''')


@unittest.skipIf(not BASH, 'needs bash on PATH')
class TestTheVendorPostStep(unittest.TestCase):
    """cron-vendor's ``Post the report to Discussions``, run with a stand-in ``python3``."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-2030-post-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        (self.bin / 'fake_python.py').write_text(FAKE_PYTHON, encoding='utf-8')
        launcher = self.bin / 'python3'
        launcher.write_text(f'#!/bin/sh\nexec \'{sys.executable}\' "$(dirname "$0")/fake_python.py" "$@"\n',
                            encoding='utf-8')
        launcher.chmod(0o755)
        self.work = self.root / 'work'
        self.work.mkdir()
        self.log = self.root / 'python.json'
        self.script = self.root / 'step.sh'
        self.script.write_text(post_step('cron-vendor.yml')['run'], encoding='utf-8')

    def run_step(self, head: 'str', vendor: 'str', status: 'str' = '',
                 artifact: 'Optional[str]' = None) -> 'tuple[str, str]':
        """The ``--status`` the step passed, and the report it handed over."""
        if artifact is not None:
            (self.work / 'report').mkdir()
            (self.work / 'report' / 'vendor-report.md').write_text(artifact, encoding='utf-8')
        env = {'PATH': f'{self.bin}{os.pathsep}{os.environ.get("PATH", "")}', 'FAKE_PYTHON_LOG': str(self.log),
               'REPORT_CATEGORY': CATEGORY, 'MODE': 'scheduled', 'HEAD_RESULT': head, 'VENDOR_RESULT': vendor,
               'VENDOR_STATUS': status}
        result = subprocess.run([str(BASH), '-e', str(self.script)], cwd=self.work, env=env,  # nosec: B603
                                capture_output=True, text=True, check=False, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        logged = json.loads(self.log.read_text(encoding='utf-8'))
        args = logged['args']
        self.assertEqual(args[:9], ['util/discussion_report.py', '--category', CATEGORY, '--title',
                                    'cron-vendor: vendor constant update report', '--report',
                                    'report/vendor-report.md', '--mode', 'scheduled'])
        self.assertEqual(args[9], '--status')
        return args[10], logged['report']

    def test_a_failed_gate_posts_a_report_of_its_own(self) -> None:
        for head in ('failure', 'cancelled'):
            with self.subTest(head=head):
                shutil.rmtree(self.work / 'report', ignore_errors=True)
                self.assertEqual(self.run_step(head, 'skipped'), (head, (
                    '### Vendor Update\n\n'
                    f'- Gate: {head}, so vendor-update did not run and nothing was crawled or committed\n')))

    def test_a_vendor_update_that_ran_posts_its_artifact(self) -> None:
        for vendor, status, expected in (('success', 'success', 'success'), ('success', 'warning', 'warning'),
                                         ('success', '', 'success'), ('failure', 'warning', 'failure'),
                                         ('failure', '', 'failure'), ('cancelled', '', 'cancelled')):
            with self.subTest(vendor=vendor, status=status):
                shutil.rmtree(self.work / 'report', ignore_errors=True)
                self.assertEqual(self.run_step('success', vendor, status, artifact='the crawl\n'),
                                 (expected, 'the crawl\n'))


#: ``vendor-update``'s ``Write the run report`` step.
def vendor_report_step() -> 'dict[str, Any]':
    [step] = [entry for entry in load('cron-vendor.yml')['jobs']['vendor-update']['steps']
              if entry.get('name') == 'Write the run report']
    return step


@unittest.skipIf(not BASH or not shutil.which('git'), 'needs bash and git on PATH')
class TestTheVendorReport(unittest.TestCase):
    """The step's script, run as the runner runs it, in a scratch repository."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-2030-vendor-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.repo = self.root / 'repo'
        self.temp = self.root / 'runner-temp'
        self.temp.mkdir()
        home = self.root / 'home'
        home.mkdir()
        (home / '.gitconfig').write_text(
            '[init]\n\tdefaultBranch = main\n[commit]\n\tgpgsign = false\n'
            '[maintenance]\n\tauto = false\n\tautoDetach = false\n'
            '[gc]\n\tauto = 0\n\tautoDetach = false\n'
            '[user]\n\tname = Jarry Shaw\n\temail = jarryshaw@icloud.com\n', encoding='utf-8')
        self.output = self.root / 'output'
        self.env = {'PATH': os.environ.get('PATH', ''), 'HOME': str(home), 'GIT_CONFIG_NOSYSTEM': '1',
                    'RUNNER_TEMP': str(self.temp), 'GITHUB_OUTPUT': str(self.output)}
        for args in (('init', '-q', str(self.repo)), ('-C', str(self.repo), 'commit', '-q', '--allow-empty',
                                                      '-m', 'Bumped version to 1.5.0b14')):
            subprocess.run(['git', *args], env=self.env, check=True, capture_output=True, timeout=60)
        self.script = self.root / 'step.sh'
        self.script.write_text(vendor_report_step()['run'], encoding='utf-8')

    def report(self, stderr: 'str' = '', **env: 'str') -> 'tuple[str, str]':
        """The report, and the ``status`` the step wrote to ``GITHUB_OUTPUT``."""
        (self.temp / 'vendor-stderr.log').write_text(stderr, encoding='utf-8')
        self.output.write_text('', encoding='utf-8')
        result = subprocess.run([str(BASH), '-e', str(self.script)], cwd=self.repo,  # nosec: B603
                                env=dict(self.env, **env), capture_output=True, text=True, check=False,
                                timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        text = (self.temp / 'vendor-report.md').read_text(encoding='utf-8')
        self.assertEqual(result.stdout, text)
        lines = self.output.read_text(encoding='utf-8').splitlines()
        self.assertEqual(len(lines), 1, lines)
        key, _, status = lines[0].partition('=')
        self.assertEqual(key, 'status')
        return text, status

    def test_a_quiet_run(self) -> None:
        self.assertEqual(self.report(CRAWL_STATUS='0', TESTS='success', FILES_CHANGED='false', COMMITTED='false'),
                         ('### Vendor Update\n\n- Crawl: every target succeeded\n- Test gate: success\n'
                          '- Committed: nothing, as nothing changed\n', 'success'))

    def test_a_bump(self) -> None:
        text, status = self.report(CRAWL_STATUS='0', TESTS='success', FILES_CHANGED='true', COMMITTED='true')
        self.assertIn('- Committed: Bumped version to 1.5.0b14\n', text)
        self.assertEqual(status, 'success')

    def test_failed_targets_are_listed_and_warn(self) -> None:
        stderr = ('pcapkit.vendor.reg.ethertype failed: HTTPError(503)\n'
                  'VendorRuntimeWarning: ConnectionError(\'request failed: 503\')\n'
                  'pcapkit.vendor.ipv4.option_class failed: Timeout()\n')
        text, status = self.report(stderr, CRAWL_STATUS='1', TESTS='success', FILES_CHANGED='false',
                                   COMMITTED='false')
        self.assertIn('- Crawl: pcapkit-vendor exited 1; these targets failed and kept their modules:\n\n```\n'
                      'pcapkit.vendor.reg.ethertype failed: HTTPError(503)\n'
                      'pcapkit.vendor.ipv4.option_class failed: Timeout()\n```\n', text)
        self.assertEqual(status, 'warning')

    def test_an_unfinished_test_gate_warns(self) -> None:
        text, status = self.report(CRAWL_STATUS='0', TESTS='failure', FILES_CHANGED='false', COMMITTED='false')
        self.assertIn('- Test gate: failure\n', text)
        self.assertEqual(status, 'warning')

    def test_a_crawl_with_no_target_named(self) -> None:
        text, status = self.report('Traceback\n', CRAWL_STATUS='2', TESTS='', FILES_CHANGED='', COMMITTED='false')
        self.assertIn('(no target name could be read from stderr)', text)
        self.assertIn('- Test gate: not run\n', text)
        self.assertIn('- Committed: nothing, as the job stopped first\n', text)
        self.assertEqual(status, 'warning')

    def test_a_job_that_stopped_before_the_crawl(self) -> None:
        text, status = self.report(CRAWL_STATUS='', TESTS='', FILES_CHANGED='', COMMITTED='false')
        self.assertIn('- Crawl: did not finish\n', text)
        self.assertEqual(status, 'warning')


if __name__ == '__main__':
    unittest.main()
