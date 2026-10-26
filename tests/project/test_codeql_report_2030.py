# -*- coding: utf-8 -*-
"""#2030: CodeQL's ``discussion`` job, which posts the open code-scanning alerts to Discussions.

* :class:`TestTheJob` pins :file:`codeql-analysis.yml`: ``analyze`` with the
  permissions :data:`ANALYZE` records, ``discussion`` the one job holding
  ``security-events: read`` and ``discussions: write``, run after ``analyze`` on a
  push or the schedule and never on a pull request, the mode each event maps to,
  the thread's title, and the status the report step hands on.
* :class:`TestThePostStep` runs ``Post the report to Discussions`` with a
  stand-in ``python3``: the report step's status, or ``analyze``'s result where
  the step wrote none.
* :class:`TestTheReport` runs :file:`util/codeql_report.py` against a stand-in
  ``gh``: the request, every page read, the alerts by severity, the status each
  run gets, and a failed read that warns and leaves ``analyze``'s result.
* :class:`TestEndToEnd` runs both steps and both scripts over a sequence of runs,
  against the stand-in GitHub of :mod:`tests.project.test_discussion_report_2030`:
  every run with an open alert posts, then one run back at none.

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

from tests._support import bash_argv
from tests._workflows import WORKFLOWS, load, pinned
from tests.project.test_discussion_report_2030 import (BASH, CATEGORY, FAKE_PYTHON, MARKER, RUN, SCRIPT,
                                                       _FakeGitHub, evaluate)
from tests.project.test_release_gates import STATUS, job_blocks, job_runs
from tests.project.test_unit_tests_push_reports_2030 import write_launcher

if TYPE_CHECKING:
    from typing import Any, Optional

ROOT = pathlib.Path(__file__).resolve().parents[2]
REPORTER = ROOT / 'util' / 'codeql_report.py'
NAME = 'codeql-analysis.yml'
TITLE = 'codeql-analysis: CodeQL report'
REPORT = 'report/codeql-report.md'
POSTER = {'contents': 'read', 'discussions': 'write', 'security-events': 'read'}
ANALYZE = {'actions': 'read', 'contents': 'read', 'security-events': 'write'}
RESULTS = ('success', 'failure', 'cancelled', 'skipped')


def discussion() -> 'dict[str, Any]':
    return load(NAME)['jobs']['discussion']


def named(name: 'str') -> 'dict[str, Any]':
    [step] = [entry for entry in discussion()['steps'] if entry.get('name') == name]
    return step


def run_step(name: 'str', cwd: 'pathlib.Path', env: 'dict[str, str]') -> 'subprocess.CompletedProcess[str]':
    """Step ``name``'s ``run:`` as a bash step runs it."""
    script = cwd.parent / 'step.sh'
    script.write_text(named(name)['run'], encoding='utf-8')
    return subprocess.run(bash_argv('-eo', 'pipefail', str(script), executable=str(BASH)),  # nosec: B603
                          cwd=cwd, env=env, capture_output=True, text=True, check=False, timeout=120)


def alert(number: 'int', rule: 'str', level: 'str', security: 'str' = '', path: 'str' = 'pcapkit/a.py',
          line: 'int' = 1) -> 'dict[str, Any]':
    """An alert as the code-scanning endpoint answers it, with the fields the report reads."""
    return {'number': number, 'state': 'open', 'html_url': f'https://github.com/o/r/security/code-scanning/{number}',
            'rule': {'id': rule, 'severity': level, 'security_severity_level': security or None},
            'most_recent_instance': {'location': {'path': path, 'start_line': line}}}


#: A stand-in ``gh``: ``api --paginate`` answers ``$FAKE_ALERTS`` and logs its
#: arguments to ``$FAKE_ALERTS_LOG``; ``api graphql --input -`` goes to the
#: stand-in GitHub beside it, where there is one.
FAKE_GH = textwrap.dedent('''\
    import json, os, runpy, sys
    if '--input' in sys.argv:
        runpy.run_path(os.path.join(os.path.dirname(__file__), 'discussions.py'), run_name='__main__')
        sys.exit(0)
    with open(os.environ['FAKE_ALERTS_LOG'], 'a', encoding='utf-8') as file:
        file.write(json.dumps(sys.argv[1:]) + '\\n')
    answer = os.environ.get('FAKE_ALERTS')
    if not answer:
        print('gh: Resource not accessible by integration (HTTP 403)', file=sys.stderr)
        sys.exit(1)
    with open(answer, encoding='utf-8') as file:
        sys.stdout.write(file.read())
''')


class TestTheJob(unittest.TestCase):
    """``discussion`` beside ``analyze``, and ``analyze`` with its own permissions."""

    def test_only_the_posting_job_holds_its_scopes(self) -> None:
        spec = load(NAME)
        self.assertEqual(spec['permissions'], {})
        self.assertEqual(spec['env'], {'REPORT_CATEGORY': CATEGORY})
        self.assertEqual(sorted(spec['jobs']), ['analyze', 'discussion'])
        self.assertEqual(spec['jobs']['analyze']['permissions'], ANALYZE)
        self.assertEqual(discussion()['permissions'], POSTER)
        for path in sorted(WORKFLOWS.glob('*.yml')):
            for job_id, job in load(path.name)['jobs'].items():
                if job_id == 'discussion' and path.name == NAME:
                    continue
                with self.subTest(workflow=path.name, job=job_id):
                    self.assertNotEqual((job.get('permissions') or {}).get('security-events'), 'read')

    def test_the_job_never_fails_the_run(self) -> None:
        job = discussion()
        self.assertEqual(job['needs'], ['analyze'])
        self.assertIs(job['continue-on-error'], True)
        self.assertNotIn('environment', job)
        for entry in job['steps']:
            with self.subTest(step=entry.get('name') or entry.get('uses')):
                if 'uses' in entry:
                    self.assertTrue(pinned(entry['uses'], 'actions/checkout'), entry['uses'])
                    self.assertIs(entry['with']['persist-credentials'], False)
                else:
                    self.assertIs(entry['continue-on-error'], True)

    def test_it_runs_after_a_push_or_the_schedule_but_never_a_pull_request(self) -> None:
        self.assertEqual(sorted(load(NAME)['on']), ['pull_request', 'push', 'schedule'])
        jobs = job_blocks((WORKFLOWS / NAME).read_text(encoding='utf-8'))
        for event in ('push', 'schedule', 'pull_request'):
            for result in RESULTS:
                context = {STATUS: {'cancelled': result == 'cancelled'}, 'github': {'event_name': event},
                           'needs': {'analyze': {'result': result, 'outputs': {}}}}  # type: dict[str, Any]
                with self.subTest(event=event, analyze=result):
                    self.assertEqual(job_runs(jobs, 'discussion', context),
                                     event != 'pull_request' and result != 'skipped')

    def test_the_mode_follows_the_event(self) -> None:
        expression = named('Post the report to Discussions')['env']['MODE']
        for event, mode in (('schedule', 'scheduled'), ('push', 'push')):
            with self.subTest(event=event):
                self.assertEqual(evaluate(expression, {'github': {'event_name': event}}), mode)

    def test_the_report_and_the_post(self) -> None:
        report = named('Write the report')
        self.assertEqual(report['id'], 'report')
        self.assertEqual(report['env'], {'GH_TOKEN': '${{ github.token }}',
                                         'ANALYZE_RESULT': '${{ needs.analyze.result }}'})
        self.assertEqual(report['run'].strip(),
                         f'python3 util/codeql_report.py --result "$ANALYZE_RESULT" --report {REPORT}')
        post = named('Post the report to Discussions')
        self.assertEqual(post['env'], {
            'GH_TOKEN': '${{ github.token }}',
            'MODE': "${{ github.event_name == 'schedule' && 'scheduled' || 'push' }}",
            'ANALYZE_RESULT': '${{ needs.analyze.result }}',
            'REPORT_STATUS': '${{ steps.report.outputs.status }}',
        })
        self.assertIn('status="${REPORT_STATUS:-$ANALYZE_RESULT}"', post['run'])
        command = ' '.join(post['run'][post['run'].index(RUN):].replace('\\\n', ' ').split())
        self.assertEqual(command, f'{RUN} --category "$REPORT_CATEGORY" --title \'{TITLE}\' --report {REPORT} '
                                  '--mode "$MODE" --status "$status"')
        self.assertTrue(TITLE.startswith(NAME[:-len('.yml')] + ': '))

    def test_no_other_job_runs_either_script(self) -> None:
        for job_id, job in load(NAME)['jobs'].items():
            if job_id != 'discussion':
                with self.subTest(job=job_id):
                    self.assertNotIn('discussion_report', json.dumps(job))
                    self.assertNotIn('codeql_report', json.dumps(job))


@unittest.skipIf(not BASH or os.name == 'nt', 'needs bash and a POSIX shell')
class TestThePostStep(unittest.TestCase):
    """``Post the report to Discussions``, with a stand-in ``python3``."""

    def post(self, status: 'str', mode: 'str' = 'push', result: 'str' = 'success') -> 'list[str]':
        with tempfile.TemporaryDirectory(prefix='pcapkit-2030-codeql-post-') as tmp:
            root = pathlib.Path(tmp)
            (root / 'bin').mkdir()
            (root / 'work' / 'report').mkdir(parents=True)
            (root / 'work' / REPORT).write_text('### CodeQL\n', encoding='utf-8')
            write_launcher(root / 'bin', 'python3', FAKE_PYTHON)
            env = {'PATH': f'{root / "bin"}{os.pathsep}{os.environ.get("PATH", "")}',
                   'FAKE_PYTHON_LOG': str(root / 'log.json'), 'REPORT_CATEGORY': CATEGORY,
                   'MODE': mode, 'ANALYZE_RESULT': result, 'REPORT_STATUS': status}
            done = run_step('Post the report to Discussions', root / 'work', env)
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            return json.loads((root / 'log.json').read_text(encoding='utf-8'))['args']

    def test_the_report_steps_status_is_passed_on(self) -> None:
        self.assertEqual(self.post('warning', mode='scheduled'), [
            'util/discussion_report.py', '--category', CATEGORY, '--title', TITLE, '--report', REPORT,
            '--mode', 'scheduled', '--status', 'warning'])

    def test_no_status_leaves_analyzes_result(self) -> None:
        self.assertEqual(self.post('', result='failure'), [
            'util/discussion_report.py', '--category', CATEGORY, '--title', TITLE, '--report', REPORT,
            '--mode', 'push', '--status', 'failure'])


@unittest.skipIf(not BASH or os.name == 'nt', 'needs bash and a POSIX shell')
class TestTheReport(unittest.TestCase):
    """:file:`util/codeql_report.py`, against a stand-in ``gh``."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-2030-codeql-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        (self.root / 'bin').mkdir()
        write_launcher(self.root / 'bin', 'gh', FAKE_GH)
        self.answer = self.root / 'alerts.json'
        self.log = self.root / 'gh.log'
        self.output = self.root / 'output'
        self.report = self.root / 'report' / 'codeql-report.md'

    def run_report(self, answer: 'Any' = None, raw: 'str' = '', result: 'str' = 'success',
                   **extra: 'str') -> 'tuple[subprocess.CompletedProcess[str], str, str]':
        env = {key: value for key, value in os.environ.items() if not key.startswith(('GITHUB_', 'GH_'))}
        env.update(PATH=f'{self.root / "bin"}{os.pathsep}{env.get("PATH", "")}', GITHUB_REPOSITORY='o/r',
                   GH_TOKEN='token', GITHUB_OUTPUT=str(self.output), FAKE_ALERTS_LOG=str(self.log))
        if answer is not None or raw:
            self.answer.write_text(raw or json.dumps(answer), encoding='utf-8')
            env['FAKE_ALERTS'] = str(self.answer)
        env.update(extra)
        self.output.write_text('', encoding='utf-8')
        done = subprocess.run([sys.executable, str(REPORTER), '--result', result,  # nosec: B603
                               '--report', str(self.report)],
                              env=env, capture_output=True, text=True, check=False, timeout=60)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        return done, self.report.read_text(encoding='utf-8'), self.output.read_text(encoding='utf-8')

    def test_the_request(self) -> None:
        self.run_report([])
        [args] = [json.loads(line) for line in self.log.read_text(encoding='utf-8').splitlines()]
        self.assertEqual(args, ['api', '--paginate', '--method', 'GET', 'repos/o/r/code-scanning/alerts',
                                '-f', 'state=open', '-f', 'tool_name=CodeQL', '-F', 'per_page=100'])

    def test_no_alert_is_a_success(self) -> None:
        done, report, output = self.run_report([])
        self.assertEqual(output, 'status=success\n')
        self.assertIn('- Open code-scanning alerts: 0', report)
        self.assertIn('No code-scanning alert is open.', report)
        self.assertNotIn('::warning', done.stdout)

    def test_an_open_alert_makes_a_success_a_warning(self) -> None:
        for alerts in ([alert(1, 'py/a', 'note')], [alert(1, 'py/a', 'error', 'high'), alert(2, 'py/b', 'note')]):
            with self.subTest(alerts=len(alerts)):
                done, _, output = self.run_report(alerts)
                self.assertEqual(output, 'status=warning\n')
                self.assertNotIn('::warning', done.stdout)

    def test_analyzes_own_result_stands(self) -> None:
        for result in ('failure', 'cancelled'):
            for alerts in ([], [alert(1, 'py/a', 'error')]):
                with self.subTest(result=result, alerts=len(alerts)):
                    _, report, output = self.run_report(alerts, result=result)
                    self.assertEqual(output, f'status={result}\n')
                    self.assertIn(f'- Analysis: `{result}`', report)
                    self.assertIn(f'- Open code-scanning alerts: {len(alerts)}', report)

    def test_every_page_is_read_and_filed_by_severity(self) -> None:
        """``--paginate`` writes one array a page; a security severity wins over the rule's own."""
        pages = [[alert(3, 'py/clear-text-logging', 'error', 'high', 'pcapkit/b.py', 7),
                  alert(9, 'py/unused-import', 'note')],
                 [alert(4, 'py/path-injection', 'error', 'high'), alert(5, 'py/empty-except', 'warning'),
                  alert(6, 'py/weak-hash', 'warning', 'critical')]]
        _, report, output = self.run_report(raw=''.join(json.dumps(page) for page in pages))
        self.assertEqual(output, 'status=warning\n')
        self.assertIn('- Analysis: `success`\n- Open code-scanning alerts: 5', report)
        table = [line for line in report.splitlines() if line.startswith('| ')][2:]
        self.assertEqual(table, ['| critical | 1 |', '| high | 2 |', '| warning | 1 |', '| note | 1 |'])
        listed = [line for line in report.splitlines() if line.startswith('- [#')]
        self.assertEqual([re.match(r'- \[#(\d+)\]', line).group(1) for line in listed],  # type: ignore[union-attr]
                         ['6', '3', '4', '5', '9'])
        self.assertIn('- [#3](https://github.com/o/r/security/code-scanning/3) `py/clear-text-logging` at '
                      '`pcapkit/b.py:7` (high)', listed)

    def test_one_array_of_them_all_reads_the_same(self) -> None:
        _, report, _ = self.run_report([alert(1, 'py/a', 'error'), alert(2, 'py/b', 'note')])
        self.assertIn('- Open code-scanning alerts: 2', report)

    def test_a_failed_read_warns_and_leaves_analyzes_result(self) -> None:
        """Nothing shows that no alert is open, so a failed read fabricates no ``success``."""
        for kind, kwargs in (('forbidden', {}), ('not json', {'raw': '<html>'}),
                             ('not a list', {'answer': {'message': 'no analysis found'}}),
                             ('no repository', {'answer': [], 'GITHUB_REPOSITORY': ''})):
            for result in ('success', 'failure'):
                with self.subTest(kind=kind, result=result):
                    done, report, output = self.run_report(result=result, **kwargs)
                    warnings = [line for line in done.stdout.splitlines() if line.startswith('::warning')]
                    self.assertEqual(len(warnings), 1, done.stdout)
                    self.assertTrue(warnings[0].startswith('::warning title=CodeQL alerts not read::'), warnings[0])
                    self.assertEqual(output, f'status={result}\n')
                    self.assertIn('- Open code-scanning alerts: unavailable', report)
                    self.assertIn('could not be read', report)


@unittest.skipIf(not BASH or os.name == 'nt', 'needs bash and a POSIX shell')
class TestEndToEnd(_FakeGitHub):
    """Both steps and both scripts: push runs and the weekly report."""

    def setUp(self) -> None:
        super().setUp()
        (self.bin / 'gh.py').rename(self.bin / 'discussions.py')
        write_launcher(self.bin, 'gh', FAKE_GH)
        (self.bin / 'python3').symlink_to(sys.executable)
        self.work = self.tmp / 'work'
        (self.work / 'util').mkdir(parents=True)
        for script in (SCRIPT, REPORTER, ROOT / 'util' / '_actions.py'):
            shutil.copy(script, self.work / 'util')
        self.answer = self.tmp / 'alerts.json'

    def run_once(self, event: 'str', result: 'str', alerts: 'Optional[int]') -> 'bool':
        """One run's two steps, ``alerts`` open or :data:`None` for a failed read; whether it posted."""
        output = self.tmp / 'output'
        output.write_text('', encoding='utf-8')
        env = self.env(FAKE_ALERTS_LOG=str(self.tmp / 'alerts.log'), GITHUB_OUTPUT=str(output),
                       GITHUB_WORKFLOW='CodeQL', REPORT_CATEGORY=CATEGORY, ANALYZE_RESULT=result,
                       MODE=evaluate(named('Post the report to Discussions')['env']['MODE'],
                                     {'github': {'event_name': event}}))
        if alerts is not None:
            self.answer.write_text(json.dumps([alert(number, 'py/x', 'warning') for number in range(alerts)]),
                                   encoding='utf-8')
            env['FAKE_ALERTS'] = str(self.answer)
        step = run_step('Write the report', self.work, env)
        self.assertEqual(step.returncode, 0, step.stdout + step.stderr)
        [status] = [line.partition('=')[2] for line in output.read_text(encoding='utf-8').splitlines()
                    if line.startswith('status=')]
        posted = len(self.state['discussions'][0]['comments']) if self.state['discussions'] else 0
        step = run_step('Post the report to Discussions', self.work, dict(env, REPORT_STATUS=status))
        self.assertEqual(step.returncode, 0, step.stdout + step.stderr)
        self.assertNotIn('::warning', step.stdout)
        return (len(self.state['discussions'][0]['comments']) if self.state['discussions'] else 0) > posted

    def test_a_week_of_runs(self) -> None:
        # (event, analyze's result, open alerts or None for a failed read, posts, the marker posted)
        sequence = (('push', 'success', 0, False, None),
                    ('schedule', 'success', 2, True, 'warning'),
                    ('push', 'success', 2, True, 'warning'),
                    ('push', 'success', 1, True, 'warning'),
                    ('push', 'success', 0, True, 'success'),
                    ('push', 'success', 0, False, None),
                    ('push', 'failure', 0, True, 'failure'),
                    ('push', 'success', 0, True, 'success'),
                    # A failed read keeps analyze's `success`, so a green thread stays quiet.
                    ('push', 'success', None, False, None),
                    ('schedule', 'success', 0, True, 'success'))
        for index, (event, result, alerts, posts, marker) in enumerate(sequence):
            with self.subTest(index=index, event=event, result=result, alerts=alerts):
                self.assertEqual(self.run_once(event, result, alerts), posts)
                if posts:
                    comment = self.thread(TITLE)['comments'][-1]
                    self.assertEqual(MARKER.findall(comment), [marker])
                    self.assertIn(f'- Open code-scanning alerts: {alerts}', comment)


if __name__ == '__main__':
    unittest.main()
