# -*- coding: utf-8 -*-
"""#2030: Coverage Comment's ``discussion`` job, which posts a Unit Tests push run to Discussions.

``unit-tests.yml`` is a reusable workflow whose callers grant ``contents: read``,
so a Unit Tests run on a push reaches its thread through
:file:`coverage-comment.yml`'s ``workflow_run`` relay, as a pull request's
coverage reaches its comment.

* :class:`TestTheJobs` pins the layout: ``comment`` keeps the pull-request path,
  its ``if:`` and its scopes; ``discussion`` takes push runs alone and is the one
  job holding ``discussions: write``; a push run's concurrency group is its own;
  and the checkout is the default branch's script, never the run's head.
* :class:`TestTheReportStep` runs ``Write the run report`` with a stand-in
  ``gh``: the conclusion each status maps from, ``warning`` for a green run
  whose non-blocking legs warned or failed, the pinned list of annotations main's
  KTLO legs write by design, which leave it ``success``, and the report it writes.
* :class:`TestThePostStep` runs ``Post the report to Discussions`` with a
  stand-in ``python3``, and :class:`TestEndToEnd` runs both steps and the real
  :file:`util/discussion_report.py` against the stand-in GitHub of
  :mod:`tests.project.test_discussion_report_2030`.

"""

from __future__ import annotations

import ast
import json
import os
import pathlib
import shutil
import subprocess  # nosec: B404
import sys
import tempfile
import textwrap
import unittest
from typing import TYPE_CHECKING

from tests._workflows import WORKFLOWS, load, pinned
from tests.project.test_discussion_report_2030 import (CATEGORY, MARKER,
                                                       _FakeGitHub)
from tests.project.test_release_gates import job_blocks, job_runs

if TYPE_CHECKING:
    from typing import Any, Optional

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'util' / 'discussion_report.py'
BASH = shutil.which('bash')
NAME = 'coverage-comment.yml'

TITLE = 'unit-tests: main push runs'
REPORT = 'report/unit-tests-report.md'
RUN_URL = 'https://github.com/JarryShaw/PyPCAPKit/actions/runs/39718608950'
SHA = 'da8596414e3e6a53f43b20b85c86755cc2ed6686'
SUITE = 'CS_kwDOBotKYc8AAAAZD_cS-g'
POSTER = {'checks': 'read', 'contents': 'read', 'discussions': 'write'}
#: The pull-request comment's condition and scopes, as before #2030.
COMMENT_IF = ("${{ github.event.workflow_run.event == 'pull_request' && "
              "github.event.workflow_run.conclusion != 'cancelled' }}")
COMMENT_SCOPES = {'actions': 'read', 'pull-requests': 'write'}
#: GitHub's run conclusions, and the ``--status`` each posts as.
CONCLUSIONS = {
    'success': 'success', 'failure': 'failure', 'cancelled': 'cancelled', 'skipped': 'skipped',
    'timed_out': 'failure', 'startup_failure': 'failure', 'action_required': 'failure',
    'neutral': 'skipped', 'stale': 'cancelled', '': 'failure',
}
RUN = 'python3 util/discussion_report.py'


def discussion() -> 'dict[str, Any]':
    return load(NAME)['jobs']['discussion']


def named(name: 'str') -> 'dict[str, Any]':
    [step] = [entry for entry in discussion()['steps'] if entry.get('name') == name]
    return step


def check_runs(*runs: 'tuple[str, str, list[tuple[str, ...]]]', more: 'bool' = False) -> 'dict[str, Any]':
    """The check-suite answer: ``(name, conclusion, [(level, title[, message])])`` per job."""
    return {'data': {'node': {'checkRuns': {'pageInfo': {'hasNextPage': more}, 'nodes': [
        {'name': name, 'conclusion': conclusion, 'annotations': {'nodes': [
            {'annotationLevel': note[0], 'title': note[1],
             'message': note[2] if len(note) > 2 else 'Process completed with exit code 1.'}
            for note in notes]}}
        for name, conclusion, notes in runs]}}}}


#: A job with the runner's notice alone.
GREEN = ('Python 3.14', 'SUCCESS', [('NOTICE', 'The ubuntu-latest label will migrate')])
#: A KTLO leg whose tests failed, which ``KTLO summary`` reports as a warning (#1672).
KTLO = ('Python 3.8 (KTLO)', 'SUCCESS', [('WARNING', 'tests failed on Python 3.8 (KTLO, non-blocking)'),
                                         ('FAILURE', '')])

#: The annotations main's run writes by design, as the step's ``EXPECTED`` lists them:
#: none since #2051 dropped the 3.7 legs and #2040's cap let pypy3.10 install.
BY_DESIGN = {}  # type: dict[str, tuple[tuple[str, str], ...]]
#: The list as it stood for pypy3.10's install failure, before #2040, which the
#: tests of the matching itself install in place of :data:`BY_DESIGN`.
LISTED = {
    job: (('WARNING', f'install failed on {leg} (KTLO, non-blocking)'), ('FAILURE', ''),
          ('WARNING', f'pcapkit did not install on {leg} (KTLO, non-blocking)'))
    for job, leg in (('Python pypy3.10 (KTLO)', 'Python pypy3.10'),)
}
#: Unit Tests run 39718608950's jobs with any annotation but a notice, as the
#: check-suite query returned them on 2026-10-22, and one job with a notice alone.
#: Its 3.7 legs are left out: #2051 dropped them, and their entries in
#: ``EXPECTED`` with them.
REAL_KTLO = "KTLO legs never block (#1633), so this job still succeeds (#1672); see the install step's log."
REAL_RUN = (
    ('Python pypy3.10 (KTLO)', 'SUCCESS', [
        ('WARNING', 'install failed on Python pypy3.10 (KTLO, non-blocking)', REAL_KTLO),
        ('FAILURE', '', 'Process completed with exit code 1.'),
        ('WARNING', 'pcapkit did not install on Python pypy3.10 (KTLO, non-blocking)',
         "pip failed without an ERROR line; see this step's log. The rest of this leg is skipped."),
        ('NOTICE', '', '"The ubuntu-latest label will migrate to Ubuntu 26 beginning October 19, 2026. For more '
                       'information, see https://github.com/actions/runner-images/issues/14748"')]),
    GREEN,
)

#: A stand-in ``gh`` for the check-suite query, logging its arguments; ``api
#: graphql --input -``, the script's own calls, goes to the stand-in GitHub.
FAKE_GH = textwrap.dedent('''\
    import json, os, runpy, sys
    if '--input' in sys.argv:
        runpy.run_path(os.path.join(os.path.dirname(__file__), 'discussions.py'), run_name='__main__')
        sys.exit(0)
    with open(os.environ['FAKE_SUITE_LOG'], 'a', encoding='utf-8') as file:
        file.write(json.dumps(sys.argv[1:]) + '\\n')
    answer = os.environ.get('FAKE_SUITE_ANSWER')
    if not answer:
        print('gh: HTTP 403', file=sys.stderr)
        sys.exit(1)
    with open(answer, encoding='utf-8') as file:
        sys.stdout.write(file.read())
''')


class TestTheJobs(unittest.TestCase):
    """The relay's two jobs, and what each may do."""

    def test_the_pull_request_comment_is_as_it_was(self) -> None:
        spec = load(NAME)
        self.assertEqual(sorted(spec['jobs']), ['comment', 'discussion'])
        comment = spec['jobs']['comment']
        self.assertEqual(comment['if'], COMMENT_IF)
        self.assertEqual(comment['permissions'], COMMENT_SCOPES)
        self.assertEqual(spec['permissions'], {})
        self.assertNotIn('discussion_report', json.dumps(comment))

    def test_each_job_takes_its_own_events(self) -> None:
        """``comment`` a pull request's run that was not cancelled; ``discussion`` every push run."""
        jobs = job_blocks((WORKFLOWS / NAME).read_text(encoding='utf-8'))
        for event in ('push', 'pull_request', 'merge_group', 'schedule'):
            for conclusion in CONCLUSIONS:
                context = {'github': {'event': {'workflow_run': {'event': event, 'conclusion': conclusion}}}}
                with self.subTest(event=event, conclusion=conclusion):
                    self.assertEqual(job_runs(jobs, 'discussion', context), event == 'push')
                    self.assertEqual(job_runs(jobs, 'comment', context),
                                     event == 'pull_request' and conclusion != 'cancelled')

    def test_only_the_posting_job_may_write_discussions(self) -> None:
        self.assertEqual(discussion()['permissions'], POSTER)
        for path in sorted(WORKFLOWS.glob('*.yml')):
            spec = load(path.name)
            with self.subTest(workflow=path.name):
                self.assertNotIn('discussions', str(spec.get('permissions')))
                for job_id, job in spec['jobs'].items():
                    if 'discussions' in str(job.get('permissions')):
                        self.assertEqual(job_id, 'discussion')
                        self.assertIn(RUN, json.dumps(job))

    def test_a_push_runs_group_is_its_own(self) -> None:
        """A pull request's group is the one it was; a pending push relay is never cancelled by the next."""
        group = ' '.join(load(NAME)['concurrency']['group'].split())
        run = 'github.event.workflow_run'
        self.assertEqual(group, (
            f"coverage-comment-${{{{ {run}.event == 'pull_request' && "
            f"format('{{0}}-{{1}}', {run}.head_repository.full_name, {run}.head_branch) || {run}.id }}}}"))
        self.assertIs(load(NAME)['concurrency']['cancel-in-progress'], False)

    def test_it_posts_with_the_script_in_push_mode(self) -> None:
        job = discussion()
        self.assertEqual(load(NAME)['env'], {'REPORT_CATEGORY': CATEGORY})
        self.assertIs(job['continue-on-error'], True)
        for name in ('Write the run report', 'Post the report to Discussions'):
            with self.subTest(step=name):
                self.assertIs(named(name)['continue-on-error'], True)
        post = named('Post the report to Discussions')
        command = ' '.join(post['run'].replace('\\\n', ' ').split())
        self.assertEqual(command, (
            f"GITHUB_WORKFLOW='Unit Tests' {RUN} --category \"$REPORT_CATEGORY\" --title \"$TITLE\" "
            f'--report {REPORT} --mode push --status "$STATUS" --run-url "$RUN_URL" --sha "$HEAD_SHA"'))
        run = 'github.event.workflow_run'
        self.assertEqual(post['env'], {
            'GH_TOKEN': '${{ github.token }}', 'TITLE': '${{ steps.report.outputs.title }}',
            'STATUS': '${{ steps.report.outputs.status }}', 'RUN_URL': f'${{{{ {run}.html_url }}}}',
            'HEAD_SHA': f'${{{{ {run}.head_sha }}}}'})
        self.assertEqual(named('Write the run report')['id'], 'report')

    def test_it_never_checks_out_the_runs_head(self) -> None:
        """The default branch's script alone, as ``workflow_run`` checks out; the head is data in ``env:``."""
        uses = [entry for entry in discussion()['steps'] if 'uses' in entry]
        self.assertEqual(len(uses), 1)
        self.assertTrue(pinned(uses[0]['uses'], 'actions/checkout'), uses[0]['uses'])
        self.assertEqual(uses[0]['with'], {'sparse-checkout': 'util/discussion_report.py\n',
                                           'sparse-checkout-cone-mode': False, 'persist-credentials': False})
        for entry in discussion()['steps']:
            outside = {key: value for key, value in entry.items() if key != 'env'}
            with self.subTest(step=entry.get('name') or entry['uses']):
                self.assertNotIn('workflow_run.head', json.dumps(outside))
                self.assertNotIn('${{', entry.get('run', ''))


def write_launcher(directory: 'pathlib.Path', name: 'str', script: 'str') -> None:
    """``directory/name``, running ``script`` (beside it) on this interpreter."""
    (directory / f'{name}.py').write_text(script, encoding='utf-8')
    launcher = directory / name
    launcher.write_text(f'#!/bin/sh\nexec \'{sys.executable}\' "$(dirname "$0")/{name}.py" "$@"\n',
                        encoding='utf-8')
    launcher.chmod(0o755)


def run_step(name: 'str', cwd: 'pathlib.Path', env: 'dict[str, str]',
             expected: 'Optional[dict[str, Any]]' = None) -> 'subprocess.CompletedProcess[str]':
    """Step ``name``'s ``run:`` as a bash step runs it, with ``EXPECTED`` replaced by ``expected`` if given."""
    script = cwd.parent / 'step.sh'
    source = named(name)['run']
    if expected is not None:
        assert source.count('\nEXPECTED = {}\n') == 1, 'the step no longer reads EXPECTED = {}'
        source = source.replace('\nEXPECTED = {}\n', f'\nEXPECTED = {expected!r}\n')
    script.write_text(source, encoding='utf-8')
    return subprocess.run([str(BASH), '--noprofile', '--norc', '-eo', 'pipefail', str(script)],  # nosec: B603
                          cwd=cwd, env=env, capture_output=True, text=True, check=False, timeout=120)


@unittest.skipIf(not BASH or os.name == 'nt', 'needs bash and a POSIX shell')
class TestTheReportStep(unittest.TestCase):
    """``Write the run report``, against a stand-in ``gh`` answering the check-suite query."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-2030-push-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        write_launcher(self.bin, 'gh', FAKE_GH)
        (self.bin / 'python3').symlink_to(sys.executable)
        self.work = self.root / 'work'
        self.work.mkdir()
        self.answer = self.root / 'answer.json'
        self.log = self.root / 'suite.log'
        self.output = self.root / 'output'

    def report(self, conclusion: 'str' = 'success', answer: 'Optional[object]' = None,
               branch: 'str' = 'main', expected: 'Optional[dict[str, Any]]' = None,
               **extra: 'str') -> 'tuple[dict[str, str], str, str]':
        """The step's outputs, its report and its stdout, for a run that ended ``conclusion``."""
        shutil.rmtree(self.work / 'report', ignore_errors=True)
        self.output.write_text('', encoding='utf-8')
        env = {'PATH': f'{self.bin}{os.pathsep}{os.environ.get("PATH", "")}', 'FAKE_SUITE_LOG': str(self.log),
               'GITHUB_OUTPUT': str(self.output), 'RUNNER_TEMP': str(self.root), 'GH_TOKEN': 'token',
               'SUITE': SUITE, 'RUN_URL': RUN_URL, 'RUN_CONCLUSION': conclusion, 'HEAD_SHA': SHA,
               'HEAD_BRANCH': branch, **extra}
        if answer is not None:
            self.answer.write_text(answer if isinstance(answer, str) else json.dumps(answer), encoding='utf-8')
            env['FAKE_SUITE_ANSWER'] = str(self.answer)
        result = run_step('Write the run report', self.work, env, expected)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        outputs = dict(line.split('=', 1) for line in self.output.read_text(encoding='utf-8').splitlines())
        return outputs, (self.work / REPORT).read_text(encoding='utf-8'), result.stdout

    def test_each_conclusion_maps_to_a_status(self) -> None:
        for conclusion, status in CONCLUSIONS.items():
            with self.subTest(conclusion=conclusion):
                outputs, report, _ = self.report(conclusion, check_runs(GREEN))
                self.assertEqual(outputs, {'title': TITLE, 'status': status})
                self.assertIn(f'concluded `{conclusion or "unknown"}`.', report)

    def test_it_asks_for_the_runs_check_suite(self) -> None:
        self.report('success', check_runs(GREEN))
        [args] = [json.loads(line) for line in self.log.read_text(encoding='utf-8').splitlines()]
        self.assertEqual(args[:2], ['api', 'graphql'])
        self.assertEqual(args[-2:], ['-f', f'id={SUITE}'])
        self.assertIn('checkRuns(first: 100)', args[3])

    def test_a_clean_green_run(self) -> None:
        outputs, report, _ = self.report('success', check_runs(GREEN))
        self.assertEqual(outputs['status'], 'success')
        self.assertEqual(report, (
            '### Unit Tests push run\n\n'
            f'[Unit Tests run]({RUN_URL}) for `{SHA[:9]}` concluded `success`.\n\n'
            'Every job passed, with no warning.\n'))

    def test_a_green_run_whose_ktlo_leg_warned_is_a_warning(self) -> None:
        outputs, report, _ = self.report('success', check_runs(GREEN, KTLO, ('Python 3.15', 'SKIPPED', [])))
        self.assertEqual(outputs['status'], 'warning')
        self.assertEqual(report, (
            '### Unit Tests push run\n\n'
            f'[Unit Tests run]({RUN_URL}) for `{SHA[:9]}` concluded `success`.\n\n'
            '**Warned, in jobs that passed:**\n\n'
            '- `Python 3.8 (KTLO)`: `tests failed on Python 3.8 (KTLO, non-blocking)`; '
            '`Process completed with exit code 1.`\n'))

    def test_the_by_design_list_is_pinned(self) -> None:
        """``EXPECTED`` holds the install failures main's KTLO legs write on every run, and nothing else."""
        source = named('Write the run report')['run']
        script = source.split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
        [value] = [node.value for node in ast.parse(script).body if isinstance(node, ast.Assign)
                   and [getattr(target, 'id', None) for target in node.targets] == ['EXPECTED']]
        self.assertEqual(ast.literal_eval(value), BY_DESIGN)

    def test_with_nothing_listed_the_old_install_failures_warn(self) -> None:
        """Run 39718608950's pypy3.10 install failure is no longer by design (#2040)."""
        outputs, report, _ = self.report('success', check_runs(*REAL_RUN))
        self.assertEqual(outputs['status'], 'warning')
        self.assertIn('- `Python pypy3.10 (KTLO)`: `install failed on Python pypy3.10 (KTLO, non-blocking)`', report)

    def test_mains_by_design_annotations_leave_a_green_run_green(self) -> None:
        """Run 39718608950's annotations, as the API returned them: ``success``, and none listed."""
        outputs, report, _ = self.report('success', check_runs(*REAL_RUN), expected=LISTED)
        self.assertEqual(outputs['status'], 'success')
        self.assertEqual(report, (
            '### Unit Tests push run\n\n'
            f'[Unit Tests run]({RUN_URL}) for `{SHA[:9]}` concluded `success`.\n\n'
            'Every job passed, with no warning but the by-design ones.\n'))

    def test_a_reworded_message_still_matches(self) -> None:
        """The title is matched, not the message, which #2041 rewords."""
        reworded = [(level, title, 'something else entirely') for level, title, _ in REAL_RUN[0][2]]
        outputs, _, _ = self.report('success', check_runs(('Python pypy3.10 (KTLO)', 'SUCCESS', reworded)),
                                    expected=LISTED)
        self.assertEqual(outputs['status'], 'success')

    def test_anything_else_still_warns(self) -> None:
        """An annotation the list does not hold, beside the by-design ones or in their place, is a warning."""
        failed = 'FAILED tests/project/test_x.py::TestX::test_y - AssertionError'
        cases = {
            'a failed test on a by-design job': ('Python pypy3.10 (KTLO)', 'WARNING', failed),
            'a failed tests step on a by-design job': (
                'Python pypy3.10 (KTLO)', 'WARNING', 'tests failed on Python pypy3.10 (KTLO, non-blocking)'),
            'a titled failure on a by-design job': ('Python pypy3.10 (KTLO)', 'FAILURE', 'Something broke'),
            'a by-design title at another level': (
                'Python pypy3.10 (KTLO)', 'FAILURE', 'install failed on Python pypy3.10 (KTLO, non-blocking)'),
            'a by-design title on another job': (
                'Python 3.8 (KTLO)', 'WARNING', 'install failed on Python pypy3.10 (KTLO, non-blocking)'),
            'an install failure on a leg not listed': (
                'Python 3.8 (KTLO)', 'WARNING', 'install failed on Python 3.8 (KTLO, non-blocking)'),
        }
        for case, (job, level, title) in cases.items():
            runs = [(name, result, list(notes)) for name, result, notes in REAL_RUN]
            found = [entry for entry in runs if entry[0] == job]
            if found:
                found[0][2].append((level, title, 'extra'))
            else:
                runs.append((job, 'SUCCESS', [(level, title, 'extra')]))
            with self.subTest(case=case):
                outputs, report, _ = self.report('success', check_runs(*runs), expected=LISTED)
                self.assertEqual(outputs['status'], 'warning')
                [line] = [line for line in report.splitlines() if line.startswith('- ')]
                self.assertEqual(line, f'- `{job}`: `{title}`')

    def test_a_job_that_failed_without_failing_the_run_is_a_warning(self) -> None:
        outputs, report, _ = self.report('success', check_runs(GREEN, ('Python 3.9 (KTLO)', 'FAILURE', [])))
        self.assertEqual(outputs['status'], 'warning')
        self.assertIn('**Failed without failing the run:**\n\n- `Python 3.9 (KTLO)` (failure)\n', report)

    def test_a_failed_run_names_its_jobs(self) -> None:
        answer = check_runs(*REAL_RUN, KTLO, ('Project tests', 'FAILURE', [('FAILURE', '')]),
                            ('Required checks passed', 'FAILURE', []), ('Python 3.13', 'TIMED_OUT', []))
        outputs, report, _ = self.report('failure', answer, expected=LISTED)
        self.assertEqual(outputs['status'], 'failure')
        self.assertIn('**Did not pass:**\n\n- `Project tests` (failure)\n- `Required checks passed` (failure)\n'
                      '- `Python 3.13` (timed_out)\n', report)
        self.assertIn('- `Python 3.8 (KTLO)`: ', report)
        self.assertNotIn('pypy3.10', report)

    def test_unreadable_jobs_keep_the_conclusion(self) -> None:
        for answer in (None, '<html>', json.dumps({'data': {'node': None}})):
            for conclusion in ('success', 'failure'):
                with self.subTest(answer=answer, conclusion=conclusion):
                    outputs, report, stdout = self.report(conclusion, answer)
                    self.assertEqual(outputs['status'], conclusion)
                    self.assertTrue(report.endswith("The run's jobs could not be read, so none is named here.\n"),
                                    report)
                    if answer is None:
                        self.assertIn("::warning::The run's jobs could not be read", stdout)

    def test_a_long_suite_says_it_was_cut(self) -> None:
        _, report, _ = self.report('success', check_runs(GREEN, more=True))
        self.assertTrue(report.endswith('Only the first 100 jobs were read.\n'), report)

    def test_the_runs_text_renders_as_code(self) -> None:
        """A job name or annotation holding Markdown, a mention or a newline stays one inert code span."""
        noisy = ('Py `3` @JarryShaw', 'SUCCESS', [('WARNING', 'a\n**b** `c` @d ' + 'x' * 300)])
        _, report, _ = self.report('success', check_runs(noisy), RUN_URL='javascript:alert(1)', HEAD_SHA='nope')
        [line] = [line for line in report.splitlines() if line.startswith('- ')]
        flat = "a **b** 'c' @d "
        self.assertEqual(line, f"- `Py '3' @JarryShaw`: `{flat}{'x' * (197 - len(flat))}...`")
        self.assertIn('\nThe Unit Tests run concluded `success`.\n', report)

    def test_the_branch_names_the_thread(self) -> None:
        for branch, title in (('main', TITLE), ('release/1.4', 'unit-tests: release/1.4 push runs'),
                              ('a b$(x)`y`', 'unit-tests: a-b--x--y- push runs'),
                              ('', 'unit-tests: unknown push runs')):
            with self.subTest(branch=branch):
                outputs, _, _ = self.report('success', check_runs(GREEN), branch=branch)
                self.assertEqual(outputs['title'], title)


#: A stand-in ``python3`` for the post step, recording its arguments and environment.
FAKE_PYTHON = textwrap.dedent('''\
    import json, os, sys
    with open(os.environ['FAKE_PYTHON_LOG'], 'w', encoding='utf-8') as file:
        json.dump({'args': sys.argv[1:], 'workflow': os.environ.get('GITHUB_WORKFLOW')}, file)
''')


@unittest.skipIf(not BASH or os.name == 'nt', 'needs bash and a POSIX shell')
class TestThePostStep(unittest.TestCase):
    """``Post the report to Discussions``, with a stand-in ``python3``."""

    def test_it_passes_the_relayed_run(self) -> None:
        with tempfile.TemporaryDirectory(prefix='pcapkit-2030-push-post-') as tmp:
            root = pathlib.Path(tmp)
            (root / 'bin').mkdir()
            (root / 'work').mkdir()
            write_launcher(root / 'bin', 'python3', FAKE_PYTHON)
            env = {'PATH': f'{root / "bin"}{os.pathsep}{os.environ.get("PATH", "")}',
                   'FAKE_PYTHON_LOG': str(root / 'log.json'), 'REPORT_CATEGORY': CATEGORY, 'TITLE': TITLE,
                   'STATUS': 'warning', 'RUN_URL': RUN_URL, 'HEAD_SHA': SHA, 'GITHUB_WORKFLOW': 'Coverage Comment'}
            result = run_step('Post the report to Discussions', root / 'work', env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            logged = json.loads((root / 'log.json').read_text(encoding='utf-8'))
        self.assertEqual(logged, {'workflow': 'Unit Tests', 'args': [
            'util/discussion_report.py', '--category', CATEGORY, '--title', TITLE, '--report', REPORT,
            '--mode', 'push', '--status', 'warning', '--run-url', RUN_URL, '--sha', SHA]})


@unittest.skipIf(not BASH, 'needs bash on PATH')
class TestEndToEnd(_FakeGitHub):
    """Both steps and the real script: a bad push run posts, one green run after it, then silence."""

    def setUp(self) -> None:
        super().setUp()
        (self.bin / 'gh.py').rename(self.bin / 'discussions.py')
        write_launcher(self.bin, 'gh', FAKE_GH)
        (self.bin / 'python3').symlink_to(sys.executable)
        self.work = self.tmp / 'work'
        (self.work / 'util').mkdir(parents=True)
        shutil.copy(SCRIPT, self.work / 'util')
        self.answer = self.tmp / 'answer.json'

    def push_run(self, conclusion: 'str', *runs: 'tuple[str, str, list[tuple[str, str]]]') -> None:
        self.answer.write_text(json.dumps(check_runs(*runs)), encoding='utf-8')
        shutil.rmtree(self.work / 'report', ignore_errors=True)
        output = self.tmp / 'output'
        output.write_text('', encoding='utf-8')
        env = self.env(FAKE_SUITE_ANSWER=str(self.answer), FAKE_SUITE_LOG=str(self.tmp / 'suite.log'),
                       GITHUB_OUTPUT=str(output), RUNNER_TEMP=str(self.tmp), GITHUB_WORKFLOW='Coverage Comment',
                       SUITE=SUITE, RUN_URL=RUN_URL, RUN_CONCLUSION=conclusion, HEAD_SHA=SHA, HEAD_BRANCH='main',
                       REPORT_CATEGORY=CATEGORY)
        result = run_step('Write the run report', self.work, env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for line in output.read_text(encoding='utf-8').splitlines():
            key, value = line.split('=', 1)
            env[key.upper()] = value
        result = run_step('Post the report to Discussions', self.work, env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('::warning', result.stdout)

    def comments(self) -> 'list[str]':
        found = [entry for entry in self.state['discussions'] if entry['title'] == TITLE]
        return found[0]['comments'] if found else []

    def test_the_cadence(self) -> None:
        self.push_run('success', GREEN)
        self.assertEqual(self.state['discussions'], [])
        self.push_run('success', GREEN, KTLO)
        self.push_run('failure', GREEN, ('Python 3.13', 'FAILURE', []))
        self.push_run('success', GREEN)
        self.push_run('success', GREEN)
        comments = self.comments()
        self.assertEqual([MARKER.findall(body) for body in comments], [['warning'], ['failure'], ['success']])
        self.assertIn('- `Python 3.8 (KTLO)`: ', comments[0])
        self.assertIn('- `Python 3.13` (failure)', comments[1])
        self.assertIn(f'Posted from [Unit Tests run]({RUN_URL}) at commit `{SHA}`, which ended `success`.',
                      comments[2])


if __name__ == '__main__':
    unittest.main()
