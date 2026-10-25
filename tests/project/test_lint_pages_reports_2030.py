# -*- coding: utf-8 -*-
"""#2030: the ``discussion`` jobs of :file:`lint.yml` and :file:`deploy-pages.yml`.

Each posts its workflow's run report to that job's thread in the ``CI reports``
category with :file:`util/discussion_report.py`, which
:mod:`tests.project.test_discussion_report_2030` tests on its own.

* :class:`TestTheWorkflowsPost` pins both workflows: the ``discussion`` job
  alone holds ``discussions: write``, every other job's permissions as they
  were, first-party actions only, the command each posts with, the mode each
  event maps to, Lint's report steps and their guards, and when each job runs:
  never on a pull request, and for GitHub Pages never on a verdict for another
  commit.
* :class:`TestTheLintReport` runs Lint's ``Write the run report`` as the runner
  runs it.
* :class:`TestThePostSteps` runs each ``Post the report to Discussions`` with a
  stand-in ``python3``: the status it passes, and the report it hands over.

"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess  # nosec: B404
import tempfile
import unittest
from typing import TYPE_CHECKING

from tests._workflows import WORKFLOWS, load, pinned
from tests.project.test_cron_reports_2030 import _ReportStep, launcher, step
from tests.project.test_discussion_report_2030 import (BASH, CATEGORY, FAKE_PYTHON, FIRST_PARTY,
                                                       POSTER, RUN, evaluate)
from tests.project.test_release_gates import STATUS, job_blocks, job_runs

if TYPE_CHECKING:
    from typing import Any, Optional

LINT = 'lint.yml'
PAGES = 'deploy-pages.yml'
POST = 'Post the report to Discussions'
#: Each workflow's thread, and the report file the post step reads.
TITLES = {LINT: ('lint: weekly lint report', 'lint-report.md'),
          PAGES: ('deploy-pages: documentation build report', 'pages-report.md')}
#: Every job's own ``permissions:``, and the top-level block, as before #2030.
PERMISSIONS = {
    LINT: {None: {'contents': 'read'}, 'lint': None},
    PAGES: {None: {'contents': 'read'}, 'head': {'contents': 'read'}, 'deploy-pages': None,
            'publish-pages': {'actions': 'read', 'contents': 'write'}},
}
#: Each ``discussion`` job's ``needs:`` and ``if:``.
NEEDS = {LINT: ['lint'], PAGES: ['head', 'deploy-pages', 'publish-pages']}
IFS = {
    LINT: "${{ always() && github.event_name != 'pull_request' && needs.lint.result != 'skipped' }}",
    PAGES: "${{ always() && github.event_name != 'pull_request' && github.event_name != 'workflow_dispatch' && "
           "(needs.deploy-pages.result != 'skipped' || "
           "needs.head.result == 'failure' || needs.head.result == 'cancelled') }}",
}
#: The ``--mode`` and ``--status`` each workflow passes, and the step's ``env:``
#: beside ``GH_TOKEN``.
ARGS = {
    LINT: ('--mode scheduled --status "$status"', {
        'LINT_RESULT': '${{ needs.lint.result }}',
        'LINT_STATUS': '${{ needs.lint.outputs.status }}',
    }),
    PAGES: ('--mode "$MODE" --status "$status"', {
        'MODE': "${{ github.event_name == 'workflow_run' && 'push' || 'scheduled' }}",
        'HEAD_RESULT': '${{ needs.head.result }}',
        'BUILD_RESULT': '${{ needs.deploy-pages.result }}',
        'PUBLISH_RESULT': '${{ needs.publish-pages.result }}',
    }),
}
#: Lint's tool steps, each with the ``id`` the report reads its outcome by.
TOOLS = ('bandit', 'mypy', 'vermin', 'pylint', 'actionlint')
#: The guard on Lint's report steps.
REPORTS = "${{ !cancelled() && github.event_name != 'pull_request' }}"


class TestTheWorkflowsPost(unittest.TestCase):
    """The ``discussion`` job of each workflow, and every other job left as it was."""

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
                        self.assertNotIn('discussion', json.dumps(spec['jobs'][job_id]))

    def test_the_posting_job_runs_first_party_actions_only(self) -> None:
        for name in TITLES:
            job = load(name)['jobs']['discussion']
            self.assertNotIn('environment', job)
            for entry in job['steps']:
                if 'uses' not in entry:
                    continue
                with self.subTest(workflow=name, step=entry.get('name') or entry['uses']):
                    self.assertTrue(any(pinned(entry['uses'], action) for action in FIRST_PARTY), entry['uses'])
                    if pinned(entry['uses'], 'actions/checkout'):
                        self.assertIs(entry['with']['persist-credentials'], False)

    def test_each_workflow_posts_its_report_with_the_script(self) -> None:
        for name, (title, file) in TITLES.items():
            spec = load(name)
            job = spec['jobs']['discussion']
            with self.subTest(workflow=name):
                self.assertEqual(spec['env'], {'REPORT_CATEGORY': CATEGORY})
                self.assertEqual(job['needs'], NEEDS[name])
                self.assertEqual(' '.join(job['if'].split()), IFS[name])
                self.assertIs(job['continue-on-error'], True)
                self.assertEqual(job['runs-on'], 'ubuntu-latest')
                self.assertTrue(title.startswith(name[:-len('.yml')] + ': '), title)
                post = step(name, 'discussion', POST)
                self.assertIs(post['continue-on-error'], True)
                args, env = ARGS[name]
                self.assertEqual(post['env'], {'GH_TOKEN': '${{ github.token }}', **env})
                command = ' '.join(post['run'][post['run'].index(RUN):].replace('\\\n', ' ').split())
                self.assertEqual(command, f'{RUN} --category "$REPORT_CATEGORY" --title \'{title}\' '
                                          f'--report report/{file} {args}')

    def test_no_other_job_runs_the_script(self) -> None:
        for name in TITLES:
            for job_id, job in load(name)['jobs'].items():
                if job_id == 'discussion':
                    continue
                with self.subTest(workflow=name, job=job_id):
                    self.assertNotIn('discussion_report', json.dumps(job))

    def test_lint_hands_its_report_on(self) -> None:
        """Lint's report steps come last, skip a pull request, and never fail the job."""
        spec = load(LINT)
        lint = spec['jobs']['lint']
        self.assertEqual(lint['outputs'], {'status': '${{ steps.run-report.outputs.status }}'})
        steps = lint['steps']
        self.assertEqual([entry.get('name') for entry in steps][-2:], ['Write the run report', 'Upload the run report'])
        self.assertEqual(steps[-2]['id'], 'run-report')
        for entry in steps[-2:]:
            self.assertEqual(entry['if'], REPORTS)
            self.assertIs(entry['continue-on-error'], True)
        self.assertEqual(steps[-2]['env'], {tool.upper(): f'${{{{ steps.{tool}.outcome }}}}' for tool in TOOLS})
        for tool in TOOLS:
            with self.subTest(tool=tool):
                entry = step(LINT, 'lint', tool)
                self.assertEqual(entry['id'], tool)
                self.assertIn('| tee -a "$RUNNER_TEMP/lint-summary.md" >> "$GITHUB_STEP_SUMMARY"', entry['run'])
        upload = steps[-1]
        self.assertTrue(pinned(upload['uses'], 'actions/upload-artifact'))
        self.assertEqual(upload['with']['name'], 'lint-report')
        self.assertEqual(upload['with']['path'], '${{ runner.temp }}/lint-report.md')
        [download] = [entry for entry in spec['jobs']['discussion']['steps']
                      if pinned(entry.get('uses'), 'actions/download-artifact')]
        self.assertEqual(download['with'], {'name': 'lint-report', 'path': 'report'})
        self.assertIs(download['continue-on-error'], True)

    def test_pages_reads_no_artifact_and_checks_out_the_script_and_its_helper(self) -> None:
        job = load(PAGES)['jobs']['discussion']
        uses = [entry['uses'] for entry in job['steps'] if 'uses' in entry]
        self.assertEqual(len(uses), 1)
        self.assertTrue(pinned(uses[0], 'actions/checkout'))
        # The script imports util/_actions.py (#2047).
        self.assertEqual(job['steps'][0]['with'], {'sparse-checkout': 'util/_actions.py\nutil/discussion_report.py\n',
                                                   'sparse-checkout-cone-mode': False,
                                                   'persist-credentials': False})

    def test_the_mode_follows_the_event(self) -> None:
        """Lint has no push trigger; GitHub Pages' ``workflow_run`` follows a push, so ``push``."""
        self.assertEqual(sorted(load(LINT)['on']), ['pull_request', 'schedule', 'workflow_dispatch'])
        # A manual run posts nothing; tests/project/test_build_only_dispatch.py pins it.
        self.assertEqual(sorted(load(PAGES)['on']),
                         ['pull_request', 'schedule', 'workflow_dispatch', 'workflow_run'])
        expression = step(PAGES, 'discussion', POST)['env']['MODE']
        for event, mode in (('schedule', 'scheduled'), ('workflow_run', 'push')):
            with self.subTest(event=event):
                self.assertEqual(evaluate(expression, {'github': {'event_name': event}}), mode)

    def test_lint_posts_on_the_schedule_and_dispatch_alone(self) -> None:
        jobs = job_blocks((WORKFLOWS / LINT).read_text(encoding='utf-8'))
        for event, result, expected in (('schedule', 'success', True), ('schedule', 'failure', True),
                                        ('workflow_dispatch', 'success', True), ('schedule', 'skipped', False),
                                        ('pull_request', 'success', False), ('pull_request', 'failure', False)):
            context = {STATUS: {'cancelled': False}, 'github': {'event_name': event, 'event': {}},
                       'needs': {'lint': {'result': result, 'outputs': {}}}}  # type: dict[str, Any]
            with self.subTest(event=event, lint=result):
                self.assertEqual(job_runs(jobs, 'discussion', context), expected)

    def test_pages_posts_on_a_build_or_a_failed_gate_but_not_a_deliberate_skip(self) -> None:
        """As cron-vendor's: a pull request's run, or a verdict for another commit, posts nothing."""
        jobs = job_blocks((WORKFLOWS / PAGES).read_text(encoding='utf-8'))
        # `(event, head, deploy-pages, whether discussion runs)`.
        rows = (
            ('schedule', 'success', 'success', True),
            ('schedule', 'success', 'failure', True),
            ('schedule', 'failure', 'skipped', True),
            ('schedule', 'cancelled', 'skipped', True),
            ('workflow_run', 'success', 'success', True),
            ('workflow_run', 'failure', 'skipped', True),
            ('workflow_run', 'success', 'skipped', False),
            ('pull_request', 'skipped', 'success', False),
            ('pull_request', 'skipped', 'failure', False),
        )
        for event, head, built, expected in rows:
            needs = {'head': {'result': head}, 'deploy-pages': {'result': built},
                     'publish-pages': {'result': 'skipped'}}
            context = {STATUS: {'cancelled': False}, 'github': {'event_name': event, 'event': {}},
                       'needs': needs}  # type: dict[str, Any]
            with self.subTest(event=event, head=head, deploy_pages=built):
                self.assertEqual(job_runs(jobs, 'discussion', context), expected)


class TestTheLintReport(_ReportStep):
    """``lint``'s report: each tool's outcome, then the summary blocks."""

    workflow, job, file = LINT, 'lint', 'lint-report.md'
    #: A run where every advisory tool found something.
    FOUND = {'BANDIT': 'failure', 'MYPY': 'failure', 'VERMIN': 'failure', 'PYLINT': 'failure',
             'ACTIONLINT': 'success'}

    def lines(self, **env: 'str') -> 'str':
        return ('### Lint\n\n'
                f"- bandit, advisory: {env.get('BANDIT', 'not run')}\n"
                f"- mypy, advisory: {env.get('MYPY', 'not run')}\n"
                f"- vermin, advisory: {env.get('VERMIN', 'not run')}\n"
                f"- pylint, advisory: {env.get('PYLINT', 'not run')}\n"
                f"- actionlint, blocking: {env.get('ACTIONLINT', 'not run')}\n")

    def test_an_advisory_finding_warns_and_the_blocks_follow(self) -> None:
        blocks = '### mypy\n```\nFound 3 errors in 2 files\n```\n'
        (self.temp / 'lint-summary.md').write_text(blocks, encoding='utf-8')
        self.assertEqual(self.report(**self.FOUND), (self.lines(**self.FOUND) + '\n' + blocks, 'warning'))

    def test_a_clean_run(self) -> None:
        clean = dict.fromkeys(self.FOUND, 'success')
        self.assertEqual(self.report(**clean), (self.lines(**clean), 'success'))

    def test_a_blocking_finding_alone_does_not_warn(self) -> None:
        """actionlint fails the job, which the post step reads instead."""
        env = {**dict.fromkeys(self.FOUND, 'success'), 'ACTIONLINT': 'failure'}
        self.assertEqual(self.report(**env), (self.lines(**env), 'success'))

    def test_a_job_that_stopped_before_the_tools(self) -> None:
        self.assertEqual(self.report(), (self.lines(), 'success'))


@unittest.skipIf(not BASH, 'needs bash on PATH')
class TestThePostSteps(unittest.TestCase):
    """Each ``Post the report to Discussions``, run with a stand-in ``python3``."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-2030-post-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        (self.bin / 'fake_python.py').write_text(FAKE_PYTHON, encoding='utf-8')
        launcher(self.bin, 'python3', 'fake_python.py')
        self.log = self.root / 'python.json'

    def run_step(self, name: 'str', artifact: 'Optional[str]' = None, **env: 'str') -> 'tuple[str, str]':
        """The ``--status`` the step passed, and the report it handed over."""
        title, file = TITLES[name]
        work = self.root / 'work'
        shutil.rmtree(work, ignore_errors=True)
        (work / 'report').mkdir(parents=True)
        if artifact is not None:
            (work / 'report' / file).write_text(artifact, encoding='utf-8')
        script = self.root / 'step.sh'
        script.write_text(step(name, 'discussion', POST)['run'], encoding='utf-8')
        env = dict(env, PATH=f'{self.bin}{os.pathsep}{os.environ.get("PATH", "")}', FAKE_PYTHON_LOG=str(self.log),
                   REPORT_CATEGORY=CATEGORY)
        result = subprocess.run([str(BASH), '-e', str(script)], cwd=work, env=env,  # nosec: B603
                                capture_output=True, text=True, check=False, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        logged = json.loads(self.log.read_text(encoding='utf-8'))
        args = logged['args']
        self.assertEqual(args[:9], ['util/discussion_report.py', '--category', CATEGORY, '--title', title,
                                    '--report', f'report/{file}', '--mode', env.get('MODE', 'scheduled')])
        self.assertEqual(args[9], '--status')
        return args[10], logged['report']

    def test_the_lint_status(self) -> None:
        for result, status, expected in (('success', 'warning', 'warning'), ('success', 'success', 'success'),
                                         ('success', '', 'success'), ('failure', 'warning', 'failure'),
                                         ('cancelled', '', 'cancelled')):
            with self.subTest(result=result, status=status):
                self.assertEqual(self.run_step(LINT, 'the week\n', LINT_RESULT=result, LINT_STATUS=status),
                                 (expected, 'the week\n'))

    def test_the_pages_status_and_report(self) -> None:
        # `(head, deploy-pages, publish-pages, --status)`.
        for head, built, published, expected in (
                ('success', 'success', 'success', 'success'),
                ('success', 'success', 'failure', 'failure'),
                ('success', 'success', 'cancelled', 'cancelled'),
                ('success', 'failure', 'skipped', 'failure'),
                ('success', 'cancelled', 'skipped', 'cancelled'),
                ('failure', 'skipped', 'skipped', 'failure'),
                ('cancelled', 'skipped', 'skipped', 'cancelled'),
        ):
            for mode in ('push', 'scheduled'):
                with self.subTest(head=head, deploy_pages=built, publish_pages=published, mode=mode):
                    self.assertEqual(self.run_step(PAGES, MODE=mode, HEAD_RESULT=head, BUILD_RESULT=built,
                                                   PUBLISH_RESULT=published), (expected, (
                        f'### GitHub Pages\n\n- Gate: {head}\n- Build: {built}\n- Publish: {published}\n')))


if __name__ == '__main__':
    unittest.main()
