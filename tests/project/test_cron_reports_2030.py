# -*- coding: utf-8 -*-
"""#2030: the ``discussion`` jobs of :file:`cron-conda.yml` and :file:`cron-python-versions.yml`.

Each posts its workflow's run report to that job's thread in the ``CI reports``
category with :file:`util/discussion_report.py`, which
:mod:`tests.project.test_discussion_report_2030` tests on its own.

* :class:`TestTheWorkflowsPost` pins both workflows: the ``discussion`` job
  alone holds ``discussions: write``, every other job's permissions as
  :data:`PERMISSIONS` lists them, first-party actions only, the mode each event
  maps to, the report steps and their guards, cron-conda's job running on a failed gate but not on
  a deliberate skip, and no ``workflow_run`` consumer of either.
* :class:`TestThePinRefresh` runs cron-conda's ``Refresh the platform pins``
  with a stand-in ``python``: the log it keeps, and the exit status it keeps.
* :class:`TestTheCondaReport` and :class:`TestThePythonVersionsReport` run
  each ``Write the run report`` step as the runner runs it.
* :class:`TestThePostSteps` runs each ``Post the report to Discussions`` with a
  stand-in ``python3``: the status it passes, and the report it hands over.

"""

from __future__ import annotations

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

from tests._support import bash_argv
from tests._workflows import WORKFLOWS, load, pinned
from tests.project.test_discussion_report_2030 import (BASH, CATEGORY, FAKE_PYTHON, FIRST_PARTY,
                                                       POSTER, RUN, evaluate)
from tests.project.test_release_gates import STATUS, job_blocks, job_runs

if TYPE_CHECKING:
    from typing import Any, Optional

CONDA = 'cron-conda.yml'
VERSIONS = 'cron-python-versions.yml'
#: ``(workflow, reporting job, the thread's title, the artifact, the file in it)``.
POSTERS = (
    (CONDA, 'conda-update', 'cron-conda: conda distribution update report', 'conda-report', 'conda-report.md'),
    (VERSIONS, 'detect', 'cron-python-versions: Python version update report', 'python-versions-report',
     'python-versions-report.md'),
)
#: Every job's own ``permissions:`` but ``discussion``'s, and the top-level block,
#: so that only ``discussion`` may write discussions (#2030).
PERMISSIONS = {
    CONDA: {None: {'contents': 'read'}, 'mode': {}, 'head': {'contents': 'read'},
            'conda-update': {'contents': 'write'}, 'conda-tag': {'contents': 'write'},
            'conda-dist': {'contents': 'write'}},
    VERSIONS: {None: {}, 'detect': {'contents': 'read', 'pull-requests': 'read'}, 'pr': {'actions': 'read'}},
}
#: The ``--mode`` and ``--status`` each workflow passes, and the step's ``env:``
#: beside ``GH_TOKEN``.
ARGS = {
    CONDA: ('--mode "$MODE" --status "$status"', {
        'MODE': "${{ github.event_name == 'workflow_run' && 'push' || 'scheduled' }}",
        'HEAD_RESULT': '${{ needs.head.result }}',
        'UPDATE_RESULT': '${{ needs.conda-update.result }}',
        'UPDATE_STATUS': '${{ needs.conda-update.outputs.status }}',
        'TAG_RESULT': '${{ needs.conda-tag.result }}',
        'DIST_RESULT': '${{ needs.conda-dist.result }}',
    }),
    VERSIONS: ('--mode scheduled --status "$status"', {
        'DETECT_RESULT': '${{ needs.detect.result }}',
        'DETECT_STATUS': '${{ needs.detect.outputs.status }}',
    }),
}
#: Each ``discussion`` job's ``needs:`` and ``if:``.
NEEDS = {CONDA: ['head', 'conda-update', 'conda-tag', 'conda-dist', 'mode'], VERSIONS: ['detect']}
IFS = {
    CONDA: "${{ always() && needs.mode.outputs.publishes == 'true' && (needs.conda-update.result != 'skipped' || "
           "needs.head.result == 'failure' || "
           "needs.head.result == 'cancelled') }}",
    VERSIONS: "${{ always() && needs.detect.result != 'skipped' }}",
}
REPORT_STEPS = ['Write the run report', 'Upload the run report']


def step(name: 'str', job: 'str', label: 'str') -> 'dict[str, Any]':
    """The one step named ``label`` of job ``job`` in workflow ``name``."""
    [found] = [entry for entry in load(name)['jobs'][job]['steps'] if entry.get('name') == label]
    return found


def launcher(directory: 'pathlib.Path', name: 'str', script: 'Optional[str]' = None) -> 'None':
    """``directory/name`` running this interpreter, on ``script`` if one is given."""
    target = '' if script is None else f' "$(dirname "$0")/{script}"'
    path = directory / name
    path.write_text(f'#!/bin/sh\nexec \'{sys.executable}\'{target} "$@"\n', encoding='utf-8')
    path.chmod(0o755)


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
                        self.assertNotIn('discussions', json.dumps(spec['jobs'][job_id]))

    def test_the_posting_job_runs_first_party_actions_only(self) -> None:
        for name, *_ in POSTERS:
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
        for name, reporter, title, artifact, file in POSTERS:
            spec = load(name)
            job = spec['jobs']['discussion']
            with self.subTest(workflow=name):
                self.assertEqual(spec['env'], {'REPORT_CATEGORY': CATEGORY})
                self.assertEqual(job['needs'], NEEDS[name])
                self.assertEqual(' '.join(job['if'].split()), IFS[name])
                self.assertIs(job['continue-on-error'], True)
                self.assertEqual(job['runs-on'], 'ubuntu-latest')
                self.assertTrue(title.startswith(name[:-len('.yml')] + ': '), title)

                [upload] = [entry for entry in spec['jobs'][reporter]['steps']
                            if entry.get('name') == 'Upload the run report']
                self.assertTrue(pinned(upload['uses'], 'actions/upload-artifact'))
                self.assertEqual(upload['with']['name'], artifact)
                self.assertEqual(upload['with']['path'], '${{ runner.temp }}/' + file)

                [download] = [entry for entry in job['steps'] if pinned(entry.get('uses'), 'actions/download-artifact')]
                self.assertEqual(download['with'], {'name': artifact, 'path': 'report'})
                self.assertIs(download['continue-on-error'], True)

                post = step(name, 'discussion', 'Post the report to Discussions')
                self.assertIs(post['continue-on-error'], True)
                args, env = ARGS[name]
                self.assertEqual(post['env'], {'GH_TOKEN': '${{ github.token }}', **env})
                command = ' '.join(post['run'][post['run'].index(RUN):].replace('\\\n', ' ').split())
                self.assertEqual(command, f'{RUN} --category "$REPORT_CATEGORY" --title \'{title}\' '
                                          f'--report report/{file} {args}')

    def test_the_mode_follows_the_event(self) -> None:
        """Python Versions is always ``scheduled``; Conda Update's ``workflow_run`` follows a push, so ``push``."""
        self.assertEqual(sorted(load(VERSIONS)['on']), ['schedule', 'workflow_dispatch'])
        # A manual run posts nothing unless `publish` is set, and then as the
        # schedule does (#2060); tests/project/test_build_only_dispatch.py pins the first.
        self.assertEqual(sorted(load(CONDA)['on']), ['schedule', 'workflow_dispatch', 'workflow_run'])
        expression = step(CONDA, 'discussion', 'Post the report to Discussions')['env']['MODE']
        for event, mode in (('schedule', 'scheduled'), ('workflow_run', 'push'), ('workflow_dispatch', 'scheduled')):
            with self.subTest(event=event):
                self.assertEqual(evaluate(expression, {'github': {'event_name': event}}), mode)

    def test_the_reporting_jobs_hand_on_their_status(self) -> None:
        conda = load(CONDA)['jobs']['conda-update']['outputs']
        self.assertEqual(conda['status'], '${{ steps.run-report.outputs.status }}')
        self.assertEqual(load(VERSIONS)['jobs']['detect']['outputs'], {
            'changed': '${{ steps.update.outputs.changed }}', 'publish': '${{ steps.update.outputs.publish }}',
            'status': '${{ steps.run-report.outputs.status }}'})

    def test_the_report_steps_come_last_and_never_fail_the_job(self) -> None:
        for name, reporter, *_ in POSTERS:
            steps = load(name)['jobs'][reporter]['steps']
            with self.subTest(workflow=name):
                self.assertEqual([entry.get('name') for entry in steps][-2:], REPORT_STEPS)
                self.assertEqual(steps[-2]['id'], 'run-report')
                for entry in steps[-2:]:
                    self.assertEqual(entry['if'], '${{ !cancelled() }}')
                    self.assertIs(entry['continue-on-error'], True)

    def test_no_other_job_runs_the_script(self) -> None:
        for name, *_ in POSTERS:
            for job_id, job in load(name)['jobs'].items():
                if job_id == 'discussion':
                    continue
                with self.subTest(workflow=name, job=job_id):
                    self.assertNotIn('discussion_report', json.dumps(job))

    def test_the_conda_report_runs_on_a_failed_gate_but_not_a_deliberate_skip(self) -> None:
        """As cron-vendor's: a pull request's ``workflow_run``, or a verdict for another commit, posts nothing."""
        jobs = job_blocks((WORKFLOWS / CONDA).read_text(encoding='utf-8'))
        # `(event, head, conda-update, whether discussion runs, mode's `publishes`)`;
        # tag and upload skip. #2060: a manual run posts only with `publish`,
        # and one `mode` refused, which wrote no `publishes`, posts nothing.
        rows = (
            ('schedule', 'success', 'success', True, 'true'),
            ('schedule', 'success', 'failure', True, 'true'),
            ('schedule', 'failure', 'skipped', True, 'true'),
            ('schedule', 'cancelled', 'skipped', True, 'true'),
            ('workflow_run', 'success', 'success', True, 'true'),
            ('workflow_run', 'failure', 'skipped', True, 'true'),
            ('workflow_run', 'success', 'skipped', False, 'true'),
            ('workflow_run', 'skipped', 'skipped', False, 'true'),
            ('workflow_dispatch', 'success', 'success', False, 'false'),
            ('workflow_dispatch', 'failure', 'skipped', False, 'false'),
            ('workflow_dispatch', 'success', 'success', True, 'true'),
            ('workflow_dispatch', 'failure', 'skipped', True, 'true'),
            ('workflow_dispatch', 'success', 'skipped', False, None),
        )
        for event, head, update, expected, publishes in rows:
            needs = {'head': {'result': head}, 'conda-update': {'result': update, 'outputs': {}},
                     'conda-tag': {'result': 'skipped'}, 'conda-dist': {'result': 'skipped'},
                     'mode': {'result': 'failure' if publishes is None else 'success',
                              'outputs': {} if publishes is None else {'publishes': publishes}}}
            context = {STATUS: {'cancelled': False}, 'github': {'event_name': event, 'event': {}},
                       'needs': needs}  # type: dict[str, Any]
            with self.subTest(event=event, head=head, conda_update=update, publishes=publishes):
                self.assertEqual(job_runs(jobs, 'discussion', context), expected)
        [download] = [entry for entry in load(CONDA)['jobs']['discussion']['steps']
                      if pinned(entry.get('uses'), 'actions/download-artifact')]
        self.assertEqual(download['if'], "needs.conda-update.result != 'skipped'")

    def test_the_versions_report_does_not_wait_on_the_approval(self) -> None:
        """``pr`` waits on the owner's approval of ``github-release``, so ``discussion`` does not need it."""
        jobs = load(VERSIONS)['jobs']
        self.assertEqual(jobs['pr']['environment'], 'github-release')
        self.assertNotIn('pr', jobs['discussion']['needs'])

    def test_no_workflow_run_consumer_reads_either(self) -> None:
        """A new job cannot move a conclusion something else filters on: nothing listens for these runs."""
        names = {load(name)['name'] for name in (CONDA, VERSIONS)}
        self.assertEqual(names, {'Conda Update', 'Python Versions'})
        for path in sorted(WORKFLOWS.glob('*.yml')):
            on = load(path.name).get('on') or {}
            listed = (on.get('workflow_run') or {}).get('workflows', []) if isinstance(on, dict) else []
            with self.subTest(workflow=path.name):
                self.assertFalse(names & set(listed), listed)


@unittest.skipIf(not BASH, 'needs bash on PATH')
class TestThePinRefresh(unittest.TestCase):
    """``Refresh the platform pins``, run with a stand-in ``python``, as ``bash -e`` runs it."""

    def run_step(self, code: 'int') -> 'tuple[subprocess.CompletedProcess[str], str]':
        with tempfile.TemporaryDirectory(prefix='pcapkit-2030-pins-') as tmp:
            root = pathlib.Path(tmp)
            (root / 'fake.py').write_text(textwrap.dedent(f'''\
                import sys
                assert sys.argv[1:] == ['util/conda_vendor.py', '--refresh-pins'], sys.argv
                print('::notice title=Platform pins::pyshark 0.6 -> 0.7 on osx-arm64')
                sys.exit({code})
            '''), encoding='utf-8')
            launcher(root, 'python', 'fake.py')
            script = root / 'step.sh'
            script.write_text(step(CONDA, 'conda-update', 'Refresh the platform pins')['run'], encoding='utf-8')
            env = {'PATH': f'{root}{os.pathsep}{os.environ.get("PATH", "")}', 'RUNNER_TEMP': str(root)}
            result = subprocess.run(bash_argv('-e', str(script), executable=str(BASH)),  # nosec: B603
                                    cwd=root, env=env, capture_output=True, text=True, check=False, timeout=60)
            return result, (root / 'platform-pins.log').read_text(encoding='utf-8')

    def test_the_log_keeps_the_annotations(self) -> None:
        result, log = self.run_step(0)
        self.assertEqual(result.returncode, 0, result.stderr)
        line = '::notice title=Platform pins::pyshark 0.6 -> 0.7 on osx-arm64\n'
        self.assertEqual((result.stdout, log), (line, line))

    def test_the_scripts_failure_still_fails_the_step(self) -> None:
        self.assertEqual(self.run_step(3)[0].returncode, 3)


@unittest.skipIf(not BASH, 'needs bash on PATH')
class _ReportStep(unittest.TestCase):
    """A ``Write the run report`` step, run in a scratch directory as ``bash -e`` runs it."""

    workflow = ''
    job = ''
    file = ''

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-2030-report-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.work = self.root / 'work'
        self.temp = self.root / 'runner-temp'
        self.bin = self.root / 'bin'
        for path in (self.work, self.temp, self.bin):
            path.mkdir()
        launcher(self.bin, 'python3')
        self.output = self.root / 'output'
        self.script = self.root / 'step.sh'
        self.script.write_text(step(self.workflow, self.job, 'Write the run report')['run'], encoding='utf-8')

    def report(self, **env: 'str') -> 'tuple[str, str]':
        """The report, and the ``status`` the step wrote to ``GITHUB_OUTPUT``."""
        self.output.write_text('', encoding='utf-8')
        env = dict(env, PATH=f'{self.bin}{os.pathsep}{os.environ.get("PATH", "")}', RUNNER_TEMP=str(self.temp),
                   GITHUB_OUTPUT=str(self.output))
        result = subprocess.run(bash_argv('-e', str(self.script), executable=str(BASH)),  # nosec: B603
                                cwd=self.work, env=env, capture_output=True, text=True, check=False, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        text = (self.temp / self.file).read_text(encoding='utf-8')
        self.assertEqual(result.stdout, text)
        lines = self.output.read_text(encoding='utf-8').splitlines()
        self.assertEqual(len(lines), 1, lines)
        key, _, status = lines[0].partition('=')
        self.assertEqual(key, 'status')
        return text, status


class TestTheCondaReport(_ReportStep):
    """``conda-update``'s report: the pins, the changed files, and the build pushed."""

    workflow, job, file = CONDA, 'conda-update', 'conda-report.md'

    def setUp(self) -> None:
        super().setUp()
        (self.work / 'conda').mkdir()
        (self.work / 'conda' / 'build').write_text('4\n', encoding='utf-8')

    def pins(self, *lines: 'str') -> 'None':
        (self.temp / 'platform-pins.log').write_text(''.join(f'{line}\n' for line in lines), encoding='utf-8')

    def report(self, **env: 'str') -> 'tuple[str, str]':
        """As a run that publishes, the schedule's or a ``workflow_run``'s, unless ``env`` says otherwise."""
        return super().report(**{'PUBLISHES': 'true', **env})

    def test_a_build_only_run(self) -> None:
        """A manual run without ``publish``, for which ``mode`` wrote 'false'."""
        self.pins()
        for files_changed in ('true', 'false'):
            with self.subTest(files_changed=files_changed):
                text, _ = self.report(PUBLISHES='false', FILES_CHANGED=files_changed, BUMP=files_changed,
                                      CHANGED_FILES='conda/requirements.txt', PUSH='skipped')
                self.assertTrue(text.endswith('- Pushed: nothing, as a manual run only builds\n'), text)

    def test_a_forced_bump(self) -> None:
        """#2060: a manual run with ``publish``, bumped and pushed although nothing changed."""
        self.pins('pcapkit/_extern: 12 distributions')
        sha = 'f4f94bcad' + '0' * 31
        self.assertEqual(self.report(FILES_CHANGED='false', BUMP='true', PUSH='success', COMMIT=sha), (
            '### Conda Update\n\n- Platform pins: none moved, and none warned\n'
            '- Changed: nothing, and the build was bumped anyway, as a manual run with publish asks\n'
            f'- Pushed: build 4 as {sha}\n', 'success'))

    def test_a_quiet_run(self) -> None:
        self.pins('pcapkit/_extern: 12 distributions')
        self.assertEqual(self.report(FILES_CHANGED='false', PUSH='skipped'), (
            '### Conda Update\n\n- Platform pins: none moved, and none warned\n'
            '- Changed: nothing, so no build was bumped\n', 'success'))

    def test_a_pushed_bump_with_a_moved_pin(self) -> None:
        self.pins('::notice title=Platform pins::pyshark 0.6 -> 0.7 on osx-arm64, 100%25 sure%0Areview by 2027-01')
        sha = 'f4f94bcad' + '0' * 31
        self.assertEqual(self.report(FILES_CHANGED='true', CHANGED_FILES='conda/build conda/platform-pins.toml',
                                     PUSH='success', COMMIT=sha), (
            '### Conda Update\n\n- Platform pins:\n'
            '  - notice: pyshark 0.6 -> 0.7 on osx-arm64, 100% sure review by 2027-01\n'
            '- Changed: conda/build conda/platform-pins.toml\n'
            f'- Pushed: build 4 as {sha}\n', 'success'))

    def test_a_pin_warning_warns(self) -> None:
        self.pins('::warning title=Platform pins::PyPI could not be read for pyshark (503), so its pins stay')
        text, status = self.report(FILES_CHANGED='false', PUSH='skipped')
        self.assertIn('  - warning: PyPI could not be read for pyshark (503), so its pins stay\n', text)
        self.assertEqual(status, 'warning')

    def test_a_bump_not_pushed(self) -> None:
        self.pins()
        for push, line in (('success', "- Pushed: nothing; Push Changes' notice says why\n"),
                           ('failure', '- Pushed: nothing, as Push Changes failed\n'),
                           ('', '- Pushed: nothing, as the job stopped first\n')):
            with self.subTest(push=push):
                text, status = self.report(FILES_CHANGED='true', CHANGED_FILES='conda/build', PUSH=push)
                self.assertTrue(text.endswith(line), text)
                self.assertEqual(status, 'success')

    def test_a_job_that_stopped_before_the_refresh(self) -> None:
        self.assertEqual(self.report(), (
            '### Conda Update\n\n- Platform pins: not refreshed, as the job stopped first\n'
            '- Pushed: nothing, as the job stopped first\n', 'success'))


#: A plan as ``update_python_versions.py update --out`` writes it, cut to the keys the report reads.
PLAN = {
    'changed_files': ['.github/python-versions.toml', 'README.md'],
    'changes': [{'impl': 'cpython', 'version': '3.16', 'before': None,
                 'after': {'tier': 'experimental', 'runner': 'ubuntu-24.04'}, 'reason': 'beta 1 is out'},
                {'impl': 'cpython', 'version': '3.10', 'before': {'tier': 'supported'}, 'after': {'tier': 'ktlo'},
                 'reason': 'end of life'}],
    'latest': ['3.14', '3.15'],
    'required': {'remove': ['Python 3.10'], 'add': ['Python 3.10 (KTLO)']},
    'notes': [{'kind': 'held', 'text': '3.17 is a prerelease'}],
}


class TestThePythonVersionsReport(_ReportStep):
    """``detect``'s report, from the plan ``Recompute the tiers`` wrote."""

    workflow, job, file = VERSIONS, 'detect', 'python-versions-report.md'
    #: A run that proposes a change, for each test to vary.
    PROPOSED = {'UPDATE': 'success', 'CHANGED': 'true', 'PUBLISH': 'true', 'AUDIT': 'success', 'APP': 'true',
                'ON_MAIN': 'true'}

    def plan(self, **changes: 'Any') -> 'None':
        (self.temp / 'proposal').mkdir(exist_ok=True)
        (self.temp / 'proposal' / 'plan.json').write_text(json.dumps(dict(PLAN, **changes)), encoding='utf-8')

    def test_a_proposal(self) -> None:
        self.plan()
        self.assertEqual(self.report(**self.PROPOSED), (
            '### Python Versions\n\n- Tiers moved:\n'
            '  - `3.16`: -- -> experimental on `ubuntu-24.04` (beta 1 is out)\n'
            '  - `3.10`: supported -> KTLO (end of life)\n'
            '  - `latest`: 3.14 -> 3.15\n'
            '- Regenerated: `.github/python-versions.toml`, `README.md`\n'
            '- Ruleset 23497679, by hand: remove `Python 3.10`\n'
            '- Ruleset 23497679, by hand: add `Python 3.10 (KTLO)`\n'
            '- held: 3.17 is a prerelease\n'
            '- Audit: success\n'
            '- Pull request: the `pr` job opens or updates it once `github-release` is approved\n', 'success'))

    def test_a_quiet_week(self) -> None:
        self.plan(changed_files=[], changes=[], latest=['3.14', '3.14'], required={'remove': [], 'add': []},
                  notes=[])
        self.assertEqual(self.report(**{**self.PROPOSED, 'CHANGED': 'false', 'PUBLISH': 'false'}), (
            '### Python Versions\n\n- Tiers: unchanged\n- Audit: success\n'
            '- Pull request: none needed, as nothing changed\n', 'success'))

    def test_what_asks_for_a_hand_warns(self) -> None:
        manual = [{'kind': 'manual', 'text': 'README.md: no row for 3.16'}]
        for label, notes, env, line in (
                ('a manual note', manual, {}, '- manual: README.md: no row for 3.16\n'),
                ('a failed audit', [], {'AUDIT': 'failure'}, '- Audit: failure\n'),
                ('no App', [], {'APP': 'false'}, '- Pull request: none, as `vars.RELEASE_APP_CLIENT_ID` is unset\n'),
        ):
            with self.subTest(label):
                self.plan(notes=notes)
                text, status = self.report(**{**self.PROPOSED, **env})
                self.assertIn(line, text)
                self.assertEqual(status, 'warning')

    def test_why_no_pull_request_opens(self) -> None:
        self.plan()
        for env, line in (({'PUBLISH': 'false'}, 'none, as `bot/python-versions` already proposes these tiers'),
                          ({'UPDATE': 'failure', 'PUBLISH': 'false'}, 'none, as Recompute the tiers failed'),
                          ({'ON_MAIN': 'false'}, 'none, as this run is not on `main`')):
            with self.subTest(**env):
                text, status = self.report(**{**self.PROPOSED, **env})
                self.assertTrue(text.endswith(f'- Pull request: {line}\n'), text)
                self.assertEqual(status, 'success')

    def test_a_job_that_stopped_before_the_plan(self) -> None:
        self.assertEqual(self.report(UPDATE='failure'), (
            '### Python Versions\n\n- Tiers: not computed, as the job stopped first\n- Audit: not run\n'
            '- Pull request: none, as Recompute the tiers failed\n', 'success'))


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

    def run_step(self, name: 'str', artifact: 'Optional[str]', **env: 'str') -> 'tuple[str, str]':
        """The ``--status`` the step passed, and the report it handed over."""
        _, _, title, _, file = next(poster for poster in POSTERS if poster[0] == name)
        work = self.root / 'work'
        shutil.rmtree(work, ignore_errors=True)
        (work / 'report').mkdir(parents=True)
        if artifact is not None:
            (work / 'report' / file).write_text(artifact, encoding='utf-8')
        script = self.root / 'step.sh'
        script.write_text(step(name, 'discussion', 'Post the report to Discussions')['run'], encoding='utf-8')
        env = dict(env, PATH=f'{self.bin}{os.pathsep}{os.environ.get("PATH", "")}', FAKE_PYTHON_LOG=str(self.log),
                   REPORT_CATEGORY=CATEGORY)
        result = subprocess.run(bash_argv('-e', str(script), executable=str(BASH)),  # nosec: B603
                                cwd=work, env=env, capture_output=True, text=True, check=False, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        logged = json.loads(self.log.read_text(encoding='utf-8'))
        args = logged['args']
        self.assertEqual(args[:7], ['util/discussion_report.py', '--category', CATEGORY, '--title', title,
                                    '--report', f'report/{file}'])
        self.assertEqual(args[7:9], ['--mode', env.get('MODE', 'scheduled')])
        self.assertEqual(args[9], '--status')
        return args[10], logged['report']

    def test_a_failed_conda_gate_posts_a_report_of_its_own(self) -> None:
        for head in ('failure', 'cancelled'):
            with self.subTest(head=head):
                self.assertEqual(self.run_step(CONDA, None, MODE='push', HEAD_RESULT=head, UPDATE_RESULT='skipped',
                                               TAG_RESULT='skipped', DIST_RESULT='skipped'), (head, (
                    '### Conda Update\n\n'
                    f'- Gate: {head}, so conda-update did not run and nothing was built or pushed\n')))

    def test_the_conda_status_and_the_tag_and_upload(self) -> None:
        # `(conda-update, its status, conda-tag, conda-dist, --status, lines added)`.
        tagged = '- Tag: success\n- Upload: '
        for update, status, tag, dist, expected, added in (
                ('success', 'success', 'skipped', 'skipped', 'success', ''),
                ('success', 'warning', 'skipped', 'skipped', 'warning', ''),
                ('success', '', 'skipped', 'skipped', 'success', ''),
                ('success', 'success', 'success', 'success', 'success', tagged + 'success\n'),
                ('success', 'warning', 'success', 'failure', 'failure', tagged + 'failure\n'),
                ('success', 'success', 'failure', 'skipped', 'failure', '- Tag: failure\n- Upload: skipped\n'),
                ('success', 'warning', 'success', 'cancelled', 'cancelled', tagged + 'cancelled\n'),
                ('failure', 'warning', 'skipped', 'skipped', 'failure', ''),
                ('cancelled', '', 'skipped', 'skipped', 'cancelled', ''),
        ):
            with self.subTest(update=update, status=status, tag=tag, dist=dist):
                self.assertEqual(self.run_step(CONDA, 'the run\n', MODE='scheduled', HEAD_RESULT='success',
                                               UPDATE_RESULT=update, UPDATE_STATUS=status, TAG_RESULT=tag,
                                               DIST_RESULT=dist), (expected, 'the run\n' + added))

    def test_the_versions_status(self) -> None:
        for result, status, expected in (('success', 'success', 'success'), ('success', 'warning', 'warning'),
                                         ('success', '', 'success'), ('failure', 'warning', 'failure'),
                                         ('cancelled', '', 'cancelled')):
            with self.subTest(result=result, status=status):
                self.assertEqual(self.run_step(VERSIONS, 'the week\n', DETECT_RESULT=result, DETECT_STATUS=status),
                                 (expected, 'the week\n'))


if __name__ == '__main__':
    unittest.main()
