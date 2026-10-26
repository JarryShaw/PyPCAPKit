# -*- coding: utf-8 -*-
"""#2060: a manual Conda Update run with ``publish`` bumps and publishes.

The owner's ruling took the recommendation: a ``publish`` input on Conda
Update's manual run, accepted on ``main`` only, that enters the ``conda-tag``
and ``anaconda`` environments and forces a build bump, so the run uploads every
platform -- 1.5.0b14's ``win-64`` and ``osx-64`` files among them -- even when
:file:`util/conda_vendor.py` regenerates the same recipe. Without it a manual
run stays build-only, which :mod:`tests.project.test_build_only_dispatch` pins.

* :class:`TestThePublishInput`: the input is a boolean, ``false`` by default.
* :class:`TestTheModeJob`: ``mode`` is the one job reading the input. Its step,
  run as ``bash`` runs it, writes ``publishes`` 'true' on the schedule, a
  ``workflow_run`` and a manual run with ``publish`` on ``main``, and 'false' on
  any other manual run; with ``publish`` on another ref it fails with an
  ``::error``, and nothing after it runs.
* :class:`TestAPublishingManualRun`: on such a run every job and step that
  pushes, tags, uploads or posts runs, as on the schedule, every
  ``conda-dist`` leg uploads, each job enters its environment, and
  ``conda-update`` joins ``repository-maintenance``; on a manual run without
  ``publish`` none of them does.
* :class:`TestTheBumpIsForced`: ``Decide whether to bump`` says 'true' on such a
  run although no file changed, and Bump Version, Commit Changes and Push
  Changes follow it.
* :class:`TestAnUnpushedForcedBumpSaysSo` and
  :class:`TestTheReportOfAnUnpushedForcedBump`: where Push Changes does not
  push a forced bump, which no later run repeats, it warns that nothing was
  published and to dispatch again, and the report says so too; every other
  run's notice is the ordinary one.

"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess  # nosec: B404
import tempfile
import unittest
from typing import TYPE_CHECKING

from tests import _workflows
from tests._workflows import WORKFLOWS
from tests.project.test_build_only_dispatch import MARKERS
from tests.project.test_cron_reports_2030 import _ReportStep
from tests.project.test_release_gates import (_RUN_LITERAL, NULL, STATUS, CondaStepHarness, block_scalar_after,
                                              conda_context, evaluate_condition, evaluate_expression, job_blocks,
                                              job_runs, step_block)

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): reads the workflow file, and runs its steps' shell offline.
__tier__ = 'LATEST'

CONDA = 'cron-conda.yml'
DISPATCH = 'workflow_dispatch'
#: The ``bash`` the steps run under, by absolute path, as tests/test_tier_guard.py finds it (#2103).
BASH = shutil.which('bash')
#: Every step that publishes, by job, as the schedule runs them on some leg.
PUBLISHERS = {
    'conda-update': ['Load maintenance deploy key', 'Push Changes'],
    'conda-tag': ['Load maintenance deploy key', 'Checkout code', 'Push Tag'],
    'conda-dist': ['Upload conda packages to Anaconda', 'Upload conda packages to Anaconda (Intel)',
                   'Upload conda packages to Anaconda (Windows)', 'Check the GitHub release exists',
                   'Upload package to GitHub Release'],
    'discussion': ['Post the report to Discussions'],
}
#: The steps that bump, and the one that hands the build on.
BUMP_STEPS = ('Bump Version', 'Commit Changes', 'Push Changes', 'Get Version')
#: The steps only a build-only run takes, which hand ``conda-dist`` the unpushed tree.
BUILD_ONLY_STEPS = {'conda-update': ('Save the changes for conda-dist', 'Upload the changes for conda-dist'),
                    'conda-dist': ('checkout-dispatched', 'download-changes', 'apply-changes')}


def name_of(entry: 'dict[str, Any]') -> 'str':
    return str(entry.get('name') or entry.get('id') or entry.get('uses'))


def step(job_id: 'str', label: 'str') -> 'dict[str, Any]':
    """The one step of ``job_id`` whose name, or else id, is ``label``."""
    [found] = [entry for entry in _workflows.steps(CONDA, job_id) if label in (entry.get('name'), entry.get('id'))]
    return found


def context(event_name: 'str', publishes: 'object', os_label: 'str' = 'ubuntu-latest',
            bump: 'str' = 'true') -> 'dict[str, Any]':
    """A step's context: ``mode`` said ``publishes``, every earlier step succeeded, the release exists."""
    return {'github': {'event_name': event_name, 'ref': 'refs/heads/main', 'ref_name': 'main'},
            'matrix': {'os': os_label},
            'needs': {'mode': {'result': 'success' if publishes is not NULL else 'failure',
                               'outputs': {} if publishes is NULL else {'publishes': publishes}},
                      'conda-update': {'result': 'success'}},
            'steps': {'verify-changed-files': {'outputs': {'files_changed': 'false'}},
                      'bump': {'outputs': {'bump': bump}},
                      'release': {'outputs': {'published': 'true'}},
                      'conda_build': {'outcome': 'success'}},
            STATUS: {'cancelled': False}}


def step_runs(job_id: 'str', label: 'str', scope: 'dict[str, Any]') -> 'bool':
    return evaluate_condition(str(step(job_id, label).get('if', 'true')), scope)


def legs() -> 'list[str]':
    return list(_workflows.job(CONDA, 'conda-dist')['strategy']['matrix']['os'])


def environment(job_id: 'str', publishes: 'object') -> 'object':
    value = _workflows.job(CONDA, job_id).get('environment', '')
    return evaluate_expression(value, context(DISPATCH, publishes)) if '${{' in value else value


def manual_run(publishes: 'object', **changes: 'Any') -> 'dict[str, object]':
    """:func:`conda_context` for a manual run whose ``mode`` wrote ``publishes``, nothing changed."""
    if publishes == 'true':
        changes = {'bump': 'true', **changes}
    else:
        changes = {'pushed': NULL, 'conda_tag': 'skipped', **changes}
    return conda_context(event_name=DISPATCH, unit_tests='success', verdict='skipped', verified=NULL,
                         publishes=publishes, files_changed='false', **changes)


class TestThePublishInput(unittest.TestCase):

    def test_it_is_a_boolean_off_by_default(self) -> None:
        inputs = _workflows.load(CONDA)['on'][DISPATCH]['inputs']
        self.assertEqual(sorted(inputs), ['publish'])
        publish = inputs['publish']
        self.assertEqual(publish['type'], 'boolean')
        self.assertIs(publish['default'], False)
        self.assertIs(publish['required'], False)
        self.assertIn('main', publish['description'])

    def test_only_mode_reads_it(self) -> None:
        """Every other job reads ``mode``'s verdict, so the input has one reading."""
        for job_id, job in _workflows.load(CONDA)['jobs'].items():
            with self.subTest(job=job_id):
                self.assertEqual('inputs.' in repr(job), job_id == 'mode')
        self.assertEqual(step('mode', 'Decide whether this run publishes')['env'], {'PUBLISH': '${{ inputs.publish }}'})


@unittest.skipIf(not BASH, 'needs bash on PATH')
class TestTheModeJob(unittest.TestCase):
    """``Decide whether this run publishes``, run in a scratch directory."""

    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix='pcapkit-2060-mode-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.script = self.tmp / 'step.sh'
        self.script.write_text(step('mode', 'Decide whether this run publishes')['run'], encoding='utf-8')
        self.output = self.tmp / 'output'

    def decide(self, event_name: 'str', publish: 'str' = '',
               ref: 'str' = 'refs/heads/main') -> 'tuple[int, str, str]':
        """The step's exit status, what it wrote to ``GITHUB_OUTPUT``, and its stdout."""
        self.output.write_text('', encoding='utf-8')
        env = {'PATH': os.environ.get('PATH', ''), 'GITHUB_OUTPUT': str(self.output),
               'GITHUB_EVENT_NAME': event_name, 'GITHUB_REF': ref, 'PUBLISH': publish}
        result = subprocess.run([str(BASH), '-e', str(self.script)], cwd=self.tmp, env=env,  # nosec: B603
                                capture_output=True, text=True, check=False, timeout=60)
        return result.returncode, self.output.read_text(encoding='utf-8'), result.stdout

    def test_every_other_event_publishes(self) -> None:
        for event_name in ('schedule', 'workflow_run'):
            with self.subTest(event=event_name):
                self.assertEqual(self.decide(event_name)[:2], (0, 'publishes=true\n'))

    def test_a_manual_run_without_publish_builds_only(self) -> None:
        """On any ref, so a branch's run is still build-only."""
        for publish in ('', 'false'):
            for ref in ('refs/heads/main', 'refs/heads/feat/x'):
                with self.subTest(publish=publish, ref=ref):
                    self.assertEqual(self.decide(DISPATCH, publish, ref)[:2], (0, 'publishes=false\n'))

    def test_a_manual_run_with_publish_on_main_publishes(self) -> None:
        status, output, stdout = self.decide(DISPATCH, 'true')
        self.assertEqual((status, output), (0, 'publishes=true\n'))
        self.assertIn('::notice title=Publishing manual run::', stdout)

    def test_a_manual_run_with_publish_elsewhere_is_refused(self) -> None:
        for ref in ('refs/heads/feat/2060', 'refs/tags/v1.5.0b14', 'refs/heads/mainline'):
            with self.subTest(ref=ref):
                status, output, stdout = self.decide(DISPATCH, 'true', ref)
                self.assertEqual((status, output), (1, ''))
                self.assertIn(f'::error title=publish is for main only::{ref} was dispatched', stdout)

    def test_a_refused_run_runs_nothing_after_it(self) -> None:
        """``mode`` failed and wrote nothing, so ``conda-update`` skips and nothing posts."""
        jobs = job_blocks((WORKFLOWS / CONDA).read_text(encoding='utf-8'))
        scope = conda_context(event_name=DISPATCH, unit_tests='success', verdict='skipped', verified=NULL,
                              mode='failure', conda_update='skipped', conda_tag='skipped',
                              conda_dist='skipped', outputs_present=False)
        for job_id in ('conda-update', 'conda-tag', 'conda-dist', 'discussion'):
            with self.subTest(job=job_id):
                self.assertFalse(job_runs(jobs, job_id, scope))
        for job_id in ('conda-update', 'conda-dist'):
            with self.subTest(job=job_id):
                self.assertEqual(environment(job_id, NULL), '')

    def test_it_skips_only_a_pull_requests_run(self) -> None:
        condition = _workflows.job(CONDA, 'mode')['if']
        for event_name, event, expected in (('schedule', None, True), (DISPATCH, None, True),
                                            ('workflow_run', 'push', True), ('workflow_run', 'pull_request', False)):
            scope = {'github': {'event_name': event_name,
                                'event': {'workflow_run': {'event': event}} if event else {}}}
            with self.subTest(event=event_name, workflow_run=event):
                self.assertIs(evaluate_condition(condition, scope), expected)
        self.assertEqual(_workflows.job(CONDA, 'mode')['permissions'], {})


class TestAPublishingManualRun(unittest.TestCase):
    """What a manual run with ``publish`` on ``main`` runs, against one without it."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.jobs = job_blocks((WORKFLOWS / CONDA).read_text(encoding='utf-8'))

    def test_the_known_publishers_are_the_scan(self) -> None:
        """Not vacuous: :data:`PUBLISHERS` is every step the build-only scan calls publishing."""
        for job_id, labels in PUBLISHERS.items():
            found = [name_of(entry) for entry in _workflows.steps(CONDA, job_id)
                     if any(marker in repr(entry) for marker in MARKERS)]
            with self.subTest(job=job_id):
                self.assertEqual(found, labels)

    def test_every_publishing_job_runs(self) -> None:
        for job_id in ('conda-update', 'conda-tag', 'conda-dist', 'discussion'):
            with self.subTest(job=job_id):
                self.assertTrue(job_runs(self.jobs, job_id, manual_run('true')))
                self.assertIs(job_runs(self.jobs, job_id, manual_run('false')),
                              job_id in ('conda-update', 'conda-dist'))

    def reachable(self, job_id: 'str', label: 'str', publishes: 'str') -> 'bool':
        """Whether the step runs on some leg: its job runs, and then its own ``if:`` holds."""
        if not job_runs(self.jobs, job_id, manual_run(publishes)):
            return False
        return any(step_runs(job_id, label, context(DISPATCH, publishes, os_label)) for os_label in legs())

    def test_every_publishing_step_runs(self) -> None:
        for job_id, labels in PUBLISHERS.items():
            for label in labels:
                with self.subTest(job=job_id, step=label):
                    self.assertTrue(self.reachable(job_id, label, 'true'))
                    self.assertFalse(self.reachable(job_id, label, 'false'))

    def test_every_leg_uploads(self) -> None:
        """Intel and Windows included, which is what 1.5.0b14 lacks."""
        uploads = [label for label in PUBLISHERS['conda-dist'] if label.startswith('Upload conda packages')]
        for os_label in legs():
            with self.subTest(os=os_label):
                self.assertEqual(sum(step_runs('conda-dist', label, context(DISPATCH, 'true', os_label))
                                     for label in uploads), 1)
                self.assertEqual(sum(step_runs('conda-dist', label, context(DISPATCH, 'false', os_label))
                                     for label in uploads), 0)
        self.assertLessEqual({'macos-26-intel', 'windows-latest'}, set(legs()))

    def test_conda_dist_checks_out_the_tag(self) -> None:
        """Not the dispatched commit with a patch, which only a build-only run hands on."""
        self.assertTrue(step_runs('conda-dist', 'checkout', context(DISPATCH, 'true')))
        for job_id, labels in BUILD_ONLY_STEPS.items():
            for label in labels:
                with self.subTest(job=job_id, step=label):
                    self.assertFalse(step_runs(job_id, label, context(DISPATCH, 'true')))
                    self.assertTrue(step_runs(job_id, label, context(DISPATCH, 'false')))
                    self.assertFalse(step_runs(job_id, label, context('schedule', 'true')))

    def test_each_job_enters_its_environment(self) -> None:
        for job_id, name in (('conda-update', 'conda-tag'), ('conda-tag', 'conda-tag'), ('conda-dist', 'anaconda')):
            with self.subTest(job=job_id):
                self.assertEqual(environment(job_id, 'true'), name)
                if job_id != 'conda-tag':
                    self.assertEqual(environment(job_id, 'false'), '')

    def test_conda_update_joins_the_write_serialisation(self) -> None:
        group = _workflows.job(CONDA, 'conda-update')['concurrency']['group']
        group = re.sub(r"format\('([^'{]*)\{0\}',\s*github\.run_id\)", r"'\g<1>7'", group)
        for publishes, expected in (('true', 'repository-maintenance'), ('false', 'repository-maintenance-7')):
            with self.subTest(publishes=publishes):
                self.assertEqual(evaluate_expression(group, context(DISPATCH, publishes)), expected)
        # The same group as the schedule's, and Vendor Update's.
        self.assertEqual(evaluate_expression(group, context('schedule', 'true')), 'repository-maintenance')

    def test_the_report_posts_as_the_schedule_does(self) -> None:
        mode = step('discussion', 'Post the report to Discussions')['env']['MODE']
        self.assertEqual(evaluate_expression(mode, {'github': {'event_name': DISPATCH}}), 'scheduled')


class TestTheBumpIsForced(unittest.TestCase):
    """A manual run with ``publish`` bumps when Verify Changed files saw nothing."""

    def test_forced_on_a_publishing_manual_run_only(self) -> None:
        forced = step('conda-update', 'Decide whether to bump')['env']['FORCED']
        for event_name, publishes, expected in ((DISPATCH, 'true', True), (DISPATCH, 'false', False),
                                                ('schedule', 'true', False), ('workflow_run', 'true', False)):
            with self.subTest(event=event_name, publishes=publishes):
                self.assertIs(evaluate_expression(forced, context(event_name, publishes)), expected)

    def test_it_sits_between_the_check_and_the_bump(self) -> None:
        names = [name_of(entry) for entry in _workflows.steps(CONDA, 'conda-update')]
        self.assertEqual(names.index('Decide whether to bump'), names.index('Verify Changed files') + 1)
        self.assertEqual(names.index('Bump Version'), names.index('Decide whether to bump') + 1)
        self.assertEqual(step('conda-update', 'Decide whether to bump')['id'], 'bump')

    @unittest.skipIf(not BASH, 'needs bash on PATH')
    def test_the_decision(self) -> None:
        script = step('conda-update', 'Decide whether to bump')['run']
        with tempfile.TemporaryDirectory(prefix='pcapkit-2060-bump-') as tmp:
            output = pathlib.Path(tmp) / 'output'
            for files_changed, forced, expected in (('false', 'true', 'true'), ('false', 'false', 'false'),
                                                    ('true', 'false', 'true'), ('', 'false', 'false')):
                output.write_text('', encoding='utf-8')
                env = {'PATH': os.environ.get('PATH', ''), 'GITHUB_OUTPUT': str(output),
                       'FILES_CHANGED': files_changed, 'FORCED': forced}
                result = subprocess.run([str(BASH), '-e', '-c', script], cwd=tmp, env=env,  # nosec: B603
                                        capture_output=True, text=True, check=False, timeout=60)
                with self.subTest(files_changed=files_changed, forced=forced):
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(output.read_text(encoding='utf-8'), f'bump={expected}\nforced={forced}\n')

    def test_the_bump_steps_follow_it(self) -> None:
        for label in BUMP_STEPS:
            with self.subTest(step=label):
                self.assertTrue(step_runs('conda-update', label, context(DISPATCH, 'true', bump='true')))
                self.assertFalse(step_runs('conda-update', label, context('schedule', 'true', bump='false')))
        # A build-only run still bumps on a change, and pushes nothing.
        self.assertTrue(step_runs('conda-update', 'Bump Version', context(DISPATCH, 'false', bump='true')))
        self.assertFalse(step_runs('conda-update', 'Push Changes', context(DISPATCH, 'false', bump='true')))

    def test_the_commit_says_why_nothing_else_changed(self) -> None:
        self.assertIn('${CHANGED_FILES:-none, as a manual run with publish bumps regardless}',
                      step('conda-update', 'Commit Changes')['run'])

    def test_push_changes_and_the_report_are_told_it_was_forced(self) -> None:
        """Through ``env:``, from the bump step's own ``forced``, not re-derived in the script."""
        for label in ('Push Changes', 'Write the run report'):
            with self.subTest(step=label):
                self.assertEqual(step('conda-update', label)['env']['FORCED'], '${{ steps.bump.outputs.forced }}')


#: Push Changes' "not pushed" notices, and the warning each becomes on a forced bump.
MOVED_PAST = ('::notice title=Not pushed as main moved past this checkout::',
              '::warning title=Nothing published as main moved past this checkout::')
MOVED_DURING = ('::notice title=Not pushed as main moved during the push::',
                '::warning title=Nothing published as main moved during the push::')
ALREADY = ('::notice title=Build already on main::',
           '::warning title=Nothing published as the build is already on main::')
#: What every forced warning says, and what a moved ``main``'s adds.
NOTHING = 'nothing was published'
AGAIN = 'dispatch Conda Update again with publish on main'


class TestAnUnpushedForcedBumpSaysSo(CondaStepHarness, unittest.TestCase):
    """Push Changes, run against a local origin, on a forced bump it does not push.

    No later run repeats a forced bump, so the notice that leaves the bump to the
    next Conda Update would be wrong: the run ends green having published
    nothing. Each path warns instead and says to dispatch again; with no forced
    bump, each notice is the ordinary one, byte for byte.

    """

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.script = block_scalar_after(step_block(cls.jobs['conda-update'], 'Push Changes'),  # type: ignore[attr-defined]
                                        _RUN_LITERAL)

    def lines(self, stdout: 'str', prefix: 'str') -> 'list[str]':
        return [line for line in stdout.splitlines() if line.startswith(prefix)]

    def moved_past(self, forced: 'str') -> 'tuple[str, str]':
        """A merge with no verdict lands before the push: the step's stdout, and the merge."""
        clone = self._clone('first')
        merge = self._land('merge', {'pcapkit/toolkit/scapy.py': 'fix\n'},
                           'fix(toolkit): a merge', (self.HUMAN, self.GITHUB))
        self._bump(clone, {})
        result, outputs = self._bash(self.script, clone, {'FORCED': forced})  # type: ignore[attr-defined]
        self.assertEqual((result.returncode, outputs), (0, {'pushed': 'false'}), result.stderr)
        return result.stdout, merge

    def moved_during(self, forced: 'str') -> 'tuple[str, str, str]':
        """A merge lands after the fetch: the step's stdout, the merge, and the bump."""
        clone = self._clone('first')
        merge, env = self._land_after_fetch('merge', {'pcapkit/toolkit/scapy.py': 'fix\n'},
                                            'fix(toolkit): a merge', (self.HUMAN, self.GITHUB))
        self._bump(clone, {})
        result, outputs = self._bash(self.script, clone, {**env, 'FORCED': forced})  # type: ignore[attr-defined]
        self.assertTrue((self.root / 'fired').exists(), 'the merge never raced the fetch')
        self.assertEqual((result.returncode, outputs), (0, {'pushed': 'false'}), result.stderr)
        return result.stdout, merge, self._git(clone, 'rev-parse', 'HEAD')

    def already(self, forced: 'str') -> 'str':
        """Another run from the same checkout pushed the same build first: the step's stdout.

        On a forced bump this is two manual runs with ``publish`` dispatched on
        one commit, or one beside a scheduled bump: the rebase drops the second.

        """
        first, second = self._clone('first'), self._clone('second')
        for clone in (first, second):
            self._bump(clone, {})
        self.assertEqual(self._bash(self.script, first, {})[1].get('pushed'), 'true')  # type: ignore[attr-defined]
        result, outputs = self._bash(self.script, second, {'FORCED': forced})  # type: ignore[attr-defined]
        self.assertEqual((result.returncode, outputs), (0, {'pushed': 'false'}), result.stderr)
        return result.stdout

    def test_moved_past_the_checkout_forced(self) -> None:
        stdout, merge = self.moved_past('true')
        self.assertEqual(self.lines(stdout, MOVED_PAST[0]), [])
        [line] = self.lines(stdout, MOVED_PAST[1])
        self.assertIn(NOTHING, line)
        self.assertTrue(line.endswith(f'{AGAIN}, now at {merge}.'), line)

    def assert_unforced_moved_past(self, forced: 'str') -> None:
        stdout, merge = self.moved_past(forced)
        self.assertEqual(self.lines(stdout, MOVED_PAST[1]), [])
        [line] = self.lines(stdout, MOVED_PAST[0])
        self.assertTrue(line.endswith(f" The bump is left to the Conda Update that {merge}'s own Unit "
                                      f'Tests run raises.'), line)

    def test_moved_past_the_checkout_unforced(self) -> None:
        self.assert_unforced_moved_past('false')

    def test_moved_past_the_checkout_unset(self) -> None:
        """An empty ``forced``, as a step that never ran leaves it, is not forced."""
        self.assert_unforced_moved_past('')

    def test_moved_during_the_push_forced(self) -> None:
        stdout, merge, commit = self.moved_during('true')
        self.assertEqual(self.lines(stdout, MOVED_DURING[0]), [])
        self.assertEqual(self.lines(stdout, MOVED_DURING[1]), [
            f'{MOVED_DURING[1]}main moved from {self.base} to {merge} after the fetch, so {commit} is not a '
            f'fast-forward. No later run repeats this forced bump, so {NOTHING}: {AGAIN}, now at {merge}.'])

    def test_moved_during_the_push_unforced(self) -> None:
        stdout, merge, commit = self.moved_during('false')
        self.assertEqual(self.lines(stdout, MOVED_DURING[1]), [])
        self.assertEqual(self.lines(stdout, MOVED_DURING[0]), [
            f'{MOVED_DURING[0]}main moved from {self.base} to {merge} after the fetch, so {commit} is not a '
            f"fast-forward. The bump is left to the Conda Update that {merge}'s own Unit Tests run raises."])

    def test_already_on_main_forced(self) -> None:
        """The run that pushed the build tags and uploads it, so dispatching again is only if it did not."""
        stdout = self.already('true')
        self.assertEqual(self.lines(stdout, ALREADY[0]), [])
        self.assertEqual(self.lines(stdout, ALREADY[1]), [
            f'{ALREADY[1]}conda/build 3 was pushed by another run, which tags and uploads it, so this run '
            f'published nothing; if that run did not publish it, {AGAIN}'])

    def test_already_on_main_unforced(self) -> None:
        stdout = self.already('false')
        self.assertEqual(self.lines(stdout, ALREADY[1]), [])
        self.assertEqual(self.lines(stdout, ALREADY[0]), [
            f'{ALREADY[0]}conda/build 3 was pushed by another run; nothing to push, tag or upload'])


class TestTheReportOfAnUnpushedForcedBump(_ReportStep):
    """Write the run report, on a forced bump Push Changes did not push: it says so, and warns."""

    workflow, job, file = CONDA, 'conda-update', 'conda-report.md'

    def setUp(self) -> None:
        super().setUp()
        (self.work / 'conda').mkdir()
        (self.work / 'conda' / 'build').write_text('4\n', encoding='utf-8')
        (self.temp / 'platform-pins.log').write_text('', encoding='utf-8')

    def test_it_says_nothing_was_published(self) -> None:
        text, status = self.report(PUBLISHES='true', FILES_CHANGED='false', BUMP='true', FORCED='true',
                                   PUSH='success')
        self.assertTrue(text.endswith("- Pushed: nothing, so this manual run with publish published nothing; "
                                      "Push Changes' warning says why, and when to dispatch it again\n"), text)
        self.assertEqual(status, 'warning')

    def test_a_pushed_forced_bump_is_a_success(self) -> None:
        text, status = self.report(PUBLISHES='true', FILES_CHANGED='false', BUMP='true', FORCED='true',
                                   PUSH='success', COMMIT='f' * 40)
        self.assertTrue(text.endswith(f'- Pushed: build 4 as {"f" * 40}\n'), text)
        self.assertEqual(status, 'success')

    def test_an_unforced_bump_not_pushed_points_at_the_push_notice(self) -> None:
        text, status = self.report(PUBLISHES='true', FILES_CHANGED='true', CHANGED_FILES='conda/build',
                                   BUMP='true', FORCED='false', PUSH='success')
        self.assertTrue(text.endswith("- Pushed: nothing; Push Changes' notice says why\n"), text)
        self.assertEqual(status, 'success')


if __name__ == '__main__':
    unittest.main()
