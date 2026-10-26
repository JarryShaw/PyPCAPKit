# -*- coding: utf-8 -*-
"""A scheduled workflow can be started by hand, and a manual run publishes nothing.

The maintainer asked for build-only manual triggers on the scheduled workflows,
so that one can be debugged without waiting for its schedule. So:

* :class:`TestEveryScheduledWorkflowCanBeStarted`: each workflow with a
  ``schedule:`` has ``workflow_dispatch:``, except those in :data:`EXEMPT`,
  which run on every push and pull request already.
* :class:`TestAManualRunPublishesNothing`: in each of :data:`BUILD_ONLY`, every
  step that pushes, tags, uploads, deploys, posts or reads a secret is
  unreachable on ``workflow_dispatch``. Read conservatively: the step's own
  ``if:``, or its job's, has to hold ``github.event_name != 'workflow_dispatch'``
  as a top-level ``&&`` conjunct, which makes it false whatever else is true --
  or, in Conda Update, ``needs.mode.outputs.publishes == 'true'``, which its
  ``mode`` job writes 'false' on a manual run without ``publish`` (#2060). A
  job that still runs names no environment, and no run joins a concurrency
  group a real run waits in. :mod:`tests.project.test_conda_publish_dispatch_2060`
  covers a manual Conda Update run with ``publish``.
* :class:`TestAManualRunStillBuilds`: the jobs and steps that build and test
  run on a manual run as they do on the schedule.
* :class:`TestCreateReleaseIgnoresAManualVendorUpdate`: Create Release, which
  every completed Vendor Update raises, releases nothing for a manual one.

The other scheduled workflows with ``workflow_dispatch``, Lint, Project Status,
CI Timing, Python Versions and Engine Benchmark, run in full on a manual run, and
are not in :data:`BUILD_ONLY`.

"""

from __future__ import annotations

import os
import re
import subprocess  # nosec: B404
import sys
import unittest
from typing import TYPE_CHECKING

from tests import _workflows
from tests._workflows import WORKFLOWS
from tests.project.test_release_gates import (NULL, STATUS, conda_context, declared_if, evaluate_condition,
                                              evaluate_expression, job_blocks, job_runs)
from tests.project.test_release_status_scripts_1967 import SKIPPED_CHECK, STATUS_BASE

if TYPE_CHECKING:
    from typing import Any, Optional

#: Test tier (#1958): reads the workflow files, a question about the tree.
__tier__ = 'LATEST'

DISPATCH = 'workflow_dispatch'
#: The guard each publishing step or job carries, whitespace removed.
GUARD = "github.event_name!='workflow_dispatch'"
#: Conda Update's form of it (#2060): its `mode` job's verdict, which is 'false'
#: on a manual run without `publish`, as test_conda_publish_dispatch_2060.py runs it to show.
PUBLISH_GUARD = "needs.mode.outputs.publishes=='true'"
#: Each guard's own text, for the scan that strips them.
_GUARDS = re.compile(r"(github\.event_name != 'workflow_dispatch'|needs\.mode\.outputs\.publishes == 'true')"
                     r"(\s*&&\s*)?")
#: Scheduled workflows with no manual run, and why none is needed.
EXEMPT = {
    'codeql-analysis.yml': 'runs on every push to main and every pull request',
    'python-compatibility.yml': 'runs on every push to main and every pull request',
}
#: The workflows whose manual run builds only.
BUILD_ONLY = ('cron-conda.yml', 'cron-vendor.yml', 'deploy-pages.yml')
#: What a step that publishes, or holds a credential, contains.
MARKERS = ('git push', 'webfactory/ssh-agent', 'anaconda/actions/upload-package', 'release_conda.py upload',
           'ncipollo/release-action', 'github-pages-deploy-action', 'discussion_report.py', 'gh release',
           'secrets.')
#: A job-level permission only a publishing job holds.
PUBLISHING_SCOPES = ('discussions', 'pages', 'id-token', 'packages', 'deployments')
#: The workflow-level ``concurrency:`` group, as one interpolation after a prefix.
_GROUP = re.compile(r'^concurrency:\n  group: (?P<prefix>[^$\n]*)\$\{\{(?P<body>[^}]*)\}\}\n', re.M)


def triggers(name: 'str') -> 'set[str]':
    on = _workflows.load(name)['on']
    return set(on) if isinstance(on, dict) else set(on if isinstance(on, list) else [on])


def scheduled() -> 'list[str]':
    """Every workflow file with a ``schedule:`` trigger."""
    return sorted(path.name for path in WORKFLOWS.glob('*.yml') if 'schedule' in triggers(path.name))


def conjuncts(condition: 'object') -> 'Optional[list[str]]':
    """``condition``'s top-level ``&&`` operands, whitespace removed; :data:`None` past a top-level ``||``."""
    text = re.sub(r'\s+', '', str(condition))
    if text.startswith('${{') and text.endswith('}}'):
        text = text[3:-2]
    parts, depth, quoted, start, index = [], 0, False, 0, 0
    while index < len(text):
        char = text[index]
        if char == "'":
            quoted = not quoted
        elif not quoted and char == '(':
            depth += 1
        elif not quoted and char == ')':
            depth -= 1
        elif not quoted and depth == 0 and text.startswith('||', index):
            return None
        elif not quoted and depth == 0 and text.startswith('&&', index):
            parts.append(text[start:index])
            start = index + 2
            index += 1
        index += 1
    parts.append(text[start:])
    return parts


def guarded(entry: 'dict[str, Any]') -> 'bool':
    """Whether ``entry``'s ``if:`` is false on a manual run, whatever else holds."""
    return bool({GUARD, PUBLISH_GUARD} & set(conjuncts(entry['if']) or [])) if 'if' in entry else False


def publishes(entry: 'dict[str, Any]') -> 'bool':
    text = repr(entry)
    return any(marker in text for marker in MARKERS)


def exposed(workflow: 'dict[str, Any]') -> 'list[str]':
    """Each publishing job or step of ``workflow`` a manual run could reach."""
    found = []
    for job_id, job in workflow['jobs'].items():
        if guarded(job):
            continue
        scopes = job.get('permissions') or {}
        if isinstance(scopes, dict) and any(scopes.get(scope) == 'write' for scope in PUBLISHING_SCOPES):
            found.append(job_id)
        found.extend(f'{job_id}: {step.get("name") or step.get("id") or step.get("uses")}'
                     for step in job.get('steps') or [] if publishes(step) and not guarded(step))
    return found


def mode_context(event_name: 'str') -> 'dict[str, Any]':
    """``github`` and Conda Update's ``mode`` output on ``event_name``, ``publish`` unset."""
    publishes = 'false' if event_name == DISPATCH else 'true'
    return {'github': {'event_name': event_name}, 'needs': {'mode': {'outputs': {'publishes': publishes}}}}


def job_group(group: 'str', event_name: 'str', run_id: 'str') -> 'str':
    """A job's ``concurrency:`` group on ``event_name``, each ``${{ }}`` in it evaluated.

    ``format('<prefix>{0}', github.run_id)`` is read as the string it makes, as
    the evaluator models no ``format``.

    """
    context = mode_context(event_name)
    context['github'] = {**context['github'], 'run_id': run_id, 'ref': 'refs/heads/main'}
    group = re.sub(r"format\('([^'{]*)\{0\}',\s*github\.run_id\)", lambda match: f"'{match.group(1)}{run_id}'",
                   group)
    return re.sub(r'\$\{\{(.*?)\}\}', lambda match: str(evaluate_expression('${{' + match.group(1) + '}}', context)),
                  group)


def dispatch_environment(job: 'dict[str, Any]', event_name: 'str' = DISPATCH) -> 'object':
    value = job.get('environment', '')
    if isinstance(value, dict):
        value = value.get('name', '')
    return evaluate_expression(value, mode_context(event_name)) if '${{' in value else value


class TestEveryScheduledWorkflowCanBeStarted(unittest.TestCase):

    def test_the_scan_finds_the_scheduled_workflows(self) -> None:
        self.assertLessEqual({*BUILD_ONLY, *EXEMPT, 'cron-python-versions.yml', 'ci-timing.yml'}, set(scheduled()))

    def test_each_has_a_manual_run(self) -> None:
        for name in scheduled():
            if name in EXEMPT:
                continue
            with self.subTest(workflow=name):
                self.assertIn(DISPATCH, triggers(name), f'{name} runs on a schedule and cannot be started by hand')

    def test_each_exemption_still_runs_on_every_change(self) -> None:
        for name in EXEMPT:
            with self.subTest(workflow=name):
                self.assertLessEqual({'push', 'pull_request', 'schedule'}, triggers(name))


class TestAManualRunPublishesNothing(unittest.TestCase):

    def test_no_publisher_is_reachable(self) -> None:
        for name in BUILD_ONLY:
            with self.subTest(workflow=name):
                self.assertEqual(exposed(_workflows.load(name)), [])

    def test_the_scan_sees_each_publisher(self) -> None:
        """Not vacuous: with the guards dropped, every known publisher is reported."""
        expected = {
            'cron-conda.yml': ['conda-update: Load maintenance deploy key', 'conda-update: Push Changes',
                               'conda-tag', 'conda-dist: Upload conda packages to Anaconda',
                               'conda-dist: Upload conda packages to Anaconda (Intel)',
                               'conda-dist: Check the GitHub release exists',
                               'conda-dist: Upload package to GitHub Release', 'discussion'],
            'cron-vendor.yml': ['vendor-update: Load maintenance deploy key', 'vendor-update: Push changes',
                                'discussion'],
            'deploy-pages.yml': ['publish-pages', 'discussion'],
        }
        for name in BUILD_ONLY:
            text = (WORKFLOWS / name).read_text(encoding='utf-8')
            stripped = _GUARDS.sub('true && ', text)
            found = exposed(_workflows.loads(stripped))
            with self.subTest(workflow=name):
                for publisher in expected[name]:
                    self.assertTrue(any(entry == publisher or entry.startswith(publisher + ':') for entry in found),
                                    f'{publisher} is not seen as a publisher: {found}')

    def test_the_conjunct_reading_is_conservative(self) -> None:
        self.assertEqual(conjuncts("${{ a && (b || c) && github.event_name != 'workflow_dispatch' }}"),
                         ['a', '(b||c)', GUARD])
        self.assertIsNone(conjuncts("github.event_name != 'workflow_dispatch' && a || b"))
        self.assertFalse(guarded({'if': "github.event_name != 'workflow_dispatch' || a"}))
        self.assertFalse(guarded({'if': "(github.event_name != 'workflow_dispatch' && a)"}))
        self.assertTrue(guarded({'if': "a && github.event_name != 'workflow_dispatch'"}))
        self.assertTrue(guarded({'if': "a && needs.mode.outputs.publishes == 'true'"}))
        self.assertFalse(guarded({'if': "needs.mode.outputs.publishes != 'true' && a"}))
        self.assertFalse(guarded({'if': "needs.mode.outputs.publishes == 'true' || a"}))
        self.assertFalse(guarded({}))

    def test_a_running_job_names_no_environment(self) -> None:
        for name in BUILD_ONLY:
            for job_id, job in _workflows.load(name)['jobs'].items():
                if guarded(job) or 'environment' not in job:
                    continue
                with self.subTest(workflow=name, job=job_id):
                    self.assertEqual(dispatch_environment(job), '')
                    self.assertNotEqual(dispatch_environment(job, 'schedule'), '')

    def test_no_run_joins_a_real_runs_group(self) -> None:
        """A group cancels its pending run when another joins it, so a manual run keeps its own."""
        for name in BUILD_ONLY:
            text = (WORKFLOWS / name).read_text(encoding='utf-8')
            match = _GROUP.search(text)
            self.assertIsNotNone(match, f'no workflow-level concurrency group in {name}')
            prefix, body = match.group('prefix'), match.group('body')  # type: ignore[union-attr]

            def group(event_name: 'str', run_id: 'str') -> 'str':
                context = {'github': {'event_name': event_name, 'run_id': run_id, 'ref': 'refs/heads/main',
                                      'event': {}}}
                return prefix + str(evaluate_expression('${{' + body + '}}', context))

            with self.subTest(workflow=name):
                self.assertEqual(group('schedule', '1'), group('schedule', '2'))
                self.assertEqual(group(DISPATCH, '1'), prefix + '1')
                self.assertNotEqual(group(DISPATCH, '1'), group('schedule', '1'))
                for job_id, job in _workflows.load(name)['jobs'].items():
                    shared = (job.get('concurrency') or {})
                    shared = shared.get('group', '') if isinstance(shared, dict) else shared
                    if guarded(job) or not shared:
                        continue
                    with self.subTest(job=job_id):
                        self.assertNotEqual(job_group(shared, DISPATCH, '1'), job_group(shared, DISPATCH, '2'))
                        self.assertEqual(job_group(shared, 'schedule', '1'), job_group(shared, 'schedule', '2'))
                        self.assertNotEqual(job_group(shared, DISPATCH, '1'), job_group(shared, 'schedule', '1'))

    def test_no_report_is_posted(self) -> None:
        for name in BUILD_ONLY:
            with self.subTest(workflow=name):
                self.assertTrue(guarded(_workflows.job(name, 'discussion')))


class TestAManualRunStillBuilds(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.jobs = {name: job_blocks((WORKFLOWS / name).read_text(encoding='utf-8'))
                    for name in (*BUILD_ONLY, 'cron-head.yml')}

    def test_the_head_gate_runs(self) -> None:
        context = {'github': {'event_name': DISPATCH, 'event': {}}, 'needs': {}, STATUS: {'cancelled': False}}
        self.assertTrue(job_runs(self.jobs['cron-head.yml'], 'unit-tests', context))
        self.assertFalse(job_runs(self.jobs['cron-head.yml'], 'verdict', context))

    def test_the_conda_chain_builds_without_tagging(self) -> None:
        for files_changed in ('true', 'false'):
            context = conda_context(event_name=DISPATCH, unit_tests='success', verdict='skipped', verified=NULL,
                                    files_changed=files_changed, pushed=NULL, conda_tag='skipped')
            jobs = self.jobs['cron-conda.yml']
            with self.subTest(files_changed=files_changed):
                self.assertTrue(job_runs(jobs, 'conda-update', context))
                self.assertFalse(job_runs(jobs, 'conda-tag', context))
                self.assertTrue(job_runs(jobs, 'conda-dist', context))
                self.assertFalse(job_runs(jobs, 'discussion', context))
        # On the schedule, no pushed bump means no build.
        context = conda_context(event_name='schedule', unit_tests='success', verdict='skipped', verified=NULL,
                                files_changed='false', pushed=NULL, conda_tag='skipped')
        self.assertFalse(job_runs(self.jobs['cron-conda.yml'], 'conda-dist', context))

    def test_conda_update_hands_conda_dist_a_version(self) -> None:
        version = next(step for step in _workflows.steps('cron-conda.yml', 'conda-update')
                       if step.get('name') == 'Get Version')
        for event_name, expected in ((DISPATCH, True), ('schedule', False)):
            context = {**mode_context(event_name),
                       'steps': {'verify-changed-files': {'outputs': {'files_changed': 'false'}},
                                 'bump': {'outputs': {'bump': 'false'}}}}
            with self.subTest(event=event_name):
                self.assertIs(evaluate_condition(version['if'], context), expected)

    def test_conda_dist_builds_the_dispatched_commit_with_the_changes(self) -> None:
        steps = _workflows.steps('cron-conda.yml', 'conda-dist')
        names = [step.get('id') or step.get('name') for step in steps]
        self.assertEqual(names[:4], ['checkout', 'checkout-dispatched', 'download-changes', 'apply-changes'])
        update = [step.get('name') for step in _workflows.steps('cron-conda.yml', 'conda-update')]
        self.assertLess(update.index('Get Version'), update.index('Save the changes for conda-dist'))
        for step in steps:
            name = step.get('id') or step.get('name')
            for os_label in _workflows.job('cron-conda.yml', 'conda-dist')['strategy']['matrix']['os']:
                for event_name in (DISPATCH, 'schedule'):
                    context = {**mode_context(event_name), 'matrix': {'os': os_label},
                               'steps': {'conda_build': {'outcome': 'success'},
                                         'release': {'outputs': {'published': 'true'}}},
                               STATUS: {'cancelled': False}}
                    runs = evaluate_condition(str(step.get('if', 'true')), context)
                    with self.subTest(step=name, os=os_label, event=event_name):
                        if name in ('checkout', 'checkout-dispatched', 'download-changes', 'apply-changes'):
                            self.assertEqual(runs, (name == 'checkout') == (event_name != DISPATCH))
                        elif name in ('install', 'download', 'conda_build', 'smoke'):
                            self.assertTrue(runs)

    def test_the_vendor_crawl_and_the_pages_build_run(self) -> None:
        context = {'github': {'event_name': DISPATCH, 'event': {}}, STATUS: {'cancelled': False},
                   'needs': {'head': {'result': 'success', 'outputs': {}}}}
        self.assertTrue(job_runs(self.jobs['cron-vendor.yml'], 'vendor-update', context))
        self.assertTrue(job_runs(self.jobs['deploy-pages.yml'], 'deploy-pages', context))
        pages = dict(context, needs={'deploy-pages': {'result': 'success'}})
        self.assertFalse(job_runs(self.jobs['deploy-pages.yml'], 'publish-pages', pages))
        names = [step.get('name') for step in _workflows.steps('cron-vendor.yml', 'vendor-update')
                 if not guarded(step)]
        self.assertLessEqual({'Update Vendor', 'Test the regenerated tree', 'Bump Version', 'Commit changes'},
                             set(names))


class TestCreateReleaseIgnoresAManualVendorUpdate(unittest.TestCase):
    """Every completed Vendor Update raises Create Release, a manual one included."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.text = (WORKFLOWS / 'create-release.yml').read_text(encoding='utf-8')
        cls.jobs = job_blocks(cls.text)

    def context(self, event: 'str') -> 'dict[str, object]':
        return {'github': {'event_name': 'workflow_run', 'ref': 'refs/heads/main', 'ref_name': 'main',
                           'run_id': '7', 'actor_id': '1', 'event': {
                               'workflow_run': {'conclusion': 'success', 'event': event}}},
                'vars': {'RELEASE_APP_BOT_ID': '2'}, STATUS: {'cancelled': False},
                'needs': {'vendor_update': {'result': 'success', 'outputs': {'updated': 'true'}}}}

    def test_neither_vendor_update_nor_version_check_runs(self) -> None:
        for job in ('vendor_update', 'version_check'):
            with self.subTest(job=job):
                self.assertFalse(evaluate_condition(declared_if(self.jobs[job]), self.context(DISPATCH)))
                for event in ('schedule', 'push'):
                    self.assertTrue(evaluate_condition(declared_if(self.jobs[job]), self.context(event)))

    def test_it_waits_in_a_group_of_its_own(self) -> None:
        match = _GROUP.search(self.text)
        assert match is not None
        group = evaluate_expression('${{' + match.group('body') + '}}', self.context(DISPATCH))
        self.assertEqual(group, '7')
        self.assertEqual(evaluate_expression('${{' + match.group('body') + '}}', self.context('schedule')),
                         'refs/heads/main')

    def test_release_status_says_why(self) -> None:
        step = next(step for step in _workflows.steps('create-release.yml', 'release_status') if 'run' in step)
        self.assertEqual(step['env']['PCAPKIT_WORKFLOW_RUN_EVENT'], '${{ github.event.workflow_run.event }}')
        script = WORKFLOWS.parents[1] / 'util' / 'release_status.py'
        env = {**os.environ, **STATUS_BASE, **SKIPPED_CHECK, 'PCAPKIT_VENDOR_UPDATED': '',
               'PCAPKIT_WORKFLOW_RUN_EVENT': DISPATCH}
        result = subprocess.run([sys.executable, str(script)], env=env, capture_output=True,  # nosec: B603
                                text=True, check=False, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('::notice title=Nothing to release::the triggering Vendor Update run was a manual, '
                      'build-only run', result.stdout)


if __name__ == '__main__':
    unittest.main()
