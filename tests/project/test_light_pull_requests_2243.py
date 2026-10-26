# -*- coding: utf-8 -*-
"""#2243, the owner's option B: docs-only and test-only pull requests skip the heavy matrices.

:file:`util/classify_changes.py` writes ``code`` and ``test-only`` (its cases are
:mod:`tests.project.test_unit_tests_queue`'s), and each workflow that runs heavy
work on ``pull_request`` acts on them. Pinned here, by evaluating each job's and
step's ``if:`` and each matrix expression, rather than reading their text:

* :file:`.github/workflows/unit-tests.yml`: ``test`` and ``integration`` run
  their ``latest`` leg alone on a test-only diff and skip a docs-only one; the
  KTLO jobs, ``engine-tests`` and ``pypcap-parity`` skip both; ``project-tests``
  runs on every diff.
* :file:`.github/workflows/experimental.yml`: its legs skip both.
* :file:`.github/workflows/python-compatibility.yml`: its required legs still
  run, under their required names, on either light diff, and skip every step
  but a notice and the job summary's; its KTLO legs are left out. A job-level
  ``if:`` would leave each required context pending, since a matrix job it skips
  reports one check under its unexpanded name.
* :file:`.github/workflows/codeql-analysis.yml` and
  :file:`.github/workflows/deploy-pages.yml`, which no ruleset requires, skip
  by a ``pull_request`` path filter. No workflow emitting a required context
  has one, as a workflow a filter skips leaves its checks pending.
* A push to ``main``, and every other event, takes none of these paths.

"""

from __future__ import annotations

import re
import unittest
from typing import TYPE_CHECKING

from tests._workflows import WORKFLOWS
from tests.project.test_python_versions_1660 import REQUIRED_AT_MAIN, legs, live_outputs, matrix, render, workflow
from tests.project.test_release_gates import STATUS, calls_status_check, evaluate_condition, evaluate_expression

if TYPE_CHECKING:
    from typing import Any, Optional

#: Test tier (#1958): reads the workflows and the tier file, a question about the tree.
__tier__ = 'LATEST'

UNIT = 'unit-tests.yml'
COMPAT = 'python-compatibility.yml'
EXPERIMENTAL = 'experimental.yml'

#: ``changes``' outputs for each kind of diff, and for a ``changes`` that wrote none.
CLASSES = {
    'code': {'code': 'true', 'test-only': 'false'},
    'docs': {'code': 'false', 'test-only': 'false'},
    'tests': {'code': 'true', 'test-only': 'true'},
    'unclassified': {},
}

#: unit-tests.yml's jobs that run on a test-only diff, on their ``latest`` leg alone.
LATEST_ONLY = ('test', 'integration')
#: unit-tests.yml's jobs that skip both light diffs.
HEAVY = ('test-ktlo', 'integration-ktlo', 'engine-tests', 'pypcap-parity', 'pypcap-parity-ktlo')

#: The workflows emitting a required context of ruleset 23497679, and the job that does.
REQUIRED_WORKFLOWS = {'lint.yml': 'lint', UNIT: 'required-checks', COMPAT: 'compatibility'}
#: The workflows a ``pull_request`` path filter gates instead, each with its filter.
FILTERED = {'codeql-analysis.yml': ['docs/**', 'tests/**', '**.md'], 'deploy-pages.yml': ['tests/**']}


def needs_context(name: 'str', job_id: 'str', outputs: 'dict[str, str]',
                  results: 'Optional[dict[str, str]]' = None) -> 'dict[str, Any]':
    """``needs`` for job ``job_id``: ``changes`` with ``outputs``, ``python-versions`` with the tier file's."""
    results = results or {}
    spec = workflow(name)['jobs'][job_id]
    found = {}  # type: dict[str, Any]
    needs = spec.get('needs', [])
    for target in [needs] if isinstance(needs, str) else needs:
        found[target] = {'result': results.get(target, 'success'), 'outputs': {}}
    if 'changes' in found:
        found['changes']['outputs'] = dict(outputs)
    if 'python-versions' in found:
        found['python-versions']['outputs'] = live_outputs()
    if 'current' in found:
        found['current']['outputs'] = {'current': 'true'}
    return found


def job_runs(name: 'str', job_id: 'str', outputs: 'dict[str, str]',
             results: 'Optional[dict[str, str]]' = None) -> 'bool':
    """Whether job ``job_id`` runs, GitHub's implicit ``success()`` applied where its ``if:`` calls none."""
    spec = workflow(name)['jobs'][job_id]
    needs = needs_context(name, job_id, outputs, results)
    succeeded = all(entry['result'] == 'success' for entry in needs.values())
    context = {'needs': needs, 'inputs': {}, 'github': {'event_name': 'pull_request'},
               STATUS: {'cancelled': False, 'always': True, 'success': succeeded,
                        'failure': any(entry['result'] == 'failure' for entry in needs.values())}}
    condition = str(spec.get('if', ''))
    runs = evaluate_condition(condition, context) if condition else True
    return runs if calls_status_check(condition) else runs and succeeded


def matrix_legs(name: 'str', job_id: 'str', outputs: 'dict[str, str]') -> 'list[dict[str, Any]]':
    """The legs job ``job_id``'s matrix expression expands to, evaluated as GitHub would."""
    raw = workflow(name)['jobs'][job_id]['strategy']['matrix']
    found = evaluate_expression(raw, {'needs': needs_context(name, job_id, outputs)})
    assert isinstance(found, dict), f'{name} {job_id} matrix evaluates to {found!r}'
    return legs(found)


class TestUnitTests(unittest.TestCase):
    """unit-tests.yml's jobs on each kind of diff."""

    def test_the_heavy_jobs_skip_both_light_diffs(self) -> None:
        for job_id in HEAVY:
            for kind, outputs in CLASSES.items():
                with self.subTest(job=job_id, diff=kind):
                    self.assertEqual(job_runs(UNIT, job_id, outputs), kind in ('code', 'unclassified'))

    def test_test_and_integration_skip_only_a_docs_only_diff(self) -> None:
        for job_id in LATEST_ONLY:
            for kind, outputs in CLASSES.items():
                with self.subTest(job=job_id, diff=kind):
                    self.assertEqual(job_runs(UNIT, job_id, outputs), kind != 'docs')

    def test_a_test_only_diff_runs_their_latest_leg_alone(self) -> None:
        """The coverage leg on ``latest``, as the full matrix spells it, and no other."""
        latest = live_outputs()['latest']
        for job_id in LATEST_ONLY:
            with self.subTest(job=job_id):
                full = matrix_legs(UNIT, job_id, CLASSES['code'])
                self.assertEqual(matrix_legs(UNIT, job_id, CLASSES['tests']),
                                 [leg for leg in full if leg['python-version'] == latest])
                self.assertEqual(len(matrix_legs(UNIT, job_id, CLASSES['tests'])), 1)
                self.assertEqual(matrix_legs(UNIT, job_id, CLASSES['tests']), legs(matrix(UNIT, job_id, light=True)))
                self.assertGreater(len(full), 1)
        self.assertEqual(matrix_legs(UNIT, 'test', CLASSES['tests']),
                         [{'python-version': latest, 'coverage': True}])

    def test_every_other_diff_runs_the_full_matrix(self) -> None:
        for job_id in LATEST_ONLY:
            for kind in ('code', 'unclassified'):
                with self.subTest(job=job_id, diff=kind):
                    self.assertEqual(matrix_legs(UNIT, job_id, CLASSES[kind]), legs(matrix(UNIT, job_id)))

    def test_project_tests_runs_on_every_diff(self) -> None:
        for kind, outputs in CLASSES.items():
            with self.subTest(diff=kind):
                self.assertTrue(job_runs(UNIT, 'project-tests', outputs))

    def test_the_gate_still_runs_whatever_its_needs_did(self) -> None:
        """``required-checks`` runs on ``always()``, so a skipped or failed leg is judged, not inherited."""
        for kind, outputs in CLASSES.items():
            for result in ('success', 'skipped', 'failure'):
                with self.subTest(diff=kind, result=result):
                    self.assertTrue(job_runs(UNIT, 'required-checks', outputs, {'test': result}))


class TestExperimental(unittest.TestCase):
    """experimental.yml's legs skip both light diffs."""

    def test_the_legs_skip_both_light_diffs(self) -> None:
        for job_id in ('experimental', 'windows'):
            for kind, outputs in CLASSES.items():
                with self.subTest(job=job_id, diff=kind):
                    self.assertEqual(job_runs(EXPERIMENTAL, job_id, outputs), kind in ('code', 'unclassified'))

    def test_changes_writes_test_only(self) -> None:
        self.assertEqual(workflow(EXPERIMENTAL)['jobs']['changes']['outputs']['test-only'],
                         '${{ steps.classify.outputs.test-only }}')


def light(outputs: 'dict[str, str]') -> 'str':
    """python-compatibility.yml's ``changes`` output ``light``, as its expression evaluates on ``outputs``."""
    expression = workflow(COMPAT)['jobs']['changes']['outputs']['light']
    value = evaluate_expression(expression, {'steps': {'classify': {'outputs': dict(outputs)}}})
    return 'true' if value is True else 'false' if value is False else str(value)


def run_steps(leg: 'dict[str, Any]', light_output: 'str') -> 'list[str]':
    """The names of the ``compatibility`` steps that run on ``leg`` with ``light`` set, none failing."""
    ran = []
    steps = {}  # type: dict[str, dict[str, Any]]
    for step in workflow(COMPAT)['jobs']['compatibility']['steps']:
        context = {'matrix': leg, 'steps': steps, 'env': {},
                   'needs': {'changes': {'outputs': {'light': light_output}}},
                   STATUS: {'success': True, 'failure': False, 'cancelled': False, 'always': True}}
        condition = str(step.get('if', ''))
        runs = evaluate_condition(condition, context) if condition else True
        label = str(step.get('name') or step['uses'].split('@', 1)[0])
        if runs:
            ran.append(label)
        if 'id' in step:
            steps[step['id']] = {'outcome': 'success' if runs else 'skipped', 'outputs': {}}
    return ran


#: The steps a light diff's ``Compat`` leg runs: a notice, and the job summary's pair.
LIGHT_STEPS = ['Skip on a docs-only or test-only diff', 'Name the job summary', 'Upload the job summary']


class TestCompatibility(unittest.TestCase):
    """python-compatibility.yml's legs on each kind of diff."""

    def test_light_is_true_on_either_light_diff_alone(self) -> None:
        expected = {'code': 'false', 'docs': 'true', 'tests': 'true', 'unclassified': 'false'}
        for kind, outputs in CLASSES.items():
            with self.subTest(diff=kind):
                self.assertEqual(light(outputs), expected[kind])

    def test_a_light_diff_still_runs_every_required_leg_by_name(self) -> None:
        """Each required ``Compat`` context is a leg that runs; a skipped matrix job would report none."""
        template = workflow(COMPAT)['jobs']['compatibility']['name']
        required = REQUIRED_AT_MAIN - {'Required checks passed'}
        for kind in ('docs', 'tests'):
            with self.subTest(diff=kind):
                found = matrix_legs(COMPAT, 'compatibility', {'light': light(CLASSES[kind])})
                self.assertEqual({render(template, leg) for leg in found}, required)
                self.assertFalse([leg for leg in found if leg.get('ktlo')])
                self.assertTrue(job_runs(COMPAT, 'compatibility', {'light': light(CLASSES[kind])}))

    def test_every_other_diff_runs_both_tiers(self) -> None:
        for kind in ('code', 'unclassified'):
            with self.subTest(diff=kind):
                found = matrix_legs(COMPAT, 'compatibility', {'light': light(CLASSES[kind])})
                self.assertEqual(found, legs(matrix(COMPAT, 'compatibility')))
                self.assertTrue([leg for leg in found if leg.get('ktlo')])

    def test_a_light_leg_checks_nothing_and_passes(self) -> None:
        for leg in matrix_legs(COMPAT, 'compatibility', {'light': 'true'}):
            with self.subTest(leg=leg['python-version']):
                self.assertEqual(run_steps(leg, 'true'), LIGHT_STEPS)

    def test_every_other_leg_checks_and_never_takes_the_notice(self) -> None:
        for value in ('false', ''):
            for leg in matrix_legs(COMPAT, 'compatibility', {'light': value}):
                with self.subTest(light=value, leg=leg['python-version']):
                    ran = run_steps(leg, value)
                    self.assertNotIn(LIGHT_STEPS[0], ran)
                    self.assertIn('Verify package', ran)

    def test_a_failed_classification_runs_every_leg_in_full(self) -> None:
        """``!cancelled()`` replaces the implicit ``success()``: a failed ``changes`` skips nothing."""
        self.assertTrue(job_runs(COMPAT, 'compatibility', {}, {'changes': 'failure'}))
        self.assertEqual(matrix_legs(COMPAT, 'compatibility', {}), legs(matrix(COMPAT, 'compatibility')))
        # And without the tier file's matrix there is nothing to expand.
        self.assertFalse(job_runs(COMPAT, 'compatibility', {}, {'python-versions': 'failure'}))

    def test_changes_classifies_this_workflows_own_pull_request(self) -> None:
        step = workflow(COMPAT)['jobs']['changes']['steps'][1]
        self.assertEqual(step['run'], 'python3 util/classify_changes.py')
        self.assertEqual(step['env']['OWN_PR'], "${{ github.event_name == 'pull_request' }}")


class TestPathFilters(unittest.TestCase):
    """Path filters gate only workflows no ruleset requires, and only on ``pull_request``."""

    @staticmethod
    def triggers(name: 'str') -> 'dict[str, Any]':
        found = workflow(name)['on']
        return {key: value or {} for key, value in found.items()} if isinstance(found, dict) else {}

    def test_no_required_workflow_has_a_path_filter(self) -> None:
        """docs.github.com, "Handling skipped but required checks": a workflow a path filter skips leaves
        its checks pending, so a pull request that requires them cannot merge."""
        names = {'lint': 'Lint', 'required-checks': 'Required checks passed'}
        for name, job_id in REQUIRED_WORKFLOWS.items():
            spec = workflow(name)['jobs'][job_id]
            self.assertTrue(spec['name'].startswith(names.get(job_id, 'Compat Python ')))
            for event, body in self.triggers(name).items():
                with self.subTest(workflow=name, event=event):
                    self.assertFalse({'paths', 'paths-ignore'} & set(body if isinstance(body, dict) else ()))

    def test_the_filtered_workflows_filter_pull_requests_alone(self) -> None:
        for name, expected in FILTERED.items():
            for event, body in self.triggers(name).items():
                with self.subTest(workflow=name, event=event):
                    keys = set(body) if isinstance(body, dict) else set()
                    if event == 'pull_request':
                        self.assertEqual(body.get('paths-ignore'), expected)
                        self.assertNotIn('paths', keys)
                    else:
                        self.assertFalse({'paths', 'paths-ignore'} & keys)

    def test_no_other_workflow_has_a_path_filter(self) -> None:
        for path in sorted(WORKFLOWS.glob('*.yml')):
            if path.name in FILTERED:
                continue
            for event, body in self.triggers(path.name).items():
                with self.subTest(workflow=path.name, event=event):
                    self.assertFalse({'paths', 'paths-ignore'} & set(body if isinstance(body, dict) else ()))

    def test_the_filters_match_light_paths_and_spare_code(self) -> None:
        """GitHub's glob: ``**`` crosses ``/``, ``*`` does not (Workflow syntax, "Filter pattern cheat sheet")."""
        def matches(pattern: 'str', path: 'str') -> 'bool':
            body = re.escape(pattern).replace(r'\*\*', '.*').replace(r'\*', '[^/]*')
            return re.fullmatch(body, path) is not None

        light_paths = {'codeql-analysis.yml': ('docs/source/index.rst', 'README.md', 'tests/test_x.py',
                                               'tests/project/fixtures/x.yml'),
                       'deploy-pages.yml': ('tests/test_x.py', 'tests/conftest.py')}
        code_paths = ('pcapkit/__init__.py', 'util/classify_changes.py', '.github/workflows/unit-tests.yml',
                      'pyproject.toml', 'examples/captures/in.pcap')
        for name, patterns in FILTERED.items():
            for path in light_paths[name]:
                with self.subTest(workflow=name, path=path):
                    self.assertTrue(any(matches(pattern, path) for pattern in patterns))
            for path in code_paths + (('docs/source/index.rst', 'README.md') if name == 'deploy-pages.yml' else ()):
                with self.subTest(workflow=name, path=path):
                    self.assertFalse(any(matches(pattern, path) for pattern in patterns))


class TestPushesTakeNoLightPath(unittest.TestCase):
    """A push to ``main``, and every event but the workflow's own pull request, classifies as code."""

    def test_every_changes_job_classifies_only_its_own_pull_request(self) -> None:
        for name in (UNIT, EXPERIMENTAL, COMPAT):
            step = next(entry for entry in workflow(name)['jobs']['changes']['steps'] if entry.get('id') == 'classify')
            expression = step['env']['OWN_PR']
            workflow_name = workflow(name)['name']
            for event in ('push', 'schedule', 'workflow_dispatch', 'workflow_run', 'pull_request_target'):
                with self.subTest(workflow=name, event=event):
                    context = {'github': {'event_name': event, 'workflow': workflow_name}}
                    self.assertFalse(evaluate_expression(expression, context))
            with self.subTest(workflow=name, event='pull_request'):
                context = {'github': {'event_name': 'pull_request', 'workflow': workflow_name}}
                self.assertTrue(evaluate_expression(expression, context))

    def test_a_push_runs_every_leg(self) -> None:
        """Pushes classify as code, which is the full matrix of every job here."""
        for job_id in LATEST_ONLY + HEAVY + ('project-tests',):
            with self.subTest(job=job_id):
                self.assertTrue(job_runs(UNIT, job_id, CLASSES['code']))
        self.assertEqual(light(CLASSES['code']), 'false')


if __name__ == '__main__':
    unittest.main()
