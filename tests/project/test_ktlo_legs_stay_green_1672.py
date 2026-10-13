# -*- coding: utf-8 -*-
"""#1672: a failed KTLO leg concludes ``success`` and reports a warning.

The owner's ruling: a KTLO failure must not turn ``main`` or a pull request red.
``Compat Python 3.7 (KTLO)`` carried job-level ``continue-on-error``, which keeps
the *run* from failing but still concludes the job's own check run ``failure`` --
check run 115490362417, the one failing check of 4673cffa9 -- and the KTLO steps
of every other job wrote ``::error`` annotations.

Every job holding a KTLO leg now works one way: each step that can fail on the
leg carries ``continue-on-error: ${{ matrix.ktlo == true }}`` and an ``id``; a
step that needs an earlier one waits on that step's ``outcome``; the last step,
``KTLO summary``, reports each failed ``outcome`` as a warning and a job-summary
line; and a step's own annotations take the job's ``ANNOTATION_LEVEL``.

:func:`run_leg` steps through a job the way the runner does -- the implicit
``success()`` GitHub prepends to an ``if:`` without a status function, and a
``continue-on-error`` step's failed ``outcome`` concluding ``success`` -- so each
step's failure is tried on every leg instead of read off the text. Expressions go
through :mod:`tests.project.test_release_gates`'s evaluator, and the scripts that
write annotations are executed.

"""

from __future__ import annotations

import functools
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest
from typing import TYPE_CHECKING, NamedTuple

from tests.project.test_python_matrix_tiers_1633 import (ANNOTATION_LEVEL, KTLO_GUARD, KTLO_LEGS,
                                                         LEG_37, TITLE_37, is_ktlo, job, legs,
                                                         titles, workflow, workflow_commands)
from tests.project.test_release_gates import NULL, STATUS, evaluate_condition, evaluate_expression

if TYPE_CHECKING:
    from typing import Any, Optional

#: Every job holding a KTLO matrix leg, as (workflow, job).
KTLO_JOBS = tuple((name, job_id) for name, job_id, _ in KTLO_LEGS)
#: The jobs whose steps write annotations of their own on a KTLO leg, so set the level.
LEVELLED = (('unit-tests.yml', 'test'), ('unit-tests.yml', 'integration'),
            ('unit-tests.yml', 'pypcap-parity'), ('python-compatibility.yml', 'compatibility'))
#: Steps that stop every leg alike, KTLO or not, by job. #1634's: a leg that cannot
#: show its tree is the tag's must not go on to publish, as
#: ``test_release_tags_the_run_sha_1634.TestPublishersCheckTheirTags`` pins.
BLOCKS_EVERY_LEG = {
    ('create-release.yml', 'pypi'): ('Checkout code', "Check the release tags name this run's commit"),
}
#: Steps whose own ``::error`` a KTLO leg cannot reach, with the ``if:`` that makes it
#: so. ``pypi``'s upload is one script with ``conda``'s (#1634), and runs only once PyPI
#: took this ``dist/``, so its "Nothing to upload" needs a supported leg's failure.
UNREACHABLE_ERRORS = {
    ('create-release.yml', 'pypi', 'Upload package to GitHub Release'): "${{ steps.publish.outcome == 'success' }}",
}
#: Steps masked on every leg by their own design, ``continue-on-error: true``: a
#: diagnostic upload (#1538), and TestPyPI, which must not gate the real release.
MASKED_ON_EVERY_LEG = {
    ('unit-tests.yml', 'test'): ('Upload test timings',),
    ('unit-tests.yml', 'integration'): ('Upload test timings',),
    ('create-release.yml', 'pypi'): ('Publish package to TestPyPI',),
}
#: ``engine-tests``'s KTLO steps: the 3.10 interpreter, and the 3.10 cell.
ENGINE_KTLO = ('Run the 3.10 cell (KTLO, non-blocking)',)
#: The workflow commands a step a KTLO leg runs may write.
KTLO_COMMANDS = frozenset({'${ANNOTATION_LEVEL}', 'warning', 'notice', 'group', 'endgroup'})
#: A workflow command a script writes, by its name.
COMMAND = re.compile(r'''(?:echo|printf|print\(f?)\s*["']::([^\s:"']+)''')
#: A status-check function: an ``if:`` holding none gets ``success() &&`` prepended.
STATUS_FUNCTION = re.compile(r'\b(?:success|failure|cancelled|always)\(\)')
#: The outputs a step with an ``id`` is taken to set: ones that let every later step run.
OUTPUTS = {
    'apt-plan': {'key': 'apt-debs-ImageOS-X64-set-0123456789abcdef', 'restore-prefix': 'apt-debs-ImageOS-X64-set-'},
    'apt-cache': {'cache-matched-key': 'apt-debs-ImageOS-X64-set-0123456789abcdef', 'cache-hit': 'false'},
}
SUMMARY = 'KTLO summary'
SUMMARY_IF = '${{ !cancelled() && matrix.ktlo == true }}'
SUMMARY_ENV = {'LEG': "Python ${{ matrix.python-version }}${{ matrix.ktlo && ' (KTLO, non-blocking)' || '' }}",
               'STEPS': '${{ toJSON(steps) }}'}


class Step(NamedTuple):
    """One step of a :func:`run_leg` run."""

    label: str
    outcome: str
    conclusion: str


def label(step: 'dict[str, Any]') -> 'str':
    return step.get('name') or step.get('uses')


def summary_step(spec: 'dict[str, Any]') -> 'dict[str, Any]':
    """The job's ``KTLO summary`` step."""
    found = [step for step in spec['steps'] if step.get('name') == SUMMARY]
    if len(found) != 1:
        raise AssertionError(f'expected one {SUMMARY!r} step, found {len(found)}')
    return found[0]


def is_engine_ktlo(step: 'dict[str, Any]') -> 'bool':
    """Whether ``step`` is one of ``engine-tests``'s, which run only the KTLO interpreter."""
    return label(step) in ENGINE_KTLO or str(step.get('with', {}).get('python-version')) == '3.10'


def stringify(value: 'object') -> 'str':
    """``value`` as an ``env:`` entry holds it."""
    if value is NULL or value is None:
        return ''
    if isinstance(value, bool):
        return 'true' if value else 'false'
    return str(value)


@functools.lru_cache(maxsize=None)
def workflow_env(name: 'str') -> 'tuple[tuple[str, Any], ...]':
    """``name``'s workflow-level ``env:``, parsed once."""
    return tuple((workflow(name).get('env') or {}).items())


def leg_env(name: 'str', spec: 'dict[str, Any]', leg: 'dict[str, Any]') -> 'dict[str, str]':
    """The workflow's and the job's ``env:``, each expression evaluated on ``leg``."""
    merged = dict(workflow_env(name), **(spec.get('env') or {}))
    return {key: stringify(evaluate_expression(value, {'matrix': leg})
                           if isinstance(value, str) and '${{' in value else value)
            for key, value in merged.items()}


def continue_on_error(step: 'dict[str, Any]', context: 'dict[str, Any]') -> 'bool':
    value = step.get('continue-on-error', False)
    return value if isinstance(value, bool) else evaluate_condition(str(value), context)


def run_leg(name: 'str', spec: 'dict[str, Any]', leg: 'dict[str, Any]',
            failing: 'int' = -1) -> 'tuple[str, list[Step]]':
    """The job's conclusion on ``leg``, and each step's, with step ``failing`` failing.

    A step runs when its ``if:`` holds -- with ``success()`` prepended when it calls
    no status function, which GitHub documents as the default -- and a failure is
    the job's unless the step's ``continue-on-error`` holds on this leg.

    """
    env = leg_env(name, spec, leg)
    steps = {}  # type: dict[str, dict[str, Any]]
    failed = False
    record = []  # type: list[Step]
    for index, step in enumerate(spec['steps']):
        context = {'matrix': leg, 'env': env, 'steps': steps, 'inputs': {},
                   STATUS: {'success': not failed, 'failure': failed, 'cancelled': False}}
        condition = '' if step.get('if') is None else str(step['if'])
        runs = STATUS_FUNCTION.search(condition) is not None or not failed
        if runs and condition:
            runs = evaluate_condition(condition, context)
        if runs:
            outcome = 'failure' if index == failing else 'success'
            conclusion = 'success' if outcome == 'failure' and continue_on_error(step, context) else outcome
            failed = failed or conclusion == 'failure'
        else:
            outcome = conclusion = 'skipped'
        if 'id' in step:
            outputs = OUTPUTS.get(step['id'], {}) if outcome == 'success' else {}
            steps[step['id']] = {'outcome': outcome, 'conclusion': conclusion, 'outputs': dict(outputs)}
        record.append(Step(label(step), outcome, conclusion))
    return ('failure' if failed else 'success'), record


def scenarios(name: 'str', spec: 'dict[str, Any]', leg: 'dict[str, Any]') -> 'list[tuple[int, str, list[Step]]]':
    """``(failing step, job conclusion, steps)`` for each step that runs on ``leg``."""
    found = []
    for index in range(len(spec['steps'])):
        conclusion, record = run_leg(name, spec, leg, failing=index)
        if record[index].outcome != 'skipped':
            found.append((index, conclusion, record))
    return found


def commands(script: 'str') -> 'set[str]':
    """The workflow commands ``script`` writes."""
    return set(COMMAND.findall(script))


def bash(script: 'str', env: 'dict[str, str]', cwd: 'pathlib.Path') -> 'subprocess.CompletedProcess[str]':
    """``script`` as ``shell: bash`` runs it."""
    return subprocess.run(['bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', script],
                          env=dict(os.environ, **env), cwd=cwd, capture_output=True, text=True,
                          check=False, timeout=60)


class TestNoKTLOFailureTurnsAJobRed(unittest.TestCase):
    """(a) Whatever step fails on a KTLO leg, the job concludes ``success``."""

    def test_no_job_with_a_ktlo_leg_masks_it_at_job_level(self) -> None:
        """Job-level, the run passes but the leg's check run concludes ``failure``."""
        for name, job_id in KTLO_JOBS + (('unit-tests.yml', 'engine-tests'),):
            with self.subTest(workflow=name, job=job_id):
                self.assertNotIn('continue-on-error', job(name, job_id))

    def test_no_step_can_fail_a_ktlo_leg(self) -> None:
        for name, job_id in KTLO_JOBS:
            spec = job(name, job_id)
            blocking = BLOCKS_EVERY_LEG.get((name, job_id), ())
            for leg in filter(is_ktlo, legs(spec)):
                runs = scenarios(name, spec, leg)
                self.assertGreater(len(runs), 3, f'{job_id} on {leg} runs almost nothing')
                for index, conclusion, _ in runs:
                    step = label(spec['steps'][index])
                    with self.subTest(workflow=name, job=job_id, python=leg['python-version'], step=step):
                        self.assertEqual(conclusion, 'failure' if step in blocking else 'success')
        spec = job('unit-tests.yml', 'engine-tests')
        for leg in legs(spec):
            ktlo = [(index, conclusion) for index, conclusion, _ in scenarios('unit-tests.yml', spec, leg)
                    if is_engine_ktlo(spec['steps'][index])]
            self.assertEqual(len(ktlo), 2, leg)
            for index, conclusion in ktlo:
                with self.subTest(engine=leg['engine'], step=label(spec['steps'][index])):
                    self.assertEqual(conclusion, 'success')

    def test_every_failure_it_masks_reaches_the_summary(self) -> None:
        """``KTLO summary`` ends each job, runs after any failure, and can see each one.

        It reads ``toJSON(steps)``, and the ``steps`` context holds only steps with
        an ``id``. A step masked on every leg, ``continue-on-error: true``, is not
        KTLO's to report.

        """
        scripts = set()
        for name, job_id in KTLO_JOBS:
            spec = job(name, job_id)
            summary = summary_step(spec)
            with self.subTest(workflow=name, job=job_id):
                self.assertIs(spec['steps'][-1], summary)
                self.assertEqual(summary.get('if'), SUMMARY_IF)
                self.assertEqual(summary.get('continue-on-error'), KTLO_GUARD)
                self.assertEqual(summary.get('shell'), 'bash')
                self.assertEqual(summary.get('env'), SUMMARY_ENV)
            scripts.add(summary['run'])
            blocking = BLOCKS_EVERY_LEG.get((name, job_id), ())
            for leg in filter(is_ktlo, legs(spec)):
                for index, _, record in scenarios(name, spec, leg):
                    step = spec['steps'][index]
                    if step is summary or label(step) in blocking:
                        continue
                    with self.subTest(workflow=name, job=job_id, python=leg['python-version'], step=label(step)):
                        self.assertNotEqual(record[-1].outcome, 'skipped')
                        if step.get('continue-on-error') is not True:
                            self.assertIn('id', step)
        self.assertEqual(len(scripts), 1, f'the copies of {SUMMARY!r} have drifted apart')


class TestAKTLOFailureIsAWarning(unittest.TestCase):
    """(b) Nothing a KTLO leg runs writes an error, and the summary writes warnings."""

    def setUp(self) -> None:
        if shutil.which('bash') is None:  # pragma: no cover
            self.skipTest('bash is needed to run the workflow shell')
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1672-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)

    def test_annotation_level_is_a_warning_on_a_ktlo_leg_only(self) -> None:
        for name, job_id in LEVELLED:
            spec = job(name, job_id)
            with self.subTest(workflow=name, job=job_id):
                self.assertEqual((spec.get('env') or {}).get('ANNOTATION_LEVEL'), ANNOTATION_LEVEL)
            for leg in legs(spec):
                with self.subTest(workflow=name, job=job_id, python=leg['python-version']):
                    self.assertEqual(leg_env(name, spec, leg)['ANNOTATION_LEVEL'],
                                     'warning' if is_ktlo(leg) else 'error')

    def test_no_step_a_ktlo_leg_runs_writes_an_error(self) -> None:
        for name, job_id in KTLO_JOBS:
            spec = job(name, job_id)
            blocking = BLOCKS_EVERY_LEG.get((name, job_id), ())
            reached = set()  # type: set[int]
            for leg in filter(is_ktlo, legs(spec)):
                for _, _, record in scenarios(name, spec, leg):
                    reached.update(index for index, step in enumerate(record) if step.outcome != 'skipped')
            for index in sorted(reached):
                step = spec['steps'][index]
                if label(step) in blocking:
                    continue
                unreachable = UNREACHABLE_ERRORS.get((name, job_id, label(step)))
                with self.subTest(workflow=name, job=job_id, step=label(step)):
                    if unreachable is not None:
                        self.assertEqual(step.get('if'), unreachable)
                        continue
                    self.assertLessEqual(commands(step.get('run', '')), KTLO_COMMANDS)
                    if '${ANNOTATION_LEVEL}' in step.get('run', ''):
                        self.assertIn((name, job_id), LEVELLED)

    def summary(self, steps: 'dict[str, str]') -> 'tuple[subprocess.CompletedProcess[str], str]':
        """``KTLO summary`` on 3.7, given each step's ``outcome``; its result and job summary."""
        if shutil.which('jq') is None:  # pragma: no cover
            self.skipTest('jq, on every Ubuntu runner image, is needed to run KTLO summary')
        script = summary_step(job('unit-tests.yml', 'test'))['run']
        context = {key: {'outputs': {}, 'outcome': outcome,
                         'conclusion': 'success' if outcome == 'failure' else outcome}
                   for key, outcome in steps.items()}
        page = self.tmp / 'summary.md'
        page.write_text('', encoding='utf-8')
        result = bash(script, {'LEG': LEG_37, 'STEPS': json.dumps(context, indent=2),
                               'GITHUB_STEP_SUMMARY': str(page)}, self.tmp)
        return result, page.read_text(encoding='utf-8')

    def test_the_summary_warns_once_per_failed_step(self) -> None:
        def warning(step: 'str') -> 'str':
            return (f'::warning title={step} failed on {TITLE_37}::KTLO legs never block (#1633), so this job '
                    f"still succeeds (#1672); see the {step} step's log.")

        def line(step: 'str') -> 'str':
            return f'- {LEG_37}: step `{step}` failed; non-blocking, so this job still succeeds.\n'

        result, page = self.summary({'checkout': 'success', 'python': 'success', 'install': 'failure',
                                     'parallelism': 'skipped', 'tests': 'skipped'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(workflow_commands(result.stdout), [warning('install')])
        self.assertEqual(titles(result.stdout), [f'install failed on {LEG_37}'])
        self.assertEqual(page, line('install'))

        result, page = self.summary({'checkout': 'failure', 'python': 'failure', 'install': 'skipped'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(workflow_commands(result.stdout), [warning('checkout'), warning('python')])
        self.assertEqual(page, line('checkout') + line('python'))

    def test_the_summary_is_quiet_when_nothing_failed(self) -> None:
        result, page = self.summary({'checkout': 'success', 'python': 'success', 'tests': 'success'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(workflow_commands(result.stdout), [])
        self.assertEqual(page, '')
        self.assertIn(f'{LEG_37}: no step failed.', result.stdout)

    def engine_cell(self, py: 'str', level: 'Optional[str]') -> 'subprocess.CompletedProcess[str]':
        """``engine-tests``'s cell script for Scapy on ``py``, whose extra fails to install.

        The step that writes the script is run, then the script, with ``python<py>``
        stubbed to make a venv whose ``python`` fails ``pip install -e .[Scapy]``.

        """
        writer = next(step for step in job('unit-tests.yml', 'engine-tests')['steps']
                      if step.get('name') == 'Write the per-cell script')
        bin_dir = self.tmp / 'bin'
        bin_dir.mkdir(exist_ok=True)
        venv_python = self.tmp / 'venv-python'
        venv_python.write_text('#!/bin/bash\ncase "$*" in\n'
                               '  --version) echo "Python $PY" ;;\n'
                               '  "-m pip install -e .[Scapy]") echo "ERROR: no Scapy"; exit 1 ;;\n'
                               'esac\n', encoding='utf-8')
        venv_python.chmod(0o755)
        interpreter = bin_dir / f'python{py}'
        interpreter.write_text('#!/bin/bash\n[ "$1 $2" = "-m venv" ]\nmkdir -p "$3/bin"\n'
                               f'cp "{venv_python}" "$3/bin/python"\n'
                               'printf \'PATH="%s/bin:$PATH"\\n\' "$3" > "$3/bin/activate"\n', encoding='utf-8')
        interpreter.chmod(0o755)
        env = {'RUNNER_TEMP': str(self.tmp), 'ENGINE': 'Scapy', 'PY': py,
               'GITHUB_STEP_SUMMARY': str(self.tmp / 'summary.md'),
               'PATH': f'{bin_dir}{os.pathsep}{os.environ["PATH"]}'}
        written = bash(writer['run'], env, self.tmp)
        self.assertEqual(written.returncode, 0, written.stderr)
        if level is not None:
            env['ANNOTATION_LEVEL'] = level
        return subprocess.run(['bash', str(self.tmp / 'engine-cell.sh'), py],
                              env=dict({k: v for k, v in os.environ.items() if k != 'ANNOTATION_LEVEL'}, **env),
                              cwd=self.tmp, capture_output=True, text=True, check=False, timeout=60)

    def test_the_engine_ktlo_cell_warns(self) -> None:
        """The 3.10 cell's step, and the cell script it runs, write no error; 3.12's does."""
        steps = {label(step): step for step in job('unit-tests.yml', 'engine-tests')['steps']}
        ktlo = steps['Run the 3.10 cell (KTLO, non-blocking)']
        self.assertEqual(ktlo.get('env'), {'ANNOTATION_LEVEL': 'warning'})
        self.assertLessEqual(commands(ktlo['run']), {'group', 'endgroup', 'warning'})
        cell = steps['Write the per-cell script']['run'].split("<<'CELL'\n", 1)[1].split('\nCELL\n', 1)[0]
        self.assertLessEqual(commands(cell), {'${ANNOTATION_LEVEL}', 'notice'})
        expected = ("::{} title=Scapy failed to install on Python {}::This cell expects 'supported', "
                    'which requires a successful install. pip exited 1.')
        for py, level in (('3.10', 'warning'), ('3.12', 'error')):
            with self.subTest(python=py):
                result = self.engine_cell(py, level)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(workflow_commands(result.stdout), [expected.format(level, py)])
        unset = self.engine_cell('3.10', None)
        self.assertNotEqual(unset.returncode, 0)
        self.assertIn('ANNOTATION_LEVEL: unbound variable', unset.stderr)

        (self.tmp / 'engine-cell.sh').write_text('exit 1\n', encoding='utf-8')
        page = self.tmp / 'cells.md'
        result = bash(ktlo['run'], {'RUNNER_TEMP': str(self.tmp), 'ENGINE': 'Scapy',
                                    'GITHUB_STEP_SUMMARY': str(page)}, self.tmp)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(workflow_commands(result.stdout)[-1],
                         '::warning title=Scapy failed on Python 3.10 (KTLO%2C non-blocking)::3.10 is '
                         'end-of-life and KTLO per #1633; this does not fail the job.')
        self.assertEqual(page.read_text(encoding='utf-8'), '| 3.10 | Scapy | | FAILED (KTLO, non-blocking) |\n')


class TestASupportedLegStillFails(unittest.TestCase):
    """(c) On a supported leg every step fails the job as before, and no summary runs."""

    def test_every_failure_still_fails_a_supported_leg(self) -> None:
        """A step's failure is the job's, unless it is masked on every leg by its own design.

        An ``outcome`` gate only ever names a step whose failure already fails a
        supported leg, so there it adds nothing to the default ``success()``.

        """
        for name, job_id in KTLO_JOBS:
            spec = job(name, job_id)
            summary = spec['steps'].index(summary_step(spec))
            by_id = {step['id']: step for step in spec['steps'] if 'id' in step}
            masked = [label(step) for step in spec['steps'] if step.get('continue-on-error') is True]
            with self.subTest(workflow=name, job=job_id):
                self.assertEqual(masked, list(MASKED_ON_EVERY_LEG.get((name, job_id), ())))
            for leg in (leg for leg in legs(spec) if not is_ktlo(leg)):
                clean, record = run_leg(name, spec, leg)
                with self.subTest(workflow=name, job=job_id, python=leg['python-version']):
                    self.assertEqual(clean, 'success')
                    self.assertEqual(record[summary].outcome, 'skipped')
                context = {'matrix': leg, 'env': leg_env(name, spec, leg)}
                for index, conclusion, record in scenarios(name, spec, leg):
                    step = spec['steps'][index]
                    with self.subTest(workflow=name, job=job_id, python=leg['python-version'], step=label(step)):
                        self.assertEqual(conclusion, 'success' if step.get('continue-on-error') is True else 'failure')
                        self.assertEqual(record[summary].outcome, 'skipped')
                        for gated in re.findall(r'steps\.([\w-]+)\.outcome', str(step.get('if', ''))):
                            self.assertFalse(continue_on_error(by_id[gated], context), gated)

    def test_a_supported_engine_cell_still_fails_its_job_as_an_error(self) -> None:
        spec = job('unit-tests.yml', 'engine-tests')
        loop = next(step for step in spec['steps'] if step.get('name') == 'Run the 3.11-3.15 cells')
        self.assertEqual(loop.get('env'), {'ANNOTATION_LEVEL': 'error'})
        for leg in legs(spec):
            for index, conclusion, _ in scenarios('unit-tests.yml', spec, leg):
                step = spec['steps'][index]
                if is_engine_ktlo(step):
                    continue
                with self.subTest(engine=leg['engine'], step=label(step)):
                    self.assertEqual(conclusion, 'success' if step.get('continue-on-error') is True else 'failure')


if __name__ == '__main__':
    unittest.main()
