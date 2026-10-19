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

#1660 added an experimental tier, free-threaded CPython and GraalPy, as legs of
``test`` only; #1732 moved them to a job of their own, ``experimental``, which
nothing gating needs. They are non-blocking by the same mechanics, every step
that can fail guarded, and report through ``Experimental summary``, that job's
last step: :class:`TestAnExperimentalLegIsNonBlockingTheSameWay`. Their
setup-python, install and test steps have caps of their own, so a slow or hung leg
fails a step rather than being cancelled with its job:
:class:`TestASlowExperimentalLegTimesOutAStepNotTheJob`.

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

from tests.project.test_python_matrix_tiers_1633 import (EXPERIMENTAL_GUARD, EXPERIMENTAL_JOB, KTLO_GUARD,
                                                         KTLO_LEGS, LEG_37, TITLE_37, annotation_level,
                                                         is_experimental, is_ktlo, is_nonblocking, job,
                                                         leg_label, legs, titles, workflow,
                                                         workflow_commands)
from tests.project.test_python_versions_1660 import ROOT, live_outputs, prose, resolve
from tests.project.test_release_gates import NULL, STATUS, evaluate_condition, evaluate_expression

if TYPE_CHECKING:
    from typing import Any, Optional

#: Every job holding a KTLO matrix leg, as (workflow, job).
KTLO_JOBS = tuple((name, job_id) for name, job_id, _ in KTLO_LEGS)
#: The jobs whose steps write annotations of their own on a KTLO leg, so set the level.
LEVELLED = (('unit-tests.yml', 'test'), ('unit-tests.yml', 'integration'),
            ('unit-tests.yml', 'pypcap-parity'), ('unit-tests.yml', 'test-ktlo'),
            ('unit-tests.yml', 'integration-ktlo'), ('unit-tests.yml', 'pypcap-parity-ktlo'),
            ('python-compatibility.yml', 'compatibility'), EXPERIMENTAL_JOB)
#: unit-tests.yml's KTLO-only jobs (#1738), which nothing gating needs. Their job-level
#: ``continue-on-error: true`` is a backstop for the failures no step contains, on top
#: of the step-level guards, which are what keep a leg's check run green.
BACKSTOPPED = (('unit-tests.yml', 'test-ktlo'), ('unit-tests.yml', 'integration-ktlo'),
               ('unit-tests.yml', 'pypcap-parity-ktlo'))
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
    ('unit-tests.yml', 'test-ktlo'): ('Upload test timings',),
    ('unit-tests.yml', 'integration-ktlo'): ('Upload test timings',),
    ('create-release.yml', 'pypi'): ('Publish package to TestPyPI',),
}
#: ``engine-tests``'s KTLO steps: the KTLO cells, and the setup step of their
#: interpreters, which reads :data:`ENGINE_KTLO_OUTPUT` (#1660).
ENGINE_KTLO = ('Run the KTLO cells (non-blocking)',)
ENGINE_KTLO_OUTPUT = '${{ needs.python-versions.outputs.engine-ktlo }}'
#: The workflow commands a step a KTLO leg runs may write.
KTLO_COMMANDS = frozenset({'${ANNOTATION_LEVEL}', 'warning', 'notice', 'group', 'endgroup'})
#: A workflow command a script writes, by its name.
COMMAND = re.compile(r'''(?:echo|printf|print\(f?)\s*["']::([^\s:"']+)''')
#: A status-check function: an ``if:`` holding none gets ``success() &&`` prepended.
STATUS_FUNCTION = re.compile(r'\b(?:success|failure|cancelled|always)\(\)')
#: A ``needs`` output a step's ``if:`` reads, such as the tier file's (#1660).
NEEDS = re.compile(r'needs\.([\w-]+)\.outputs\.([\w-]+)')
#: The outputs a step with an ``id`` is taken to set: ones that let every later step run.
OUTPUTS = {
    'apt-plan': {'key': 'apt-debs-ImageOS-X64-set-0123456789abcdef', 'restore-prefix': 'apt-debs-ImageOS-X64-set-'},
    'apt-cache': {'cache-matched-key': 'apt-debs-ImageOS-X64-set-0123456789abcdef', 'cache-hit': 'false'},
}
SUMMARY = 'KTLO summary'
SUMMARY_IF = '${{ !cancelled() && matrix.ktlo == true }}'
SUMMARY_ENV = {'LEG': "Python ${{ matrix.python-version }}${{ matrix.ktlo && ' (KTLO, non-blocking)' || '' }}",
               'STEPS': '${{ toJSON(steps) }}'}
#: ``experimental``'s report of a leg (#1660), its last step; every leg is one, so it
#: tests no ``matrix`` flag (#1732).
EXPERIMENTAL_SUMMARY = 'Experimental summary'
EXPERIMENTAL_SUMMARY_IF = '${{ !cancelled() }}'
EXPERIMENTAL_SUMMARY_ENV = {'LEG': 'Python ${{ matrix.python-version }} (experimental, non-blocking)',
                            'STEPS': '${{ toJSON(steps) }}'}
#: Why each summary's warning says the job still succeeds; the scripts differ in nothing else.
KTLO_REASON = 'KTLO legs never block (#1633), so this job still succeeds (#1672)'
EXPERIMENTAL_REASON = 'Experimental legs never block (#1660), so this job still succeeds'
#: ``experimental``'s steps with a ``timeout-minutes`` of their own (#1660), by ``id``:
#: setup-python, the install, the watcher's setup-python and requests (#1938) and the
#: tests. #1732: the tests' is GraalPy's unit tier less the round-trip sweeps, 88-113
#: minutes (estimate) from the 26% its leg reached in 25 (job 115915976024).
EXPERIMENTAL_CAPS = {'python': 5, 'install': 10, 'watcher-python': 1, 'watcher': 1, 'tests': 120}
#: ``experimental``'s own ``timeout-minutes`` (#1732), and ``test``'s, main's 45 again.
EXPERIMENTAL_JOB_CAP = 140
JOB_CAP = 45
#: The job's minutes those caps leave for the rest of an experimental leg. Everything
#: but the install and the tests took at most 0.32 minutes, setup-python included, on
#: every uncovered leg of runs 38569321543, 38569429406 and 38569522442. #1938's two
#: capped watcher steps took 2 of the 5 this was.
UNCAPPED_MINUTES = 3
#: Those steps' cap on every other leg: the largest a step's ``timeout-minutes`` may be
#: (docs.github.com, workflow-syntax, ``jobs.<job_id>.steps[*].timeout-minutes``).
DOCUMENTED_MAXIMUM = 360


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


def experimental_summary_step(spec: 'dict[str, Any]') -> 'dict[str, Any]':
    """``experimental``'s ``Experimental summary`` step (#1660)."""
    found = [step for step in spec['steps'] if step.get('name') == EXPERIMENTAL_SUMMARY]
    if len(found) != 1:
        raise AssertionError(f'expected one {EXPERIMENTAL_SUMMARY!r} step, found {len(found)}')
    return found[0]


def experimental_legs() -> 'list[dict[str, Any]]':
    """``experimental``'s legs, from the tier file (#1732)."""
    return [leg for leg in legs(*EXPERIMENTAL_JOB) if is_experimental(leg)]


def is_engine_ktlo(step: 'dict[str, Any]') -> 'bool':
    """Whether ``step`` is one of ``engine-tests``'s, which run only the KTLO interpreters."""
    return label(step) in ENGINE_KTLO or step.get('with', {}).get('python-version') == ENGINE_KTLO_OUTPUT


def stringify(value: 'object') -> 'str':
    """``value`` as an ``env:`` entry holds it."""
    if value is NULL or value is None:
        return ''
    if isinstance(value, bool):
        return 'true' if value else 'false'
    return str(value)


def interpolate(template: 'str', context: 'dict[str, Any]') -> 'str':
    """``template`` with each ``${{ ... }}`` in it evaluated, as a step's ``env:`` value."""
    return re.sub(r'\$\{\{.*?\}\}', lambda match: stringify(evaluate_expression(match.group(0), context)), template)


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


def needs_context(name: 'str', job_id: 'str', spec: 'dict[str, Any]') -> 'dict[str, Any]':
    """The ``needs`` outputs the job's steps test, each as the tier file sets it (#1660).

    An output that does not come from :file:`util/python_versions.py` is unset.

    """
    found = {}  # type: dict[str, Any]
    for step in spec['steps']:
        for target, output in NEEDS.findall(str(step.get('if', ''))):
            try:
                value = resolve(name, job_id, f'${{{{ needs.{target}.outputs.{output} }}}}')
            except AssertionError:
                value = None
            found.setdefault(target, {'outputs': {}})['outputs'][output] = NULL if value is None else value
    return found


def continue_on_error(step: 'dict[str, Any]', context: 'dict[str, Any]') -> 'bool':
    value = step.get('continue-on-error', False)
    return value if isinstance(value, bool) else evaluate_condition(str(value), context)


def run_leg(name: 'str', job_id: 'str', spec: 'dict[str, Any]', leg: 'dict[str, Any]',
            failing: 'int' = -1) -> 'tuple[str, list[Step]]':
    """The job's conclusion on ``leg``, and each step's, with step ``failing`` failing.

    A step runs when its ``if:`` holds -- with ``success()`` prepended when it calls
    no status function, which GitHub documents as the default -- and a failure is
    the job's unless the step's ``continue-on-error`` holds on this leg.

    """
    env = leg_env(name, spec, leg)
    needs = needs_context(name, job_id, spec)
    steps = {}  # type: dict[str, dict[str, Any]]
    failed = False
    record = []  # type: list[Step]
    for index, step in enumerate(spec['steps']):
        context = {'matrix': leg, 'env': env, 'steps': steps, 'inputs': {}, 'needs': needs,
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


def scenarios(name: 'str', job_id: 'str', spec: 'dict[str, Any]',
              leg: 'dict[str, Any]') -> 'list[tuple[int, str, list[Step]]]':
    """``(failing step, job conclusion, steps)`` for each step that runs on ``leg``."""
    found = []
    for index in range(len(spec['steps'])):
        conclusion, record = run_leg(name, job_id, spec, leg, failing=index)
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
        """Job-level, the run passes but the leg's check run concludes ``failure``.

        So it is never the mechanism: only :data:`BACKSTOPPED` carries it, as a
        backstop on top of the step-level guards the tests below pin (#1738).

        """
        for name, job_id in KTLO_JOBS + (('unit-tests.yml', 'engine-tests'),):
            with self.subTest(workflow=name, job=job_id):
                if (name, job_id) in BACKSTOPPED:
                    self.assertIs(job(name, job_id).get('continue-on-error'), True)
                else:
                    self.assertNotIn('continue-on-error', job(name, job_id))

    def test_no_step_can_fail_a_ktlo_leg(self) -> None:
        for name, job_id in KTLO_JOBS:
            spec = job(name, job_id)
            blocking = BLOCKS_EVERY_LEG.get((name, job_id), ())
            for leg in filter(is_ktlo, legs(name, job_id)):
                runs = scenarios(name, job_id, spec, leg)
                self.assertGreater(len(runs), 3, f'{job_id} on {leg} runs almost nothing')
                for index, conclusion, _ in runs:
                    step = label(spec['steps'][index])
                    with self.subTest(workflow=name, job=job_id, python=leg['python-version'], step=step):
                        self.assertEqual(conclusion, 'failure' if step in blocking else 'success')
        spec = job('unit-tests.yml', 'engine-tests')
        for leg in legs('unit-tests.yml', 'engine-tests'):
            ktlo = [(index, conclusion)
                    for index, conclusion, _ in scenarios('unit-tests.yml', 'engine-tests', spec, leg)
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
            for leg in filter(is_ktlo, legs(name, job_id)):
                for index, _, record in scenarios(name, job_id, spec, leg):
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
        """And on an experimental one (#1660), which is non-blocking the same way."""
        for name, job_id in LEVELLED:
            spec = job(name, job_id)
            with self.subTest(workflow=name, job=job_id):
                self.assertEqual((spec.get('env') or {}).get('ANNOTATION_LEVEL'), annotation_level(name, job_id))
            for leg in legs(name, job_id):
                with self.subTest(workflow=name, job=job_id, python=leg['python-version']):
                    self.assertEqual(leg_env(name, spec, leg)['ANNOTATION_LEVEL'],
                                     'warning' if is_nonblocking(leg) else 'error')

    def test_no_step_a_ktlo_leg_runs_writes_an_error(self) -> None:
        for name, job_id in KTLO_JOBS:
            spec = job(name, job_id)
            blocking = BLOCKS_EVERY_LEG.get((name, job_id), ())
            reached = set()  # type: set[int]
            for leg in filter(is_ktlo, legs(name, job_id)):
                for _, _, record in scenarios(name, job_id, spec, leg):
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
        """A KTLO cell's step, and the cell script it runs, write no error; a supported cell's does."""
        steps = {label(step): step for step in job('unit-tests.yml', 'engine-tests')['steps']}
        ktlo = steps['Run the KTLO cells (non-blocking)']
        self.assertEqual(ktlo.get('env'), {'PYTHONS': ENGINE_KTLO_OUTPUT, 'ANNOTATION_LEVEL': 'warning'})
        ktlo_py = live_outputs()['engine-ktlo'].split()[0]
        supported_py = live_outputs()['engine-supported'].split()[0]
        self.assertLessEqual(commands(ktlo['run']), {'group', 'endgroup', 'warning'})
        cell = steps['Write the per-cell script']['run'].split("<<'CELL'\n", 1)[1].split('\nCELL\n', 1)[0]
        self.assertLessEqual(commands(cell), {'${ANNOTATION_LEVEL}', 'notice'})
        expected = ("::{} title=Scapy failed to install on Python {}::This cell expects 'supported', "
                    'which requires a successful install. pip exited 1.')
        for py, level in ((ktlo_py, 'warning'), (supported_py, 'error')):
            with self.subTest(python=py):
                result = self.engine_cell(py, level)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(workflow_commands(result.stdout), [expected.format(level, py)])
        unset = self.engine_cell(ktlo_py, None)
        self.assertNotEqual(unset.returncode, 0)
        self.assertIn('ANNOTATION_LEVEL: unbound variable', unset.stderr)

        (self.tmp / 'engine-cell.sh').write_text('exit 1\n', encoding='utf-8')
        page = self.tmp / 'cells.md'
        result = bash(ktlo['run'], {'RUNNER_TEMP': str(self.tmp), 'ENGINE': 'Scapy', 'PYTHONS': ktlo_py,
                                    'GITHUB_STEP_SUMMARY': str(page)}, self.tmp)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(workflow_commands(result.stdout)[-1],
                         f'::warning title=Scapy failed on Python {ktlo_py} (KTLO%2C non-blocking)::{ktlo_py} is '
                         'end-of-life and KTLO per #1633; this does not fail the job.')
        self.assertEqual(page.read_text(encoding='utf-8'), f'| {ktlo_py} | Scapy | | FAILED (KTLO, non-blocking) |\n')


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
            for leg in (leg for leg in legs(name, job_id) if not is_nonblocking(leg)):
                clean, record = run_leg(name, job_id, spec, leg)
                with self.subTest(workflow=name, job=job_id, python=leg['python-version']):
                    self.assertEqual(clean, 'success')
                    self.assertEqual(record[summary].outcome, 'skipped')
                context = {'matrix': leg, 'env': leg_env(name, spec, leg)}
                for index, conclusion, record in scenarios(name, job_id, spec, leg):
                    step = spec['steps'][index]
                    with self.subTest(workflow=name, job=job_id, python=leg['python-version'], step=label(step)):
                        self.assertEqual(conclusion, 'success' if step.get('continue-on-error') is True else 'failure')
                        self.assertEqual(record[summary].outcome, 'skipped')
                        for gated in re.findall(r'steps\.([\w-]+)\.outcome', str(step.get('if', ''))):
                            self.assertFalse(continue_on_error(by_id[gated], context), gated)

    def test_no_summary_runs_on_a_supported_leg(self) -> None:
        """``test`` has one, ``KTLO summary``; ``Experimental summary`` left it with its legs (#1732)."""
        spec = job('unit-tests.yml', 'test')
        self.assertNotIn(EXPERIMENTAL_SUMMARY, [label(step) for step in spec['steps']])
        self.assertIs(spec['steps'][-1], summary_step(spec))
        for leg in (leg for leg in legs('unit-tests.yml', 'test') if not is_nonblocking(leg)):
            for _, _, record in scenarios('unit-tests.yml', 'test', spec, leg):
                with self.subTest(python=leg['python-version']):
                    self.assertEqual(record[-1].outcome, 'skipped')

    def test_a_supported_engine_cell_still_fails_its_job_as_an_error(self) -> None:
        spec = job('unit-tests.yml', 'engine-tests')
        loop = next(step for step in spec['steps'] if step.get('name') == 'Run the supported cells')
        self.assertEqual(loop.get('env'), {'PYTHONS': '${{ needs.python-versions.outputs.engine-supported }}',
                                           'ANNOTATION_LEVEL': 'error'})
        for leg in legs('unit-tests.yml', 'engine-tests'):
            for index, conclusion, _ in scenarios('unit-tests.yml', 'engine-tests', spec, leg):
                step = spec['steps'][index]
                if is_engine_ktlo(step):
                    continue
                with self.subTest(engine=leg['engine'], step=label(step)):
                    self.assertEqual(conclusion, 'success' if step.get('continue-on-error') is True else 'failure')


class TestAnExperimentalLegIsNonBlockingTheSameWay(unittest.TestCase):
    """#1660: the experimental legs conclude ``success`` and warn, as (a) and (b) pin for KTLO."""

    def setUp(self) -> None:
        self.spec = job(*EXPERIMENTAL_JOB)
        self.summary = experimental_summary_step(self.spec)
        self.position = self.spec['steps'].index(self.summary)
        self.legs = experimental_legs()
        self.assertTrue(self.legs, 'the tier file gives `experimental` no leg')
        self.assertTrue(all(map(is_experimental, legs(*EXPERIMENTAL_JOB))))

    def test_no_step_can_fail_an_experimental_leg(self) -> None:
        for leg in self.legs:
            runs = scenarios(*EXPERIMENTAL_JOB, self.spec, leg)
            self.assertGreater(len(runs), 3, f'test on {leg} runs almost nothing')
            for index, conclusion, _ in runs:
                with self.subTest(python=leg['python-version'], step=label(self.spec['steps'][index])):
                    self.assertEqual(conclusion, 'success')

    def test_every_failure_it_masks_reaches_the_experimental_summary(self) -> None:
        """It runs after any failure on an experimental leg, as the job's last step."""
        self.assertIs(self.spec['steps'][-1], self.summary)
        self.assertNotIn(SUMMARY, [label(step) for step in self.spec['steps']])
        self.assertEqual(self.summary.get('if'), EXPERIMENTAL_SUMMARY_IF)
        self.assertEqual(self.summary.get('continue-on-error'), EXPERIMENTAL_GUARD)
        self.assertEqual(self.summary.get('shell'), 'bash')
        self.assertEqual(self.summary.get('env'), EXPERIMENTAL_SUMMARY_ENV)
        for leg in self.legs:
            for index, _, record in scenarios(*EXPERIMENTAL_JOB, self.spec, leg):
                step = self.spec['steps'][index]
                if step is self.summary:
                    continue
                with self.subTest(python=leg['python-version'], step=label(step)):
                    self.assertNotEqual(record[self.position].outcome, 'skipped')
                    if step.get('continue-on-error') is not True:
                        self.assertIn('id', step)
        # One script with the KTLO summary's, so a fix to either reaches both.
        self.assertIn(EXPERIMENTAL_REASON, self.summary['run'])
        self.assertEqual(self.summary['run'].replace(EXPERIMENTAL_REASON, KTLO_REASON),
                         summary_step(job('unit-tests.yml', 'test'))['run'])

    def test_each_step_names_the_leg_by_its_tier(self) -> None:
        """``LEG`` in an annotation's title: ``(experimental, non-blocking)``."""
        named = [step for step in self.spec['steps'] if 'LEG' in (step.get('env') or {})]
        # #1740's `Containment summary` titles the tests' causes by the leg, as the others do.
        self.assertEqual([label(step) for step in named],
                         ['Install package and test dependencies', 'Containment summary', EXPERIMENTAL_SUMMARY])
        for leg in legs(*EXPERIMENTAL_JOB):
            for step in named:
                with self.subTest(python=leg['python-version'], step=label(step)):
                    self.assertEqual(interpolate(step['env']['LEG'], {'matrix': leg}), leg_label(leg))

    def test_no_step_an_experimental_leg_runs_writes_an_error(self) -> None:
        reached = set()  # type: set[int]
        for leg in self.legs:
            for _, _, record in scenarios(*EXPERIMENTAL_JOB, self.spec, leg):
                reached.update(index for index, step in enumerate(record) if step.outcome != 'skipped')
        self.assertIn(self.position, reached)
        for index in sorted(reached):
            step = self.spec['steps'][index]
            with self.subTest(step=label(step)):
                self.assertLessEqual(commands(step.get('run', '')), KTLO_COMMANDS)

    def test_the_summary_warns_once_per_failed_step(self) -> None:
        if shutil.which('bash') is None or shutil.which('jq') is None:  # pragma: no cover
            self.skipTest('bash and jq, on every Ubuntu runner image, are needed to run the summary')
        with tempfile.TemporaryDirectory(prefix='pcapkit-1660-') as tmp:
            for leg in self.legs:
                name = leg_label(leg)
                title = name.replace(',', '%2C')
                page = pathlib.Path(tmp) / 'summary.md'
                page.write_text('', encoding='utf-8')
                steps = {'checkout': 'success', 'python': 'success', 'install': 'failure', 'tests': 'skipped'}
                context = {key: {'outputs': {}, 'outcome': outcome,
                                 'conclusion': 'success' if outcome == 'failure' else outcome}
                           for key, outcome in steps.items()}
                with self.subTest(python=leg['python-version']):
                    self.assertEqual(interpolate(self.summary['env']['LEG'], {'matrix': leg}), name)
                    result = bash(self.summary['run'], {'LEG': name, 'STEPS': json.dumps(context),
                                                        'GITHUB_STEP_SUMMARY': str(page)}, pathlib.Path(tmp))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(workflow_commands(result.stdout), [
                        f'::warning title=install failed on {title}::{EXPERIMENTAL_REASON}; '
                        "see the install step's log."])
                    self.assertEqual(titles(result.stdout), [f'install failed on {name}'])
                    self.assertEqual(page.read_text(encoding='utf-8'),
                                     f'- {name}: step `install` failed; non-blocking, so this job still succeeds.\n')


class TestASlowExperimentalLegTimesOutAStepNotTheJob(unittest.TestCase):
    """#1660: an experimental leg's slow or hung step fails, which its guard contains.

    A job past its ``timeout-minutes`` is cancelled, which no step-level
    ``continue-on-error`` contains, and docs.github.com does not say whether the
    job-level one does. A step past its own is failed instead, and ``continue-on-error`` then applies to it as to any failure
    (actions/runner src/Runner.Worker/StepsRunner.cs:322-353, at 5f0b3ddcc) --
    the path :class:`TestAnExperimentalLegIsNonBlockingTheSameWay` runs.

    """

    def setUp(self) -> None:
        self.spec = job(*EXPERIMENTAL_JOB)
        self.capped = [step for step in self.spec['steps'] if 'timeout-minutes' in step]

    def caps(self, leg: 'dict[str, Any]') -> 'dict[str, Any]':
        """Each capped step's ``timeout-minutes`` on ``leg``, by ``id``."""
        return {step.get('id', label(step)): evaluate_expression(str(step['timeout-minutes']), {'matrix': leg})
                if isinstance(step['timeout-minutes'], str) else step['timeout-minutes'] for step in self.capped}

    def test_an_experimental_legs_steps_end_inside_its_job(self) -> None:
        """Each cap a whole number under the job's, the install's under the tests', all of them with room left."""
        self.assertTrue(experimental_legs())
        for leg in experimental_legs():
            caps, job_cap = self.caps(leg), self.spec['timeout-minutes']
            with self.subTest(python=leg['python-version']):
                self.assertEqual(caps, EXPERIMENTAL_CAPS)
                self.assertEqual(job_cap, EXPERIMENTAL_JOB_CAP)
                for cap in caps.values():
                    self.assertIsInstance(cap, int)
                    self.assertTrue(0 < cap < job_cap, cap)
                self.assertLess(caps['install'], caps['tests'])
                self.assertLessEqual(sum(caps.values()) + UNCAPPED_MINUTES, job_cap)
                for step in self.capped:
                    self.assertTrue(continue_on_error(step, {'matrix': leg}), label(step))

    def test_test_keeps_mains_caps(self) -> None:
        """#1732: ``test``'s job cap is 45 again, and none of its steps has one, so the 45 binds.

        main's step caps were 360, the documented maximum, on every leg but the
        experimental ones, which leave with them.

        """
        spec = job('unit-tests.yml', 'test')
        self.assertEqual(spec['timeout-minutes'], JOB_CAP)
        self.assertEqual([label(step) for step in spec['steps'] if 'timeout-minutes' in step], [])
        self.assertGreaterEqual(DOCUMENTED_MAXIMUM, JOB_CAP)

    def test_the_workflows_page_states_the_caps(self) -> None:
        page = prose(ROOT / 'docs' / 'source' / 'contributing' / 'workflows.rst')
        stated = re.findall(r'caps of their own, of ((?:\d+, )+\d+) and (\d+) minutes', page)
        self.assertEqual([tuple(head.split(', ')) + (last,) for head, last in stated],
                         [tuple(str(cap) for cap in EXPERIMENTAL_CAPS.values())])
        self.assertEqual(re.findall(r"minutes, under the job's (\d+)", page), [str(EXPERIMENTAL_JOB_CAP)])


if __name__ == '__main__':
    unittest.main()
