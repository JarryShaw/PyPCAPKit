# -*- coding: utf-8 -*-
"""#1967: the conda jobs keep no step or ``case`` arm for a runner they have no leg on.

This guards the conda jobs of :file:`.github/workflows/create-release.yml` and
:file:`.github/workflows/cron-conda.yml` -- ``conda-build``, ``conda-test`` and
the publisher, ``conda`` or ``conda-dist`` (#3133) -- against code no run
reaches: in a job with no ``windows-latest`` leg, a Windows-only step such as
``Install and Setup (Windows)``, a ``matrix.os != 'windows-latest'`` guard on its
twin, or a ``windows-latest`` arm in a ``case "${{ matrix.os }}"``.

* :class:`TestNoDeadRunnerCode` pins that no step's ``if:`` or
  ``continue-on-error`` names a runner label the job lacks, no ``case`` arm maps
  one, :file:`util/release_conda.py`, which their steps run (#1967), maps no
  label that no conda job runs on, and, in a job with no Windows leg, no step is
  Windows-only. A job with no matrix, as the build and the publisher are since
  they handle one noarch package (#3133), names no ``matrix.`` value either,
  which would read as empty.
  So a leg comes with its steps added deliberately, rather than reviving ones
  nobody has run.
* :class:`TestTheCheckSeesDeadCode` feeds :func:`dead` the jobs with such dead
  code rebuilt into them from the real ones, so the pin cannot pass by reading
  nothing.

"""

from __future__ import annotations

import copy
import re
import unittest
from typing import TYPE_CHECKING

from tests import _workflows
from util import release_conda

if TYPE_CHECKING:
    from typing import Any, Optional

#: Test tier (#1958): reads the workflow files, a question about the tree.
__tier__ = 'LATEST'

#: The conda jobs, as (workflow, job).
JOBS = tuple((name, job_id) for name in ('create-release.yml', 'cron-conda.yml')
             for job_id in ('conda-build', 'conda-test', 'conda' if name == 'create-release.yml' else 'conda-dist'))
#: The build jobs, whose steps the rebuilt dead code below is grafted onto (#3133).
BUILD_JOBS = (('create-release.yml', 'conda-build'), ('cron-conda.yml', 'conda-build'))
#: A ``matrix.os`` comparison in an ``if:``, capturing the label compared against.
GUARD = re.compile(r"matrix\.os\s*[!=]=\s*'([^']+)'")
#: A ``case "${{ matrix.os }}" in`` block of a step's ``run:``.
CASE = re.compile(r'case "\$\{\{ matrix\.os \}\}" in\n(.*?)\n\s*esac', re.DOTALL)
#: An arm of that block, capturing its pattern.
ARM = re.compile(r'^\s*([^\s()]+)\)\s*$', re.MULTILINE)
#: A Windows runner label, or the step name of a Windows-only step.
WINDOWS = re.compile(r'windows', re.IGNORECASE)
#: An ``if:`` that runs its step on Windows alone.
WINDOWS_ONLY = re.compile(r"(?:matrix|runner)\.os\s*==\s*'[^']*windows", re.IGNORECASE)
#: A ``run:`` that maps the leg through :data:`release_conda.PLATFORMS` (#1967).
MAPS = re.compile(r'\butil/release_conda\.py (?:leg|build)\b')
#: A ``matrix`` context in an expression, capturing the value it reads.
MATRIX = re.compile(r'\bmatrix\.([\w-]+)')


def labels_of(spec: 'dict[str, Any]') -> 'list[str]':
    """The runner labels ``spec``, a job, runs on: its matrix's ``os`` axis, or else its ``runs-on``."""
    if 'strategy' in spec:
        return list(spec['strategy']['matrix']['os'])
    return [str(spec['runs-on'])]


def legs() -> 'set[str]':
    """Every runner label a conda job has a leg on."""
    return {label for name, job_id in JOBS for label in labels_of(_workflows.job(name, job_id))}


def dead(spec: 'dict[str, Any]', every: 'Optional[set[str]]' = None) -> 'list[str]':
    """What of ``spec``, a job, names a runner its matrix has no leg on.

    The labels :data:`release_conda.PLATFORMS` maps serve both jobs, so they are
    held to ``every``, the labels either has a leg on, by default :func:`legs`.

    """
    labels = labels_of(spec)
    every = legs() if every is None else every
    windows_leg = any(WINDOWS.search(label) for label in labels)
    found = []
    for step in spec['steps']:
        name = str(step.get('name') or step.get('uses') or step.get('id'))
        condition = str(step.get('if', ''))
        if 'strategy' not in spec:
            found.extend(f'{name}: reads matrix.{value}, and the job has no matrix'
                         for value in sorted(set(MATRIX.findall(str(step)))))
        for key in ('if', 'continue-on-error'):
            for label in GUARD.findall(str(step.get(key, ''))):
                if label not in labels:
                    found.append(f'{name}: `{key}:` compares matrix.os with {label}, which is no leg')
        if not windows_leg and (WINDOWS_ONLY.search(condition) or WINDOWS.search(str(step.get('name', '')))):
            found.append(f'{name}: Windows-only, and no leg is Windows')
        for block in CASE.findall(str(step.get('run', ''))):
            for pattern in ARM.findall(block):
                if pattern != '*' and pattern not in labels:
                    found.append(f'{name}: `case` arm {pattern}, which is no leg')
        if MAPS.search(str(step.get('run', ''))):
            found.extend(f'{name}: release_conda.py maps {label}, which no conda job has a leg on'
                         for label in sorted(set(release_conda.PLATFORMS) - every))
            found.extend(f'{name}: release_conda.py maps no platform for {label}'
                         for label in labels if label not in release_conda.PLATFORMS)
    return found


class TestNoDeadRunnerCode(unittest.TestCase):
    """Each conda job's steps and ``case`` arms cover its legs and nothing else."""

    def test_no_step_or_arm_names_a_missing_leg(self) -> None:
        for name, job_id in JOBS:
            with self.subTest(workflow=name, job=job_id):
                self.assertEqual(dead(_workflows.job(name, job_id)), [])


def without_windows(step: 'dict[str, Any]') -> 'dict[str, Any]':
    """``step`` without #2060's Windows guard, ``case`` arm or ``if:`` clause."""
    step = {key: value for key, value in step.items()
            if not (key == 'continue-on-error' and WINDOWS.search(str(value)))}
    if 'if' in step:
        step['if'] = str(step['if']).replace(" && matrix.os != 'windows-latest'", '')
    if 'run' in step:
        step['run'] = re.sub(r'\n\s*windows-latest\)\n[^\n]*\n\s*;;', '', str(step['run']))
    return step


class TestTheCheckSeesDeadCode(unittest.TestCase):
    """:func:`dead` reports each kind of dead runner code: a step, a guard and a ``case`` arm."""

    def test_it_reports_a_windows_step_guard_and_arm(self) -> None:
        for name, job_id in BUILD_JOBS:
            spec = copy.deepcopy(_workflows.job(name, job_id))
            # A matrix of its one runner, as a job with no Windows leg.
            spec['strategy'] = {'matrix': {'os': labels_of(spec)}}
            spec['steps'] = [without_windows(step) for step in spec['steps']
                             if not WINDOWS.search(str(step.get('name', '')))]
            install = next(step for step in spec['steps'] if step.get('name') == 'Install and Setup')
            install['if'] = "${{ matrix.os != 'windows-latest' }}"
            spec['steps'].append({'name': 'Install and Setup (Windows)',
                                  'if': "${{ matrix.os == 'windows-latest' }}",
                                  'run': 'python -m pip install -U pip setuptools wheel\n'})
            spec['steps'].append({'name': 'Map the leg', 'run': (
                'case "${{ matrix.os }}" in\n'
                '  windows-latest)\n'
                '    target_platform="win-64"\n'
                '    ;;\n'
                '  *)\n'
                '    target_platform=""\n'
                '    ;;\n'
                'esac\n')})
            with self.subTest(workflow=name, job=job_id):
                self.assertEqual(dead(spec), [
                    'Install and Setup: `if:` compares matrix.os with windows-latest, which is no leg',
                    'Install and Setup (Windows): `if:` compares matrix.os with windows-latest, which is no leg',
                    'Install and Setup (Windows): Windows-only, and no leg is Windows',
                    'Map the leg: `case` arm windows-latest, which is no leg',
                ])

    def test_a_matrix_value_in_a_job_with_none_is_reported(self) -> None:
        """#3133: what dropping the per-platform matrix could leave behind."""
        for name, job_id in BUILD_JOBS:
            spec = copy.deepcopy(_workflows.job(name, job_id))
            build = next(step for step in spec['steps'] if step.get('name') == 'Build conda packages')
            build['env']['PCAPKIT_PYTHON_VERSION'] = '${{ matrix.python-version }}'
            build['if'] = "${{ matrix.os == 'ubuntu-latest' }}"
            with self.subTest(workflow=name, job=job_id):
                self.assertEqual(dead(spec), ['Build conda packages: reads matrix.os, and the job has no matrix',
                                              'Build conda packages: reads matrix.python-version, and the job has '
                                              'no matrix'])

    def test_a_runner_the_script_does_not_map_is_reported(self) -> None:
        for job_id, step in (('conda', 'Check whether this leg is already on Anaconda'),
                             ('conda-build', 'Build conda packages')):
            spec = copy.deepcopy(_workflows.job('create-release.yml', job_id))
            spec['runs-on'] = 'macos-99'
            with self.subTest(job=job_id):
                self.assertEqual(dead(spec, legs() | {'macos-99'}),
                                 [f'{step}: release_conda.py maps no platform for macos-99'])

    def test_a_windows_leg_allows_its_own_steps(self) -> None:
        spec = {'strategy': {'matrix': {'os': ['ubuntu-latest', 'windows-latest']}},
                'steps': [{'name': 'Setup (Windows)', 'if': "${{ matrix.os == 'windows-latest' }}",
                           'run': 'case "${{ matrix.os }}" in\n  windows-latest)\n    x=1\n    ;;\nesac\n'}]}
        self.assertEqual(dead(spec), [])


if __name__ == '__main__':
    unittest.main()
