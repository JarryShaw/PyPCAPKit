# -*- coding: utf-8 -*-
"""#1967: the conda jobs keep no step or ``case`` arm for a runner they have no leg on.

``conda`` in :file:`.github/workflows/create-release.yml` and ``conda-dist`` in
:file:`.github/workflows/cron-conda.yml` have had no ``windows-latest`` leg since
2023, yet carried ``Install and Setup (Windows)``, ``Setup Conda Distribution
(Windows)``, the ``matrix.os != 'windows-latest'`` guards on their twins, and a
``windows-latest`` arm in each ``case "${{ matrix.os }}"``: code no run reached.

* :class:`TestNoDeadRunnerCode` pins that no step's ``if:`` or
  ``continue-on-error`` names a runner label the job's matrix lacks, no ``case``
  arm maps one, :file:`util/release_conda.py`, which both jobs' steps run since
  #1967, maps no label that neither job has a leg on, and, with no Windows leg,
  no step is Windows-only. So adding a
  Windows leg back means adding its steps back deliberately, rather than
  reviving ones nobody has run. #2060 did so for both jobs, whose Windows
  steps are therefore live.
* :class:`TestTheCheckSeesDeadCode` feeds :func:`dead` the jobs as they stood
  before, rebuilt from the current ones, so the pin cannot pass by reading
  nothing, and ``conda-dist`` without its Windows leg, whose steps must then read
  as dead.

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
JOBS = (('create-release.yml', 'conda'), ('cron-conda.yml', 'conda-dist'))
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


def legs() -> 'set[str]':
    """Every runner label a conda job has a leg on."""
    return {label for name, job_id in JOBS for label in _workflows.job(name, job_id)['strategy']['matrix']['os']}


def dead(spec: 'dict[str, Any]', every: 'Optional[set[str]]' = None) -> 'list[str]':
    """What of ``spec``, a job, names a runner its matrix has no leg on.

    The labels :data:`release_conda.PLATFORMS` maps serve both jobs, so they are
    held to ``every``, the labels either has a leg on, by default :func:`legs`.

    """
    labels = list(spec['strategy']['matrix']['os'])
    every = legs() if every is None else every
    windows_leg = any(WINDOWS.search(label) for label in labels)
    found = []
    for step in spec['steps']:
        name = str(step.get('name') or step.get('uses') or step.get('id'))
        condition = str(step.get('if', ''))
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
    """:func:`dead` reports each kind of dead code the jobs held before #1967."""

    def test_it_reports_a_windows_step_guard_and_arm(self) -> None:
        for name, job_id in JOBS:
            spec = copy.deepcopy(_workflows.job(name, job_id))
            # #2060: conda-dist as it stood before its Windows leg came back.
            spec['strategy']['matrix']['os'] = [os for os in spec['strategy']['matrix']['os']
                                                if not WINDOWS.search(os)]
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

    def test_dropping_the_windows_legs_leaves_their_steps_dead(self) -> None:
        """#2060's steps are live only while the legs are there."""
        for name, job_id in JOBS:
            spec = copy.deepcopy(_workflows.job(name, job_id))
            spec['strategy']['matrix']['os'].remove('windows-latest')
            found = dead(spec, legs() - {'windows-latest'})
            for line in (
                    'Upload conda packages to Anaconda: `if:` compares matrix.os with windows-latest, which is no leg',
                    'Upload conda packages to Anaconda (Windows): Windows-only, and no leg is Windows',
                    'Build conda packages: release_conda.py maps windows-latest, which no conda job has a leg on'):
                with self.subTest(workflow=name, job=job_id, line=line):
                    self.assertIn(line, found)

    def test_a_leg_the_script_does_not_map_is_reported(self) -> None:
        spec = copy.deepcopy(_workflows.job('create-release.yml', 'conda'))
        spec['strategy']['matrix']['os'].append('macos-99')
        self.assertEqual(dead(spec, legs() | {'macos-99'}), [
            "Check whether this leg is already on Anaconda: release_conda.py maps no platform for macos-99",
            'Build conda packages: release_conda.py maps no platform for macos-99',
        ])

    def test_a_windows_leg_allows_its_own_steps(self) -> None:
        spec = {'strategy': {'matrix': {'os': ['ubuntu-latest', 'windows-latest']}},
                'steps': [{'name': 'Setup (Windows)', 'if': "${{ matrix.os == 'windows-latest' }}",
                           'run': 'case "${{ matrix.os }}" in\n  windows-latest)\n    x=1\n    ;;\nesac\n'}]}
        self.assertEqual(dead(spec), [])


if __name__ == '__main__':
    unittest.main()
