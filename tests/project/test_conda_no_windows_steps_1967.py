# -*- coding: utf-8 -*-
"""#1967: the conda jobs keep no step or ``case`` arm for a runner they have no leg on.

``conda`` in :file:`.github/workflows/create-release.yml` and ``conda-dist`` in
:file:`.github/workflows/cron-conda.yml` have had no ``windows-latest`` leg since
2023, yet carried ``Install and Setup (Windows)``, ``Setup Conda Distribution
(Windows)``, the ``matrix.os != 'windows-latest'`` guards on their twins, and a
``windows-latest`` arm in each ``case "${{ matrix.os }}"``: code no run reached.

* :class:`TestNoDeadRunnerCode` pins that no step's ``if:`` names a runner label
  the job's matrix lacks, no ``case`` arm maps one, and, with no Windows leg, no
  step is Windows-only. So adding a Windows leg back means adding its steps back
  deliberately, rather than reviving ones nobody has run.
* :class:`TestTheCheckSeesDeadCode` feeds :func:`dead` the jobs as they stood
  before, rebuilt from the current ones, so the pin cannot pass by reading nothing.

"""

from __future__ import annotations

import copy
import re
import unittest
from typing import TYPE_CHECKING

from tests import _workflows

if TYPE_CHECKING:
    from typing import Any

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


def dead(spec: 'dict[str, Any]') -> 'list[str]':
    """What of ``spec``, a job, names a runner its matrix has no leg on."""
    labels = list(spec['strategy']['matrix']['os'])
    windows_leg = any(WINDOWS.search(label) for label in labels)
    found = []
    for step in spec['steps']:
        name = str(step.get('name') or step.get('uses') or step.get('id'))
        condition = str(step.get('if', ''))
        for label in GUARD.findall(condition):
            if label not in labels:
                found.append(f'{name}: `if:` compares matrix.os with {label}, which is no leg')
        if not windows_leg and (WINDOWS_ONLY.search(condition) or WINDOWS.search(str(step.get('name', '')))):
            found.append(f'{name}: Windows-only, and no leg is Windows')
        for block in CASE.findall(str(step.get('run', ''))):
            for pattern in ARM.findall(block):
                if pattern != '*' and pattern not in labels:
                    found.append(f'{name}: `case` arm {pattern}, which is no leg')
    return found


class TestNoDeadRunnerCode(unittest.TestCase):
    """Each conda job's steps and ``case`` arms cover its legs and nothing else."""

    def test_no_step_or_arm_names_a_missing_leg(self) -> None:
        for name, job_id in JOBS:
            with self.subTest(workflow=name, job=job_id):
                self.assertEqual(dead(_workflows.job(name, job_id)), [])


class TestTheCheckSeesDeadCode(unittest.TestCase):
    """:func:`dead` reports each kind of dead code the jobs held before #1967."""

    def test_it_reports_a_windows_step_guard_and_arm(self) -> None:
        for name, job_id in JOBS:
            spec = copy.deepcopy(_workflows.job(name, job_id))
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

    def test_a_windows_leg_allows_its_own_steps(self) -> None:
        spec = {'strategy': {'matrix': {'os': ['ubuntu-latest', 'windows-latest']}},
                'steps': [{'name': 'Setup (Windows)', 'if': "${{ matrix.os == 'windows-latest' }}",
                           'run': 'case "${{ matrix.os }}" in\n  windows-latest)\n    x=1\n    ;;\nesac\n'}]}
        self.assertEqual(dead(spec), [])


if __name__ == '__main__':
    unittest.main()
