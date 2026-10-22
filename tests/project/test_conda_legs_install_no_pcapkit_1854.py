# -*- coding: utf-8 -*-
"""The conda legs do not install pcapkit into setup-python's interpreter (#1854).

``conda-dist`` in :file:`.github/workflows/cron-conda.yml` and ``conda`` in
:file:`.github/workflows/create-release.yml` ran ``pip install -e .[all]``, and
the release leg ``pip install pathlib2 typing_extensions`` too, for no later
step: ``pip download`` needs pip alone, ``conda build`` installs into its own
host environment, the version comes from job outputs, and ``--smoke`` runs its
probe under ``-I -S``. On ``macos-26-intel`` the extras resolve a cryptography
with no Intel wheel, which pip has to compile or fail on. The jobs are read
with :func:`tests._workflows.job`.

"""

from __future__ import annotations

import pathlib
import re
import shlex
import unittest
from typing import TYPE_CHECKING

from tests import _workflows

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from typing import Any

WORKFLOWS = pathlib.Path(__file__).resolve().parents[2] / '.github' / 'workflows'
#: The conda jobs, as (workflow, job).
JOBS = (('cron-conda.yml', 'conda-dist'), ('create-release.yml', 'conda'))
#: What each install step still upgrades: ``pip download`` runs on this pip.
BUILD_TOOLS = ['python', '-m', 'pip', 'install', '-U', 'pip', 'setuptools', 'wheel']
#: The backports #1821 removed from ``cron-conda.yml``.
BACKPORTS = {'pathlib2', 'typing_extensions', 'typing-extensions'}
#: A step running pcapkit from setup-python's interpreter, which would need it installed.
USES_PCAPKIT = re.compile(r'\bimport\s+pcapkit\b|-m\s+pcapkit\b|\bpcapkit-(?:cli|vendor)\b')


def commands(step: 'dict[str, Any]') -> 'list[str]':
    """The step's ``run`` lines that are not blank or comments."""
    return [line.strip() for line in str(step.get('run', '')).splitlines()
            if line.strip() and not line.lstrip().startswith('#')]


def installs(step: 'dict[str, Any]') -> 'list[list[str]]':
    """Each ``python -m pip install`` command of the step, split as the shell splits it."""
    found = []
    for line in commands(step):
        if re.search(r'\bpip\s+install\b', line):
            words = shlex.split(line)
            if words[1:4] != ['-m', 'pip', 'install']:
                raise AssertionError(f'not run as `python -m pip install`, so not read here: {line}')
            found.append(words)
    return found


@unittest.skipIf(yaml is None, 'PyYAML, from the test extra, is not installed')
class TestTheCondaLegsInstallOnlyTheBuildTools(unittest.TestCase):
    """setup-python's interpreter gets pip, setuptools and wheel, and nothing to import."""

    def steps(self) -> 'list[tuple[str, str, dict[str, Any]]]':
        found = []
        for name, job_id in JOBS:
            spec = _workflows.job(WORKFLOWS / name, job_id)
            found.extend((name, job_id, step) for step in spec['steps'])
        return found

    def test_no_leg_installs_the_project(self) -> None:
        for name, job_id, step in self.steps():
            for words in installs(step):
                targets = [word for word in words[4:] if not word.startswith('-')]
                with self.subTest(workflow=name, job=job_id, step=step.get('name'), command=words):
                    self.assertFalse([word for word in targets if word == '.' or word.startswith('.[')])

    def test_no_leg_installs_the_backports(self) -> None:
        for name, job_id, step in self.steps():
            for words in installs(step):
                with self.subTest(workflow=name, job=job_id, step=step.get('name'), command=words):
                    self.assertFalse(BACKPORTS.intersection(words))

    def test_each_install_step_upgrades_the_build_tools_alone(self) -> None:
        for name, job_id in JOBS:
            steps = [step for found, job, step in self.steps() if (found, job) == (name, job_id)
                     and str(step.get('name', '')).startswith('Install and Setup')]
            with self.subTest(workflow=name, job=job_id):
                self.assertEqual(len(steps), 1, 'one step for every leg, with no Windows twin (#1967)')
            for step in steps:
                with self.subTest(workflow=name, job=job_id, step=step['name']):
                    self.assertEqual(installs(step), [BUILD_TOOLS])

    def test_no_step_runs_pcapkit_from_that_interpreter(self) -> None:
        """What would need the install back: an import, ``-m pcapkit`` or an entry point."""
        for name, job_id, step in self.steps():
            with self.subTest(workflow=name, job=job_id, step=step.get('name')):
                self.assertFalse([line for line in commands(step) if USES_PCAPKIT.search(line)])


if __name__ == '__main__':
    unittest.main()
