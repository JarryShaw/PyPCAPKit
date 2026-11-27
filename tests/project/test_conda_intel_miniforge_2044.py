# -*- coding: utf-8 -*-
"""#2044: every conda job's ``macos-26-intel`` leg installs Miniforge.

Given no installer, setup-miniconda downloads
``Miniconda3-latest-MacOSX-x86_64.sh`` on the Intel runner. That installer is
frozen at conda 25.7.0, which conflicts with conda-forge's conda-content-trust
plugin. So on the Intel legs every setup-miniconda step passes
``miniforge-version: latest``; every other leg passes an empty string, which
names no installer, so it keeps the bundled or downloaded Miniconda. Since
#3133 those legs are ``conda-test``'s, in
:file:`.github/workflows/create-release.yml` and
:file:`.github/workflows/cron-conda.yml`; :func:`intel_steps` finds every job
of every workflow that sets up conda on the Intel runner, so a new one is held
to the same rule.

The step's inputs are evaluated per matrix leg with
:func:`tests.project.test_release_gates.evaluate_expression`, cast to a string as
the runner casts a ``with:`` value, and trimmed as ``core.getInput`` trims it.
:func:`installer` then chooses the way setup-miniconda's provider list does: an
``installer-url`` first, then Miniforge when ``miniforge-version`` or
``miniforge-variant`` is non-empty, else Miniconda.

#2123: with Miniforge, installing another Python into base rebuilds
conda-forge's libmambapy at a version conda-libmamba-solver cannot drive, so the
Intel legs leave base's Python alone; :class:`TestTheIntelLegsKeepBasesPython`
pins that.

"""

from __future__ import annotations

import unittest
from typing import TYPE_CHECKING

from tests import _workflows
from tests.project.test_python_versions_1660 import script as versions_script
from tests.project.test_release_gates import _as_string, evaluate_expression

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): reads the workflow files, a question about the tree.
__tier__ = 'LATEST'

ACTION = 'conda-incubator/setup-miniconda'
#: The leg whose Miniconda installer is frozen.
INTEL = 'macos-26-intel'
#: The installer inputs setup-miniconda reads to choose a provider.
INSTALLER_INPUTS = ('installer-url', 'miniconda-version', 'miniforge-variant', 'miniforge-version')
#: The jobs with an Intel leg since #3133, which :func:`intel_steps` must find.
CONDA_TEST = (('create-release.yml', 'conda-test'), ('cron-conda.yml', 'conda-test'))


def legs(spec: 'dict[str, Any]') -> 'list[str]':
    """The runner labels job ``spec`` runs on: its matrix's ``os`` axis, or else its ``runs-on``."""
    strategy = spec.get('strategy')
    matrix = strategy.get('matrix') if isinstance(strategy, dict) else None
    # A whole-matrix ``fromJSON`` reads as a string: no ``os`` axis to read.
    axis = matrix.get('os') if isinstance(matrix, dict) else None
    return [str(label) for label in axis] if isinstance(axis, list) else [str(spec.get('runs-on'))]


def intel_steps() -> 'list[tuple[str, str, dict[str, Any], list[str]]]':
    """``(workflow, job, step, legs)`` for each setup-miniconda step of a job with an Intel leg."""
    found = []
    for path in sorted(_workflows.WORKFLOWS.glob('*.yml')):
        for job_id, spec in (_workflows.load(path).get('jobs') or {}).items():
            labels = legs(spec)
            if INTEL not in labels:
                continue
            found.extend((path.name, job_id, step, labels) for step in spec.get('steps') or ()
                         if _workflows.pinned(step.get('uses'), ACTION))
    return found


def inputs(step: 'dict[str, Any]', os: 'str') -> 'dict[str, str]':
    """Each installer input of ``step`` as the action receives it on leg ``os``."""
    context = {'matrix': {'os': os}}  # type: dict[str, object]
    given = step.get('with') or {}
    return {key: _as_string(evaluate_expression(str(given[key]), context)).strip() if key in given else ''
            for key in INSTALLER_INPUTS}


def installer(received: 'dict[str, str]') -> 'str':
    """The installer setup-miniconda picks for ``received``, per its provider order."""
    if received['installer-url']:
        return 'installer-url'
    if received['miniforge-version'] or received['miniforge-variant']:
        return 'Miniforge'
    return 'Miniconda'


class TestTheIntelLegsInstallMiniforge(unittest.TestCase):
    """Miniforge on ``macos-26-intel``, and Miniconda on every other leg."""

    def test_the_scan_finds_conda_test(self) -> None:
        """#3133's jobs are found, so the checks below read them rather than nothing."""
        found = {(name, job_id) for name, job_id, _, _ in intel_steps()}
        for name, job_id in CONDA_TEST:
            with self.subTest(workflow=name, job=job_id):
                self.assertIn((name, job_id), found)

    def test_the_intel_leg_installs_the_latest_miniforge(self) -> None:
        for name, job_id, step, _ in intel_steps():
            with self.subTest(workflow=name, job=job_id):
                received = inputs(step, INTEL)
                self.assertEqual(installer(received), 'Miniforge')
                self.assertEqual(received['miniforge-version'], 'latest')
                self.assertEqual(received['miniforge-variant'], '')

    def test_the_other_legs_keep_miniconda(self) -> None:
        for name, job_id, step, labels in intel_steps():
            for os in labels:
                if os == INTEL:
                    continue
                with self.subTest(workflow=name, job=job_id, os=os):
                    self.assertEqual(installer(inputs(step, os)), 'Miniconda')

    def test_no_leg_names_two_installers(self) -> None:
        """setup-miniconda refuses ``miniforge-version`` with ``miniconda-version`` or ``installer-url``."""
        for name, job_id, step, labels in intel_steps():
            for os in labels:
                received = inputs(step, os)
                with self.subTest(workflow=name, job=job_id, os=os):
                    if received['miniforge-version']:
                        self.assertEqual(received['miniconda-version'], '')
                        self.assertEqual(received['installer-url'], '')


class TestTheIntelLegsKeepBasesPython(unittest.TestCase):
    """#2123: no Python install into base on ``macos-26-intel``, on any CPython of either tier."""

    def test_the_intel_leg_installs_no_python(self) -> None:
        script = versions_script()
        data = script.load()
        pythons = [*script.tier(data, 'cpython', 'ktlo'), *script.tier(data, 'cpython', 'supported')]
        self.assertTrue(pythons, 'no CPython to check')
        for name, job_id, step, _ in intel_steps():
            given = (step.get('with') or {}).get('python-version')
            for python in pythons:
                context = {'matrix': {'os': INTEL, 'python-version': python}}  # type: dict[str, object]
                received = '' if given is None else _as_string(evaluate_expression(str(given), context)).strip()
                with self.subTest(workflow=name, job=job_id, python=python):
                    self.assertEqual(received, '')


if __name__ == '__main__':
    unittest.main()
