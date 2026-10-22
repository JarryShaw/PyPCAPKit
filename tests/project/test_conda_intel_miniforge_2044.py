# -*- coding: utf-8 -*-
"""#2044: the conda jobs' ``macos-26-intel`` legs install Miniforge.

The step "Conda environment creation and activation" of ``conda-dist`` in
:file:`.github/workflows/cron-conda.yml` and of ``conda`` in
:file:`.github/workflows/create-release.yml` named no installer, so on the Intel
runner setup-miniconda downloaded ``Miniconda3-latest-MacOSX-x86_64.sh``. That
installer is frozen at conda 25.7.0, which conflicts with conda-forge's
conda-content-trust plugin and has no py314 build. The Intel legs now pass
``miniforge-version: latest``; every other leg passes an empty string, which
names no installer, so it keeps the bundled or downloaded Miniconda.

The step's inputs are evaluated per matrix leg with
:func:`tests.project.test_release_gates.evaluate_expression`, cast to a string as
the runner casts a ``with:`` value, and trimmed as ``core.getInput`` trims it.
:func:`installer` then chooses the way setup-miniconda's provider list does: an
``installer-url`` first, then Miniforge when ``miniforge-version`` or
``miniforge-variant`` is non-empty, else Miniconda.

"""

from __future__ import annotations

import unittest
from typing import TYPE_CHECKING

from tests import _workflows
from tests.project.test_release_gates import _as_string, evaluate_expression

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): reads the workflow files, a question about the tree.
__tier__ = 'LATEST'

#: The conda jobs, as (workflow, job).
JOBS = (('cron-conda.yml', 'conda-dist'), ('create-release.yml', 'conda'))
STEP = 'Conda environment creation and activation'
ACTION = 'conda-incubator/setup-miniconda'
#: The leg whose Miniconda installer is frozen.
INTEL = 'macos-26-intel'
#: The installer inputs setup-miniconda reads to choose a provider.
INSTALLER_INPUTS = ('installer-url', 'miniconda-version', 'miniforge-variant', 'miniforge-version')


def step(name: 'str', job_id: 'str') -> 'dict[str, Any]':
    """The setup-miniconda step of job ``job_id`` in workflow ``name``."""
    found = [entry for entry in _workflows.steps(name, job_id) if entry.get('name') == STEP]
    if len(found) != 1:
        raise AssertionError(f'{name}: {job_id} has {len(found)} steps named {STEP!r}, not one')
    return found[0]


def legs(name: 'str', job_id: 'str') -> 'list[str]':
    """The ``os`` values of job ``job_id``'s matrix in workflow ``name``."""
    return list(_workflows.job(name, job_id)['strategy']['matrix']['os'])


def inputs(entry: 'dict[str, Any]', os: 'str') -> 'dict[str, str]':
    """Each installer input of ``entry`` as the action receives it on leg ``os``."""
    context = {'matrix': {'os': os}}  # type: dict[str, object]
    given = entry.get('with', {})
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
    """Miniforge on ``macos-26-intel``, and the former installer on every other leg."""

    def test_the_step_is_setup_miniconda(self) -> None:
        for name, job_id in JOBS:
            with self.subTest(workflow=name, job=job_id):
                self.assertTrue(_workflows.pinned(step(name, job_id).get('uses'), ACTION))

    def test_the_intel_leg_installs_the_latest_miniforge(self) -> None:
        for name, job_id in JOBS:
            with self.subTest(workflow=name, job=job_id):
                self.assertIn(INTEL, legs(name, job_id))
                received = inputs(step(name, job_id), INTEL)
                self.assertEqual(installer(received), 'Miniforge')
                self.assertEqual(received['miniforge-version'], 'latest')
                self.assertEqual(received['miniforge-variant'], '')

    def test_the_other_legs_keep_miniconda(self) -> None:
        for name, job_id in JOBS:
            others = [os for os in legs(name, job_id) if os != INTEL]
            with self.subTest(workflow=name, job=job_id):
                self.assertTrue(others, 'no other leg to check')
            for os in others:
                with self.subTest(workflow=name, job=job_id, os=os):
                    self.assertEqual(installer(inputs(step(name, job_id), os)), 'Miniconda')

    def test_no_leg_names_two_installers(self) -> None:
        """setup-miniconda refuses ``miniforge-version`` with ``miniconda-version`` or ``installer-url``."""
        for name, job_id in JOBS:
            for os in legs(name, job_id):
                received = inputs(step(name, job_id), os)
                with self.subTest(workflow=name, job=job_id, os=os):
                    if received['miniforge-version']:
                        self.assertEqual(received['miniconda-version'], '')
                        self.assertEqual(received['installer-url'], '')


if __name__ == '__main__':
    unittest.main()
