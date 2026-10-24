# -*- coding: utf-8 -*-
"""#2044: the conda jobs' ``macos-26-intel`` legs upload with the anaconda-client CLI.

``anaconda/actions/upload-package`` v0.3.1 installs its CLI from
``anaconda.sh/releases/stable/v0.2.1/ana-darwin-x86_64``, which returns 404, so
the step "Upload conda packages to Anaconda" failed on every Intel leg of
``conda-dist`` in :file:`.github/workflows/cron-conda.yml` and would on ``conda``
in :file:`.github/workflows/create-release.yml`. That step now skips the Intel
leg, and "Upload conda packages to Anaconda (Intel)" runs there alone, making
the action's own ``anaconda --token … upload --user …`` call from conda-forge's
anaconda-client, with ``--skip-existing``.

Each step's ``if:`` is evaluated per matrix leg with
:func:`tests.project.test_release_gates.evaluate_condition`. The CLI step's
script, :file:`util/release_conda.py` ``upload`` since #1967, is run with a
stand-in ``conda`` and ``anaconda``, and the arguments it passes are compared
with those :func:`action_arguments` builds as the action's "Upload to
anaconda.org" step does.

"""

from __future__ import annotations

import os
import pathlib
import stat
import subprocess  # nosec: B404
import sys
import tempfile
import textwrap
import unittest
from typing import TYPE_CHECKING

from tests import _workflows
from tests._support import scale_timeout
from tests.project.test_conda_native_platforms_1822 import BASH
from tests.project.test_release_gates import evaluate_condition

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): reads the workflow files, a question about the tree.
__tier__ = 'LATEST'

#: The conda jobs, as (workflow, job).
JOBS = (('cron-conda.yml', 'conda-dist'), ('create-release.yml', 'conda'))
ACTION_STEP = 'Upload conda packages to Anaconda'
CLI_STEP = 'Upload conda packages to Anaconda (Intel)'
ACTION = 'anaconda/actions/upload-package'
#: The leg whose upload-package CLI download returns 404.
INTEL = 'macos-26-intel'
SECRET = '${{ secrets.ANACONDA_TOKEN }}'
#: The CLI step's ``run:`` (#1967), and the script it runs.
CLI_RUN = 'python3 util/release_conda.py upload'
SCRIPT = pathlib.Path(__file__).resolve().parents[2] / 'util' / 'release_conda.py'
#: The CLI step's ``env:`` key for each action input it carries.
CARRIED = {'token': 'ANACONDA_API_TOKEN', 'channel': 'PCAPKIT_CONDA_CHANNEL',
           'packages': 'PCAPKIT_CONDA_PACKAGES', 'labels': 'PCAPKIT_CONDA_LABELS'}

#: A stand-in ``conda`` and ``anaconda``, each appending its arguments, one per
#: line, to ``$FAKE_LOG``, then a blank line.
RECORDER = textwrap.dedent('''\
    #!/usr/bin/env bash
    set -eu
    { echo "$(basename "$0")"; printf '%s\\n' "$@"; echo; } >> "$FAKE_LOG"
''')


def step(name: 'str', job_id: 'str', step_name: 'str') -> 'dict[str, Any]':
    """The step named ``step_name`` of job ``job_id`` in workflow ``name``."""
    found = [entry for entry in _workflows.steps(name, job_id) if entry.get('name') == step_name]
    if len(found) != 1:
        raise AssertionError(f'{name}: {job_id} has {len(found)} steps named {step_name!r}, not one')
    return found[0]


def index(name: 'str', job_id: 'str', step_name: 'str') -> 'int':
    """The position of the step named ``step_name`` in job ``job_id``."""
    return [entry.get('name') for entry in _workflows.steps(name, job_id)].index(step_name)


def legs(name: 'str', job_id: 'str') -> 'list[str]':
    """The ``os`` values of job ``job_id``'s matrix in workflow ``name``."""
    return list(_workflows.job(name, job_id)['strategy']['matrix']['os'])


def runs(entry: 'dict[str, Any]', os: 'str', published: 'str' = 'false') -> 'bool':
    """Whether ``entry`` runs on leg ``os``, with ``check_leg`` having found ``published``.

    On the schedule, where cron-conda.yml's `mode` says the run publishes: a
    build-only manual run uploads nothing on any leg, which
    tests/project/test_build_only_dispatch.py pins.

    """
    context = {'matrix': {'os': os}, 'github': {'event_name': 'schedule'},
               'needs': {'mode': {'outputs': {'publishes': 'true'}}},
               'steps': {'check_leg': {'outputs': {'PCAPKIT_LEG_EXISTS': published}}}}  # type: dict[str, object]
    return evaluate_condition(str(entry.get('if', 'true')), context)


def action_arguments(inputs: 'dict[str, str]', token: 'str', packages: 'str', labels: 'str') -> 'list[str]':
    """The arguments upload-package v0.3.1 passes ``anaconda`` for ``inputs``.

    Its "Upload to anaconda.org" step at commit
    a6f488910b4a1e4f3fe01736241ca1b92b4b355a: ``--token``, ``upload``,
    ``--user`` with the channel, ``--force`` when ``force`` is ``'true'``, a
    ``--label`` per comma-separated label, trimmed, then the packages
    word-split.
    """
    flags = ['--force'] if str(inputs.get('force', 'false')) == 'true' else []
    for label in labels.split(','):
        if label.strip():
            flags += ['--label', label.strip()]
    return ['--token', token, 'upload', '--user', str(inputs['channel']), *flags, *packages.split()]


class TestOnlyTheIntelLegUsesTheCLI(unittest.TestCase):
    """The action on every leg but ``macos-26-intel``, the CLI step there alone."""

    def test_the_action_step_is_still_the_action(self) -> None:
        for name, job_id in JOBS:
            with self.subTest(workflow=name, job=job_id):
                self.assertTrue(_workflows.pinned(step(name, job_id, ACTION_STEP).get('uses'), ACTION))
                self.assertNotIn('uses', step(name, job_id, CLI_STEP))

    def test_the_intel_leg_runs_the_cli_step_only(self) -> None:
        for name, job_id in JOBS:
            with self.subTest(workflow=name, job=job_id):
                self.assertIn(INTEL, legs(name, job_id))
                self.assertFalse(runs(step(name, job_id, ACTION_STEP), INTEL))
                self.assertTrue(runs(step(name, job_id, CLI_STEP), INTEL))

    def test_every_other_leg_runs_the_action_only(self) -> None:
        # #2060: but the Windows leg, whose own CLI step test_conda_windows_leg_2060 pins.
        for name, job_id in JOBS:
            others = [os for os in legs(name, job_id) if os not in (INTEL, 'windows-latest')]
            with self.subTest(workflow=name, job=job_id):
                self.assertTrue(others, 'no other leg to check')
            for os in others:
                with self.subTest(workflow=name, job=job_id, os=os):
                    self.assertTrue(runs(step(name, job_id, ACTION_STEP), os))
                    self.assertFalse(runs(step(name, job_id, CLI_STEP), os))

    def test_a_published_release_leg_runs_neither(self) -> None:
        """#888's per-leg check still gates both release uploads."""
        for os in legs('create-release.yml', 'conda'):
            with self.subTest(os=os):
                self.assertFalse(runs(step('create-release.yml', 'conda', ACTION_STEP), os, published='true'))
                self.assertFalse(runs(step('create-release.yml', 'conda', CLI_STEP), os, published='true'))

    def test_the_cli_step_follows_the_action_step(self) -> None:
        """So it, too, runs after the smoke test and before the GitHub upload."""
        for name, job_id in JOBS:
            with self.subTest(workflow=name, job=job_id):
                self.assertEqual(index(name, job_id, CLI_STEP), index(name, job_id, ACTION_STEP) + 1)


class TestTheCLIStepMatchesTheAction(unittest.TestCase):
    """The CLI step uploads what the action would, with ``--skip-existing``."""

    def test_the_token_comes_through_env(self) -> None:
        for name, job_id in JOBS:
            entry = step(name, job_id, CLI_STEP)
            with self.subTest(workflow=name, job=job_id):
                self.assertEqual(entry['env']['ANACONDA_API_TOKEN'], SECRET)
                self.assertEqual(entry['run'], CLI_RUN)
        self.assertIn("'--token', env('ANACONDA_API_TOKEN')", SCRIPT.read_text(encoding='utf-8'))

    def test_it_carries_the_actions_inputs(self) -> None:
        for name, job_id in JOBS:
            given = step(name, job_id, ACTION_STEP)['with']
            env = step(name, job_id, CLI_STEP)['env']
            for key, variable in CARRIED.items():
                with self.subTest(workflow=name, job=job_id, input=key):
                    self.assertEqual(env[variable], given[key])

    def test_it_runs_the_actions_call_with_skip_existing(self) -> None:
        if not BASH:
            self.skipTest('needs bash on PATH')
        packages = [f'/build/out/osx-64/pypcapkit-1.0-py314_{build}.tar.bz2' for build in (0, 1)]
        for name, job_id in JOBS:
            given = step(name, job_id, ACTION_STEP)['with']
            entry = step(name, job_id, CLI_STEP)
            self.assertEqual(entry.get('shell'), 'bash')
            for labels in ('main', ' main , dev ', ''):
                with self.subTest(workflow=name, job=job_id, labels=labels):
                    calls = self.run_script(entry, packages='\n'.join(packages), labels=labels)
                    self.assertEqual(calls[0], ['conda', 'install', '-n', 'base', '--override-channels',
                                                '-c', 'conda-forge', '-y', 'anaconda-client'])
                    expected = action_arguments(given, 'TOKEN', '\n'.join(packages), labels)
                    expected = [argument for argument in expected if argument != '--force']
                    expected.insert(expected.index('--user') + 2, '--skip-existing')
                    self.assertEqual(calls[1:], [['anaconda', *expected]])

    def test_no_packages_uploads_nothing_and_fails(self) -> None:
        """Where the action would run ``anaconda upload`` with no file."""
        if not BASH:
            self.skipTest('needs bash on PATH')
        for name, job_id in JOBS:
            with self.subTest(workflow=name, job=job_id):
                calls = self.run_script(step(name, job_id, CLI_STEP), packages='', labels='main', status=1)
                self.assertEqual([call[0] for call in calls], ['conda'])

    def run_script(self, entry: 'dict[str, Any]', packages: 'str', labels: 'str',
                   status: 'int' = 0) -> 'list[list[str]]':
        """Each call ``entry``'s script makes to ``conda`` and ``anaconda``, as argument lists.

        The script has to exit with ``status``.
        """
        with tempfile.TemporaryDirectory() as temp:
            scratch = pathlib.Path(temp)
            for tool in (scratch / 'bin' / 'conda', scratch / 'base' / 'bin' / 'anaconda'):
                tool.parent.mkdir(parents=True, exist_ok=True)
                tool.write_text(RECORDER, encoding='utf-8')
                tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
            log = scratch / 'log'
            log.write_text('', encoding='utf-8')
            env = dict(os.environ, PATH=f'{scratch / "bin"}{os.pathsep}{os.environ["PATH"]}',
                       CONDA=str(scratch / 'base'), FAKE_LOG=str(log), ANACONDA_API_TOKEN='TOKEN',
                       ANACONDA_CLI_FORCE_NEW='1', PCAPKIT_CONDA_CHANNEL=str(entry['env']['PCAPKIT_CONDA_CHANNEL']),
                       PCAPKIT_CONDA_PACKAGES=packages, PCAPKIT_CONDA_LABELS=labels)
            self.assertEqual(entry['run'], CLI_RUN)
            result = subprocess.run([sys.executable, str(SCRIPT), 'upload'], cwd=temp, env=env,  # nosec: B603
                                    capture_output=True, text=True, check=False, timeout=scale_timeout(60))
            self.assertEqual(result.returncode, status, result.stdout + result.stderr)
            blocks = log.read_text(encoding='utf-8').split('\n\n')
            return [block.splitlines() for block in blocks if block.strip()]


if __name__ == '__main__':
    unittest.main()
