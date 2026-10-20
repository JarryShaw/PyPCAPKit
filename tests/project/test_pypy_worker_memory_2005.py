# -*- coding: utf-8 -*-
"""#2005: a PyPy leg of ``test`` runs the ``ALL`` tier as several pytest runs.

On PyPy an xdist worker's RSS grows with every test it runs, so through the
whole tier at ``-n 4`` its workers outgrew the runner. ``Run unit tests`` runs
pytest once per directory its ``SHARDS`` names on a PyPy leg, then once more
over the rest, ignoring each, so every run starts its workers afresh. Every
other leg runs pytest once, as before. :class:`TestTheRunsCoverTheTier` runs the
step's own script with a stub ``python``, as
:mod:`tests.project.test_sweeps_on_latest_only_1732` does.

"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import unittest

from tests import _tiers
from tests.project.test_python_matrix_tiers_1633 import job, legs
from tests.project.test_python_versions_1660 import ROOT, prose
from tests.project.test_sweeps_on_latest_only_1732 import (JOB, RUNNER_TEMP, run_step_each, shards, step,
                                                          step_env, unsharded)

#: Test tier (#1958): checks the workflow's own shell.
__tier__ = 'LATEST'

#: The ``test`` job's KTLO twin, which runs its steps by YAML alias.
KTLO = ('unit-tests.yml', 'test-ktlo')
#: The directories a PyPy leg runs on their own, in order.
SHARDS = ['tests/protocols', 'tests/corekit']
#: The page that says how the legs run.
DOC = ROOT / 'docs' / 'source' / 'contributing' / 'workflows.rst'


def pypy_leg() -> 'dict[str, object]':
    """The supported PyPy leg of ``test``, which blocks."""
    found = [leg for leg in legs(*JOB) if str(leg['python-version']).startswith('pypy')]
    if len(found) != 1:
        raise AssertionError(f'expected one PyPy leg of test, found {found}')
    return found[0]


class TestOnlyPyPyShards(unittest.TestCase):

    def test_each_pypy_leg_names_the_shards_and_no_other_leg_does(self) -> None:
        every = legs(*JOB) + legs(*KTLO)
        self.assertTrue([leg for leg in legs(*KTLO) if str(leg['python-version']).startswith('pypy')])
        for leg in every:
            with self.subTest(python=leg['python-version']):
                pypy = str(leg['python-version']).startswith('pypy')
                self.assertEqual(shards(leg), SHARDS if pypy else [])

    def test_the_ktlo_twin_runs_the_same_step(self) -> None:
        self.assertEqual(job(*KTLO)['steps'], job(*JOB)['steps'])

    def test_each_shard_is_a_directory_the_tier_keeps(self) -> None:
        for shard in SHARDS:
            with self.subTest(shard=shard):
                self.assertTrue((ROOT / shard).is_dir())
                self.assertTrue([module for module in _tiers.all_tier_paths() if module.startswith(shard + '/')])


@unittest.skipIf(shutil.which('bash') is None, 'the step is a bash script')
class TestTheRunsCoverTheTier(unittest.TestCase):

    def test_a_pypy_leg_runs_each_shard_then_the_rest(self) -> None:
        leg = pypy_leg()
        runs = run_step_each(leg)
        self.assertEqual(len(runs), len(SHARDS) + 1)
        common = unsharded(leg, runs)
        self.assertEqual(common[:2], ['-m', 'pytest'])
        self.assertIn(f'--junitxml={RUNNER_TEMP}/junit.xml', common)
        self.assertEqual([run[-1] for run in runs[:-1]], SHARDS)
        self.assertEqual(runs[-1][-len(SHARDS):], [f'--ignore={shard}' for shard in SHARDS])

    def test_every_other_leg_runs_pytest_once(self) -> None:
        for leg in legs(*JOB):
            if shards(leg):
                continue
            with self.subTest(python=leg['python-version']):
                self.assertEqual(len(run_step_each(leg)), 1)

    def test_a_shard_that_fails_fails_the_step_after_the_rest_ran(self) -> None:
        """A failing run does not stop the others, and its status is the step's."""
        with tempfile.TemporaryDirectory() as temp:
            stub = pathlib.Path(temp, 'python')
            # The first pytest run fails as pytest does on a failed test; `-c` asks the real interpreter.
            stub.write_text('#!/bin/sh\ncase "$1" in -c) exec "$REAL_PYTHON" "$@";; '
                            'util/cap_file_size.py) shift; exec "$@";; esac\n'
                            'echo run >> "$RUNS"\n'
                            '[ "$(wc -l < "$RUNS")" -eq 1 ] && exit 1\nexit 0\n', encoding='utf-8')
            stub.chmod(0o755)
            runs = pathlib.Path(temp, 'runs')
            env = dict(os.environ, **step_env(pypy_leg()), RUNS=str(runs), RUNNER_TEMP=temp,
                       REAL_PYTHON=sys.executable, ANNOTATION_LEVEL='error',
                       PATH=temp + os.pathsep + os.environ.get('PATH', ''))
            env.pop('PYTHONSAFEPATH', None)
            result = subprocess.run(['bash', '-e', '-c', step()['run']], env=env, cwd=ROOT,  # nosec B603 B607
                                    capture_output=True, text=True, check=False, timeout=120)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertEqual(runs.read_text(encoding='utf-8').count('run'), len(SHARDS) + 1)


class TestTheTimingsAreUploaded(unittest.TestCase):

    def test_the_upload_takes_each_runs_junit_file(self) -> None:
        upload = next(entry for entry in job(*JOB)['steps'] if entry.get('name') == 'Upload test timings')
        self.assertEqual(upload['with']['path'], '${{ runner.temp }}/junit*.xml')
        for shard in SHARDS:
            with self.subTest(shard=shard):
                self.assertIn(f'--junitxml="$RUNNER_TEMP/junit-${{shard//\\//-}}.xml" "$shard"', step()['run'])


class TestTheDocsSayIt(unittest.TestCase):

    def test_the_workflows_page_names_the_shards(self) -> None:
        page = prose(DOC)
        for phrase in ('#2005', '``SHARDS``', '``Run unit tests``', *(f'``{shard}``' for shard in SHARDS)):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, page)

    def test_the_step_says_why(self) -> None:
        text = prose(ROOT / '.github' / 'workflows' / 'unit-tests.yml')
        for phrase in ('#2005:', 'A smaller `-n` only hands each worker more tests.',
                       'every run starts its workers afresh'):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)


if __name__ == '__main__':
    unittest.main()
