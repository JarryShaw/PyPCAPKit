# -*- coding: utf-8 -*-
"""The release conda leg smoke-tests its package as Conda Update does (#1855).

``conda-build`` in :file:`.github/workflows/cron-conda.yml` runs
``util/conda_vendor.py --smoke`` after ``conda build`` and before any upload
(#1821). ``conda-build`` in :file:`.github/workflows/create-release.yml`, whose
package ``conda`` publishes (#3133), runs the same step, and its build step writes
the ``host_package`` output the step reads; without either, a release package
is published untested. The jobs are read with
:func:`tests._workflows.steps`, and each build step is run with a stand-in ``conda``,
as ``test_conda_native_platforms_1822.py`` runs it.

"""

from __future__ import annotations

import os
import pathlib
import re
import stat
import subprocess  # nosec: B404
import sys
import tempfile
import unittest
from typing import TYPE_CHECKING

from tests import _workflows
from tests._support import scale_timeout
from tests.project.test_conda_native_platforms_1822 import BASH, CONDA
from tests.project.test_release_conda_scripts_1967 import read_outputs

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / '.github' / 'workflows'
#: The conda build jobs, as (workflow, job); the first is the one the release mirrors.
CRON, RELEASE = ('cron-conda.yml', 'conda-build'), ('create-release.yml', 'conda-build')
#: The jobs publishing what each built (#3133), and the steps that do.
PUBLISHERS = {CRON: ('cron-conda.yml', 'conda-dist'), RELEASE: ('create-release.yml', 'conda')}
UPLOADS = ('Upload conda packages to Anaconda', 'Upload package to GitHub Release')
#: The step handing the smoke-tested package to ``conda-test`` and the publisher.
ARTIFACT = 'Upload the conda package'


def steps(workflow: 'str', job_id: 'str') -> 'list[dict[str, Any]]':
    return _workflows.steps(WORKFLOWS / workflow, job_id)


def smoke_steps(found: 'list[dict[str, Any]]') -> 'list[int]':
    """The index of each step that runs ``util/conda_vendor.py --smoke``."""
    return [index for index, step in enumerate(found)
            if re.search(r'\butil/conda_vendor\.py\s+--smoke\b', str(step.get('run', '')))]


@unittest.skipIf(yaml is None, 'PyYAML, from the test extra, is not installed')
class TestTheReleaseLegSmokeTests(unittest.TestCase):
    """The release leg checks its package before publishing it."""

    def test_the_smoke_test_runs_after_the_build_and_before_every_upload(self) -> None:
        """#3133: before the artifact, which the publisher uploads only once ``conda-test`` passed."""
        for workflow, job_id in (CRON, RELEASE):
            found = steps(workflow, job_id)
            smoke = smoke_steps(found)
            with self.subTest(workflow=workflow, job=job_id):
                self.assertEqual(len(smoke), 1, f'{workflow} {job_id} runs no smoke test')
                build = next(index for index, step in enumerate(found) if step.get('id') == 'conda_build')
                self.assertGreater(smoke[0], build)
                artifact = [index for index, step in enumerate(found) if step.get('name') == ARTIFACT]
                self.assertEqual(len(artifact), 1)
                self.assertLess(smoke[0], artifact[0])
                self.assertFalse([step for step in found if step.get('name') in UPLOADS])
                publisher = PUBLISHERS[(workflow, job_id)]
                self.assertLessEqual({job_id, 'conda-test'}, set(_workflows.job(WORKFLOWS / publisher[0],
                                                                                publisher[1])['needs']))
                self.assertEqual(sorted(step.get('name') for step in steps(*publisher)
                                        if step.get('name') in UPLOADS), sorted(UPLOADS))

    def test_it_is_conda_updates_step(self) -> None:
        """The same interpreter and package: setup-python's, ``host_package``.

        Conda Update's step alone has an ``id``, which its build-only run's pin reads.

        """
        cron = steps(*CRON)
        release = steps(*RELEASE)
        expected = cron[smoke_steps(cron)[0]]
        self.assertEqual(expected['env'], {'PCAPKIT_CONDA_PACKAGE': '${{ steps.conda_build.outputs.host_package }}'})
        self.assertEqual(expected['run'], '"${pythonLocation}/bin/python" util/conda_vendor.py --smoke '
                                          '"$PCAPKIT_CONDA_PACKAGE"')
        found = smoke_steps(release)
        self.assertEqual(len(found), 1, 'the release leg runs no smoke test')
        self.assertEqual(expected['id'], 'smoke')
        self.assertEqual(release[found[0]], {key: value for key, value in expected.items() if key != 'id'})


@unittest.skipIf(yaml is None, 'PyYAML, from the test extra, is not installed')
@unittest.skipIf(not BASH, 'needs bash on PATH')
class TestEachBuildStepNamesItsPackage(unittest.TestCase):
    """``host_package``, which the smoke step reads, is the package the step built."""

    def outputs(self, workflow: 'str', job_id: 'str') -> 'tuple[str, str]':
        """The build step's ``$GITHUB_OUTPUT`` on ``ubuntu-latest``, and its log."""
        step = next(step for step in steps(workflow, job_id) if step.get('id') == 'conda_build')
        # #1967: util/release_conda.py's, run from the recipe's directory.
        self.assertEqual(step['run'], 'python ../../util/release_conda.py build')
        with tempfile.TemporaryDirectory() as temp:
            scratch = pathlib.Path(temp)
            (scratch / 'bin').mkdir()
            conda = scratch / 'bin' / 'conda'
            conda.write_text(CONDA, encoding='utf-8')
            conda.chmod(conda.stat().st_mode | stat.S_IXUSR)
            output = scratch / 'output'
            output.write_text('', encoding='utf-8')
            result = subprocess.run(
                [sys.executable, str(ROOT / 'util' / 'release_conda.py'), 'build'], cwd=temp,  # nosec: B603
                env=dict(os.environ, PATH=f'{scratch / "bin"}{os.pathsep}{os.environ["PATH"]}',
                         TMPDIR=temp, GITHUB_OUTPUT=str(output), FAKE_SUBDIR='noarch',
                         PCAPKIT_VERSION='1.0', PCAPKIT_BUILD='0', PCAPKIT_CONDA_OS='ubuntu-latest',
                         PCAPKIT_PYTHON_VERSION='3.14'),
                capture_output=True, text=True, check=False, timeout=scale_timeout(60))
            return output.read_text(encoding='utf-8'), result.stdout + result.stderr

    def test_host_package_is_the_package_built(self) -> None:
        for workflow, job_id in (CRON, RELEASE):
            written, log = self.outputs(workflow, job_id)
            with self.subTest(workflow=workflow, job=job_id):
                outputs = read_outputs(written)
                host = [value for name, value in outputs if name == 'host_package']
                self.assertEqual(len(host), 1, f'no host_package output\n{written}{log}')
                packages = [value for name, value in outputs if name == 'packages']
                self.assertEqual(len(packages), 1, log)
                self.assertEqual(host, packages[0].splitlines())
                self.assertEqual(pathlib.PurePosixPath(host[0]).parent.name, 'noarch')


if __name__ == '__main__':
    unittest.main()
