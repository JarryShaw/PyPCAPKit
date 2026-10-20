# -*- coding: utf-8 -*-
"""The release conda leg smoke-tests its package as Conda Update does (#1855).

#1821 added ``util/conda_vendor.py --smoke`` to ``conda-dist`` in
:file:`.github/workflows/cron-conda.yml`, after ``conda build`` and before any
upload. ``conda`` in :file:`.github/workflows/create-release.yml`, which
publishes the release packages, had no such step, and its build step did not
write the ``host_package`` output the step reads. The jobs are read with
:func:`tests._workflows.steps`, and each build step is run with a stand-in ``conda``,
as ``test_conda_native_platforms_1822.py`` runs it.

"""

from __future__ import annotations

import os
import pathlib
import re
import stat
import subprocess  # nosec: B404
import tempfile
import unittest
from typing import TYPE_CHECKING

from tests import _workflows
from tests._support import scale_timeout
from tests.project.test_conda_native_platforms_1822 import BASH, CONDA

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from typing import Any

WORKFLOWS = pathlib.Path(__file__).resolve().parents[2] / '.github' / 'workflows'
#: The conda jobs, as (workflow, job); the first is the one the release mirrors.
CRON, RELEASE = ('cron-conda.yml', 'conda-dist'), ('create-release.yml', 'conda')
#: The steps that publish what the leg built.
UPLOADS = ('Upload conda packages to Anaconda', 'Upload package to GitHub Release')


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
        for workflow, job_id in (CRON, RELEASE):
            found = steps(workflow, job_id)
            smoke = smoke_steps(found)
            with self.subTest(workflow=workflow, job=job_id):
                self.assertEqual(len(smoke), 1, f'{workflow} {job_id} runs no smoke test')
                build = next(index for index, step in enumerate(found) if step.get('id') == 'conda_build')
                self.assertGreater(smoke[0], build)
                uploads = [index for index, step in enumerate(found) if step.get('name') in UPLOADS]
                self.assertEqual(len(uploads), len(UPLOADS))
                self.assertLess(smoke[0], min(uploads))

    def test_it_is_conda_updates_step(self) -> None:
        """The same interpreter, package and gate: setup-python's, ``host_package``, none."""
        cron = steps(*CRON)
        release = steps(*RELEASE)
        expected = cron[smoke_steps(cron)[0]]
        self.assertEqual(expected['env'], {'PCAPKIT_CONDA_PACKAGE': '${{ steps.conda_build.outputs.host_package }}'})
        self.assertIn('"${pythonLocation}/bin/python" util/conda_vendor.py --smoke', expected['run'])
        found = smoke_steps(release)
        self.assertEqual(len(found), 1, 'the release leg runs no smoke test')
        self.assertEqual(release[found[0]], expected)


@unittest.skipIf(yaml is None, 'PyYAML, from the test extra, is not installed')
@unittest.skipIf(not BASH, 'needs bash on PATH')
class TestEachBuildStepNamesItsPackage(unittest.TestCase):
    """``host_package``, which the smoke step reads, is the package the step built."""

    def outputs(self, workflow: 'str', job_id: 'str') -> 'tuple[str, str]':
        """The build step's ``$GITHUB_OUTPUT`` on ``ubuntu-latest``, and its log."""
        step = next(step for step in steps(workflow, job_id) if step.get('id') == 'conda_build')
        script = step['run'].replace('${{ matrix.os }}', 'ubuntu-latest').replace('${{ matrix.python-version }}',
                                                                                 '3.14')
        self.assertNotIn('${{', script)
        with tempfile.TemporaryDirectory() as temp:
            scratch = pathlib.Path(temp)
            (scratch / 'bin').mkdir()
            conda = scratch / 'bin' / 'conda'
            conda.write_text(CONDA, encoding='utf-8')
            conda.chmod(conda.stat().st_mode | stat.S_IXUSR)
            output = scratch / 'output'
            output.write_text('', encoding='utf-8')
            result = subprocess.run(
                [BASH, '-e', '-c', script], cwd=temp,  # nosec: B603
                env=dict(os.environ, PATH=f'{scratch / "bin"}{os.pathsep}{os.environ["PATH"]}',
                         TMPDIR=temp, GITHUB_OUTPUT=str(output), FAKE_SUBDIR='linux-64',
                         PCAPKIT_VERSION='1.0', PCAPKIT_BUILD='0'),
                capture_output=True, text=True, check=False, timeout=scale_timeout(60))
            return output.read_text(encoding='utf-8'), result.stdout + result.stderr

    def test_host_package_is_the_package_built(self) -> None:
        for workflow, job_id in (CRON, RELEASE):
            written, log = self.outputs(workflow, job_id)
            with self.subTest(workflow=workflow, job=job_id):
                host = re.findall(r'^host_package=(.*)$', written, re.MULTILINE)
                self.assertEqual(len(host), 1, f'no host_package output\n{written}{log}')
                packages = re.search(r'^packages<<EOF\n(.*?)^EOF$', written, re.MULTILINE | re.DOTALL)
                self.assertIsNotNone(packages, log)
                self.assertEqual(host, packages.group(1).splitlines())  # type: ignore[union-attr]
                self.assertEqual(pathlib.PurePosixPath(host[0]).parent.name, 'linux-64')


if __name__ == '__main__':
    unittest.main()
