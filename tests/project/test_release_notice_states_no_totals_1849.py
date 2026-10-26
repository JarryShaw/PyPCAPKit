# -*- coding: utf-8 -*-
"""The steady-state "Nothing to release" notice states no file totals (#1849).

``release_status`` in :file:`.github/workflows/create-release.yml` posts it when
every target reconciled by skipping. Guards against it naming fixed PyPI and
Anaconda totals: ``version_check`` derives both at release time from the tag's own
tier file, so a fixed total goes wrong once a supported version is added or
retired, and for an older tag. The step is read with :func:`tests._workflows.steps` and its script,
:file:`util/release_status.py` (#1967), run in that state, so the notice checked
is the one a run prints.

"""

from __future__ import annotations

import os
import pathlib
import re
import subprocess  # nosec: B404
import unittest

from tests import _workflows
from tests._support import scale_timeout
from tests.project.test_release_tags_the_run_sha_1634 import script_command

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

WORKFLOW = pathlib.Path(__file__).resolve().parents[2] / '.github' / 'workflows' / 'create-release.yml'

#: Every publisher skipped with its own evidence present: the steady state. The
#: version carries no digit, so any digit in the notice is the script's own.
STEADY = {
    'PCAPKIT_EVENT_NAME': 'workflow_run',
    'PCAPKIT_WORKFLOW_RUN_CONCLUSION': 'success',
    'PCAPKIT_VENDOR_UPDATED': 'true',
    'PCAPKIT_UNIT_TESTS': 'success',
    'PCAPKIT_VERSION_CHECK': 'success',
    'PCAPKIT_GITHUB_JOB': 'skipped',
    'PCAPKIT_TAG_JOB': 'skipped',
    'PCAPKIT_PYPI_JOB': 'skipped',
    'PCAPKIT_CONDA_JOB': 'skipped',
    'PCAPKIT_VERSION': 'VERSION',
    'PCAPKIT_TAG_EXISTS': 'true',
    'PCAPKIT_CONDA_TAG_EXISTS': 'true',
    'PCAPKIT_PYPI_COMPLETE': 'true',
    'PCAPKIT_CONDA_COMPLETE': 'true',
    'PCAPKIT_RELEASED_ELSEWHERE': 'false',
}
#: The tag name the notice spells out; its ``0`` is a build number, not a total.
CONDA_TAG = 'conda-*+0'


@unittest.skipIf(yaml is None, 'PyYAML, from the test extra, is not installed')
class TestNothingToReleaseStatesNoTotals(unittest.TestCase):
    """The notice says what is published without counting it."""

    def notice(self) -> 'str':
        """The ``Nothing to release`` notice the step prints in :data:`STEADY`."""
        steps = _workflows.steps(WORKFLOW, 'release_status')
        step = next(step for step in steps if 'run' in step)
        env = dict.fromkeys(step['env'], '')
        env.update(STEADY, PATH=os.environ.get('PATH', os.defpath))
        command = script_command(step['run'])
        self.assertIsNotNone(command, step['run'])
        result = subprocess.run(command, env=env,  # type: ignore[arg-type] # nosec: B603
                                capture_output=True, text=True, check=False, timeout=scale_timeout(10))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        found = [line for line in result.stdout.splitlines()
                 if line.startswith('::notice title=Nothing to release::')]
        self.assertEqual(len(found), 1, result.stdout)
        return found[0]

    def test_the_steady_state_notice_counts_nothing(self) -> None:
        notice = self.notice()
        self.assertIn(CONDA_TAG, notice)
        self.assertIsNone(re.search(r'\d', notice.replace(CONDA_TAG, '')),
                          f'a total version_check does not compute here: {notice}')


if __name__ == '__main__':
    unittest.main()
