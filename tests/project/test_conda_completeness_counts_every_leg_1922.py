# -*- coding: utf-8 -*-
"""``version_check``'s Anaconda completeness check counts every platform the ``conda`` legs publish (#1922).

* The platforms it counts, :file:`util/release_published.py`'s ``SUBDIRS``
  since #1967, are the ones the ``conda`` job's ``os`` legs map to, read from
  that job's matrix and :file:`util/release_conda.py`'s ``PLATFORMS``, which its
  steps run.
* Run as the workflow runs it, with ``curl`` stubbed, a release reads complete
  only with each of those platforms for each build, so a missing ``osx-arm64``
  upload reads incomplete and the ``conda`` gate runs the leg that lacks it.

"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess  # nosec: B404
import sys
import tempfile
import unittest
from typing import TYPE_CHECKING

from tests import _workflows
from util import release_conda, release_published

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github' / 'workflows' / 'create-release.yml'
STEP = 'Check Anaconda publish completeness'
BUILDS = ('py313', 'py314')

def jobs() -> 'dict[str, Any]':
    if yaml is None:  # pragma: no cover
        raise unittest.SkipTest('PyYAML, from the test extra, is not installed')
    return _workflows.load(WORKFLOW)['jobs']


def check() -> 'dict[str, Any]':
    return next(step for step in jobs()['version_check']['steps'] if step.get('name') == STEP)


def published() -> 'set[str]':
    """The platform each ``conda`` leg publishes, from its matrix and the script its steps run (#1967)."""
    spec = jobs()['conda']
    runs = [str(step.get('run', '')) for step in spec['steps'] if 'util/release_conda.py' in str(step.get('run', ''))]
    assert len(runs) == 4, runs  # the leg check, the build, and the Intel and Windows uploads (#2060)
    return {release_conda.PLATFORMS[label] for label in spec['strategy']['matrix']['os']}


class TheCheckCountsTheLegs(unittest.TestCase):
    """What the check counts is what the legs publish."""

    def test_the_check_lists_each_published_platform(self) -> None:
        """Its one list of platforms, which sets both its count and its set."""
        self.assertEqual(check()['run'].split()[:3], ['python3', 'util/release_published.py', 'anaconda'])
        self.assertEqual(sorted(release_published.SUBDIRS.split()), sorted(published()))
        self.assertIn('osx-arm64', published())


@unittest.skipIf(shutil.which('python3') is None, 'python3 is needed to run the count')
class TheCheckRunsAsTheWorkflowRunsIt(unittest.TestCase):
    """The step's script, on this interpreter, with ``curl`` answering from a fake Anaconda release."""

    def complete(self, distributions: 'list[tuple[str, str]]') -> 'tuple[str, str]':
        """``PCAPKIT_CONDA_COMPLETE`` and the log for a release holding these (platform, build) pairs."""
        step = check()
        self.assertEqual(sorted(step['env']), ['PCAPKIT_CONDA_BUILDS', 'PCAPKIT_TAG_EXISTS', 'PCAPKIT_VERSION'])
        with tempfile.TemporaryDirectory(prefix='pcapkit-1922-') as tmp:
            scratch = pathlib.Path(tmp)
            reply = scratch / 'reply.json'
            reply.write_text(json.dumps({'distributions': [{'attrs': {'subdir': platform, 'build': f'{build}_0'}}
                                                           for platform, build in distributions]}), encoding='utf-8')
            curl = scratch / 'curl'
            curl.write_text('#!/bin/bash\nwhile [ $# -gt 0 ]; do [ "$1" = -o ] && cp "$REPLY" "$2"; shift; done\n'
                            'printf 200\n', encoding='utf-8')
            curl.chmod(0o755)
            output = scratch / 'output'
            output.write_text('', encoding='utf-8')
            words = step['run'].replace('/tmp/anaconda_release.json', str(scratch / 'release.json')).split()
            result = subprocess.run(  # nosec: B603
                [sys.executable, str(ROOT / words[1]), *words[2:]],
                env=dict(os.environ, PATH=f'{scratch}{os.pathsep}{os.environ["PATH"]}', REPLY=str(reply),
                         GITHUB_OUTPUT=str(output), PCAPKIT_VERSION='1.5.0', PCAPKIT_CONDA_BUILDS=' '.join(BUILDS),
                         PCAPKIT_TAG_EXISTS='false'),
                capture_output=True, text=True, check=False, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            written = dict(line.split('=', 1) for line in output.read_text(encoding='utf-8').split())
        return written['PCAPKIT_CONDA_COMPLETE'], result.stdout

    def test_every_platform_for_every_build_reads_complete(self) -> None:
        every = [(platform, build) for platform in sorted(published()) for build in BUILDS]
        state, log = self.complete(every)
        self.assertEqual(state, 'true', log)
        self.assertIn(f'found {len(every)} of {len(every)} expected', log)

    def test_a_missing_platform_reads_incomplete(self) -> None:
        for missing in sorted(published()):
            rest = [(platform, build) for platform in sorted(published() - {missing}) for build in BUILDS]
            with self.subTest(missing=missing):
                self.assertEqual(self.complete(rest)[0], 'false')

    def test_a_missing_osx_arm64_build_reads_incomplete(self) -> None:
        every = [(platform, build) for platform in sorted(published()) for build in BUILDS]
        state, log = self.complete([pair for pair in every if pair != ('osx-arm64', BUILDS[-1])])
        self.assertEqual(state, 'false', log)
        self.assertIn(f'found {len(every) - 1} of {len(every)} expected', log)


if __name__ == '__main__':
    unittest.main()
