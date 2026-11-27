# -*- coding: utf-8 -*-
"""``version_check``'s Anaconda completeness check counts what the ``conda`` job publishes (#1922, #3133).

* The platforms it counts, :file:`util/release_published.py`'s ``SUBDIRS``
  (#1967), are the one the ``conda`` job's runner maps to, read from that job's
  ``runs-on`` and :file:`util/release_conda.py`'s ``PLATFORMS``, which its steps
  run: ``noarch``, one package for every platform and Python (#3133). The build
  it counts, :file:`util/python_versions.py`'s ``conda-builds``, is that
  package's, whose build string is ``py_<number>``.
* Run as the workflow runs it, with ``curl`` stubbed, a release reads complete
  only with that file, so a release of per-platform files reads incomplete and
  the ``conda`` gate runs. A tagged version's own platforms are
  test_release_tags_the_run_sha_1634's ``TestTheCountsAreOfTheReleasedPlatforms``.

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
from util import python_versions, release_conda, release_published

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github' / 'workflows' / 'create-release.yml'
STEP = 'Check Anaconda publish completeness'


def jobs() -> 'dict[str, Any]':
    if yaml is None:  # pragma: no cover
        raise unittest.SkipTest('PyYAML, from the test extra, is not installed')
    return _workflows.load(WORKFLOW)['jobs']


def check() -> 'dict[str, Any]':
    return next(step for step in jobs()['version_check']['steps'] if step.get('name') == STEP)


def published() -> 'set[str]':
    """The platform the ``conda`` job publishes, from its runner and the script its steps run (#1967)."""
    spec = jobs()['conda']
    runs = [str(step.get('run', '')) for step in spec['steps'] if 'util/release_conda.py' in str(step.get('run', ''))]
    assert len(runs) == 2, runs  # the leg check and the downloaded package (#3133)
    assert 'strategy' not in spec, spec['strategy']  # one package, so no matrix (#3133)
    return {release_conda.PLATFORMS[spec['runs-on']]}


def builds() -> 'str':
    """``conda-builds``, as "Read the Python versions" writes it."""
    return python_versions.outputs(python_versions.load())['conda-builds']


class TheCheckCountsTheLegs(unittest.TestCase):
    """What the check counts is what the job publishes."""

    def test_the_check_lists_each_published_platform(self) -> None:
        """Its one list of platforms, which sets both its count and its set."""
        self.assertEqual(check()['run'].split()[:3], ['python3', 'util/release_published.py', 'anaconda'])
        self.assertEqual(sorted(release_published.SUBDIRS.split()), sorted(published()))
        self.assertEqual(published(), {'noarch'})

    def test_it_counts_one_build(self) -> None:
        """The noarch package's build tag, which the leg check reads too."""
        self.assertEqual(builds(), 'py')
        self.assertEqual(release_conda.BUILD, builds())


@unittest.skipIf(shutil.which('python3') is None, 'python3 is needed to run the count')
class TheCheckRunsAsTheWorkflowRunsIt(unittest.TestCase):
    """The step's script, on this interpreter, with ``curl`` answering from a fake Anaconda release."""

    def complete(self, distributions: 'list[tuple[str, str]]') -> 'tuple[str, str]':
        """``PCAPKIT_CONDA_COMPLETE`` and the log for a release holding these (platform, build string) pairs."""
        step = check()
        self.assertEqual(sorted(step['env']), ['PCAPKIT_CONDA_BUILDS', 'PCAPKIT_TAG_EXISTS', 'PCAPKIT_VERSION'])
        with tempfile.TemporaryDirectory(prefix='pcapkit-1922-') as tmp:
            scratch = pathlib.Path(tmp)
            reply = scratch / 'reply.json'
            reply.write_text(json.dumps({'distributions': [{'attrs': {'subdir': platform, 'build': build}}
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
                         GITHUB_OUTPUT=str(output), PCAPKIT_VERSION='1.8.2', PCAPKIT_CONDA_BUILDS=builds(),
                         PCAPKIT_TAG_EXISTS='false'),
                capture_output=True, text=True, check=False, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            written = dict(line.split('=', 1) for line in output.read_text(encoding='utf-8').split())
        return written['PCAPKIT_CONDA_COMPLETE'], result.stdout

    def test_the_noarch_file_reads_complete(self) -> None:
        """``py_0`` is the build string conda-build gave the recipe, measured on #3133."""
        state, log = self.complete([('noarch', 'py_0')])
        self.assertEqual(state, 'true', log)
        self.assertIn('found 1 of 1 expected', log)

    def test_a_bumped_build_counts_once(self) -> None:
        """A Conda Update bump adds ``py_1`` beside ``py_0``, still one file to expect."""
        state, log = self.complete([('noarch', 'py_0'), ('noarch', 'py_1')])
        self.assertEqual(state, 'true', log)
        self.assertIn('found 1 of 1 expected', log)

    def test_per_platform_files_read_incomplete(self) -> None:
        """The pre-#3133 shape does not stand in for the noarch file."""
        every = [(platform, f'py{python}_0') for platform in ('linux-64', 'osx-64', 'osx-arm64', 'win-64')
                 for python in ('314', '315')]
        state, log = self.complete(every)
        self.assertEqual(state, 'false', log)
        self.assertIn('found 0 of 1 expected', log)

    def test_a_per_python_build_string_reads_incomplete(self) -> None:
        self.assertEqual(self.complete([('noarch', 'py315_0')])[0], 'false')

    def test_no_file_reads_incomplete(self) -> None:
        self.assertEqual(self.complete([])[0], 'false')


if __name__ == '__main__':
    unittest.main()
