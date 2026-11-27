# -*- coding: utf-8 -*-
"""#1967: :file:`util/release_conda.py`, run as both conda jobs' steps run it.

* :class:`TestTheScripts` runs ``conda``'s "Check whether this leg is already on
  Anaconda" and both conda jobs' "Build conda packages", for the one noarch package
  (#3133), against stand-in ``curl`` and ``conda``: each of :data:`LEG_CASES` and
  :data:`BUILD_CASES` to its status and step outputs, and on some of them the
  outputs' values, read as the runner reads them with the build's fresh directory
  as ``<out>``, what a run prints and calls, and the errors for a leg on another
  platform.
* :class:`TestTheScriptsInProcess` runs ``leg`` and ``build`` in this process, with
  the network and ``conda`` stubbed, so their branches count towards coverage.
* :class:`TestTheStepsRunTheScripts` pins each step to its script and its
  ``env:``, both jobs' runner to :data:`release_conda.PLATFORMS`, the recipe's
  host Python to the one that downloaded its wheels, and the script to Python
  3.8's syntax.

"""

from __future__ import annotations

import ast
import io
import json
import os
import pathlib
import shutil
import subprocess  # nosec: B404
import sys
import tempfile
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests._workflows import job, steps
from tests.project.test_requires_python_floor_2051 import FLOOR
from util import release_conda

if TYPE_CHECKING:
    from typing import Any, Optional

#: Test tier (#1958): runs the tree's own scripts and the steps' inline shell forms.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
UTIL = ROOT / 'util'
RECIPE = (ROOT / 'conda' / 'pypcapkit' / 'meta.yaml').read_text(encoding='utf-8')
JOBS = (('create-release.yml', 'conda-build'), ('cron-conda.yml', 'conda-build'))


def read_outputs(text: 'str') -> 'list[tuple[str, str]]':
    """``$GITHUB_OUTPUT``'s ``(name, value)`` pairs as the runner reads them, ``name<<DELIMITER`` included."""
    found = []
    lines = iter(text.split('\n'))
    for line in lines:
        name, sep, value = line.partition('=')
        if '<<' in name or not sep and '<<' in line:
            name, _, delimiter = line.partition('<<')
            value = '\n'.join(iter(lambda: next(lines), delimiter))
        elif not sep:
            continue
        found.append((name, value))
    return found


#: A ``curl`` writing ``$CURL_REPLY`` to its ``-o`` and printing ``$CURL_CODE``, then exiting ``$CURL_FAIL``.
FAKE_CURL = r'''#!/bin/sh
printf 'curl %s\n' "$*" >> "$CALL_LOG"
while [ $# -gt 0 ]; do [ "$1" = -o ] && cp "$CURL_REPLY" "$2"; shift; done
printf '%s' "${CURL_CODE:-200}"
exit "${CURL_FAIL:-0}"
'''

#: A ``conda`` whose ``build`` writes each of ``$FAKE_BUILT``'s paths under its
#: ``--output-folder`` -- ``<path>/`` a directory, ``<path>@<target>`` a link --
#: and which fails with ``$BUILD_FAIL``.
FAKE_CONDA = r'''#!/bin/bash
out=""
for arg in "$@"; do [ "$prev" = --output-folder ] && out="$arg"; prev="$arg"; done
printf 'conda %s\n' "$*" | sed "s|${out:-@@}|<out>|g" >> "$CALL_LOG"
case "$1" in
  build)
    echo 'conda-build: building'
    [ -z "${BUILD_FAIL:-}" ] || { echo 'conda-build: failed' >&2; exit "$BUILD_FAIL"; }
    for path in $FAKE_BUILT; do
      case "$path" in
        */) mkdir -p "$out/$path" ;;
        *@*) mkdir -p "$out/$(dirname "${path%@*}")"; ln -s "${path#*@}" "$out/${path%@*}" ;;
        *) mkdir -p "$out/$(dirname "$path")"; : > "$out/$path" ;;
      esac
    done
    ;;
esac
'''


def reply(*builds: 'tuple[str, str]') -> 'str':
    """An Anaconda release reply holding a distribution per ``(subdir, build)``."""
    return json.dumps({'distributions': [{'attrs': {'subdir': subdir, 'build': build}} for subdir, build in builds]})


#: The leg check's cases: ``(name, os, reply, extra env, (status, PCAPKIT_LEG_EXISTS))``.
LEG_CASES = (
    ('the package is published', 'ubuntu-latest', reply(('noarch', 'py_0')), {}, (0, 'true')),
    ('a bumped build is published', 'ubuntu-latest', reply(('noarch', 'py_1')), {}, (0, 'true')),
    ('a platform package is not it', 'ubuntu-latest', reply(('linux-64', 'py_0'), ('linux-64', 'py314_0')), {},
     (0, 'false')),
    ('a per-Python build is not it', 'ubuntu-latest', reply(('noarch', 'py314_0')), {}, (0, 'false')),
    ('no distributions', 'ubuntu-latest', '{}', {}, (0, 'false')),
    ('not found', 'ubuntu-latest', reply(('noarch', 'py_0')), {'CURL_CODE': '404'}, (0, 'false')),
    ('a 2xx other than 200 is not read', 'ubuntu-latest', reply(('noarch', 'py_0')), {'CURL_CODE': '201'},
     (0, 'false')),
    ('a 204 with no body', 'ubuntu-latest', '', {'CURL_CODE': '204'}, (0, 'false')),
    ('curl fails', 'ubuntu-latest', reply(('noarch', 'py_0')), {'CURL_CODE': '000', 'CURL_FAIL': '7'},
     (0, 'false')),
    ('a 200 that is no JSON', 'ubuntu-latest', 'not json', {}, (1, None)),
    ('a 200 that is a list', 'ubuntu-latest', '[]', {}, (1, None)),
    ('no version', 'ubuntu-latest', '{}', {'PCAPKIT_VERSION': None}, (1, None)),
    ('no label', None, '{}', {}, (1, None)),
)

#: The outputs a build that succeeds writes, in order.
BUILT = ['out_dir', 'host_package', 'packages_csv', 'packages']
#: The build's cases: ``(name, os, $FAKE_BUILT, extra env, (status, the outputs written))``.
BUILD_CASES = (
    ('noarch on ubuntu-latest', 'ubuntu-latest', 'noarch/pypcapkit-1.5.0-py_0.tar.bz2', {}, (0, BUILT)),
    ('every package, sorted, and nothing else', 'ubuntu-latest',
     'noarch/z.tar.bz2 noarch/a.conda noarch/repodata.json noarch/dir.tar.bz2/ '
     'noarch/link.conda@a.conda noarch/.hidden.conda', {}, (0, BUILT)),
    ('linux-64 on ubuntu-latest', 'ubuntu-latest', 'linux-64/pypcapkit-1.5.0-py314_0.tar.bz2', {},
     (1, ['out_dir', 'host_package'])),
    ('an unmapped label', 'macos-99', 'noarch/pypcapkit-1.5.0-py_0.tar.bz2', {}, (1, ['out_dir', 'host_package'])),
    ('nothing built', 'ubuntu-latest', 'noarch/repodata.json', {}, (1, ['out_dir'])),
    ('a failed build', 'ubuntu-latest', 'noarch/a.tar.bz2', {'BUILD_FAIL': '3'}, (3, ['out_dir'])),
    ('no conda', 'ubuntu-latest', '', {'PATH': None}, (127, ['out_dir'])),
    ('no Python', 'ubuntu-latest', 'noarch/pypcapkit-1.5.0-py_0.tar.bz2', {'PCAPKIT_PYTHON_VERSION': None},
     (1, [])),
)


class _Stand(unittest.TestCase):
    """A scratch directory with stand-in ``curl``, ``conda`` and ``python3`` first on ``PATH``."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1967-conda-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.bin = self.tmp / 'bin'
        for path, text in ((self.bin / 'curl', FAKE_CURL), (self.bin / 'conda', FAKE_CONDA)):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8')
            path.chmod(0o755)
        # The count's ``python3 -``, on this interpreter.
        (self.bin / 'python3').symlink_to(sys.executable)
        self.work = self.tmp / 'work'
        self.scratch = self.tmp / 'scratch'
        self.output = self.tmp / 'output'
        self.log = self.tmp / 'calls'
        self.reply = self.tmp / 'reply'
        self.release = self.tmp / 'release.json'
        self.base = {
            'PATH': f'{self.bin}{os.pathsep}{os.environ.get("PATH", "")}', 'HOME': str(self.tmp), 'LC_ALL': 'C',
            'TMPDIR': str(self.scratch), 'GITHUB_OUTPUT': str(self.output), 'CALL_LOG': str(self.log),
            'CURL_REPLY': str(self.reply), 'PCAPKIT_VERSION': '1.5.0',
        }

    def reset(self) -> None:
        """Leave nothing of an earlier run but the stand-ins."""
        for path in (self.output, self.log, self.release):
            if path.exists():
                path.unlink()
        for path in (self.work, self.scratch):
            shutil.rmtree(path, ignore_errors=True)
            path.mkdir()
        self.output.write_text('', encoding='utf-8')

    def env(self, extra: 'dict[str, Optional[str]]', **variables: 'Optional[str]') -> 'dict[str, str]':
        merged = dict(self.base, **variables, **extra)
        if 'PATH' in extra and extra['PATH'] is None:  # no conda
            merged['PATH'] = str(self.tmp / 'empty')
        return {key: value for key, value in merged.items() if value is not None}

    def state(self, result: 'subprocess.CompletedProcess[str]') -> 'tuple[object, ...]':
        """Status, both streams, the outputs and the calls, the build's directory read as ``<out>``."""
        outputs = read_outputs(self.output.read_text(encoding='utf-8'))
        out_dir = dict(outputs).get('out_dir')

        def plain(text: 'str') -> 'str':
            return text.replace(out_dir, '<out>') if out_dir else text
        if out_dir:
            self.assertTrue(out_dir.startswith(f'{self.scratch}{os.sep}compilation-'), out_dir)
            self.assertTrue(os.path.isdir(out_dir))
        calls = self.log.read_text(encoding='utf-8') if self.log.exists() else None
        return (result.returncode, plain(result.stdout), plain(result.stderr),
                [(name, plain(value)) for name, value in outputs], calls)

    def script(self, run: 'str', env: 'dict[str, str]') -> 'tuple[object, ...]':
        """``run``, the step's ``python[3] [../../]util/<script> ...``, on this interpreter."""
        words = run.replace('/tmp/anaconda_release.json', str(self.release)).split()
        assert words[0] in ('python', 'python3') and 'util/' in words[1], run
        script = UTIL / words[1].rsplit('/', 1)[1]
        return self.state(subprocess.run([sys.executable, str(script), *words[2:]], cwd=self.work,  # nosec: B603
                                         env=env, capture_output=True, text=True, check=False, timeout=120))

    def leg_env(self, case: 'tuple[object, ...]') -> 'dict[str, str]':
        label, body, extra = case[1:4]
        self.reply.write_text(str(body), encoding='utf-8')
        return self.env(extra, PCAPKIT_CONDA_OS=label)  # type: ignore[arg-type]

    def build_env(self, case: 'tuple[object, ...]') -> 'dict[str, str]':
        label, built, extra = case[1:4]
        return self.env(dict({'PCAPKIT_PYTHON_VERSION': '3.15'}, **extra),  # type: ignore[arg-type]
                        PCAPKIT_CONDA_OS=label, FAKE_BUILT=built, PCAPKIT_BUILD='0')


#: Each step, as ``(workflow, job, step name)``, and the ``run:`` it holds.
STEPS = {
    ('create-release.yml', 'conda', 'Check whether this leg is already on Anaconda'):
        'python3 util/release_conda.py leg /tmp/anaconda_release.json',
    ('create-release.yml', 'conda-build', 'Build conda packages'): 'python ../../util/release_conda.py build',
    ('cron-conda.yml', 'conda-build', 'Build conda packages'): 'python ../../util/release_conda.py build',
    # #3133: the publishers find the package conda-build built and conda-test installed.
    ('create-release.yml', 'conda', 'Find the conda package'):
        'python3 util/release_conda.py downloaded "$RUNNER_TEMP/conda-package"',
    ('cron-conda.yml', 'conda-dist', 'Find the conda package'):
        'python3 util/release_conda.py downloaded "$RUNNER_TEMP/conda-package"',
}
LEG_RUN = STEPS[('create-release.yml', 'conda', 'Check whether this leg is already on Anaconda')]
BUILD_RUN = STEPS[('cron-conda.yml', 'conda-build', 'Build conda packages')]


class TestTheScripts(_Stand):
    """What a run outputs, read as the runner reads it."""

    def setUp(self) -> None:
        super().setUp()
        self.reset()

    def test_every_leg_case(self) -> None:
        for case in LEG_CASES:
            with self.subTest(case=case[0]):
                self.reset()
                status, _, _, outputs, _ = self.script(LEG_RUN, self.leg_env(case))
                self.assertEqual((status, dict(outputs).get('PCAPKIT_LEG_EXISTS')), case[4])

    def test_every_build_case(self) -> None:
        for case in BUILD_CASES:
            with self.subTest(case=case[0]):
                self.reset()
                status, _, _, outputs, _ = self.script(BUILD_RUN, self.build_env(case))
                self.assertEqual((status, [name for name, _ in outputs]), case[4])

    def test_a_build_outputs_every_package(self) -> None:
        status, stdout, _, outputs, _ = self.script(BUILD_RUN, self.build_env(BUILD_CASES[1]))
        self.assertEqual(status, 0)
        found = ['<out>/noarch/.hidden.conda', '<out>/noarch/a.conda', '<out>/noarch/z.tar.bz2']
        self.assertEqual(stdout, 'conda-build: building\n' + ''.join(f'{path}\n' for path in found))
        self.assertEqual(outputs, [('out_dir', '<out>'), ('host_package', found[0]),
                                   ('packages_csv', ','.join(found)), ('packages', '\n'.join(found))])

    def test_a_package_for_another_platform_fails_the_leg(self) -> None:
        status, stdout, _, outputs, _ = self.script(BUILD_RUN, self.build_env(BUILD_CASES[2]))
        self.assertEqual(status, 1)
        self.assertEqual(stdout.splitlines()[-1], (
            '::error title=linux-64 package on a noarch leg (#1822)::ubuntu-latest publishes noarch, and conda '
            'built linux-64 here; a package is published only for the platform it was built for.'))
        self.assertEqual([name for name, _ in outputs], ['out_dir', 'host_package'])

    def test_a_published_leg_is_announced(self) -> None:
        status, stdout, _, outputs, calls = self.script(LEG_RUN, self.leg_env(LEG_CASES[0]))
        self.assertEqual(status, 0)
        self.assertEqual(outputs, [('PCAPKIT_LEG_EXISTS', 'true')])
        self.assertEqual(stdout, '::notice title=conda leg already published::pypcapkit 1.5.0 for noarch / py '
                                 "is already on anaconda.org/jarryshaw (http 200); skipping this leg's upload.\n")
        self.assertEqual(calls, f'curl -s --retry 3 --retry-connrefused -o {self.release} -w %{{http_code}} '
                                'https://api.anaconda.org/release/jarryshaw/pypcapkit/1.5.0\n')

    def test_only_a_200_is_read(self) -> None:
        """A 201 holding this very leg reads ``false``, uncounted."""
        case = next(case for case in LEG_CASES if case[0] == 'a 2xx other than 200 is not read')
        status, stdout, stderr, outputs, calls = self.script(LEG_RUN, self.leg_env(case))
        self.assertEqual((status, stdout, stderr), (0, '', ''))
        self.assertEqual(outputs, [('PCAPKIT_LEG_EXISTS', 'false')])
        self.assertEqual(str(calls).count('\n'), 1)  # curl alone, no count

    def test_the_outputs_reader_reads_both_forms(self) -> None:
        self.assertEqual(read_outputs('a=1\nb<<EOF_x\nl1\nl2\nEOF_x\nc=x<<y\n'),
                         [('a', '1'), ('b', 'l1\nl2'), ('c', 'x<<y')])


class TestTheScriptsInProcess(unittest.TestCase):
    """``main`` run here, its outputs read back (#3133)."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-3133-conda-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.output = self.tmp / 'output'
        self.output.write_text('', encoding='utf-8')

    def env(self, **variables: 'str') -> 'mock._patch[Any]':
        return mock.patch.dict(os.environ, {'GITHUB_OUTPUT': str(self.output), 'PCAPKIT_VERSION': '1.8.2',
                                            'PCAPKIT_CONDA_OS': 'ubuntu-latest', **variables})

    def test_a_published_package_is_found(self) -> None:
        reply = str(self.tmp / 'reply.json')
        stdout = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
        with self.env(), mock.patch.object(release_conda.release_published, 'fetch', return_value=b'200'), \
                mock.patch.object(release_conda.release_published, 'count', return_value=b'true') as count, \
                mock.patch('sys.stdout', stdout):
            self.assertEqual(release_conda.main(['leg', reply]), 0)
        count.assert_called_once_with(release_conda.leg_source(reply, 'noarch', 'py'))
        stdout.flush()
        self.assertEqual(stdout.buffer.getvalue(), b'::notice title=conda leg already published::pypcapkit 1.8.2 for '
                                                   b"noarch / py is already on anaconda.org/jarryshaw (http 200); "
                                                   b"skipping this leg's upload.\n")
        self.assertEqual(self.output.read_text(encoding='utf-8'), 'PCAPKIT_LEG_EXISTS=true\n')

    def test_another_status_counts_nothing(self) -> None:
        with self.env(), mock.patch.object(release_conda.release_published, 'fetch', return_value=b'404'), \
                mock.patch.object(release_conda.release_published, 'count') as count:
            self.assertEqual(release_conda.main(['leg', str(self.tmp / 'reply.json')]), 0)
        count.assert_not_called()
        self.assertEqual(self.output.read_text(encoding='utf-8'), 'PCAPKIT_LEG_EXISTS=false\n')

    def test_an_output_that_does_not_open_fails(self) -> None:
        err = io.StringIO()
        with self.env(GITHUB_OUTPUT=str(self.tmp / 'missing' / 'output')), mock.patch('sys.stderr', err), \
                mock.patch.object(release_conda.release_published, 'fetch', return_value=b'404'):
            self.assertEqual(release_conda.main(['leg', str(self.tmp / 'reply.json')]), 1)
        self.assertIn('No such file or directory', err.getvalue())

    def test_a_failed_count_ends_the_check(self) -> None:
        with self.env(), mock.patch.object(release_conda.release_published, 'fetch', return_value=b'200'), \
                mock.patch.object(release_conda.release_published, 'count',
                                  side_effect=release_conda.release_published.Failed(3)):
            self.assertEqual(release_conda.main(['leg', str(self.tmp / 'reply.json')]), 3)

    def build(self, *built: 'str', status: 'int' = 0) -> 'tuple[int, str, str]':
        """``build``'s status, standard output and ``$GITHUB_OUTPUT``, conda writing ``built`` under its folder."""
        out_dir = self.tmp / 'compilation-x'
        out_dir.mkdir()

        def conda(*args: 'str') -> 'int':
            for name in built:
                (out_dir / name).parent.mkdir(parents=True, exist_ok=True)
                (out_dir / name).write_bytes(b'')
            return status
        stdout = io.StringIO()
        with self.env(PCAPKIT_PYTHON_VERSION='3.15'), mock.patch('sys.stdout', stdout), \
                mock.patch.object(release_conda.tempfile, 'mkdtemp', return_value=str(out_dir)), \
                mock.patch.object(release_conda, 'call', side_effect=conda):
            result = release_conda.main(['build'])
        return result, stdout.getvalue(), self.output.read_text(encoding='utf-8')

    def test_a_noarch_build_outputs_its_package(self) -> None:
        status, stdout, written = self.build('noarch/pypcapkit-1.8.2-py_0.tar.bz2', 'noarch/repodata.json')
        package = str(self.tmp / 'compilation-x' / 'noarch' / 'pypcapkit-1.8.2-py_0.tar.bz2')
        self.assertEqual(status, 0, stdout)
        self.assertIn(package, stdout)
        self.assertEqual(dict(read_outputs(written)), {'out_dir': str(self.tmp / 'compilation-x'),
                                                       'host_package': package, 'packages_csv': package,
                                                       'packages': package})

    def test_a_platform_build_fails(self) -> None:
        status, stdout, _ = self.build('linux-64/pypcapkit-1.8.2-py315_0.tar.bz2')
        self.assertEqual(status, 1)
        self.assertIn('::error title=linux-64 package on a noarch leg (#1822)::', stdout)

    def test_nothing_built_fails(self) -> None:
        status, stdout, _ = self.build('noarch/repodata.json')
        self.assertEqual(status, 1)
        self.assertIn('::error::No conda package was built', stdout)

    def test_a_failed_build_is_its_status(self) -> None:
        self.assertEqual(self.build(status=5)[0], 5)

    def test_the_downloaded_package_is_output(self) -> None:
        """#3133: what the publisher uploads, found where the artifact was downloaded."""
        found = self.tmp / 'conda-package'
        (found / 'deep').mkdir(parents=True)
        for name in ('pypcapkit-1.8.2-py_0.tar.bz2', 'deep/pypcapkit-1.8.2-py_0.conda', 'repodata.json'):
            (found / name).write_bytes(b'')
        stdout = io.StringIO()
        with self.env(), mock.patch('sys.stdout', stdout):
            self.assertEqual(release_conda.main(['downloaded', str(found)]), 0)
        packages = [str(found / 'deep' / 'pypcapkit-1.8.2-py_0.conda'), str(found / 'pypcapkit-1.8.2-py_0.tar.bz2')]
        self.assertEqual(stdout.getvalue(), ''.join(f'{path}\n' for path in packages))
        self.assertEqual(dict(read_outputs(self.output.read_text(encoding='utf-8'))),
                         {'packages_csv': ','.join(packages), 'packages': '\n'.join(packages)})

    def test_no_downloaded_package_fails(self) -> None:
        stdout = io.StringIO()
        with self.env(), mock.patch('sys.stdout', stdout):
            self.assertEqual(release_conda.main(['downloaded', str(self.tmp)]), 1)
        self.assertIn(f'::error::No conda package was downloaded to {self.tmp}', stdout.getvalue())
        self.assertEqual(self.output.read_text(encoding='utf-8'), '')

    def test_a_missing_command_is_127(self) -> None:
        err = io.StringIO()
        with mock.patch('sys.stderr', err):
            self.assertEqual(release_conda.call(str(self.tmp / 'no-such-conda')), 127)
        self.assertIn('no-such-conda: command not found', err.getvalue())


class TestTheStepsRunTheScripts(unittest.TestCase):
    """Each step runs its script, with the ``env:`` the script reads."""

    def step(self, workflow: 'str', job_id: 'str', name: 'str') -> 'dict[str, object]':
        found = [entry for entry in steps(workflow, job_id) if entry.get('name') == name]
        self.assertEqual(len(found), 1, (workflow, job_id, name))
        return found[0]

    def test_each_step_runs_its_script(self) -> None:
        for (workflow, job_id, name), run in sorted(STEPS.items()):
            with self.subTest(workflow=workflow, job=job_id, step=name):
                self.assertEqual(self.step(workflow, job_id, name)['run'], run)

    def test_the_leg_and_build_steps_name_the_leg(self) -> None:
        for workflow, job_id, name in STEPS:
            if 'release_conda.py downloaded' in STEPS[(workflow, job_id, name)]:
                continue
            given = self.step(workflow, job_id, name)['env']
            with self.subTest(workflow=workflow, step=name):
                self.assertEqual(given['PCAPKIT_CONDA_OS'], job(workflow, job_id)['runs-on'])  # type: ignore[index]

    def test_the_recipe_is_hosted_on_the_python_that_downloaded_the_wheels(self) -> None:
        """#3133: pip refuses a wheel tagged for another Python, as dictdumper's ``cp3XX-none-any`` are."""
        for workflow, job_id in JOBS:
            setup = [entry for entry in steps(workflow, job_id)
                     if str(entry.get('uses', '')).startswith('actions/setup-python@')]
            build = self.step(workflow, job_id, 'Build conda packages')
            with self.subTest(workflow=workflow):
                self.assertEqual(len(setup), 1)
                self.assertEqual(build['env']['PCAPKIT_PYTHON_VERSION'],  # type: ignore[index]
                                 setup[0]['with']['python-version'])  # type: ignore[index]
        self.assertIn("{% set python = environ['PCAPKIT_PYTHON_VERSION'] %}", RECIPE)
        self.assertIn('    - python {{ python }}.*\n', RECIPE)

    def test_the_build_runs_from_the_recipe_under_a_login_shell(self) -> None:
        """Where conda's base ``python`` is first on ``PATH``, and on Windows ``conda`` is defined at all."""
        for workflow, job_id in JOBS:
            build = self.step(workflow, job_id, 'Build conda packages')
            with self.subTest(workflow=workflow):
                self.assertEqual(build['working-directory'], 'conda/pypcapkit')
                self.assertEqual(build['shell'], 'bash -el {0}')

    def test_no_step_holds_the_reference_shell(self) -> None:
        for workflow, job_id in JOBS:
            for entry in steps(workflow, job_id):
                for line in ('target_platform', 'anaconda --token', '/bin/anaconda', 'conda build .'):
                    with self.subTest(workflow=workflow, step=entry.get('name'), line=line):
                        self.assertNotIn(line, str(entry.get('run', '')))

    def test_every_leg_is_mapped_and_every_mapping_is_a_leg(self) -> None:
        legs = set()  # type: set[str]
        for workflow, job_id in JOBS:
            labels = [job(workflow, job_id)['runs-on']]
            legs.update(labels)
            with self.subTest(workflow=workflow):
                self.assertLessEqual(set(labels), set(release_conda.PLATFORMS))
        self.assertEqual(set(release_conda.PLATFORMS), legs)

    def test_the_scripts_parse_as_python_3_8(self) -> None:
        """Best-effort on a newer interpreter, as ``feature_version`` is (#2206).

        The 3.8 compat leg's ``Compile the 3.8-floor util scripts`` is the
        authoritative check.

        """
        ast.parse((UTIL / 'release_conda.py').read_text(encoding='utf-8'), feature_version=FLOOR)


if __name__ == '__main__':
    unittest.main()
