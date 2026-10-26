# -*- coding: utf-8 -*-
"""#1967: :file:`util/release_conda.py`, run as both conda jobs' steps run it.

* :class:`TestTheFormerShellAgrees` runs each step's inline shell form, the
  reference the script must match -- ``conda``'s "Check whether this leg is already on Anaconda", both
  conda jobs' "Build conda packages" and "Upload conda packages to Anaconda
  (Intel)" -- and the script, on the cases below, against stand-in ``curl``, ``conda`` and ``anaconda``, and
  requires the same status, standard output and error, step outputs and calls.
  ``bash``'s ``<path>: line N:`` before its own errors is dropped, and the
  build's fresh directory is read as ``<out>``. The step bodies are kept here
  verbatim, and each case table is checked to reach every way its shell ends.
* :class:`TestTheScripts` pins what the cases cannot compare: the step outputs a
  run writes, and the errors for a leg on another platform.
* :class:`TestTheStepsRunTheScripts` pins each step to its script and its
  ``env:``, both jobs' legs to :data:`release_conda.PLATFORMS`, and the script
  to Python 3.8's syntax.

"""

from __future__ import annotations

import ast
import json
import os
import pathlib
import re
import shutil
import subprocess  # nosec: B404
import sys
import tempfile
import textwrap
import unittest
from typing import TYPE_CHECKING

from tests._workflows import job, steps
from tests.project.test_requires_python_floor_2051 import FLOOR
from util import release_conda

if TYPE_CHECKING:
    from typing import Optional

#: Test tier (#1958): runs the tree's own scripts and the steps' inline shell forms.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
UTIL = ROOT / 'util'
BASH = shutil.which('bash') or ''
JOBS = (('create-release.yml', 'conda'), ('cron-conda.yml', 'conda-dist'))


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
#: and whose ``install`` and ``build`` fail with ``$INSTALL_FAIL`` and ``$BUILD_FAIL``.
FAKE_CONDA = r'''#!/bin/bash
out=""
for arg in "$@"; do [ "$prev" = --output-folder ] && out="$arg"; prev="$arg"; done
printf 'conda %s\n' "$*" | sed "s|${out:-@@}|<out>|g" >> "$CALL_LOG"
case "$1" in
  install) exit "${INSTALL_FAIL:-0}" ;;
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

#: An ``anaconda`` logging its arguments a line each, failing with ``$ANACONDA_FAIL``.
FAKE_ANACONDA = r'''#!/bin/sh
{ echo anaconda; printf '%s\n' "$@"; } >> "$CALL_LOG"
exit "${ANACONDA_FAIL:-0}"
'''

#: "Check whether this leg is already on Anaconda" in ``conda``, as inline shell: what
#: :file:`util/release_conda.py`'s ``leg`` must match.
FORMER_LEG = textwrap.dedent(r'''
    set -euo pipefail

    case "${{ matrix.os }}" in
      macos-latest)
        target_platform="osx-arm64"
        ;;
      macos-26-intel)
        target_platform="osx-64"
        ;;
      ubuntu-latest)
        target_platform="linux-64"
        ;;
      *)
        target_platform=""
        ;;
    esac
    py_tag="py$(echo "${{ matrix.python-version }}" | tr -d '.')"

    # Same coupling risk, and the same fix, as version_check's checks.
    status="$(curl -s --retry 3 --retry-connrefused \
      -o /tmp/anaconda_release.json -w '%{http_code}' \
      "https://api.anaconda.org/release/jarryshaw/pypcapkit/${PCAPKIT_VERSION}" || echo 000)"

    exists=false
    if [ "$status" = "200" ]; then
      # The `printf` form of version_check's checks, and needed here: this
      # runs before setup-python, so `python3` is the image's (3.12 on
      # ubuntu-latest, 3.13 on macos-latest), and indented `python3 -c`
      # source would fail under `set -e` -- only on the retry this is for.
      exists="$(printf '%s\n' \
        "import json" \
        "with open('/tmp/anaconda_release.json') as f:" \
        "    data = json.load(f)" \
        "target_platform = '$target_platform'" \
        "py_tag = '$py_tag'" \
        "found = any(" \
        "    d.get('attrs', {}).get('subdir') == target_platform" \
        "    and d.get('attrs', {}).get('build', '').startswith(py_tag + '_')" \
        "    for d in data.get('distributions', [])" \
        ")" \
        "print('true' if found else 'false')" \
        | python3 -)"
    fi

    echo "PCAPKIT_LEG_EXISTS=$exists" >> "$GITHUB_OUTPUT"
    if [ "$exists" = "true" ]; then
      echo "::notice title=conda leg already published::pypcapkit ${PCAPKIT_VERSION} for ${target_platform} / ${py_tag} is already on anaconda.org/jarryshaw (http ${status}); skipping this leg's upload."
    fi
''').lstrip()

#: "Build conda packages" in ``conda-dist``, as inline shell: what ``build`` must match;
#: ``conda``'s is the same but for the ``windows-latest`` arm (:data:`FORMER_RELEASE_BUILD`).
FORMER_BUILD = textwrap.dedent(r'''
    set -euo pipefail

    out_dir="$(mktemp -d -t compilation-XXXXXXXXXX)"
    echo "out_dir=$out_dir" >> "$GITHUB_OUTPUT"

    conda build . --package-format .tar.bz2 --no-anaconda-upload --output-folder "$out_dir" --python "${{ matrix.python-version }}"
    host_package="$(find "$out_dir" -type f \( -name '*.tar.bz2' -o -name '*.conda' \) -print | sort | sed -n '1p')"
    if [ -z "$host_package" ]; then
      echo "::error::No conda package was built"
      exit 1
    fi

    case "${{ matrix.os }}" in
      macos-latest)
        target_platform="osx-arm64"
        ;;
      macos-26-intel)
        target_platform="osx-64"
        ;;
      ubuntu-latest)
        target_platform="linux-64"
        ;;
      windows-latest)
        target_platform="win-64"
        ;;
      *)
        target_platform=""
        ;;
    esac

    echo "host_package=$host_package" >> "$GITHUB_OUTPUT"

    # #1822: never `conda convert` across architectures. It relabels the
    # package and copies its binaries unchanged, so the osx-64 package it
    # made from the arm64 build carried arm64 extensions.
    host_platform="$(basename "$(dirname "$host_package")")"
    if [ "$host_platform" != "$target_platform" ]; then
      echo "::error title=${host_platform} package on a ${target_platform:-unmapped} leg (#1822)::${{ matrix.os }} publishes ${target_platform:-nothing}, and conda built ${host_platform} here; a package is published only for the platform it was built on."
      exit 1
    fi

    package_paths="$(find "$out_dir" -type f \( -name '*.tar.bz2' -o -name '*.conda' \) -print | sort)"
    if [ -z "$package_paths" ]; then
      echo "::error::No conda packages were found"
      exit 1
    fi

    printf '%s\n' "$package_paths"
    package_paths_csv="$(printf '%s\n' "$package_paths" | paste -sd ',' -)"
    echo "packages_csv=$package_paths_csv" >> "$GITHUB_OUTPUT"
    {
      echo 'packages<<EOF'
      printf '%s\n' "$package_paths"
      echo EOF
    } >> "$GITHUB_OUTPUT"
''').lstrip()
FORMER_RELEASE_BUILD = FORMER_BUILD.replace('  windows-latest)\n    target_platform="win-64"\n    ;;\n', '')

#: "Upload conda packages to Anaconda (Intel)" in both jobs, as inline shell: what ``upload`` must match.
FORMER_UPLOAD = textwrap.dedent(r'''
    set -euo pipefail

    conda install -n base --override-channels -c conda-forge -y anaconda-client

    # The action's handling of its `labels:` and `packages:` inputs: a
    # comma-separated list, each trimmed, and the build step's
    # newline-separated paths.
    labels=()
    IFS=',' read -ra names <<< "$PCAPKIT_CONDA_LABELS"
    for name in ${names[@]+"${names[@]}"}; do
      name="$(echo "$name" | xargs)"
      if [ -n "$name" ]; then
        labels+=(--label "$name")
      fi
    done
    packages=()
    while IFS= read -r path; do
      if [ -n "$path" ]; then
        packages+=("$path")
      fi
    done <<< "$PCAPKIT_CONDA_PACKAGES"
    if [ "${#packages[@]}" -eq 0 ]; then
      echo "::error::No conda packages to upload"
      exit 1
    fi

    "${CONDA}/bin/anaconda" --token "$ANACONDA_API_TOKEN" upload \
      --user "$PCAPKIT_CONDA_CHANNEL" --skip-existing ${labels[@]+"${labels[@]}"} "${packages[@]}"
''').lstrip()


def reply(*builds: 'tuple[str, str]') -> 'str':
    """An Anaconda release reply holding a distribution per ``(subdir, build)``."""
    return json.dumps({'distributions': [{'attrs': {'subdir': subdir, 'build': build}} for subdir, build in builds]})


#: The leg check's cases: ``(name, os, python, reply, extra env)``.
LEG_CASES = (
    ('the leg is published', 'ubuntu-latest', '3.14', reply(('linux-64', 'py314_0')), {}),
    ('another platform is', 'macos-latest', '3.14', reply(('linux-64', 'py314_0'), ('osx-64', 'py314_0')), {}),
    ('the arm64 leg is published', 'macos-latest', '3.13', reply(('osx-arm64', 'py313_1')), {}),
    ('the Intel leg is published', 'macos-26-intel', '3.13', reply(('osx-64', 'py313_0')), {}),
    ('a longer tag is another build', 'ubuntu-latest', '3.1', reply(('linux-64', 'py314_0')), {}),
    ('an unmapped label matches nothing', 'macos-99', '3.14', reply(('', 'py314_0'), ('osx-64', 'py314_0')), {}),
    ('no distributions', 'ubuntu-latest', '3.14', '{}', {}),
    ('not found', 'ubuntu-latest', '3.14', reply(('linux-64', 'py314_0')), {'CURL_CODE': '404'}),
    ('a 2xx other than 200 is not read', 'ubuntu-latest', '3.14', reply(('linux-64', 'py314_0')),
     {'CURL_CODE': '201'}),
    ('a 204 with no body', 'ubuntu-latest', '3.14', '', {'CURL_CODE': '204'}),
    ('curl fails', 'ubuntu-latest', '3.14', reply(('linux-64', 'py314_0')), {'CURL_CODE': '000', 'CURL_FAIL': '7'}),
    ('a 200 that is no JSON', 'ubuntu-latest', '3.14', 'not json', {}),
    ('a 200 that is a list', 'ubuntu-latest', '3.14', '[]', {}),
    ('no version', 'ubuntu-latest', '3.14', '{}', {'PCAPKIT_VERSION': None}),
)

#: The build's cases: ``(name, os, $FAKE_BUILT, extra env)``.
BUILD_CASES = (
    ('linux-64 on ubuntu-latest', 'ubuntu-latest', 'linux-64/pypcapkit-1.5.0-py314_0.tar.bz2', {}),
    ('osx-arm64 on macos-latest', 'macos-latest', 'osx-arm64/pypcapkit-1.5.0-py314_0.tar.bz2', {}),
    ('osx-64 on macos-26-intel', 'macos-26-intel', 'osx-64/pypcapkit-1.5.0-py314_0.tar.bz2', {}),
    ('win-64 on windows-latest', 'windows-latest', 'win-64/pypcapkit-1.5.0-py314_0.tar.bz2', {}),
    ('every package, sorted, and nothing else', 'ubuntu-latest',
     'linux-64/z.tar.bz2 linux-64/a.conda linux-64/repodata.json linux-64/dir.tar.bz2/ '
     'linux-64/link.conda@a.conda linux-64/.hidden.conda', {}),
    ('osx-arm64 on macos-26-intel', 'macos-26-intel', 'osx-arm64/pypcapkit-1.5.0-py314_0.tar.bz2', {}),
    ('an unmapped label', 'macos-99', 'osx-arm64/pypcapkit-1.5.0-py314_0.tar.bz2', {}),
    ('nothing built', 'ubuntu-latest', 'linux-64/repodata.json', {}),
    ('a failed build', 'ubuntu-latest', 'linux-64/a.tar.bz2', {'BUILD_FAIL': '3'}),
    ('no conda', 'ubuntu-latest', '', {'PATH': None}),
)

PACKAGES = '/out/osx-64/pypcapkit-1.5.0-py314_0.tar.bz2\n/out/osx-64/pypcapkit-1.5.0-py314_1.conda'
#: The upload's cases: ``(name, $PCAPKIT_CONDA_LABELS, $PCAPKIT_CONDA_PACKAGES, extra env)``.
UPLOAD_CASES = (
    ('one label', 'main', PACKAGES, {}),
    ('labels trimmed', ' main , dev ', PACKAGES, {}),
    ('no label', '', PACKAGES, {}),
    ('empty and blank labels', ',main,, ,dev,', PACKAGES, {}),
    ('a label holding a run of spaces', 'a  b', PACKAGES, {}),
    ('only the first line of labels', 'main\ndev', PACKAGES, {}),
    ('blank package lines', 'main', '\n' + PACKAGES + '\n\n', {}),
    ('a path holding spaces', 'main', '/out/osx-64/a b.conda', {}),
    ('no packages', 'main', '\n\n', {}),
    ('a failed install', 'main', PACKAGES, {'INSTALL_FAIL': '5'}),
    ('a failed upload', 'main', PACKAGES, {'ANACONDA_FAIL': '2'}),
    ('no CONDA', 'main', PACKAGES, {'CONDA': None}),
    ('no labels', None, PACKAGES, {}),
)


class _Stand(unittest.TestCase):
    """A scratch directory with stand-in ``curl``, ``conda``, ``anaconda`` and ``python3`` first on ``PATH``."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1967-conda-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.bin = self.tmp / 'bin'
        conda_bin = self.tmp / 'conda' / 'bin'
        for path, text in ((self.bin / 'curl', FAKE_CURL), (self.bin / 'conda', FAKE_CONDA),
                           (conda_bin / 'anaconda', FAKE_ANACONDA)):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8')
            path.chmod(0o755)
        # The count's ``python3 -``, on this interpreter in both runs.
        (self.bin / 'python3').symlink_to(sys.executable)
        self.work = self.tmp / 'work'
        self.scratch = self.tmp / 'scratch'
        self.output = self.tmp / 'output'
        self.log = self.tmp / 'calls'
        self.reply = self.tmp / 'reply'
        self.release = self.tmp / 'release.json'
        self.shell = self.tmp / 'step.sh'
        self.base = {
            'PATH': f'{self.bin}{os.pathsep}{os.environ.get("PATH", "")}', 'HOME': str(self.tmp), 'LC_ALL': 'C',
            'TMPDIR': str(self.scratch), 'GITHUB_OUTPUT': str(self.output), 'CALL_LOG': str(self.log),
            'CURL_REPLY': str(self.reply), 'CONDA': str(self.tmp / 'conda'), 'PCAPKIT_VERSION': '1.5.0',
            'ANACONDA_API_TOKEN': 'TOKEN', 'ANACONDA_CLI_FORCE_NEW': '1', 'PCAPKIT_CONDA_CHANNEL': 'jarryshaw',
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
        if 'PATH' in extra and extra['PATH'] is None:  # no conda, but the shell's own tools
            merged['PATH'] = os.pathsep.join(os.path.dirname(shutil.which(tool) or '') for tool in
                                             ('find', 'sort', 'sed', 'paste', 'mktemp', 'basename', 'dirname'))
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

    def former(self, shell: 'str', env: 'dict[str, str]', label: 'str' = '',
               python: 'str' = '') -> 'tuple[object, ...]':
        """``shell``, templated for the leg, as ``shell: bash`` runs it, its own errors' ``<path>: line N:`` dropped."""
        self.shell.write_text(shell.replace('/tmp/anaconda_release.json', str(self.release))
                              .replace('${{ matrix.os }}', label)
                              .replace('${{ matrix.python-version }}', python), encoding='utf-8')
        result = subprocess.run([BASH, '--noprofile', '--norc', '-eo', 'pipefail', str(self.shell)],  # nosec: B603
                                cwd=self.work, env=env, capture_output=True, text=True, check=False, timeout=120)
        result.stderr = re.sub(rf'(?m)^{re.escape(str(self.shell))}: line \d+: ', '', result.stderr)
        return self.state(result)

    def leg_env(self, case: 'tuple[object, ...]') -> 'dict[str, str]':
        _, label, python, body, extra = case
        self.reply.write_text(str(body), encoding='utf-8')
        return self.env(extra, PCAPKIT_CONDA_OS=label, PCAPKIT_PYTHON_VERSION=python)  # type: ignore[arg-type]

    def build_env(self, case: 'tuple[object, ...]') -> 'dict[str, str]':
        _, label, built, extra = case
        return self.env(extra, PCAPKIT_CONDA_OS=label, PCAPKIT_PYTHON_VERSION='3.14',  # type: ignore[arg-type]
                        FAKE_BUILT=built, PCAPKIT_BUILD='0')

    def upload_env(self, case: 'tuple[object, ...]') -> 'dict[str, str]':
        _, labels, packages, extra = case
        return self.env(extra, PCAPKIT_CONDA_LABELS=labels, PCAPKIT_CONDA_PACKAGES=packages)  # type: ignore[arg-type]


#: Each step, as ``(workflow, job, step name)``, and the ``run:`` it holds.
STEPS = {
    ('create-release.yml', 'conda', 'Check whether this leg is already on Anaconda'):
        'python3 util/release_conda.py leg /tmp/anaconda_release.json',
    ('create-release.yml', 'conda', 'Build conda packages'): 'python ../../util/release_conda.py build',
    ('cron-conda.yml', 'conda-dist', 'Build conda packages'): 'python ../../util/release_conda.py build',
    ('create-release.yml', 'conda', 'Upload conda packages to Anaconda (Intel)'):
        'python3 util/release_conda.py upload',
    ('cron-conda.yml', 'conda-dist', 'Upload conda packages to Anaconda (Intel)'):
        'python3 util/release_conda.py upload',
}
LEG_RUN = STEPS[('create-release.yml', 'conda', 'Check whether this leg is already on Anaconda')]
BUILD_RUN = STEPS[('cron-conda.yml', 'conda-dist', 'Build conda packages')]
UPLOAD_RUN = STEPS[('cron-conda.yml', 'conda-dist', 'Upload conda packages to Anaconda (Intel)')]


@unittest.skipIf(not BASH, 'needs bash, which ran the former shell')
class TestTheFormerShellAgrees(_Stand):
    """Each script exits, prints, writes and calls exactly as the step's inline shell form, on every case."""

    def agree(self, shell: 'str', run: 'str', env: 'dict[str, str]', label: 'str' = '',
              python: 'str' = '') -> 'tuple[object, ...]':
        self.reset()
        old = self.former(shell, env, label, python)
        self.reset()
        new = self.script(run, env)
        self.assertEqual(new, old)
        return old

    def test_the_leg_check(self) -> None:
        for case in LEG_CASES:
            with self.subTest(case=case[0]):
                self.agree(FORMER_LEG, LEG_RUN, self.leg_env(case), str(case[1]), str(case[2]))

    def test_the_build(self) -> None:
        for shell, cases in ((FORMER_BUILD, BUILD_CASES),
                             (FORMER_RELEASE_BUILD, [case for case in BUILD_CASES if case[1] != 'windows-latest'])):
            for case in cases:
                with self.subTest(case=case[0], release=shell is FORMER_RELEASE_BUILD):
                    self.agree(shell, BUILD_RUN, self.build_env(case), str(case[1]), '3.14')

    def test_the_upload(self) -> None:
        for case in UPLOAD_CASES:
            with self.subTest(case=case[0]):
                self.agree(FORMER_UPLOAD, UPLOAD_RUN, self.upload_env(case))

    def test_every_way_each_shell_ends_was_reached(self) -> None:
        """So agreement is not agreement on one path."""
        ended = {}  # type: dict[str, set[object]]
        for name, shell, cases, env in (
                ('leg', FORMER_LEG, LEG_CASES, self.leg_env), ('build', FORMER_BUILD, BUILD_CASES, self.build_env),
                ('upload', FORMER_UPLOAD, UPLOAD_CASES, self.upload_env)):
            for case in cases:
                self.reset()
                found = self.former(shell, env(case), str(case[1]), '3.14' if name == 'build' else str(case[2]))
                ended.setdefault(name, set()).add((found[0], dict(found[3]).get('PCAPKIT_LEG_EXISTS')))
        self.assertEqual(ended, {
            'leg': {(0, 'true'), (0, 'false'), (1, None)},
            'build': {(0, None), (1, None), (3, None), (127, None)},
            'upload': {(0, None), (1, None), (2, None), (5, None)},
        })


class TestTheScripts(_Stand):
    """What a run outputs, read as the runner reads it."""

    def setUp(self) -> None:
        super().setUp()
        self.reset()

    def test_a_build_outputs_every_package(self) -> None:
        status, stdout, _, outputs, _ = self.script(BUILD_RUN, self.build_env(BUILD_CASES[4]))
        self.assertEqual(status, 0)
        found = ['<out>/linux-64/.hidden.conda', '<out>/linux-64/a.conda', '<out>/linux-64/z.tar.bz2']
        self.assertEqual(stdout, 'conda-build: building\n' + ''.join(f'{path}\n' for path in found))
        self.assertEqual(outputs, [('out_dir', '<out>'), ('host_package', found[0]),
                                   ('packages_csv', ','.join(found)), ('packages', '\n'.join(found))])

    def test_a_package_for_another_platform_fails_the_leg(self) -> None:
        status, stdout, _, outputs, _ = self.script(BUILD_RUN, self.build_env(BUILD_CASES[5]))
        self.assertEqual(status, 1)
        self.assertEqual(stdout.splitlines()[-1], (
            '::error title=osx-arm64 package on a osx-64 leg (#1822)::macos-26-intel publishes osx-64, and conda '
            'built osx-arm64 here; a package is published only for the platform it was built on.'))
        self.assertEqual([name for name, _ in outputs], ['out_dir', 'host_package'])

    def test_a_published_leg_is_announced(self) -> None:
        status, stdout, _, outputs, calls = self.script(LEG_RUN, self.leg_env(LEG_CASES[0]))
        self.assertEqual(status, 0)
        self.assertEqual(outputs, [('PCAPKIT_LEG_EXISTS', 'true')])
        self.assertEqual(stdout, '::notice title=conda leg already published::pypcapkit 1.5.0 for linux-64 / py314 '
                                 "is already on anaconda.org/jarryshaw (http 200); skipping this leg's upload.\n")
        self.assertEqual(calls, f'curl -s --retry 3 --retry-connrefused -o {self.release} -w %{{http_code}} '
                                'https://api.anaconda.org/release/jarryshaw/pypcapkit/1.5.0\n')

    def test_only_a_200_is_read(self) -> None:
        """As :data:`FORMER_LEG`'s ``[ "$status" = "200" ]``: a 201 holding this very leg reads ``false``, uncounted."""
        case = next(case for case in LEG_CASES if case[0] == 'a 2xx other than 200 is not read')
        status, stdout, stderr, outputs, calls = self.script(LEG_RUN, self.leg_env(case))
        self.assertEqual((status, stdout, stderr), (0, '', ''))
        self.assertEqual(outputs, [('PCAPKIT_LEG_EXISTS', 'false')])
        self.assertEqual(str(calls).count('\n'), 1)  # curl alone, no count

    def test_the_upload_makes_the_actions_call(self) -> None:
        status, _, _, _, calls = self.script(UPLOAD_RUN, self.upload_env(UPLOAD_CASES[1]))
        self.assertEqual(status, 0)
        self.assertEqual(str(calls).splitlines(), [
            'conda install -n base --override-channels -c conda-forge -y anaconda-client', 'anaconda',
            '--token', 'TOKEN', 'upload', '--user', 'jarryshaw', '--skip-existing', '--label', 'main',
            '--label', 'dev', *PACKAGES.split('\n')])

    def test_the_outputs_reader_reads_both_forms(self) -> None:
        self.assertEqual(read_outputs('a=1\nb<<EOF_x\nl1\nl2\nEOF_x\nc=x<<y\n'),
                         [('a', '1'), ('b', 'l1\nl2'), ('c', 'x<<y')])


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
            if 'release_conda.py upload' in STEPS[(workflow, job_id, name)]:
                continue
            given = self.step(workflow, job_id, name)['env']
            with self.subTest(workflow=workflow, step=name):
                self.assertEqual(given['PCAPKIT_CONDA_OS'], '${{ matrix.os }}')  # type: ignore[index]
                self.assertEqual(given['PCAPKIT_PYTHON_VERSION'], '${{ matrix.python-version }}')  # type: ignore[index]

    def test_the_build_runs_from_the_recipe_under_a_login_shell(self) -> None:
        """Where conda's base ``python`` is first on ``PATH``, and on Windows ``conda`` is defined at all."""
        for workflow, job_id in JOBS:
            build = self.step(workflow, job_id, 'Build conda packages')
            with self.subTest(workflow=workflow):
                self.assertEqual(build['working-directory'], 'conda/pypcapkit')
                self.assertEqual(build['shell'], 'bash -el {0}')

    def test_no_step_keeps_the_former_shell(self) -> None:
        for workflow, job_id in JOBS:
            for entry in steps(workflow, job_id):
                for line in ('target_platform', 'anaconda --token', '/bin/anaconda', 'conda build .'):
                    with self.subTest(workflow=workflow, step=entry.get('name'), line=line):
                        self.assertNotIn(line, str(entry.get('run', '')))

    def test_every_leg_is_mapped_and_every_mapping_is_a_leg(self) -> None:
        legs = set()  # type: set[str]
        for workflow, job_id in JOBS:
            labels = job(workflow, job_id)['strategy']['matrix']['os']
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
