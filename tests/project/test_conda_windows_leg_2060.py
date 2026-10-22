# -*- coding: utf-8 -*-
"""#2060, phase 1: Conda Update builds and smoke-tests win-64, and publishes none of it.

``conda-dist`` in :file:`.github/workflows/cron-conda.yml` gained a
``windows-latest`` leg. ``create-release.yml``'s ``conda`` job has none yet;
phase 2 adds it, with the uploads.

* :class:`TestTheWindowsLegPublishesNothing`: every step reading a secret or
  publishing is evaluated on ``windows-latest`` with
  :func:`tests.project.test_release_gates.evaluate_condition` and must not run.
  So no step on that leg receives ``ANACONDA_TOKEN``, which the job's
  ``environment: anaconda`` holds.
* :class:`TestTheWindowsLegNeverBlocks`: each step that runs there has an ``id``
  and a ``continue-on-error`` true on that leg alone, and ``Windows summary``,
  the last step, reports their failures as warnings, as ``KTLO summary`` does (#1672).
* :class:`TestBldBat`: ``conda/pypcapkit/bld.bat`` does what ``build.sh`` does:
  one install of every downloaded file, then the project, each checked. Its
  previous ``FOR`` loop wrote ``%A``, a syntax error in a batch file.
* :class:`TestPortableExecutable` and :class:`TestTheWindowsLayout`:
  :file:`util/conda_vendor.py` reads a ``.pyd``'s PE machine, and ``--smoke``
  takes a Windows package's ``Lib/site-packages``, whose path names no Python.

Nothing here runs on Windows; what a real Conda Update run shows is the rest.

"""

from __future__ import annotations

import bz2
import copy
import io
import json
import os
import pathlib
import re
import subprocess  # nosec: B404
import sys
import tarfile
import tempfile
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests import _workflows
from tests.project.test_conda_native_platforms_1822 import DISTRIBUTION, SHIM, elf, load, pe
from tests.project.test_release_gates import PUBLISHING_MARKERS, STATUS, evaluate_condition

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): reads the workflow and recipe files, and drives the script offline.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
RECIPE = ROOT / 'conda' / 'pypcapkit'
JOB = ('cron-conda.yml', 'conda-dist')
WINDOWS = 'windows-latest'
SUMMARY = 'Windows summary'
#: The steps that read ``ANACONDA_TOKEN``: the uploads, and nothing else.
ANACONDA_UPLOADS = ['Upload conda packages to Anaconda', 'Upload conda packages to Anaconda (Intel)']
#: What publishes besides :data:`PUBLISHING_MARKERS`: the GitHub Release upload.
MORE_MARKERS = ('ncipollo/release-action',)


def spec() -> 'dict[str, Any]':
    return _workflows.job(*JOB)


def context(os_label: 'str') -> 'dict[str, object]':
    """A leg on ``os_label`` where every earlier step succeeded and the release exists."""
    steps = {step['id']: {'outcome': 'success', 'conclusion': 'success',
                          'outputs': {'published': 'true'}}
             for step in spec()['steps'] if 'id' in step}
    return {'matrix': {'os': os_label}, 'steps': steps,
            STATUS: {'cancelled': False, 'success': True, 'failure': False}}


def runs(step: 'dict[str, Any]', os_label: 'str') -> 'bool':
    return evaluate_condition(str(step.get('if', 'true')), context(os_label))


def sensitive(step: 'dict[str, Any]') -> 'bool':
    """Whether ``step`` reads a secret or publishes anything."""
    text = repr(step)
    return 'secrets.' in text or any(marker in text for marker in (*PUBLISHING_MARKERS, *MORE_MARKERS))


def windows_publishers(job: 'dict[str, Any]') -> 'list[str]':
    """Each step of ``job`` that reads a secret or publishes, and would run on the Windows leg."""
    return [str(step.get('name') or step.get('uses')) for step in job['steps']
            if sensitive(step) and runs(step, WINDOWS)]


class TestTheWindowsLegPublishesNothing(unittest.TestCase):
    """No step that publishes, or reads a secret, runs on ``windows-latest``."""

    def test_the_leg_exists_in_conda_update_alone(self) -> None:
        self.assertIn(WINDOWS, spec()['strategy']['matrix']['os'])
        # Phase 2's: the release job gets the leg with its uploads.
        self.assertNotIn(WINDOWS, _workflows.job('create-release.yml', 'conda')['strategy']['matrix']['os'])

    def test_no_secret_or_upload_reaches_the_windows_leg(self) -> None:
        self.assertEqual(windows_publishers(spec()), [])

    def test_only_the_uploads_read_the_anaconda_token(self) -> None:
        readers = [step.get('name') for step in spec()['steps'] if 'secrets.ANACONDA_TOKEN' in repr(step)]
        self.assertEqual(readers, ANACONDA_UPLOADS)
        self.assertNotIn('ANACONDA_TOKEN', repr({key: value for key, value in spec().items() if key != 'steps'}))

    def test_every_other_leg_still_uploads(self) -> None:
        """So the pin cannot pass by gating every upload off every leg."""
        steps = [step for step in spec()['steps'] if step.get('name') in ANACONDA_UPLOADS]
        for os_label in spec()['strategy']['matrix']['os']:
            if os_label == WINDOWS:
                continue
            with self.subTest(os=os_label):
                self.assertEqual(sum(runs(step, os_label) for step in steps), 1)

    def test_the_check_sees_an_ungated_upload(self) -> None:
        job = copy.deepcopy(spec())
        upload = next(step for step in job['steps'] if step.get('name') == ANACONDA_UPLOADS[0])
        upload['if'] = upload['if'].replace(f" && matrix.os != '{WINDOWS}'", '')
        self.assertEqual(windows_publishers(job), [ANACONDA_UPLOADS[0]])


class TestTheWindowsLegNeverBlocks(unittest.TestCase):
    """Each step that can fail on the leg continues, and the summary reports it."""

    def test_each_step_it_runs_continues_on_error_there_alone(self) -> None:
        steps = spec()['steps']
        self.assertEqual(steps[-1].get('name'), SUMMARY)
        others = [os_label for os_label in spec()['strategy']['matrix']['os'] if os_label != WINDOWS]
        for step in steps[:-1]:
            if not runs(step, WINDOWS):
                continue
            name = step.get('name') or step.get('uses')
            with self.subTest(step=name):
                self.assertIn('id', step)
                guard = str(step.get('continue-on-error'))
                self.assertTrue(evaluate_condition(guard, context(WINDOWS)))
                for os_label in others:
                    self.assertFalse(evaluate_condition(guard, context(os_label)), os_label)

    def test_the_summary_runs_on_the_leg_alone_and_last(self) -> None:
        summary = spec()['steps'][-1]
        self.assertIs(summary.get('continue-on-error'), True)
        self.assertEqual(summary.get('shell'), 'bash')
        self.assertEqual(summary['env']['STEPS'], '${{ toJSON(steps) }}')
        self.assertEqual(summary['run'], 'python util/leg_summary.py conda-windows')
        for os_label in spec()['strategy']['matrix']['os']:
            with self.subTest(os=os_label):
                self.assertEqual(runs(summary, os_label), os_label == WINDOWS)
        cancelled = dict(context(WINDOWS), **{STATUS: {'cancelled': True, 'success': False, 'failure': False}})
        self.assertFalse(evaluate_condition(summary['if'], cancelled))

    def test_the_summary_warns_per_failed_step(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            page = pathlib.Path(temp) / 'summary.md'
            result = subprocess.run(  # nosec: B603
                [sys.executable, str(ROOT / 'util' / 'leg_summary.py'), 'conda-windows'],
                env=dict(os.environ, LEG='conda-dist on windows-latest', GITHUB_STEP_SUMMARY=str(page),
                         STEPS=json.dumps({'checkout': {'outcome': 'success'}, 'conda_build': {'outcome': 'failure'}})),
                capture_output=True, text=True, check=False, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            '::warning title=conda_build failed on conda-dist on windows-latest::The win-64 conda leg is '
            "unpublished and never blocks (#2060), so this job still succeeds; see the conda_build step's log."])

    def test_the_bash_steps_name_their_shell(self) -> None:
        """A ``run:`` step's default shell on Windows is ``pwsh``."""
        for step in spec()['steps']:
            if 'run' in step and runs(step, WINDOWS):
                with self.subTest(step=step.get('name')):
                    self.assertTrue(str(step.get('shell', '')).startswith('bash'))

    def test_the_build_step_maps_the_leg_to_win_64(self) -> None:
        build = next(step for step in spec()['steps'] if step.get('id') == 'conda_build')
        self.assertRegex(build['run'], r'\n\s*windows-latest\)\n\s*target_platform="win-64"\n')

    def test_the_smoke_test_runs_python_exe_on_windows(self) -> None:
        smoke = next(step for step in spec()['steps'] if step.get('id') == 'smoke')
        self.assertIn('if [ "$RUNNER_OS" = Windows ]; then\n  python="$(cygpath -u "$pythonLocation")/python.exe"\n',
                      smoke['run'])


#: A FOR loop's variable, with the percent signs before it.
FOR_VARIABLE = re.compile(r'^\s*FOR\s+(?:/\w+\s+(?:"[^"]*"\s+)?)*(%+)(\w)\s', re.IGNORECASE | re.MULTILINE)


def code(text: 'str') -> 'list[str]':
    """A batch file's lines but blank and ``REM`` ones."""
    return [line.strip() for line in text.splitlines()
            if line.strip() and not re.match(r'(?i)@?REM\b', line.strip())]


def pip_flags(line: 'str') -> 'list[str]':
    """What follows the targets of a ``pip install`` line, slashes for backslashes."""
    words = re.split(r'\bpip\s+install\s+', line, maxsplit=1)[1].split()
    while words and not words[0].startswith('-'):
        words.pop(0)
    return [word.replace('\\', '/') for word in words]


class TestBldBat(unittest.TestCase):
    """``bld.bat`` is ``build.sh`` for cmd."""

    def read(self, text: 'str') -> 'list[str]':
        """What is wrong with ``text`` as ``bld.bat``."""
        problems = []
        lines = code(text)
        for percents, name in FOR_VARIABLE.findall('\n'.join(lines)):
            if percents != '%%':
                problems.append(f'FOR variable {percents}{name}: a batch file needs %%{name}')
            for line in lines:
                if re.search(rf'(?<!%)%{name}(?![\w%])', line):
                    problems.append(f'{line}: %{name} with one percent sign')
        installs = [index for index, line in enumerate(lines) if re.search(r'\bpip\s+install\b', line)]
        depth = 0
        for line in lines:
            loop = re.match(r'(?i)FOR\b', line)
            if re.search(r'\bpip\s+install\b', line) and (depth or loop):
                problems.append(f'{line}: inside a FOR loop, so pip installs one file at a time')
            if loop and line.endswith('('):
                depth += 1
            elif line == ')' and depth:
                depth -= 1
        shell = [line for line in code((RECIPE / 'build.sh').read_text(encoding='utf-8'))
                 if re.search(r'\bpip\s+install\b', line)]
        if [pip_flags(lines[index]) for index in installs] != [pip_flags(line) for line in shell]:
            problems.append(f'pip calls {[lines[index] for index in installs]} are not build.sh\'s {shell}')
        for index in installs:
            following = lines[index + 1] if index + 1 < len(lines) else ''
            if following.upper() != 'IF ERRORLEVEL 1 EXIT 1':
                problems.append(f'{lines[index]}: not followed by IF ERRORLEVEL 1 EXIT 1')
        if not any(re.search(r'\bFOR\b.*\bconda\\wheels\\\*', line, re.IGNORECASE) for line in lines):
            problems.append('installs no conda\\wheels\\*, as build.sh installs conda/wheels/*')
        return problems

    def test_bld_bat_is_build_sh(self) -> None:
        self.assertEqual(self.read((RECIPE / 'bld.bat').read_text(encoding='utf-8')), [])

    def test_the_check_sees_the_loop_2060_replaced(self) -> None:
        old = ('@ECHO OFF\n\n'
               'FOR /F "Tokens=*" %A IN (\'DIR /B conda\\wheels\\\') DO @(\n'
               '    "%PYTHON%" -m pip install conda\\wheels\\%A --target pcapkit\\_extern -vv\n'
               ')\n\n'
               '"%PYTHON%" -m pip install . -vv\n\n'
               'IF ERRORLEVEL 1 EXIT 1\n')
        problems = self.read(old)
        self.assertIn('FOR variable %A: a batch file needs %%A', problems)
        self.assertIn('"%PYTHON%" -m pip install conda\\wheels\\%A --target pcapkit\\_extern -vv: '
                      'not followed by IF ERRORLEVEL 1 EXIT 1', problems)
        self.assertIn('"%PYTHON%" -m pip install conda\\wheels\\%A --target pcapkit\\_extern -vv: '
                      'inside a FOR loop, so pip installs one file at a time', problems)


class TestPortableExecutable(unittest.TestCase):
    """:func:`conda_vendor.native` reads a PE image's COFF ``Machine``."""

    def test_it_reads_each_machine(self) -> None:
        vendor = load('conda_vendor')
        for machine, name in ((0x8664, 'x86_64'), (0xaa64, 'arm64'), (0x014c, 'i386'), (0x1234, 'Machine 0x1234')):
            with self.subTest(machine=machine):
                self.assertEqual(vendor.native(pe(machine)), ('PE', frozenset((name,))))
        self.assertEqual(vendor.native(pe(0x8664, offset=0x200)), ('PE', frozenset(('x86_64',))))

    def test_an_mz_header_without_a_pe_one_is_unknown(self) -> None:
        vendor = load('conda_vendor')
        broken = bytearray(pe(0x8664))
        broken[0x80:0x84] = b'NE\0\0'
        for head in (b'MZ\x90\x00' + bytes(60), bytes(broken), pe(0x8664)[:0x3f], pe(0x8664)[:0x84]):
            with self.subTest(head=len(head)):
                self.assertIsNone(vendor.native(head))

    def test_win_64_takes_an_x86_64_pyd_alone(self) -> None:
        vendor = load('conda_vendor')
        for head, problem in ((pe(0x8664), None), (pe(0xaa64), 'PE arm64, not PE x86_64 as win-64 needs'),
                              (elf(62), 'ELF x86_64, not PE x86_64 as win-64 needs')):
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as temp:
                path = pathlib.Path(temp) / 'Lib' / 'site-packages' / '_cffi_backend.cp314-win_amd64.pyd'
                path.parent.mkdir(parents=True)
                path.write_bytes(head)
                self.assertEqual(vendor.foreign(pathlib.Path(temp), 'win-64'), (1, [] if problem is None else [
                    f'Lib/site-packages/_cffi_backend.cp314-win_amd64.pyd: {problem}']))

    def test_win_64_environments_are_nt(self) -> None:
        vendor = load('conda_vendor')
        envs = vendor.environments(['3.14'])
        self.assertEqual({(env['sys_platform'], env['os_name']) for env in envs},
                         {('linux', 'posix'), ('darwin', 'posix'), ('win32', 'nt')})
        self.assertRegex('cryptography-50.0.2-cp311-abi3-win_amd64.whl', vendor.WHEEL_PLATFORMS['win-64'])


class TestTheWindowsLayout(unittest.TestCase):
    """``--smoke`` on a package with ``Lib/site-packages``, as conda builds on Windows."""

    PYTHON = f'{sys.version_info.major}.{sys.version_info.minor}'

    def test_the_python_is_read_from_the_build_string(self) -> None:
        vendor = load('conda_vendor')
        site = pathlib.Path('root') / 'Lib' / 'site-packages'
        for build, built in (('py314h1a2b3c4_0', 'python3.14'), ('py39_0', 'python3.9'), ('py310_2', 'python3.10'),
                             (None, "Lib/site-packages with build string None"),
                             ('h1a2b3c4_0', "Lib/site-packages with build string 'h1a2b3c4_0'")):
            with self.subTest(build=build):
                self.assertEqual(vendor.built_for(site, {} if build is None else {'build': build}), built)
        posix = pathlib.Path('root') / 'lib' / 'python3.14' / 'site-packages'
        self.assertEqual(vendor.built_for(posix, {'build': 'py39_0'}), 'python3.14')

    def smoke(self, build: 'str') -> 'tuple[int, str]':
        vendor = load('conda_vendor')
        files = dict({'pcapkit/__init__.py': SHIM.encode()}, **DISTRIBUTION)
        files['pcapkit/_extern/native/_speedups.pyd'] = pe(0x8664)
        files['pcapkit/_extern/native-1.0.dist-info/RECORD'] = (
            b'native/__init__.py,,\nnative/_speedups.pyd,,\nnative-1.0.dist-info/METADATA,,\n'
            b'native-1.0.dist-info/RECORD,,\n')
        members = {f'Lib/site-packages/{name}': data for name, data in files.items()}
        members['info/index.json'] = json.dumps({'name': 'pypcapkit', 'subdir': 'win-64', 'build': build}).encode()
        with tempfile.TemporaryDirectory() as temp:
            package = pathlib.Path(temp) / 'pypcapkit-0-py_0.tar.bz2'
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode='w') as archive:
                for name, data in members.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            package.write_bytes(bz2.compress(buffer.getvalue()))
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.object(vendor, 'runner_platform', return_value='win-64'), \
                    mock.patch('sys.stdout', out), mock.patch('sys.stderr', err):
                status = vendor.smoke(package)
        return status, out.getvalue() + err.getvalue()

    def test_a_windows_package_for_this_python_passes(self) -> None:
        status, log = self.smoke(f'py{self.PYTHON.replace(".", "")}h0_0')
        self.assertEqual(status, 0, log)
        self.assertIn('win-64: 1 native binaries read, none failing', log)

    def test_a_windows_package_for_another_python_fails(self) -> None:
        status, log = self.smoke('py27_0')
        self.assertEqual(status, 1, log)
        self.assertIn('is built for python2.7, and this is ', log)


if __name__ == '__main__':
    unittest.main()
