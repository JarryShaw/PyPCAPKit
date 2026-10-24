# -*- coding: utf-8 -*-
"""#2060: the conda jobs build, smoke-test and publish win-64.

Phase 1 gave ``conda-dist`` in :file:`.github/workflows/cron-conda.yml` a
non-blocking ``windows-latest`` leg that published nothing. Once its Conda
Update runs were green, phase 2 gave ``conda`` in
:file:`.github/workflows/create-release.yml` the leg too, made both blocking, and
uploads from both with the anaconda-client CLI, as the Intel legs do (#2044).

* :class:`TestTheWindowsLegPublishes`: on ``windows-latest`` each job runs one
  upload, "Upload conda packages to Anaconda (Windows)", evaluated with
  :func:`tests.project.test_release_gates.evaluate_condition`; it is the Intel
  step's call in a login shell, and skips a build-only manual run and a leg
  already on Anaconda. :data:`release_published.SUBDIRS` counts the platform.
* :class:`TestTheWindowsLegBlocks`: no step continues on error and no
  ``Windows summary`` reports, so a failure fails the leg as it does the others;
  each ``run:`` the leg reaches names ``bash``.
* :class:`TestTheWindowsClient`: ``release_conda.py upload`` runs base's
  ``Scripts\\anaconda.exe`` on Windows.
* :class:`TestBldBat`: ``conda/pypcapkit/bld.bat`` does what ``build.sh`` does:
  one install of every downloaded file, then the project, each checked. Its
  previous ``FOR`` loop wrote ``%A``, a syntax error in a batch file.
* :class:`TestPortableExecutable` and :class:`TestTheWindowsLayout`:
  :file:`util/conda_vendor.py` reads a ``.pyd``'s PE machine, and ``--smoke``
  takes a Windows package's ``Lib/site-packages``, or from Python 3.15 its
  ``lib/python/site-packages`` (conda-forge's CFEP-27), whose path names no Python.
* :class:`TestTheEnvironmentWithoutEnvironb`: the scripts read their variables
  where :data:`os.environb` is missing, as on Windows (#2120), where
  ``release_conda.py build`` died reading ``PCAPKIT_CONDA_OS``.

Nothing here runs on Windows; what a real run shows is the rest.

"""

from __future__ import annotations

import bz2
import contextlib
import copy
import io
import json
import os
import pathlib
import re
import sys
import tarfile
import tempfile
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests import _workflows
from tests.project.test_conda_native_platforms_1822 import DISTRIBUTION, SHIM, elf, load, pe
from tests.project.test_release_gates import PUBLISHING_MARKERS, STATUS, evaluate_condition
from util import _actions, leg_summary, release_conda, release_published, release_tiers

if TYPE_CHECKING:
    from typing import Any, Iterator

#: Test tier (#1958): reads the workflow and recipe files, and drives the script offline.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
RECIPE = ROOT / 'conda' / 'pypcapkit'
#: The conda jobs, as (workflow, job).
JOBS = (('cron-conda.yml', 'conda-dist'), ('create-release.yml', 'conda'))
WINDOWS = 'windows-latest'
INTEL = 'macos-26-intel'
#: The Windows leg's upload, and the Intel one it copies.
WINDOWS_UPLOAD = 'Upload conda packages to Anaconda (Windows)'
INTEL_UPLOAD = 'Upload conda packages to Anaconda (Intel)'
#: The steps that read ``ANACONDA_TOKEN``: the uploads, and nothing else.
ANACONDA_UPLOADS = ['Upload conda packages to Anaconda', INTEL_UPLOAD, WINDOWS_UPLOAD]
#: What publishes besides :data:`PUBLISHING_MARKERS`: Conda Update's GitHub Release upload.
MORE_MARKERS = ('ncipollo/release-action',)
#: The step that ran phase 1's warnings.
SUMMARY = 'Windows summary'


def spec(name: 'str', job_id: 'str') -> 'dict[str, Any]':
    return _workflows.job(name, job_id)


def step(name: 'str', job_id: 'str', step_name: 'str') -> 'dict[str, Any]':
    found = [entry for entry in spec(name, job_id)['steps'] if entry.get('name') == step_name]
    if len(found) != 1:
        raise AssertionError(f'{name}: {job_id} has {len(found)} steps named {step_name!r}, not one')
    return found[0]


def context(job: 'dict[str, Any]', os_label: 'str', event_name: 'str' = 'schedule',
            published: 'str' = 'false', publish: 'bool' = False) -> 'dict[str, object]':
    """A leg on ``os_label`` where every earlier step succeeded and the GitHub release exists.

    On the schedule unless ``event_name`` says otherwise: a manual run uploads
    nothing on any leg, which :mod:`tests.project.test_build_only_dispatch` pins,
    unless ``publish`` is set (#2060), which Conda Update's ``mode`` job turns
    into ``publishes``. ``published`` is what the release job's ``check_leg``
    found.

    """
    steps = {entry['id']: {'outcome': 'success', 'conclusion': 'success',
                           'outputs': {'published': 'true', 'PCAPKIT_LEG_EXISTS': published}}
             for entry in job['steps'] if 'id' in entry}
    publishes = 'true' if publish or event_name != 'workflow_dispatch' else 'false'
    return {'matrix': {'os': os_label}, 'steps': steps, 'github': {'event_name': event_name},
            'needs': {'mode': {'result': 'success', 'outputs': {'publishes': publishes}}},
            STATUS: {'cancelled': False, 'success': True, 'failure': False}}


def runs(job: 'dict[str, Any]', entry: 'dict[str, Any]', os_label: 'str', event_name: 'str' = 'schedule',
         published: 'str' = 'false', publish: 'bool' = False) -> 'bool':
    return evaluate_condition(str(entry.get('if', 'true')), context(job, os_label, event_name, published, publish))


def sensitive(entry: 'dict[str, Any]') -> 'bool':
    """Whether ``entry`` reads a secret or publishes anything."""
    text = repr(entry)
    return 'secrets.' in text or any(marker in text for marker in (*PUBLISHING_MARKERS, *MORE_MARKERS))


def publishers(job: 'dict[str, Any]', os_label: 'str', event_name: 'str' = 'schedule',
               published: 'str' = 'false', publish: 'bool' = False) -> 'list[str]':
    """Each step of ``job`` that reads a secret or publishes, and would run on ``os_label``."""
    return [str(entry.get('name') or entry.get('uses')) for entry in job['steps']
            if sensitive(entry) and runs(job, entry, os_label, event_name, published, publish)]


class TestTheWindowsLegPublishes(unittest.TestCase):
    """Each conda job uploads win-64 from its Windows leg, with the anaconda-client CLI."""

    def test_both_jobs_have_the_leg(self) -> None:
        for name, job_id in JOBS:
            with self.subTest(workflow=name, job=job_id):
                self.assertIn(WINDOWS, spec(name, job_id)['strategy']['matrix']['os'])
        self.assertEqual(release_conda.PLATFORMS[WINDOWS], 'win-64')

    def test_the_windows_leg_runs_its_own_upload_alone(self) -> None:
        """On a scheduled bump or a release, so the GitHub Release takes no win-64 file (as none of macOS's)."""
        for name, job_id in JOBS:
            with self.subTest(workflow=name, job=job_id):
                self.assertEqual(publishers(spec(name, job_id), WINDOWS), [WINDOWS_UPLOAD])

    def test_no_other_leg_runs_it(self) -> None:
        for name, job_id in JOBS:
            job = spec(name, job_id)
            for os_label in job['strategy']['matrix']['os']:
                with self.subTest(workflow=name, job=job_id, os=os_label):
                    self.assertEqual(runs(job, step(name, job_id, WINDOWS_UPLOAD), os_label), os_label == WINDOWS)
                    self.assertEqual(sum(runs(job, step(name, job_id, upload), os_label)
                                         for upload in ANACONDA_UPLOADS), 1)

    def test_a_manual_conda_update_run_publishes_nothing_there(self) -> None:
        job = spec('cron-conda.yml', 'conda-dist')
        self.assertEqual(publishers(job, WINDOWS, event_name='workflow_dispatch'), [])
        self.assertEqual(job['environment'], "${{ needs.mode.outputs.publishes == 'true' && 'anaconda' || '' }}")

    def test_a_manual_conda_update_run_with_publish_uploads_there(self) -> None:
        """#2060: the manual run that gets 1.5.0b14's missing win-64 file onto Anaconda."""
        job = spec('cron-conda.yml', 'conda-dist')
        self.assertEqual(publishers(job, WINDOWS, event_name='workflow_dispatch', publish=True), [WINDOWS_UPLOAD])

    def test_a_leg_already_on_anaconda_skips_it(self) -> None:
        """#888's per-leg check gates the Windows upload as it does the others."""
        job = spec('create-release.yml', 'conda')
        self.assertEqual(publishers(job, WINDOWS, published='true'), [])
        self.assertEqual(job['environment'], 'anaconda')
        check = next(entry for entry in job['steps'] if entry.get('id') == 'check_leg')
        self.assertEqual(check['env']['PCAPKIT_CONDA_OS'], '${{ matrix.os }}')

    def test_only_the_uploads_read_the_anaconda_token(self) -> None:
        for name, job_id in JOBS:
            job = spec(name, job_id)
            with self.subTest(workflow=name, job=job_id):
                readers = [entry.get('name') for entry in job['steps'] if 'secrets.ANACONDA_TOKEN' in repr(entry)]
                self.assertEqual(readers, ANACONDA_UPLOADS)

    def test_it_is_the_intel_call_in_a_login_shell(self) -> None:
        """The Intel step's inputs, on conda's base ``python``, which only ``bash -el`` activates."""
        for name, job_id in JOBS:
            names = [entry.get('name') for entry in spec(name, job_id)['steps']]
            windows, intel = step(name, job_id, WINDOWS_UPLOAD), step(name, job_id, INTEL_UPLOAD)
            with self.subTest(workflow=name, job=job_id):
                self.assertEqual(windows['env'], intel['env'])
                self.assertEqual(windows['shell'], 'bash -el {0}')
                self.assertEqual(windows['run'], 'python util/release_conda.py upload')
                self.assertEqual(windows['if'], intel['if'].replace(INTEL, WINDOWS))
                self.assertNotIn('uses', windows)
                self.assertEqual(names.index(WINDOWS_UPLOAD), names.index(INTEL_UPLOAD) + 1)

    def test_the_check_sees_an_upload_gated_off_the_leg(self) -> None:
        """So :meth:`test_the_windows_leg_runs_its_own_upload_alone` reads the gate, as phase 1 had it."""
        for name, job_id in JOBS:
            job = copy.deepcopy(spec(name, job_id))
            job['steps'] = [entry for entry in job['steps'] if entry.get('name') != WINDOWS_UPLOAD]
            with self.subTest(workflow=name, job=job_id):
                self.assertEqual(publishers(job, WINDOWS), [])

    def test_the_completeness_check_counts_every_release_leg(self) -> None:
        """``version_check`` expects each platform the release legs publish, win-64 among them."""
        legs = spec('create-release.yml', 'conda')['strategy']['matrix']['os']
        self.assertEqual(sorted(release_published.SUBDIRS.split()),
                         sorted(release_conda.PLATFORMS[os_label] for os_label in legs))
        self.assertIn('win-64', release_published.SUBDIRS.split())


class TestTheWindowsLegBlocks(unittest.TestCase):
    """A failure on the Windows leg fails it, as on every other leg."""

    def test_no_step_continues_on_error(self) -> None:
        for name, job_id in JOBS:
            job = spec(name, job_id)
            with self.subTest(workflow=name, job=job_id):
                self.assertNotIn('continue-on-error', job)
                self.assertEqual([entry.get('name') or entry.get('id') for entry in job['steps']
                                  if 'continue-on-error' in entry], [])
                self.assertNotIn(SUMMARY, [entry.get('name') for entry in job['steps']])
        self.assertNotIn('conda-windows', leg_summary.REASONS)

    def test_the_bash_steps_name_their_shell(self) -> None:
        """A ``run:`` step's default shell on Windows is ``pwsh``."""
        for name, job_id in JOBS:
            job = spec(name, job_id)
            for event_name in ('schedule', 'workflow_dispatch') if name == 'cron-conda.yml' else ('push',):
                for entry in job['steps']:
                    if 'run' in entry and runs(job, entry, WINDOWS, event_name):
                        with self.subTest(workflow=name, step=entry.get('name'), event=event_name):
                            self.assertTrue(str(entry.get('shell', '')).startswith('bash'))

    def test_conda_runs_in_a_login_shell(self) -> None:
        """Only ``bash -el`` has base active on Windows, so ``conda`` and base's ``python`` there."""
        for name, job_id in JOBS:
            for entry in spec(name, job_id)['steps']:
                text = str(entry.get('run', ''))
                if re.search(r'^conda |release_conda\.py (?:build|upload)$', text, re.MULTILINE) \
                        and entry.get('name') != INTEL_UPLOAD:
                    with self.subTest(workflow=name, step=entry.get('name')):
                        self.assertEqual(entry.get('shell'), 'bash -el {0}')

    def test_the_build_step_maps_the_leg_to_win_64(self) -> None:
        # #1967: util/release_conda.py maps it, which the step runs with the leg's label.
        for name, job_id in JOBS:
            build = next(entry for entry in spec(name, job_id)['steps'] if entry.get('id') == 'conda_build')
            with self.subTest(workflow=name, job=job_id):
                self.assertEqual(build['run'], 'python ../../util/release_conda.py build')
                self.assertEqual(build['env']['PCAPKIT_CONDA_OS'], '${{ matrix.os }}')

    def test_the_smoke_test_runs_python_exe_on_windows(self) -> None:
        for name, job_id in JOBS:
            smoke = step(name, job_id, 'Smoke-test the vendored packages')
            with self.subTest(workflow=name, job=job_id):
                self.assertNotIn('if', smoke)
                self.assertIn('if [ "$RUNNER_OS" = Windows ]; then\n'
                              '  python="$(cygpath -u "$pythonLocation")/python.exe"\n', smoke['run'])


class TestTheWindowsClient(unittest.TestCase):
    """``release_conda.py upload`` runs base's ``anaconda``, wherever conda keeps it."""

    PACKAGE = 'D:\\out\\win-64\\pypcapkit-0-py314_0.tar.bz2'

    def upload(self, windows: 'bool', conda: 'str') -> 'list[tuple[str, ...]]':
        calls = []  # type: list[tuple[str, ...]]

        def call(*args: 'str') -> 'int':
            calls.append(args)
            return 0

        environ = {'CONDA': conda, 'ANACONDA_API_TOKEN': 'TOKEN', 'PCAPKIT_CONDA_CHANNEL': 'jarryshaw',
                   'PCAPKIT_CONDA_LABELS': 'main', 'PCAPKIT_CONDA_PACKAGES': self.PACKAGE}
        with mock.patch.dict(os.environ, environ), mock.patch.object(release_conda, 'WINDOWS', windows), \
                mock.patch.object(release_conda, 'call', side_effect=call):
            self.assertEqual(release_conda.main(['upload']), 0)
        return calls

    def test_windows_runs_scripts_anaconda_exe(self) -> None:
        calls = self.upload(True, 'C:\\Miniconda')
        self.assertEqual(calls[0][0], 'conda')
        self.assertEqual(calls[1], ('C:\\Miniconda\\Scripts\\anaconda.exe', '--token', 'TOKEN', 'upload', '--user',
                                    'jarryshaw', '--skip-existing', '--label', 'main', self.PACKAGE))

    def test_elsewhere_it_runs_bin_anaconda(self) -> None:
        self.assertEqual(self.upload(False, '/opt/miniforge')[1][0], '/opt/miniforge/bin/anaconda')

    def test_the_flag_reads_the_running_os(self) -> None:
        self.assertIs(release_conda.WINDOWS, os.name == 'nt')


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

    def test_the_cfep_27_layout_is_read_from_the_build_string(self) -> None:
        """conda-forge's Python 3.15 on Windows has ``lib/python/site-packages``, naming no version."""
        vendor = load('conda_vendor')
        site = pathlib.Path('root') / 'lib' / 'python' / 'site-packages'
        self.assertEqual(vendor.built_for(site, {'build': 'py315_0'}), 'python3.15')
        self.assertEqual(vendor.built_for(site, {'build': 'h1a2b3c4_0'}),
                         "lib/python/site-packages with build string 'h1a2b3c4_0'")
        # Only under lib: anything else named python is not the layout.
        other = pathlib.Path('root') / 'opt' / 'python' / 'site-packages'
        self.assertEqual(vendor.built_for(other, {'build': 'py315_0'}), 'python')

    def smoke(self, build: 'str', site: 'str' = 'Lib/site-packages') -> 'tuple[int, str]':
        vendor = load('conda_vendor')
        files = dict({'pcapkit/__init__.py': SHIM.encode()}, **DISTRIBUTION)
        files['pcapkit/_extern/native/_speedups.pyd'] = pe(0x8664)
        files['pcapkit/_extern/native-1.0.dist-info/RECORD'] = (
            b'native/__init__.py,,\nnative/_speedups.pyd,,\nnative-1.0.dist-info/METADATA,,\n'
            b'native-1.0.dist-info/RECORD,,\n')
        members = {f'{site}/{name}': data for name, data in files.items()}
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

    def test_a_cfep_27_windows_package_for_this_python_passes(self) -> None:
        status, log = self.smoke(f'py{self.PYTHON.replace(".", "")}h0_0', site='lib/python/site-packages')
        self.assertEqual(status, 0, log)
        self.assertIn('win-64: 1 native binaries read, none failing', log)

    def test_a_windows_package_for_another_python_fails(self) -> None:
        status, log = self.smoke('py27_0')
        self.assertEqual(status, 1, log)
        self.assertIn('is built for python2.7, and this is ', log)


@contextlib.contextmanager
def without_environb(**environ: 'str') -> 'Iterator[None]':
    """``os`` as Windows has it, no :data:`os.environb`, with ``environ`` set and nothing else (#2120)."""
    environb = os.environb
    with mock.patch.dict(os.environ, environ, clear=True), \
            mock.patch.object(os, 'supports_bytes_environ', False):
        del os.environb
        try:
            yield
        finally:
            os.environb = environb


class TestTheEnvironmentWithoutEnvironb(unittest.TestCase):
    """#2120: each ``var()``, and the helper they share, on an ``os`` with no ``environb``."""

    VALUE = 'caf\xe9 windows-latest'

    def test_the_emulation_has_no_environb(self) -> None:
        with without_environb():
            self.assertFalse(hasattr(os, 'environb'))
        self.assertTrue(hasattr(os, 'environb'))

    def test_the_helper_reads_os_environ(self) -> None:
        with without_environb(PCAPKIT_CONDA_OS=self.VALUE):
            self.assertEqual(_actions.getenvb('PCAPKIT_CONDA_OS'), os.fsencode(self.VALUE))
            with self.assertRaises(KeyError):
                _actions.getenvb('PCAPKIT_UNSET')

    def test_the_helper_reads_os_environb_where_it_exists(self) -> None:
        with mock.patch.dict(os.environb, {b'PCAPKIT_CONDA_OS': b'\xff'}):
            self.assertEqual(_actions.getenvb('PCAPKIT_CONDA_OS'), b'\xff')

    def test_each_var_reads_the_value_and_refuses_an_unset_one(self) -> None:
        for module in (release_conda.release_published, release_tiers):
            with self.subTest(module=module.__name__), without_environb(PCAPKIT_CONDA_OS=self.VALUE):
                self.assertEqual(module.var('PCAPKIT_CONDA_OS'), os.fsencode(self.VALUE))
                with self.assertRaises(module.Unbound) as caught:
                    module.var('PCAPKIT_UNSET')
                self.assertEqual(str(caught.exception), 'PCAPKIT_UNSET')

    def test_build_gets_past_its_variables(self) -> None:
        """``build`` reads both variables and runs ``conda build``, where it raised AttributeError."""
        with tempfile.TemporaryDirectory() as temp:
            output = os.path.join(temp, 'output')
            out_dir = os.path.join(temp, 'compilation-x')
            with without_environb(PCAPKIT_CONDA_OS=WINDOWS, PCAPKIT_PYTHON_VERSION='3.15', GITHUB_OUTPUT=output), \
                    mock.patch.object(release_conda.tempfile, 'mkdtemp', return_value=out_dir), \
                    mock.patch.object(release_conda, 'call', return_value=7) as call:
                status = release_conda.main(['build'])
            with open(output, encoding='utf-8') as file:
                written = file.read()
        self.assertEqual(status, 7)
        call.assert_called_once_with('conda', 'build', '.', '--package-format', '.tar.bz2', '--no-anaconda-upload',
                                     '--output-folder', out_dir, '--python', '3.15')
        self.assertEqual(written, f'out_dir={out_dir}\n')

    def test_build_still_names_an_unset_variable(self) -> None:
        err = io.StringIO()
        with without_environb(), mock.patch.object(release_conda, 'call') as call, mock.patch('sys.stderr', err):
            status = release_conda.main(['build'])
        self.assertEqual((status, err.getvalue()), (1, 'PCAPKIT_CONDA_OS: unbound variable\n'))
        call.assert_not_called()


if __name__ == '__main__':
    unittest.main()
