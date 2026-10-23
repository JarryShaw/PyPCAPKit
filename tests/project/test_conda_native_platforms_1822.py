# -*- coding: utf-8 -*-
"""Each conda package carries binaries for its own platform (#1822).

* Both conda jobs map each runner label of their ``os`` axis, through
  :file:`util/release_conda.py`'s ``PLATFORMS`` since #1967, to the conda
  platform of that runner's own architecture, as GitHub's runner-images table
  gives it (the snapshot in :file:`python_versions_fixtures`), and between them
  build exactly :data:`conda_vendor.PLATFORMS`; win-64 only in Conda Update,
  which does not publish it yet (#2060).
* Neither job runs ``conda convert``. Run as the job runs it, with a stand-in
  ``conda``, a leg publishes the one package conda built, and fails before any
  upload when that is not the platform its label maps to.
* ``--smoke`` reads each native binary's ELF, Mach-O or PE header and fails on one
  that is not for the package's platform, and on a package that is not for the
  runner's own.

"""

from __future__ import annotations

import bz2
import importlib.util
import io
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess  # nosec: B404
import sys
import tarfile
import tempfile
import textwrap
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests import _workflows
from tests.project.test_release_conda_scripts_1967 import read_outputs
from util import release_conda

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from typing import Any, Optional

#: Test tier (#1958): checks the conda jobs' matrices and drives their scripts
#: offline.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / '.github' / 'workflows'
FIXTURES = pathlib.Path(__file__).resolve().parent / 'python_versions_fixtures'
NO_TOMLLIB = 'tomllib, which util/conda_vendor.py imports, needs Python 3.11+'
BASH = shutil.which('bash')

#: The conda jobs, as (workflow, job).
JOBS = (('cron-conda.yml', 'conda-dist'), ('create-release.yml', 'conda'))
#: What each leg publishes. ``macos-latest`` is arm64 and ``macos-26-intel``
#: Intel, per https://docs.github.com/en/actions/reference/runners/github-hosted-runners
#: as read on 2026-10-16; the test below checks the snapshot of the image table too.
LEGS = {'macos-latest': 'osx-arm64', 'macos-26-intel': 'osx-64', 'ubuntu-latest': 'linux-64'}
#: Each job's legs: Conda Update's add #2060's unpublished ``windows-latest``.
JOB_LEGS = {('cron-conda.yml', 'conda-dist'): dict(LEGS, **{'windows-latest': 'win-64'}),
            ('create-release.yml', 'conda'): LEGS}
#: ``platform.machine()``, as the runner-images table names the architecture.
ARCH = {'x86_64': 'x64', 'arm64': 'arm64', 'AMD64': 'x64'}

_MODULES = {}  # type: dict[str, Any]


def load(name: 'str') -> 'Any':
    """:file:`util/<name>.py`, loaded once; skipped without :mod:`tomllib`, which both import."""
    if tomllib is None:  # pragma: no cover
        raise unittest.SkipTest(NO_TOMLLIB)
    if name not in _MODULES:
        spec = importlib.util.spec_from_file_location(name, ROOT / 'util' / f'{name}.py')
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        _MODULES[name] = module
    return _MODULES[name]


def job(name: 'str', job_id: 'str') -> 'dict[str, Any]':
    if yaml is None:  # pragma: no cover
        raise unittest.SkipTest('PyYAML, from the test extra, is not installed')
    return _workflows.job(WORKFLOWS / name, job_id)


def mappings(spec: 'dict[str, Any]') -> 'list[dict[str, str]]':
    """The label-to-platform map each of the job's steps that maps its leg reads (#1967)."""
    return [dict(release_conda.PLATFORMS) for step in spec.get('steps', [])
            if re.search(r'\butil/release_conda\.py (?:leg|build)\b', str(step.get('run', '')))]


class RunnerMappingTests(unittest.TestCase):
    """Each label publishes the platform its runner is."""

    def test_each_leg_publishes_its_runners_own_platform(self) -> None:
        vendor, updater = load('conda_vendor'), load('update_python_versions')
        images = updater.parse_images((FIXTURES / 'runner-images-readme.md').read_text(encoding='utf-8'))
        for name, job_id in JOBS:
            spec = job(name, job_id)
            labels = spec['strategy']['matrix']['os']
            blocks = mappings(spec)
            self.assertTrue(blocks, f'{name} {job_id} maps no runner label')
            for block in blocks:
                with self.subTest(workflow=name, job=job_id):
                    self.assertEqual({label: block.get(label) for label in labels}, JOB_LEGS[(name, job_id)])
                for label in labels:
                    sys_platform, _, machine = vendor.PLATFORMS[block[label]]
                    with self.subTest(workflow=name, job=job_id, label=label):
                        self.assertEqual({(target.platform, target.arch)
                                          for target in updater.label_targets(label, images)},
                                         {(sys_platform, ARCH[machine])})

    def test_the_legs_are_the_vendored_platforms(self) -> None:
        """What conda/requirements.txt is derived for is what the legs build."""
        built = sorted({platform for legs in JOB_LEGS.values() for platform in legs.values()})
        self.assertEqual(sorted(load('conda_vendor').PLATFORMS), built)
        self.assertEqual(sorted(load('conda_vendor').BINARIES), built)


#: Stands in for ``conda``: ``build`` writes an empty package under
#: ``$FAKE_SUBDIR`` of ``--output-folder``, ``convert`` one under ``-p`` of ``-o``.
CONDA = textwrap.dedent('''\
    #!/usr/bin/env bash
    set -eu
    command="$1"; shift
    out=""; platform="${FAKE_SUBDIR}"
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --output-folder|-o) out="$2"; shift ;;
        -p) platform="$2"; shift ;;
      esac
      shift
    done
    mkdir -p "$out/$platform"
    : > "$out/$platform/pypcapkit-1.0-py314_0.tar.bz2"
''')


@unittest.skipIf(not BASH, 'needs bash on PATH')
class NoConvertTests(unittest.TestCase):
    """No package is relabelled for another architecture."""

    def test_no_workflow_runs_conda_convert(self) -> None:
        if yaml is None:  # pragma: no cover
            raise unittest.SkipTest('PyYAML, from the test extra, is not installed')
        for path in sorted(WORKFLOWS.glob('*.yml')):
            for job_id, spec in (_workflows.load(path).get('jobs') or {}).items():
                for step in spec.get('steps', []):
                    code = [line for line in str(step.get('run', '')).splitlines()
                            if not line.lstrip().startswith('#')]
                    with self.subTest(workflow=path.name, job=job_id, step=step.get('name')):
                        self.assertFalse([line for line in code if re.search(r'\bconda\s+convert\b', line)])

    def build(self, name: 'str', job_id: 'str', label: 'str', built: 'str') -> 'tuple[int, str, list[str]]':
        """The job's build step on ``label`` where conda builds ``built``: status, log, packages."""
        step = next(step for step in job(name, job_id)['steps'] if step.get('id') == 'conda_build')
        self.assertEqual(step['run'], 'python ../../util/release_conda.py build')
        self.assertEqual(step['env']['PCAPKIT_CONDA_OS'], '${{ matrix.os }}')
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
                         TMPDIR=temp, GITHUB_OUTPUT=str(output), FAKE_SUBDIR=built,
                         PCAPKIT_VERSION='1.0', PCAPKIT_BUILD='0', PCAPKIT_CONDA_OS=label,
                         PCAPKIT_PYTHON_VERSION='3.14'),
                capture_output=True, text=True, check=False, timeout=60)
            written = dict(read_outputs(output.read_text(encoding='utf-8')))
        found = written['packages'].splitlines() if 'packages' in written else []
        return result.returncode, result.stdout + result.stderr, [path.split('/')[-2] for path in found]

    def test_a_leg_publishes_only_the_package_conda_built(self) -> None:
        for name, job_id in JOBS:
            for label, platform in JOB_LEGS[(name, job_id)].items():
                with self.subTest(workflow=name, label=label):
                    status, log, packages = self.build(name, job_id, label, platform)
                    self.assertEqual(status, 0, log)
                    self.assertEqual(packages, [platform])

    def test_a_leg_whose_conda_built_another_platform_fails(self) -> None:
        for name, job_id in JOBS:
            for label, built in (('macos-26-intel', 'osx-arm64'), ('macos-latest', 'osx-64'),
                                 ('macos-99', 'osx-arm64')):
                with self.subTest(workflow=name, label=label):
                    status, log, packages = self.build(name, job_id, label, built)
                    self.assertEqual(status, 1, log)
                    self.assertIn(f'::error title={built} package on a ', log)
                    self.assertEqual(packages, [])


def elf(machine: 'int', bits: 'int' = 64) -> 'bytes':
    """A little-endian ELF shared object's header for ``e_machine``."""
    return b'\x7fELF' + bytes((bits // 32, 1, 1, 0, 0)) + bytes(7) + (3).to_bytes(2, 'little') \
        + machine.to_bytes(2, 'little') + bytes(44)


def macho(cpu: 'int') -> 'bytes':
    """A 64-bit little-endian Mach-O bundle's header for ``cputype``."""
    return b'\xcf\xfa\xed\xfe' + cpu.to_bytes(4, 'little') + bytes(4) + (8).to_bytes(4, 'little') + bytes(16)


def pe(machine: 'int', offset: 'int' = 0x80) -> 'bytes':
    """A PE image's header for COFF ``Machine``, its ``PE\\0\\0`` at ``offset`` (#2060)."""
    head = bytearray(b'MZ\x90\x00' + bytes(offset - 4))
    head[0x3c:0x40] = offset.to_bytes(4, 'little')
    return bytes(head) + b'PE\0\0' + machine.to_bytes(2, 'little') + bytes(18)


def fat(*cpus: 'int') -> 'bytes':
    """A universal Mach-O's header with a slice per ``cputype``."""
    return b'\xca\xfe\xba\xbe' + len(cpus).to_bytes(4, 'big') + b''.join(
        cpu.to_bytes(4, 'big') + bytes(16) for cpu in cpus) + bytes(64)


X86_64, ARM64 = 0x01000007, 0x0100000c
#: One of each binary a wheel may carry, with what :func:`conda_vendor.native` reads.
STUBS = {
    'elf-x86_64': (elf(62), ('ELF', {'x86_64'})),
    'elf-arm64': (elf(183), ('ELF', {'arm64'})),
    'elf-i386': (elf(3, bits=32), ('ELF', {'i386'})),
    'macho-x86_64': (macho(X86_64), ('Mach-O', {'x86_64'})),
    'macho-arm64': (macho(ARM64), ('Mach-O', {'arm64'})),
    'universal2': (fat(X86_64, ARM64), ('Mach-O', {'x86_64', 'arm64'})),
    'fat-arm64': (fat(ARM64), ('Mach-O', {'arm64'})),
    'pe-x86_64': (pe(0x8664), ('PE', {'x86_64'})),
    'pe-arm64': (pe(0xaa64), ('PE', {'arm64'})),
    'pe-i386': (pe(0x014c), ('PE', {'i386'})),
}
#: The stubs a package for each platform may carry.
ACCEPTS = {
    'linux-64': {'elf-x86_64'},
    'osx-64': {'macho-x86_64', 'universal2'},
    'osx-arm64': {'macho-arm64', 'universal2', 'fat-arm64'},
    'win-64': {'pe-x86_64'},
}


class ArchitectureTests(unittest.TestCase):
    """:func:`conda_vendor.foreign` against stub binaries of each architecture."""

    def test_native_reads_each_header(self) -> None:
        vendor = load('conda_vendor')
        for stub, (head, (kind, machines)) in STUBS.items():
            with self.subTest(stub=stub):
                self.assertEqual(vendor.native(head), (kind, frozenset(machines)))
        java = b'\xca\xfe\xba\xbe\x00\x00\x00\x41' + bytes(32)
        for head in (java, b'', b'\x7fEL', b'# -*- coding: utf-8 -*-\n', b'MZ\x90\x00'):
            with self.subTest(head=head[:8]):
                self.assertIsNone(vendor.native(head))

    def test_each_platform_takes_only_its_own_machine(self) -> None:
        vendor = load('conda_vendor')
        self.assertEqual(sorted(ACCEPTS), sorted(vendor.PLATFORMS))
        for subdir, accepted in ACCEPTS.items():
            for stub, (head, _) in STUBS.items():
                with self.subTest(subdir=subdir, stub=stub), tempfile.TemporaryDirectory() as temp:
                    path = pathlib.Path(temp) / 'lib' / 'pcapkit' / '_extern' / 'native' / '_speedups.so'
                    path.parent.mkdir(parents=True)
                    path.write_bytes(head)
                    count, problems = vendor.foreign(pathlib.Path(temp), subdir)
                    self.assertEqual(count, 1)
                    if stub in accepted:
                        self.assertEqual(problems, [])
                    else:
                        self.assertEqual(len(problems), 1, problems)
                        self.assertTrue(problems[0].startswith('lib/pcapkit/_extern/native/_speedups.so: '),
                                        problems)
                        self.assertIn(f'as {subdir} needs', problems[0])

    def test_other_files_are_passed_over_and_an_unreadable_library_is_not(self) -> None:
        vendor = load('conda_vendor')
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            (root / 'pkg').mkdir()
            (root / 'pkg' / 'Main.class').write_bytes(b'\xca\xfe\xba\xbe\x00\x00\x00\x41' + bytes(32))
            (root / 'pkg' / '__init__.py').write_text('', encoding='utf-8')
            (root / 'pkg' / 'data.json').write_text('{}', encoding='utf-8')
            self.assertEqual(vendor.foreign(root, 'linux-64'), (0, []))
            (root / 'pkg' / '_native.pyd').write_bytes(b'MZ\x90\x00' + bytes(60))
            (root / 'pkg' / 'libffi.so.8').write_text('not a library', encoding='utf-8')
            count, problems = vendor.foreign(root, 'linux-64')
        self.assertEqual(count, 0)
        self.assertEqual(problems, ['pkg/_native.pyd: not ELF, Mach-O or PE, so its machine is unknown',
                                    'pkg/libffi.so.8: not ELF, Mach-O or PE, so its machine is unknown'])

    def test_noarch_carries_no_binary(self) -> None:
        vendor = load('conda_vendor')
        with tempfile.TemporaryDirectory() as temp:
            (pathlib.Path(temp) / 'x.so').write_bytes(STUBS['elf-x86_64'][0])
            self.assertEqual(vendor.foreign(pathlib.Path(temp), 'noarch'),
                             (1, ['x.so: ELF x86_64, but noarch has no native machine']))

    def test_the_runner_is_read_from_its_system_and_machine(self) -> None:
        vendor = load('conda_vendor')
        for here, subdir in ((('Linux', 'x86_64'), 'linux-64'), (('Darwin', 'x86_64'), 'osx-64'),
                             (('Darwin', 'arm64'), 'osx-arm64'), (('Linux', 'aarch64'), None),
                             (('Windows', 'AMD64'), 'win-64'), (('Windows', 'ARM64'), None)):
            with self.subTest(here=here), mock.patch.object(vendor.platform, 'system', return_value=here[0]), \
                    mock.patch.object(vendor.platform, 'machine', return_value=here[1]):
                self.assertEqual(vendor.runner_platform(), subdir)


#: A ``pcapkit/__init__.py`` reduced to its ``_extern`` shim.
SHIM = textwrap.dedent('''\
    import os, sys
    _extern = os.path.join(os.path.dirname(os.path.realpath(__file__)), '_extern')
    if os.path.exists(_extern):
        sys.path.append(_extern)
''')
#: A vendored distribution's native library, which nothing imports.
NATIVE = 'pcapkit/_extern/native/_speedups.so'
#: The rest of that distribution, so that the probe's checks pass.
DISTRIBUTION = {
    'pcapkit/_extern/native/__init__.py': b'',
    'pcapkit/_extern/native-1.0.dist-info/METADATA': b'Name: native\n',
    'pcapkit/_extern/native-1.0.dist-info/RECORD':
        b'native/__init__.py,,\nnative/_speedups.so,,\nnative-1.0.dist-info/METADATA,,\n'
        b'native-1.0.dist-info/RECORD,,\n',
}


class SmokeArchitectureTests(unittest.TestCase):
    """``--smoke`` on a package whose platform or binaries are not this runner's."""

    def setUp(self) -> None:
        self.runner = load('conda_vendor').runner_platform()
        if self.runner is None:  # pragma: no cover
            raise unittest.SkipTest('this machine is none of the platforms the conda legs build on')
        self.own = next(head for stub, (head, _) in STUBS.items() if stub in ACCEPTS[self.runner])
        self.other = next(head for stub, (head, _) in STUBS.items()
                          if stub not in ACCEPTS[self.runner] and stub.startswith('macho-'))

    def smoke(self, subdir: 'Optional[str]', files: 'dict[str, bytes]') -> 'tuple[int, str]':
        site = f'lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages/'
        files = dict({'pcapkit/__init__.py': SHIM.encode()}, **DISTRIBUTION, **files)
        members = {site + name: data for name, data in files.items()}
        if subdir is not None:
            members['info/index.json'] = json.dumps({'name': 'pypcapkit', 'subdir': subdir}).encode()
        with tempfile.TemporaryDirectory() as temp:
            package = pathlib.Path(temp) / 'pypcapkit-0-py_0.tar.bz2'
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode='w') as archive:
                for name, data in members.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            package.write_bytes(bz2.compress(buffer.getvalue()))
            result = subprocess.run(  # nosec: B603
                [sys.executable, str(ROOT / 'util' / 'conda_vendor.py'), '--smoke', str(package)],
                capture_output=True, text=True, check=False, timeout=120)
        return result.returncode, result.stdout + result.stderr

    def test_the_runners_own_binary_passes(self) -> None:
        status, log = self.smoke(self.runner, {NATIVE: self.own})
        self.assertEqual(status, 0, log)
        self.assertIn(f'{self.runner}: 1 native binaries read, none failing', log)
        self.assertIn('native-1.0.dist-info: 4/4 files, ok', log)

    def test_a_relabelled_binary_fails(self) -> None:
        """What ``conda convert`` made: the label is this runner's, the binary another machine's."""
        status, log = self.smoke(self.runner, {NATIVE: self.other})
        self.assertEqual(status, 1, log)
        self.assertIn(f'FOREIGN lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages/'
                      f'{NATIVE}: Mach-O ', log)
        self.assertIn(f'as {self.runner} needs', log)

    def test_a_package_for_another_platform_fails(self) -> None:
        other = next(subdir for subdir in ACCEPTS if subdir != self.runner)
        status, log = self.smoke(other, {NATIVE: self.own})
        self.assertEqual(status, 1, log)
        self.assertIn(f'is filed under {other}, and this runner is {self.runner}', log)

    def test_a_package_naming_no_platform_fails(self) -> None:
        status, log = self.smoke(None, {NATIVE: self.own})
        self.assertEqual(status, 1, log)
        self.assertIn('info/index.json names no subdir', log)


if __name__ == '__main__':
    unittest.main()
