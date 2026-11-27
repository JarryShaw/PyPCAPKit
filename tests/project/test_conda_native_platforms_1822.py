# -*- coding: utf-8 -*-
"""The conda package carries no native binary, as one ``noarch: python`` build (#1822, #3133).

* Both conda build jobs run on one runner, which :file:`util/release_conda.py`'s
  ``PLATFORMS`` (#1967) maps to ``noarch``, and the recipe declares
  ``noarch: python``; ``conda-test`` installs that one file everywhere (#3133).
* Neither job runs ``conda convert``. Run as the job runs it, with a stand-in
  ``conda``, the job publishes the one package conda built, and fails before any
  upload when that is not filed under ``noarch``.
* ``--smoke`` reads each native binary's ELF, Mach-O or PE header and fails on
  any, and on a package that is not ``noarch: python``.

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

#: Test tier (#1958): checks the conda jobs and drives their scripts offline.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / '.github' / 'workflows'
RECIPE = ROOT / 'conda' / 'pypcapkit' / 'meta.yaml'
NO_TOMLLIB = 'tomllib, which util/conda_vendor.py imports, needs Python 3.11+'
BASH = shutil.which('bash')

#: The conda build jobs, as (workflow, job) (#3133).
JOBS = (('cron-conda.yml', 'conda-build'), ('create-release.yml', 'conda-build'))
#: The jobs whose steps map their runner through ``PLATFORMS``: the builds, and
#: ``conda``'s check of Anaconda before it publishes.
MAPPED = JOBS + (('create-release.yml', 'conda'),)

_MODULES = {}  # type: dict[str, Any]


def load(name: 'str') -> 'Any':
    """:file:`util/<name>.py`, loaded once; skipped without :mod:`tomllib`, which it imports."""
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


class RunnerMappingTests(unittest.TestCase):
    """The one runner publishes the noarch package."""

    def test_each_job_runs_one_leg_that_publishes_noarch(self) -> None:
        for name, job_id in MAPPED:
            spec = job(name, job_id)
            with self.subTest(workflow=name):
                self.assertNotIn('strategy', spec)
                self.assertEqual(release_conda.PLATFORMS, {spec['runs-on']: 'noarch'})
                named = {step['env']['PCAPKIT_CONDA_OS'] for step in spec['steps']
                         if re.search(r'\butil/release_conda\.py (?:leg|build)\b', str(step.get('run', '')))}
                self.assertEqual(named, {spec['runs-on']})

    def test_the_recipe_is_noarch_python(self) -> None:
        self.assertRegex(RECIPE.read_text(encoding='utf-8'), r'(?m)^build:\n(?:  .*\n)*?  noarch: python$')


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
    : > "$out/$platform/pypcapkit-1.0-py_0.tar.bz2"
''')


@unittest.skipIf(not BASH, 'needs bash on PATH')
class NoConvertTests(unittest.TestCase):
    """No package is relabelled for another platform."""

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
        self.assertEqual(step['env']['PCAPKIT_CONDA_OS'], 'ubuntu-latest')
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
                         PCAPKIT_PYTHON_VERSION='3.15'),
                capture_output=True, text=True, check=False, timeout=60)
            written = dict(read_outputs(output.read_text(encoding='utf-8')))
        found = written['packages'].splitlines() if 'packages' in written else []
        return result.returncode, result.stdout + result.stderr, [path.split('/')[-2] for path in found]

    def test_the_job_publishes_only_the_package_conda_built(self) -> None:
        for name, job_id in JOBS:
            with self.subTest(workflow=name):
                status, log, packages = self.build(name, job_id, 'ubuntu-latest', 'noarch')
                self.assertEqual(status, 0, log)
                self.assertEqual(packages, ['noarch'])

    def test_a_job_whose_conda_built_a_platform_package_fails(self) -> None:
        for name, job_id in JOBS:
            for label, built in (('ubuntu-latest', 'linux-64'), ('macos-latest', 'noarch')):
                with self.subTest(workflow=name, label=label, built=built):
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

    def test_noarch_takes_no_binary_of_any_machine(self) -> None:
        vendor = load('conda_vendor')
        for stub, (head, (kind, machines)) in STUBS.items():
            with self.subTest(stub=stub), tempfile.TemporaryDirectory() as temp:
                path = pathlib.Path(temp) / 'site-packages' / 'pcapkit' / '_extern' / 'native' / '_speedups.so'
                path.parent.mkdir(parents=True)
                path.write_bytes(head)
                self.assertEqual(vendor.foreign(pathlib.Path(temp)),
                                 [f'site-packages/pcapkit/_extern/native/_speedups.so: {kind} '
                                  f'{", ".join(sorted(machines))}, and noarch has no native machine'])

    def test_other_files_are_passed_over_and_an_unreadable_library_is_not(self) -> None:
        vendor = load('conda_vendor')
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            (root / 'pkg').mkdir()
            (root / 'pkg' / 'Main.class').write_bytes(b'\xca\xfe\xba\xbe\x00\x00\x00\x41' + bytes(32))
            (root / 'pkg' / '__init__.py').write_text('', encoding='utf-8')
            (root / 'pkg' / 'data.json').write_text('{}', encoding='utf-8')
            self.assertEqual(vendor.foreign(root), [])
            (root / 'pkg' / '_native.pyd').write_bytes(b'MZ\x90\x00' + bytes(60))
            (root / 'pkg' / 'libffi.so.8').write_text('not a library', encoding='utf-8')
            problems = vendor.foreign(root)
        self.assertEqual(problems, ['pkg/_native.pyd: not ELF, Mach-O or PE, so its machine is unknown',
                                    'pkg/libffi.so.8: not ELF, Mach-O or PE, so its machine is unknown'])


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
        b'native/__init__.py,,\nnative-1.0.dist-info/METADATA,,\nnative-1.0.dist-info/RECORD,,\n',
}


class SmokeArchitectureTests(unittest.TestCase):
    """``--smoke`` on a package that is not one pure ``noarch: python`` build."""

    def smoke(self, index: 'Optional[dict[str, str]]', files: 'dict[str, bytes]') -> 'tuple[int, str]':
        """``--smoke``'s status and log on a package of ``files`` in the noarch layout, and ``index``."""
        files = dict({'pcapkit/__init__.py': SHIM.encode()}, **DISTRIBUTION, **files)
        members = {f'site-packages/{name}': data for name, data in files.items()}
        if index is not None:
            members['info/index.json'] = json.dumps(dict({'name': 'pypcapkit'}, **index)).encode()
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

    NOARCH = {'subdir': 'noarch', 'noarch': 'python'}

    def test_a_pure_noarch_package_passes(self) -> None:
        status, log = self.smoke(self.NOARCH, {})
        self.assertEqual(status, 0, log)
        self.assertIn('noarch: no native binaries', log)
        self.assertIn('native-1.0.dist-info: 3/3 files, ok', log)
        self.assertIn('native: imported from pcapkit/_extern', log)

    def test_a_native_binary_fails(self) -> None:
        """What a vendored compiled wheel would bring in."""
        for stub in ('elf-x86_64', 'macho-arm64', 'pe-x86_64'):
            with self.subTest(stub=stub):
                status, log = self.smoke(self.NOARCH, {NATIVE: STUBS[stub][0]})
                self.assertEqual(status, 1, log)
                self.assertIn(f'FOREIGN site-packages/{NATIVE}: ', log)
                self.assertIn('noarch: 1 native binaries', log)

    def test_a_platform_package_fails(self) -> None:
        for index in ({'subdir': 'linux-64'}, {'subdir': 'noarch', 'noarch': 'generic'}):
            with self.subTest(index=index):
                status, log = self.smoke(index, {})
                self.assertEqual(status, 1, log)
                self.assertIn('and the package is one noarch: python build (#3133)', log)

    def test_a_package_naming_no_platform_fails(self) -> None:
        status, log = self.smoke(None, {})
        self.assertEqual(status, 1, log)
        self.assertIn('info/index.json names no subdir', log)


if __name__ == '__main__':
    unittest.main()
