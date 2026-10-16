# -*- coding: utf-8 -*-
"""Pins for the conda distribution's vendored packages (#1814).

* Every file under :file:`pcapkit/_extern` reaches the wheel, not just the
  modules package discovery finds, with no bytecode; a tree without the
  directory builds with no warning about it. Measured by building a wheel of a
  stub package carrying :file:`pyproject.toml`'s own ``[tool.setuptools]`` tables.
* :file:`util/conda_vendor.py` derives :file:`conda/requirements.txt` from
  ``dependencies`` and the ``all`` extra, walks what they require, drops a
  requirement no conda build can need, and its ``--check`` passes on the list it
  writes and fails on a stale one. These run on stand-in metadata, so they need
  neither the network nor any vendored package installed.
* The committed list holds every requirement :file:`pyproject.toml` makes live on
  a conda build, with its marker, and none that is dead there.
* ``--smoke`` passes on a conda package whose vendored distributions are complete
  and fails on one missing a data file.

"""

from __future__ import annotations

import bz2
import contextlib
import importlib.util
import io
import json
import pathlib
import subprocess  # nosec: B404
import sys
import tarfile
import tempfile
import textwrap
import unittest
import zipfile
from typing import TYPE_CHECKING

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from typing import Any, Optional

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'util' / 'conda_vendor.py'
NO_TOMLLIB = 'tomllib, which reads pyproject.toml and .github/python-versions.toml, needs Python 3.11+'

_MODULE = []  # type: list[Any]


def vendor() -> 'Any':
    """:file:`util/conda_vendor.py`, loaded once."""
    if tomllib is None:  # pragma: no cover
        raise unittest.SkipTest(NO_TOMLLIB)
    if not _MODULE:
        spec = importlib.util.spec_from_file_location('conda_vendor', SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        _MODULE.append(module)
    return _MODULE[0]


def toml_tables(prefix: 'str', table: 'dict[str, Any]') -> 'str':
    """``table`` as TOML: strings, booleans and lists of strings, nested tables last."""
    plain = {key: value for key, value in table.items() if not isinstance(value, dict)}
    out = [f'[{prefix}]'] + [f'{json.dumps(key)} = {json.dumps(value)}' for key, value in plain.items()]
    for key, value in table.items():
        if isinstance(value, dict):
            out.append(toml_tables(f'{prefix}.{json.dumps(key)}', value))
    return '\n'.join(out) + '\n'


#: Builds a wheel through setuptools' PEP 517 hook, in the stub's directory, and
#: prints its name.
BUILD = 'import sys; from setuptools import build_meta; print(build_meta.build_wheel(sys.argv[1]))'


class PackageDataTests(unittest.TestCase):
    """``pip install .`` in the conda recipe ships the whole of :file:`pcapkit/_extern`."""

    def build(self, extern: 'Optional[dict[str, bytes]]') -> 'tuple[list[str], str]':
        """The stub's wheel listing and build log, with ``extern`` under ``pcapkit/_extern``."""
        if tomllib is None:  # pragma: no cover
            raise unittest.SkipTest(NO_TOMLLIB)
        config = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))
        setuptools = {key: value for key, value in config['tool']['setuptools'].items()
                      if key != 'dynamic'}
        with tempfile.TemporaryDirectory() as temp:
            stub = pathlib.Path(temp) / 'stub'
            (stub / 'pcapkit').mkdir(parents=True)
            (stub / 'pcapkit' / '__init__.py').write_text('', encoding='utf-8')
            (stub / 'pyproject.toml').write_text(
                '[project]\nname = "stub"\nversion = "0"\n\n' + toml_tables('tool.setuptools', setuptools),
                encoding='utf-8')
            for name, data in (extern or {}).items():
                path = stub / 'pcapkit' / '_extern' / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            out = pathlib.Path(temp) / 'dist'
            out.mkdir()
            result = subprocess.run([sys.executable, '-c', BUILD, str(out)], cwd=stub,  # nosec
                                    capture_output=True, text=True, check=False, timeout=300)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            wheel = out / result.stdout.strip().splitlines()[-1]
            with zipfile.ZipFile(wheel) as archive:
                names = archive.namelist()
        return names, result.stdout + result.stderr

    def test_every_vendored_file_ships(self) -> None:
        extern = {
            'certifi/__init__.py': b'',
            'certifi/cacert.pem': b'-----BEGIN CERTIFICATE-----\n',
            'certifi/__pycache__/core.cpython-314.pyc': b'\0',
            'certifi-1.0.dist-info/METADATA': b'Name: certifi\n',
            'certifi-1.0.dist-info/RECORD': b'certifi/cacert.pem,,\n',
            'emoji/unicode_codes/emoji.json': b'{}',
            '7cf47097__mypyc.cpython-314-x86_64-linux-gnu.so': b'\0',
            'six.py': b'',
            '__pycache__/six.cpython-314.pyc': b'\0',
        }
        names, _ = self.build(extern)
        shipped = sorted(name[len('pcapkit/_extern/'):] for name in names
                         if name.startswith('pcapkit/_extern/'))
        self.assertEqual(shipped, sorted(name for name in extern if not name.endswith('.pyc')))

    def test_a_tree_without_extern_ships_none_of_it_and_warns_nothing(self) -> None:
        names, log = self.build(None)
        self.assertEqual(sorted(name for name in names if not name.startswith('stub-0.dist-info/')),
                         ['pcapkit/__init__.py'])
        self.assertNotRegex(log, r'(?i)warn.*_extern|_extern.*warn')


def requirement_lines(*lines: 'str') -> 'str':
    return ''.join(f'{line}\n' for line in lines)


#: Stand-in ``Requires-Dist`` metadata for :func:`conda_vendor.derive`.
METADATA = {
    'core': ['helper>=1', 'oldshim; python_version < "3.8"', 'docsy; extra == "docs"'],
    'helper': None,
    'crypt': ['ffi; platform_python_implementation != "PyPy"', 'socksy; extra == "socks"'],
    'ffi': ['parser; implementation_name != "PyPy"'],
    'parser': [],
    'socksy': [],
    'newer': [],
}
VERSIONS = {name: '1.0' for name in METADATA}


def requires(name: 'str') -> 'Optional[list[str]]':
    if name not in METADATA:
        raise KeyError(name)
    return METADATA[name]


class DeriveTests(unittest.TestCase):
    """:mod:`conda_vendor` classifies and writes the vendored set."""

    PYTHONS = ['3.11', '3.12', '3.13']

    def found(self, *direct: 'str') -> 'dict[str, dict[str, Any]]':
        module = vendor()
        from packaging.requirements import Requirement
        return module.derive([Requirement(line) for line in direct],
                             module.environments(self.PYTHONS), requires)

    def test_classes(self) -> None:
        found = self.found('core', 'crypt[socks]', 'backport; python_version < "3.11"',
                           'newer; python_version >= "3.12"')
        self.assertEqual({name: entry['class'] for name, entry in found.items()},
                         {'core': 'needed', 'helper': 'transitive', 'crypt': 'needed',
                          'ffi': 'transitive', 'parser': 'transitive', 'socksy': 'transitive',
                          'backport': 'dead', 'newer': 'needed'})

    def test_lines_carry_a_marker_only_where_some_builds_need_none(self) -> None:
        module = vendor()
        envs = module.environments(self.PYTHONS)
        found = self.found('core', 'backport; python_version < "3.11"', 'newer; python_version >= "3.12"')
        self.assertEqual(module.lines(found, envs, VERSIONS.__getitem__),
                         ['core==1.0', 'helper==1.0',
                          'newer==1.0; python_version == "3.12" or python_version == "3.13"'])

    def test_a_live_package_not_installed_here_is_named_with_its_builds(self) -> None:
        module = vendor()
        import importlib.metadata  # 3.8+, and vendor() has skipped below 3.11
        from packaging.requirements import Requirement
        here = f'{sys.version_info.major}.{sys.version_info.minor}'

        def lacking(name: 'str') -> 'list[str]':
            if name == 'shim':
                raise importlib.metadata.PackageNotFoundError(name)
            return {'core': ['shim; python_version < "3.2"']}.get(name, [])

        # Python 3.1 stands for a build this interpreter is not, as 3.11 is for
        # Conda Update's newest Python.
        with self.assertRaises(module.NotInstalled) as elsewhere:
            module.derive([Requirement('core')], module.environments(['3.1', '3.2']), lacking)
        self.assertIn('shim is needed on Python 3.1 on darwin, linux (core requires shim; '
                      'python_version < "3.2")', str(elsewhere.exception))
        self.assertIn(f'and Python {here} on {sys.platform}, which runs this, does not have it: '
                      'its marker leaves it out here', str(elsewhere.exception))
        with self.assertRaises(module.NotInstalled) as local:
            module.derive([Requirement('shim')], module.environments([here]), lacking)
        self.assertIn('(pyproject.toml asks for shim)', str(local.exception))
        self.assertTrue(str(local.exception).endswith('install .[all] first'), str(local.exception))

    def test_compare_passes_on_written_lines_and_names_each_stale_one(self) -> None:
        module = vendor()
        envs = module.environments(self.PYTHONS)
        found = self.found('core', 'crypt', 'backport; python_version < "3.11"')
        written = requirement_lines(*module.lines(found, envs, VERSIONS.__getitem__))
        self.assertEqual(module.compare(written, found, envs), [])
        repinned = written.replace('core==1.0', 'core==9.9')
        self.assertEqual(module.compare(repinned, found, envs), [])
        stale = requirement_lines('backport==1.0; python_version < "3.11"', 'core==1.0',
                                  'crypt==1.0', 'ffi==1.0', 'helper==1.0', 'lxml==6.1.3')
        problems = module.compare(stale, found, envs)
        self.assertEqual([problem.split(':')[0] + ':' + problem.split()[1] for problem in problems],
                         ['dead:backport', 'stale:lxml', 'missing:parser'])


class CommittedListTests(unittest.TestCase):
    """:file:`conda/requirements.txt` against :file:`pyproject.toml`, offline."""

    def test_every_live_direct_requirement_is_listed_and_no_dead_one(self) -> None:
        module = vendor()
        from packaging.markers import Marker
        envs = module.environments(module.conda_pythons())
        have = module.parse((ROOT / 'conda' / 'requirements.txt').read_text(encoding='utf-8'))
        for found in module.derive(module.direct(), envs, lambda name: []).items():
            name, entry = found
            with self.subTest(requirement=name):
                if entry['class'] == 'dead':
                    self.assertNotIn(name, have)
                    continue
                self.assertIn(name, have)
                marker = module.render_marker(entry['builds'], envs)
                self.assertEqual(have[name], None if marker is None else str(Marker(marker)))

    def test_check_passes_on_its_own_output_and_fails_on_a_stale_file(self) -> None:
        module = vendor()
        metadata = dict.fromkeys((req.name for req in module.direct()), [])
        with tempfile.TemporaryDirectory() as temp:
            target = pathlib.Path(temp) / 'requirements.txt'
            saved = module.FILE, module.ROOT, module._requires, module._version
            module.FILE, module.ROOT = target, pathlib.Path(temp)
            module._requires = lambda name: metadata.get(name, [])
            module._version = lambda name: '1.0'
            try:
                self.assertEqual(module.main([]), 0)
                with contextlib.redirect_stdout(io.StringIO()) as quiet:
                    self.assertEqual(module.main(['--check']), 0)
                self.assertEqual(quiet.getvalue(), '')
                target.write_text(target.read_text(encoding='utf-8') + 'scapy==2.8.0\n', encoding='utf-8')
                with contextlib.redirect_stdout(io.StringIO()) as report:
                    self.assertEqual(module.main(['--check']), 1)
                self.assertIn('stale: scapy', report.getvalue())
            finally:
                module.FILE, module.ROOT, module._requires, module._version = saved


#: A ``pcapkit/__init__.py`` reduced to its ``_extern`` shim.
SHIM = textwrap.dedent('''\
    import os, sys
    _extern = os.path.join(os.path.dirname(os.path.realpath(__file__)), '_extern')
    if os.path.exists(_extern):
        sys.path.append(_extern)
''')


class SmokeTests(unittest.TestCase):
    """``--smoke`` reads a built conda package's vendored distributions."""

    def package(self, temp: 'str', files: 'dict[str, str]') -> 'pathlib.Path':
        site = f'lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages/'
        path = pathlib.Path(temp) / 'pypcapkit-0-py_0.tar.bz2'
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as archive:
            for name, text in dict({'pcapkit/__init__.py': SHIM}, **files).items():
                data = text.encode('utf-8')
                info = tarfile.TarInfo(site + name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        path.write_bytes(bz2.compress(buffer.getvalue()))
        return path

    def smoke(self, files: 'dict[str, str]') -> 'tuple[int, str]':
        with tempfile.TemporaryDirectory() as temp:
            package = self.package(temp, files)
            result = subprocess.run([sys.executable, str(SCRIPT), '--smoke', str(package)],  # nosec
                                    capture_output=True, text=True, check=False, timeout=120)
        return result.returncode, result.stdout + result.stderr

    #: ``bundle`` reads its data on first use, as chardet reads its models, so a
    #: missing data file leaves the import working and only ``RECORD`` notices.
    FILES = {
        'pcapkit/_extern/bundle/__init__.py':
            "import os\n\ndef where():\n    return open(os.path.join(os.path.dirname(__file__), 'data.pem')).read()\n",
        'pcapkit/_extern/bundle/data.pem': 'pem\n',
        'pcapkit/_extern/bundle-1.0.dist-info/METADATA': 'Name: bundle\n',
        'pcapkit/_extern/bundle-1.0.dist-info/RECORD':
            'bundle/__init__.py,,\nbundle/data.pem,,\nbundle-1.0.dist-info/METADATA,,\n'
            'bundle-1.0.dist-info/RECORD,,\n../../bin/bundle,,\n',
    }

    def test_a_complete_package_passes(self) -> None:
        if tomllib is None:  # pragma: no cover
            raise unittest.SkipTest(NO_TOMLLIB)
        status, log = self.smoke(self.FILES)
        self.assertEqual(status, 0, log)
        self.assertIn('bundle: imported from pcapkit/_extern', log)

    def test_a_missing_data_file_fails(self) -> None:
        if tomllib is None:  # pragma: no cover
            raise unittest.SkipTest(NO_TOMLLIB)
        files = {name: text for name, text in self.FILES.items() if not name.endswith('data.pem')}
        status, log = self.smoke(files)
        self.assertEqual(status, 1, log)
        self.assertIn('MISSING bundle/data.pem', log)
        self.assertIn('bundle: imported from pcapkit/_extern', log)


if __name__ == '__main__':
    unittest.main()
