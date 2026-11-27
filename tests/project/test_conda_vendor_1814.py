# -*- coding: utf-8 -*-
"""Pins for the conda distribution's vendored packages (#1814).

* Every file under :file:`pcapkit/_extern` reaches the wheel, not just the
  modules package discovery finds, with no bytecode; a tree without the
  directory builds with no warning about it. Measured by building a wheel of a
  stub package carrying :file:`pyproject.toml`'s own ``[tool.setuptools]`` tables.
* :file:`util/conda_vendor.py` derives :file:`conda/requirements.txt` from the
  ``dependencies`` conda-forge lacks (#3133), walks what they require, drops a
  requirement no interpreter can need, refuses one only some need, and its
  ``--check`` passes on the list it writes and fails on a stale one. These run on
  stand-in metadata, so they need neither the network nor any vendored package
  installed.
* The committed list holds every requirement :file:`pyproject.toml` makes live,
  with no marker, and none that is dead. The recipe takes the rest of
  ``dependencies`` from conda-forge, and no optional dependency at all.
* ``parse`` and ``--check`` report lines pinning one package differently under
  one marker, which pip cannot install together, and accept an identical
  duplicate (#1852).
* ``--smoke`` passes on a conda package whose vendored distributions are complete
  and fails on one missing a data file. Its noarch checks (#1822) are
  :file:`test_conda_native_platforms_1822.py`'s.
* :class:`InProcessTests` runs in this process the modes the others run as a
  subprocess, so their branches count towards coverage.

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
from unittest import mock

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from typing import Any, Optional

#: Test tier (#1958): drives util/conda_vendor.py, which runs on one interpreter.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'util' / 'conda_vendor.py'
RECIPE = ROOT / 'conda' / 'pypcapkit' / 'meta.yaml'
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
    'core': ['helper>=1', 'oldshim; python_version < "3.8"', 'docsy; extra == "docs"', 'typing-extensions'],
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

    def test_conda_forge_packages_are_not_vendored(self) -> None:
        """Asked for directly or by a vendored package, as ``core`` asks for typing-extensions (#3133)."""
        found = self.found('core', 'chardet', 'Typing_Extensions; python_version < "3.11"')
        self.assertEqual(sorted(found), ['core', 'helper'])

    def test_lines_carry_no_marker(self) -> None:
        module = vendor()
        envs = module.environments(self.PYTHONS)
        found = self.found('core', 'backport; python_version < "3.11"')
        self.assertEqual(module.lines(found, envs, VERSIONS.__getitem__), ['core==1.0', 'helper==1.0'])

    def test_a_package_only_some_interpreters_need_is_refused(self) -> None:
        """One noarch package serves them all, so it cannot vendor one for 3.12 and up alone (#3133)."""
        module = vendor()
        envs = module.environments(self.PYTHONS)
        found = self.found('core', 'newer; python_version >= "3.12"')
        with self.assertRaises(module.Partial) as raised:
            module.lines(found, envs, VERSIONS.__getitem__)
        self.assertEqual(str(raised.exception), (
            'partial: newer is needed on Python 3.12, 3.13 on darwin, linux, win32 only (and not on every '
            'interpreter one noarch package serves), so take it from conda-forge instead'))
        self.assertEqual(module.compare(requirement_lines('core==1.0', 'helper==1.0', 'newer==1.0'), found, envs),
                         [str(raised.exception)])

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
        self.assertIn('shim is needed on Python 3.1 on darwin, linux, win32 (core requires shim; '
                      'python_version < "3.2")', str(elsewhere.exception))
        self.assertIn(f'and Python {here} on {sys.platform}, which runs this, does not have it: '
                      'its marker leaves it out here', str(elsewhere.exception))
        with self.assertRaises(module.NotInstalled) as local:
            module.derive([Requirement('shim')], module.environments([here]), lacking)
        self.assertIn('(pyproject.toml asks for shim)', str(local.exception))
        self.assertTrue(str(local.exception).endswith('install . first'), str(local.exception))

    def test_compare_passes_on_written_lines_and_names_each_stale_one(self) -> None:
        module = vendor()
        envs = module.environments(self.PYTHONS)
        found = self.found('core', 'crypt', 'backport; python_version < "3.11"')
        written = requirement_lines(*module.lines(found, envs, VERSIONS.__getitem__))
        self.assertEqual(module.compare(written, found, envs), [])
        repinned = written.replace('core==1.0', 'core==9.9')
        self.assertEqual(module.compare(repinned, found, envs), [])
        stale = requirement_lines('backport==1.0; python_version < "3.11"', 'core==1.0',
                                  'crypt==1.0; sys_platform == "linux"', 'ffi==1.0', 'helper==1.0', 'lxml==6.1.3')
        problems = module.compare(stale, found, envs)
        self.assertEqual([problem.split(':')[0] + ':' + problem.split()[1] for problem in problems],
                         ['dead:backport', 'marker:crypt', 'stale:lxml', 'missing:parser'])


class CommittedListTests(unittest.TestCase):
    """:file:`conda/requirements.txt` against :file:`pyproject.toml`, offline."""

    def test_every_live_direct_requirement_is_listed_and_no_dead_one(self) -> None:
        module = vendor()
        envs = module.environments(module.conda_pythons())
        have = module.parse((ROOT / 'conda' / 'requirements.txt').read_text(encoding='utf-8'))
        for found in module.derive(module.direct(), envs, lambda name: []).items():
            name, entry = found
            with self.subTest(requirement=name):
                if entry['class'] == 'dead':
                    self.assertNotIn(name, have)
                    continue
                self.assertIn(name, have)
                self.assertEqual(set(have[name]), {None})

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


class DuplicatePinTests(unittest.TestCase):
    """Lines pinning one package differently under one marker, which pip rejects (#1852)."""

    #: A pin of dictdumper the committed file does not hold, as ``pip download -r``
    #: got one of aenum beside it in the issue and failed with ``ResolutionImpossible``.
    OTHER = '0.8.4'

    def setUp(self) -> None:
        self.module = vendor()
        self.text = (ROOT / 'conda' / 'requirements.txt').read_text(encoding='utf-8')
        self.envs = self.module.environments(self.module.conda_pythons())
        # Stand-in metadata: what the committed file says that this does not
        # derive is the same with the duplicate as without it.
        self.found = self.module.derive(self.module.direct(), self.envs, lambda name: [])
        self.pinned = self.module.parse(self.text)['dictdumper'][None]
        self.assertNotEqual(self.pinned, self.OTHER, 'pick another conflicting dictdumper pin')

    def added(self, line: 'str') -> 'list[str]':
        """What ``--check`` reports of the committed file with ``line`` appended, and not without it."""
        before = self.module.compare(self.text, self.found, self.envs)
        after = self.module.compare(self.text + line + '\n', self.found, self.envs)
        return [problem for problem in after if problem not in before]

    def test_the_committed_file_has_no_conflict(self) -> None:
        self.assertEqual([problem for problem in self.module.compare(self.text, self.found, self.envs)
                          if problem.startswith('conflict:')], [])

    def test_a_conflicting_pin_is_reported(self) -> None:
        conflict = f"conflict: dictdumper pins '=={self.pinned}' and '=={self.OTHER}' under the marker None"
        with self.assertRaises(self.module.Conflicting) as raised:
            self.module.parse(self.text + f'dictdumper=={self.OTHER}\n')
        self.assertEqual(str(raised.exception), conflict)
        self.assertEqual(self.added(f'dictdumper=={self.OTHER}'), [conflict])

    def test_markers_are_compared_once_normalised(self) -> None:
        text = requirement_lines('Six==1.0; python_version == "3.12"', "six==2.0; python_version=='3.12'",
                                 'six==3.0; python_version == "3.13"')
        with self.assertRaises(self.module.Conflicting) as raised:
            self.module.parse(text)
        self.assertEqual(str(raised.exception),
                         "conflict: six pins '==1.0' and '==2.0' under the marker 'python_version == \"3.12\"'")

    def test_an_identical_duplicate_is_accepted(self) -> None:
        line = f'dictdumper=={self.pinned}'
        self.assertEqual(self.module.parse(self.text + line + '\n'), self.module.parse(self.text))
        self.assertEqual(self.added(line), [])

    def test_check_exits_1_on_a_conflicting_duplicate_of_its_own_output(self) -> None:
        module = self.module
        with tempfile.TemporaryDirectory() as temp:
            target = pathlib.Path(temp) / 'requirements.txt'
            saved = module.FILE, module.ROOT, module._requires, module._version
            module.FILE, module.ROOT = target, pathlib.Path(temp)
            module._requires = lambda name: []
            module._version = lambda name: '1.0'
            try:
                self.assertEqual(module.main([]), 0)
                written = target.read_text(encoding='utf-8')
                target.write_text(written + 'dictdumper==1.0\n', encoding='utf-8')
                with contextlib.redirect_stdout(io.StringIO()) as quiet:
                    self.assertEqual(module.main(['--check']), 0)
                self.assertEqual(quiet.getvalue(), '')
                target.write_text(written + 'dictdumper==0.9\n', encoding='utf-8')
                with contextlib.redirect_stdout(io.StringIO()) as report:
                    self.assertEqual(module.main(['--check']), 1)
                self.assertEqual(report.getvalue(), "requirements.txt: conflict: dictdumper pins '==1.0' and "
                                                    "'==0.9' under the marker None\n")
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
        path = pathlib.Path(temp) / 'pypcapkit-0-py_0.tar.bz2'
        # #3133: the noarch layout, and index, which --smoke requires.
        members = {f'site-packages/{name}': text
                   for name, text in dict({'pcapkit/__init__.py': SHIM}, **files).items()}
        members['info/index.json'] = json.dumps({'name': 'pypcapkit', 'subdir': 'noarch', 'noarch': 'python'})
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as archive:
            for name, text in members.items():
                data = text.encode('utf-8')
                info = tarfile.TarInfo(name)
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


class InProcessTests(unittest.TestCase):
    """The modes the other tests run as a subprocess, run here, so their branches count (#3133)."""

    def setUp(self) -> None:
        self.module = vendor()
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-3133-vendor-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.temp = tmp.name

    def shown(self, returncode: 'int', stdout: 'bytes' = b'', stderr: 'bytes' = b'') -> 'Any':
        return mock.patch.object(self.module.subprocess, 'run', return_value=subprocess.CompletedProcess(
            ['git'], returncode, stdout, stderr))

    def test_same_dependencies_in_each_outcome(self) -> None:
        ours = (ROOT / 'pyproject.toml').read_bytes()
        cases = (
            (self.shown(0, ours), 0, 'v1 names the dependencies main does, which the conda recipe takes from '
                                     'conda-forge or vendors\n'),
            (self.shown(0, b'[project]\ndependencies = [ "tbtrim" ]\n'), self.module.NOT_SAME,
             "v1's tree would be built with main's conda recipe, and the two name different dependencies. "
             'v1: tbtrim. main: '),
            (self.shown(128, stderr=b"fatal: path 'pyproject.toml' 100%\nexists on disk"), 1,
             "::error title=No pyproject.toml at v1::fatal: path 'pyproject.toml' 100%25%0Aexists on disk\n"),
        )
        for patch, status, printed in cases:
            with self.subTest(status=status), patch, contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(self.module.main(['--same-dependencies', 'v1']), status)
            self.assertTrue(out.getvalue().startswith(printed), out.getvalue())

    def test_smoke_runs_from_main(self) -> None:
        package = SmokeTests().package(self.temp, SmokeTests.FILES)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.module.main(['--smoke', str(package)]), 0)

    def test_smoke_refuses_what_is_not_one_noarch_package(self) -> None:
        def package(index: 'Optional[str]', pcapkit: 'tuple[str, ...]') -> 'pathlib.Path':
            target = pathlib.Path(self.temp) / f'case-{len(list(pathlib.Path(self.temp).iterdir()))}.tar.bz2'
            members = {f'{site}pcapkit/__init__.py': SHIM for site in pcapkit}
            if index is not None:
                members['info/index.json'] = index
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode='w') as archive:
                for name, body in members.items():
                    data = body.encode('utf-8')
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            target.write_bytes(bz2.compress(buffer.getvalue()))
            return target
        noarch = json.dumps({'subdir': 'noarch', 'noarch': 'python'})
        for name, index, sites, said in (
                ('no pcapkit', noarch, (), 'expected one site-packages/pcapkit, found 0'),
                ('two pcapkits', noarch, ('site-packages/', 'a/site-packages/'), 'found 2'),
                ('no index', None, ('site-packages/',), 'info/index.json names no subdir'),
                ('an index that is not JSON', 'nope', ('site-packages/',), 'info/index.json names no subdir'),
                ('a platform package', json.dumps({'subdir': 'linux-64'}), ('site-packages/',),
                 'is filed under linux-64 as noarch None')):
            err = io.StringIO()
            with self.subTest(name), contextlib.redirect_stderr(err):
                self.assertEqual(self.module.smoke(package(index, sites)), 1)
            self.assertIn(said, err.getvalue())

    def test_main_names_a_package_not_installed(self) -> None:
        import importlib.metadata

        def lacking(name: 'str') -> 'list[str]':
            raise importlib.metadata.PackageNotFoundError(name)
        err = io.StringIO()
        with mock.patch.object(self.module, '_requires', lacking), contextlib.redirect_stderr(err):
            self.assertEqual(self.module.main(['--check']), 2)
        self.assertIn('install . first', err.getvalue())

    def test_main_refuses_a_package_only_some_interpreters_need(self) -> None:
        from packaging.requirements import Requirement
        target = pathlib.Path(self.temp) / 'requirements.txt'
        target.write_text('kept\n', encoding='utf-8')
        err = io.StringIO()
        with mock.patch.object(self.module, 'direct', lambda: [Requirement('newer; python_version >= "3.12"')]), \
                mock.patch.object(self.module, '_requires', lambda name: []), \
                mock.patch.object(self.module, 'FILE', target), contextlib.redirect_stderr(err):
            self.assertEqual(self.module.main([]), 1)
        self.assertTrue(err.getvalue().startswith('partial: newer is needed on Python 3.12'), err.getvalue())
        self.assertEqual(target.read_text(encoding='utf-8'), 'kept\n')

    def test_parse_passes_over_comments_and_blank_lines(self) -> None:
        self.assertEqual(self.module.parse('# vendored\n\ntbtrim==0.3.1  # for refined exceptions\n'),
                         {'tbtrim': {None: '0.3.1'}})

    def test_the_metadata_readers_read_what_is_installed(self) -> None:
        import importlib.metadata
        self.assertEqual(self.module._version('packaging'), importlib.metadata.version('packaging'))
        self.assertEqual(self.module._requires('packaging'), importlib.metadata.requires('packaging'))

    def test_a_package_asked_for_twice_is_walked_once(self) -> None:
        """Directly twice, and dead twice: one entry each, as the queue meets them."""
        module = self.module
        from packaging.requirements import Requirement
        found = module.derive([Requirement(line) for line in ('core', 'helper', 'helper', 'old; python_version < "3"',
                                                              'old; python_version < "3.1"')],
                              module.environments(['3.11', '3.12']), requires)
        self.assertEqual({name: entry['class'] for name, entry in found.items()},
                         {'core': 'needed', 'helper': 'needed', 'old': 'dead'})
        self.assertEqual(found['old']['marker'], 'python_version < "3"')


def recipe_list(section: 'str') -> 'list[str]':
    """The items of the recipe's ``requirements:`` ``section``, as written."""
    lines = RECIPE.read_text(encoding='utf-8').splitlines()
    start = lines.index(f'  {section}:') + 1
    found = []
    for line in lines[start:]:
        if line.startswith('    - '):
            found.append(line[len('    - '):])
        elif line.startswith('    #') or not line.strip():
            continue
        else:
            break
    return found


class RecipeTests(unittest.TestCase):
    """The recipe carries the core alone: conda-forge's packages, and the vendored rest (#3133)."""

    def setUp(self) -> None:
        if tomllib is None:  # pragma: no cover
            raise unittest.SkipTest(NO_TOMLLIB)
        from packaging.utils import canonicalize_name
        self.canonical = canonicalize_name
        self.project = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))['project']
        self.vendored = set(vendor().parse((ROOT / 'conda' / 'requirements.txt').read_text(encoding='utf-8')))

    def test_the_run_requirements_are_python_and_conda_forge(self) -> None:
        self.assertEqual(recipe_list('run'), [f'python {self.project["requires-python"]}',
                                              *sorted(vendor().CONDA_FORGE.values())])

    def test_each_core_dependency_comes_from_conda_forge_or_is_vendored(self) -> None:
        from packaging.requirements import Requirement
        core = {self.canonical(Requirement(line).name) for line in self.project['dependencies']}
        self.assertLessEqual(set(vendor().CONDA_FORGE), core)
        self.assertEqual(core - set(vendor().CONDA_FORGE), self.vendored)
        self.assertFalse(self.vendored & set(vendor().CONDA_FORGE))

    def test_no_optional_dependency_is_carried(self) -> None:
        """A user pip-installs one into the environment, which pcapkit uses ahead of _extern."""
        from packaging.requirements import Requirement
        core = {self.canonical(Requirement(line).name) for line in self.project['dependencies']}
        optional = {self.canonical(Requirement(line).name)
                    for lines in self.project['optional-dependencies'].values() for line in lines} - core
        self.assertIn('pycrate', optional)
        carried = self.vendored | {self.canonical(item.split()[0]) for item in recipe_list('run')}
        self.assertEqual(carried & optional, set())

    def test_the_recipe_test_imports_each_vendored_package_from_extern(self) -> None:
        command = next(line for line in RECIPE.read_text(encoding='utf-8').splitlines()
                       if line.strip().startswith('- python -c'))
        modules = command.split('import os, pcapkit, ', 1)[1].split(';', 1)[0].split(', ')
        self.assertEqual(sorted(modules), sorted(self.vendored))
        self.assertIn(f'for m in ({", ".join(modules)}))', command)


if __name__ == '__main__':
    unittest.main()
