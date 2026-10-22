# -*- coding: utf-8 -*-
"""#1660 Part B: a weekly job keeps :file:`.github/python-versions.toml` current.

:file:`util/update_python_versions.py` recomputes the tiers from python.org's
release cycle, PyPy's releases, setup-python's ``versions-manifest.json`` and the
runner-images README, rewrites the file and the prose the audit pins to it, and
lists the check runs a tier move renames. :file:`.github/workflows/cron-python-versions.yml`
runs it weekly: ``detect`` with no secret, ``pr`` behind ``github-release`` with a
release App token of contents and pull requests write, pushing
``bot/python-versions`` alone. The owner's rulings on #1660: a pull request he
merges, never a push to ``main``; the release App, given Pull requests; the
renames in the body, never a ruleset edit.

Nothing here touches the network. The sources are the snapshots in
:file:`tests/project/python_versions_fixtures/`, trimmed from what each URL
served on 2026-10-13, and each scenario edits a copy of them; :class:`TestFetch`
stubs ``requests.get``, which the script fetches them with (#1894). The scenarios run
on a scratch copy of the files the script writes, with the tier file as it stood
then (the ``python-versions.toml`` there) and the prose regenerated to match it,
so a later tier change, this job's own included, leaves them as they are. The
publishing tests run :func:`update_python_versions.publish` against a scratch
``origin`` with ``gh`` stubbed, so what it pushes is read back from a real
repository.

"""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import os
import pathlib
import re
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import types
import unittest
from typing import TYPE_CHECKING
from unittest import mock

import requests

from tests import _workflows
from tests._support import scale_timeout
from tests.project.test_release_gates import evaluate_condition

try:
    import tomllib
except ImportError:  # Python 3.10 and older
    tomllib = None  # type: ignore[assignment]

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from typing import Any, Callable, Optional

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'util' / 'update_python_versions.py'
FIXTURES = pathlib.Path(__file__).resolve().with_name('python_versions_fixtures')
#: The tier file as the snapshot found it, which ``as_of_the_file`` reproduces.
FROZEN = FIXTURES / 'python-versions.toml'
WORKFLOW = ROOT / '.github' / 'workflows' / 'cron-python-versions.yml'
NO_TOMLLIB = 'tomllib, which reads .github/python-versions.toml, needs Python 3.11+'

_UPDATER = []  # type: list[Any]


def updater() -> 'Any':
    """:file:`util/update_python_versions.py`, loaded once; skipped without :mod:`tomllib` or PyYAML."""
    if tomllib is None:
        raise unittest.SkipTest(NO_TOMLLIB)
    if yaml is None:  # pragma: no cover
        raise unittest.SkipTest('PyYAML, from the test extra, is not installed')
    if not SCRIPT.is_file():
        raise AssertionError(f'{SCRIPT.relative_to(ROOT)} is missing')
    if not _UPDATER:
        spec = importlib.util.spec_from_file_location('update_python_versions', SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        _UPDATER.append(module)
    return _UPDATER[0]


def workflow() -> 'dict[str, Any]':
    return _workflows.load(WORKFLOW)


###############################################################################
# Sources and scratch trees
###############################################################################


def snapshot() -> 'dict[str, Any]':
    """The sources as saved on 2026-10-13, parsed."""
    return copy.deepcopy(updater().parse_sources(updater().read_sources(FIXTURES)))


def without_pypy(sources: 'dict[str, Any]', line: 'str') -> 'dict[str, Any]':
    """PyPy's releases with every one of Python ``line`` (``'3.12'``) removed."""
    sources['pypy'] = [release for release in sources['pypy']
                       if not release['python_version'].startswith(line + '.') and release['python_version'] != line]
    return sources


def as_of_the_file(sources: 'dict[str, Any]') -> 'dict[str, Any]':
    """The snapshot as it stood before PyPy 8.0.0 added 3.12 -- what the file encodes."""
    return without_pypy(sources, '3.12')


def set_status(sources: 'dict[str, Any]', version: 'str', status: 'str') -> 'dict[str, Any]':
    sources['release-cycle'].setdefault(version, {'branch': version})['status'] = status
    return sources


def add_build(sources: 'dict[str, Any]', version: 'str', stable: 'bool',
              targets: 'tuple[tuple[str, Optional[str], str], ...]') -> 'dict[str, Any]':
    """A setup-python release of ``version`` with a build for each ``(platform, platform_version, arch)``."""
    files = []
    for platform, platform_version, arch in targets:
        file = {'filename': f'python-{version}-{platform}-{arch}.tar.gz', 'arch': arch, 'platform': platform}
        if platform_version is not None:
            file['platform_version'] = platform_version
        files.append(file)
    sources['manifest'].insert(0, {'version': version, 'stable': stable, 'files': files})
    return sources


def drop_build(sources: 'dict[str, Any]', minor: 'str', platform_version: 'str') -> 'dict[str, Any]':
    for release in sources['manifest']:
        if release['version'].startswith(minor + '.'):
            release['files'] = [file for file in release['files'] if file.get('platform_version') != platform_version]
    return sources


def drop_image(sources: 'dict[str, Any]', label: 'str') -> 'dict[str, Any]':
    """The runner-images table without the row listing ``label``."""
    sources['runner-images'] = ''.join(line for line in sources['runner-images'].splitlines(True)
                                       if f'`{label}`' not in line)
    return sources


def move_latest(sources: 'dict[str, Any]', image: 'str') -> 'dict[str, Any]':
    """``ubuntu-latest`` moved to the Ubuntu ``image`` (``'26.04'``) row, as on 2026-10-19."""
    lines = []
    for line in sources['runner-images'].splitlines(True):
        line = line.replace('`ubuntu-latest` or ', '')
        if line.startswith(f'| Ubuntu {image}<br>'):
            line = line.replace(f'`ubuntu-{image}`', f'`ubuntu-latest` or `ubuntu-{image}`')
        lines.append(line)
    sources['runner-images'] = ''.join(lines)
    return sources


#: Stable builds of a new CPython for every image ``ubuntu-latest`` may mean, and macOS.
EVERYWHERE = (('linux', '22.04', 'x64'), ('linux', '24.04', 'x64'), ('linux', '26.04', 'x64'),
              ('darwin', None, 'arm64'), ('darwin', None, 'x64'))


def three_eleven_ends_and_three_sixteen_ships(sources: 'dict[str, Any]') -> 'dict[str, Any]':
    """October 2027, roughly: 3.11 end-of-life, 3.16 released and built everywhere."""
    set_status(sources, '3.11', 'end-of-life')
    set_status(sources, '3.16', 'bugfix')
    return add_build(sources, '3.16.0', True, EVERYWHERE)


def frozen() -> 'dict[str, Any]':
    """:data:`FROZEN`, through :func:`python_versions.load`."""
    return updater().validate(FROZEN.read_text(encoding='utf-8'))


def scratch(test: 'unittest.TestCase', regenerate: 'bool' = True) -> 'pathlib.Path':
    """A copy of every file the script reads or writes, with :data:`FROZEN` as the tier file.

    With ``regenerate``, the prose is then rewritten to match :data:`FROZEN`, as a
    run on the snapshot it reproduces would, so it starts from what the
    checkout said on 2026-10-13 whatever the checkout says now.

    """
    tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1660b-')  # pylint: disable=consider-using-with
    test.addCleanup(tmp.cleanup)
    root = pathlib.Path(tmp.name)
    for path in updater().TARGETS + (updater().TEMPLATE,):
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / path, root / path)
    shutil.copytree(ROOT / '.github' / 'workflows', root / '.github' / 'workflows')
    shutil.copyfile(FROZEN, root / updater().TIER_FILE)
    if regenerate:
        plan, texts = updater().compute_plan(root, as_of_the_file(snapshot()))
        test.assertEqual(plan['changes'], [])
        for path, text in texts.items():
            (root / path).write_bytes(text.encode('utf-8'))
    return root


def save_sources(test: 'unittest.TestCase', sources: 'dict[str, Any]') -> 'pathlib.Path':
    """``sources`` written as the files ``update --sources`` reads."""
    tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1660b-sources-')  # pylint: disable=consider-using-with
    test.addCleanup(tmp.cleanup)
    directory = pathlib.Path(tmp.name)
    for name, source in updater().SOURCES.items():
        value = sources[name]
        (directory / source.filename).write_text(value if isinstance(value, str) else json.dumps(value),
                                                 encoding='utf-8')
    return directory


def run_main(root: 'pathlib.Path', argv: 'list[str]', output: 'Optional[pathlib.Path]' = None) -> 'tuple[int, str]':
    """The command line run in this process over ``root``, with its status and stdout."""
    environ = {key: value for key, value in os.environ.items() if key not in ('GITHUB_OUTPUT', 'GITHUB_STEP_SUMMARY')}
    if output is not None:
        environ['GITHUB_OUTPUT'] = str(output)
    stdout = io.StringIO()
    with mock.patch.dict(os.environ, environ, clear=True), contextlib.redirect_stdout(stdout):
        status = updater().main(argv, root=root)
    return status, stdout.getvalue()


def plan_for(test: 'unittest.TestCase', sources: 'dict[str, Any]',
             write: 'bool' = False) -> 'tuple[pathlib.Path, dict[str, Any], dict[str, str]]':
    root = scratch(test)
    plan, texts = updater().compute_plan(root, sources)
    if write:
        for path, text in texts.items():
            (root / path).write_bytes(text.encode('utf-8'))
    return root, plan, texts


def changes(plan: 'dict[str, Any]') -> 'dict[str, tuple[Any, Any]]':
    return {change['version']: (change['before'], change['after']) for change in plan['changes']}


def notes(plan: 'dict[str, Any]', kind: 'str') -> 'list[str]':
    return [note['text'] for note in plan['notes'] if note['kind'] == kind]


def context(sources: 'dict[str, Any]') -> 'Any':
    """The rules' :class:`Context` for ``sources``, with the labels the real workflows use."""
    module = updater()
    return module.Context(sources, module.parse_images(sources['runner-images']),
                          module.workflow_labels(module.load_workflows(ROOT)))


###############################################################################
# Fetching
###############################################################################


#: Where the stubbed source points: a reserved name, so nothing it reaches answers.
INVALID_URL = 'https://example.invalid/release-cycle.json'


def http_response(status: 'int', body: 'bytes' = b'') -> 'requests.Response':
    """A :class:`requests.Response` as ``requests.get`` returns it."""
    response = requests.Response()
    response.status_code = status
    response.url = INVALID_URL
    response.raw = io.BytesIO(body)
    return response


class TestFetch(unittest.TestCase):
    """#1894: :func:`fetch` reads each source through ``requests.get``."""

    def setUp(self) -> None:
        self.module = updater()
        self.sleeps = []  # type: list[float]
        self.calls = []  # type: list[tuple[str, dict[str, Any]]]
        self.outcomes = []  # type: list[Any]
        source = self.module.Source(INVALID_URL, 'release-cycle.json', 'json')
        for patcher in (mock.patch.dict(self.module.SOURCES, {'release-cycle': source}),
                        mock.patch.object(self.module, 'time', types.SimpleNamespace(sleep=self.sleeps.append)),
                        mock.patch('requests.get', self.get)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def get(self, url: 'str', **kwargs: 'Any') -> 'requests.Response':
        self.calls.append((url, kwargs))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def test_a_source_is_read_with_requests(self) -> None:
        self.outcomes = [http_response(200, '{"3.15": {"status": "bugfix"}}'.encode('utf-8'))]
        self.assertEqual(self.module.fetch('release-cycle'), '{"3.15": {"status": "bugfix"}}')
        self.assertEqual(self.calls, [(INVALID_URL, {
            'timeout': 60, 'headers': {'User-Agent': 'PyPCAPKit cron-python-versions (#1660)'}})])
        self.assertEqual(self.sleeps, [])

    def test_an_error_status_and_a_dropped_connection_are_retried(self) -> None:
        self.outcomes = [http_response(503), requests.ConnectionError('connection reset'),
                         http_response(200, b'{}')]
        self.assertEqual(self.module.fetch('release-cycle'), '{}')
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(self.sleeps, [5, 10])

    def test_the_last_failure_is_an_oserror_naming_the_source(self) -> None:
        """``main`` reports an :exc:`OSError` as the run's error, as it did before."""
        self.outcomes = [http_response(404)] * 3
        with self.assertRaises(OSError) as caught:
            self.module.fetch('release-cycle')
        self.assertTrue(str(caught.exception).startswith(f'{INVALID_URL}: 404 Client Error'), caught.exception)
        self.assertIsInstance(caught.exception.__cause__, requests.HTTPError)
        self.assertEqual(self.sleeps, [5, 10])

    def test_loading_the_script_imports_neither_requests_nor_markdown_it(self) -> None:
        """``pr`` runs ``publish`` on a bare ``python3``, so loading the script must not need them."""
        imported = "print(sorted({'requests', 'markdown_it'} & set(sys.modules)))\n"
        script = (
            'import importlib.util, pathlib, sys\n'
            + imported
            + f'spec = importlib.util.spec_from_file_location("update_python_versions", {str(SCRIPT)!r})\n'
            'module = importlib.util.module_from_spec(spec)\n'
            'spec.loader.exec_module(module)\n'
            f'module.read_sources(pathlib.Path({str(FIXTURES)!r}))\n'
            + imported
        )
        result = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True, check=False,
                                timeout=scale_timeout(60))
        # Not imported at startup either, or the second answer would prove nothing.
        self.assertEqual((result.returncode, result.stdout), (0, '[]\n[]\n'), result.stderr)


#: The runner-images table's header and delimiter rows, as the README has them.
TABLE_HEAD = ('| Image | Architecture | YAML Label | Included Software |\n'
              '| --------------------|--------------|---------------------|------------------|\n')


class TestTheImageTable(unittest.TestCase):
    """#1894: the runner-images table is read as GitHub renders it, by markdown-it-py."""

    def test_an_escaped_pipe_stays_in_its_cell(self) -> None:
        """In a cell's text or in a code span; splitting the line on ``|`` shifted every column after it."""
        module = updater()
        text = TABLE_HEAD + (
            '| Ubuntu 24.04 \\| Noble<br>![Endpoint Badge](https://example.invalid/badge) | x64 '
            '| `ubuntu-latest` or `ubuntu-24.04` | [ubuntu-24.04] |\n'
            '| Ubuntu 22.04 | x64 | `ubuntu-22.04` or `ubuntu\\|22.04` | [ubuntu-22.04] |\n'
            '| macOS 15 Arm64 | arm64 | `macos-15`, or `macos-15-xlarge` | [macOS-15-arm64] |\n')
        self.assertEqual(module.parse_images(text), [
            module.Image('ubuntu', '24.04', 'x64', ('ubuntu-latest', 'ubuntu-24.04')),
            module.Image('ubuntu', '22.04', 'x64', ('ubuntu-22.04', 'ubuntu|22.04')),
            module.Image('macos', '15', 'arm64', ('macos-15', 'macos-15-xlarge')),
        ])

    def test_a_line_of_prose_with_a_pipe_is_not_the_table(self) -> None:
        """Only a table's header row names its columns, not any line that starts with ``|``."""
        module = updater()
        text = ('| The YAML Label column below is what `runs-on` takes.\n\n'
                + TABLE_HEAD + '| Ubuntu 24.04 | x64 | `ubuntu-24.04` | [ubuntu-24.04] |\n')
        self.assertEqual(module.parse_images(text), [module.Image('ubuntu', '24.04', 'x64', ('ubuntu-24.04',))])

    def test_what_it_refuses(self) -> None:
        """The same errors as before markdown-it-py read the table."""
        module = updater()
        cases = (
            ('no table', 'Images: `ubuntu-24.04`.\n', 'has no table with a "YAML Label" column'),
            ('no Architecture column', '| Image | YAML Label |\n| --- | --- |\n| Ubuntu 24.04 | `ubuntu-24.04` |\n',
             r"has columns \['Image', 'YAML Label'\]"),
            ('no Ubuntu image', TABLE_HEAD + '| macOS 15 | arm64 | `macos-15` | [macOS-15] |\n', 'lists no Ubuntu image'),
        )
        for label, text, message in cases:
            with self.subTest(label):
                with self.assertRaisesRegex(ValueError, message):
                    module.parse_images(text)


###############################################################################
# The tiers
###############################################################################


class TestTheTiers(unittest.TestCase):
    """The rules, each against the snapshot and an edit of it."""

    def test_the_labels_come_from_the_workflows(self) -> None:
        """``matrix.os || 'ubuntu-latest'``; the conda jobs' ``os`` axis; where ``latest`` is installed."""
        found = context(snapshot()).labels
        self.assertEqual(found, {'default': ['ubuntu-latest'],
                                 # #2060: Conda Update's windows-latest leg.
                                 'supported': ['macos-26-intel', 'macos-latest', 'ubuntu-latest', 'windows-latest'],
                                 'latest': ['macos-latest', 'ubuntu-latest']})

    def test_ubuntu_latest_counts_as_its_image_and_every_newer_one(self) -> None:
        module = updater()
        images = module.parse_images(snapshot()['runner-images'])
        self.assertEqual(module.label_targets('ubuntu-latest', images),
                         [module.Target('linux', '24.04', 'x64'), module.Target('linux', '26.04', 'x64')])
        self.assertEqual(module.label_targets('ubuntu-24.04', images), [module.Target('linux', '24.04', 'x64')])
        self.assertEqual(module.label_targets('macos-latest', images), [module.Target('darwin', None, 'arm64')])
        # #2060: the Windows Server image; the Arm64 Windows 11 one is no newer x64 image.
        self.assertEqual(module.label_targets('windows-latest', images), [module.Target('win32', None, 'x64')])
        moved = module.parse_images(move_latest(snapshot(), '26.04')['runner-images'])
        self.assertEqual(module.label_targets('ubuntu-latest', moved), [module.Target('linux', '26.04', 'x64')])
        with self.assertRaisesRegex(ValueError, 'does not list'):
            module.label_targets('ubuntu-20.04', images)

    def test_the_snapshot_reproduces_the_file_but_for_pypy_312(self) -> None:
        """PyPy 8.0.0 (2026-09-19) ships 3.11 and 3.12: the first run proposes pypy3.12."""
        _, plan, texts = plan_for(self, snapshot())
        self.assertEqual(changes(plan), {'pypy3.12': (None, {'tier': 'supported'})})
        self.assertEqual(plan['latest'], ['3.15', '3.15'])
        # Only the tier file: releasing.rst counted the wheels until #1811, so a new PyPy rewrote it.
        self.assertEqual(sorted(texts), ['.github/python-versions.toml'])
        self.assertEqual(plan['required'], {'remove': [], 'add': []})
        # #1958: a supported PyPy gets a `test` and an `integration` leg too.
        self.assertEqual(plan['added'], ['PyPI distribution for Python pypy3.12',
                                         'Integration Python pypy3.12', 'Python pypy3.12'])

    def test_as_of_the_file_nothing_changes(self) -> None:
        """Before PyPy 8.0.0, the sources gave the tier file exactly as #1677 wrote it."""
        plan, _ = updater().compute_plan(scratch(self, regenerate=False), as_of_the_file(snapshot()))
        self.assertEqual((plan['changes'], plan['latest'], plan['notes']), ([], ['3.15', '3.15'], []))
        _, plan, texts = plan_for(self, as_of_the_file(snapshot()))
        self.assertEqual((plan['changes'], texts, plan['notes']), ([], {}, []))

    def test_security_to_end_of_life_is_ktlo_on_ubuntu_latest(self) -> None:
        """3.11 has a 26.04 build, so its KTLO legs need no ``runner``; its Compat leg leaves the ruleset."""
        _, plan, _ = plan_for(self, set_status(as_of_the_file(snapshot()), '3.11', 'end-of-life'))
        self.assertEqual(changes(plan), {'3.11': ({'tier': 'supported'}, {'tier': 'ktlo'})})
        self.assertEqual(plan['required'], {'remove': ['Compat Python 3.11'], 'add': []})
        for old in ('Python 3.11', 'Integration Python 3.11', 'Compat Python 3.11',
                    'PyPCAP/PyPCAPFile parity Python 3.11', 'PyPI distribution for Python 3.11'):
            with self.subTest(leg=old):
                self.assertIn([old, f'{old} (KTLO)'], plan['renamed'])
        self.assertIn('Conda deployment (release) on macos-latest with Python 3.11', plan['removed'])
        self.assertTrue(any('ktlo_311' in text for text in notes(plan, 'manual')), plan['notes'])

    def test_end_of_life_with_no_build_left_is_dropped(self) -> None:
        """ubuntu-22.04 retires (2027-04-17): 3.7, whose newest build is for it, leaves the matrices."""
        _, plan, texts = plan_for(self, drop_image(as_of_the_file(snapshot()), 'ubuntu-22.04'))
        self.assertEqual(changes(plan), {'3.7': ({'tier': 'ktlo', 'runner': 'ubuntu-22.04'}, None)})
        self.assertIn('no hosted Ubuntu image', plan['changes'][0]['reason'])
        self.assertIn('Python 3.7 (KTLO)', plan['removed'])
        self.assertNotIn('"3.7"', texts['.github/python-versions.toml'])

    def test_a_version_dropped_from_the_middle_leaves_the_ranges_for_a_hand_edit(self) -> None:
        """3.7's image retires and 3.9 has no build left: "3.8 to 3.10" would say 3.9 is still tested."""
        sources = drop_image(as_of_the_file(snapshot()), 'ubuntu-22.04')
        for image in ('22.04', '24.04', '26.04'):
            drop_build(sources, '3.9', image)
        root, plan, texts = plan_for(self, sources)
        self.assertEqual(changes(plan), {'3.7': ({'tier': 'ktlo', 'runner': 'ubuntu-22.04'}, None),
                                         '3.9': ({'tier': 'ktlo', 'runner': 'ubuntu-24.04'}, None)})
        self.assertIn('README.md: `tests the end-of-life (3\\.\\d+) to (3\\.\\d+)` cannot state a tier that is empty '
                      'or has a gap', notes(plan, 'manual'))
        for path, text in texts.items():
            with self.subTest(path=path):
                self.assertNotRegex(text, r'3\.8 (?:to|through) 3\.10|3\.8-3\.10')
        # Spanned anyway, the prose reads true to the audit's ends; the gap is what fails it.
        with mock.patch.object(updater(), 'span', lambda tier: (tier[0], tier[-1]) if tier else None):
            root, _, texts = plan_for(self, sources)
        self.assertIn('3.8 to 3.10', texts['README.md'])
        for path, text in texts.items():
            (root / path).write_text(text, encoding='utf-8')
        result = run_prose_audit(root)
        failed = {getattr(test, 'test_case', test)._testMethodName  # pylint: disable=protected-access
                  for test, _ in result.failures + result.errors}
        self.assertEqual(failed, {'test_each_tier_range_names_the_files_tier'})

    def test_a_runner_is_the_newest_image_with_a_build(self) -> None:
        sources = drop_build(as_of_the_file(snapshot()), '3.10', '26.04')
        _, plan, texts = plan_for(self, sources)
        self.assertEqual(changes(plan), {'3.10': ({'tier': 'ktlo'}, {'tier': 'ktlo', 'runner': 'ubuntu-24.04'})})
        self.assertIn('"3.10" = { tier = "ktlo", runner = "ubuntu-24.04" }\n', texts['.github/python-versions.toml'])
        self.assertEqual((plan['renamed'], plan['required']), ([], {'remove': [], 'add': []}))

    def test_ubuntu_latest_moving_to_2604_changes_nothing(self) -> None:
        """The file already pins 3.8 and 3.9 to 24.04 for the move on 2026-10-19."""
        _, plan, texts = plan_for(self, move_latest(as_of_the_file(snapshot()), '26.04'))
        self.assertEqual((plan['changes'], texts), ([], {}))

    def test_a_feature_branch_without_a_build_is_not_listed(self) -> None:
        sources = as_of_the_file(snapshot())
        self.assertEqual(sources['release-cycle']['3.16']['status'], 'feature')
        result = updater().compute_cpython(frozen()['versions']['cpython'], context(sources))
        self.assertNotIn('3.16', result.entries)
        _, plan, _ = plan_for(self, sources)
        self.assertEqual(notes(plan, 'held'), [])

    def test_a_prerelease_with_a_build_is_held_back(self) -> None:
        """The tier :func:`python_versions.load` refuses, until a workflow runs pre-release legs."""
        sources = add_build(as_of_the_file(snapshot()), '3.16.0-alpha.1', False,
                            (('linux', '24.04', 'x64'), ('linux', '26.04', 'x64')))
        result = updater().compute_cpython(frozen()['versions']['cpython'], context(sources))
        self.assertEqual(result.entries['3.16'], {'tier': 'pre-release'})
        _, plan, texts = plan_for(self, sources)
        self.assertEqual((plan['changes'], texts), ([], {}))
        self.assertEqual(len(notes(plan, 'held')), 1)
        self.assertIn('3.16', notes(plan, 'held')[0])
        self.assertEqual(updater().HELD, ('pre-release',))
        listed = FROZEN.read_text(encoding='utf-8').replace(
            '"3.15" = { tier = "supported" }\n', '"3.15" = { tier = "supported" }\n"3.16" = { tier = "pre-release" }\n')
        with self.assertRaisesRegex(ValueError, 'no workflow runs pre-release legs'):
            updater().validate(listed)

    def test_latest_moves_to_the_newest_bugfix_branch(self) -> None:
        _, plan, texts = plan_for(self, three_eleven_ends_and_three_sixteen_ships(as_of_the_file(snapshot())))
        self.assertEqual(plan['latest'], ['3.15', '3.16'])
        self.assertEqual(changes(plan), {'3.11': ({'tier': 'supported'}, {'tier': 'ktlo'}),
                                         '3.16': (None, {'tier': 'supported'})})
        self.assertEqual(plan['required'], {'remove': ['Compat Python 3.11'], 'add': ['Compat Python 3.16']})
        self.assertIn('Compat Python 3.16', plan['added'])
        self.assertIn('latest moves to 3.16', plan['title'])
        self.assertIn('latest = "3.16"\n', texts['.github/python-versions.toml'])

    def test_latest_stays_while_the_newest_bugfix_branch_lacks_a_macos_build(self) -> None:
        sources = set_status(as_of_the_file(snapshot()), '3.16', 'bugfix')
        add_build(sources, '3.16.0', True, EVERYWHERE[:3])
        _, plan, _ = plan_for(self, sources)
        self.assertEqual(plan['latest'], ['3.15', '3.15'])
        self.assertEqual(changes(plan), {'3.16': (None, {'tier': 'supported'})})
        self.assertTrue(any('`latest` stays older' in text for text in notes(plan, 'warning')), plan['notes'])
        self.assertTrue(any('supported 3.16' in text and 'darwin arm64' in text
                            for text in notes(plan, 'warning')), plan['notes'])

    def test_pypy_follows_its_newest_stable_release(self) -> None:
        """A line the newest release drops is KTLO; one only in a numbered pre-release is held; a nightly is not."""
        sources = snapshot()
        sources['pypy'] = [release for release in sources['pypy']
                           if not (release['pypy_version'] == '8.0.0' and release['python_version'].startswith('3.11'))]
        linux = [{'filename': 'pypy.tar.bz2', 'arch': 'x64', 'platform': 'linux'}]
        sources['pypy'] += [{'pypy_version': '8.1.0rc1', 'python_version': '3.13.1', 'stable': False, 'files': linux},
                            {'pypy_version': 'nightly', 'python_version': '3.14', 'stable': False, 'files': linux}]
        result = updater().compute_pypy(frozen()['versions']['pypy'], context(sources))
        self.assertEqual(result.entries, {'pypy3.10': {'tier': 'ktlo'}, 'pypy3.11': {'tier': 'ktlo'},
                                          'pypy3.12': {'tier': 'supported'}, 'pypy3.13': {'tier': 'pre-release'}})
        self.assertEqual(result.reasons['pypy3.11'], 'not in PyPy 8.0.0; its newest stable build is PyPy 7.3.23')
        _, plan, _ = plan_for(self, sources)
        self.assertEqual(changes(plan), {'pypy3.11': ({'tier': 'supported'}, {'tier': 'ktlo'}),
                                         'pypy3.12': (None, {'tier': 'supported'})})
        self.assertIn(['PyPI distribution for Python pypy3.11', 'PyPI distribution for Python pypy3.11 (KTLO)'],
                      plan['renamed'])
        self.assertEqual(len(notes(plan, 'held')), 1)

    def test_an_end_of_life_version_the_file_does_not_list_is_not_added(self) -> None:
        """3.6 and older are end-of-life; 3.6's builds are for retired images, 3.5's too."""
        sources = add_build(as_of_the_file(snapshot()), '3.6.15', True, (('linux', '24.04', 'x64'),))
        result = updater().compute_cpython(frozen()['versions']['cpython'], context(sources))
        self.assertNotIn('3.6', result.entries)
        self.assertNotIn('3.5', result.entries)

    def test_a_dropped_version_with_builds_left_is_not_re_added(self) -> None:
        """#2051 dropped 3.7 by hand, below ``requires-python``, while setup-python still builds it."""
        sources = add_build(as_of_the_file(snapshot()), '3.7.17', True, (('linux', '24.04', 'x64'),))
        current = {version: entry for version, entry in frozen()['versions']['cpython'].items()
                   if version != '3.7'}
        result = updater().compute_cpython(current, context(sources))
        self.assertNotIn('3.7', result.entries)
        self.assertIn('3.8', result.entries)

    def test_each_implementation_is_one_entry(self) -> None:
        """Another implementation is one more source and entry here, and its spelling in python_versions.py.

        Bar GraalPy, which is experimental only (#1660): no source here rates it.

        """
        module = updater()
        self.assertEqual(set(module.IMPLEMENTATIONS), set(module.pv.SPELLING) - {'graalpy'})
        self.assertTrue(module.pv.experimental_only('graalpy', 'graalpy-25.4'))
        for name, implementation in module.IMPLEMENTATIONS.items():
            with self.subTest(implementation=name):
                self.assertLessEqual(set(implementation.sources), set(module.SOURCES))
        self.assertEqual({name: source.filename for name, source in module.SOURCES.items()},
                         {name: source.filename for name, source in module.SOURCES.items()
                          if (FIXTURES / source.filename).is_file()})
        self.assertEqual({source.url for source in module.SOURCES.values()}, {
            'https://peps.python.org/api/release-cycle.json',
            'https://downloads.python.org/pypy/versions.json',
            'https://raw.githubusercontent.com/actions/python-versions/main/versions-manifest.json',
            'https://raw.githubusercontent.com/actions/runner-images/main/README.md',
        })


###############################################################################
# The rewrite
###############################################################################


class TestTheRewrite(unittest.TestCase):
    """The tier file keeps its comments and layout; the prose follows it; nothing else moves."""

    def test_an_unchanged_tier_file_renders_byte_for_byte(self) -> None:
        """The checkout's tier file, and :data:`FROZEN`."""
        module = updater()
        for path in (ROOT / module.TIER_FILE, FROZEN):
            text = path.read_bytes().decode('utf-8')
            data = module.validate(text)
            with self.subTest(path=path.name):
                self.assertEqual(module.render_tier_file(text, data['latest'], data['versions']), text)

    def test_a_no_change_run_writes_nothing(self) -> None:
        """The whole command, ``--write`` and ``--out`` included, over a scratch tree."""
        root = scratch(self)
        before = {path: (root / path).read_bytes() for path in updater().TARGETS}
        sources = save_sources(self, as_of_the_file(snapshot()))
        out, output = root / 'proposal', root / 'github-output'
        status, printed = run_main(root, ['update', '--sources', str(sources), '--write', '--out', str(out),
                                          '--github-output'], output)
        self.assertEqual(status, 0, printed)
        self.assertEqual({path: (root / path).read_bytes() for path in updater().TARGETS}, before)
        self.assertEqual(json.loads((out / 'plan.json').read_text(encoding='utf-8'))['changed_files'], [])
        self.assertFalse((out / 'files').exists())
        self.assertIn('changed=false\npublish=false\n', output.read_text(encoding='utf-8'))

    def test_a_second_run_after_a_change_writes_nothing(self) -> None:
        sources = three_eleven_ends_and_three_sixteen_ships(snapshot())
        root, plan, _ = plan_for(self, sources, write=True)
        self.assertTrue(plan['changed_files'])
        again, texts = updater().compute_plan(root, sources)
        self.assertEqual((again['changes'], texts), ([], {}))

    def test_comments_exemptions_and_layout_survive_a_change(self) -> None:
        _, _, texts = plan_for(self, three_eleven_ends_and_three_sixteen_ships(snapshot()))
        old = FROZEN.read_text(encoding='utf-8').splitlines()
        new = texts['.github/python-versions.toml'].splitlines()
        entry = updater().ENTRY
        self.assertEqual([line for line in new if not entry.match(line) and not line.startswith('latest = ')],
                         [line for line in old if not entry.match(line) and not line.startswith('latest = ')])
        self.assertEqual([line for line in new if entry.match(line)], [
            '"3.7" = { tier = "ktlo", runner = "ubuntu-22.04" }',
            '"3.8" = { tier = "ktlo", runner = "ubuntu-24.04" }',
            '"3.9" = { tier = "ktlo", runner = "ubuntu-24.04" }',
            '"3.10" = { tier = "ktlo" }',
            '"3.11" = { tier = "ktlo" }',
            '"3.12" = { tier = "supported" }',
            '"3.13" = { tier = "supported" }',
            '"3.14" = { tier = "supported" }',
            '"3.15" = { tier = "supported" }',
            '"3.16" = { tier = "supported" }',
            '"pypy3.10" = { tier = "ktlo" }',
            '"pypy3.11" = { tier = "supported" }',
            '"pypy3.12" = { tier = "supported" }',
        ])
        self.assertEqual(updater().validate(texts['.github/python-versions.toml'])['exemptions'],
                         frozen()['exemptions'])

    def test_an_inline_comment_on_a_changed_entry_is_kept(self) -> None:
        module = updater()
        text = FROZEN.read_text(encoding='utf-8').replace(
            '"3.11" = { tier = "supported" }', '"3.11" = { tier = "supported" }  # until 2027-10')
        data = frozen()
        versions = copy.deepcopy(data['versions'])
        versions['cpython']['3.11'] = {'tier': 'ktlo'}
        self.assertIn('"3.11" = { tier = "ktlo" }  # until 2027-10\n',
                      module.render_tier_file(text, data['latest'], versions))

    def test_the_regenerated_tree_passes_the_audit(self) -> None:
        """The prose the audit pins, against the scratch tree, before and after the prose is rewritten.

        With only the tier file moved, the audit fails, so it reads the scratch
        tree; with everything the script writes, it passes.
        """
        sources = three_eleven_ends_and_three_sixteen_ships(snapshot())
        root, plan, texts = plan_for(self, sources)
        tier_file = root / '.github' / 'python-versions.toml'
        tier_file.write_text(texts['.github/python-versions.toml'], encoding='utf-8')
        stale = run_prose_audit(root)
        self.assertFalse(stale.wasSuccessful(), 'the audit does not read the scratch tree')
        for path, text in texts.items():
            (root / path).write_text(text, encoding='utf-8')
        result = run_prose_audit(root)
        self.assertEqual(result.testsRun, stale.testsRun)
        self.assertTrue(result.wasSuccessful(),
                        '\n'.join(text for _, text in result.failures + result.errors))
        # #1747: and `pypcap-parity`, which 3.11 leaving empties, for the owner to retire.
        self.assertEqual([note for note in notes(plan, 'manual')
                          if 'ktlo_311' not in note and note not in plan['retire']], [])

    def test_every_claim_and_rewriter_matches_once_on_main(self) -> None:
        """So a reworded sentence fails here, not as a silent skip in a weekly run."""
        module = updater()
        workflows = module.load_workflows(ROOT)
        data = module.pv.load()
        values = module.pv.outputs(data)
        facts = module.make_facts(data, values, workflows, (ROOT / module.TIER_FILE).read_text(encoding='utf-8'))
        for path in module.TARGETS:
            if path == module.TIER_FILE:
                continue
            text = (ROOT / path).read_text(encoding='utf-8')
            with self.subTest(path=path):
                rewritten, problems = module.apply_claims(text, module.CLAIMS.get(path, ()), facts)
                for rewrite in module.REWRITERS.get(path, ()):
                    rewritten, more = rewrite(rewritten, facts)
                    problems += more
                self.assertEqual(problems, [])
                self.assertEqual(rewritten, text)

    def test_a_claim_rewrites_each_group_and_never_spans_a_break(self) -> None:
        """#1811 retired the count claims and their spelt-out words; a claim states versions and lines."""
        module = updater()
        claim = module.Claim(r'(3\.\d+) to (3\.\d+)', lambda facts: ('3.12', '3.16'))
        self.assertEqual(module.apply_claims('Tests 3.11 to 3.15.', [claim], {}), ('Tests 3.12 to 3.16.', []))
        self.assertEqual(module.apply_claims('# tests 3.11 to\n# 3.15', [claim], {}), ('# tests 3.12 to\n# 3.16', []))
        broken = module.Claim(r'(to 3\.\d+)', lambda facts: ('x',))
        self.assertEqual(module.apply_claims('to\n3.15', [broken], {})[1], [
            '`(to 3\\.\\d+)` group 1 spans a line break'])
        self.assertEqual(module.apply_claims('none', [claim], {})[1], ['`(3\\.\\d+) to (3\\.\\d+)` matches 0 times'])
        self.assertFalse(hasattr(module, 'Word'), 'a count claim is back; #1103 rules counts out of the prose')

    def test_no_file_under_workflows_is_written_or_restates_a_tier(self) -> None:
        """An App token needs ``workflows: write`` to push a workflow change, and ``pr``'s has none.

        So the script writes no workflow, :func:`publish` refuses one, and the
        workflow comments that restated the tiers before Part B now name them;
        a restatement coming back would go stale on the first tier move.
        """
        module = updater()
        self.assertFalse([path for path in module.TARGETS if path.startswith('.github/workflows/')])
        with self.assertRaisesRegex(ValueError, 'not a file this script writes'):
            module.check_targets(['.github/workflows/unit-tests.yml'])
        with self.assertRaisesRegex(ValueError, 'not a file this script writes'):
            module.check_targets(['setup.py'])
        restated = re.compile('|'.join((
            r'sweep\s+3\.\d+-3\.\d+', r'KTLO legs 3\.\d+-3\.\d+', r"`test` job's Python 3\.\d+ leg",
            r'\(unit tier, Python 3\.\d+,', r'keeps only on the 3\.\d+ leg', r'against the \d+ expected',
            r'\d+-leg ``conda`` matrix', r'only \d+ of \d+ legs', r'\w+ for `Compat Python 3\.\d+`-`3\.\d+`',
            r'requires (?:one|two|three|four|five|six|seven|eight|nine|ten) contexts',
        )))
        for path in sorted((ROOT / '.github' / 'workflows').glob('*.yml')):
            view, _ = module.prose_view(path.read_text(encoding='utf-8'))
            with self.subTest(workflow=path.name):
                self.assertEqual([match.group(0) for match in restated.finditer(view)], [])


#: :data:`FROZEN` with one experimental build of each kind (#1660), the CPython one
#: carrying an inline comment, so "as written" is checked byte for byte.
FREE_THREADED = '"3.14t" = { tier = "experimental" }  # free-threaded, hand-kept\n'
GRAALPY = '\n# GraalPy, hand-kept.\n[versions.graalpy]\n"graalpy-25.4" = { tier = "experimental" }\n'


def with_experimental(text: 'str') -> 'str':
    """A tier file's text with :data:`FREE_THREADED` after CPython's last line and :data:`GRAALPY` after PyPy's."""
    for anchor, added in (('"3.15" = { tier = "supported" }\n', FREE_THREADED),
                          ('"pypy3.11" = { tier = "supported" }\n', GRAALPY)):
        if text.count(anchor) != 1:
            raise AssertionError(f'{anchor!r} is not one line of the tier file')
        text = text.replace(anchor, anchor + added)
    return text


class TestTheExperimentalEntriesAreHandKept(unittest.TestCase):
    """#1660: no source rates free-threaded CPython or GraalPy, so every recompute keeps them as written."""

    def scratch(self) -> 'pathlib.Path':
        """:func:`scratch` with :func:`with_experimental` applied to :data:`FROZEN`, the prose regenerated."""
        root = scratch(self, regenerate=False)
        tier_file = root / updater().TIER_FILE
        tier_file.write_text(with_experimental(FROZEN.read_text(encoding='utf-8')), encoding='utf-8')
        plan, texts = updater().compute_plan(root, as_of_the_file(snapshot()))
        self.assertEqual(plan['changes'], [])
        self.assertNotIn(updater().TIER_FILE, texts)
        for path, text in texts.items():
            (root / path).write_bytes(text.encode('utf-8'))
        return root

    def test_a_run_that_changes_nothing_writes_nothing(self) -> None:
        root = self.scratch()
        plan, texts = updater().compute_plan(root, as_of_the_file(snapshot()))
        self.assertEqual((plan['changes'], texts, plan['notes']), ([], {}, []))
        # The leg counts this read back went with #1811; the fact behind them is
        # that the hand-kept entries are experimental.yml's legs and no Unit Tests job's.
        module = updater()
        values = module.pv.outputs(module.validate((root / module.TIER_FILE).read_text(encoding='utf-8')))
        found = {job: {leg.get('python-version') for leg in legs}
                 for job, legs in module.matrix_legs(module.load_workflows(root), values).items()}
        hand_kept = {'3.14t', 'graalpy-25.4'}
        self.assertEqual(found[('experimental.yml', 'experimental')], hand_kept)
        self.assertEqual({job: versions & hand_kept for job, versions in found.items()
                          if job[0] == 'unit-tests.yml' and versions & hand_kept}, {})

    def test_a_tier_move_keeps_them_byte_for_byte_after_the_computed_versions(self) -> None:
        root = self.scratch()
        before = (root / updater().TIER_FILE).read_text(encoding='utf-8')
        plan, texts = updater().compute_plan(root, three_eleven_ends_and_three_sixteen_ships(snapshot()))
        self.assertEqual(changes(plan), {'3.11': ({'tier': 'supported'}, {'tier': 'ktlo'}),
                                         '3.16': (None, {'tier': 'supported'}),
                                         'pypy3.12': (None, {'tier': 'supported'})})
        after = texts[updater().TIER_FILE]
        self.assertIn('"3.16" = { tier = "supported" }\n' + FREE_THREADED, after)
        self.assertIn('"pypy3.12" = { tier = "supported" }\n' + GRAALPY, after)
        self.assertEqual(after.replace('"3.16" = { tier = "supported" }\n', '').replace(
            '"pypy3.12" = { tier = "supported" }\n', '').replace(
            '"3.11" = { tier = "ktlo" }', '"3.11" = { tier = "supported" }').replace(
            'latest = "3.16"', 'latest = "3.15"'), before)
        self.assertEqual(updater().validate(after)['versions']['graalpy'], {'graalpy-25.4': {'tier': 'experimental'}})
        self.assertFalse([name for name in plan['added'] + plan['removed'] + sum(plan['renamed'], [])
                          if 'experimental' in name], plan)

    def test_a_hand_edit_to_one_is_not_a_new_proposal(self) -> None:
        """The fingerprint is the computed tiers', so an open proposal stays recognised across one."""
        module = updater()
        data = frozen()
        edited = module.validate(with_experimental(FROZEN.read_text(encoding='utf-8')))
        self.assertNotEqual(edited['versions'], data['versions'])
        self.assertEqual(module.fingerprint(edited['latest'], edited['versions']),
                         module.fingerprint(data['latest'], data['versions']))
        moved = copy.deepcopy(edited['versions'])
        moved['cpython']['3.11'] = {'tier': 'ktlo'}
        self.assertNotEqual(module.fingerprint(edited['latest'], moved),
                            module.fingerprint(edited['latest'], edited['versions']))
        _, plain, _ = plan_for(self, snapshot())
        plan, _ = module.compute_plan(self.scratch(), snapshot())
        self.assertEqual(plan['fingerprint'], plain['fingerprint'])

    def test_no_experimental_leg_is_proposed_as_a_required_context(self) -> None:
        """Were one ever given a ``Compat`` leg, the ruleset edit the body lists would still leave it out."""
        module = updater()
        workflows = module.load_workflows(ROOT)
        values = module.pv.outputs(frozen())
        compatibility = json.loads(values['compatibility'])
        compatibility['include'].append({'python-version': '3.14t', 'experimental': True})
        widened = dict(values, compatibility=json.dumps(compatibility))
        self.assertIn('3.14t', [leg['python-version'] for leg in
                                module.matrix_legs(workflows, widened)[module.REQUIRED_JOB]])
        self.assertEqual(module.required_contexts(workflows, widened), module.required_contexts(workflows, values))


def run_prose_audit(root: 'pathlib.Path') -> 'unittest.TestResult':
    """The audit's prose class, reading ``root`` instead of the checkout.

    The prose the script rewrites is what :class:`TestTheProseFollowsTheFile` reads;
    the leg-count check :mod:`tests.project.test_python_matrix_tiers_1633` added to
    it went with the counts (#1811).

    """
    # pylint: disable=import-outside-toplevel
    from tests.project import test_python_versions_1660 as versions

    script = versions.script()
    original = script.load
    tier_file = root / '.github' / 'python-versions.toml'
    suite = unittest.TestSuite()
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(versions.TestTheProseFollowsTheFile))
    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.object(versions, 'ROOT', root))
        stack.enter_context(mock.patch.object(versions, 'WORKFLOWS', root / '.github' / 'workflows'))
        stack.enter_context(mock.patch.object(versions, 'TIER_FILE', tier_file))
        stack.enter_context(mock.patch.object(script, 'load', lambda path=tier_file: original(path)))
        return unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)


###############################################################################
# The pull request body
###############################################################################


#: Two lines of ``python -m unittest -v`` output for a failed and an errored test.
AUDIT_LOG = '''\
test_x (tests.project.test_python_matrix_tiers_1633.TestPython37IsKTLO.test_x) ... FAIL
======================================================================
FAIL: test_x (tests.project.test_python_matrix_tiers_1633.TestPython37IsKTLO.test_x)
----------------------------------------------------------------------
ERROR: test_y (tests.project.test_ktlo_legs_stay_green_1672.TestAKTLOFailureIsAWarning.test_y)
'''


class TestThePullRequestBody(unittest.TestCase):
    """The repository's template, ``ci`` ticked, the moves, the ruleset edits, the renames, the audit."""

    def test_the_body_lists_what_the_owner_does_by_hand(self) -> None:
        module = updater()
        _, plan, _ = plan_for(self, set_status(as_of_the_file(snapshot()), '3.11', 'end-of-life'))
        failures = module.audit_failures(AUDIT_LOG)
        self.assertEqual(failures, ['tests.project.test_python_matrix_tiers_1633.TestPython37IsKTLO.test_x',
                                    'tests.project.test_ktlo_legs_stay_green_1672.TestAKTLOFailureIsAWarning.test_y'])
        description = module.describe_plan(plan, ('failure', failures), 'https://example.invalid/run')
        body = module.fill_template((ROOT / module.TEMPLATE).read_text(encoding='utf-8'), description, 'failure')
        self.assertIn('- [x] `ci` — workflows or build tooling', body)
        self.assertEqual(body.count('- [x]'), 1)
        self.assertIn('regenerated `CHANGELOG.md`, if the change is user-visible — N/A — centralised in #657', body)
        self.assertIn('### Description of your *pull request* and other information', body)
        self.assertNotIn('&emsp; Explanation of your', body)
        self.assertIn(f'| `3.11` | supported | KTLO | {plan["changes"][0]["reason"]} |', body)
        self.assertIn('- remove `Compat Python 3.11`', body)
        self.assertIn('`Compat Python 3.11` -> `Compat Python 3.11 (KTLO)`', body)
        self.assertIn('`ktlo_311`', body)
        self.assertIn('**failure**', body)
        self.assertIn(f'- `{failures[0]}`', body)
        self.assertIn('#1660', body)
        self.assertLess(len(description.splitlines()), 40)

    def test_an_unchanged_ruleset_says_so(self) -> None:
        module = updater()
        _, plan, _ = plan_for(self, snapshot())
        description = module.describe_plan(plan, ('success', []), 'https://example.invalid/run')
        self.assertIn('Ruleset 23497679 needs no edit', description)
        self.assertIn('passed on this tree', description)
        self.assertIn('| `pypy3.12` | -- | supported |', description)

    def test_the_commit_names_its_proposal(self) -> None:
        module = updater()
        _, plan, _ = plan_for(self, snapshot())
        message = module.commit_message(plan)
        self.assertTrue(message.startswith('ci(python): pypy3.12 joins the supported tier (#1660)\n\n'))
        self.assertEqual(module.proposal_of(message), plan['fingerprint'])
        self.assertTrue(message.rstrip('\n').endswith(f'{module.TRAILER}: {plan["fingerprint"]}'))


###############################################################################
# Publishing
###############################################################################


#: ``gh``, stubbed: each call's arguments appended to ``$GH_STUB_LOG`` as JSON.
#: ``$GH_STUB_OPEN`` holds the branch's open pull request, if any, which ``pr create`` opens as #99.
GH_STUB = '''\
import json, os, pathlib, sys
with open(os.environ['GH_STUB_LOG'], 'a', encoding='utf-8') as log:
    log.write(json.dumps(sys.argv[1:]) + '\\n')
state = pathlib.Path(os.environ['GH_STUB_OPEN'])
if sys.argv[1:3] == ['pr', 'list']:
    print(state.read_text(encoding='utf-8') if state.exists() else '')
elif sys.argv[1:3] == ['pr', 'create']:
    state.write_text('99\\n', encoding='utf-8')
    print('https://github.com/JarryShaw/PyPCAPKit/pull/99')
elif sys.argv[1:3] != ['pr', 'edit']:
    sys.exit(3)
'''
#: An ``origin`` hook closing the pull request whose head branch is deleted, as GitHub does.
CLOSE_ON_DELETE = '''\
#!/bin/sh
while read old new ref; do
  if [ "$ref" = refs/heads/bot/python-versions ] && [ "$new" = 0000000000000000000000000000000000000000 ]; then
    : > "$GH_STUB_OPEN"
  fi
done
'''
#: An ``origin`` hook refusing what GitHub refuses an App token without ``workflows``.
REFUSE_WORKFLOWS = '''\
#!/bin/sh
while read old new ref; do
  if [ "$ref" = refs/heads/bot/python-versions ] && [ "$old" != 0000000000000000000000000000000000000000 ] \\
      && [ "$new" != 0000000000000000000000000000000000000000 ] \\
      && ! git diff --quiet "$old" "$new" -- .github/workflows; then
    printf '%s %s\\n' 'refusing to allow a GitHub App to create or update workflow' \\
      '`.github/workflows/ci.yml` without `workflows` permission' >&2
    exit 1
  fi
done
'''


class ScratchOrigin(unittest.TestCase):
    """A scratch ``origin`` whose ``main`` holds :meth:`seed_files`, ``gh`` stubbed, git isolated."""

    def seed_files(self) -> 'dict[str, bytes]':
        raise NotImplementedError

    def setUp(self) -> None:
        if shutil.which('git') is None:  # pragma: no cover
            self.skipTest('git is needed')
        self.module = updater()
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1660b-git-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        config = self.tmp / 'gitconfig'
        # #1644: git 2.55's auto-repack races the temporary directory's cleanup.
        config.write_text('[user]\n\tname = Test\n\temail = test@example.invalid\n[init]\n\tdefaultBranch = main\n'
                          '[maintenance]\n\tauto = false\n[gc]\n\tauto = 0\n\tautoDetach = false\n'
                          '[commit]\n\tgpgsign = false\n', encoding='utf-8')
        bin_dir = self.tmp / 'bin'
        bin_dir.mkdir()
        gh = bin_dir / 'gh'
        gh.write_text(f'#!{sys.executable}\n' + GH_STUB, encoding='utf-8')
        gh.chmod(0o755)
        self.log = self.tmp / 'gh.log'
        self.env = {'GIT_CONFIG_GLOBAL': str(config), 'GIT_CONFIG_NOSYSTEM': '1', 'HOME': str(self.tmp),
                    'PATH': f'{bin_dir}{os.pathsep}{os.environ["PATH"]}', 'GH_STUB_LOG': str(self.log),
                    'GH_STUB_OPEN': str(self.tmp / 'gh-open'), 'GITHUB_REPOSITORY': 'JarryShaw/PyPCAPKit',
                    'APP_SLUG': 'pypcapkit-release', 'APP_BOT_ID': '123456'}
        patcher = mock.patch.dict(os.environ, self.env)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.origin = self.tmp / 'origin.git'
        self.git(self.tmp, 'init', '--quiet', '--bare', str(self.origin))
        # GitHub serves a commits-only fetch, as ahead() asks.
        self.git(self.origin, 'config', 'uploadpack.allowFilter', 'true')
        hook = self.origin / 'hooks' / 'post-receive'
        hook.write_text(CLOSE_ON_DELETE, encoding='utf-8')
        hook.chmod(0o755)
        self.seed = self.tmp / 'seed'
        self.git(self.tmp, 'clone', '--quiet', str(self.origin), str(self.seed))
        for path, data in self.seed_files().items():
            (self.seed / path).parent.mkdir(parents=True, exist_ok=True)
            (self.seed / path).write_bytes(data)
        self.git(self.seed, 'add', '-A')
        self.git(self.seed, 'commit', '--quiet', '-m', 'seed')
        self.git(self.seed, 'push', '--quiet', 'origin', 'HEAD:refs/heads/main')

    def git(self, cwd: 'pathlib.Path', *argv: 'str') -> 'str':
        result = subprocess.run(['git', *argv], cwd=cwd, capture_output=True, text=True, check=False, timeout=60)
        self.assertEqual(result.returncode, 0, f'git {argv}: {result.stderr}')
        return result.stdout.strip()

    def refs(self) -> 'dict[str, str]':
        listed = self.git(self.origin, 'for-each-ref', '--format=%(refname) %(objectname)')
        return dict(line.split(' ', 1) for line in listed.splitlines())

    def calls(self) -> 'list[list[str]]':
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding='utf-8').splitlines()]

    def checkout(self, shallow: 'bool' = False) -> 'pathlib.Path':
        """A fresh clone of ``main``: full, as the ``pr`` job checks it out, or ``detect``'s depth 1."""
        work = self.tmp / f'work-{len(list(self.tmp.glob("work-*")))}'
        if shallow:
            self.git(self.tmp, 'clone', '--quiet', '--depth', '1', self.origin.as_uri(), str(work))
        else:
            self.git(self.tmp, 'clone', '--quiet', str(self.origin), str(work))
        return work

    def hand_edit(self, path: 'str' = 'README.md') -> 'str':
        """The owner's commit on top of ``bot/python-versions``, pushed; its sha."""
        hand = self.checkout()
        self.git(hand, 'checkout', '--quiet', self.module.BRANCH)
        (hand / path).write_text('fixed by hand\n', encoding='utf-8')
        self.git(hand, 'commit', '--quiet', '-am', 'fix the prose by hand')
        self.git(hand, 'push', '--quiet', 'origin', f'HEAD:refs/heads/{self.module.BRANCH}')
        return self.git(hand, 'rev-parse', 'HEAD')

    def move_main(self) -> 'str':
        """An unrelated commit on ``main``, as a week brings; its sha."""
        self.git(self.seed, 'pull', '--quiet', '--ff-only', 'origin', 'main')
        (self.seed / 'NEWS').write_text(self.git(self.seed, 'rev-list', '--count', 'HEAD') + '\n', encoding='utf-8')
        self.git(self.seed, 'add', 'NEWS')
        self.git(self.seed, 'commit', '--quiet', '-m', 'meanwhile on main')
        self.git(self.seed, 'push', '--quiet', 'origin', 'HEAD:refs/heads/main')
        return self.git(self.seed, 'rev-parse', 'HEAD')

    def merge_main(self) -> 'str':
        """``main`` merged into ``bot/python-versions``, as GitHub's "Update branch" does, pushed; its sha."""
        hand = self.checkout()
        self.git(hand, 'checkout', '--quiet', self.module.BRANCH)
        self.git(hand, 'merge', '--quiet', '--no-ff', '-m', f"Merge branch 'main' into {self.module.BRANCH}",
                 'origin/main')
        self.git(hand, 'push', '--quiet', 'origin', f'HEAD:refs/heads/{self.module.BRANCH}')
        return self.git(hand, 'rev-parse', 'HEAD')

    def squash_merge(self) -> 'str':
        """``bot/python-versions`` squash-merged into ``main``, its pull request closed, the branch kept; ``main``."""
        self.git(self.seed, 'pull', '--quiet', '--ff-only', 'origin', 'main')
        self.git(self.seed, 'fetch', '--quiet', 'origin', self.module.BRANCH)
        self.git(self.seed, 'merge', '--quiet', '--squash', 'FETCH_HEAD')
        self.git(self.seed, 'commit', '--quiet', '-m', 'the proposal, squash-merged')
        self.git(self.seed, 'push', '--quiet', 'origin', 'HEAD:refs/heads/main')
        self.pull_request('')
        return self.git(self.seed, 'rev-parse', 'HEAD')

    def pull_request(self, number: 'str') -> 'None':
        """The branch's open pull request is ``number``; ``''``: none, merged or closed."""
        pathlib.Path(self.env['GH_STUB_OPEN']).write_text(number + '\n', encoding='utf-8')

    def contains(self, tip: 'str', commit: 'str') -> 'bool':
        return commit in self.git(self.origin, 'rev-list', tip).split()

    def proposal(self, tier: 'str', changed: 'Optional[list[str]]' = None) -> 'pathlib.Path':
        """A ``detect`` artifact proposing ``latest = tier``."""
        out = self.tmp / f'proposal-{len(list(self.tmp.glob("proposal-*")))}'
        files = {self.module.TIER_FILE: f'latest = "{tier}"\n'}
        plan = {'title': f'ci(python): latest moves to {tier} (#1660)', 'fingerprint': f'f{tier.replace(".", "")}',
                'changed_files': changed if changed is not None else list(files), 'changes': [],
                'latest': ['3.15', tier]}
        for path, text in files.items():
            (out / 'files' / path).parent.mkdir(parents=True, exist_ok=True)
            (out / 'files' / path).write_text(text, encoding='utf-8')
        (out / 'plan.json').write_text(json.dumps(plan), encoding='utf-8')
        (out / 'commit-message.txt').write_text(self.module.commit_message(plan), encoding='utf-8')
        (out / 'pr-body.md').write_text('body\n', encoding='utf-8')
        return out

    def publish(self, work: 'pathlib.Path', out: 'pathlib.Path') -> 'tuple[int, str]':
        """``publish`` as the ``pr`` job runs it, in the checkout ``work``."""
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = self.module.main(['publish', str(out)], root=work)
        return status, stdout.getvalue()


class TestPublishing(ScratchOrigin):
    """``publish`` against a scratch ``origin``: only ``bot/python-versions`` moves."""

    def seed_files(self) -> 'dict[str, bytes]':
        return {self.module.TIER_FILE: b'latest = "3.15"\n', 'README.md': b'readme\n',
                '.github/workflows/ci.yml': b'name: CI\n'}

    def test_it_opens_a_pull_request_from_its_branch_and_updates_it_after(self) -> None:
        main = self.refs()['refs/heads/main']
        status, printed = self.publish(self.checkout(), self.proposal('3.16'))
        self.assertEqual(status, 0, printed)
        refs = self.refs()
        self.assertEqual(set(refs), {'refs/heads/main', 'refs/heads/bot/python-versions'})
        self.assertEqual(refs['refs/heads/main'], main)
        tip = refs['refs/heads/bot/python-versions']
        self.assertEqual(self.git(self.origin, 'rev-parse', f'{tip}^'), main)
        self.assertEqual(self.git(self.origin, 'log', '-1', '--format=%an <%ae>', tip),
                         'pypcapkit-release[bot] <123456+pypcapkit-release[bot]@users.noreply.github.com>')
        self.assertEqual(self.git(self.origin, 'show', f'{tip}:.github/python-versions.toml'), 'latest = "3.16"')
        self.assertEqual(self.module.proposal_of(self.git(self.origin, 'log', '-1', '--format=%B', tip)), 'f316')
        self.assertEqual(self.calls()[-1][:2], ['pr', 'create'])
        self.assertIn(['--base', 'main'], [self.calls()[-1][i:i + 2] for i in range(len(self.calls()[-1]))])
        self.assertIn(['--head', 'bot/python-versions'],
                      [self.calls()[-1][i:i + 2] for i in range(len(self.calls()[-1]))])

        self.pull_request('7')
        status, printed = self.publish(self.checkout(), self.proposal('3.17'))
        self.assertEqual(status, 0, printed)
        refs = self.refs()
        self.assertEqual(refs['refs/heads/main'], main)
        self.assertEqual(self.git(self.origin, 'rev-parse', 'refs/heads/bot/python-versions^'), main)
        self.assertEqual(self.calls()[-1][:3], ['pr', 'edit', '7'])
        self.assertEqual(self.module.proposed(self.checkout(shallow=True), self.module.BRANCH), ['f317'])

    def test_it_keeps_commits_it_did_not_make(self) -> None:
        """While the pull request it opened is open."""
        self.assertEqual(self.publish(self.checkout(), self.proposal('3.16'))[0], 0)
        self.hand_edit()
        before, calls = self.refs(), len(self.calls())
        status, printed = self.publish(self.checkout(), self.proposal('3.17'))
        self.assertEqual(status, 1)
        self.assertIn('::error title=Not overwriting bot/python-versions::', printed)
        self.assertEqual(self.refs(), before)
        # It read whether #99 is open, and touched no pull request.
        self.assertEqual([call[:2] for call in self.calls()[calls:]], [['pr', 'list']])

    def test_a_branch_with_no_open_pull_request_is_recreated_from_main(self) -> None:
        """Merged or closed, the branch stays (``delete_branch_on_merge`` is off); the next proposal replaces it."""
        self.assertEqual(self.publish(self.checkout(), self.proposal('3.16'))[0], 0)
        hand = self.hand_edit()
        self.pull_request('')
        main = self.move_main()
        status, printed = self.publish(self.checkout(), self.proposal('3.17'))
        self.assertEqual(status, 0, printed)
        self.assertIn('::notice title=Recreating bot/python-versions::it has no open pull request', printed)
        self.assertNotIn('::error', printed)
        tip = self.refs()['refs/heads/bot/python-versions']
        self.assertEqual(self.git(self.origin, 'rev-parse', f'{tip}^'), main)
        self.assertEqual(self.module.proposals(self.origin, f'{main}..{tip}'), ['f317'])
        self.assertFalse(self.contains(tip, hand))
        self.assertEqual(self.calls()[-1][:2], ['pr', 'create'])

    def test_a_branch_behind_mains_workflows_is_recreated(self) -> None:
        """Moving it would change a workflow file, which the token cannot; a new branch does not."""
        hook = self.origin / 'hooks' / 'pre-receive'
        hook.write_text(REFUSE_WORKFLOWS, encoding='utf-8')
        hook.chmod(0o755)
        self.assertEqual(self.publish(self.checkout(), self.proposal('3.16'))[0], 0)
        (self.seed / '.github' / 'workflows' / 'ci.yml').write_text('name: CI 2\n', encoding='utf-8')
        self.git(self.seed, 'commit', '--quiet', '-am', 'a workflow change on main')
        self.git(self.seed, 'push', '--quiet', 'origin', 'HEAD:refs/heads/main')
        main = self.refs()['refs/heads/main']
        status, printed = self.publish(self.checkout(), self.proposal('3.17'))
        self.assertEqual(status, 0, printed)
        self.assertIn('::warning title=Recreating bot/python-versions::', printed)
        self.assertEqual(self.refs()['refs/heads/main'], main)
        self.assertEqual(self.git(self.origin, 'rev-parse', 'refs/heads/bot/python-versions^'), main)
        # Deleting the branch closed #99, so a new pull request opens.
        self.assertEqual(self.calls()[-1][:2], ['pr', 'create'])

    def test_it_refuses_a_file_it_does_not_write(self) -> None:
        before = self.refs()
        status, printed = self.publish(self.checkout(), self.proposal('3.16', changed=['.github/workflows/ci.yml']))
        self.assertEqual(status, 1)
        self.assertIn('::error title=Cannot publish the Python version tiers::ValueError', printed)
        self.assertEqual((self.refs(), self.calls()), (before, []))

    def test_detect_reads_the_branchs_proposal_without_credentials(self) -> None:
        work = self.checkout(shallow=True)
        self.assertIsNone(self.module.proposed(work, self.module.BRANCH))
        self.assertEqual(self.publish(self.checkout(), self.proposal('3.16'))[0], 0)
        self.assertEqual(self.module.proposed(work, self.module.BRANCH), ['f316'])

    def test_detect_reads_every_commit_ahead_of_main_and_none_of_main(self) -> None:
        """A hand edit on top does not hide the proposal under it, nor do ``main``'s commits since count."""
        self.assertEqual(self.publish(self.checkout(), self.proposal('3.16'))[0], 0)
        self.hand_edit()
        self.move_main()
        for shallow in (True, False):
            with self.subTest(shallow=shallow):
                self.assertEqual(self.module.proposed(self.checkout(shallow), self.module.BRANCH), [None, 'f316'])

    def test_a_merge_of_main_hides_neither_the_proposal_nor_a_hand_edit(self) -> None:
        """GitHub's "Update branch": the merge is left out, and nothing under it is lost."""
        self.assertEqual(self.publish(self.checkout(), self.proposal('3.16'))[0], 0)
        self.move_main()
        self.merge_main()
        for shallow in (True, False):
            with self.subTest(shallow=shallow):
                self.assertEqual(self.module.proposed(self.checkout(shallow), self.module.BRANCH), ['f316'])
        self.hand_edit()
        self.move_main()
        self.merge_main()
        for shallow in (True, False):
            with self.subTest(shallow=shallow, hand_edit=True):
                self.assertEqual(self.module.proposed(self.checkout(shallow), self.module.BRANCH), [None, 'f316'])

    def test_a_merge_of_another_branch_is_a_hand_edit(self) -> None:
        """Only a merge bringing in ``main``'s commits is left out."""
        self.assertEqual(self.publish(self.checkout(), self.proposal('3.16'))[0], 0)
        hand = self.checkout()
        self.git(hand, 'checkout', '--quiet', '-b', 'topic', 'origin/main')
        (hand / 'TOPIC').write_text('topic\n', encoding='utf-8')
        self.git(hand, 'add', 'TOPIC')
        self.git(hand, 'commit', '--quiet', '-m', 'a topic of its own')
        self.git(hand, 'checkout', '--quiet', self.module.BRANCH)
        self.git(hand, 'merge', '--quiet', '--no-ff', '-m', 'Merge branch topic', 'topic')
        self.git(hand, 'push', '--quiet', 'origin', f'HEAD:refs/heads/{self.module.BRANCH}')
        # The merge and the topic's commit, in an order their equal dates leave open.
        self.assertEqual(sorted(self.module.proposed(self.checkout(shallow=True), self.module.BRANCH), key=str),
                         [None, None, 'f316'])

    def test_a_branch_main_already_holds_proposes_nothing(self) -> None:
        """Merged with a merge commit and not deleted."""
        self.assertEqual(self.publish(self.checkout(), self.proposal('3.16'))[0], 0)
        self.git(self.seed, 'fetch', '--quiet', 'origin', self.module.BRANCH)
        self.git(self.seed, 'push', '--quiet', 'origin', f'FETCH_HEAD:refs/heads/{self.module.BASE}')
        self.assertEqual(self.module.proposed(self.checkout(shallow=True), self.module.BRANCH), [])


class TestTheProposalIsNotRepeated(unittest.TestCase):
    """``publish`` is false while the branch's open pull request proposes these tiers, so no approval is asked."""

    def test_publish_follows_the_branchs_fingerprint(self) -> None:
        """Any commit ahead of ``main`` carrying it counts; a branch publish would refuse fails here instead.

        With no open pull request the branch was merged or closed, so whatever it
        holds is proposed afresh, and ``publish`` recreates it.

        """
        root = scratch(self)
        sources = save_sources(self, snapshot())
        fingerprint = updater().compute_plan(root, snapshot())[0]['fingerprint']
        other = '0123456789abcdef'
        for held, opened, status, publish in (
                ([fingerprint], ['7'], 0, 'false'), ([None, fingerprint], ['7'], 0, 'false'),
                ([other], ['7'], 0, 'true'), ([], ['7'], 0, 'true'), (None, [], 0, 'true'),
                ([None, other], ['7'], 1, 'false'), ([None], ['7'], 1, 'false'),
                ([fingerprint], [], 0, 'true'), ([None, other], [], 0, 'true'), ([None], [], 0, 'true')):
            output = root / f'output-{len(list(root.glob("output-*")))}'
            with self.subTest(held=held, opened=opened), \
                    mock.patch.object(updater(), 'proposed', return_value=held), \
                    mock.patch.object(updater(), 'open_pull_requests', return_value=opened) as lookup:
                found, printed = run_main(root, ['update', '--sources', str(sources), '--proposal-branch',
                                                 'bot/python-versions', '--github-output'], output)
                self.assertEqual(found, status, printed)
                self.assertEqual(output.read_text(encoding='utf-8'),
                                 f'changed=true\npublish={publish}\nfingerprint={fingerprint}\n')
                self.assertEqual('::error title=Not overwriting bot/python-versions::' in printed, bool(status))
                self.assertEqual('::notice title=Proposing afresh::' in printed, held is not None and not opened)
                # No branch, no pull request to look up.
                self.assertEqual(lookup.call_args_list, [] if held is None else [mock.call('bot/python-versions')])


class TestDetectAgainstAHandEditedBranch(ScratchOrigin):
    """The cross-review's case, end to end: ``update``, ``body`` and ``publish`` against a scratch ``origin``.

    The pull request body tells the owner to finish a failed audit by hand on the
    branch. A ``detect`` reading only the tip then took his commit for no
    proposal, asked for the approval every week, and ``publish`` refused it.

    """

    def seed_files(self) -> 'dict[str, bytes]':
        tree = scratch(self)
        return {path.relative_to(tree).as_posix(): path.read_bytes() for path in sorted(tree.rglob('*'))
                if path.is_file()}

    def detect(self, sources: 'dict[str, Any]') -> 'tuple[int, str, dict[str, str], pathlib.Path]':
        """``detect``'s ``update`` step, in a depth-1 checkout: its status, log, outputs and proposal."""
        work = self.checkout(shallow=True)
        out, output = work.with_name(work.name + '-proposal'), work.with_name(work.name + '-output')
        status, printed = run_main(work, ['update', '--sources', str(save_sources(self, sources)), '--write',
                                          '--out', str(out), '--proposal-branch', self.module.BRANCH,
                                          '--github-output'], output)
        written = dict(line.split('=', 1) for line in output.read_text(encoding='utf-8').splitlines())
        self.assertEqual(run_main(work, ['body', str(out)])[0], 0)
        return status, printed, written, out

    def test_a_hand_edit_on_the_proposal_is_not_proposed_again(self) -> None:
        status, printed, written, out = self.detect(snapshot())
        self.assertEqual((status, written['publish']), (0, 'true'), printed)
        self.assertEqual(self.publish(self.checkout(), out)[0], 0)
        self.hand_edit()
        self.move_main()
        before = self.refs()
        status, printed, written, _ = self.detect(snapshot())
        self.assertEqual((status, written['changed'], written['publish']), (0, 'true', 'false'), printed)
        self.assertIn('::notice title=Already proposed::bot/python-versions already proposes these tiers', printed)
        self.assertEqual(self.refs(), before)

    def test_tiers_moving_again_under_a_hand_edit_fail_detect_not_publish(self) -> None:
        status, printed, _, out = self.detect(snapshot())
        self.assertEqual(self.publish(self.checkout(), out)[0], 0)
        self.hand_edit()
        status, printed, written, out = self.detect(three_eleven_ends_and_three_sixteen_ships(snapshot()))
        self.assertEqual((status, written['publish']), (1, 'false'), printed)
        self.assertIn('::error title=Not overwriting bot/python-versions::it holds commits this workflow did not '
                      'make', printed)
        # What publish says of the same branch, had the approval been asked for.
        status, printed = self.publish(self.checkout(), out)
        self.assertEqual(status, 1)
        self.assertIn('::error title=Not overwriting bot/python-versions::', printed)

    def test_tiers_moving_again_under_its_own_commit_are_proposed(self) -> None:
        status, printed, _, out = self.detect(snapshot())
        self.assertEqual(self.publish(self.checkout(), out)[0], 0)
        self.move_main()
        status, printed, written, out = self.detect(three_eleven_ends_and_three_sixteen_ships(snapshot()))
        self.assertEqual((status, written['publish']), (0, 'true'), printed)
        self.pull_request('7')
        self.assertEqual(self.publish(self.checkout(), out)[0], 0)
        tip = self.refs()['refs/heads/bot/python-versions']
        self.assertEqual(self.module.proposals(self.origin, f'{self.refs()["refs/heads/main"]}..{tip}'),
                         [json.loads((out / 'plan.json').read_text(encoding='utf-8'))['fingerprint']])

    def test_a_merge_of_main_is_neither_a_proposal_nor_a_hand_edit(self) -> None:
        """GitHub's "Update branch" on the open proposal: a depth-1 ``detect`` still finds it under the merge."""
        status, printed, _, out = self.detect(snapshot())
        self.assertEqual(self.publish(self.checkout(), out)[0], 0)
        self.move_main()
        self.merge_main()
        before = self.refs()
        status, printed, written, _ = self.detect(snapshot())
        self.assertEqual((status, written['changed'], written['publish']), (0, 'true', 'false'), printed)
        self.assertIn('::notice title=Already proposed::bot/python-versions already proposes these tiers', printed)
        self.assertEqual(self.refs(), before)

        status, printed, written, out = self.detect(three_eleven_ends_and_three_sixteen_ships(snapshot()))
        self.assertEqual((status, written['publish']), (0, 'true'), printed)
        self.assertNotIn('::error', printed)
        status, printed = self.publish(self.checkout(), out)
        self.assertEqual(status, 0, printed)
        main, tip = self.refs()['refs/heads/main'], self.refs()['refs/heads/bot/python-versions']
        self.assertEqual(self.git(self.origin, 'rev-parse', f'{tip}^'), main)
        self.assertEqual(self.module.proposals(self.origin, f'{main}..{tip}'),
                         [json.loads((out / 'plan.json').read_text(encoding='utf-8'))['fingerprint']])
        self.assertEqual(self.calls()[-1][:3], ['pr', 'edit', '99'])

    def test_a_squash_merged_proposal_leaves_a_branch_the_next_change_recreates(self) -> None:
        """``delete_branch_on_merge`` is off, so the merged branch stays, hand edit and all."""
        status, printed, _, out = self.detect(snapshot())
        self.assertEqual(self.publish(self.checkout(), out)[0], 0)
        hand = self.hand_edit()
        self.squash_merge()
        status, printed, written, _ = self.detect(snapshot())
        self.assertEqual((status, written['changed'], written['publish']), (0, 'false', 'false'), printed)

        status, printed, written, out = self.detect(three_eleven_ends_and_three_sixteen_ships(snapshot()))
        self.assertEqual((status, written['publish']), (0, 'true'), printed)
        self.assertIn('::notice title=Proposing afresh::bot/python-versions has no open pull request', printed)
        self.assertNotIn('::error', printed)
        status, printed = self.publish(self.checkout(), out)
        self.assertEqual(status, 0, printed)
        self.assertIn('::notice title=Recreating bot/python-versions::', printed)
        main, tip = self.refs()['refs/heads/main'], self.refs()['refs/heads/bot/python-versions']
        self.assertEqual(self.git(self.origin, 'rev-parse', f'{tip}^'), main)
        self.assertFalse(self.contains(tip, hand))
        self.assertEqual(self.calls()[-1][:2], ['pr', 'create'])


###############################################################################
# The workflow
###############################################################################


class TestTheWorkflow(unittest.TestCase):
    """``detect`` holds no secret; ``pr`` mints the narrow token behind ``github-release``."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.spec = workflow()
        cls.jobs = cls.spec['jobs']

    def step(self, job: 'str', label: 'str') -> 'dict[str, Any]':
        return next(step for step in self.jobs[job]['steps'] if step.get('name') == label)

    def test_it_runs_weekly_and_on_dispatch_only(self) -> None:
        """No ``push``: the branch it pushes starts the pull request's checks, never this."""
        self.assertEqual(self.spec['name'], 'Python Versions')
        triggers = self.spec.get('on', self.spec.get(True))
        self.assertEqual(set(triggers), {'schedule', 'workflow_dispatch'})
        self.assertEqual(len(triggers['schedule']), 1)
        for path in sorted(WORKFLOW.parent.glob('*.yml')):
            spec = _workflows.load(path)
            on = spec.get('on', spec.get(True)) or {}
            with self.subTest(workflow=path.name):
                listed = (on.get('workflow_run') or {}).get('workflows', []) if isinstance(on, dict) else []
                self.assertNotIn('Python Versions', listed)
                if path != WORKFLOW:
                    self.assertNotIn('bot/python-versions', path.read_text(encoding='utf-8'))

    def test_version_check_treats_its_merge_like_any_other(self) -> None:
        """Create Release starts on a ``v*`` tag or Vendor Update, and its gate names no branch of this job's."""
        spec = _workflows.load(WORKFLOW.parent / 'create-release.yml')
        on = spec.get('on', spec.get(True))
        self.assertEqual(set(on), {'push', 'workflow_run'})
        self.assertEqual(on['push'], {'tags': ['v*']})
        self.assertEqual(on['workflow_run']['workflows'], ['Vendor Update'])
        # #1748 added the triggering Vendor Update's own reading, which names no branch either.
        self.assertEqual(' '.join(spec['jobs']['version_check']['if'].split()),
                         "${{ !cancelled() && (github.event_name != 'workflow_run' || "
                         "github.event.workflow_run.conclusion == 'success') && !(github.event_name == 'push' "
                         "&& github.actor_id == vars.RELEASE_APP_BOT_ID) && "
                         "needs.vendor_update.outputs.updated != 'false' }}")

    def test_permissions_are_nothing_by_default_and_little_per_job(self) -> None:
        self.assertEqual(self.spec['permissions'], {})
        # detect reads the branch's pull request; pr's token is the App's.
        self.assertEqual(self.jobs['detect']['permissions'], {'contents': 'read', 'pull-requests': 'read'})
        self.assertEqual(self.jobs['pr']['permissions'], {'actions': 'read'})
        # #2030: `discussion` posts detect's report; test_cron_reports_2030.py pins it.
        self.assertEqual(set(self.jobs), {'detect', 'pr', 'discussion'})

    def test_detect_reads_no_secret_and_names_no_environment(self) -> None:
        text = json.dumps(self.jobs['detect'])
        self.assertNotIn('secrets', text)
        self.assertNotIn('environment', self.jobs['detect'])
        checkout = self.jobs['detect']['steps'][0]
        self.assertTrue(checkout['uses'].startswith('actions/checkout@'))
        self.assertIs(checkout['with']['persist-credentials'], False)

    def test_detect_recomputes_audits_and_hands_over(self) -> None:
        module = updater()
        update = self.step('detect', 'Recompute the tiers')
        self.assertEqual(update['run'].split(), ['python', 'util/update_python_versions.py', 'update', '--write',
                                                 '--out', '"$RUNNER_TEMP/proposal"', '--proposal-branch',
                                                 module.BRANCH, '--github-output'])
        # For gh, to read whether the branch's pull request is open.
        self.assertEqual(update['env'], {'GH_TOKEN': '${{ github.token }}'})
        audit = self.step('detect', 'Run the audit tests')
        self.assertIs(audit['continue-on-error'], True)
        self.assertEqual(audit['shell'], 'bash')
        command = audit['run'].split('2>&1')[0].split()
        self.assertEqual(command[:4], ['python', '-m', 'unittest', '-v'])
        self.assertEqual(tuple(command[4:]), module.AUDIT)
        self.assertEqual(self.jobs['detect']['outputs'], {'changed': '${{ steps.update.outputs.changed }}',
                                                           'publish': '${{ steps.update.outputs.publish }}',
                                                           'status': '${{ steps.run-report.outputs.status }}'})
        upload = self.step('detect', 'Upload the proposal')
        self.assertEqual(upload['if'], "${{ steps.update.outputs.publish == 'true' }}")
        # The proposal's files/.github/python-versions.toml is a hidden path.
        self.assertIs(upload['with']['include-hidden-files'], True)
        download = self.step('pr', 'Download the proposal')
        self.assertIn(f'--name {upload["with"]["name"]}', ' '.join(download['run'].split()))
        self.assertEqual(download['env'], {'GH_TOKEN': '${{ github.token }}'})

    def test_pr_mints_contents_and_pull_requests_write_behind_github_release(self) -> None:
        job = self.jobs['pr']
        self.assertEqual(job['environment'], 'github-release')
        self.assertEqual(job['needs'], 'detect')
        mint = self.step('pr', "Mint the release App's token")
        self.assertTrue(_workflows.pinned(mint['uses'], 'actions/create-github-app-token'), mint['uses'])
        self.assertEqual({version.split('.')[0]
                          for version in _workflows.versions(WORKFLOW, 'actions/create-github-app-token')}, {'v3'})
        self.assertEqual(mint['with'], {
            'client-id': '${{ vars.RELEASE_APP_CLIENT_ID }}',
            'private-key': '${{ secrets.RELEASE_APP_PRIVATE_KEY }}',
            'permission-contents': 'write',
            'permission-pull-requests': 'write',
        })
        self.assertEqual([step for step in job['steps'] if 'secrets.' in json.dumps(step)], [mint])

    def test_pr_runs_only_with_something_to_propose_the_app_and_main(self) -> None:
        condition = self.jobs['pr']['if']
        for publish, client, ref, expected in (('true', 'Iv23example', 'refs/heads/main', True),
                                               ('true', '', 'refs/heads/main', False),
                                               ('false', 'Iv23example', 'refs/heads/main', False),
                                               ('true', 'Iv23example', 'refs/heads/feature', False)):
            with self.subTest(publish=publish, client=client, ref=ref):
                state = {'needs': {'detect': {'outputs': {'publish': publish}}},
                         'vars': {'RELEASE_APP_CLIENT_ID': client}, 'github': {'ref': ref}}
                self.assertIs(evaluate_condition(condition, state), expected)

    def test_pr_pushes_through_publish_only(self) -> None:
        """No ``git push`` of its own; :class:`TestPublishing` shows ``publish`` moves only its branch."""
        job = self.jobs['pr']
        checkout = next(step for step in job['steps'] if str(step.get('uses', '')).startswith('actions/checkout@'))
        self.assertEqual(checkout['with'], {'ref': '${{ github.sha }}', 'fetch-depth': 0,
                                            'token': '${{ steps.app.outputs.token }}'})
        self.assertNotIn('git push', WORKFLOW.read_text(encoding='utf-8'))
        publish = self.step('pr', 'Push the proposal and open or update its pull request')
        self.assertEqual(publish['run'].split(), ['python3', 'util/update_python_versions.py', 'publish',
                                                  '"$RUNNER_TEMP/proposal"'])
        self.assertEqual(publish['env']['GH_TOKEN'], '${{ steps.app.outputs.token }}')
        self.assertEqual(updater().BRANCH, 'bot/python-versions')
        self.assertEqual(updater().BASE, 'main')

    def test_its_actions_are_pinned_as_the_other_workflows_pin_them(self) -> None:
        others = set()
        for path in sorted(WORKFLOW.parent.glob('*.yml')):
            if path != WORKFLOW:
                others.update(re.findall(r'(?m)^\s*(?:- )?uses: ([^\s#]+)', path.read_text(encoding='utf-8')))
        uses = re.findall(r'(?m)^\s*(?:- )?uses: ([^\s#]+)', WORKFLOW.read_text(encoding='utf-8'))
        self.assertTrue(uses)
        self.assertLessEqual(set(uses), others)


if __name__ == '__main__':
    unittest.main()
