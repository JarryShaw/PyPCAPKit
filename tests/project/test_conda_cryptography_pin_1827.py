# -*- coding: utf-8 -*-
"""cryptography is pinned apart on Intel macOS, which has no wheel of its newest releases (#1827).

* :file:`conda/requirements.txt` carries a line per platform pin of each package
  :file:`conda/platform-pins.toml` pins, and of cryptography whether or not it
  is, and on each conda build exactly one of a package's lines applies: the
  table's pin on its platform, the installed release elsewhere. Read from the
  table rather than spelt here, since the weekly Conda Update moves and drops
  pins (#1851).
* :file:`util/conda_vendor.py` writes those lines from ``PLATFORM_PINS``, and
  ``--check`` passes on them and fails when the table entry or the file's pin
  goes, when the pin moves, and when the table names a package or platform no
  build has. All offline, on stand-in metadata and a stand-in 48.0.1 pin.

"""

from __future__ import annotations

import contextlib
import datetime
import importlib.util
import io
import pathlib
import re
import tempfile
import unittest
from typing import TYPE_CHECKING
from unittest import mock

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
REQUIREMENTS = ROOT / 'conda' / 'requirements.txt'
#: The Intel macOS line :func:`stand_in`'s pin writes.
INTEL = 'cryptography==48.0.1; sys_platform == "darwin" and platform_machine == "x86_64"'
#: The other line, whose pin the weekly Conda Update moves.
REST = re.compile(r'cryptography==(\S+); sys_platform != "darwin" or platform_machine != "x86_64"')

_MODULE = []  # type: list[Any]


def vendor() -> 'Any':
    """:file:`util/conda_vendor.py`, loaded once; skipped without :mod:`tomllib`, which it imports."""
    if tomllib is None:  # pragma: no cover
        raise unittest.SkipTest('tomllib, which util/conda_vendor.py imports, needs Python 3.11+')
    if not _MODULE:
        spec = importlib.util.spec_from_file_location('conda_vendor', ROOT / 'util' / 'conda_vendor.py')
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        _MODULE.append(module)
    return _MODULE[0]


def committed() -> 'list[str]':
    """The committed file's cryptography lines."""
    return [line for line in REQUIREMENTS.read_text(encoding='utf-8').splitlines()
            if line.startswith('cryptography')]


def pinned(*pins: 'tuple[str, str, str]') -> 'dict[str, dict[str, Any]]':
    """A ``PLATFORM_PINS`` of (package, conda subdir, version), with a stand-in date and reason."""
    module, table = vendor(), {}  # type: Any, dict[str, dict[str, Any]]
    for name, subdir, version in pins:
        table.setdefault(name, {})[subdir] = module.Pin(version, datetime.date(2027, 1, 15), 'a stand-in')
    return table


def stand_in() -> 'Any':
    """``PLATFORM_PINS`` patched to cryptography 48.0.1 on osx-64, as #1827 committed it."""
    return mock.patch.object(vendor(), 'PLATFORM_PINS', pinned(('cryptography', 'osx-64', '48.0.1')))


def written() -> 'list[str]':
    """The cryptography lines the writer gives :func:`stand_in`'s pin, with 50.0.2 installed."""
    module = vendor()
    envs = module.environments(module.conda_pythons())
    with stand_in():
        return module.lines(cryptography(module, envs), envs, lambda name: '50.0.2')


def cryptography(module: 'Any', envs: 'list[dict[str, str]]') -> 'dict[str, Any]':
    """What the conda builds vendor for ``pyproject.toml``'s cryptography line, on stand-in metadata."""
    return module.derive([req for req in module.direct() if req.name == 'cryptography'], envs, lambda name: [])


class CommittedLinesTests(unittest.TestCase):
    """The committed lines of each pinned package, and of cryptography, evaluated for each conda build."""

    def test_each_build_reads_one_line_per_pinned_package(self) -> None:
        from packaging.requirements import Requirement
        module = vendor()
        lines = [Requirement(line) for line in REQUIREMENTS.read_text(encoding='utf-8').splitlines()
                 if line.split('#', 1)[0].strip()]
        for name in sorted({'cryptography', *module.PLATFORM_PINS}):
            pins = module.PLATFORM_PINS.get(name, {})
            reads = {}  # type: dict[tuple[str, str], str]
            for env in module.environments(module.conda_pythons()):
                subdir = next(subdir for subdir, (sys_platform, _, machine) in module.PLATFORMS.items()
                              if (sys_platform, machine) == (env['sys_platform'], env['platform_machine']))
                with self.subTest(package=name, subdir=subdir, python=env['python_version']):
                    live = [str(req) for req in lines
                            if req.name == name and (req.marker is None or req.marker.evaluate(env))]
                    self.assertEqual(len(live), 1, live)
                    reads[subdir, env['python_version']] = live[0]
                    if subdir in pins:
                        self.assertEqual(str(Requirement(live[0]).specifier), f'=={pins[subdir].version}')
            # The builds no pin names read none of the pinned lines.
            on_pinned = {line for (subdir, _), line in reads.items() if subdir in pins}
            self.assertFalse({line for (subdir, _), line in reads.items() if subdir not in pins} & on_pinned,
                             reads)


class WriterTests(unittest.TestCase):
    """The writer emits a line per platform pin."""

    def test_the_writer_emits_the_platform_lines(self) -> None:
        self.assertEqual(written(),
                         [INTEL, 'cryptography==50.0.2; sys_platform != "darwin" or platform_machine != "x86_64"'])
        self.assertIsNotNone(REST.fullmatch(written()[1]))

    def test_a_python_marker_is_kept_beside_the_platform_one(self) -> None:
        from packaging.requirements import Requirement
        module = vendor()
        envs = module.environments(['3.11', '3.12'])
        found = module.derive([Requirement('cryptography; python_version >= "3.12"')], envs, lambda name: [])
        with stand_in():
            lines = module.lines(found, envs, lambda name: '50.0.2')
        self.assertEqual(lines, [
            'cryptography==48.0.1; (python_version == "3.12") and '
            '(sys_platform == "darwin" and platform_machine == "x86_64")',
            'cryptography==50.0.2; (python_version == "3.12") and '
            '(sys_platform != "darwin" or platform_machine != "x86_64")',
        ])
        for env in envs:
            with self.subTest(env=(env['python_version'], env['sys_platform'], env['platform_machine'])):
                live = [line for line in lines if Requirement(line).marker.evaluate(env)]
                self.assertEqual(len(live), env['python_version'] == '3.12')


class CheckTests(unittest.TestCase):
    """``--check`` against the committed cryptography lines, and against :func:`stand_in`'s."""

    def problems(self, text: 'str') -> 'list[str]':
        module = vendor()
        envs = module.environments(module.conda_pythons())
        return module.compare(text, cryptography(module, envs), envs)

    def test_the_committed_lines_pass(self) -> None:
        self.assertEqual(self.problems('\n'.join(committed())), [])

    def test_the_stand_in_lines_pass(self) -> None:
        lines = written()
        with stand_in():
            self.assertEqual(self.problems('\n'.join(lines)), [])

    def test_without_the_override_the_platform_lines_fail(self) -> None:
        lines = written()
        with mock.patch.object(vendor(), 'PLATFORM_PINS', {}):
            problems = self.problems('\n'.join(lines))
        self.assertEqual(len(problems), 1, problems)
        self.assertTrue(problems[0].startswith('marker: cryptography has ['), problems)

    def test_a_dropped_or_moved_platform_pin_fails(self) -> None:
        rest = [line for line in written() if line != INTEL]
        with stand_in():
            dropped = self.problems('\n'.join(rest))
            unmarked = self.problems('\n'.join(rest + ['cryptography==48.0.1']))
            moved = self.problems('\n'.join(rest + [INTEL.replace('48.0.1', '49.0.0')]))
        self.assertEqual([problem.split(':')[0] for problem in dropped], ['marker'], dropped)
        self.assertEqual([problem.split(':')[0] for problem in unmarked], ['marker'], unmarked)
        self.assertEqual(moved, ["pin: cryptography pins '49.0.0' where sys_platform == \"darwin\" and "
                                 "platform_machine == \"x86_64\", and PLATFORM_PINS '48.0.1'"])

    def test_an_override_no_build_can_use_fails(self) -> None:
        lines = written()
        pins = pinned(('cryptography', 'osx-64', '48.0.1'), ('cryptography', 'win-64', '1.0'),
                      ('gone', 'osx-64', '1.0'))
        with mock.patch.object(vendor(), 'PLATFORM_PINS', pins):
            problems = self.problems('\n'.join(lines))
        self.assertEqual(problems, ['override: cryptography is pinned for win-64, which no conda leg builds',
                                    'override: gone is pinned for osx-64, and no conda build vendors it'])

    def test_the_writer_refuses_an_override_no_build_can_use(self) -> None:
        module = vendor()
        with tempfile.TemporaryDirectory() as temp:
            target = pathlib.Path(temp) / 'requirements.txt'
            saved = module.FILE, module.ROOT, module._requires, module._version
            module.FILE, module.ROOT = target, pathlib.Path(temp)
            module._requires = lambda name: []
            module._version = lambda name: '1.0'
            try:
                with mock.patch.object(module, 'PLATFORM_PINS', pinned(('gone', 'osx-64', '1.0'))), \
                        contextlib.redirect_stderr(io.StringIO()) as errors:
                    self.assertEqual(module.main([]), 1)
                self.assertFalse(target.exists())
                self.assertIn('override: gone is pinned for osx-64', errors.getvalue())
            finally:
                module.FILE, module.ROOT, module._requires, module._version = saved


if __name__ == '__main__':
    unittest.main()
