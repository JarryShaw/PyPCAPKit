# -*- coding: utf-8 -*-
"""cryptography is pinned apart on Intel macOS, which has no wheel of its newest releases (#1827).

* :file:`conda/requirements.txt` carries a cryptography line per platform pin,
  and on each conda build exactly one of them applies: 48.0.1 on ``osx-64``,
  the installed release elsewhere.
* :file:`util/conda_vendor.py` writes those lines from ``PLATFORM_PINS``, and
  ``--check`` passes on them and fails when the table entry or the file's pin
  goes, when the pin moves, and when the table names a package or platform no
  build has. All offline, on stand-in metadata.

"""

from __future__ import annotations

import contextlib
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


def cryptography(module: 'Any', envs: 'list[dict[str, str]]') -> 'dict[str, Any]':
    """What the conda builds vendor for ``pyproject.toml``'s cryptography line, on stand-in metadata."""
    return module.derive([req for req in module.direct() if req.name == 'cryptography'], envs, lambda name: [])


class CommittedLinesTests(unittest.TestCase):
    """The committed cryptography lines, evaluated for each conda build."""

    def test_each_build_reads_one_cryptography_line(self) -> None:
        from packaging.requirements import Requirement
        module = vendor()
        lines = committed()
        self.assertIn(INTEL, lines)
        self.assertEqual(len([line for line in lines if REST.fullmatch(line)]), 1, lines)
        self.assertEqual(module.PLATFORM_PINS, {'cryptography': {'osx-64': '48.0.1'}})
        for env in module.environments(module.conda_pythons()):
            subdir = next(subdir for subdir, (sys_platform, _, machine) in module.PLATFORMS.items()
                          if (sys_platform, machine) == (env['sys_platform'], env['platform_machine']))
            with self.subTest(subdir=subdir, python=env['python_version']):
                live = [line for line in lines if Requirement(line).marker.evaluate(env)]
                self.assertEqual(len(live), 1, live)
                self.assertEqual(live[0] == INTEL, subdir == 'osx-64', live)


class WriterTests(unittest.TestCase):
    """The writer emits a line per platform pin."""

    def test_the_writer_emits_the_platform_lines(self) -> None:
        module = vendor()
        envs = module.environments(module.conda_pythons())
        self.assertEqual(module.lines(cryptography(module, envs), envs, lambda name: '50.0.2'),
                         [INTEL, 'cryptography==50.0.2; sys_platform != "darwin" or platform_machine != "x86_64"'])

    def test_a_python_marker_is_kept_beside_the_platform_one(self) -> None:
        from packaging.requirements import Requirement
        module = vendor()
        envs = module.environments(['3.11', '3.12'])
        found = module.derive([Requirement('cryptography; python_version >= "3.12"')], envs, lambda name: [])
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
    """``--check`` against the committed cryptography lines."""

    def problems(self, text: 'str') -> 'list[str]':
        module = vendor()
        envs = module.environments(module.conda_pythons())
        return module.compare(text, cryptography(module, envs), envs)

    def test_the_committed_lines_pass(self) -> None:
        lines = committed()
        self.assertIn(INTEL, lines)
        self.assertEqual(self.problems('\n'.join(lines)), [])

    def test_without_the_override_the_platform_lines_fail(self) -> None:
        with mock.patch.object(vendor(), 'PLATFORM_PINS', {}):
            problems = self.problems('\n'.join(committed()))
        self.assertEqual(len(problems), 1, problems)
        self.assertTrue(problems[0].startswith('marker: cryptography has ['), problems)

    def test_a_dropped_or_moved_platform_pin_fails(self) -> None:
        rest = [line for line in committed() if line != INTEL]
        dropped = self.problems('\n'.join(rest))
        self.assertEqual([problem.split(':')[0] for problem in dropped], ['marker'], dropped)
        unmarked = self.problems('\n'.join(rest + ['cryptography==48.0.1']))
        self.assertEqual([problem.split(':')[0] for problem in unmarked], ['marker'], unmarked)
        moved = self.problems('\n'.join(rest + [INTEL.replace('48.0.1', '49.0.0')]))
        self.assertEqual(moved, ["pin: cryptography pins '49.0.0' where sys_platform == \"darwin\" and "
                                 "platform_machine == \"x86_64\", and PLATFORM_PINS '48.0.1'"])

    def test_an_override_no_build_can_use_fails(self) -> None:
        pins = {'cryptography': {'osx-64': '48.0.1', 'win-64': '1.0'}, 'gone': {'osx-64': '1.0'}}
        with mock.patch.object(vendor(), 'PLATFORM_PINS', pins):
            problems = self.problems('\n'.join(committed()))
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
                with mock.patch.object(module, 'PLATFORM_PINS', {'gone': {'osx-64': '1.0'}}), \
                        contextlib.redirect_stderr(io.StringIO()) as errors:
                    self.assertEqual(module.main([]), 1)
                self.assertFalse(target.exists())
                self.assertIn('override: gone is pinned for osx-64', errors.getvalue())
            finally:
                module.FILE, module.ROOT, module._requires, module._version = saved


if __name__ == '__main__':
    unittest.main()
