# -*- coding: utf-8 -*-
"""Tests that :file:`.github/coverage.toml` repeats :file:`pyproject.toml`'s coverage settings.

#1063: the coverage leg of :file:`.github/workflows/unit-tests.yml` runs with
``--rcfile=.github/coverage.toml``, and coverage reads exactly one config file.
So the ``[tool.coverage.*]`` tables in :file:`pyproject.toml` are *not* read on
that run; the rcfile has to repeat them, plus the keys only the CI run needs
(``parallel``, ``patch`` and ``core``). A setting changed in :file:`pyproject.toml` alone
would silently not apply in CI, which is the drift asserted against here.

"""

from __future__ import annotations

import pathlib
import unittest

try:
    import tomllib
except ImportError:  # Python 3.10
    tomllib = None  # type: ignore[assignment]

ROOT = pathlib.Path(__file__).resolve().parents[2]
PYPROJECT = ROOT / 'pyproject.toml'
RCFILE = ROOT / '.github' / 'coverage.toml'


@unittest.skipIf(tomllib is None, 'tomllib needs Python 3.11+')
class CoverageRcfileTests(unittest.TestCase):
    """:file:`.github/coverage.toml` against :file:`pyproject.toml`."""

    def setUp(self) -> None:
        for path in (PYPROJECT, RCFILE):
            if not path.is_file():
                self.skipTest(f'{path} is not present, e.g. in a source distribution')
        self.project = tomllib.loads(PYPROJECT.read_text(encoding='utf-8'))['tool']['coverage']
        self.rcfile = tomllib.loads(RCFILE.read_text(encoding='utf-8'))['tool']['coverage']

    def test_every_pyproject_setting_is_repeated_unchanged(self) -> None:
        """Each ``[tool.coverage.<section>]`` key has the same value in the rcfile."""
        for section, options in self.project.items():
            for key, value in options.items():
                with self.subTest(setting=f'{section}.{key}'):
                    self.assertEqual(self.rcfile.get(section, {}).get(key), value)

    def test_the_xdist_workers_are_measured(self) -> None:
        """Without these two keys an ``-n auto`` run measures only the controller."""
        run = self.rcfile['run']
        self.assertIs(run.get('parallel'), True)
        self.assertIn('subprocess', run.get('patch', ()))

    def test_a_sigterm_saves_the_data(self) -> None:
        """A worker SIGTERMed during shutdown otherwise leaves no data file (#1423)."""
        self.assertIs(self.rcfile['run'].get('sigterm'), True)

    def test_the_core_is_ctrace(self) -> None:
        """sysmon grew one module's peak RSS from 0.40 to 4.17 GiB and killed the runner (#1064)."""
        self.assertEqual(self.rcfile['run'].get('core'), 'ctrace')


if __name__ == '__main__':
    unittest.main()
