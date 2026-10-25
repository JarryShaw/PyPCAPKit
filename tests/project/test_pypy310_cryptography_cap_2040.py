# -*- coding: utf-8 -*-
"""#2040: the ``crypto`` and ``all`` extras cap ``cryptography`` on PyPy below 3.11, and only there.

45.0.7 is the newest ``cryptography`` with a manylinux ``pp310`` wheel. Without
the cap pip on the ``pypy3.10`` leg builds the newest release's sdist, which
fails, so the leg never runs a test. Each environment below gets exactly one live
``cryptography`` requirement from each extra, read from :file:`pyproject.toml`
and evaluated with :mod:`packaging.markers`: capped on PyPy 3.10, uncapped on
PyPy 3.11 and on CPython 3.10.

"""

from __future__ import annotations

import pathlib
import unittest

from packaging.requirements import Requirement
from packaging.version import Version

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

#: Test tier (#1958): reads pyproject.toml, which is the same on every interpreter.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
PYPROJECT = ROOT / 'pyproject.toml'

#: The newest release with a manylinux ``pp310`` wheel, and the first without one.
LAST_PP310 = Version('45.0.7')
FIRST_WITHOUT = Version('46.0.0')
#: The release ``pypy3.10`` resolves to without the cap, whose sdist fails there.
NEWEST = Version('50.0.2')


def env(implementation: 'str', python: 'str') -> 'dict[str, str]':
    """A Linux x86_64 marker environment for ``implementation`` at ``python``."""
    return {
        'implementation_name': implementation.lower(),
        'platform_python_implementation': implementation,
        'python_version': python,
        'python_full_version': f'{python}.0',
        'implementation_version': f'{python}.0',
        'sys_platform': 'linux', 'platform_system': 'Linux', 'os_name': 'posix',
        'platform_machine': 'x86_64', 'platform_release': '', 'platform_version': '',
        'extra': '',
    }


ENVS = {
    'PyPy 3.10': env('PyPy', '3.10'),
    'PyPy 3.11': env('PyPy', '3.11'),
    'CPython 3.10': env('CPython', '3.10'),
}


@unittest.skipIf(tomllib is None, 'tomllib, which reads pyproject.toml, needs Python 3.11+')
class TestCryptographyCap(unittest.TestCase):
    """Which ``cryptography`` each extra asks for, per interpreter."""

    extras = {}  # type: dict[str, list[str]]

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.extras = tomllib.loads(PYPROJECT.read_text(encoding='utf-8'))['project']['optional-dependencies']

    def live(self, extra: 'str', name: 'str') -> 'Requirement':
        """The one ``cryptography`` requirement of ``extra`` live on ``ENVS[name]``."""
        found = [requirement for requirement in map(Requirement, self.extras[extra])
                 if requirement.name == 'cryptography'
                 and (requirement.marker is None or requirement.marker.evaluate(ENVS[name]))]
        self.assertEqual(len(found), 1,
                         f'{extra} has {len(found)} live cryptography requirements on {name}, '
                         f'not one: {[str(requirement) for requirement in found]}')
        return found[0]

    def test_pypy310_is_capped_at_the_last_release_with_a_pp310_wheel(self) -> 'None':
        for extra in ('crypto', 'all'):
            with self.subTest(extra=extra):
                specifier = self.live(extra, 'PyPy 3.10').specifier
                self.assertIn(LAST_PP310, specifier)
                self.assertIn(Version('3.4'), specifier)
                self.assertNotIn(FIRST_WITHOUT, specifier)
                self.assertNotIn(NEWEST, specifier)

    def test_every_other_interpreter_stays_uncapped(self) -> 'None':
        for extra in ('crypto', 'all'):
            for name in ('PyPy 3.11', 'CPython 3.10'):
                with self.subTest(extra=extra, env=name):
                    specifier = self.live(extra, name).specifier
                    self.assertIn(NEWEST, specifier)
                    self.assertIn(Version('3.4'), specifier)
                    self.assertNotIn(Version('3.3'), specifier)


if __name__ == '__main__':
    unittest.main()
