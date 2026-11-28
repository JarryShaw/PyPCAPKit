# -*- coding: utf-8 -*-
"""#3201: the ``crypto`` and ``all`` extras leave ``cryptography`` out on PyPy 3.12 onwards.

No release ships a ``pp312`` wheel, and one built from the sdist fails to import
there, missing ``PyPy*`` C-API symbols. Each extra's requirements are read from
:file:`pyproject.toml` and evaluated with :mod:`packaging.markers`, in the marker
environments of #2040's test. The same evaluation derives
:data:`tests._dependency_gates.PYPY_EXCLUSIONS`, which the dependency-gate guard reads.

"""

from __future__ import annotations

import pathlib
import unittest
from typing import TYPE_CHECKING

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version

from tests import _dependency_gates
from tests.project.test_pypy310_cryptography_cap_2040 import env

if TYPE_CHECKING:
    from typing import Optional

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

#: Test tier (#1958): reads pyproject.toml, which is the same on every interpreter.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
PYPROJECT = ROOT / 'pyproject.toml'
VERSIONS = ROOT / '.github' / 'python-versions.toml'

#: The first release with no manylinux ``pp310`` wheel, which #2040's cap excludes.
FIRST_WITHOUT_PP310 = Version('46.0.0')
#: What each interpreter gets from each extra, in order.
EXPECTED = (
    ('CPython', '3.12', 'included'),
    ('PyPy', '3.10', 'capped'),
    ('PyPy', '3.11', 'included'),
    ('PyPy', '3.12', 'excluded'),
)


@unittest.skipIf(tomllib is None, 'tomllib, which reads pyproject.toml, needs Python 3.11+')
class TestCryptographyOnPyPy312(unittest.TestCase):
    """Which ``cryptography`` each extra asks for, and what PyPy goes without."""

    project = {}  # type: dict

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.project = tomllib.loads(PYPROJECT.read_text(encoding='utf-8'))['project']

    def verdict(self, extra: 'str', implementation: 'str', python: 'str') -> 'str':
        """``extra``'s ``cryptography`` on ``implementation`` ``python``: included, capped or excluded."""
        found = [requirement for requirement in map(Requirement, self.project['optional-dependencies'][extra])
                 if requirement.name == 'cryptography'
                 and (requirement.marker is None or requirement.marker.evaluate(env(implementation, python)))]
        if not found:
            return 'excluded'
        self.assertEqual(len(found), 1, [str(requirement) for requirement in found])
        return 'included' if FIRST_WITHOUT_PP310 in found[0].specifier else 'capped'

    def test_pypy312_goes_without_cryptography(self) -> 'None':
        for extra in ('crypto', 'all'):
            with self.subTest(extra=extra):
                self.assertEqual(
                    [(implementation, python, self.verdict(extra, implementation, python))
                     for implementation, python, _ in EXPECTED],
                    list(EXPECTED))

    def test_pypy_exclusions_are_what_the_markers_leave_out(self) -> 'None':
        """Every gated distribution PyPy goes without, CPython keeping it, from ``since`` on.

        Over each Python version from ``requires-python``'s floor to ``latest``, so a
        new marker of the kind is a missing entry here, and a lifted one a stale entry.

        """
        latest = Version(tomllib.loads(VERSIONS.read_text(encoding='utf-8'))['latest'])
        floor = SpecifierSet(self.project['requires-python'])
        pythons = [f'3.{minor}' for minor in range(latest.minor + 1) if f'3.{minor}' in floor]

        declared = [Requirement(text) for text in self.project['dependencies']]
        declared += [Requirement(text) for extra in self.project['optional-dependencies'].values()
                     for text in extra]
        gated = {canonicalize_name(Requirement(provider).name)
                 for providers in _dependency_gates.MODULE_PROVIDERS.values()
                 for provider in providers if provider != _dependency_gates.CORE}

        def live(requirements: 'list[Requirement]', implementation: 'str', python: 'str') -> 'bool':
            return any(requirement.marker is None or requirement.marker.evaluate(env(implementation, python))
                       for requirement in requirements)

        derived = {}  # type: dict[str, Optional[str]]
        for name in sorted(gated):
            requirements = [requirement for requirement in declared if canonicalize_name(requirement.name) == name]
            dark = [python for python in pythons if requirements
                    and live(requirements, 'CPython', python) and not live(requirements, 'PyPy', python)]
            if not dark:
                continue
            with self.subTest(distribution=name):
                self.assertEqual(dark, pythons[pythons.index(dark[0]):],
                                 f'PyPy goes without {name} on {dark}, which is no "from a version on"')
            derived[name] = None if dark == pythons else dark[0]

        self.assertEqual({name: exclusion.since for name, exclusion in _dependency_gates.PYPY_EXCLUSIONS.items()},
                         derived)


if __name__ == '__main__':
    unittest.main()
