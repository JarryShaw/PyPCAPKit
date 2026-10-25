# -*- coding: utf-8 -*-
"""#2051: 1.5.0 requires Python 3.8, and nothing converts the sources.

The owner ruled on #2040 for a ``requires-python`` of ``>=3.8`` and none of the
``bpc-*`` backport tools, which are no longer maintained. Pinned here:

* ``requires-python`` is floored at 3.8, and at nothing else;
* no requirement in :file:`pyproject.toml` names a ``bpc-`` distribution;
* no requirement carries a ``python_version`` marker that reads the same on every
  version from the floor up, such as ``>= '3.7'`` on ``scapy``;
* :file:`vermin.ini` targets the floor.

"""

from __future__ import annotations

import pathlib
import re
import unittest

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

#: Test tier (#1958): reads pyproject.toml and vermin.ini, the same on every leg.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The floor #2051 set.
FLOOR = (3, 8)

#: A ``python_version`` comparison in a requirement's marker.
MARKER = re.compile(r'''python_version\s*(<=|>=|==|!=|<|>)\s*['"](\d+)\.(\d+)['"]''')


def constant_from_floor(operator: 'str', version: 'tuple[int, int]') -> 'bool':
    """Whether ``python_version <operator> version`` reads the same on every version from :data:`FLOOR`."""
    if operator in ('<', '>='):
        return version <= FLOOR
    return version < FLOOR


class RequiresPythonFloorTests(unittest.TestCase):
    """``requires-python``, the requirements and vermin agree on 3.8."""

    def setUp(self) -> None:
        if tomllib is None:  # pragma: no cover
            self.skipTest('tomllib needs Python 3.11')
        self.pyproject = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))

    def requirements(self) -> 'list[tuple[str, str]]':
        """Every requirement string, with where it is declared."""
        project = self.pyproject['project']
        found = [('build-system.requires', text) for text in self.pyproject['build-system']['requires']]
        found += [('project.dependencies', text) for text in project['dependencies']]
        for extra, texts in project['optional-dependencies'].items():
            found += [(f'project.optional-dependencies.{extra}', text) for text in texts]
        return found

    def test_requires_python_is_floored_at_3_8(self) -> None:
        clauses = [clause.strip() for clause in self.pyproject['project']['requires-python'].split(',')]
        floors = [clause for clause in clauses if clause.startswith('>')]
        self.assertEqual(floors, ['>=3.8'])

    def test_no_bpc_requirement_remains(self) -> None:
        stale = [f'{where}: {text}' for where, text in self.requirements()
                 if re.match(r'\s*bpc-', text, re.IGNORECASE)]
        self.assertEqual(stale, [])

    def test_no_marker_is_constant_from_the_floor(self) -> None:
        constant = [f'{where}: {text}' for where, text in self.requirements()
                    for operator, major, minor in MARKER.findall(text)
                    if constant_from_floor(operator, (int(major), int(minor)))]
        self.assertEqual(constant, [])

    def test_vermin_targets_the_floor(self) -> None:
        text = (ROOT / 'vermin.ini').read_text(encoding='utf-8')
        self.assertEqual(re.findall(r'(?m)^targets = (.+)$', text), ['3.8'])


if __name__ == '__main__':
    unittest.main()
