# -*- coding: utf-8 -*-
"""#2062: the setuptools floor is one that ships ``pcapkit/py.typed``.

Nothing declares ``py.typed``: :file:`MANIFEST.in` includes ``*.py`` alone, and
:file:`pyproject.toml` has no ``package-data`` entry for ``pcapkit``. setuptools
69.0.0 is the first release that packages it regardless (pypa/setuptools#3136,
in that release's ``NEWS.rst``), measured: a wheel built with 68.2.2 leaves it
out, and one built with 69.0.0 has it. Pinned here:

* ``[build-system] requires`` floors setuptools at 69.0.0 or later;
* every setuptools pin in :file:`conda/pypcapkit/meta.yaml` matches that floor.

These read the declarations, not a built wheel: they catch the floor being
lowered, not a later setuptools release dropping the behaviour.

"""

from __future__ import annotations

import pathlib
import re
import unittest

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

#: Test tier (#1958): reads pyproject.toml and the conda recipe, the same on every leg.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The first setuptools that packages ``py.typed`` without being told to (#2062).
FIRST_WITH_PY_TYPED = (69, 0, 0)

#: A ``setuptools>=X.Y.Z`` requirement, as either file spells it.
FLOOR = re.compile(r'^\s*(?:-\s*)?setuptools\s*>=\s*(\d+)\.(\d+)\.(\d+)\s*$')


def floors(lines: 'list[str]') -> 'list[tuple[int, int, int]]':
    """Every ``setuptools>=`` floor in ``lines``."""
    return [tuple(int(part) for part in match.groups())  # type: ignore[misc]
            for match in map(FLOOR.match, lines) if match]


class SetuptoolsFloorTests(unittest.TestCase):
    """The build floor packages ``py.typed``, and conda agrees with it."""

    def setUp(self) -> None:
        if tomllib is None:  # pragma: no cover
            self.skipTest('tomllib needs Python 3.11')
        pyproject = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))
        requires = pyproject['build-system']['requires']
        self.assertEqual([text for text in requires if text.startswith('setuptools')],
                         [text for text in requires if FLOOR.match(text)],
                         'every setuptools requirement should be a plain ">=" floor')
        self.floors = floors(requires)

    def test_build_floor_ships_py_typed(self) -> None:
        self.assertEqual(len(self.floors), 1, self.floors)
        self.assertGreaterEqual(self.floors[0], FIRST_WITH_PY_TYPED,
                                'setuptools older than 69.0.0 builds wheels without pcapkit/py.typed')

    def test_conda_pins_match_the_build_floor(self) -> None:
        lines = (ROOT / 'conda' / 'pypcapkit' / 'meta.yaml').read_text(encoding='utf-8').splitlines()
        pins = floors(lines)
        self.assertTrue(pins, 'the conda recipe pins no setuptools floor')
        self.assertEqual(set(pins), set(self.floors))

    def test_py_typed_exists(self) -> None:
        self.assertTrue((ROOT / 'pcapkit' / 'py.typed').is_file())


if __name__ == '__main__':
    unittest.main()
