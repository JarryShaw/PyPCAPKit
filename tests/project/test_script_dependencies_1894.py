# -*- coding: utf-8 -*-
"""#1894: what the scripts import is declared alike for CI and for the dev environment.

The scripts under :file:`util/` and :file:`examples/generators/` fetch with
``requests``, sample memory with ``psutil``, parse XML with ``lxml`` and read a
Markdown table with ``markdown-it-py``. The ``test`` extra in
:file:`pyproject.toml` carries them for CI; at the owner's request
:file:`Pipfile`'s ``[dev-packages]``, which ``make``'s ``pipenv run`` targets
resolve against, carries them too, with the ``test`` extra's markers. Those keep
each off the interpreters PyPI has no wheel of it for: ``psutil`` and ``lxml``
are CPython only (``lxml`` by #1958), as PyPI has none of it for GraalPy or PyPy
8.0. The ``dev`` extra is not asked: it holds what the toolchain linting
:mod:`pcapkit` must resolve, not the scripts' dependencies.

"""

from __future__ import annotations

import pathlib
import re
import unittest
from typing import TYPE_CHECKING

from tests.project.test_python_versions_1660 import NO_TOMLLIB, tomllib

if TYPE_CHECKING:
    from typing import Any, Optional

if tomllib is None:
    raise unittest.SkipTest(NO_TOMLLIB)

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The distributions the scripts import, by their PyPI names.
SCRIPT_DEPENDENCIES = ('requests', 'psutil', 'lxml', 'markdown-it-py')

#: A requirement string's distribution name, before any extras, specifier or marker.
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]*')


def canonical(name: 'str') -> 'str':
    """``name`` as PEP 503 normalises it."""
    return re.sub(r'[-_.]+', '-', name).lower()


def extra(name: 'str') -> 'dict[str, Optional[str]]':
    """``pyproject.toml``'s extra ``name``: each distribution's marker as written, or :data:`None`."""
    project = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))['project']
    found = {}  # type: dict[str, Optional[str]]
    for line in project['optional-dependencies'][name]:
        match = NAME.match(line)
        assert match is not None, line
        _, _, marker = line.partition(';')
        found[canonical(match.group(0))] = marker.strip() or None
    return found


def dev_packages() -> 'dict[str, Optional[str]]':
    """:file:`Pipfile`'s ``[dev-packages]``: each distribution's marker as written, or :data:`None`."""
    pipfile = tomllib.loads((ROOT / 'Pipfile').read_text(encoding='utf-8'))
    found = {}  # type: dict[str, Optional[str]]
    for name, spec in pipfile['dev-packages'].items():  # type: str, Any
        found[canonical(name)] = spec.get('markers') if isinstance(spec, dict) else None
    return found


class TestTheScriptDependencies(unittest.TestCase):
    """The ``test`` extra's entries, and the same entries in the Pipfile."""

    def test_the_test_extra_carries_them_with_their_markers(self) -> None:
        test = extra('test')
        self.assertEqual({name: test.get(name, 'absent') for name in SCRIPT_DEPENDENCIES}, {
            'requests': None,
            'psutil': "platform_python_implementation == 'CPython'",
            'lxml': "platform_python_implementation == 'CPython'",
            'markdown-it-py': None,
        })

    def test_the_pipfile_dev_packages_have_the_test_extras_markers(self) -> None:
        test, pipfile = extra('test'), dev_packages()
        for name in SCRIPT_DEPENDENCIES:
            with self.subTest(name=name):
                self.assertIn(name, pipfile, f"the Pipfile's [dev-packages] does not carry {name}")
                self.assertEqual(pipfile[name], test[name])


if __name__ == '__main__':
    unittest.main()
