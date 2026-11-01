# -*- coding: utf-8 -*-
"""Pins that every importable shipped module has a documentation entry (#2559).

The *Resolvable Targets* section of
:file:`docs/source/contributing/conventions/documentation.rst` rules that every
importable module under :file:`pcapkit/` is documented, the placeholder sources
under :file:`pcapkit/protocols/*/NotImplemented/` being the one exception.

* :class:`ModulePageTests` -- every module outside the exception is named by a
  ``module``, ``currentmodule`` or ``automodule`` directive under
  :file:`docs/source/`, and no module inside it is.

The check is textual and imports nothing.

"""

from __future__ import annotations

import pathlib
import re
import unittest

#: Test tier (#1958): reads the package tree and the docs pages, and imports nothing.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The package whose modules must be documented, and the pages documenting them.
PACKAGE = ROOT / 'pcapkit'
DOCS = ROOT / 'docs' / 'source'

#: The directory name of the placeholder sources the convention exempts.
EXEMPT_DIR = 'NotImplemented'

#: A directive that names a module, capturing the dotted name.
DIRECTIVE = re.compile(r'^\.\. +(?:py:)?(?:module|currentmodule|automodule):: +(\S+)', re.M)


def _modules() -> 'dict[str, bool]':
    """Every module under :data:`PACKAGE`, mapped to whether it is in the exempt set."""
    found = {}  # type: dict[str, bool]
    for path in PACKAGE.rglob('*.py'):
        rel = path.relative_to(ROOT).with_suffix('')
        if '__pycache__' in rel.parts:
            continue
        parts = rel.parts[:-1] if rel.name == '__init__' else rel.parts
        found['.'.join(parts)] = EXEMPT_DIR in parts
    return found


def _documented() -> 'set[str]':
    """Every dotted name a module directive under :data:`DOCS` declares."""
    names = set()  # type: set[str]
    for page in DOCS.rglob('*.rst'):
        names.update(DIRECTIVE.findall(page.read_text(encoding='utf-8')))
    return names


class ModulePageTests(unittest.TestCase):
    """Every shipped module has an entry, and the exempt set has none."""

    modules = _modules()
    documented = _documented()

    def test_every_module_is_documented(self) -> 'None':
        """A module outside the exception with no directive names the page it needs."""
        missing = sorted(name for name, exempt in self.modules.items()
                         if not exempt and name not in self.documented)
        self.assertEqual(missing, [], 'add a page or a module directive for each of these')

    def test_exempt_modules_have_no_entry(self) -> 'None':
        """The exception exists, and documenting one of its modules breaks the convention's claim."""
        exempt = {name for name, flag in self.modules.items() if flag}
        self.assertTrue(exempt, f'no module under a {EXEMPT_DIR}/ directory; update the convention')
        self.assertEqual(sorted(exempt & self.documented), [])


if __name__ == '__main__':
    unittest.main()
