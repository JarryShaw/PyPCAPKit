# -*- coding: utf-8 -*-
"""GitHub issue #1712: the bounded-cache :mod:`chardet` wrapper lives in corekit.

:func:`~pcapkit.corekit.chardet.detect` and
:data:`~pcapkit.corekit.chardet.DETECT_CACHE_SIZE` moved from
``pcapkit.utilities.chardet`` to :mod:`pcapkit.corekit.chardet`, and the
``pcapkit.utilities.detect`` re-export went with them: the owner's ruling on
#1715, applied to #1712, is that a move updates every import path directly and
leaves no re-export behind. This pins that the old path no longer imports, that
every caller uses the new module, and that the move adds no import cycle -- the
new module imports nothing from :mod:`pcapkit`, and :mod:`pcapkit.utilities`
still imports nothing from :mod:`pcapkit.corekit`.

"""

import ast
import importlib
import json
import pathlib
import subprocess  # nosec: B404
import sys
import unittest

from tests._support import reimport_once_per_class
from tests.corekit._roundtrip import skip_without_runtime

ROOT = pathlib.Path(__file__).resolve().parents[2]

NEW_PATH = 'pcapkit.corekit.chardet'

#: Where the wrapper lived before #1712; removed, not re-exported.
OLD_PATH = 'pcapkit.utilities.chardet'

#: Every module that calls :func:`~pcapkit.corekit.chardet.detect`.
CALLERS = (
    'pcapkit.corekit.fields.strings',
    'pcapkit.protocols.protocol',
    'pcapkit.protocols.application.ftp',
    'pcapkit.protocols.application.httpv1',
)


def imported_modules(path: 'pathlib.Path') -> 'list[str]':
    """Every module ``path`` imports, read with :mod:`ast` rather than imported."""
    names = []
    for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.append('.' * node.level + (node.module or ''))
    return names


class ChardetHousingTests(unittest.TestCase):
    """The wrapper is at :data:`NEW_PATH` and nowhere else."""

    def setUp(self) -> None:
        skip_without_runtime(self)
        reimport_once_per_class(self)

    def test_the_old_import_path_no_longer_imports(self) -> None:
        """No re-export is left at ``pcapkit.utilities.chardet``."""
        with self.assertRaises(ModuleNotFoundError) as ctx:
            importlib.import_module(OLD_PATH)
        self.assertEqual(ctx.exception.name, OLD_PATH)

    def test_detect_is_no_longer_reexported(self) -> None:
        """``detect`` is gone from :mod:`pcapkit.utilities`, and so from :mod:`pcapkit.all`."""
        for package in ('pcapkit.utilities', 'pcapkit.all'):
            with self.subTest(package=package):
                module = importlib.import_module(package)
                self.assertNotIn('detect', getattr(module, '__all__', ()))
                self.assertFalse(hasattr(module, 'detect'))

    def test_the_wrapper_keeps_its_bound(self) -> None:
        """The cache stays bounded at :data:`~pcapkit.corekit.chardet.DETECT_CACHE_SIZE`."""
        module = importlib.import_module(NEW_PATH)
        self.assertEqual(module.__all__, ['detect'])
        self.assertEqual(module.DETECT_CACHE_SIZE, 1024)
        self.assertEqual(module.detect.cache_info().maxsize, module.DETECT_CACHE_SIZE)

    def test_every_caller_uses_the_new_module(self) -> None:
        """Each caller holds the one cached function, so they share its cache."""
        detect = importlib.import_module(NEW_PATH).detect
        for name in CALLERS:
            with self.subTest(module=name):
                self.assertIs(importlib.import_module(name).detect, detect)


class ChardetLayeringTests(unittest.TestCase):
    """The move adds no edge that could close an import cycle."""

    def test_the_new_module_imports_nothing_from_pcapkit(self) -> None:
        """A leaf module cannot close a cycle through its importers."""
        path = ROOT.joinpath(*NEW_PATH.split('.')).with_suffix('.py')
        names = imported_modules(path)
        self.assertIn('chardet', names)
        self.assertEqual([name for name in names if name.startswith(('pcapkit', '.'))], [])

    def test_utilities_imports_nothing_from_corekit(self) -> None:
        """:mod:`pcapkit.utilities` sits below :mod:`pcapkit.corekit` and does not reach up."""
        for path in sorted(ROOT.joinpath('pcapkit', 'utilities').glob('*.py')):
            with self.subTest(path=path.name):
                self.assertEqual([name for name in imported_modules(path)
                                  if name.startswith('pcapkit.corekit')], [])

    def test_the_new_module_imports_first_in_a_fresh_interpreter(self) -> None:
        """Imported first, from the tree under test, with nothing loaded at the old path."""
        skip_without_runtime(self)
        script = ('import json, sys, pcapkit.corekit.chardet as m; '
                  'print(json.dumps([m.__file__, sorted(n for n in sys.modules'
                  ' if n.startswith("pcapkit.") and n.endswith(".chardet"))]))')
        proc = subprocess.run([sys.executable, '-c', script], cwd=str(ROOT),  # nosec: B603
                              capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        path, loaded = json.loads(proc.stdout.splitlines()[-1])
        self.assertEqual(pathlib.Path(path).resolve(), ROOT / 'pcapkit' / 'corekit' / 'chardet.py')
        self.assertEqual(loaded, [NEW_PATH])


if __name__ == '__main__':
    unittest.main()
