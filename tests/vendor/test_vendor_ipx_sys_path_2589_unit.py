# -*- coding: utf-8 -*-
"""A failed IPX crawler import leaves :data:`sys.path` as it found it.

GitHub issue #2589. :mod:`pcapkit.vendor.ipx`, :mod:`pcapkit.vendor.ipx.packet`
and :mod:`pcapkit.vendor.ipx.socket` each pop ``sys.path[0]`` before their
imports and put it back after them. Run as a script, a crawler there has the
package directory as ``sys.path[0]``, and its sibling ``socket.py`` would then
shadow the standard library's :mod:`socket`, which ``requests`` imports through
:mod:`urllib3`. Without a ``finally``, an import that raises -- ``requests``
missing, say -- loses the popped entry. :func:`pkgutil.walk_packages` swallows
that :exc:`ImportError` and retries the import on every walk, so each walk loses
more, until ``sys.path.pop(0)`` raises :exc:`IndexError`.

``requests`` is hidden by binding it to :data:`None` in :data:`sys.modules`, so
importing it raises :exc:`ModuleNotFoundError` just as a missing package does,
whether or not it is installed here. The whole of :mod:`pcapkit.vendor` is
purged first, so each import runs its code again, and put back afterwards. The
package itself is in that region: an import that is first to load it does so
with ``requests`` hidden, which records ``requests`` in its ``_MISSING``.

Without the ``finally`` blocks every test here fails on the :data:`sys.path`
comparison.

"""
from __future__ import annotations

import importlib
import importlib.util
import pathlib
import sys
import unittest

from tests._support import isolate_modules

#: Test tier (#1958): import bookkeeping in pure Python, the same on every interpreter.
__tier__ = 'LATEST'

#: The package directory, which is ``sys.path[0]`` when a crawler in it runs as a script.
IPX_DIR = pathlib.Path(__file__).resolve().parents[2] / 'pcapkit' / 'vendor' / 'ipx'

#: The crawler modules of :mod:`pcapkit.vendor.ipx`, each of which pops and
#: restores ``sys.path[0]`` around its own imports.
CRAWLERS = ('packet', 'socket')

#: What the failing import raises on, and so the module this file hides.
HIDDEN = 'requests'

#: Marks :data:`HIDDEN` as absent from :data:`sys.modules` before the test.
_ABSENT = object()


class FailedImportKeepsSysPathTests(unittest.TestCase):
    """An IPX import that raises puts back the :data:`sys.path` entry it popped."""

    def setUp(self) -> None:
        isolate_modules(self, ('pcapkit.vendor',))

        # On an unfixed tree the import loses entries; restoring them keeps that
        # failure from breaking every import after this test.
        saved = list(sys.path)
        self.addCleanup(sys.path.__setitem__, slice(None), saved)

        held = sys.modules.get(HIDDEN, _ABSENT)
        sys.modules[HIDDEN] = None
        self.addCleanup(self._unhide, held)

    @staticmethod
    def _unhide(held: object) -> None:
        """Put :data:`HIDDEN` back in :data:`sys.modules` as it was before the test."""
        if held is _ABSENT:
            sys.modules.pop(HIDDEN, None)
        else:
            sys.modules[HIDDEN] = held

    def test_failed_package_import_keeps_sys_path(self) -> None:
        # The import pkgutil.walk_packages makes, and retries on every walk.
        expected = list(sys.path)
        with self.assertRaises(ImportError):
            importlib.import_module('pcapkit.vendor.ipx')
        self.assertEqual(sys.path, expected,
                         'a failed import of pcapkit.vendor.ipx lost a sys.path entry')

    def test_failed_crawler_run_as_script_keeps_sys_path(self) -> None:
        # Loaded from its file with the package directory first on sys.path, as
        # `python pcapkit/vendor/ipx/<crawler>.py` has it. The package import
        # above never reaches the socket crawler, as the packet crawler fails first.
        for name in CRAWLERS:
            with self.subTest(crawler=name):
                sys.path.insert(0, str(IPX_DIR))
                expected = list(sys.path)
                spec = importlib.util.spec_from_file_location(
                    f'_ipx_{name}_as_script', IPX_DIR / f'{name}.py')
                assert spec is not None and spec.loader is not None
                module = importlib.util.module_from_spec(spec)
                try:
                    with self.assertRaises(ImportError):
                        spec.loader.exec_module(module)
                    self.assertEqual(sys.path, expected,
                                     f'a failed run of the {name} crawler lost a sys.path entry')
                finally:
                    if sys.path and sys.path[0] == str(IPX_DIR):
                        del sys.path[0]


if __name__ == '__main__':
    unittest.main()
