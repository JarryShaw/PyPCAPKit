# -*- coding: utf-8 -*-
"""#2134: the timestamp conversions live in :mod:`pcapkit.utilities.datetime`.

The owner ruled on #2136 that the module reuses the stdlib name, as
:mod:`pcapkit.utilities.logging` and :mod:`pcapkit.utilities.warnings` do. The
old ``pcapkit.utilities.timestamp`` path was added by #2111 and is in no
release, so it is deleted rather than re-exported (#1715).

"""

import datetime
import importlib
import sys
import unittest

#: Test tier (#1958): a module-layout check, independent of the interpreter.
__tier__ = 'LATEST'


class TestDatetimeModule(unittest.TestCase):
    """:mod:`pcapkit.utilities.datetime` holds the conversions, and the old path is gone."""

    def test_new_module_exposes_the_conversions(self) -> None:
        module = importlib.import_module('pcapkit.utilities.datetime')
        self.assertEqual(sorted(module.__all__), ['fromtimestamp', 'totimestamp'])
        self.assertTrue(callable(module.fromtimestamp))
        self.assertTrue(callable(module.totimestamp))

    def test_new_module_imports_the_stdlib_datetime(self) -> None:
        module = importlib.import_module('pcapkit.utilities.datetime')
        self.assertIs(module.datetime, datetime)
        self.assertIs(sys.modules['datetime'], datetime)

    def test_old_module_path_is_gone(self) -> None:
        with self.assertRaises(ModuleNotFoundError):
            importlib.import_module('pcapkit.utilities.timestamp')


if __name__ == '__main__':
    unittest.main()
