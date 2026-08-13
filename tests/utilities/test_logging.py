from __future__ import annotations

import os
import unittest

from tests._support import load_module, purge_modules


class LoggingTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])
        self._saved = {key: os.environ.get(key) for key in ('PCAPKIT_DEVMODE', 'PCAPKIT_VERBOSE', 'PCAPKIT_SPHINX')}

    def tearDown(self) -> None:
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        purge_modules(['pcapkit'])

    def test_boolean_environment_flags_are_parsed(self) -> None:
        os.environ['PCAPKIT_DEVMODE'] = 'yes'
        os.environ['PCAPKIT_VERBOSE'] = 'on'
        os.environ['PCAPKIT_SPHINX'] = 'true'

        logging_module = load_module('pcapkit.utilities.logging', 'pcapkit/utilities/logging.py')

        self.assertTrue(logging_module.DEVMODE)
        self.assertTrue(logging_module.VERBOSE)
        self.assertTrue(logging_module.SPHINX_TYPE_CHECKING)

    def test_invalid_boolean_environment_values_fall_back_to_false(self) -> None:
        os.environ['PCAPKIT_DEVMODE'] = 'maybe'
        os.environ['PCAPKIT_VERBOSE'] = 'sometimes'
        os.environ['PCAPKIT_SPHINX'] = 'idk'

        logging_module = load_module('pcapkit.utilities.logging', 'pcapkit/utilities/logging.py')

        self.assertFalse(logging_module.DEVMODE)
        self.assertFalse(logging_module.VERBOSE)
        self.assertFalse(logging_module.SPHINX_TYPE_CHECKING)

    def test_utilities_package_re_exports_common_helpers(self) -> None:
        package = load_module('pcapkit.utilities', 'pcapkit/utilities/__init__.py')

        self.assertIn('logger', package.__all__)
        self.assertTrue(callable(package.warn))
        self.assertTrue(callable(package.stacklevel))


if __name__ == '__main__':
    unittest.main()
