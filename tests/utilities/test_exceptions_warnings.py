from __future__ import annotations

import sys
import unittest
import warnings as pywarnings
from unittest import mock

from tests._support import bootstrap_core_modules, purge_modules


class ExceptionsWarningsTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])
        modules = bootstrap_core_modules()
        self.exceptions = modules['exceptions']
        self.warnings = modules['warnings']

    def test_stacklevel_returns_integer(self) -> None:
        level = self.exceptions.stacklevel()
        self.assertIsInstance(level, int)

    def test_struct_error_records_eof_flag(self) -> None:
        error = self.exceptions.StructError('truncated', eof=True, quiet=True)
        self.assertTrue(error.eof)
        self.assertEqual(str(error), 'truncated')

    def test_base_error_limits_traceback_in_non_dev_mode(self) -> None:
        original = getattr(sys, 'tracebacklimit', None)
        try:
            with mock.patch.object(self.exceptions, 'DEVMODE', False):
                self.exceptions.BaseError('boom', quiet=True)
            self.assertEqual(sys.tracebacklimit, 0)
        finally:
            if original is None:
                if hasattr(sys, 'tracebacklimit'):
                    del sys.tracebacklimit
            else:
                sys.tracebacklimit = original

    def test_base_error_devmode_logs_with_verbose_metadata(self) -> None:
        with mock.patch.object(self.exceptions, 'DEVMODE', True):
            with mock.patch.object(self.exceptions, 'VERBOSE', True):
                with mock.patch.object(self.exceptions.logger, 'critical') as critical:
                    self.exceptions.BaseError('boom')

        critical.assert_called_once()
        self.assertTrue(critical.call_args.kwargs['stack_info'])

    def test_warn_suppresses_base_warning_categories_outside_dev_mode(self) -> None:
        with mock.patch.object(self.warnings, 'DEVMODE', False):
            with pywarnings.catch_warnings(record=True) as records:
                pywarnings.simplefilter('always')
                self.warnings.warn('careful', self.warnings.FormatWarning, stacklevel=1)

        self.assertEqual(records, [])

    def test_warn_default_stacklevel_and_base_warning_devmode_logging(self) -> None:
        with mock.patch.object(self.warnings, 'stacklevel_calculator', return_value=3):
            with mock.patch.object(self.warnings.logger, 'warning') as logger_warning:
                with pywarnings.catch_warnings(record=True) as records:
                    pywarnings.simplefilter('always')
                    self.warnings.warn('careful', UserWarning)

        self.assertEqual(len(records), 1)
        self.assertEqual(logger_warning.call_args.kwargs['stacklevel'], 3)

        with mock.patch.object(self.warnings, 'DEVMODE', True):
            with mock.patch.object(self.warnings, 'VERBOSE', True):
                with mock.patch.object(self.warnings.logger, 'warning') as logger_warning:
                    warning = self.warnings.BaseWarning('dev warning')
        self.assertIsInstance(warning, self.warnings.BaseWarning)
        logger_warning.assert_called_once()
        self.assertTrue(logger_warning.call_args.kwargs['stack_info'])

        with mock.patch.object(self.warnings, 'DEVMODE', True):
            with mock.patch.object(self.warnings, 'VERBOSE', False):
                with mock.patch.object(self.warnings.logger, 'warning') as logger_warning:
                    self.warnings.BaseWarning('dev warning')
        logger_warning.assert_called_once_with('dev warning')


if __name__ == '__main__':
    unittest.main()
