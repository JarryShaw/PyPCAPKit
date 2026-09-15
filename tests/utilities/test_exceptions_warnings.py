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
        # Only a *loud* error does this: `sys.tracebacklimit` is process-global,
        # and a quiet error is internal control flow that must not truncate
        # unrelated tracebacks. See tests/utilities/test_quiet_exceptions.py.
        original = getattr(sys, 'tracebacklimit', None)
        try:
            with mock.patch.object(self.exceptions, 'DEVMODE', False):
                with mock.patch.object(self.exceptions.logger, 'critical'):
                    self.exceptions.BaseError('boom')
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

    def test_warn_delivers_base_warning_categories_to_the_caller(self) -> None:
        # pcapkit no longer installs an `ignore` filter of its own, so a caller
        # who asks to see the warning sees it. Whether it is displayed, raised or
        # dropped is now entirely the application's decision -- see
        # tests/utilities/test_warning_filters.py for that contract in full.
        with mock.patch.object(self.warnings.logger, 'warning'):
            with pywarnings.catch_warnings(record=True) as records:
                pywarnings.simplefilter('always')
                self.warnings.warn('careful', self.warnings.FormatWarning, stacklevel=1)

        self.assertEqual(len(records), 1)
        self.assertIs(records[0].category, self.warnings.FormatWarning)

    def test_warn_passes_the_calculated_stacklevel_to_the_logger(self) -> None:
        with mock.patch.object(self.warnings, 'stacklevel_calculator', return_value=3):
            with mock.patch.object(self.warnings.logger, 'warning') as logger_warning:
                with pywarnings.catch_warnings(record=True) as records:
                    pywarnings.simplefilter('always')
                    self.warnings.warn('careful', UserWarning)

        self.assertEqual(len(records), 1)
        logger_warning.assert_called_once()
        self.assertEqual(logger_warning.call_args.kwargs['stacklevel'], 3)

    def test_constructing_a_base_warning_reports_nothing(self) -> None:
        # Constructing a warning is not reporting one: the constructor logs
        # nothing and installs no filter. See
        # tests/utilities/test_warning_emission.py for the devmode arm.
        with mock.patch.object(self.warnings.logger, 'warning') as logger_warning:
            filters = pywarnings.filters[:]
            warning = self.warnings.BaseWarning('dev warning')

        self.assertIsInstance(warning, self.warnings.BaseWarning)
        self.assertEqual(str(warning), 'dev warning')
        logger_warning.assert_not_called()
        self.assertEqual(pywarnings.filters, filters)


if __name__ == '__main__':
    unittest.main()
