"""Regression tests for GH-363 -- one :func:`~pcapkit.utilities.warnings.warn`
call must produce exactly one record on each channel.

The emission model, which these tests pin:

* exactly **one** :mod:`logging` record, on the ``pcapkit`` logger, at
  ``WARNING`` level, whatever the warning filters say;
* exactly **one** :mod:`warnings`-module emission, subject to the filters;
* **the same counts in development mode and out of it** --
  :envvar:`PCAPKIT_DEVMODE` and :envvar:`PCAPKIT_VERBOSE` change how much detail
  the log record carries, never how many records there are;
* constructing a warning category is **not** an emission, and reports nothing.

Before the fix the counts were: 1 outside development mode (the
:mod:`warnings` emission was swallowed by the filter the constructor installed --
see GH-364) and 3 in development mode (two log records, from ``warn()`` and again
from ``BaseWarning.__init__``, plus the :mod:`warnings` emission).

"""
from __future__ import annotations

import os
import unittest
import warnings as pywarnings
from unittest import mock

from tests._support import purge_modules
from tests.utilities._harness import bootstrap, capture


class WarningEmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._saved_devmode = os.environ.get('PCAPKIT_DEVMODE')

    def tearDown(self) -> None:
        if self._saved_devmode is None:
            os.environ.pop('PCAPKIT_DEVMODE', None)
        else:
            os.environ['PCAPKIT_DEVMODE'] = self._saved_devmode
        purge_modules(['pcapkit'])

    def emissions(self, devmode: 'bool', verbose: 'bool' = False,
                  category: 'type | None' = None) -> 'tuple[list, list]':
        """Report one warning and return ``(log records, warnings emissions)``."""
        modules = bootstrap(devmode=devmode)
        warnings_module = modules['warnings']
        logger = modules['logging'].logger
        if category is None:
            category = warnings_module.SchemaWarning

        with mock.patch.object(warnings_module, 'VERBOSE', verbose):
            with capture(logger) as recorder:
                with pywarnings.catch_warnings(record=True) as records:
                    pywarnings.resetwarnings()
                    pywarnings.simplefilter('always')
                    warnings_module.warn('a complaint', category, stacklevel=1)
        return recorder.records, list(records)

    def test_one_record_per_channel_outside_devmode(self) -> None:
        records, emissions = self.emissions(devmode=False)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].levelname, 'WARNING')
        self.assertEqual(records[0].getMessage(), 'a complaint')

        self.assertEqual(len(emissions), 1)
        self.assertEqual(str(emissions[0].message), 'a complaint')

    def test_one_record_per_channel_in_devmode(self) -> None:
        records, emissions = self.emissions(devmode=True)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].levelname, 'WARNING')
        self.assertEqual(records[0].getMessage(), 'a complaint')

        self.assertEqual(len(emissions), 1)
        self.assertEqual(str(emissions[0].message), 'a complaint')

    def test_counts_do_not_depend_on_devmode_or_verbose(self) -> None:
        for devmode in (False, True):
            for verbose in (False, True):
                with self.subTest(devmode=devmode, verbose=verbose):
                    records, emissions = self.emissions(devmode=devmode, verbose=verbose)
                    self.assertEqual(len(records), 1)
                    self.assertEqual(len(emissions), 1)

    def test_a_non_pcapkit_category_is_reported_the_same_way(self) -> None:
        """The counts must not depend on the category being a ``BaseWarning``.

        A ``BaseWarning`` used to be reported a different number of times from a
        plain :exc:`UserWarning`, because only the former ran the constructor that
        logged and filtered.

        """
        for devmode in (False, True):
            with self.subTest(devmode=devmode):
                records, emissions = self.emissions(devmode=devmode, category=UserWarning)
                self.assertEqual(len(records), 1)
                self.assertEqual(len(emissions), 1)

    def test_constructing_a_warning_reports_nothing(self) -> None:
        """Building a warning object is not reporting a warning."""
        for devmode in (False, True):
            with self.subTest(devmode=devmode):
                modules = bootstrap(devmode=devmode)
                warnings_module = modules['warnings']

                with capture(modules['logging'].logger) as recorder:
                    with pywarnings.catch_warnings(record=True) as records:
                        pywarnings.resetwarnings()
                        pywarnings.simplefilter('always')
                        warning = warnings_module.SchemaWarning('just constructing the object')

                self.assertIsInstance(warning, warnings_module.BaseWarning)
                self.assertEqual(str(warning), 'just constructing the object')
                self.assertEqual(recorder.messages, [])
                self.assertEqual(list(records), [])

    def test_the_log_record_is_emitted_even_when_the_category_is_filtered_out(self) -> None:
        """The two channels are independent: filtering one does not mute the other."""
        modules = bootstrap(devmode=False)
        warnings_module = modules['warnings']

        with capture(modules['logging'].logger) as recorder:
            with pywarnings.catch_warnings(record=True) as records:
                pywarnings.resetwarnings()
                pywarnings.simplefilter('ignore')
                warnings_module.warn('a complaint', warnings_module.SchemaWarning, stacklevel=1)

        self.assertEqual(len(recorder.records), 1)
        self.assertEqual(list(records), [])


if __name__ == '__main__':
    unittest.main()
