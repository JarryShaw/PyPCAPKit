"""Regression tests for GH-364 -- constructing a pcapkit warning must not touch
the process-global :data:`warnings.filters`.

``BaseWarning.__init__`` used to call ``warnings.simplefilter('ignore',
type(self))`` outside development mode. That inserted an entry at index 0 of the
filter list -- *ahead* of everything the interpreter, :option:`-W` and the host
application had put there -- and never removed it. Two consequences reached code
that has nothing to do with :mod:`pcapkit`:

1. the application's own configuration for the category was overridden, so
   ``-W error`` and a programmatic :func:`warnings.simplefilter` were both
   defeated;
2. :func:`warnings.simplefilter` calls ``warnings._filters_mutated()``, which
   invalidates every module's ``__warningregistry__``, so an unrelated
   once-per-location warning was reported a second time.

Every test here forces ``PCAPKIT_DEVMODE=0``, because the defect only reproduced
outside development mode -- in development mode the constructor logged instead of
filtering, and these assertions would pass against the unfixed code.

"""
from __future__ import annotations

import os
import unittest
import warnings as pywarnings

from tests._support import purge_modules
from tests.utilities import _unrelated_warning
from tests.utilities._harness import bootstrap, capture

#: Every warning category the module exports, by name.
CATEGORY_NAMES = [
    'BaseWarning',
    'FormatWarning', 'EngineWarning', 'InvalidVendorWarning',
    'FileWarning', 'LayerWarning', 'ProtocolWarning', 'AttributeWarning',
    'DevModeWarning', 'VendorRequestWarning', 'VendorRuntimeWarning',
    'UnknownFieldWarning', 'RegistryWarning', 'SchemaWarning', 'InfoWarning',
    'SeekWarning', 'ExtractionWarning',
    'DPKTWarning', 'ScapyWarning', 'PySharkWarning', 'EmojiWarning',
    'VendorWarning',
    'DeprecatedFormatWarning',
]


class WarningFilterTests(unittest.TestCase):
    def setUp(self) -> None:
        self._saved_devmode = os.environ.get('PCAPKIT_DEVMODE')
        modules = bootstrap(devmode=False)
        self.warnings = modules['warnings']
        self.logger = modules['logging'].logger

    def tearDown(self) -> None:
        if self._saved_devmode is None:
            os.environ.pop('PCAPKIT_DEVMODE', None)
        else:
            os.environ['PCAPKIT_DEVMODE'] = self._saved_devmode
        purge_modules(['pcapkit'])

    def categories(self) -> 'list[type]':
        return [getattr(self.warnings, name) for name in CATEGORY_NAMES]

    def test_constructing_a_warning_leaves_the_global_filters_identical(self) -> None:
        """Construct every category and require the filter list to be unchanged."""
        with pywarnings.catch_warnings():
            # A stand-in for the configuration an application, a test runner or
            # `-W` would have installed: `error` for the unrelated category,
            # `ignore` for a category pcapkit does use.
            pywarnings.resetwarnings()
            pywarnings.simplefilter('always')
            pywarnings.filterwarnings('error', category=_unrelated_warning.UnrelatedWarning)
            pywarnings.filterwarnings('ignore', category=DeprecationWarning)
            snapshot = pywarnings.filters[:]

            for category in self.categories():
                category('just constructing the object')

            self.assertEqual(pywarnings.filters, snapshot)
            # Called out separately: index 0 is the slot `simplefilter` used to
            # take over, and the one that decides which action wins.
            self.assertEqual(pywarnings.filters[0], snapshot[0])
            self.assertEqual(len(pywarnings.filters), len(snapshot))

    def test_warn_leaves_the_global_filters_identical(self) -> None:
        """The same, going through :func:`warn` rather than the constructor."""
        with capture(self.logger):
            with pywarnings.catch_warnings(record=True):
                pywarnings.resetwarnings()
                pywarnings.simplefilter('always')
                snapshot = pywarnings.filters[:]

                self.warnings.warn('a complaint', self.warnings.SchemaWarning, stacklevel=1)

                self.assertEqual(pywarnings.filters, snapshot)

    def test_application_filter_configuration_is_honoured(self) -> None:
        """``simplefilter('error')`` must turn a pcapkit warning into an error.

        This is the programmatic equivalent of ``python -W error``, which the
        index-0 override used to defeat.

        """
        with capture(self.logger):
            with pywarnings.catch_warnings():
                pywarnings.resetwarnings()
                pywarnings.simplefilter('error')

                with self.assertRaises(self.warnings.SchemaWarning):
                    self.warnings.warn('a complaint', self.warnings.SchemaWarning, stacklevel=1)

    def test_application_can_still_silence_pcapkit_warnings(self) -> None:
        """The suppression pcapkit used to impose must remain available to the caller."""
        with capture(self.logger):
            with pywarnings.catch_warnings(record=True) as records:
                pywarnings.resetwarnings()
                pywarnings.simplefilter('always')
                pywarnings.filterwarnings('ignore', category=self.warnings.BaseWarning)

                self.warnings.warn('a complaint', self.warnings.SchemaWarning, stacklevel=1)

            self.assertEqual([record.message for record in records], [])

    def test_a_standard_base_category_filter_reaches_pcapkit_warnings(self) -> None:
        """``-W ignore::UserWarning`` and friends must reach pcapkit's categories.

        This is the command-line escape hatch the documentation offers, since
        :option:`-W` cannot name a pcapkit category directly -- CPython resolves
        the category before :mod:`site` puts ``site-packages`` on
        :data:`sys.path`. Filtering on the standard category each pcapkit warning
        is mixed with is what works, so the mixin has to keep working.

        """
        cases = [
            (UserWarning, self.warnings.SchemaWarning),
            (RuntimeWarning, self.warnings.SchemaWarning),
            (ImportWarning, self.warnings.FormatWarning),
            (ResourceWarning, self.warnings.DPKTWarning),
            (DeprecationWarning, self.warnings.DeprecatedFormatWarning),
        ]
        for standard, pcapkit_category in cases:
            with self.subTest(standard=standard.__name__,
                              category=pcapkit_category.__name__):
                self.assertTrue(issubclass(pcapkit_category, standard))

                with capture(self.logger):
                    with pywarnings.catch_warnings():
                        pywarnings.resetwarnings()
                        pywarnings.simplefilter('always')
                        pywarnings.filterwarnings('error', category=standard)

                        with self.assertRaises(pcapkit_category):
                            self.warnings.warn('a complaint', pcapkit_category, stacklevel=1)

    def test_unrelated_category_configuration_survives(self) -> None:
        """A filter for a category pcapkit has never heard of keeps working."""
        with capture(self.logger):
            with pywarnings.catch_warnings():
                pywarnings.resetwarnings()
                pywarnings.simplefilter('always')
                pywarnings.filterwarnings('error', category=_unrelated_warning.UnrelatedWarning)

                for category in self.categories():
                    category('just constructing the object')
                self.warnings.warn('a complaint', self.warnings.SchemaWarning, stacklevel=1)

                with self.assertRaises(_unrelated_warning.UnrelatedWarning):
                    _unrelated_warning.emit()

    def refire_probe(self, middle: 'object') -> 'tuple[int, int]':
        """Count an unrelated module's warnings before and after ``middle`` runs.

        Emits the unrelated warning twice under the ``default`` action, so the
        second one is de-duplicated, then runs ``middle``, then emits a third
        time. Returns ``(count after two, count after three)``; equal values mean
        de-duplication survived whatever ``middle`` did.

        """
        with pywarnings.catch_warnings(record=True) as records:
            pywarnings.resetwarnings()
            pywarnings.simplefilter('default')

            _unrelated_warning.emit()
            _unrelated_warning.emit()
            deduplicated = len([record for record in records
                                if record.category is _unrelated_warning.UnrelatedWarning])

            middle()  # type: ignore[operator]

            _unrelated_warning.emit()
            afterwards = len([record for record in records
                              if record.category is _unrelated_warning.UnrelatedWarning])
        return deduplicated, afterwards

    def test_unrelated_warnings_do_not_refire(self) -> None:
        """An unrelated de-duplicated warning must not be reported again.

        The control arm establishes that the probe can tell the two apart: a
        plain :func:`warnings.warn` in the middle does not disturb the registry,
        so if the pcapkit arm shows a re-fire it is pcapkit's doing.

        """
        control = self.refire_probe(lambda: pywarnings.warn('control', DeprecationWarning))
        self.assertEqual(control, (1, 1), 'control arm re-fired; the probe cannot '
                                          'attribute a re-fire to pcapkit')

        with capture(self.logger):
            constructed = self.refire_probe(lambda: self.warnings.SchemaWarning('probe'))
            reported = self.refire_probe(
                lambda: self.warnings.warn('probe', self.warnings.SchemaWarning, stacklevel=1))

        self.assertEqual(constructed, (1, 1))
        self.assertEqual(reported, (1, 1))


if __name__ == '__main__':
    unittest.main()
