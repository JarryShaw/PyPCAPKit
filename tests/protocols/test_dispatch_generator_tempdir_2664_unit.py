# -*- coding: utf-8 -*-
"""The dispatch generator removes the capture it writes to probe a case (#2664).

:func:`examples.generators.dispatch._extract_first` wrote each probe capture into
a directory of its own and never removed it, so every run of the generator, or of
:file:`test_dispatch_registry_unit.py`, left a :file:`pcapkit-dispatch-*`
directory in the temporary directory for each case it probed.

Each test points :data:`tempfile.tempdir` at a directory of its own, so the
directories a probe makes are the only ones it can see, and none from another
process or test is mistaken for a leak.

"""
from __future__ import annotations

import pathlib
import tempfile
import unittest
from unittest import mock

from tests._support import reimport_once_per_class, time_limit
from tests.protocols.test_dispatch_registry_unit import CASE_TIMEOUT, HAS_RUNTIME, _load_generator

#: Test tier (#1958): probes every case of the dispatch generator.
__tier__ = 'LATEST'


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class DispatchGeneratorTempdirTests(unittest.TestCase):
    """What the generator leaves in the temporary directory."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        scratch = tempfile.TemporaryDirectory(prefix='pcapkit-2664-')
        self.addCleanup(scratch.cleanup)
        self.scratch = pathlib.Path(scratch.name)
        patcher = mock.patch.object(tempfile, 'tempdir', scratch.name)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.dispatch = _load_generator()

    def leftovers(self) -> 'list[str]':
        """The probe directories still in the scratch directory."""
        return sorted(path.name for path in self.scratch.glob('pcapkit-dispatch-*'))

    def test_the_scratch_directory_is_where_a_probe_writes(self) -> None:
        """The redirect reaches the generator, so an empty listing below means something."""
        self.assertEqual(pathlib.Path(tempfile.gettempdir()), self.scratch)
        self.assertIs(self.dispatch.tempfile, tempfile)

    def test_no_case_leaves_a_directory_behind(self) -> None:
        """Probing every case removes each capture's directory.

        Fails without the fix with one ``pcapkit-dispatch-*`` directory per case.

        """
        cases = self.dispatch.cases()
        self.assertTrue(cases, 'the generator yields no case, so nothing is probed')
        for case in cases:
            with time_limit(CASE_TIMEOUT):
                self.dispatch.probe(case)
        self.assertEqual(self.leftovers(), [])

    def test_a_probe_that_raises_leaves_no_directory_behind(self) -> None:
        """Both ways out of an extraction that finds no frame: it raises while opening, or while indexing.

        Fails without the fix, which removes the directory on neither.

        """
        from pcapkit.utilities.exceptions import FormatError

        with self.assertRaises(FormatError):
            self.dispatch._extract_first(b'not a capture', '.pcap')
        with self.assertRaises(IndexError):
            self.dispatch._extract_first(self.dispatch._pcap_bytes((), linktype=1), '.pcap')
        self.assertEqual(self.leftovers(), [])


if __name__ == '__main__':
    unittest.main()
