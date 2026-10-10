# -*- coding: utf-8 -*-
"""The engine agreement module retries a pyshark run once on a tshark crash.

GitHub issue #1534: tshark now and then exits 255 on a capture it reads cleanly
on a rerun, and pyshark raises ``TSharkCrashException``. The agreement module
(:file:`test_engine_agreement_runtime.py`) caches one run per engine and
capture, so that one crash failed all nine pyshark aspects of the capture.

Each case replaces :func:`pcapkit.extract` with a stand-in, so nothing here
reads a capture or needs pyshark; the exception is matched by class name, so a
class of the same name stands in for pyshark's.

"""

import types
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation._roundtrip import Outcome
from tests.foundation.engines import test_engine_agreement_runtime as agreement

#: A capture git tracks, so the unit-tier guard lets its name through.
CAPTURE = 'in.pcap'


class TSharkCrashException(Exception):
    """Stands in for ``pyshark.capture.capture.TSharkCrashException``."""


@unittest.skipUnless(agreement.HAS_RUNTIME, 'runtime dependencies not installed')
class TestTSharkCrashRetry(unittest.TestCase):
    """Pin how the agreement module's runner handles a pyshark run that raises."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _compare(self, *errors: 'Exception') -> 'tuple[Outcome, int, list[str]]':
        """``compare`` the pyshark ``frames`` aspect, its runs raising ``errors`` in turn.

        Returns the outcome, the number of pyshark runs, and every warning raised.

        """
        import pcapkit

        pending = list(errors)
        calls = []  # type: list[str]

        def extract(**kwargs: 'object') -> 'object':
            engine = kwargs['engine']
            calls.append(engine)
            if engine == 'pyshark' and pending:
                raise pending.pop(0)
            return types.SimpleNamespace(_exnam=engine, length=2, frame=(),
                                         reassembly=None, trace=None)

        with mock.patch.dict(agreement._RUNS, clear=True), \
                mock.patch.object(pcapkit, 'extract', extract), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            outcome = agreement.compare('pyshark', CAPTURE, 'frames')
        return outcome, calls.count('pyshark'), [str(item.message) for item in caught]

    def test_one_crash_is_retried_and_logged(self) -> None:
        crash = TSharkCrashException('TShark (pid 1) seems to have crashed (retcode: 255).\n'
                                     'Last error line: None')
        outcome, runs, logged = self._compare(crash)
        self.assertEqual(outcome, Outcome('OK'))
        self.assertEqual(runs, 2)
        self.assertEqual(logged, [f'pyshark on {CAPTURE}: TSharkCrashException: TShark (pid 1) '
                                  'seems to have crashed (retcode: 255). Retrying once (#1534).'])

    def test_a_crash_that_persists_is_an_error(self) -> None:
        crashes = [TSharkCrashException(f'TShark (pid {pid}) seems to have crashed (retcode: 255).')
                   for pid in (1, 2)]
        outcome, runs, logged = self._compare(*crashes)
        self.assertEqual(outcome, Outcome('ERROR', 'TSharkCrashException: TShark (pid 2) seems '
                                                   'to have crashed (retcode: 255).'))
        self.assertEqual(runs, 2)
        self.assertEqual(len(logged), 1)

    def test_any_other_error_is_not_retried(self) -> None:
        outcome, runs, logged = self._compare(ValueError('invalid literal'))
        self.assertEqual(outcome, Outcome('ERROR', 'ValueError: invalid literal'))
        self.assertEqual(runs, 1)
        self.assertEqual(logged, [])


if __name__ == '__main__':
    unittest.main()
