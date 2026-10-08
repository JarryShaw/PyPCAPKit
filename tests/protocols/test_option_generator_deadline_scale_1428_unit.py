# -*- coding: utf-8 -*-
"""The option generator's per-case deadline honours the suite's timeout scale. C.f. #1428.

:func:`roundtrip` in :file:`examples/generators/options.py` arms a
:func:`signal.alarm` around each case and records ``'TIMEOUT'`` when it fires.
The budget was a flat 5 seconds of wall-clock time, so a stalled CI runner failed
:mod:`tests.protocols.test_option_generator_httpv2_stream_unit` on a case that
takes about 1.3 ms. The default is now 30 seconds, the budget
:mod:`tests.protocols.test_option_roundtrip_unit` already gives the same cycle,
and ``PCAPKIT_TEST_TIMEOUT_SCALE`` stretches it exactly as it stretches
:func:`tests._support.time_limit`.

This module is unit tier: it loads the generator by path and builds nothing, so
it imports no :mod:`pcapkit` and reads no capture.

"""

from __future__ import annotations

import importlib.util
import os
import signal
import sys
import types
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests._tiers import ROOT

if TYPE_CHECKING:
    from typing import Any

#: The variable :mod:`tests._support` reads, spelled out so a generator reading a
#: different name fails here rather than agreeing with itself.
SCALE_ENV = 'PCAPKIT_TEST_TIMEOUT_SCALE'


def _load_generator() -> 'types.ModuleType':
    """Load :file:`examples/generators/options.py` by path, under a name of its own.

    Returns:
        The generator module.

    Raises:
        RuntimeError: If the module cannot be found or loaded.

    """
    path = ROOT / 'examples' / 'generators' / 'options.py'
    spec = importlib.util.spec_from_file_location(
        'pcapkit_samples_options_deadline_scale', path)
    if spec is None or spec.loader is None:  # pragma: no cover
        raise RuntimeError(f'cannot load the option generator from {path}')

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _Spin:  # pylint: disable=too-few-public-methods
    """A family whose constructor never returns, standing in for a real hang."""

    def build(self, code: 'Any', kwargs: 'Any') -> bytes:  # pylint: disable=unused-argument
        """Loop until the deadline interrupts it."""
        while True:
            pass


@unittest.skipUnless(hasattr(signal, 'SIGALRM'), 'needs signal.SIGALRM')
class GeneratorDeadlineScaleTests(unittest.TestCase):
    """:data:`DEADLINE`, as armed under each value of the scale."""

    options: 'types.ModuleType'

    @classmethod
    def setUpClass(cls) -> None:
        cls.options = _load_generator()

    def setUp(self) -> None:
        # Start each test from no pending alarm and a handler this class owns, and
        # from no scale: one set for the whole run would stretch every value below.
        self.handler = lambda signum, frame: None
        previous = signal.signal(signal.SIGALRM, self.handler)
        self.addCleanup(signal.signal, signal.SIGALRM, previous)
        self.addCleanup(signal.alarm, 0)
        environ = mock.patch.dict(os.environ)
        environ.start()
        self.addCleanup(environ.stop)
        os.environ.pop(SCALE_ENV, None)

    def armed(self, seconds: int) -> int:
        """Seconds :class:`_deadline` arms for ``seconds``, read back from the alarm."""
        with self.options._deadline(seconds):  # pylint: disable=protected-access
            return signal.alarm(0)

    def test_the_default_is_thirty_seconds_unscaled(self) -> None:
        """Unset, the default applies as written -- and it is no longer 5."""
        self.assertEqual(self.options.DEADLINE, 30)
        self.assertEqual(self.options.TIMEOUT_SCALE_ENV, SCALE_ENV)
        self.assertIn(self.armed(self.options.DEADLINE), (29, 30))

    def test_the_scale_multiplies_what_is_armed(self) -> None:
        """The scale stretches the alarm itself, rounding up to whole seconds."""
        for raw, seconds, expected in (('3', 5, 15), ('1.5', 5, 8), ('0.01', 5, 1),
                                       (' 2 ', 30, 60)):
            with self.subTest(scale=raw, seconds=seconds):
                os.environ[SCALE_ENV] = raw
                self.assertEqual(self.options.scale_deadline(seconds), expected)
                self.assertIn(self.armed(seconds), (expected - 1, expected))

    def test_a_blank_scale_leaves_the_deadline_alone(self) -> None:
        """Empty or whitespace reads as unset, as in :mod:`tests._support`."""
        for raw in ('', '   '):
            with self.subTest(scale=raw):
                os.environ[SCALE_ENV] = raw
                self.assertEqual(self.options.scale_deadline(30), 30)

    def test_a_malformed_scale_is_refused_before_anything_is_armed(self) -> None:
        """Ignoring it would undo a scale CI asked for; zero would disarm the guard."""
        for raw in ('fast', '0', '-1', 'nan', 'inf'):
            with self.subTest(scale=raw):
                os.environ[SCALE_ENV] = raw
                with self.assertRaisesRegex(ValueError, f'{SCALE_ENV} must be a positive number'):
                    self.armed(5)
                self.assertIs(signal.getsignal(signal.SIGALRM), self.handler)
                self.assertEqual(signal.alarm(0), 0)

    def test_an_oversized_scale_is_refused(self) -> None:
        """Past a day is refused, not handed to :func:`signal.alarm` to overflow."""
        for raw in ('1e9', '1e308'):
            with self.subTest(scale=raw):
                os.environ[SCALE_ENV] = raw
                with self.assertRaisesRegex(ValueError, 'past the 86400s ceiling'):
                    self.armed(30)
                self.assertIs(signal.getsignal(signal.SIGALRM), self.handler)

    def test_a_zero_deadline_stays_disarmed_under_any_scale(self) -> None:
        """``deadline=0`` is the opt-out the round-trip suite uses; scaling must not undo it."""
        os.environ[SCALE_ENV] = '3'
        self.assertEqual(self.armed(0), 0)

    def test_a_hang_is_still_recorded_as_timeout_naming_the_scaled_deadline(self) -> None:
        """The ``'TIMEOUT'`` contract holds, and its detail names the seconds allowed."""
        os.environ[SCALE_ENV] = '0.5'
        case = self.options.Case('spin', 0, 'Spin', {})
        with mock.patch.dict(self.options.FAMILY_MAP, {'spin': _Spin()}):
            outcome = self.options.roundtrip(case, deadline=2)
        self.assertEqual(outcome.status, 'TIMEOUT')
        self.assertEqual(outcome.detail, 'did not finish within 1s')
        self.assertIs(signal.getsignal(signal.SIGALRM), self.handler)


if __name__ == '__main__':
    unittest.main()
