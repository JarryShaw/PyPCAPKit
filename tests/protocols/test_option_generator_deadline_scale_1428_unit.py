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

The spin that stands in for a hang is bounded (#1889). Unbounded, a deadline
whose raise was lost -- one raised inside a finaliser is reported and dropped --
spun until pytest-timeout's backstop ended the whole xdist worker. Now it gives up
after :data:`SPIN_LIMIT` and the test fails by name, and the generator repeats
the raise until :func:`roundtrip` has it.

The spin waits in a call made from inside the ``try`` that drops a raise, and
arms the deadline there (#1897). Waiting inline, a raise handled at the jump
closing the loop went past the ``except`` on CPython 3.13; armed as
:func:`roundtrip` entered it, the deadline could come due in a stall before the
``try``. Either way the first raise was not dropped.

This module is unit tier: it loads the generator by path and builds nothing, so
it imports no :mod:`pcapkit` and reads no capture.

"""

from __future__ import annotations

import dis
import importlib.util
import os
import signal
import sys
import threading
import time
import types
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._tiers import ROOT

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): branches on the running interpreter's version or implementation.
__tier__ = 'ALL'

#: The variable :mod:`tests._support` reads, spelled out so a generator reading a
#: different name fails here rather than agreeing with itself.
SCALE_ENV = 'PCAPKIT_TEST_TIMEOUT_SCALE'

#: Seconds :class:`_Spin` runs before it gives up on being interrupted: ten times
#: the one-second deadline the tests here arm, so a deadline that fires at all,
#: repeats included, lands well inside it.
SPIN_LIMIT = 10.0

#: Seconds a stalled :class:`_Spin` sleeps before its loop: past the one-second
#: deadline, so an alarm counting down from the deadline's entry comes due in it.
STALL = 1.5

#: :func:`signal.alarm` itself, for :class:`_Spin` to reach while its
#: :meth:`_Spin.alarm` stands in for the name.
_ALARM = signal.alarm


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


class _SpinGaveUp(Exception):
    """Raised by :class:`_Spin` once its limit passes with no deadline raised in it."""


class _Spin:
    """A family whose constructor spins until the deadline interrupts it.

    It stands in for a real hang, but a bounded one: after ``limit`` seconds it
    sets :attr:`gave_up` and raises :exc:`_SpinGaveUp`, so a lost deadline fails
    the test in seconds instead of hanging the worker.

    The first raise has to land inside the ``try`` that drops it (#1897), so the
    waiting is done in :meth:`wait`, called from inside that ``try``, and the
    deadline is armed there too: run it through
    :meth:`GeneratorDeadlineScaleTests.spin_roundtrip`, which puts :meth:`alarm`
    in place of :func:`signal.alarm` to hold the deadline back until then.

    Args:
        limit: Seconds to spin before giving up.
        swallow: How many :exc:`TimeoutError` to drop before letting one
            through, standing in for a finaliser that drops the deadline's raise.
        clear: Drop the deadline instead of arming it, so it never fires.
        stall: Seconds to sleep before the loop, standing in for a stalled runner.

    """

    def __init__(self, limit: float = SPIN_LIMIT, swallow: int = 0,
                 clear: bool = False, stall: float = 0.0) -> None:
        self.limit = limit
        self.swallow = swallow
        self.clear = clear
        self.stall = stall
        #: Seconds the deadline asked :meth:`alarm` for as it was entered, or ``0``.
        self.deadline = 0
        #: Seconds held back by :meth:`alarm` and not yet armed by :meth:`wait`.
        self.held = 0
        #: :exc:`TimeoutError` dropped so far.
        self.swallowed = 0
        #: Whether the limit passed before a deadline got through.
        self.gave_up = False

    def alarm(self, seconds: int) -> int:
        """:func:`signal.alarm`, but the deadline's own arm is held for :meth:`wait`.

        The first non-zero call is the deadline being entered. It is recorded in
        :attr:`deadline`, and no alarm runs until :meth:`wait` arms it. Armed as
        the deadline is entered, it counts down through everything before the
        ``try``, and a runner stalled there for the whole second gets the raise
        outside it. Every other call reaches the alarm, so the deadline's repeats
        and its cancel are real.
        """
        if seconds and not self.deadline:
            self.deadline = self.held = seconds
            return _ALARM(0)
        return _ALARM(seconds)

    def wait(self, end: float) -> None:
        """Arm the deadline :meth:`alarm` held, then busy-wait until ``end``.

        A call from inside :meth:`build`'s ``try``, so a raise delivered anywhere
        in here reaches that ``try``. Written inline there, the jump closing the
        loop falls outside the range its ``except`` covers, and on CPython 3.13
        an alarm handled at that jump raised straight past it. CPython 3.12's
        table has the same gap, but an alarm handled there resumes inside the
        ``try``.
        """
        if self.held:
            seconds, self.held = self.held, 0
            if not self.clear:
                _ALARM(seconds)
        while time.monotonic() < end:
            pass

    def build(self, code: 'Any', kwargs: 'Any') -> bytes:  # pylint: disable=unused-argument
        """Loop until the deadline interrupts it, or until :attr:`limit` passes."""
        if self.stall:
            time.sleep(self.stall)
        end = time.monotonic() + self.limit
        while time.monotonic() < end:
            try:
                self.wait(end)
            except TimeoutError:
                if self.swallowed == self.swallow:
                    raise
                self.swallowed += 1
        self.gave_up = True
        raise _SpinGaveUp(f'no deadline interrupted the spin within {self.limit:g}s')


class _Abort(BaseException):
    """Leaves :func:`roundtrip` past every ``except Exception`` clause."""


class _RaiseAt:
    """A family that raises ``exc`` at ``step``, or round-trips one octet if it is :data:`None`."""

    def __init__(self, step: 'str | None', exc: 'BaseException | None') -> None:
        self.step = step
        self.exc = exc

    def _at(self, step: str) -> None:
        if step == self.step and self.exc is not None:
            raise self.exc

    def build(self, code: 'Any', kwargs: 'Any') -> bytes:  # pylint: disable=unused-argument
        """One zero octet, unless this is the step to raise at."""
        self._at('build')
        return b'\x00'

    def parse(self, octets: bytes) -> bytes:
        """``octets`` as they are, unless this is the step to raise at."""
        self._at('parse')
        return octets

    def extract(self, parsed: bytes) -> bytes:
        """``parsed`` as it is."""
        return parsed

    def rebuild(self, parsed: bytes) -> bytes:
        """``parsed`` as it is, unless this is the step to raise at."""
        self._at('rebuild')
        return parsed


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

    def roundtrip(self, family: 'Any') -> 'Any':
        """:func:`roundtrip` over ``family`` under a one-second deadline (scale 0.5 x 2s)."""
        os.environ[SCALE_ENV] = '0.5'
        case = self.options.Case('spin', 0, 'Spin', {})
        with mock.patch.dict(self.options.FAMILY_MAP, {'spin': family}):
            return self.options.roundtrip(case, deadline=2)

    def spin_roundtrip(self, spin: '_Spin') -> 'Any':
        """:meth:`roundtrip` over ``spin``, with :meth:`_Spin.alarm` as :func:`signal.alarm`."""
        with mock.patch.object(signal, 'alarm', spin.alarm):
            return self.roundtrip(spin)

    def assert_interrupted(self, spin: '_Spin', outcome: 'Any') -> None:
        """Fail by name, rather than on a status mismatch, if the deadline never got through."""
        if spin.gave_up:
            self.fail(f'the deadline never interrupted the spin; roundtrip recorded '
                      f'{outcome.status}: {outcome.detail}')

    def assert_dropped_once(self, spin: '_Spin', outcome: 'Any') -> None:
        """One raise dropped, the next recorded as ``'TIMEOUT'``, and nothing left behind.

        One comparison, so a failure shows the count dropped next to what
        :func:`roundtrip` recorded.
        """
        self.assert_interrupted(spin, outcome)
        self.assertEqual(
            {'deadline': spin.deadline, 'swallowed': spin.swallowed,
             'status': outcome.status, 'detail': outcome.detail},
            {'deadline': 1, 'swallowed': 1,
             'status': 'TIMEOUT', 'detail': 'did not finish within 1s'})
        self.assertIs(signal.getsignal(signal.SIGALRM), self.handler)
        self.assertEqual(signal.alarm(0), 0)

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
        spin = _Spin()
        outcome = self.spin_roundtrip(spin)
        self.assert_interrupted(spin, outcome)
        self.assertEqual(spin.deadline, 1)
        self.assertEqual(outcome.status, 'TIMEOUT')
        self.assertEqual(outcome.detail, 'did not finish within 1s')
        self.assertIs(signal.getsignal(signal.SIGALRM), self.handler)

    def test_a_raise_that_never_reaches_the_body_is_repeated(self) -> None:
        """#1889: a dropped raise is followed by another, still recorded as ``'TIMEOUT'``."""
        spin = _Spin(swallow=1)
        self.assert_dropped_once(spin, self.spin_roundtrip(spin))

    def test_a_stall_before_the_spin_still_leaves_a_raise_to_drop(self) -> None:
        """#1897: a runner stalled for longer than the deadline before the spin changes nothing.

        Armed as :func:`roundtrip` entered the deadline, the alarm came due in
        the stall, before the ``try`` that drops a raise. That raise went
        straight through and none was dropped.
        """
        spin = _Spin(swallow=1, stall=STALL)
        self.assert_dropped_once(spin, self.spin_roundtrip(spin))

    @unittest.skipUnless(sys.implementation.name == 'cpython' and sys.version_info >= (3, 12),
                         'needs sys.monitoring')
    @unittest.skipUnless(hasattr(signal, 'pthread_kill'), 'needs signal.pthread_kill')
    def test_a_raise_as_the_spin_loops_back_is_dropped_too(self) -> None:
        """#1897: a raise at the jump that closes the spin's loop is dropped.

        Written inline in the ``try``, that jump lies outside the range the
        ``except`` covers on CPython 3.12 and 3.13. On 3.13 an alarm handled at
        that jump raised straight past the ``except``; on 3.12 one handled there
        resumes inside the ``try``. Here the signal is sent from a
        :mod:`sys.monitoring` callback on the first backward jump after the
        deadline is armed, so the raise lands on the jump itself and exercises
        that layout on 3.12 and 3.13. From 3.14 the range covers the jump, so
        there this is a guard that cannot fail.
        """
        monitoring = sys.monitoring  # pylint: disable=no-member
        tool = next((tool for tool in range(6) if monitoring.get_tool(tool) is None), None)
        if tool is None:
            self.skipTest('no sys.monitoring tool id is free')
        spin = _Spin(swallow=1)
        codes = [function.__code__ for function in vars(_Spin).values()
                 if isinstance(function, types.FunctionType)]
        jumps = {(code, instruction.offset) for code in codes
                 for instruction in dis.get_instructions(code)
                 if instruction.opname == 'JUMP_BACKWARD'}
        sent = []  # type: list[str]

        def instruction(code: 'types.CodeType', offset: int) -> 'Any':
            if sent or (code, offset) not in jumps:
                return monitoring.DISABLE
            if spin.deadline and not spin.held:
                sent.append(code.co_name)
                signal.pthread_kill(threading.get_ident(), signal.SIGALRM)
            return None

        event = monitoring.events.INSTRUCTION
        monitoring.use_tool_id(tool, 'pcapkit #1897')
        self.addCleanup(monitoring.free_tool_id, tool)
        monitoring.register_callback(tool, event, instruction)
        self.addCleanup(monitoring.register_callback, tool, event, None)
        for code in codes:
            monitoring.set_local_events(tool, code, event)
            self.addCleanup(monitoring.set_local_events, tool, code, 0)

        outcome = self.spin_roundtrip(spin)
        self.assertEqual(len(sent), 1, 'no backward jump was reached with the deadline armed')
        self.assert_dropped_once(spin, outcome)

    def test_each_raise_re_arms_until_the_body_settles_it(self) -> None:
        """A raise re-arms one second; once :attr:`settled` is set, a firing does nothing."""
        with self.options._deadline(5) as limit:  # pylint: disable=protected-access
            expire = signal.getsignal(signal.SIGALRM)
            with self.assertRaisesRegex(TimeoutError, 'did not finish within 5s'):
                expire(signal.SIGALRM, None)
            self.assertEqual(signal.alarm(5), 1)
            limit.settled = True
            self.assertIsNone(expire(signal.SIGALRM, None))
            self.assertIn(signal.alarm(0), (4, 5))
        self.assertIs(signal.getsignal(signal.SIGALRM), self.handler)

    def test_a_lost_deadline_fails_in_seconds_rather_than_hanging(self) -> None:
        """#1889: with the deadline never armed, the spin gives up and the test says why."""
        spin = _Spin(limit=0.5, clear=True)
        outcome = self.spin_roundtrip(spin)
        self.assertEqual(spin.deadline, 1)
        self.assertTrue(spin.gave_up)
        self.assertEqual(outcome.status, 'CONSTRUCT')
        self.assertEqual(outcome.detail,
                         '_SpinGaveUp: no deadline interrupted the spin within 0.5s')
        with self.assertRaisesRegex(AssertionError, 'the deadline never interrupted the spin'):
            self.assert_interrupted(spin, outcome)

    @unittest.skipUnless(hasattr(signal, 'pthread_kill'), 'needs signal.pthread_kill')
    def test_a_firing_on_the_way_out_leaves_nothing_behind(self) -> None:
        """#1889: ``SIGALRM`` on the way out of :func:`roundtrip` changes nothing.

        Fired while the outcome is built, as :meth:`_deadline.__exit__` is
        entered (ahead of its first statement), just before it cancels the
        alarm, and from :meth:`warnings.catch_warnings.__exit__`, on every way
        out: each step's ``'TIMEOUT'`` and failure, a :exc:`BaseException`, and
        ``'OK'``. Each time the outcome or the exception
        comes back as it was, no alarm is left pending, and the handler is this
        test's again. ``reached`` is whether the firing found the deadline's
        handler still installed.
        """
        real_alarm = signal.alarm
        real_outcome = self.options.Outcome
        deadline = self.options._deadline  # pylint: disable=protected-access
        real_entry = deadline.__exit__
        real_exit = warnings.catch_warnings.__exit__
        fired = []  # type: list[bool]

        def fire() -> None:
            fired.append(signal.getsignal(signal.SIGALRM) is not self.handler)
            # Delivered to this thread, and its handler run before this returns.
            signal.pthread_kill(threading.get_ident(), signal.SIGALRM)

        def firing_outcome(*args: 'Any') -> 'Any':
            if not fired:
                fire()
            return real_outcome(*args)

        def firing_entry(limit: 'Any', *exc_info: 'Any') -> 'Any':
            # Ahead of __exit__'s first statement, as the check on entry runs it.
            fire()
            return real_entry(limit, *exc_info)

        def firing_alarm(seconds: int) -> int:
            if not seconds and not fired:
                fire()
            return real_alarm(seconds)

        def firing_exit(manager: 'Any', *exc_info: 'Any') -> 'Any':
            fire()
            return real_exit(manager, *exc_info)

        where = {
            'outcome': lambda: mock.patch.object(self.options, 'Outcome', firing_outcome),
            'entry': lambda: mock.patch.object(deadline, '__exit__', firing_entry),
            'cancel': lambda: mock.patch.object(signal, 'alarm', firing_alarm),
            'catch_warnings': lambda: mock.patch.object(warnings.catch_warnings, '__exit__',
                                                        firing_exit),
        }
        ways_out = (
            ('build', TimeoutError, 'TIMEOUT'), ('build', ValueError, 'CONSTRUCT'),
            ('parse', TimeoutError, 'TIMEOUT'), ('parse', ValueError, 'PARSE'),
            ('rebuild', TimeoutError, 'TIMEOUT'), ('rebuild', ValueError, 'RECONSTRUCT'),
            ('build', _Abort, '_Abort'), (None, None, 'OK'),
        )
        for point, patch in where.items():
            for step, error, expected in ways_out:
                if point == 'outcome' and expected == '_Abort':
                    continue  # no outcome is built on that way out
                # Only an ``'OK'`` outcome is built after the deadline is gone.
                reached = point in ('entry', 'cancel') or (point == 'outcome' and expected != 'OK')
                with self.subTest(fired=point, step=step, result=expected):
                    fired.clear()
                    try:
                        with patch():
                            result = self.roundtrip(_RaiseAt(step, error and error()))
                    except (_Abort, TimeoutError) as exc:
                        result = exc
                    finally:
                        pending = real_alarm(0)
                        handler = signal.signal(signal.SIGALRM, self.handler)
                    # One comparison, so a failure shows the leak and the result together.
                    self.assertEqual(
                        {'result': (result.status if isinstance(result, real_outcome)
                                    else type(result).__name__),
                         'reached': fired, 'pending': pending,
                         'restored': handler is self.handler},
                        {'result': expected, 'reached': [reached], 'pending': 0,
                         'restored': True})

    @unittest.skipUnless(hasattr(signal, 'pthread_kill'), 'needs signal.pthread_kill')
    def test_a_firing_as_an_unsettled_deadline_cancels_is_a_no_op(self) -> None:
        """#1889: :meth:`_deadline.__exit__` settles before it cancels, as a backstop.

        The body here never settles the deadline, so only ``__exit__`` can stop a
        firing between its first statement and the cancel from re-arming and
        raising past the restore.
        """
        real_alarm = signal.alarm

        def firing_alarm(seconds: int) -> int:
            if not seconds:
                signal.pthread_kill(threading.get_ident(), signal.SIGALRM)
            return real_alarm(seconds)

        result = None  # type: TimeoutError | None
        try:
            with mock.patch.object(signal, 'alarm', firing_alarm):
                with self.options._deadline(5):  # pylint: disable=protected-access
                    pass
        except TimeoutError as exc:
            result = exc
        finally:
            pending = real_alarm(0)
            handler = signal.signal(signal.SIGALRM, self.handler)
        self.assertEqual(
            {'raised': result, 'pending': pending, 'restored': handler is self.handler},
            {'raised': None, 'pending': 0, 'restored': True})


if __name__ == '__main__':
    unittest.main()
