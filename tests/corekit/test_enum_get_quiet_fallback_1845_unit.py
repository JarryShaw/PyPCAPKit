# -*- coding: utf-8 -*-
"""GitHub issue #1845: ``get(value, default)`` falls back quietly; ``register`` stays loud.

#1823 gave every generated registry a ``_validate_value`` override raising a loud
:exc:`~pcapkit.utilities.exceptions.EnumValueError`, and
:meth:`~pcapkit.corekit.enum.EnumLookup.get` calls that hook before ``cls(key)``.
So ``get(out_of_range, default)`` returned ``default`` but logged a
:data:`logging.CRITICAL` record and installed :mod:`pcapkit`'s exception hooks
on the way. The owner took the quiet option for ``get`` and kept ``register``
loud. The quiet path lives in :mod:`pcapkit.corekit`, so the generated overrides
are untouched: ``get`` runs them inside a
:class:`~pcapkit.utilities.exceptions._CaughtByCaller` block, which makes a
:exc:`ValueError`-derived :class:`~pcapkit.utilities.exceptions.BaseError`
constructed there quiet.

The generated registry under test is
:class:`~pcapkit.const.ipv4.tos_pre.ToSPrecedence`, whose override accepts
``0``-``7`` only. ``LLACode``, the registry the issue measured on, is avoided
because one of its members is being renamed in parallel (#1848).

"""

from __future__ import annotations

import contextlib
import sys
import threading
import unittest
from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.const.ipv4.tos_pre import ToSPrecedence
from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities import exceptions
from pcapkit.utilities.exceptions import EnumValueError, IntError
from pcapkit.utilities.logging import DEVMODE
from pcapkit.utilities.logging import logger as package_logger
from tests.utilities._harness import capture

if TYPE_CHECKING:
    from typing import Any, Iterator

    from tests.utilities._harness import Recorder

__all__ = ['QuietFallbackTests', 'LoudPathTests', 'MechanismTests']

#: A value :class:`ToSPrecedence`'s ``_validate_value`` refuses: the field is 3 bits.
OUT_OF_RANGE = 8

#: The one record a loud rejection of :data:`OUT_OF_RANGE` leaves.
LOUD_RECORD = ('CRITICAL', f'EnumValueError: {OUT_OF_RANGE} is not a valid ToSPrecedence')

#: Set by :class:`_Blocking`'s hook once it is parked inside ``get``.
_INSIDE = threading.Event()
#: Set by the test to let :class:`_Blocking`'s hook reject and return.
_RELEASE = threading.Event()


@contextlib.contextmanager
def _records() -> 'Iterator[tuple[Recorder, Recorder]]':
    """Capture the package logger and, separately, the exceptions module's own."""
    with capture(package_logger) as package, capture(exceptions.logger) as module:
        yield package, module


class _Nested(EnumRegistry, IntEnum):
    """A registry whose range hook calls ``register`` on another one.

    Contrived on purpose: nothing in :mod:`pcapkit.const` does this, and it is
    the only way ``register`` can run while a ``get`` is in progress.

    """

    zero = 0

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        try:
            ToSPrecedence.register(OUT_OF_RANGE, 'Nested_1845')
        except ValueError:
            pass
        if not 0 <= value <= 7:
            raise EnumValueError(f'{value!r} is not a valid {cls.__name__}')


class _Blocking(EnumRegistry, IntEnum):
    """A registry whose range hook parks until told to reject."""

    zero = 0

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        _INSIDE.set()
        _RELEASE.wait(timeout=10)
        raise EnumValueError(f'{value!r} is not a valid {cls.__name__}')


class _HookGuard(unittest.TestCase):
    """Install sentinel exception hooks, and restore the real ones afterwards.

    A loud error outside development mode replaces :data:`sys.excepthook` and
    :data:`threading.excepthook`, so the loud controls below would otherwise leak
    :mod:`pcapkit`'s hooks into every later test. The sentinels also make "left
    the hooks alone" an identity check rather than a guess about what was there.

    """

    def setUp(self) -> 'None':
        saved_sys, saved_threading = sys.excepthook, threading.excepthook

        def _restore() -> 'None':
            sys.excepthook = saved_sys
            threading.excepthook = saved_threading

        self.addCleanup(_restore)

        def _sys_sentinel(*args: 'Any') -> 'None':
            saved_sys(*args)

        def _threading_sentinel(args: 'Any') -> 'None':
            saved_threading(args)

        self.sys_sentinel = _sys_sentinel
        self.threading_sentinel = _threading_sentinel
        sys.excepthook = _sys_sentinel
        threading.excepthook = _threading_sentinel


class QuietFallbackTests(_HookGuard):
    """The fix: an out-of-range value with a usable ``default`` is silent."""

    def test_returns_the_default(self) -> 'None':
        self.assertIs(ToSPrecedence.get(OUT_OF_RANGE, 0), ToSPrecedence.Routine)
        self.assertIs(ToSPrecedence.get(-1, ToSPrecedence.Flash.value), ToSPrecedence.Flash)

    def test_logs_nothing(self) -> 'None':
        with _records() as (package, module):
            ToSPrecedence.get(OUT_OF_RANGE, 0)
        self.assertEqual(module.messages, [],
                         'get() fell back to default and still logged from '
                         'pcapkit.utilities.exceptions')
        self.assertEqual(package.messages, [])

    @unittest.skipIf(DEVMODE, 'a loud error installs no hook in development mode')
    def test_leaves_the_exception_hooks_alone(self) -> 'None':
        with _records():
            ToSPrecedence.get(OUT_OF_RANGE, 0)
        self.assertIs(sys.excepthook, self.sys_sentinel,
                      'get() fell back to default and still replaced sys.excepthook')
        self.assertIs(threading.excepthook, self.threading_sentinel)

    def test_mints_nothing(self) -> 'None':
        names, values = dict(ToSPrecedence._member_map_), dict(ToSPrecedence._value2member_map_)
        with _records():
            ToSPrecedence.get(OUT_OF_RANGE, 0)
        self.assertEqual(ToSPrecedence._member_map_, names)
        self.assertEqual(ToSPrecedence._value2member_map_, values)


class LoudPathTests(_HookGuard):
    """What stays as it was. These pass before the fix too: they guard against a
    fix that quiets more than ``get``'s fallback."""

    def _assert_one_loud_record(self, module: 'Recorder') -> 'None':
        self.assertEqual(module.messages, [LOUD_RECORD])
        if not DEVMODE:
            self.assertIs(sys.excepthook, exceptions._excepthook)

    def test_get_without_default_is_loud(self) -> 'None':
        with _records() as (_, module):
            with self.assertRaises(EnumValueError) as caught:
                ToSPrecedence.get(OUT_OF_RANGE)
        self.assertEqual(str(caught.exception), f'{OUT_OF_RANGE} is not a valid ToSPrecedence')
        self._assert_one_loud_record(module)

    def test_get_with_an_unregistered_default_is_loud(self) -> 'None':
        self.assertNotIn(99, ToSPrecedence._value2member_map_)
        with _records() as (_, module):
            with self.assertRaises(EnumValueError):
                ToSPrecedence.get(OUT_OF_RANGE, 99)
        self._assert_one_loud_record(module)

    def test_register_is_loud(self) -> 'None':
        with _records() as (_, module):
            with self.assertRaises(EnumValueError):
                ToSPrecedence.register(OUT_OF_RANGE, 'Probe_1845')
        self._assert_one_loud_record(module)
        self.assertNotIn('Probe_1845', ToSPrecedence.__members__)

    def test_a_non_value_error_from_the_hook_is_loud(self) -> 'None':
        """``get`` catches only :exc:`ValueError`, so only that is quieted."""

        class _TypeRejecting(EnumRegistry, IntEnum):
            zero = 0

            @classmethod
            def _validate_value(cls, value: 'Any') -> 'None':
                raise IntError(f'{value!r} is not an int-like {cls.__name__}')

        with _records() as (_, module):
            with self.assertRaises(IntError):
                _TypeRejecting.get(5, 0)
        self.assertEqual([level for level, _ in module.messages], ['CRITICAL'])


class MechanismTests(_HookGuard):
    """The block is re-entrant, per thread, and cannot quiet ``register``."""

    def test_register_reached_from_inside_get_stays_loud(self) -> 'None':
        with _records() as (_, module):
            self.assertIs(_Nested.get(99, 0), _Nested.zero)
        self.assertEqual(module.messages, [LOUD_RECORD],
                         'expected exactly the register() rejection, loud, with the '
                         "get() fallback's own rejection quiet")

    def test_register_inside_a_quiet_block_stays_loud(self) -> 'None':
        with _records() as (_, module):
            with exceptions._CaughtByCaller(ValueError):
                with self.assertRaises(EnumValueError):
                    ToSPrecedence.register(OUT_OF_RANGE, 'Block_1845')
        self.assertEqual(module.messages, [LOUD_RECORD])

    def test_blocks_nest_and_restore(self) -> 'None':
        with _records() as (_, module):
            with exceptions._CaughtByCaller(ValueError):
                EnumValueError('outer, quiet')
                with exceptions._CaughtByCaller():
                    EnumValueError('inner, loud')
                EnumValueError('outer again, quiet')
                IntError('not a ValueError, loud')
            EnumValueError('outside, loud')
        self.assertEqual([message for _, message in module.messages],
                         ['EnumValueError: inner, loud', 'IntError: not a ValueError, loud',
                          'EnumValueError: outside, loud'])

    def test_one_threads_block_does_not_quiet_another_thread(self) -> 'None':
        _INSIDE.clear()
        _RELEASE.clear()
        result = []  # type: list[object]
        worker = threading.Thread(target=lambda: result.append(_Blocking.get(5, 0)))
        with _records() as (_, module):
            worker.start()
            try:
                self.assertTrue(_INSIDE.wait(timeout=10), 'the worker never reached the hook')
                # The worker is now parked inside get()'s quiet block.
                EnumValueError('main thread, loud')
            finally:
                _RELEASE.set()
                worker.join(timeout=10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result, [_Blocking.zero])
        self.assertEqual([message for _, message in module.messages],
                         ['EnumValueError: main thread, loud'],
                         "the worker's fallback logged, or its block quieted the main thread")


if __name__ == '__main__':
    unittest.main()
