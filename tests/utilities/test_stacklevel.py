# -*- coding: utf-8 -*-
"""Regression tests for :func:`pcapkit.utilities.exceptions.stacklevel` -- the
level it returns must be *relative*.

:func:`warnings.warn` and the :mod:`logging` module both count ``stacklevel``
outwards from the frame that made the call: ``1`` is that frame, ``2`` its caller,
and so on. ``stacklevel()`` used to return an absolute index into
:func:`traceback.extract_stack`'s result instead, so the value grew with the depth
of the caller's *own* stack and the attributed frame drifted one frame further out
for every extra outer frame. Under :program:`pytest`, or any deep call chain, the
function inverted its own purpose and blamed a frame with nothing to do with the
complaint.

It also returned ``-1``, and not only in theory: :func:`traceback.extract_stack`
honours :data:`sys.tracebacklimit`, which :class:`BaseError
<pcapkit.utilities.exceptions.BaseError>` sets to ``0`` for every loud error
outside development mode. After the first such error the extracted stack was
*empty*, the ``for``/``else`` branch ran, and every subsequent warning in the
process got ``-1``.

Three groups of tests here, because they fail for different reasons:

* :class:`StacklevelArithmeticTests` -- the derivation and both clamps, over
  synthetic frames, including the shapes no real stack under :program:`pytest`
  can produce;
* :class:`StacklevelAttributionTests` -- the end-to-end attribution, driving real
  :mod:`pcapkit` APIs from a range of stack depths, which is what a user actually
  sees and where the drift showed up;
* :class:`WarnWrapperLevelTests` -- :func:`pcapkit.utilities.warnings.warn`'s own
  ``stacklevel`` argument, which every call site in the package forwards a
  ``stacklevel()`` through.

Nothing here reads a capture, so the module is unit tier -- see
:mod:`tests._tiers`.

"""
from __future__ import annotations

import linecache
import logging
import os
import sys
import traceback
import unittest
import warnings as pywarnings
from typing import TYPE_CHECKING
from unittest import mock

import pcapkit.utilities.exceptions as exceptions
import pcapkit.utilities.warnings as pcapkit_warnings
from pcapkit.corekit.infoclass import Info, info_final
from tests.utilities._harness import capture

if TYPE_CHECKING:
    from typing import Any, Callable, Optional, TypeVar

    _T = TypeVar('_T')

#: The path fragment :func:`~pcapkit.utilities.exceptions.stacklevel` treats as
#: "inside :mod:`pcapkit`".
MARKER = f'{os.path.sep}pcapkit{os.path.sep}'

#: Stand-in filenames for the synthetic stacks. Built with :data:`os.path.sep` so
#: that the marker matches on Windows too.
EXTERNAL = os.path.join(os.path.sep, 'home', 'user', 'app.py')
INTERNAL = os.path.join(os.path.sep, 'site-packages', 'pcapkit', 'internal.py')

#: Outer stack depths the end-to-end tests run every probe at. The point of the
#: list is its spread: the old absolute level was right by coincidence at exactly
#: one depth, so a single-depth test passed against the defect.
DEPTHS = (0, 1, 2, 5, 12, 30)

#: A checkout inside a directory literally named ``pcapkit`` would make this very
#: file look internal, which *inverts* the boundary the end-to-end tests measure
#: rather than breaking it. Those tests are skipped in that case; the synthetic
#: ones are unaffected and still run.
OUTSIDE_PCAPKIT = MARKER not in os.path.abspath(__file__)


@info_final
class Probe(Info):
    """An already-finalised info class.

    Handing it back to :func:`~pcapkit.corekit.infoclass.info_final` warns, and
    assigning to an attribute raises -- one probe for each of the two channels
    ``stacklevel()`` feeds, needing no capture and no optional dependency.

    """


def through(depth: 'int', call: 'Callable[[], _T]') -> '_T':
    """Invoke ``call`` with ``depth`` extra frames of this module's on the stack.

    Recursive rather than a chain of distinct functions: only the *number* of
    intervening frames matters, and every frame it adds belongs to this module,
    which is what makes a drifting attribution land on this function's own line
    instead of on the probe's.

    """
    if depth <= 0:
        return call()
    return through(depth - 1, call)


class FakeFrame:
    """The two attributes ``stacklevel()`` reads off a frame, and nothing else.

    Synthetic frames rather than real ones because the shapes that matter cannot
    all be produced for real: under :program:`pytest` there are always a dozen
    external frames above the test, so "the whole stack is inside :mod:`pcapkit`"
    -- the case the upper clamp exists for -- is unreachable. The end-to-end tests
    below cover the shapes that *are* reachable.

    """

    def __init__(self, filename: 'str', back: 'Optional[FakeFrame]') -> None:
        self.f_code = type('FakeCode', (), {'co_filename': filename})()
        self.f_back = back


def synthetic_stack(outer: 'int', inner: 'int') -> 'Optional[FakeFrame]':
    """The innermost frame of a synthetic stack, as ``currentframe()`` returns it.

    Args:
        outer: Number of outermost frames whose files sit outside :mod:`pcapkit`.
        inner: Number of innermost frames whose files sit inside it, standing in
            for everything from the outermost :mod:`pcapkit` frame down to
            ``stacklevel()``'s own.

    """
    frame = None  # type: Optional[FakeFrame]
    for _ in range(outer):
        frame = FakeFrame(EXTERNAL, frame)
    for _ in range(inner):
        frame = FakeFrame(INTERNAL, frame)
    return frame


def frame_at(innermost: 'Optional[FakeFrame]', level: 'int') -> 'FakeFrame':
    """The frame a relative ``level`` names, walking out from ``innermost``.

    ``innermost`` stands for ``stacklevel()``'s own frame, which is level ``0``, so
    a level of ``L`` is ``L`` steps out from it.

    """
    frame = innermost
    for _ in range(level):
        assert frame is not None
        frame = frame.f_back
    assert frame is not None
    return frame


def source_at(filename: 'str', lineno: 'int') -> 'str':
    """The source line a reported attribution points at.

    Asserting on the *text* of the blamed line keeps the tests free of offset
    arithmetic against the probe helpers, which is itself easy to get wrong and
    silently right.

    """
    return linecache.getline(filename, lineno).strip()


class Recorder(logging.Handler):
    """A handler that keeps records, so their attribution can be read back.

    :class:`tests.utilities._harness.Recorder` would do, but it is reached through
    :func:`~tests.utilities._harness.capture`, which is about *counting* records
    rather than inspecting the two fields these tests care about.

    """

    def __init__(self) -> None:
        super().__init__(level=logging.NOTSET)
        self.records = []  # type: list[logging.LogRecord]

    def emit(self, record: 'logging.LogRecord') -> None:
        self.records.append(record)


class StacklevelArithmeticTests(unittest.TestCase):
    """The derivation and the clamps, against synthetic stacks."""

    def level_for(self, outer: 'int', inner: 'int') -> 'int':
        """``stacklevel()`` over a synthetic stack of the given shape."""
        stack = synthetic_stack(outer, inner)
        with mock.patch.object(exceptions.inspect, 'currentframe', return_value=stack):
            return exceptions.stacklevel()

    def test_level_counts_the_pcapkit_frames_not_the_outer_ones(self) -> None:
        """``len(tb) - index``, i.e. the depth of the :mod:`pcapkit` run."""
        for inner in (1, 2, 4, 9):
            with self.subTest(inner=inner):
                self.assertEqual(self.level_for(outer=3, inner=inner), inner)

    def test_level_does_not_grow_with_the_outer_stack(self) -> None:
        """The defect, stated directly: the outer depth must not matter.

        The old ``index - 1`` returned the number of outer frames less one, so
        these six shapes -- identical on the :mod:`pcapkit` side -- gave six
        different answers.

        """
        levels = {outer: self.level_for(outer=outer, inner=4)
                  for outer in (1, 2, 3, 10, 50, 200)}
        self.assertEqual(set(levels.values()), {4}, levels)

    def test_level_names_the_innermost_frame_outside_pcapkit(self) -> None:
        """Resolve the level against the stack and check where it lands.

        Level ``0`` is ``stacklevel()``'s own frame, so level ``L`` is ``L`` steps
        out from it. The frame wanted is the first one past the boundary, so the
        frame the level names must be external and the next one inwards internal.

        """
        for outer in (1, 2, 5, 20):
            for inner in (1, 2, 3, 8):
                with self.subTest(outer=outer, inner=inner):
                    stack = synthetic_stack(outer, inner)
                    with mock.patch.object(exceptions.inspect, 'currentframe', return_value=stack):
                        level = exceptions.stacklevel()

                    self.assertEqual(frame_at(stack, level).f_code.co_filename, EXTERNAL)
                    self.assertEqual(frame_at(stack, level - 1).f_code.co_filename, INTERNAL)

    def test_level_is_never_below_one(self) -> None:
        """``0`` and ``-1`` are not levels: exhaustively, over every shape.

        ``-1`` was reachable -- ``index`` is ``0`` when the outermost frame is
        already inside :mod:`pcapkit`, e.g. running the package as a script -- and
        :meth:`logging.Logger.findCaller` reads a level below ``1`` as "do not walk
        out at all", so it blamed :mod:`logging` itself.

        """
        for outer in range(0, 5):
            for inner in range(0, 5):
                with self.subTest(outer=outer, inner=inner):
                    self.assertGreaterEqual(self.level_for(outer, inner), 1)

    def test_level_never_walks_past_the_outermost_frame(self) -> None:
        """The upper clamp, reached when the whole stack is inside :mod:`pcapkit`.

        :func:`warnings.warn` falls back to blaming the :mod:`sys` module once the
        walk runs off the top of the stack, so the level stops at ``tb[0]``.

        """
        for inner in range(2, 7):
            with self.subTest(inner=inner):
                self.assertEqual(self.level_for(outer=0, inner=inner), inner - 1)

    def test_no_pcapkit_frame_at_all_yields_the_immediate_caller(self) -> None:
        """The ``for``/``else`` branch, which used to return ``len(tb) - 1``."""
        for outer in (1, 4, 25):
            with self.subTest(outer=outer):
                self.assertEqual(self.level_for(outer=outer, inner=0), 1)

    def test_boundary_is_the_outermost_pcapkit_frame(self) -> None:
        """An interleaved stack walks out to the *first* entry into :mod:`pcapkit`.

        A user callback invoked by :mod:`pcapkit` that calls back into
        :mod:`pcapkit` puts external frames in the middle. The level then covers
        them too, deliberately: what the report should name is where the user
        entered :mod:`pcapkit`, not where they re-entered it.

        """
        stack = None  # type: Any
        for filename in (EXTERNAL, INTERNAL, EXTERNAL, INTERNAL, INTERNAL):
            stack = FakeFrame(filename, stack)

        with mock.patch.object(exceptions.inspect, 'currentframe', return_value=stack):
            level = exceptions.stacklevel()

        self.assertEqual(level, 4)
        self.assertEqual(frame_at(stack, level).f_code.co_filename, EXTERNAL)
        self.assertIsNone(frame_at(stack, level).f_back)


@unittest.skipUnless(OUTSIDE_PCAPKIT,
                     f'this file is inside a {MARKER!r} path, so the boundary '
                     f'these tests measure does not exist here')
class StacklevelAttributionTests(unittest.TestCase):
    """Where a real complaint from a real :mod:`pcapkit` API gets attributed."""

    def test_level_is_one_when_the_caller_is_outside_pcapkit(self) -> None:
        """Called from non-:mod:`pcapkit` code, the answer is ``1`` at any depth.

        The boundary is ``stacklevel()``'s own frame, so the only external frame
        to name is its immediate caller. The old absolute index returned
        ``len(tb) - 2`` here, which under :program:`pytest` is a couple of dozen
        and climbing.

        """
        levels = {depth: through(depth, exceptions.stacklevel) for depth in DEPTHS}
        self.assertEqual(set(levels.values()), {1}, levels)

    def warning_site(self) -> 'pywarnings.WarningMessage':
        """Provoke one :exc:`~pcapkit.utilities.warnings.InfoWarning`."""
        with capture(pcapkit_warnings.logger):
            with pywarnings.catch_warnings(record=True) as records:
                pywarnings.resetwarnings()
                pywarnings.simplefilter('always')
                info_final(Probe)
        self.assertEqual(len(records), 1, [str(record.message) for record in records])
        return records[-1]

    def test_warning_blames_the_same_line_from_every_depth(self) -> None:
        """One logical call, six outer depths, one attribution."""
        seen = {}  # type: dict[int, tuple[str, int]]
        for depth in DEPTHS:
            record = through(depth, self.warning_site)
            seen[depth] = (record.filename, record.lineno)

        self.assertEqual(len(set(seen.values())), 1, seen)
        filename, lineno = seen[DEPTHS[0]]
        self.assertEqual(os.path.abspath(filename), os.path.abspath(__file__))
        self.assertIn('info_final(Probe)', source_at(filename, lineno))

    def test_warning_is_not_attributed_to_pcapkit_itself(self) -> None:
        """The purpose of the function: keep the internals out of the report."""
        for depth in DEPTHS:
            with self.subTest(depth=depth):
                record = through(depth, self.warning_site)
                self.assertNotIn(MARKER, os.path.abspath(record.filename))

    def test_a_truncated_traceback_limit_does_not_blind_the_walk(self) -> None:
        """``sys.tracebacklimit = 0`` must not change the answer.

        :class:`~pcapkit.utilities.exceptions.BaseError` sets it for every loud
        error outside development mode, and :func:`traceback.extract_stack` honours
        it -- returning an *empty* list, on which the old implementation fell
        through to its ``for``/``else`` and returned ``-1``. So in ordinary use the
        first error silently broke the attribution of every warning after it, for
        the life of the process. It is also why this only ever reproduced in a
        full-suite run: alone, this module never raises a loud error first.

        """
        saved = getattr(sys, 'tracebacklimit', None)
        try:
            sys.tracebacklimit = 0
            self.assertEqual(len(traceback.extract_stack()), 0,
                             'precondition: extract_stack() is meant to be blinded here')

            record = through(3, self.warning_site)

            self.assertEqual(os.path.abspath(record.filename), os.path.abspath(__file__))
            self.assertIn('info_final(Probe)', source_at(record.filename, record.lineno))
        finally:
            if saved is None:
                if hasattr(sys, 'tracebacklimit'):
                    del sys.tracebacklimit
            else:
                sys.tracebacklimit = saved

    def error_site(self) -> 'logging.LogRecord':
        """Provoke one :exc:`~pcapkit.utilities.exceptions.UnsupportedCall`.

        Development mode is forced on because that is the branch which logs; the
        other one sets :data:`sys.tracebacklimit` and reports no attribution to
        read back.

        """
        recorder = Recorder()
        logger = exceptions.logger
        handlers, level, propagate = logger.handlers, logger.level, logger.propagate
        logger.handlers, logger.propagate = [recorder], False
        logger.setLevel(logging.DEBUG)
        try:
            with mock.patch.object(exceptions, 'DEVMODE', True):
                with mock.patch.object(exceptions, 'VERBOSE', False):
                    with self.assertRaises(exceptions.UnsupportedCall):
                        Probe().spam = 'immutable'
        finally:
            logger.handlers, logger.level, logger.propagate = handlers, level, propagate

        self.assertEqual(len(recorder.records), 1, recorder.records)
        return recorder.records[-1]

    def test_error_log_blames_the_same_line_from_every_depth(self) -> None:
        """``BaseError`` used to negate the level, which blamed :mod:`logging`."""
        seen = {}  # type: dict[int, tuple[str, int]]
        for depth in DEPTHS:
            record = through(depth, self.error_site)
            seen[depth] = (record.pathname, record.lineno)

        self.assertEqual(len(set(seen.values())), 1, seen)
        pathname, lineno = seen[DEPTHS[0]]
        self.assertEqual(os.path.abspath(pathname), os.path.abspath(__file__))
        self.assertIn('Probe().spam', source_at(pathname, lineno))

    def test_error_log_is_attributed_to_neither_pcapkit_nor_logging(self) -> None:
        for depth in DEPTHS:
            with self.subTest(depth=depth):
                record = through(depth, self.error_site)
                self.assertNotIn(MARKER, os.path.abspath(record.pathname))
                self.assertNotEqual(os.path.abspath(record.pathname),
                                    os.path.abspath(logging.__file__))


@unittest.skipUnless(OUTSIDE_PCAPKIT,
                     f'this file is inside a {MARKER!r} path, so the boundary '
                     f'these tests measure does not exist here')
class WarnWrapperLevelTests(unittest.TestCase):
    """:func:`pcapkit.utilities.warnings.warn` counts from *its caller's* frame.

    It calls :func:`warnings.warn` from inside itself, so the level it forwards
    has to have its own frame added back. Without that, the ``stacklevel()`` a
    call site computes in its own frame lands one frame short of the boundary --
    still inside :mod:`pcapkit`, which is the frame the whole exercise skips past.

    """

    def emit(self, **kwargs: 'Any') -> 'pywarnings.WarningMessage':
        """Report one warning through :func:`warn` and return the emission.

        The :func:`warn` call is kept on one source line on purpose: which line of
        a multi-line call expression a frame reports as its current one has changed
        between Python versions, and these tests assert on the line.

        """
        with capture(pcapkit_warnings.logger):
            with pywarnings.catch_warnings(record=True) as records:
                pywarnings.resetwarnings()
                pywarnings.simplefilter('always')
                pcapkit_warnings.warn('a complaint', pcapkit_warnings.SchemaWarning, **kwargs)
        self.assertEqual(len(records), 1)
        return records[-1]

    def test_level_one_blames_the_line_that_called_warn(self) -> None:
        record = self.emit(stacklevel=1)

        self.assertEqual(os.path.abspath(record.filename), os.path.abspath(__file__))
        self.assertIn('pcapkit_warnings.warn(', source_at(record.filename, record.lineno))

    def test_level_two_blames_that_line_s_caller(self) -> None:
        record = self.emit(stacklevel=2)

        self.assertEqual(os.path.abspath(record.filename), os.path.abspath(__file__))
        self.assertIn('self.emit(stacklevel=2)', source_at(record.filename, record.lineno))

    def test_default_level_blames_the_innermost_caller_outside_pcapkit(self) -> None:
        """Omitting the argument walks out to the boundary, wherever it is.

        Here the boundary is :meth:`emit`, since :func:`warn` is the only
        :mod:`pcapkit` frame on the stack -- so the default coincides with
        ``stacklevel=1``, and both must land on the same line.

        """
        default = self.emit()
        explicit = self.emit(stacklevel=1)

        self.assertEqual((default.filename, default.lineno),
                         (explicit.filename, explicit.lineno))
        self.assertNotIn(MARKER, os.path.abspath(default.filename))


if __name__ == '__main__':
    unittest.main()
