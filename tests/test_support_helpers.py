# -*- coding: utf-8 -*-
"""Tests for the helpers in :mod:`tests._support`.

Two of them are pinned here, both for the same reason: they are *machinery* the
rest of the suite leans on, so a fault in either reports itself as a failure in
whichever test happened to be running rather than as a fault in the helper.
:func:`~tests._support.time_limit` is covered by :class:`TimeLimitTests` at the
end; the rest of the module is :func:`~tests._support.close_extractor`.

That helper is teardown machinery: nearly every runtime and integration test
hands it an extractor from ``addCleanup`` or a ``finally`` block. Teardown code
is exactly the code whose bugs stay invisible -- a leak leaks silently, and a
teardown that raises reports itself as a failure in whichever test happened to
be running rather than as a fault in the helper. So the contract is pinned here
rather than left to be inferred from the call sites.

Three things are worth pinning, and they are the three ways this could rot:

* both resources are released, not just the input file
  (:class:`ClosesBothTests`) -- the original helper closed ``_ifile`` alone and
  leaked the engine's :class:`pcap.pcap` handle on every abandoned extractor;
* one broken resource cannot strand the other
  (:class:`IndependenceTests`);
* nothing it is handed in teardown makes it raise
  (:class:`ToleranceTests`).

This module is unit-tier: it drives the helper with stand-ins rather than real
extractors, so it reads no sample capture and needs no engine installed.

"""
from __future__ import annotations

import signal
import time
import unittest

from tests._support import close_extractor, time_limit


class Closeable:
    """A stand-in for a resource that records having been closed.

    Args:
        error: Exception to raise from :meth:`close`, or :data:`None` to close
            cleanly. A resource that raises on close is the half-constructed
            engine case, and is why the helper guards each call.

    """

    def __init__(self, error: 'BaseException | None' = None) -> None:
        self.error = error
        self.calls = 0

    def close(self) -> None:
        self.calls += 1
        if self.error is not None:
            raise self.error


class Extractor:
    """A stand-in exposing the two private attributes the helper reads."""

    def __init__(self, ifile: 'object' = None, exeng: 'object' = None) -> None:
        self._ifile = ifile
        self._exeng = exeng


class ClosesBothTests(unittest.TestCase):
    """The engine is closed as well as the input file."""

    def test_closes_the_input_file_and_the_engine(self) -> None:
        stream, engine = Closeable(), Closeable()

        close_extractor(Extractor(stream, engine))

        self.assertEqual(stream.calls, 1)
        # The regression this guards: closing the stream alone leaves the
        # engine's OS-level handle open for the rest of the process.
        self.assertEqual(engine.calls, 1)


class IndependenceTests(unittest.TestCase):
    """Neither resource can prevent the other from being released."""

    def test_engine_is_closed_even_when_the_stream_close_fails(self) -> None:
        stream, engine = Closeable(OSError('stream is already gone')), Closeable()

        close_extractor(Extractor(stream, engine))

        self.assertEqual(engine.calls, 1)

    def test_stream_is_closed_even_when_the_engine_close_fails(self) -> None:
        stream, engine = Closeable(), Closeable(AttributeError('_extmp'))

        close_extractor(Extractor(stream, engine))

        self.assertEqual(stream.calls, 1)


class ToleranceTests(unittest.TestCase):
    """Nothing teardown can hand the helper makes it raise.

    Each case below is reached in practice: an extractor whose ``__init__``
    failed before assigning ``_exeng``, a test double that is neither, and an
    engine whose ``close`` raises because its handle was never opened.

    """

    def test_absent_attributes_are_ignored(self) -> None:
        close_extractor(object())

    def test_none_valued_attributes_are_ignored(self) -> None:
        close_extractor(Extractor(None, None))

    def test_half_constructed_extractor_without_an_engine(self) -> None:
        stream = Closeable()

        # ``_exeng`` is assigned only once the engine has been selected, so an
        # extractor that raised before that point has no such attribute at all.
        class Partial:
            def __init__(self) -> None:
                self._ifile = stream

        close_extractor(Partial())

        self.assertEqual(stream.calls, 1)

    def test_non_callable_close_attribute_is_ignored(self) -> None:
        class NotReallyCloseable:
            close = 'not a method'

        close_extractor(Extractor(NotReallyCloseable(), NotReallyCloseable()))

    def test_both_closes_raising_is_still_swallowed(self) -> None:
        stream = Closeable(OSError('stream'))
        engine = Closeable(RuntimeError('engine'))

        close_extractor(Extractor(stream, engine))

        self.assertEqual(stream.calls, 1)
        self.assertEqual(engine.calls, 1)

    def test_a_close_lookup_that_raises_is_ignored(self) -> None:
        """Reaching ``close`` at all can fail, and that is tolerated too.

        ``close`` need not be a plain method: as a property, or resolved through
        ``__getattr__``, the *lookup* raises rather than the call. Guarding only
        the call would let that escape and mask the real failure.

        """
        class HostileLookup:
            @property
            def close(self) -> 'object':
                raise RuntimeError('lookup')

        engine = Closeable()

        close_extractor(Extractor(HostileLookup(), engine))

        # And the engine is still closed: one unreachable resource must not
        # strand the other, exactly as when the call itself raises.
        self.assertEqual(engine.calls, 1)


class PropagationTests(unittest.TestCase):
    """What the helper deliberately does *not* swallow."""

    def test_base_exception_is_not_swallowed(self) -> None:
        """A :exc:`KeyboardInterrupt` during teardown still ends the run.

        The helper catches :exc:`Exception`, not :exc:`BaseException`, so
        interrupting a suite mid-teardown is not quietly absorbed by a cleanup
        helper.

        """
        with self.assertRaises(KeyboardInterrupt):
            close_extractor(Extractor(Closeable(KeyboardInterrupt()), Closeable()))


@unittest.skipUnless(hasattr(signal, 'SIGALRM'), 'signal.alarm is unavailable')
class TimeLimitTests(unittest.TestCase):
    """A deadline that arrives, and an enclosing one that survives.

    A process has one pending alarm, so arming a deadline cancels whatever was
    already scheduled. The helper reads what it displaced and puts it back; these
    pin that, because an enclosing deadline going missing is invisible until the
    run it should have bounded hangs instead.

    """

    def setUp(self) -> None:
        # Whatever a test leaves behind, the next one starts from nothing pending
        # and from a handler this class owns rather than the helper's.
        self.handled = []  # type: list[int]
        previous = signal.signal(signal.SIGALRM, lambda signum, frame: self.handled.append(signum))
        self.addCleanup(signal.signal, signal.SIGALRM, previous)
        self.addCleanup(signal.alarm, 0)

    def test_the_deadline_fires_on_a_body_that_overruns(self) -> None:
        """The point of the helper, pinned so the rest cannot be met by disarming."""
        with self.assertRaises(TimeoutError):
            with time_limit(1):
                while True:
                    pass

    def test_an_enclosing_alarm_is_restored(self) -> None:
        """An outer deadline keeps counting down across the ``with``.

        Before this was fixed the helper cancelled the pending alarm on the way out
        and never re-armed it, so an outer ``signal.alarm(30)`` read back as ``0``
        afterwards: the enclosing deadline was gone, silently.

        """
        own_handler = signal.getsignal(signal.SIGALRM)

        signal.alarm(30)
        with time_limit(5):
            pass

        # Reading the remaining seconds cancels the alarm, which is the cleanup
        # this test wanted anyway.
        remaining = signal.alarm(0)

        self.assertGreater(remaining, 0)
        self.assertLessEqual(remaining, 30)
        self.assertIs(signal.getsignal(signal.SIGALRM), own_handler)
        self.assertEqual(self.handled, [])

    def test_an_enclosing_alarm_that_expired_in_the_body_is_re_armed(self) -> None:
        """An outer deadline overtaken by the body is honoured late, not dropped.

        The body holds the process past the moment the outer alarm was due, so it
        cannot be delivered on time. The helper re-arms it for a second rather than
        cancelling it, since cancelling is how an outer timeout goes missing
        altogether.

        """
        signal.alarm(1)
        with time_limit(5):
            time.sleep(1.2)

        remaining = signal.alarm(0)

        self.assertGreaterEqual(remaining, 1)
        self.assertEqual(self.handled, [])

    def test_nothing_is_re_armed_when_nothing_was_pending(self) -> None:
        """The common case: no enclosing deadline, nothing left behind."""
        with time_limit(5):
            pass

        self.assertEqual(signal.alarm(0), 0)


if __name__ == '__main__':
    unittest.main()
