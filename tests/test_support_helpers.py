# -*- coding: utf-8 -*-
"""Tests for :func:`tests._support.close_extractor`.

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

import unittest

from tests._support import close_extractor


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


if __name__ == '__main__':
    unittest.main()
