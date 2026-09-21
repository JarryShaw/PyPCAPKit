"""Regression tests for #362 -- ``quiet=True`` must mean *emit nothing*.

``BaseError.__init__`` used to treat ``quiet`` as "log at ``ERROR`` instead of
``CRITICAL``", so every absent-key lookup through
:meth:`MultiDict.get <pcapkit.corekit.multidict.MultiDict.get>` -- which raises
:exc:`~pcapkit.utilities.exceptions.MissingKeyError` with ``quiet=True`` and
catches it immediately -- put an ``ERROR`` record on :data:`sys.stderr`. Parsing a
capture with unfragmented IPv6 and reassembly enabled produced one such record
per frame, for what the calling code itself documents as the ordinary case.

The same constructor also set :data:`sys.tracebacklimit` to ``0`` on both
branches, so an absent-key ``.get()`` truncated the tracebacks of entirely
unrelated exceptions for the rest of the process. ``quiet=True`` now means no log
record on any channel and no process-global side effect; a loud error is
unchanged.

"""
from __future__ import annotations

import io
import os
import sys
import traceback
import unittest

from tests._support import purge_modules
from tests.utilities._harness import bootstrap, capture


def _unrelated_failure() -> 'int':
    """Format an unrelated exception and count the traceback's lines.

    The :mod:`traceback` module honours :data:`sys.tracebacklimit`, so this is
    what a logging handler using ``exc_info=True``, or a framework's error page,
    would show for an exception that has nothing to do with :mod:`pcapkit`.

    """
    def inner() -> None:
        raise ValueError('an exception that has nothing to do with pcapkit')

    def middle() -> None:
        inner()

    try:
        middle()
    except ValueError:
        return len(traceback.format_exc().splitlines())
    raise AssertionError('unreachable')  # pragma: no cover


class QuietExceptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._saved_devmode = os.environ.get('PCAPKIT_DEVMODE')
        self._saved_tracebacklimit = getattr(sys, 'tracebacklimit', None)
        # The defect, and the traceback truncation, only reproduce outside
        # development mode.
        modules = bootstrap(devmode=False)
        self.exceptions = modules['exceptions']
        self.multidict = modules['multidict']
        self.decorators = modules['decorators']
        self.logger = modules['logging'].logger

    def tearDown(self) -> None:
        if self._saved_tracebacklimit is None:
            if hasattr(sys, 'tracebacklimit'):
                del sys.tracebacklimit
        else:
            sys.tracebacklimit = self._saved_tracebacklimit
        if self._saved_devmode is None:
            os.environ.pop('PCAPKIT_DEVMODE', None)
        else:
            os.environ['PCAPKIT_DEVMODE'] = self._saved_devmode
        purge_modules(['pcapkit'])

    def test_quiet_error_logs_nothing(self) -> None:
        with capture(self.logger) as recorder:
            error = self.exceptions.BaseError('boom', quiet=True)

        self.assertEqual(recorder.messages, [])
        self.assertEqual(str(error), 'boom')

    def test_quiet_error_with_keyword_state_logs_nothing(self) -> None:
        """A ``quiet`` subclass that carries extra state is still silent."""
        with capture(self.logger) as recorder:
            error = self.exceptions.StructError('truncated', eof=True, quiet=True)

        self.assertEqual(recorder.messages, [])
        self.assertTrue(error.eof)
        self.assertEqual(str(error), 'truncated')

    def test_loud_error_still_logs_exactly_once_at_critical(self) -> None:
        with capture(self.logger) as recorder:
            self.exceptions.BaseError('boom')

        self.assertEqual(recorder.messages, [('CRITICAL', 'BaseError: boom')])

    def test_absent_key_lookup_logs_nothing(self) -> None:
        """``.get()`` on an absent key is control flow, not an error."""
        for name in ('MultiDict', 'OrderedMultiDict'):
            with self.subTest(mapping=name):
                mapping = getattr(self.multidict, name)()

                with capture(self.logger) as recorder:
                    missing = mapping.get('absent')
                    defaulted = mapping.get('absent', 'fallback')

                self.assertEqual(recorder.messages, [])
                self.assertIsNone(missing)
                self.assertEqual(defaulted, 'fallback')

    def test_absent_key_subscript_still_raises(self) -> None:
        """Silencing the log must not silence the exception."""
        for name in ('MultiDict', 'OrderedMultiDict'):
            with self.subTest(mapping=name):
                mapping = getattr(self.multidict, name)()

                with capture(self.logger) as recorder:
                    with self.assertRaises(self.exceptions.MissingKeyError):
                        mapping['absent']
                    with self.assertRaises(KeyError):
                        mapping['absent']

                self.assertEqual(recorder.messages, [])

    def test_quiet_error_leaves_tracebacklimit_alone(self) -> None:
        if hasattr(sys, 'tracebacklimit'):
            del sys.tracebacklimit
        before = _unrelated_failure()

        with capture(self.logger):
            self.multidict.OrderedMultiDict().get('absent')
            self.exceptions.BaseError('boom', quiet=True)

        self.assertFalse(hasattr(sys, 'tracebacklimit'))
        self.assertEqual(_unrelated_failure(), before)
        self.assertGreater(before, 1)

    def test_prepare_raises_stream_eof_error_quietly(self) -> None:
        """End of stream is control flow, so ``prepare`` raises it silently.

        :func:`~pcapkit.utilities.decorators.prepare` passes ``quiet=True``
        when a *measured* -- as opposed to caller-declared -- read length comes
        back zero, because that is how the frame reader learns a capture is
        exhausted rather than a fault worth a log record. It is the same
        convention :exc:`~pcapkit.utilities.exceptions.StructError` follows via
        its own ``eof=True``.

        Dropping the ``quiet=True`` would put one ``CRITICAL`` record on
        :data:`sys.stderr` for every capture parsed to completion, which is the
        #362 defect this module exists for -- and would also set
        :data:`sys.tracebacklimit` to ``0`` process-wide.

        """
        class DemoSchema:
            @classmethod
            def pre_unpack(cls, packet):
                return None

            def post_process(self, packet):
                return packet

            @classmethod
            @self.decorators.prepare
            def unpack(cls, data, length=None, packet=None):
                return cls()

        if hasattr(sys, 'tracebacklimit'):
            del sys.tracebacklimit

        with capture(self.logger) as recorder:
            with self.assertRaises(self.exceptions.StreamEOFError) as caught:
                DemoSchema.unpack(io.BytesIO(b''), None, None)

        self.assertEqual(recorder.messages, [])
        self.assertEqual(str(caught.exception), 'prepare: end of stream')
        self.assertFalse(hasattr(sys, 'tracebacklimit'))

    def test_loud_stream_eof_error_still_logs(self) -> None:
        """The control for the test above: ``quiet`` is what silences it.

        Without this, ``recorder.messages == []`` would also pass if
        :exc:`~pcapkit.utilities.exceptions.StreamEOFError` had simply stopped
        logging altogether.

        """
        if hasattr(sys, 'tracebacklimit'):
            del sys.tracebacklimit

        with capture(self.logger) as recorder:
            self.exceptions.StreamEOFError('boom')

        self.assertEqual(recorder.messages, [('CRITICAL', 'StreamEOFError: boom')])

    def test_loud_error_still_limits_the_traceback(self) -> None:
        """The feature a loud error provides is unchanged."""
        if hasattr(sys, 'tracebacklimit'):
            del sys.tracebacklimit

        with capture(self.logger):
            self.exceptions.BaseError('boom')

        self.assertEqual(sys.tracebacklimit, 0)


if __name__ == '__main__':
    unittest.main()
