# -*- coding: utf-8 -*-
"""#2881: :func:`pcapkit.utilities.callbacks.run_callbacks` runs every callback.

The first :exc:`Exception` a callback raises is re-raised once the last has run,
a later one is logged on the caller's logger at debug level with its traceback,
and any other :exc:`BaseException` stops the rest at once. Reassembly and flow
tracing run their callbacks through it, as ruled in review of #2875 (#2855).

"""

import logging
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Callable, Optional

#: Test tier (#1958): pure-Python control flow, the same on every interpreter.
__tier__ = 'LATEST'

#: The logger the cases pass as the caller's, outside :mod:`pcapkit`'s own.
LOGGER = logging.getLogger(__name__)


class Refused(Exception):
    """What a raising callback raises."""


class Halted(BaseException):
    """A :exc:`BaseException` that is not an :exc:`Exception`."""


class RunCallbacksTests(unittest.TestCase):
    """What :func:`~pcapkit.utilities.callbacks.run_callbacks` calls, raises and logs."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.utilities.callbacks import run_callbacks

        self.run_callbacks = run_callbacks
        self.calls = []  # type: list[tuple[str, Any]]

    def callback(self, label: str, error: 'Optional[BaseException]' = None) -> 'Callable[[Any], None]':
        """A callback recording ``label`` and its argument, then raising ``error``."""
        def callback(argument: 'Any') -> None:
            self.calls.append((label, argument))
            if error is not None:
                raise error
        return callback

    def call(self, *callbacks: 'Callable[[Any], None]', argument: 'Any' = 'flow') -> None:
        """Run ``callbacks`` on ``argument``, as the caller ``LOGGER`` belongs to."""
        return self.run_callbacks(callbacks, argument, logger=LOGGER, subject='TCP flow f1')

    def labels(self) -> 'list[str]':
        """The callbacks called, in order."""
        return [label for (label, _) in self.calls]

    def test_every_callback_runs_on_the_argument(self) -> None:
        """#2881: with none raising, each runs once, in order, on the one argument."""
        argument = object()
        self.assertIsNone(self.call(self.callback('1'), self.callback('2'), argument=argument))
        self.assertEqual(self.calls, [('1', argument), ('2', argument)])
        self.call()
        self.assertEqual(self.labels(), ['1', '2'])

    def test_the_first_error_propagates_once_the_last_has_run(self) -> None:
        """#2881: callbacks 1, 2 (raising) and 3 all run, and the second's error propagates."""
        error = Refused('second')
        with self.assertRaises(Refused) as caught:
            self.call(self.callback('1'), self.callback('2', error), self.callback('3'))
        self.assertIs(caught.exception, error)
        self.assertEqual(self.labels(), ['1', '2', '3'])

    def test_a_later_error_is_logged_on_the_callers_logger(self) -> None:
        """#2881: with two raising, the first propagates and the second is logged at debug."""
        first, second = Refused('first'), ValueError('second')
        refusing = self.callback('2', second)
        with self.assertLogs(LOGGER, logging.DEBUG) as logs, self.assertRaises(Refused) as caught:
            self.call(self.callback('1', first), refusing, self.callback('3'))
        self.assertIs(caught.exception, first)
        self.assertEqual(self.labels(), ['1', '2', '3'])
        (record,) = logs.records
        self.assertEqual((record.name, record.levelno), (LOGGER.name, logging.DEBUG))
        self.assertEqual(record.getMessage(), f'TCP flow f1 callback {refusing!r} raised after an earlier one')
        self.assertIs(record.exc_info[1], second)  # type: ignore[index]

    def test_a_base_exception_stops_the_rest_at_once(self) -> None:
        """#2881: a ``KeyboardInterrupt`` or other non-``Exception`` stops them, over an earlier error."""
        for halt in (KeyboardInterrupt, SystemExit, Halted):
            for earlier in (False, True):
                with self.subTest(halt=halt.__name__, earlier=earlier):
                    self.calls.clear()
                    with self.assertRaises(halt):
                        self.call(self.callback('1', Refused() if earlier else None), self.callback('2', halt()),
                                  self.callback('3'))
                    self.assertEqual(self.labels(), ['1', '2'])


if __name__ == '__main__':
    unittest.main()
