"""Shared scaffolding for the warning/exception emission regressions.

Two things the tests in this directory need and the stdlib does not offer in a
form that fits:

* :func:`capture` -- collect every record a :class:`logging.Logger` emits, at any
  level, without also printing it. :mod:`unittest.TestCase.assertNoLogs` would do
  half of this but only exists on Python 3.10+, and this project declares support
  from 3.6.
* :func:`bootstrap` -- (re)load the :mod:`pcapkit` core modules with
  :envvar:`PCAPKIT_DEVMODE` forced on or off. The flag is read once, at import
  time, so a test that cares about it has to control the environment *before* the
  import rather than patch a module global afterwards.

It is deliberately not named ``test_*``, so :program:`pytest` imports it only
when a test asks for it.

"""
from __future__ import annotations

import contextlib
import logging
import os
import sys
from typing import TYPE_CHECKING

from tests._support import bootstrap_core_modules, purge_modules

if TYPE_CHECKING:
    from typing import Iterator

__all__ = ['Recorder', 'capture', 'bootstrap']


class Recorder(logging.Handler):
    """A handler that keeps the records instead of formatting them."""

    def __init__(self) -> None:
        super().__init__(level=logging.NOTSET)
        self.records = []  # type: list[logging.LogRecord]

    def emit(self, record: 'logging.LogRecord') -> None:
        self.records.append(record)

    @property
    def messages(self) -> 'list[tuple[str, str]]':
        """Every captured record so far, as ``(levelname, message)`` pairs."""
        return [(record.levelname, record.getMessage()) for record in self.records]


@contextlib.contextmanager
def capture(logger: 'logging.Logger') -> 'Iterator[Recorder]':
    """Take ``logger`` over for the duration of the block.

    :mod:`pcapkit.utilities.logging` attaches a :class:`logging.StreamHandler` to
    :data:`sys.stderr` at import time, so a test that merely *adds* a handler
    both counts records and prints them. This swaps the handler list out, drops
    the level to :data:`~logging.DEBUG` so that nothing is filtered out before it
    can be counted, turns off propagation, and restores all three afterwards.

    Capturing at :data:`~logging.DEBUG` is deliberate: an assertion that a quiet
    error logs *nothing* must be able to see a record that has been demoted to
    ``DEBUG``, that being one of the things it might plausibly be changed to.

    """
    recorder = Recorder()
    handlers, level, propagate = logger.handlers, logger.level, logger.propagate
    logger.handlers = [recorder]
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    try:
        yield recorder
    finally:
        logger.handlers = handlers
        logger.setLevel(level)
        logger.propagate = propagate


def bootstrap(devmode: 'bool') -> 'dict[str, object]':
    """Reload the :mod:`pcapkit` core modules with ``PCAPKIT_DEVMODE`` forced.

    Returns the mapping :func:`tests._support.bootstrap_core_modules` returns,
    plus the freshly loaded ``logging`` module under the key ``'logging'``.

    The caller is responsible for restoring :data:`os.environ`; the test cases
    here do it in ``tearDown``.

    """
    os.environ['PCAPKIT_DEVMODE'] = '1' if devmode else '0'
    purge_modules(['pcapkit'])
    modules = dict(bootstrap_core_modules())
    modules['logging'] = sys.modules['pcapkit.utilities.logging']

    # Guard against the test passing for the wrong reason: several of these
    # regressions only reproduce with development mode off, so a silently
    # ignored environment variable would turn a real assertion into a no-op.
    if getattr(modules['logging'], 'DEVMODE') is not devmode:
        raise AssertionError(
            'PCAPKIT_DEVMODE did not take effect: expected DEVMODE=%r, got %r'
            % (devmode, getattr(modules['logging'], 'DEVMODE'))
        )
    return modules
