# -*- coding: utf-8 -*-
"""Running Callbacks
=======================

.. module:: pcapkit.utilities.callbacks

:mod:`pcapkit.utilities.callbacks` holds :func:`run_callbacks`, which calls every
registered callback whatever an earlier one raised, as reassembly and flow tracing
both run theirs (:issue:`2881`).

.. versionadded:: 1.7.0

"""
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from logging import Logger
    from typing import Any, Callable, Iterable, Optional

__all__ = ['run_callbacks']

#: Argument the callbacks take.
_T = TypeVar('_T')


def run_callbacks(callbacks: 'Iterable[Callable[[_T], Any]]', argument: '_T', *,
                  logger: 'Logger', subject: 'str') -> 'None':
    """Call each callback with ``argument``, every one whatever the others raise.

    Arguments:
        callbacks: callbacks to call, in order
        argument: the only argument each is called with
        logger: the caller's logger, which records a later error
        subject: what the callbacks are for, leading that record

    Raises:
        Exception: The first :exc:`Exception` a callback raised, once the last
            has run.

    One raising an :exc:`Exception` does not stop the rest: the first such
    error is re-raised once all have run, and a later one logged at debug
    level with its traceback. Any other :exc:`BaseException` propagates at
    once, dropping an earlier error.

    """
    error = None  # type: Optional[Exception]
    for callback in callbacks:
        try:
            callback(argument)
        except Exception as exc:  # pylint: disable=broad-except
            if error is None:
                error = exc
                continue
            # NOTE: logged rather than raised, so it cannot replace the first error.
            logger.debug('%s callback %r raised after an earlier one', subject, callback, exc_info=True)
    if error is not None:
        raise error
