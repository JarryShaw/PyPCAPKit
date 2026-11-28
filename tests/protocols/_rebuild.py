# -*- coding: utf-8 -*-
"""What a parse or a rebuild reports, and how deep it goes, for the rebuild tests.

A rebuild with :meth:`from_data <pcapkit.protocols.protocol.ProtocolBase.from_data>`
is held to report what its parse reported and to stay about as deep. :class:`Logged`
collects what the ``pcapkit`` logger reports, and :func:`reported` that and the
:mod:`warnings` channel, for the modules comparing the two (#2703, #2711);
:func:`depth` counts the Python frames a call goes down, for those bounding the
rebuild's (#1610, #1619). Shared under #3148.

Nothing here imports :mod:`pcapkit`, so each test module keeps its classes'
own import, after :func:`~tests._support.reimport_once_per_class`.

"""
from __future__ import annotations

import contextlib
import logging
import sys
import warnings
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Callable, Iterator, Optional


def logged(record: 'logging.LogRecord') -> 'str':
    """``record`` as ``logged: <message>``."""
    return f'logged: {record.getMessage()}'


def levelled(record: 'logging.LogRecord') -> 'str':
    """``record`` as ``<LEVEL>: <message>``."""
    return f'{record.levelname}: {record.getMessage()}'


class Logged(logging.Handler):
    """Collect what the ``pcapkit`` logger reports, each record as ``form`` writes it.

    A record that ``form`` writes as :data:`None` is left out. Used as a context
    manager, the handler is on the logger for the block.

    """

    def __init__(self, form: 'Callable[[logging.LogRecord], Optional[str]]' = logged) -> None:
        super().__init__(logging.DEBUG)
        self.form = form
        self.messages = []  # type: list[str]

    def emit(self, record: 'logging.LogRecord') -> None:
        message = self.form(record)
        if message is not None:
            self.messages.append(message)

    def __enter__(self) -> 'Logged':
        logging.getLogger('pcapkit').addHandler(self)
        return self

    def __exit__(self, *exc: object) -> None:
        logging.getLogger('pcapkit').removeHandler(self)


@contextlib.contextmanager
def reported(form: 'Callable[[logging.LogRecord], Optional[str]]' = logged) -> 'Iterator[list[str]]':
    """Collect what the block reports: the logger's records as ``form`` writes them,
    then each warning as ``warned: <message>``."""
    with Logged(form) as handler, warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter('always')
        yield handler.messages
    handler.messages.extend(f'warned: {item.message}' for item in caught)


def depth(func: 'Callable[[], object]') -> int:
    """How many Python frames deeper than its caller ``func()`` goes."""
    state = {'now': 0, 'most': 0}

    def profile(frame: object, event: str, arg: object) -> None:  # pylint: disable=unused-argument
        if event == 'call':
            state['now'] += 1
            state['most'] = max(state['most'], state['now'])
        elif event == 'return':
            state['now'] -= 1

    sys.setprofile(profile)
    try:
        func()
    finally:
        sys.setprofile(None)
    return state['most']
