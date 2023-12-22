# -*- coding: utf-8 -*-
# pylint: disable=protected-access
"""Decorator Functions
=========================

.. module:: pcapkit.utilities.decorators

:mod:`pcapkit.utilities.decorators` contains several useful
decorators, including :func:`~pcapkit.utilities.decorators.seekset`,
:func:`~pcapkit.utilities.decorators.beholder` and
:func:`~pcapkit.utilities.decorators.prepare`.

"""
import functools
import io
import os
import traceback
from typing import TYPE_CHECKING, cast

from pcapkit.utilities.exceptions import StructError, stacklevel
from pcapkit.utilities.logging import DEVMODE, VERBOSE, logger

if TYPE_CHECKING:
    from typing import IO, Any, Callable, Optional, Type, TypeVar

    from typing_extensions import Concatenate, ParamSpec

    from pcapkit.protocols.protocol import ProtocolBase as Protocol
    from pcapkit.protocols.schema.schema import Schema

    P = ParamSpec('P')
    R_seekset = TypeVar('R_seekset')
    R_beholder = TypeVar('R_beholder', bound=Protocol)
    R_prepare = TypeVar('R_prepare', bound=Schema)

__all__ = ['seekset', 'beholder', 'prepare']


def seekset(func: 'Callable[Concatenate[Protocol, P], R_seekset]') -> 'Callable[P, R_seekset]':
    """Read file from start then set back to original.

    Important:
        This decorator function is designed for decorating *class methods*.

    The decorator will keep the current offset of :attr:`self._file <pcapkit.protocols.protocol.Protocol._file>`,
    then call the decorated function. Afterwards, it will rewind the  offset of
    :attr:`self._file <pcapkit.protocols.protocol.Protocol._file>` to the original and returns the return value from
    the decorated function.

    Note:
        The decorated function should have following signature::

            func(self: 'pcapkit.protocols.protocol.ProtocolBase',
                 *args: 'typing.Any', **kwargs: 'typing.Any') -> 'typing.Any'

    See Also:
        :meth:`pcapkit.protocols.protocol.Protocol._read_packet`

    :param func: decorated function
    :meta decorator:
    """
    @functools.wraps(func)
    def seekcur(*args: 'P.args', **kw: 'P.kwargs') -> 'R_seekset':
        # extract self object
        self = cast('Protocol', args[0])

        # move file pointer
        seek_cur = self._file.tell()
        self._file.seek(self._seekset, os.SEEK_SET)

        # call method
        return_ = func(*args, **kw)

        # reset file pointer
        self._file.seek(seek_cur, os.SEEK_SET)
        return return_
    return seekcur


def beholder(func: 'Callable[Concatenate[Protocol, int, Optional[int], P], R_beholder]') -> 'Callable[P, R_beholder]':
    """Behold extraction procedure.

    Important:
        This decorator function is designed for decorating *class methods*.

    This decorator first keep the current offset of
    :attr:`self._file <pcapkit.protocols.protocol.Protocol._file>`, then
    try to call the decorated function. Should any exception raised, it will
    re-parse the :attr:`self._file <pcapkit.protocols.protocol.Protocol._file>`
    as :class:`~pcapkit.protocols.misc.raw.Raw` protocol.

    Note:
        The decorated function should have following signature::

            func(self: 'pcapkit.protocols.protocol.ProtocolBase',
                 proto: 'int', length: 'typing.Optional[int]',
                 *args: 'typing.Any', **kwargs: 'typing.Any') -> 'pcapkit.protocols.protocol.ProtocolBase'

    See Also:
        :meth:`pcapkit.protocols.protocol.Protocol._decode_next_layer`

    :param func: decorated function
    :meta decorator:
    """
    @functools.wraps(func)
    def behold(*args: 'P.args', **kwargs: 'P.kwargs') -> 'R_beholder':
        # extract self object & args
        self = cast('R_beholder', args[0])
        try:
            length = cast('int', args[2])
        except IndexError:
            length = None

        # record file pointer
        try:
            # call method
            return func(*args, **kwargs)
        except Exception as exc:
            if isinstance(exc, StructError) and exc.eof:  # pylint: disable=no-member
                from pcapkit.protocols.misc.null import NoPayload as protocol  # isort: skip # pylint: disable=import-outside-toplevel
            else:
                from pcapkit.protocols.misc.raw import Raw as protocol  # type: ignore[assignment] # isort: skip # pylint: disable=import-outside-toplevel
            # error = traceback.format_exc(limit=1).strip().rsplit(os.linesep, maxsplit=1)[-1]

            # log error
            logger.error(str(exc), exc_info=exc, stack_info=DEVMODE, stacklevel=stacklevel())
            if VERBOSE:
               traceback.print_exc()

            file_ = self.__header__.get_payload()
            next_ = protocol(file_, length, error=str(exc))
            return cast('R_beholder', next_)
    return behold


def prepare(func: 'Callable[Concatenate[Type[R_prepare], bytes | IO[bytes], Optional[int], Optional[dict[str, Any]], P], R_prepare]') -> 'Callable[P, R_prepare]':
    """Prepare schema packet data before unpacking.

    Important:
        This decorate function is designed for decorating the
        :meth:`Schema.unpack <pcapkit.protocols.schema.schema.Schema.unpack>`
        *class method*.

    This decorator will revise the parameter list provided to the original
    :meth:`Schema.unpack <pcapkit.protocols.schema.schema.Schema.unpack>` method
    and extract necessary information based on the given parameters, then provide
    the revised version of parameter list to the original method.

    Note:
        The decorated function should have following signature::

            func(cls: 'typing.Type[pcapkit.protocols.schema.schema.Schema]',
                 data: 'bytes | typing.IO[bytes]',
                 length: 'Optional[int],
                 packet: 'Optional[dict[str, Any]',
                 *args: 'typing.Any', **kwargs: 'Any') -> 'pcapkit.protocols.schema.schema.Schema'

    See Also:
        :meth:`pcapkit.protocols.schema.schema.Schema.unpack`

    :param func: decorated function
    :meta decorator:
    """
    @functools.wraps(func)
    def unpack(*args: 'P.args', **kwargs: 'P.kwargs') -> 'R_prepare':
        cls = cast('Type[R_prepare]', args[0])
        data = cast('bytes | IO[bytes]', args[1])
        length = cast('Optional[int]', args[2])
        packet = cast('Optional[dict[str, Any]]', args[3])

        if isinstance(data, bytes):
            length = len(data) if length is None else length
            data = io.BytesIO(data)
        else:
            if length is None:
                current = data.tell()
                length = data.seek(0, io.SEEK_END) - current
                data.seek(current)

        if length == 0:
            raise EOFError

        if packet is None:
            packet = {}
        packet['__length__'] = length

        # call the user customised preparation method
        # then proceed with the unpacking process
        # and eventually revise the schema data
        cls.pre_unpack(packet)
        schema = func(cls, data, length, packet)
        ret = schema.post_process(packet)

        return cast('R_prepare', ret)
    return unpack
