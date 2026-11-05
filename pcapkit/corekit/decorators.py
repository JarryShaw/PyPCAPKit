# -*- coding: utf-8 -*-
# pylint: disable=protected-access
"""Decorator Functions
=========================

.. module:: pcapkit.corekit.decorators

:mod:`pcapkit.corekit.decorators` contains the decorators
:func:`~pcapkit.corekit.decorators.seekset`,
:func:`~pcapkit.corekit.decorators.beholder` and
:func:`~pcapkit.corekit.decorators.prepare`.

They act on a protocol's file and on the schema it unpacks, and
:func:`~pcapkit.corekit.decorators.beholder` falls back to protocol classes,
so they live with the packet model rather than in :mod:`pcapkit.utilities`
(:issue:`1735`).

.. versionadded:: 1.5.0

.. versionremoved:: 1.5.0

   ``pcapkit.utilities.decorators``, now :mod:`pcapkit.corekit.decorators`
   (:issue:`1735`). :mod:`pcapkit.utilities` does not export these
   decorators either.

"""
import functools
import io
import os
import traceback
from typing import TYPE_CHECKING, cast

from pcapkit.utilities.contextvars import beholding, rebuilding
from pcapkit.utilities.exceptions import (CaughtByCaller, ProtocolError, StreamEOFError,
                                          StructError, stacklevel)
from pcapkit.utilities.logging import DEVMODE, VERBOSE, get_logger

if TYPE_CHECKING:
    from typing import IO, Any, Callable, Optional, Type, TypeVar

    from typing_extensions import Concatenate, ParamSpec

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema import Schema

    P = ParamSpec('P')
    R_seekset = TypeVar('R_seekset')
    R_beholder = TypeVar('R_beholder', bound=ProtocolBase)
    R_prepare = TypeVar('R_prepare', bound=Schema)

__all__ = ['seekset', 'beholder', 'prepare']


#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)


def seekset(func: 'Callable[Concatenate[ProtocolBase, P], R_seekset]') -> 'Callable[P, R_seekset]':
    """Read file from start then set back to original.

    Important:
        This decorator function is designed for decorating *instance methods*.

    The decorator will keep the current offset of :attr:`self._file <pcapkit.protocols.protocol.Protocol._file>`,
    then call the decorated function. Afterwards, it will rewind the offset of
    :attr:`self._file <pcapkit.protocols.protocol.Protocol._file>` to the original and return the return value from
    the decorated function.

    Note:
        The decorated function should have the following signature::

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
        self = cast('ProtocolBase', args[0])

        # move file pointer
        seek_cur = self._file.tell()
        self._file.seek(self._seekset, os.SEEK_SET)

        # call method
        return_ = func(*args, **kw)

        # reset file pointer
        self._file.seek(seek_cur, os.SEEK_SET)
        return return_
    return seekcur


def beholder(
    func: 'Callable[Concatenate[ProtocolBase, int, Optional[int], P], R_beholder]',
) -> 'Callable[P, R_beholder]':
    """Behold extraction procedure.

    Important:
        This decorator function is designed for decorating *instance methods*.

    This decorator calls the decorated function. Should any exception be
    raised, it re-parses the current layer's payload as
    :class:`~pcapkit.protocols.misc.raw.protocol.Raw` -- or as
    :class:`~pcapkit.protocols.misc.no_payload.protocol.NoPayload`, if the error is an
    end-of-file :exc:`~pcapkit.utilities.exceptions.StructError` -- whose
    ``error`` is the exception's message.

    The decorated call runs inside a
    :class:`~pcapkit.utilities.exceptions.CaughtByCaller` block naming
    :exc:`~pcapkit.utilities.exceptions.ProtocolError` (:issue:`2588`). The
    block spans the whole call, so every such error built while it runs is
    quiet, at any depth and whether or not the code that built it catches it,
    unless an inner :class:`~pcapkit.utilities.exceptions.CaughtByCaller` says
    otherwise: the next layer refusing its octets, a parser's own trial, a
    registry entry whose class its module has since lost. One that reaches
    here is recorded on ``error`` and is not logged here either. Any other
    exception is logged here at :data:`logging.WARNING`, and is as loud as it
    was constructed.

    Inside a payload :meth:`Protocol._make_payload
    <pcapkit.protocols.protocol.Protocol._make_payload>` rebuilds, the block
    names every :exc:`Exception`, which is what the ``except`` below catches,
    and nothing is logged here: the layer the payload is rebuilt for parses
    the same octets again, outside the rebuild, and its own :func:`beholder`
    reports the error there (:issue:`2711`).

    The recovery runs after the block has ended. Under the outermost
    :func:`beholder` of a parse, a
    :exc:`~pcapkit.utilities.exceptions.ProtocolError` it raises therefore
    reaches the caller loud; under any other, the block of the
    :func:`beholder` around it is still active, so that error is quiet, and
    becomes the enclosing replacement's ``error``.

    When :meth:`Protocol._parse_next_layer
    <pcapkit.protocols.protocol.Protocol._parse_next_layer>` held the
    warnings of the layer that raised, they are dropped with it: they describe a
    layer the result does not have, and the replacement's ``error`` reports the
    failure (:issue:`2308`).

    Note:
        The decorated function should have the following signature::

            func(self: 'pcapkit.protocols.protocol.ProtocolBase',
                 proto: 'int', length: 'typing.Optional[int]',
                 *args: 'typing.Any', **kwargs: 'typing.Any') -> 'pcapkit.protocols.protocol.ProtocolBase'

    See Also:
        :meth:`pcapkit.protocols.protocol.Protocol._decode_next_layer`

    .. versionchanged:: 1.3.0

       Logs the exception it absorbs, and prints its traceback in verbose mode.

    .. versionchanged:: 1.6.0

       A :exc:`~pcapkit.utilities.exceptions.ProtocolError` the decorated
       function builds is quiet, and one this decorator absorbs is not logged
       here either (:issue:`2588`). Inside a payload being rebuilt, so is every
       other error (:issue:`2711`).

    :param func: decorated function
    :meta decorator:
    """
    @functools.wraps(func)
    def behold(*args: 'P.args', **kwargs: 'P.kwargs') -> 'R_beholder':
        # extract self object & args
        self = cast('R_beholder', args[0])
        try:
            proto = args[1]
        except IndexError:
            proto = None
        try:
            length = cast('int', args[2])
        except IndexError:
            length = None

        # NOTE: A rebuilt payload's parse is repeated by the layer it is rebuilt
        # for, which reports what this one would (#2711).
        rebuilt = rebuilding.get()
        try:
            # call method
            token = beholding.set(True)
            try:
                # NOTE: The whole call is quiet for a ProtocolError, which the ``except`` below
                # records; the recovery runs after it, loud unless an outer block is active (#2588).
                with CaughtByCaller(Exception if rebuilt else ProtocolError):
                    return func(*args, **kwargs)
            finally:
                beholding.reset(token)
        except Exception as exc:
            if isinstance(exc, StructError) and exc.eof:  # pylint: disable=no-member
                from pcapkit.protocols.misc.no_payload.protocol import NoPayload as protocol  # isort: skip # pylint: disable=import-outside-toplevel
            else:
                from pcapkit.protocols.misc.raw.protocol import Raw as protocol  # type: ignore[assignment] # isort: skip # pylint: disable=import-outside-toplevel
            # error = traceback.format_exc(limit=1).strip().rsplit(os.linesep, maxsplit=1)[-1]

            # NOTE: Keyed on the class, not on quietness: a quiet end-of-file StructError is still
            # logged here, and a ProtocolError built loud has logged at CRITICAL already (#2588).
            if not isinstance(exc, ProtocolError) and not rebuilt:
                logger.warning(str(exc), stack_info=DEVMODE, stacklevel=stacklevel())

                if VERBOSE:
                    logger.error('The following error occurred while parsing the packet:')
                    traceback.print_exc()

            # NOTE: A ``payload`` passed in wins, as IPv6 hands its upper layer the octets
            # past the extension headers, which would otherwise be held twice (#1471).
            file_ = cast('Optional[bytes]', kwargs.get('payload'))
            if file_ is None:
                # NOTE: Not ``self.__header__.get_payload()``, as SCTP and PCAP-NG schemas
                # have no ``payload`` field and the recovery path would crash on them.
                file_ = self._get_payload()

            # NOTE: ``alias=proto`` matches ``_import_next_layer``, so a failed parse still
            # reports the code it arrived with as ``Data_Raw.protocol`` (#418).
            next_ = protocol(file_, length, error=str(exc), alias=proto)
            return cast('R_beholder', next_)
    return behold


def prepare(func: 'Callable[Concatenate[Type[R_prepare], bytes | IO[bytes], Optional[int], Optional[dict[str, Any]], P], R_prepare]') -> 'Callable[P, R_prepare]':
    """Prepare schema packet data before unpacking.

    Important:
        This decorator function is designed for decorating the
        :meth:`Schema.unpack <pcapkit.protocols.schema.Schema.unpack>`
        *class method*.

    This decorator will revise the parameter list provided to the original
    :meth:`Schema.unpack <pcapkit.protocols.schema.Schema.unpack>` method
    and extract necessary information based on the given parameters, then provide
    the revised version of parameter list to the original method.

    Note:
        The decorated function should have the following signature::

            func(cls: 'typing.Type[pcapkit.protocols.schema.Schema]',
                 data: 'bytes | typing.IO[bytes]',
                 length: 'Optional[int]',
                 packet: 'Optional[dict[str, Any]]') -> 'pcapkit.protocols.schema.Schema'

        No further positional or keyword arguments are read from -- or
        forwarded to -- the decorated function. :func:`prepare` is applied only to
        :meth:`Schema.unpack <pcapkit.protocols.schema.Schema.unpack>`,
        whose real signature has exactly these parameters, and nothing
        calls it with more. Rather than discard extras silently (:issue:`454`),
        the wrapper raises :exc:`TypeError` for an extra positional argument or
        an unconsumed keyword, the same as an ordinary call with too many
        arguments would.

    See Also:
        :meth:`pcapkit.protocols.schema.Schema.unpack`

    :param func: decorated function
    :meta decorator:
    """
    @functools.wraps(func)
    def unpack(*args: 'P.args', **kwargs: 'P.kwargs') -> 'R_prepare':
        cls = cast('Type[R_prepare]', args[0])
        data = cast('bytes | IO[bytes]', args[1])
        # ``length`` and ``packet`` are optional, both in the decorated
        # signature and here: a caller may omit them, pass them positionally,
        # or pass them by keyword. ``args`` only has an ``[2]``/``[3]`` to
        # subscript when the caller supplied that many positionals, so fall
        # back to ``kwargs`` -- and to the documented default of ``None`` --
        # rather than assuming the position is always filled.
        length = cast('Optional[int]', args[2] if len(args) > 2 else kwargs.pop('length', None))
        packet = cast('Optional[dict[str, Any]]', args[3] if len(args) > 3 else kwargs.pop('packet', None))

        # NOTE: The real signature is exactly the parameters above (#454), so anything left is
        # unwanted, including ``length``/``packet`` given both positionally and by keyword.
        extra_args = args[4:]
        if extra_args or kwargs:
            culprits = ', '.join([repr(arg) for arg in extra_args]
                                  + [f'{name}={value!r}' for name, value in kwargs.items()])
            raise TypeError(f'{func.__qualname__}() got unexpected argument(s): {culprits}')

        # Whether the caller told us exactly how much there is to read, even
        # if that is zero -- e.g. a nested schema sized by a ``length`` field
        # that evaluates to zero, or an otherwise genuinely empty schema -- as
        # opposed to leaving ``length`` to be derived from what is actually
        # left in ``data``. Only a *derived* zero means the underlying stream
        # itself is exhausted; a *declared* zero means this schema legitimately
        # has nothing to read. See #458.
        declared_length = length is not None

        if isinstance(data, bytes):
            length = len(data) if length is None else length
            data = io.BytesIO(data)
        else:
            if length is None:
                current = data.tell()
                length = data.seek(0, io.SEEK_END) - current
                data.seek(current)

        if length == 0 and not declared_length:
            # Quiet: this is the frame reader's ordinary "no more packets"
            # signal, caught as such by
            # ``pcapkit.foundation.extraction.Extractor`` and friends -- cf.
            # ``pcapkit.protocols.protocol.ProtocolBase._read_unpack``'s
            # ``StructError(..., quiet=True, eof=True)`` for the same pattern.
            raise StreamEOFError('prepare: end of stream', quiet=True)

        if packet is None:
            packet = {}
        packet['__length__'] = length

        # call the user customised preparation method
        # then proceed with the unpacking process
        # and eventually revise the schema data
        cls.pre_unpack(packet)
        schema = func(cls, data, length, packet)
        ret = schema.post_process(packet)

        # NOTE: ``post_process`` sets ``__updated__`` again, so a later re-pack would rerun it
        # without the enclosing layer's context; clear it as ``Schema.pack`` does, if present.
        if hasattr(ret, '__updated__'):
            ret.__updated__ = False

        return cast('R_prepare', ret)
    return unpack
