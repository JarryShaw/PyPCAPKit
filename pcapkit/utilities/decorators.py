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
from pcapkit.utilities.logging import DEVMODE, VERBOSE, get_logger

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


#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)


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
            proto = args[1]
        except IndexError:
            proto = None
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
            logger.warning(str(exc), stack_info=DEVMODE, stacklevel=stacklevel())

            if VERBOSE:
                logger.error('The following error occurred while parsing the packet:')
                traceback.print_exc()

            # NOTE: ``self._get_payload()`` rather than
            # ``self.__header__.get_payload()``, which it wraps. The two agree
            # for every protocol whose payload is a schema field, and differ for
            # the two that override it: SCTP carries user data inside a DATA
            # chunk and PCAP-NG inside a block, so neither header schema has a
            # ``payload`` field at all. Going through the schema there raises
            # ProtocolUnbound('unknown field: payload') *from the recovery path*,
            # turning a next-layer parse failure that should have degraded to
            # Raw into a crash. Unreachable until something was registered on an
            # SCTP payload protocol identifier, which NGAP now is.
            file_ = self._get_payload()

            # NOTE: ``alias=proto`` matches what the success path passes, so a
            # payload that failed to parse is still named after the protocol
            # number it arrived with -- ``SCTP:PayloadProtocolIdentifier_3GPP_NG
            # _Application_Protocol`` rather than a bare ``SCTP:Raw``. Without
            # it, registering a protocol on a number made the output *less*
            # informative than leaving the number unregistered, since an
            # unregistered number reaches Raw through the success path and keeps
            # its name. A plain integer has no ``name`` and still renders as
            # ``Raw``, c.f. ``Raw.__post_init__``, so this only adds a name where
            # the registry key is an enumeration.
            next_ = protocol(file_, length, error=str(exc), alias=proto)
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

        # NOTE: ``Schema.unpack`` clears ``__updated__`` before returning, but
        # ``post_process`` runs after it and assigns fields -- and every field
        # assignment sets the flag again (``Schema.__setattr__``). The schema is
        # then left marked as needing a re-pack even though its ``__buffer__``
        # already holds the octets just read off the wire, so the next
        # ``bytes(schema)`` or ``len(schema)`` silently re-packs it.
        #
        # That re-pack is not merely wasted work: ``Schema.pack`` calls
        # ``post_process`` a *second* time, with a packet context rebuilt from
        # the schema's own fields and therefore holding none of the enclosing
        # layer's, so it overwrites exactly the values ``post_process`` derived
        # from that context. It is what discarded the IPv6 source address that
        # ``pcapkit.protocols.schema.internet.hopopt.MPLOption.post_process``
        # had just resolved: ``OptionField.unpack`` measures each parsed option
        # with ``len(data)``, which triggered the re-pack one option later.
        #
        # ``Schema.pack`` already orders the two the other way round -- clear the
        # flag *after* ``post_process``, not before -- so match it here and the
        # revision made while unpacking survives.
        #
        # Guarded rather than assigned outright because ``post_process`` may hand
        # back something other than a schema: an implementation is free to return
        # a nested one instead of ``self``, as
        # ``pcapkit.protocols.schema.internet.hopopt._SMFDPDOption`` does, and the
        # decorator is also applied to stand-ins in the test suite that return
        # the packet mapping. Only a real schema carries the flag.
        if hasattr(ret, '__updated__'):
            ret.__updated__ = False

        return cast('R_prepare', ret)
    return unpack
