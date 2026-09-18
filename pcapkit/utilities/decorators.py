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

from pcapkit.utilities.exceptions import StreamEOFError, StructError, stacklevel
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

            # NOTE: ``alias=proto`` matches what ``_import_next_layer`` passes, so
            # a payload that failed to parse still reports the code it arrived
            # with, which is what ``Data_Raw.protocol`` means. A plain integer has
            # no ``name`` and still renders as ``Raw`` in the protochain, c.f.
            # ``Raw.__post_init__``, so this only adds a name where the registry
            # key is an enumeration.
            #
            # Measured, because the layers differ and it is easy to state this too
            # broadly: SCTP's unregistered path keeps its enumeration -- an unknown
            # PPID gives ``SCTP:Unassigned_4243`` and ``protocol=4243`` -- so
            # without this line, *registering* NGAP on PPID 60 would have made a
            # failed parse report a bare ``SCTP:Raw`` and ``protocol=None``, less
            # than the same bytes gave while unregistered. TCP's unregistered path
            # does not: an unknown port yields ``protocol=None`` already, because
            # ``Transport._decode_next_layer`` resolves ports through
            # ``__proto__`` and never reaches here. So this makes the *failure*
            # path uniform while the *unknown* paths stay inconsistent with each
            # other, which is #418 rather than something to fix from inside a
            # decorator.
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
                 length: 'Optional[int]',
                 packet: 'Optional[dict[str, Any]]') -> 'pcapkit.protocols.schema.schema.Schema'

        No further positional or keyword arguments are read from -- or
        forwarded to -- the decorated function. :func:`prepare` is applied to
        exactly one function in this tree,
        :meth:`Schema.unpack <pcapkit.protocols.schema.schema.Schema.unpack>`,
        whose real signature has never had more than these four parameters,
        and nothing calls it with more; an earlier revision of this note
        nonetheless promised implementors a trailing ``*args, **kwargs``, which
        the wrapper below never populated. A caller relying on that promise
        got extras silently discarded instead of forwarded -- see `#454
        <https://github.com/JarryShaw/PyPCAPKit/issues/454>`__ -- so the
        wrapper now raises :exc:`TypeError` for a fifth positional argument or
        an unconsumed keyword, the same as an ordinary call with too many
        arguments would.

    See Also:
        :meth:`pcapkit.protocols.schema.schema.Schema.unpack`

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

        # NOTE: The decorated function's real signature is exactly the four
        # parameters above -- see #454. Anything left over here is therefore
        # unwanted rather than something to forward: a fifth positional
        # argument, or a keyword that ``kwargs.pop`` above never touched
        # because ``length``/``packet`` arrived positionally instead. The
        # latter is also what catches ``length`` (or ``packet``) supplied
        # *both* positionally and by keyword -- the positional value wins
        # above and the keyword is left in ``kwargs`` unconsumed, so it
        # surfaces here rather than silently losing the keyword's value.
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
            # ``pcapkit.foundation.extraction.Extractor`` and friends -- c.f.
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
