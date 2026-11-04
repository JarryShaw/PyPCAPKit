# -*- coding: utf-8 -*-
"""Transport Layer Protocol Registries
=========================================

.. module:: pcapkit.foundation.registry.protocols.transport

This module provides the registries of the transport layer protocols in
:mod:`pcapkit.protocols.transport`.

.. versionadded:: 1.6.0

   Moved here from the single :file:`pcapkit/foundation/registry/protocols.py`
   module. The :mod:`pcapkit.foundation.registry.protocols` package exports
   this module's functions (:issue:`2578`).

"""
from typing import TYPE_CHECKING, cast, overload

from pcapkit.const.dccp.option import Option as DCCP_Option
from pcapkit.const.reg.apptype import AppType as Enum_AppType
from pcapkit.const.reg.apptype import TransportProtocol
from pcapkit.const.sctp.cause_code import CauseCode as SCTP_CauseCode
from pcapkit.const.sctp.chunk import Chunk as SCTP_Chunk
from pcapkit.const.sctp.parameter import Parameter as SCTP_Parameter
from pcapkit.const.sctp.payload_protocol_identifier import \
    PayloadProtocolIdentifier as Enum_PayloadProtocolIdentifier
from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as TCP_MPTCPOption
from pcapkit.const.tcp.option import Option as TCP_Option
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.sentinels import NULL
from pcapkit.foundation.registry.protocols.protocol import _check_code, _register_name
from pcapkit.protocols.transport.dccp.protocol import DCCP
from pcapkit.protocols.transport.dccp.schema import Option as Schema_DCCP_Option
from pcapkit.protocols.transport.sctp.protocol import SCTP
from pcapkit.protocols.transport.sctp.schema import Chunk as Schema_SCTP_Chunk
from pcapkit.protocols.transport.sctp.schema import ErrorCause as Schema_SCTP_ErrorCause
from pcapkit.protocols.transport.sctp.schema import Parameter as Schema_SCTP_Parameter
from pcapkit.protocols.transport.tcp.protocol import TCP
from pcapkit.protocols.transport.tcp.schema import MPTCP as Schema_TCP_MPTCP
from pcapkit.protocols.transport.tcp.schema import Option as Schema_TCP_Option
from pcapkit.protocols.transport.udp.protocol import UDP
from pcapkit.utilities.exceptions import RegistryError
from pcapkit.utilities.logging import get_logger

if TYPE_CHECKING:
    from typing import Any, Optional, Type

    from pcapkit.const.sctp.payload_protocol_identifier import \
        PayloadProtocolIdentifier as SCTP_PayloadProtocolIdentifier
    from pcapkit.corekit.sentinels import NullType
    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.transport.dccp.protocol import \
        OptionConstructor as DCCP_OptionConstructor
    from pcapkit.protocols.transport.dccp.protocol import OptionParser as DCCP_OptionParser
    from pcapkit.protocols.transport.sctp.protocol import CauseConstructor as SCTP_CauseConstructor
    from pcapkit.protocols.transport.sctp.protocol import CauseParser as SCTP_CauseParser
    from pcapkit.protocols.transport.sctp.protocol import ChunkConstructor as SCTP_ChunkConstructor
    from pcapkit.protocols.transport.sctp.protocol import ChunkParser as SCTP_ChunkParser
    from pcapkit.protocols.transport.sctp.protocol import \
        ParameterConstructor as SCTP_ParameterConstructor
    from pcapkit.protocols.transport.sctp.protocol import ParameterParser as SCTP_ParameterParser
    from pcapkit.protocols.transport.tcp.protocol import \
        MPOptionConstructor as TCP_MPOptionConstructor
    from pcapkit.protocols.transport.tcp.protocol import MPOptionParser as TCP_MPOptionParser
    from pcapkit.protocols.transport.tcp.protocol import OptionConstructor as TCP_OptionConstructor
    from pcapkit.protocols.transport.tcp.protocol import OptionParser as TCP_OptionParser

__all__ = [
    'register_apptype',
    'register_tcp', 'register_udp', 'register_sctp', 'register_dccp',
    'register_tcp_option', 'register_tcp_mp_option',
    'register_sctp_chunk', 'register_sctp_parameter', 'register_sctp_cause',
    'register_dccp_option',
]

#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)


###############################################################################
# Transport Layer Registries
###############################################################################


@overload
def register_apptype(code: 'int', module: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]', *transport: 'TransportProtocol | str') -> 'None': ...
@overload
def register_apptype(code: 'Enum_AppType', module: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]', *transport: 'TransportProtocol | str') -> 'None': ...
@overload
def register_apptype(code: 'int', module: 'str', class_: 'str', *transport: 'TransportProtocol | str') -> 'None': ...
@overload
def register_apptype(code: 'Enum_AppType', module: 'str', class_: 'str', *transport: 'TransportProtocol | str') -> 'None': ...


def register_apptype(code: 'int | Enum_AppType', module: 'str | ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]',
                     class_: 'str | TransportProtocol | NullType' = NULL,
                     *transport: 'TransportProtocol | str') -> 'None':
    r"""Register a new protocol class.

    Notes:
        The fully qualified class name of the new protocol class
        should be ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.transport.tcp.protocol.TCP.__proto__` and/or
    :data:`pcapkit.protocols.transport.udp.protocol.UDP.__proto__` registry.

    Arguments:
        code: port number
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass
        class\_: class name, meaningful only when ``module`` is a :class:`str`.
            Positional, at the same position as the sibling ``register_*``
            functions -- but unlike them, a third positional argument here is
            not always ``class_``: which parameter it binds to is decided by
            ``type(module)`` alone, never by what the value looks like.
            When ``module`` is **not** a :class:`str`, whatever is given here
            is treated as the first ``*transport`` element instead --
            prepended, so argument order is preserved -- and ``class_`` itself
            stays unset; ``register_apptype(80, Unit, TransportProtocol.udp)``
            therefore reaches ``transport`` rather than being silently
            swallowed. This is not a heuristic on the value: with a
            :class:`str` ``module``, a :class:`str` third argument is
            **always** a class name -- ``register_apptype(80, 'a.b', 'tcp')``
            registers a class literally named ``'tcp'`` -- and naming a
            transport alongside a :class:`str` module takes the fourth
            position onward instead.
        *transport: transport protocols to register ``code`` under, named **one
            at a time**, each as a :class:`~pcapkit.const.reg.apptype.apptype.TransportProtocol`
            member or as that member's ``name`` (case-insensitively, e.g. ``'tcp'``,
            ``'TCP'`` or ``'Tcp'`` alike); the two forms are coerced to the same
            member and behave identically,
            including which error they raise. Where none is given and ``code`` is
            an :class:`~pcapkit.const.reg.apptype.apptype.AppType` member, the
            member's own :attr:`~pcapkit.const.reg.apptype.apptype.AppType.proto`
            is used, which names exactly the registry the member lives in. A bare
            :class:`int` carries no such default and so requires at least one.

    Raises:
        pcapkit.utilities.exceptions.RegistryError: If ``code`` is neither an
            :class:`int` (a :class:`bool` is not accepted, even though it is one)
            nor an :class:`~pcapkit.const.reg.apptype.apptype.AppType`
            member, e.g. a member of another enum; if no transport protocol is
            given for a bare :class:`int`; if one of those given (member or name)
            names no port-keyed registry; or if a ``str`` matches no
            :class:`~pcapkit.const.reg.apptype.apptype.TransportProtocol` member's
            ``name``. A composite such as ``tcp | udp``, or its string form
            ``'tcp|udp'``, names two and is refused for the same reason: one call
            registers under one transport protocol.
        pcapkit.utilities.exceptions.ProtocolError: Raised from
            :attr:`ModuleDescriptor.klass <pcapkit.corekit.module.ModuleDescriptor.klass>`,
            which the port-keyed registry resolves before storing the entry,
            when ``module`` is a :class:`str` and either ``class_`` names no
            attribute of it, or ``class_`` was never given at all -- the
            latter distinguished from the former rather than reported as a
            missing attribute named ``'(null)'``. See GitHub issues :issue:`832` and
            :issue:`833`.

    Important:
        :class:`~pcapkit.protocols.transport.sctp.protocol.SCTP` is deliberately **not**
        one of the registries this writes to, so naming ``sctp`` here is an error
        rather than a no-op. Its
        :data:`~pcapkit.protocols.transport.sctp.protocol.SCTP.__proto__` registry is
        keyed by the DATA chunk's payload protocol identifier rather than by
        port number, so writing a port number into it would dispatch on a
        number from the wrong registry. Use
        :func:`pcapkit.foundation.registry.protocols.transport.register_sctp` instead.

    See Also:
        * :func:`pcapkit.foundation.registry.protocols.transport.register_tcp`
        * :func:`pcapkit.foundation.registry.protocols.transport.register_udp`
        * :func:`pcapkit.foundation.registry.protocols.transport.register_sctp`

    .. versionremoved:: 1.3.1

       ``register_port``, which this replaces with no alias.

    .. versionchanged:: 1.5.0

       The keyword-only ``proto`` is replaced by ``*transport``, one transport
       protocol per argument, with no alias (:issue:`806`).

    """
    # NOTE: which of TCP's and UDP's registries this writes into depends on
    # ``*transport``, which is resolved below -- after this check, so a bad
    # ``code`` is still reported before a bad transport protocol. The two are
    # keyed alike, so the check itself is the same for either and TCP names it.
    # :func:`register_tcp` and :func:`register_udp` name one each.
    _check_code(code, Enum_AppType, TCP, number=True)

    # NOTE: ``class_`` sits at the sibling position -- positional, ahead of
    # ``*transport`` -- per maintainer ruling, so a third positional that is
    # really a transport would be swallowed as a class name. That is
    # disambiguated here by ``type(module)`` alone, never by what ``class_``
    # itself looks like. A ``str`` module means
    # ``class_`` really is a class name, so it is left untouched -- including
    # when it happens to be a string like ``'tcp'``, which is not sniffed for
    # looking like a transport. Any other module type means the third
    # positional was never a class name to begin with, so it is moved to the
    # front of ``transport`` -- prepended, so argument order survives -- and
    # ``class_`` is reset to ``NULL`` so the ``ModuleDescriptor`` branch below
    # never sees it.
    if not isinstance(module, str) and class_ is not NULL:
        transport = (cast('TransportProtocol | str', class_),) + transport
        class_ = NULL

    # NOTE: a ``str`` transport is coerced to its ``TransportProtocol`` member
    # up front, before any registry work, so every downstream use -- the
    # ``code.proto`` default and the registries lookup below -- sees members
    # only. Resolution is by the member's own ``name``, case-insensitively --
    # a ruling given in review of the work for #806 -- via ``__members__``
    # directly rather than ``TransportProtocol[name]``: this function's
    # contract is :exc:`~pcapkit.utilities.exceptions.RegistryError` for
    # anything unrecognised, composite-spelled or not, and ``__getitem__``
    # raises a bare :exc:`KeyError` on a miss instead of that -- both
    # ``TransportProtocol['tcp|udp']`` and ``TransportProtocol['bogus']`` do,
    # because ``TransportProtocol`` is not an ``IntFlag``, under which the
    # first would silently compose into the value ``3`` (#808).
    # ``__members__.get(...)`` lets this function
    # raise its own exception on a miss instead of letting ``__getitem__``'s
    # propagate, and lowercasing does not turn ``'tcp|udp'`` into a member
    # name either way. Anything that is neither a ``str`` nor a
    # ``TransportProtocol`` member is rejected here too, rather than falling
    # through to the registries lookup below: a bare ``int`` still hashes
    # and compares equal to its matching member -- ``TransportProtocol``
    # being an ``IntEnum`` rather than an ``IntFlag`` changes neither -- so
    # ``registries.get(1)`` resolves to ``TCP`` just as
    # ``registries.get(TransportProtocol.tcp)`` does, and would otherwise
    # register the port before the ``proto.name`` access below it
    # raised -- leaving the port written into ``TCP.__proto__`` with
    # ``register_protocol`` never called.
    coerced: 'list[TransportProtocol]' = []
    for proto in transport:
        if isinstance(proto, str):
            # NOTE: ``proto`` itself -- not the lowercased lookup key -- is
            # what the error message formats with ``!r``, so a mismatched
            # name such as ``'TCP '`` still shows its own casing and its
            # trailing space rather than the lowercased form.
            member = TransportProtocol.__members__.get(proto.lower())
            if member is None:
                raise RegistryError(f'unknown transport protocol: {proto!r}')
            proto = cast('TransportProtocol', member)
        elif not isinstance(proto, TransportProtocol):
            raise RegistryError(f'unknown transport protocol: {proto!r}')
        coerced.append(proto)
    transport = tuple(coerced)

    # NOTE: the member's own ``proto`` is the single transport protocol of the
    # registry it lives in -- GitHub issue #806 -- so it names one destination
    # rather than fanning out across every transport IANA gave the service. A
    # fan-out would make ``register_apptype(TCP.http, Dummy)`` displace the UDP
    # handler for port 80 as well, which no caller naming the TCP member asked
    # for.
    if not transport:
        if not isinstance(code, Enum_AppType):
            raise RegistryError(f'no transport protocol given for port {code}; name each '
                                'transport protocol to register under')
        transport = (code.proto,)
    if isinstance(code, Enum_AppType):
        code = code.port
    if isinstance(module, str):
        module = cast('ModuleDescriptor[ProtocolBase]', ModuleDescriptor(module, class_))

    registries = cast('dict[TransportProtocol, Type[ProtocolBase]]', {
        TransportProtocol.tcp: TCP,
        TransportProtocol.udp: UDP,
    })
    targets = []  # type: list[tuple[type, Any]]
    for proto in transport:
        # NOTE: a composite is not a key here, so ``tcp | udp`` is rejected
        # rather than quietly registering under both. Naming them one at a time
        # is what the varargs are for.
        cls = registries.get(proto)
        if cls is None:
            raise RegistryError(f'unknown transport protocol: {proto.name}')

        cls.register(code, module)
        targets.append((cls, code))
        logger.debug('registered %s port: %s', proto.name, code)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    _register_name(module, *targets)


@overload
def register_tcp(code: 'int | Enum_AppType', module: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None': ...
@overload
def register_tcp(code: 'int | Enum_AppType', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.protocols.transport.tcp.protocol.TCP.__proto__
def register_tcp(code: 'int | Enum_AppType', module: 'str | ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]',
                 class_: 'str | NullType' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The fully qualified class name of the new protocol class
        should be ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.transport.tcp.protocol.TCP.__proto__` registry.

    Arguments:
        code: port number
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass
        class\_: class name

    Raises:
        RegistryError: If ``code`` is neither an :class:`int` (a :class:`bool`
            is not accepted, even though it is one) nor an
            :class:`~pcapkit.const.reg.apptype.apptype.AppType` member, e.g. a
            member of another enum.

    """
    _check_code(code, Enum_AppType, TCP, number=True)
    if isinstance(code, Enum_AppType):
        code = code.port
    if isinstance(module, str):
        module = cast('ModuleDescriptor[ProtocolBase]', ModuleDescriptor(module, class_))

    TCP.register(code, module)
    logger.debug('registered TCP port: %s', code)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    _register_name(module, (TCP, code))


# NOTE: pcapkit.protocols.transport.tcp.protocol.TCP.__option__
def register_tcp_option(code: 'TCP_Option', meth: 'str | tuple[TCP_OptionParser, TCP_OptionConstructor]', *,
                        schema: 'Optional[Type[Schema_TCP_Option]]' = None) -> 'None':
    """Register an option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.transport.tcp.protocol.TCP.__option__` registry.

    Args:
        code: :class:`~pcapkit.protocols.transport.tcp.protocol.TCP` option code as in
            :class:`~pcapkit.const.tcp.option.Option`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the option. A name names the
            ``_read_mode_*`` and ``_make_mode_*`` methods, and has to name
            an existing ``_read_mode_*`` one.
        schema: :class:`~pcapkit.protocols.schema.Schema` class for the option.
            It should be a subclass of :class:`pcapkit.protocols.transport.tcp.schema.Option`.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.tcp.option.Option`
            member, e.g. a member of another enum, or ``meth``
            is a name with no matching ``_read_mode_*`` method.

    """
    _check_code(code, TCP_Option, TCP)
    if isinstance(meth, str) and not hasattr(TCP, f'_read_mode_{meth}'):
        raise RegistryError('method must be a TCP option parser function')

    TCP.register_option(code, meth)
    if schema is not None:
        Schema_TCP_Option.register(code, schema)
    logger.debug('registered TCP option parser: %s', code.name)


# NOTE: pcapkit.protocols.transport.tcp.protocol.TCP.__mp_option__
def register_tcp_mp_option(code: 'TCP_MPTCPOption', meth: 'str | tuple[TCP_MPOptionParser, TCP_MPOptionConstructor]', *,
                           schema: 'Optional[Type[Schema_TCP_MPTCP]]' = None) -> 'None':
    """Register an MPTCP option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.transport.tcp.protocol.TCP.__mp_option__` registry.

    Args:
        code: Multipath :class:`~pcapkit.protocols.transport.tcp.protocol.TCP` option code as in
            :class:`~pcapkit.const.tcp.mp_tcp_option.MPTCPOption`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the option. A name names the
            ``_read_mptcp_*`` and ``_make_mptcp_*`` methods, and has to name
            an existing ``_read_mptcp_*`` one.
        schema: :class:`~pcapkit.protocols.schema.Schema` class for the option.
            It should be a subclass of :class:`pcapkit.protocols.transport.tcp.schema.MPTCP`.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.tcp.mp_tcp_option.MPTCPOption`
            member, e.g. a member of another enum, or ``meth``
            is a name with no matching ``_read_mptcp_*`` method.

    """
    _check_code(code, TCP_MPTCPOption, TCP)
    if isinstance(meth, str) and not hasattr(TCP, f'_read_mptcp_{meth}'):
        raise RegistryError('method must be a MPTCP option parser function')

    TCP.register_mp_option(code, meth)
    if schema is not None:
        Schema_TCP_MPTCP.register(code, schema)
    logger.debug('registered MPTCP option parser: %s', code.name)


@overload
def register_udp(code: 'int | Enum_AppType', module: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None': ...
@overload
def register_udp(code: 'int | Enum_AppType', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.protocols.transport.udp.protocol.UDP.__proto__
def register_udp(code: 'int | Enum_AppType', module: 'str | ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]',
                 class_: 'str | NullType' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The fully qualified class name of the new protocol class
        should be ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.transport.udp.protocol.UDP.__proto__` registry.

    Arguments:
        code: port number
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass
        class\_: class name

    Raises:
        RegistryError: If ``code`` is neither an :class:`int` (a :class:`bool`
            is not accepted, even though it is one) nor an
            :class:`~pcapkit.const.reg.apptype.apptype.AppType` member, e.g. a
            member of another enum.

    """
    _check_code(code, Enum_AppType, UDP, number=True)
    if isinstance(code, Enum_AppType):
        code = code.port
    if isinstance(module, str):
        module = cast('ModuleDescriptor[ProtocolBase]', ModuleDescriptor(module, class_))

    UDP.register(code, module)
    logger.debug('registered UDP port: %s', code)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    _register_name(module, (UDP, code))


@overload
def register_sctp(code: 'int | SCTP_PayloadProtocolIdentifier', module: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None': ...
@overload
def register_sctp(code: 'int | SCTP_PayloadProtocolIdentifier', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.protocols.transport.sctp.protocol.SCTP.__proto__
def register_sctp(code: 'int | SCTP_PayloadProtocolIdentifier', module: 'str | ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]',
                  class_: 'str | NullType' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The fully qualified class name of the new protocol class
        should be ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.transport.sctp.protocol.SCTP.__proto__` registry.

    Arguments:
        code: payload protocol identifier (PPID), as in
            :class:`~pcapkit.const.sctp.payload_protocol_identifier.PayloadProtocolIdentifier`
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass
        class\_: class name

    Important:
        Unlike :func:`register_tcp` and :func:`register_udp`, ``code`` is a
        *payload protocol identifier* taken from the DATA chunk, **not** a port
        number: SCTP names its upper layer per DATA chunk rather than per
        association. See :rfc:`9260#section-3.3.1`.

    Raises:
        RegistryError: If ``code`` is neither an :class:`int` (a :class:`bool`
            is not accepted, even though it is one) nor a
            :class:`~pcapkit.const.sctp.payload_protocol_identifier.PayloadProtocolIdentifier`
            member, e.g. a member of the
            :class:`~pcapkit.const.reg.apptype.sctp.SCTP` port enum.

    """
    _check_code(code, Enum_PayloadProtocolIdentifier, SCTP, number=True)
    if isinstance(module, str):
        module = cast('ModuleDescriptor[ProtocolBase]', ModuleDescriptor(module, class_))

    SCTP.register(code, module)
    logger.debug('registered SCTP payload protocol identifier: %s', code)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    _register_name(module, (SCTP, code))


# NOTE: pcapkit.protocols.transport.sctp.protocol.SCTP.__chunk__
def register_sctp_chunk(code: 'SCTP_Chunk', meth: 'str | tuple[SCTP_ChunkParser, SCTP_ChunkConstructor]', *,
                        schema: 'Optional[Type[Schema_SCTP_Chunk]]' = None) -> 'None':
    """Register a chunk parser.

    The function will register the given chunk parser to the
    :data:`pcapkit.protocols.transport.sctp.protocol.SCTP.__chunk__` registry.

    Args:
        code: :class:`~pcapkit.protocols.transport.sctp.protocol.SCTP` chunk type as in
            :class:`~pcapkit.const.sctp.chunk.Chunk`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the chunk. A name names the
            ``_read_chunk_*`` and ``_make_chunk_*`` methods, and has to name
            an existing ``_read_chunk_*`` one.
        schema: :class:`~pcapkit.protocols.schema.Schema` class for the chunk.
            It should be a subclass of :class:`pcapkit.protocols.transport.sctp.schema.Chunk`.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.sctp.chunk.Chunk`
            member, e.g. a member of another enum, or ``meth``
            is a name with no matching ``_read_chunk_*`` method.

    .. versionadded:: 1.6.0

    """
    _check_code(code, SCTP_Chunk, SCTP)
    if isinstance(meth, str) and not hasattr(SCTP, f'_read_chunk_{meth}'):
        raise RegistryError('method must be a valid SCTP chunk parser function')

    SCTP.register_chunk(code, meth)
    if schema is not None:
        Schema_SCTP_Chunk.register(code, schema)
    logger.debug('registered SCTP chunk parser: %s', code.name)


# NOTE: pcapkit.protocols.transport.sctp.protocol.SCTP.__parameter__
def register_sctp_parameter(code: 'SCTP_Parameter',
                            meth: 'str | tuple[SCTP_ParameterParser, SCTP_ParameterConstructor]', *,
                            schema: 'Optional[Type[Schema_SCTP_Parameter]]' = None) -> 'None':
    """Register a chunk parameter parser.

    The function will register the given chunk parameter parser to the
    :data:`pcapkit.protocols.transport.sctp.protocol.SCTP.__parameter__` registry.

    Args:
        code: :class:`~pcapkit.protocols.transport.sctp.protocol.SCTP` chunk parameter type
            as in :class:`~pcapkit.const.sctp.parameter.Parameter`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the parameter. A name names the
            ``_read_param_*`` and ``_make_param_*`` methods, and has to name
            an existing ``_read_param_*`` one.
        schema: :class:`~pcapkit.protocols.schema.Schema` class for the parameter.
            It should be a subclass of :class:`pcapkit.protocols.transport.sctp.schema.Parameter`.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.sctp.parameter.Parameter`
            member, e.g. a member of another enum, or ``meth``
            is a name with no matching ``_read_param_*`` method.

    .. versionadded:: 1.6.0

    """
    _check_code(code, SCTP_Parameter, SCTP)
    if isinstance(meth, str) and not hasattr(SCTP, f'_read_param_{meth}'):
        raise RegistryError('method must be a valid SCTP chunk parameter parser function')

    SCTP.register_parameter(code, meth)
    if schema is not None:
        Schema_SCTP_Parameter.register(code, schema)
    logger.debug('registered SCTP chunk parameter parser: %s', code.name)


# NOTE: pcapkit.protocols.transport.sctp.protocol.SCTP.__cause__
def register_sctp_cause(code: 'SCTP_CauseCode', meth: 'str | tuple[SCTP_CauseParser, SCTP_CauseConstructor]', *,
                        schema: 'Optional[Type[Schema_SCTP_ErrorCause]]' = None) -> 'None':
    """Register an error cause parser.

    The function will register the given error cause parser to the
    :data:`pcapkit.protocols.transport.sctp.protocol.SCTP.__cause__` registry.

    Args:
        code: :class:`~pcapkit.protocols.transport.sctp.protocol.SCTP` error cause code as
            in :class:`~pcapkit.const.sctp.cause_code.CauseCode`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the cause. A name names the
            ``_read_cause_*`` and ``_make_cause_*`` methods, and has to name
            an existing ``_read_cause_*`` one.
        schema: :class:`~pcapkit.protocols.schema.Schema` class for the cause.
            It should be a subclass of :class:`pcapkit.protocols.transport.sctp.schema.ErrorCause`.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.sctp.cause_code.CauseCode`
            member, e.g. a member of another enum, or ``meth``
            is a name with no matching ``_read_cause_*`` method.

    .. versionadded:: 1.6.0

    """
    _check_code(code, SCTP_CauseCode, SCTP)
    if isinstance(meth, str) and not hasattr(SCTP, f'_read_cause_{meth}'):
        raise RegistryError('method must be a valid SCTP error cause parser function')

    SCTP.register_cause(code, meth)
    if schema is not None:
        Schema_SCTP_ErrorCause.register(code, schema)
    logger.debug('registered SCTP error cause parser: %s', code.name)


@overload
def register_dccp(code: 'int | Enum_AppType', module: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None': ...
@overload
def register_dccp(code: 'int | Enum_AppType', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.protocols.transport.dccp.protocol.DCCP.__proto__
def register_dccp(code: 'int | Enum_AppType', module: 'str | ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]',
                  class_: 'str | NullType' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The fully qualified class name of the new protocol class
        should be ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.transport.dccp.protocol.DCCP.__proto__` registry.

    Arguments:
        code: port number
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass
        class\_: class name

    Raises:
        RegistryError: If ``code`` is neither an :class:`int` (a :class:`bool`
            is not accepted, even though it is one) nor an
            :class:`~pcapkit.const.reg.apptype.apptype.AppType` member, e.g. a
            member of another enum.

    .. versionadded:: 1.6.0

    """
    _check_code(code, Enum_AppType, DCCP, number=True)
    if isinstance(code, Enum_AppType):
        code = code.port
    if isinstance(module, str):
        module = cast('ModuleDescriptor[ProtocolBase]', ModuleDescriptor(module, class_))

    DCCP.register(code, module)
    logger.debug('registered DCCP port: %s', code)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    _register_name(module, (DCCP, code))


# NOTE: pcapkit.protocols.transport.dccp.protocol.DCCP.__option__
def register_dccp_option(code: 'DCCP_Option', meth: 'str | tuple[DCCP_OptionParser, DCCP_OptionConstructor]', *,
                         schema: 'Optional[Type[Schema_DCCP_Option]]' = None) -> 'None':
    """Register an option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.transport.dccp.protocol.DCCP.__option__` registry.

    Args:
        code: :class:`~pcapkit.protocols.transport.dccp.protocol.DCCP` option type as in
            :class:`~pcapkit.const.dccp.option.Option`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the option. A name names the
            ``_read_opt_*`` and ``_make_opt_*`` methods, and has to name
            an existing ``_read_opt_*`` one.
        schema: :class:`~pcapkit.protocols.schema.Schema` class for the option.
            It should be a subclass of :class:`pcapkit.protocols.transport.dccp.schema.Option`.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.dccp.option.Option`
            member, e.g. a member of another enum, or ``meth``
            is a name with no matching ``_read_opt_*`` method.

    .. versionadded:: 1.6.0

    """
    _check_code(code, DCCP_Option, DCCP)
    if isinstance(meth, str) and not hasattr(DCCP, f'_read_opt_{meth}'):
        raise RegistryError('method must be a valid DCCP option parser function')

    DCCP.register_option(code, meth)
    if schema is not None:
        Schema_DCCP_Option.register(code, schema)
    logger.debug('registered DCCP option parser: %s', code.name)
