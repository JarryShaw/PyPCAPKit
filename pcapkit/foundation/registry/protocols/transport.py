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
from typing import TYPE_CHECKING, cast

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
from pcapkit.foundation.registry.protocols.protocol import _check_code, _check_meth, _register_name
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
    from typing import Any, Optional, Sequence, Type

    from pcapkit.const.sctp.payload_protocol_identifier import \
        PayloadProtocolIdentifier as SCTP_PayloadProtocolIdentifier
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


def register_apptype(code: 'int | Enum_AppType', protocol: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]', *,
                     transport: 'TransportProtocol | str | Sequence[TransportProtocol | str] | None' = None) -> 'None':
    r"""Register a new protocol class.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.transport.tcp.protocol.TCP.__proto__` and/or
    :data:`pcapkit.protocols.transport.udp.protocol.UDP.__proto__` registry.

    Arguments:
        code: port number
        protocol: module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass
        transport: transport protocol to register ``code`` under, or a
            :class:`list` or :class:`tuple` of several, each a
            :class:`~pcapkit.const.reg.apptype.apptype.TransportProtocol`
            member or that member's ``name`` (case-insensitively, e.g. ``'tcp'``,
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
            ``'tcp|udp'``, names two and is refused for the same reason: each
            item names one transport protocol.

    Important:
        :class:`~pcapkit.protocols.transport.sctp.protocol.SCTP` is deliberately **not**
        one of the registries this writes to, so naming ``sctp`` here is an error
        rather than a no-op. Its
        :data:`~pcapkit.protocols.transport.sctp.protocol.SCTP.__proto__` registry is
        keyed by the DATA or I-DATA chunk's payload protocol identifier rather
        than by port number, so writing a port number into it would dispatch on a
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

    .. versionchanged:: 1.7.0

       ``protocol`` replaces ``module`` and ``class_``, and the keyword-only
       ``transport`` replaces ``*transport``, with no shim (:issue:`2838`).

    """
    # NOTE: checked before ``transport`` is resolved, so a bad ``code`` is reported first;
    # TCP's and UDP's registries are keyed alike, so TCP names the check.
    _check_code(code, Enum_AppType, TCP, number=True)

    if transport is None:
        transport = ()
    elif isinstance(transport, (str, TransportProtocol)):
        transport = (transport,)
    elif not isinstance(transport, (list, tuple)):
        raise RegistryError(f'unknown transport protocol: {transport!r}')

    # NOTE: coerce up front, by case-insensitive member name via ``__members__`` so a miss is a
    # ``RegistryError`` (#806, #808); a bare ``int`` is refused, or it would half-register the port.
    coerced: 'list[TransportProtocol]' = []
    for proto in transport:
        if isinstance(proto, str):
            # NOTE: the error formats ``proto`` itself, not the lowercased key, so a name such
            # as ``'TCP '`` shows its own casing and trailing space.
            member = TransportProtocol.__members__.get(proto.lower())
            if member is None:
                raise RegistryError(f'unknown transport protocol: {proto!r}')
            proto = cast('TransportProtocol', member)
        elif not isinstance(proto, TransportProtocol):
            raise RegistryError(f'unknown transport protocol: {proto!r}')
        coerced.append(proto)

    # NOTE: the member's ``proto`` names the one registry it lives in (#806), so
    # ``register_apptype(TCP.http, Dummy)`` does not displace the UDP port 80 handler.
    if not coerced:
        if not isinstance(code, Enum_AppType):
            raise RegistryError(f'no transport protocol given for port {code}; name each '
                                'transport protocol to register under')
        coerced.append(code.proto)
    if isinstance(code, Enum_AppType):
        code = code.port

    registries = cast('dict[TransportProtocol, Type[ProtocolBase]]', {
        TransportProtocol.tcp: TCP,
        TransportProtocol.udp: UDP,
    })
    targets = []  # type: list[tuple[type, Any]]
    for proto in coerced:
        # NOTE: a composite is not a key, so ``tcp | udp`` is rejected rather than
        # registering under both; a list names them one at a time.
        cls = registries.get(proto)
        if cls is None:
            raise RegistryError(f'unknown transport protocol: {proto.name}')

        cls.register(code, protocol)
        targets.append((cls, code))
        logger.debug('registered %s port: %s', proto.name, code)

    # register protocol to protocol registry
    if isinstance(protocol, ModuleDescriptor):
        protocol = protocol.klass
    _register_name(protocol, *targets)


# NOTE: pcapkit.protocols.transport.tcp.protocol.TCP.__proto__
def register_tcp(code: 'int | Enum_AppType', protocol: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None':
    r"""Register a new protocol class.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.transport.tcp.protocol.TCP.__proto__` registry.

    Arguments:
        code: port number
        protocol: module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass

    Raises:
        RegistryError: If ``code`` is neither an :class:`int` (a :class:`bool`
            is not accepted, even though it is one) nor an
            :class:`~pcapkit.const.reg.apptype.apptype.AppType` member, e.g. a
            member of another enum.

    """
    _check_code(code, Enum_AppType, TCP, number=True)
    if isinstance(code, Enum_AppType):
        code = code.port

    TCP.register(code, protocol)
    logger.debug('registered TCP port: %s', code)

    # register protocol to protocol registry
    if isinstance(protocol, ModuleDescriptor):
        protocol = protocol.klass
    _register_name(protocol, (TCP, code))


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
            is a name with no matching ``_read_mode_*`` method, or neither a name
            nor a pair of two callables.

    """
    _check_code(code, TCP_Option, TCP)
    _check_meth(meth, TCP)
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
            is a name with no matching ``_read_mptcp_*`` method, or neither a name
            nor a pair of two callables.

    """
    _check_code(code, TCP_MPTCPOption, TCP)
    _check_meth(meth, TCP)
    if isinstance(meth, str) and not hasattr(TCP, f'_read_mptcp_{meth}'):
        raise RegistryError('method must be a MPTCP option parser function')

    TCP.register_mp_option(code, meth)
    if schema is not None:
        Schema_TCP_MPTCP.register(code, schema)
    logger.debug('registered MPTCP option parser: %s', code.name)


# NOTE: pcapkit.protocols.transport.udp.protocol.UDP.__proto__
def register_udp(code: 'int | Enum_AppType', protocol: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None':
    r"""Register a new protocol class.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.transport.udp.protocol.UDP.__proto__` registry.

    Arguments:
        code: port number
        protocol: module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass

    Raises:
        RegistryError: If ``code`` is neither an :class:`int` (a :class:`bool`
            is not accepted, even though it is one) nor an
            :class:`~pcapkit.const.reg.apptype.apptype.AppType` member, e.g. a
            member of another enum.

    """
    _check_code(code, Enum_AppType, UDP, number=True)
    if isinstance(code, Enum_AppType):
        code = code.port

    UDP.register(code, protocol)
    logger.debug('registered UDP port: %s', code)

    # register protocol to protocol registry
    if isinstance(protocol, ModuleDescriptor):
        protocol = protocol.klass
    _register_name(protocol, (UDP, code))


# NOTE: pcapkit.protocols.transport.sctp.protocol.SCTP.__proto__
def register_sctp(code: 'int | SCTP_PayloadProtocolIdentifier',
                  protocol: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None':
    r"""Register a new protocol class.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.transport.sctp.protocol.SCTP.__proto__` registry.

    Arguments:
        code: payload protocol identifier (PPID), as in
            :class:`~pcapkit.const.sctp.payload_protocol_identifier.PayloadProtocolIdentifier`
        protocol: module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass

    Important:
        Unlike :func:`register_tcp` and :func:`register_udp`, ``code`` is a
        *payload protocol identifier* taken from the DATA or I-DATA chunk,
        **not** a port number: SCTP names its upper layer per chunk rather than
        per association. See :rfc:`9260#section-3.3.1` and :rfc:`8260#section-2.1`.

    Raises:
        RegistryError: If ``code`` is neither an :class:`int` (a :class:`bool`
            is not accepted, even though it is one) nor a
            :class:`~pcapkit.const.sctp.payload_protocol_identifier.PayloadProtocolIdentifier`
            member, e.g. a member of the
            :class:`~pcapkit.const.reg.apptype.sctp.SCTP` port enum.

    """
    _check_code(code, Enum_PayloadProtocolIdentifier, SCTP, number=True)

    SCTP.register(code, protocol)
    logger.debug('registered SCTP payload protocol identifier: %s', code)

    # register protocol to protocol registry
    if isinstance(protocol, ModuleDescriptor):
        protocol = protocol.klass
    _register_name(protocol, (SCTP, code))


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
            is a name with no matching ``_read_chunk_*`` method, or neither a name
            nor a pair of two callables.

    .. versionadded:: 1.6.0

    """
    _check_code(code, SCTP_Chunk, SCTP)
    _check_meth(meth, SCTP)
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
            is a name with no matching ``_read_param_*`` method, or neither a name
            nor a pair of two callables.

    .. versionadded:: 1.6.0

    """
    _check_code(code, SCTP_Parameter, SCTP)
    _check_meth(meth, SCTP)
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
            is a name with no matching ``_read_cause_*`` method, or neither a name
            nor a pair of two callables.

    .. versionadded:: 1.6.0

    """
    _check_code(code, SCTP_CauseCode, SCTP)
    _check_meth(meth, SCTP)
    if isinstance(meth, str) and not hasattr(SCTP, f'_read_cause_{meth}'):
        raise RegistryError('method must be a valid SCTP error cause parser function')

    SCTP.register_cause(code, meth)
    if schema is not None:
        Schema_SCTP_ErrorCause.register(code, schema)
    logger.debug('registered SCTP error cause parser: %s', code.name)


# NOTE: pcapkit.protocols.transport.dccp.protocol.DCCP.__proto__
def register_dccp(code: 'int | Enum_AppType',
                  protocol: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None':
    r"""Register a new protocol class.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.transport.dccp.protocol.DCCP.__proto__` registry.

    Arguments:
        code: port number
        protocol: module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass

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

    DCCP.register(code, protocol)
    logger.debug('registered DCCP port: %s', code)

    # register protocol to protocol registry
    if isinstance(protocol, ModuleDescriptor):
        protocol = protocol.klass
    _register_name(protocol, (DCCP, code))


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
            is a name with no matching ``_read_opt_*`` method, or neither a name
            nor a pair of two callables.

    .. versionadded:: 1.6.0

    """
    _check_code(code, DCCP_Option, DCCP)
    _check_meth(meth, DCCP)
    if isinstance(meth, str) and not hasattr(DCCP, f'_read_opt_{meth}'):
        raise RegistryError('method must be a valid DCCP option parser function')

    DCCP.register_option(code, meth)
    if schema is not None:
        Schema_DCCP_Option.register(code, schema)
    logger.debug('registered DCCP option parser: %s', code.name)
