# -*- coding: utf-8 -*-
"""Internet Layer Protocol Registries
========================================

.. module:: pcapkit.foundation.registry.protocols.internet

This module provides the registries of the internet layer protocols in
:mod:`pcapkit.protocols.internet`.

.. versionadded:: 1.6.0

   Moved here from the single :file:`pcapkit/foundation/registry/protocols.py`
   module. The :mod:`pcapkit.foundation.registry.protocols` package exports
   this module's functions (:issue:`2578`).

"""
from typing import TYPE_CHECKING, cast, overload

from pcapkit.const.hip.parameter import Parameter as HIP_Parameter
from pcapkit.const.icmp.type import Type as ICMPv4_Type
from pcapkit.const.icmpv6.type import Type as ICMPv6_Type
from pcapkit.const.ipv4.option_number import OptionNumber as IPv4_OptionNumber
from pcapkit.const.ipv6.option import Option as IPv6_Option
from pcapkit.const.ipv6.routing import Routing as IPv6_Routing
from pcapkit.const.ipx.packet import Packet as IPX_Packet
from pcapkit.const.mh.cga_extension import CGAExtension as MH_CGAExtension
from pcapkit.const.mh.option import Option as MH_Option
from pcapkit.const.mh.packet import Packet as MH_Packet
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.sentinels import NULL
from pcapkit.foundation.registry.protocols.protocol import _check_code, _register_name
from pcapkit.protocols.internet.hip import HIP
from pcapkit.protocols.internet.hopopt import HOPOPT
from pcapkit.protocols.internet.icmpv4 import ICMPv4
from pcapkit.protocols.internet.icmpv6 import ICMPv6
from pcapkit.protocols.internet.internet import Internet
from pcapkit.protocols.internet.ipv4 import IPv4
from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
from pcapkit.protocols.internet.ipv6_route import IPv6_Route
from pcapkit.protocols.internet.ipx import IPX
from pcapkit.protocols.internet.mh import MH
from pcapkit.protocols.schema.internet.hip import Parameter as Schema_HIP_Parameter
from pcapkit.protocols.schema.internet.hopopt import Option as Schema_HOPOPT_Option
from pcapkit.protocols.schema.internet.ipv4 import Option as Schema_IPv4_Option
from pcapkit.protocols.schema.internet.ipv6_opts import Option as Schema_IPv6_Opts_Option
from pcapkit.protocols.schema.internet.ipv6_route import \
    RoutingType as Schema_IPv6_Route_RoutingType
from pcapkit.protocols.schema.internet.mh import CGAExtension as Schema_MH_CGAExtension
from pcapkit.protocols.schema.internet.mh import Option as Schema_MH_Option
from pcapkit.protocols.schema.internet.mh import Packet as Schema_MH_Packet
from pcapkit.utilities.exceptions import RegistryError
from pcapkit.utilities.logging import get_logger

if TYPE_CHECKING:
    from typing import Any, Callable, Optional, Type

    from pcapkit.const.reg.transtype import TransType
    from pcapkit.corekit.sentinels import NullType
    from pcapkit.protocols.internet.hip import ParameterConstructor as HIP_ParameterConstructor
    from pcapkit.protocols.internet.hip import ParameterParser as HIP_ParameterParser
    from pcapkit.protocols.internet.hopopt import OptionConstructor as HOPOPT_OptionConstructor
    from pcapkit.protocols.internet.hopopt import OptionParser as HOPOPT_OptionParser
    from pcapkit.protocols.internet.ipv4 import OptionConstructor as IPv4_OptionConstructor
    from pcapkit.protocols.internet.ipv4 import OptionParser as IPv4_OptionParser
    from pcapkit.protocols.internet.ipv6_opts import \
        OptionConstructor as IPv6_Opts_OptionConstructor
    from pcapkit.protocols.internet.ipv6_opts import OptionParser as IPv6_Opts_OptionParser
    from pcapkit.protocols.internet.ipv6_route import TypeConstructor as IPv6_Route_TypeConstructor
    from pcapkit.protocols.internet.ipv6_route import TypeParser as IPv6_Route_TypeParser
    from pcapkit.protocols.internet.mh import ExtensionConstructor as MH_ExtensionConstructor
    from pcapkit.protocols.internet.mh import ExtensionParser as MH_ExtensionParser
    from pcapkit.protocols.internet.mh import OptionConstructor as MH_OptionConstructor
    from pcapkit.protocols.internet.mh import OptionParser as MH_OptionParser
    from pcapkit.protocols.internet.mh import PacketConstructor as MH_PacketConstructor
    from pcapkit.protocols.internet.mh import PacketParser as MH_PacketParser
    from pcapkit.protocols.protocol import ProtocolBase

__all__ = [
    'register_transtype',
    'register_ipx',
    'register_icmp_type',
    'register_ipv4_option', 'register_hip_parameter', 'register_hopopt_option',
    'register_ipv6_opts_option', 'register_ipv6_route_routing',
    'register_mh_message', 'register_mh_option', 'register_mh_extension',
]

#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)


###############################################################################
# Internet Layer Registries
###############################################################################


@overload
def register_transtype(code: 'TransType', module: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None': ...
@overload
def register_transtype(code: 'TransType', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.protocols.internet.internet.Internet.__proto__
def register_transtype(code: 'TransType', module: 'str | ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]',
                       class_: 'str | NullType' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The fully qualified class name of the new protocol class
        should be ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.internet.internet.Internet.__proto__` registry.

    Arguments:
        code: protocol code as in :class:`~pcapkit.const.reg.transtype.TransType`
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass
        class\_: class name

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.reg.transtype.TransType`
            member, e.g. a member of another enum, or ``module``
            is not a :class:`~pcapkit.protocols.protocol.ProtocolBase`
            subclass.

    """
    _check_code(code, Enum_TransType, Internet)  # type: ignore[type-abstract]
    if isinstance(module, str):
        module = cast('ModuleDescriptor[ProtocolBase]', ModuleDescriptor(module, class_))

    Internet.register(code, module)
    logger.debug('registered transtype protocol: %s', code.name)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    _register_name(module, (Internet, code))


@overload
def register_ipx(code: 'int | IPX_Packet', module: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None': ...
@overload
def register_ipx(code: 'int | IPX_Packet', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.protocols.internet.ipx.IPX.__proto__
def register_ipx(code: 'int | IPX_Packet', module: 'str | ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]',
                 class_: 'str | NullType' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The fully qualified class name of the new protocol class
        should be ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.internet.ipx.IPX.__proto__` registry.

    Arguments:
        code: IPX Packet Type, as in :class:`~pcapkit.const.ipx.packet.Packet`
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass
        class\_: class name

    Important:
        Unlike :func:`register_transtype`, ``code`` is an IPX Packet Type, **not**
        an IP protocol number: :class:`~pcapkit.protocols.internet.ipx.IPX`
        keeps a registry of its own (:issue:`2169`).

    Raises:
        RegistryError: If ``code`` is neither an :class:`int` (a :class:`bool`
            is not accepted, even though it is one) nor a
            :class:`~pcapkit.const.ipx.packet.Packet` member, e.g. a
            :class:`~pcapkit.const.reg.transtype.TransType` member, or ``module``
            is not a :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass.

    .. versionadded:: 1.6.0

    """
    _check_code(code, IPX_Packet, IPX, number=True)
    if isinstance(module, str):
        module = cast('ModuleDescriptor[ProtocolBase]', ModuleDescriptor(module, class_))

    IPX.register(code, module)
    logger.debug('registered IPX packet type protocol: %s', code)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    _register_name(module, (IPX, code))


# NOTE: pcapkit.protocols.internet.ipv4.IPv4.__option__
def register_ipv4_option(code: 'IPv4_OptionNumber', meth: 'str | tuple[IPv4_OptionParser, IPv4_OptionConstructor]', *,
                         schema: 'Optional[Type[Schema_IPv4_Option]]' = None) -> 'None':
    """Register an option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.internet.ipv4.IPv4.__option__` registry.

    Args:
        code: :class:`IPv4 <pcapkit.protocols.internet.ipv4.IPv4>` option code as
            in :class:`~pcapkit.const.ipv4.option_number.OptionNumber`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the option. A name names the
            ``_read_opt_*`` and ``_make_opt_*`` methods, and has to name
            an existing ``_read_opt_*`` one.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the option.
            It should be a subclass of :class:`pcapkit.protocols.schema.internet.ipv4.Option`.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.ipv4.option_number.OptionNumber`
            member, e.g. a member of another enum, or ``meth``
            is a name with no matching ``_read_opt_*`` method.

    """
    _check_code(code, IPv4_OptionNumber, IPv4)
    if isinstance(meth, str) and not hasattr(IPv4, f'_read_opt_{meth}'):
        raise RegistryError('method must be a valid IPv4 option parser function')

    IPv4.register_option(code, meth)
    if schema is not None:
        Schema_IPv4_Option.register(code, schema)
    logger.debug('registered IPv4 option parser: %s', code.name)


# NOTE: pcapkit.protocols.internet.icmpv4.ICMPv4.__type__, pcapkit.protocols.internet.icmpv6.ICMPv6.__type__
def register_icmp_type(code: 'ICMPv4_Type | ICMPv6_Type',
                       meth: 'str | tuple[Callable[..., Any], Callable[..., Any]]') -> 'None':
    """Register a message body parser.

    The function will register the given message body parser to the
    :data:`~pcapkit.protocols.internet.icmpv4.ICMPv4.__type__` registry when
    ``code`` is an ICMPv4 type, or to
    :data:`~pcapkit.protocols.internet.icmpv6.ICMPv6.__type__` when it is an
    ICMPv6 type. Each registry is written by that class's own
    :meth:`register_type` classmethod.

    Args:
        code: ICMP type as in :class:`~pcapkit.const.icmp.type.Type` or
            :class:`~pcapkit.const.icmpv6.type.Type`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the message body. A name names the
            ``_read_data_type_*`` and ``_make_data_type_*`` methods of the
            protocol, and has to name an existing ``_read_data_type_*`` one.

    Raises:
        RegistryError: If ``code`` is not a member of either ICMP type enum,
            or ``meth`` is a name with no matching ``_read_data_type_*`` method.

    """
    kind, protocol = (ICMPv6_Type, ICMPv6) if isinstance(code, ICMPv6_Type) else (ICMPv4_Type, ICMPv4)
    _check_code(code, kind, protocol)
    if isinstance(meth, str) and not hasattr(protocol, f'_read_data_type_{meth}'):
        raise RegistryError('method must be a valid ICMP message parser function')

    protocol.register_type(code, meth)
    logger.debug('registered ICMP type parser: %s', code.name)


# NOTE: pcapkit.protocols.internet.hip.HIP.__parameter__
def register_hip_parameter(code: 'HIP_Parameter', meth: 'str | tuple[HIP_ParameterParser, HIP_ParameterConstructor]', *,
                           schema: 'Optional[Type[Schema_HIP_Parameter]]' = None) -> 'None':
    """Register a parameter parser.

    The function will register the given parameter parser to the
    :data:`pcapkit.protocols.internet.hip.HIP.__parameter__` registry.

    Args:
        code: :class:`~pcapkit.protocols.internet.hip.HIP` parameter code as
            in :class:`~pcapkit.const.hip.parameter.Parameter`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the parameter. A name names the
            ``_read_param_*`` and ``_make_param_*`` methods, and has to name
            an existing ``_read_param_*`` one.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the parameter.
            It should be a subclass of :class:`pcapkit.protocols.schema.internet.hip.Parameter`.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.hip.parameter.Parameter`
            member, e.g. a member of another enum, or ``meth``
            is a name with no matching ``_read_param_*`` method.

    """
    _check_code(code, HIP_Parameter, HIP)
    if isinstance(meth, str) and not hasattr(HIP, f'_read_param_{meth}'):
        raise RegistryError('method must be a valid HIP parameter parser function')

    HIP.register_parameter(code, meth)
    if schema is not None:
        Schema_HIP_Parameter.register(code, schema)
    logger.debug('registered HIP parameter parser: %s', code.name)


# NOTE: pcapkit.protocols.internet.hopopt.HOPOPT.__option__
def register_hopopt_option(code: 'IPv6_Option', meth: 'str | tuple[HOPOPT_OptionParser, HOPOPT_OptionConstructor]', *,
                           schema: 'Optional[Type[Schema_HOPOPT_Option]]' = None) -> 'None':
    """Register an option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.internet.hopopt.HOPOPT.__option__` registry.

    Args:
        code: :class:`~pcapkit.protocols.internet.hopopt.HOPOPT` option code as
            in :class:`~pcapkit.const.ipv6.option.Option`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the option. A name names the
            ``_read_opt_*`` and ``_make_opt_*`` methods, and has to name
            an existing ``_read_opt_*`` one.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the option.
            It should be a subclass of :class:`pcapkit.protocols.schema.internet.hopopt.Option`.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.ipv6.option.Option`
            member, e.g. a member of another enum, or ``meth``
            is a name with no matching ``_read_opt_*`` method.

    """
    _check_code(code, IPv6_Option, HOPOPT)
    if isinstance(meth, str) and not hasattr(HOPOPT, f'_read_opt_{meth}'):
        raise RegistryError('method must be a valid HOPOPT option parser function')

    HOPOPT.register_option(code, meth)
    if schema is not None:
        Schema_HOPOPT_Option.register(code, schema)
    logger.debug('registered HOPOPT option parser: %s', code.name)


# NOTE: pcapkit.protocols.internet.ipv6_opts.IPv6_Opts.__option__
def register_ipv6_opts_option(code: 'IPv6_Option', meth: 'str | tuple[IPv6_Opts_OptionParser, IPv6_Opts_OptionConstructor]', *,
                              schema: 'Optional[Type[Schema_IPv6_Opts_Option]]' = None) -> 'None':
    """Register an option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.internet.ipv6_opts.IPv6_Opts.__option__` registry.

    Args:
        code: :class:`IPv6-Opts <pcapkit.protocols.internet.ipv6_opts.IPv6_Opts>`
            option code as in :class:`~pcapkit.const.ipv6.option.Option`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the option. A name names the
            ``_read_opt_*`` and ``_make_opt_*`` methods, and has to name
            an existing ``_read_opt_*`` one.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the option.
            It should be a subclass of :class:`pcapkit.protocols.schema.internet.ipv6_opts.Option`.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.ipv6.option.Option`
            member, e.g. a member of another enum, or ``meth``
            is a name with no matching ``_read_opt_*`` method.

    """
    _check_code(code, IPv6_Option, IPv6_Opts)
    if isinstance(meth, str) and not hasattr(IPv6_Opts, f'_read_opt_{meth}'):
        raise RegistryError('method must be a valid IPv6-Opts option parser function')

    IPv6_Opts.register_option(code, meth)
    if schema is not None:
        Schema_IPv6_Opts_Option.register(code, schema)
    logger.debug('registered IPv6-Opts option parser: %s', code.name)


# NOTE: pcapkit.protocols.internet.ipv6_route.IPv6_Route.__routing__
def register_ipv6_route_routing(code: 'IPv6_Routing', meth: 'str | tuple[IPv6_Route_TypeParser, IPv6_Route_TypeConstructor]', *,
                                schema: 'Optional[Type[Schema_IPv6_Route_RoutingType]]' = None) -> 'None':
    """Register a routing data parser.

    The function will register the given routing data parser to the
    :data:`pcapkit.protocols.internet.ipv6_route.IPv6_Route.__routing__` registry.

    Args:
        code: :class:`IPv6-Route <pcapkit.protocols.internet.ipv6_route.IPv6_Route>`
            data type code as in :class:`~pcapkit.const.ipv6.routing.Routing`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the data. A name names the
            ``_read_data_type_*`` and ``_make_data_type_*`` methods, and has to name
            an existing ``_read_data_type_*`` one.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the routing data.
            It should be a subclass of :class:`pcapkit.protocols.schema.internet.ipv6_route.RoutingType`.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.ipv6.routing.Routing`
            member, e.g. a member of another enum, or ``meth``
            is a name with no matching ``_read_data_type_*`` method.

    """
    _check_code(code, IPv6_Routing, IPv6_Route)
    if isinstance(meth, str) and not hasattr(IPv6_Route, f'_read_data_type_{meth}'):
        raise RegistryError('method must be a valid IPv6-Route routing data parser function')

    IPv6_Route.register_routing(code, meth)
    if schema is not None:
        Schema_IPv6_Route_RoutingType.register(code, schema)
    logger.debug('registered IPv6-Route routing data parser: %s', code.name)


# NOTE: pcapkit.protocols.internet.mh.MH.__message__
def register_mh_message(code: 'MH_Packet', meth: 'str | tuple[MH_PacketParser, MH_PacketConstructor]', *,
                        schema: 'Optional[Type[Schema_MH_Packet]]' = None) -> 'None':
    """Register an MH message type parser.

    The function will register the given message type parser to the
    :data:`pcapkit.protocols.internet.mh.MH.__message__` registry.

    Args:
        code: :class:`~pcapkit.protocols.internet.mh.MH`
            message type code as in :class:`~pcapkit.const.mh.packet.Packet`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the data. A name names the
            ``_read_msg_*`` and ``_make_msg_*`` methods, and has to name
            an existing ``_read_msg_*`` one.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the message type.
            It should be a subclass of :class:`pcapkit.protocols.schema.internet.mh.Packet`.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.mh.packet.Packet`
            member, e.g. a member of another enum, or ``meth``
            is a name with no matching ``_read_msg_*`` method.

    """
    _check_code(code, MH_Packet, MH)
    if isinstance(meth, str) and not hasattr(MH, f'_read_msg_{meth}'):
        raise RegistryError('method must be a valid MH message type parser function')

    MH.register_message(code, meth)
    if schema is not None:
        Schema_MH_Packet.register(code, schema)
    logger.debug('registered MH message type parser: %s', code.name)


# NOTE: pcapkit.protocols.internet.mh.MH.__option__
def register_mh_option(code: 'MH_Option', meth: 'str | tuple[MH_OptionParser, MH_OptionConstructor]', *,
                       schema: 'Optional[Type[Schema_MH_Option]]' = None) -> 'None':
    """Register an MH option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.internet.mh.MH.__option__` registry.

    Args:
        code: :class:`~pcapkit.protocols.internet.mh.MH`
            option code as in :class:`~pcapkit.const.mh.option.Option`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the data. A name names the
            ``_read_opt_*`` and ``_make_opt_*`` methods, and has to name
            an existing ``_read_opt_*`` one.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the option.
            It should be a subclass of :class:`pcapkit.protocols.schema.internet.mh.Option`.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.mh.option.Option`
            member, e.g. a member of another enum, or ``meth``
            is a name with no matching ``_read_opt_*`` method.

    """
    _check_code(code, MH_Option, MH)
    if isinstance(meth, str) and not hasattr(MH, f'_read_opt_{meth}'):
        raise RegistryError('method must be a valid MH option parser function')

    MH.register_option(code, meth)
    if schema is not None:
        Schema_MH_Option.register(code, schema)
    logger.debug('registered MH option parser: %s', code.name)


# NOTE: pcapkit.protocols.internet.mh.MH.__extension__
def register_mh_extension(code: 'MH_CGAExtension', meth: 'str | tuple[MH_ExtensionParser, MH_ExtensionConstructor]', *,
                          schema: 'Optional[Type[Schema_MH_CGAExtension]]' = None) -> 'None':
    """Register a CGA extension parser.

    The function will register the given CGA extension parser to the
    :data:`pcapkit.protocols.internet.mh.MH.__extension__` registry.

    Args:
        code: :class:`~pcapkit.protocols.internet.mh.MH`
            CGA extension code as in :class:`~pcapkit.const.mh.cga_extension.CGAExtension`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the data. A name names the
            ``_read_ext_*`` and ``_make_ext_*`` methods, and has to name
            an existing ``_read_ext_*`` one.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the CGA extension.
            It should be a subclass of :class:`pcapkit.protocols.schema.internet.mh.CGAExtension`.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.mh.cga_extension.CGAExtension`
            member, e.g. a member of another enum, or ``meth``
            is a name with no matching ``_read_ext_*`` method.

    .. versionchanged:: 1.5.0

       ``schema`` is keyword-only, as in the other ``register_*`` functions
       that take one (:issue:`516`).

    """
    _check_code(code, MH_CGAExtension, MH)
    if isinstance(meth, str) and not hasattr(MH, f'_read_ext_{meth}'):
        raise RegistryError('method must be a valid MH CGA extension function')

    MH.register_extension(code, meth)
    if schema is not None:
        Schema_MH_CGAExtension.register(code, schema)
    logger.debug('registered MH CGA extension: %s', code.name)
