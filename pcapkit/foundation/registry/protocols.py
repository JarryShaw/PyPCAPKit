# -*- coding: utf-8 -*-
"""Protocol Registries
=========================

.. module:: pcapkit.foundation.registry.protocols

This module provides the protocol registries for :mod:`pcapkit`.

"""
from typing import TYPE_CHECKING, cast, overload

from pcapkit.const.reg.apptype import AppType as Enum_AppType
from pcapkit.const.reg.apptype import TransportProtocol
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.protocols import __proto__ as protocol_registry
from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
from pcapkit.protocols.internet.hip import HIP
from pcapkit.protocols.internet.hopopt import HOPOPT
from pcapkit.protocols.internet.internet import Internet
from pcapkit.protocols.internet.ipv4 import IPv4
from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
from pcapkit.protocols.internet.ipv6_route import IPv6_Route
from pcapkit.protocols.internet.mh import MH
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.misc.pcap.frame import Frame
from pcapkit.protocols.misc.pcapng import PCAPNG
from pcapkit.protocols.protocol import ProtocolBase as Protocol
from pcapkit.protocols.schema.application.httpv2 import FrameType as Schema_HTTP_FrameType
from pcapkit.protocols.schema.internet.hip import Parameter as Schema_HIP_Parameter
from pcapkit.protocols.schema.internet.hopopt import Option as Schema_HOPOPT_Option
from pcapkit.protocols.schema.internet.ipv4 import Option as Schema_IPv4_Option
from pcapkit.protocols.schema.internet.ipv6_opts import Option as Schema_IPv6_Opts_Option
from pcapkit.protocols.schema.internet.ipv6_route import \
    RoutingType as Schema_IPv6_Route_RoutingType
from pcapkit.protocols.schema.internet.mh import CGAExtension as Schema_MH_CGAExtension
from pcapkit.protocols.schema.internet.mh import Option as Schema_MH_Option
from pcapkit.protocols.schema.internet.mh import Packet as Schema_MH_Packet
from pcapkit.protocols.schema.misc.pcapng import BlockType as Schema_PCAPNG_BlockType
from pcapkit.protocols.schema.misc.pcapng import DSBSecrets as Schema_PCAPNG_DSBSecrets
from pcapkit.protocols.schema.misc.pcapng import \
    NameResolutionRecord as Schema_PCAPNG_NameResolutionRecord
from pcapkit.protocols.schema.misc.pcapng import Option as Schema_PCAPNG_Option
from pcapkit.protocols.schema.transport.tcp import MPTCP as Schema_TCP_MPTCP
from pcapkit.protocols.schema.transport.tcp import Option as Schema_TCP_Option
from pcapkit.protocols.transport.tcp import TCP
from pcapkit.protocols.transport.udp import UDP
from pcapkit.utilities.exceptions import RegistryError
from pcapkit.utilities.logging import logger

if TYPE_CHECKING:
    from typing import Optional, Type

    from pcapkit.const.hip.parameter import Parameter as HIP_Parameter
    from pcapkit.const.http.frame import Frame as HTTP_Frame
    from pcapkit.const.ipv4.option_number import OptionNumber as IPv4_OptionNumber
    from pcapkit.const.ipv6.option import Option as IPv6_Option
    from pcapkit.const.ipv6.routing import Routing as IPv6_Routing
    from pcapkit.const.mh.cga_extension import CGAExtension as MH_CGAExtension
    from pcapkit.const.mh.option import Option as MH_Option
    from pcapkit.const.mh.packet import Packet as MH_Packet
    from pcapkit.const.pcapng.block_type import BlockType as PCAPNG_BlockType
    from pcapkit.const.pcapng.option_type import OptionType as PCAPNG_OptionType
    from pcapkit.const.pcapng.record_type import RecordType as PCAPNG_RecordType
    from pcapkit.const.pcapng.secrets_type import SecretsType as PCAPNG_SecretsType
    from pcapkit.const.reg.ethertype import EtherType
    from pcapkit.const.reg.linktype import LinkType
    from pcapkit.const.reg.transtype import TransType
    from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as TCP_MPTCPOption
    from pcapkit.const.tcp.option import Option as TCP_Option
    from pcapkit.protocols.application.httpv2 import FrameConstructor as HTTP_FrameConstructor
    from pcapkit.protocols.application.httpv2 import FrameParser as HTTP_FrameParser
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
    from pcapkit.protocols.misc.pcapng import BlockConstructor as PCAPNG_BlockConstructor
    from pcapkit.protocols.misc.pcapng import BlockParser as PCAPNG_BlockParser
    from pcapkit.protocols.misc.pcapng import OptionConstructor as PCAPNG_OptionConstructor
    from pcapkit.protocols.misc.pcapng import OptionParser as PCAPNG_OptionParser
    from pcapkit.protocols.misc.pcapng import RecordConstructor as PCAPNG_RecordConstructor
    from pcapkit.protocols.misc.pcapng import RecordParser as PCAPNG_RecordParser
    from pcapkit.protocols.misc.pcapng import SecretsConstructor as PCAPNG_SecretsConstructor
    from pcapkit.protocols.misc.pcapng import SecretsParser as PCAPNG_SecretsParser
    from pcapkit.protocols.transport.tcp import MPOptionConstructor as TCP_MPOptionConstructor
    from pcapkit.protocols.transport.tcp import MPOptionParser as TCP_MPOptionParser
    from pcapkit.protocols.transport.tcp import OptionConstructor as TCP_OptionConstructor
    from pcapkit.protocols.transport.tcp import OptionParser as TCP_OptionParser

__all__ = [
    'register_protocol',

    'register_linktype',
    'register_pcap', 'register_pcapng',

    'register_ethertype',

    'register_transtype',
    'register_ipv4_option', 'register_hip_parameter', 'register_hopopt_option',
    'register_ipv6_opts_option', 'register_ipv6_route_routing',
    'register_mh_message', 'register_mh_option', 'register_mh_extension',

    'register_apptype',
    'register_tcp', 'register_udp',
    'register_tcp_option', 'register_tcp_mp_option',

    'register_http_frame',

    'register_pcapng_block', 'register_pcapng_option', 'register_pcapng_secrets',
    'register_pcapng_record',
]

NULL = '(null)'


# NOTE: pcapkit.protocols.__proto__
def register_protocol(protocol: 'Type[Protocol]') -> 'None':
    """Registered protocol class.

    The protocol class must be a subclass of
    :class:`~pcapkit.protocols.protocol.Protocol`, and will be registered to
    the :data:`pcapkit.protocols.__proto__` registry.

    Args:
        protocol: Protocol class.

    """
    if not issubclass(protocol, Protocol):
        raise RegistryError(f'protocol must be a Protocol subclass, not {protocol!r}')

    protocol_registry[protocol.__name__.upper()] = protocol
    logger.info('registered protocol: %s', protocol.__name__)


###############################################################################
# Top-Level Registries
###############################################################################


@overload
def register_linktype(code: 'LinkType', module: 'ModuleDescriptor[Protocol] | Type[Protocol]') -> 'None': ...
@overload
def register_linktype(code: 'LinkType', module: 'str', class_: 'str') -> 'None': ...


def register_linktype(code: 'LinkType', module: 'str | ModuleDescriptor[Protocol] | Type[Protocol]',
                      class_: 'str' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The full qualified class name of the new protocol class
        should be as ``{module}.{class_}``.

    The function will register the given protocol class to the
    following registries:

    - :data:`pcapkit.protocols.misc.pcap.frame.Frame.__proto__`
    - :data:`pcapkit.protocols.misc.pcapng.PCAPNG.__proto__`

    Arguments:
        code: protocol code as in :class:`~pcapkit.const.reg.linktype.LinkType`
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.Protocol` subclass
        class\_: class name

    See Also:
        * :func:`pcapkit.foundation.registry.protocols.register_pcap`
        * :func:`pcapkit.foundation.registry.protocols.register_pcapng`

    """
    if isinstance(module, str):
        module = cast('ModuleDescriptor[Protocol]', ModuleDescriptor(module, class_))

    Frame.register(code, module)
    PCAPNG.register(code, module)
    logger.info('registered linktype protocol: %s', code.name)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    register_protocol(module)


@overload
def register_pcap(code: 'LinkType', module: 'ModuleDescriptor[Protocol] | Type[Protocol]') -> 'None': ...
@overload
def register_pcap(code: 'LinkType', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.protocols.misc.pcap.frame.Frame.__proto__
def register_pcap(code: 'LinkType', module: 'str | ModuleDescriptor[Protocol] | Type[Protocol]',
                  class_: 'str' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The full qualified class name of the new protocol class
        should be as ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.misc.pcap.frame.Frame.__proto__` registry.

    Arguments:
        code: protocol code as in :class:`~pcapkit.const.reg.linktype.LinkType`
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.Protocol` subclass
        class\_: class name

    """
    if isinstance(module, str):
        module = cast('ModuleDescriptor[Protocol]', ModuleDescriptor(module, class_))

    Frame.register(code, module)
    logger.info('registered PCAP linktype protocol: %s', code.name)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    register_protocol(module)


@overload
def register_pcapng(code: 'LinkType', module: 'ModuleDescriptor[Protocol] | Type[Protocol]') -> 'None': ...
@overload
def register_pcapng(code: 'LinkType', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.protocols.misc.pcapng.PCAPNG.__proto__
def register_pcapng(code: 'LinkType', module: 'str | ModuleDescriptor[Protocol] | Type[Protocol]',
                    class_: 'str' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The full qualified class name of the new protocol class
        should be as ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.misc.pcapng.PCAPNG.__proto__` registry.

    Arguments:
        code: protocol code as in :class:`~pcapkit.const.reg.linktype.LinkType`
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.Protocol` subclass
        class\_: class name

    """
    if isinstance(module, str):
        module = cast('ModuleDescriptor[Protocol]', ModuleDescriptor(module, class_))

    PCAPNG.register(code, module)
    logger.info('registered PCAP-NG linktype protocol: %s', code.name)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    register_protocol(module)


###############################################################################
# Link Layer Registries
###############################################################################


@overload
def register_ethertype(code: 'EtherType', module: 'ModuleDescriptor[Protocol] | Type[Protocol]') -> 'None': ...
@overload
def register_ethertype(code: 'EtherType', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.protocols.link.link.Link.__proto__
def register_ethertype(code: 'EtherType', module: 'str | ModuleDescriptor[Protocol] | Type[Protocol]',
                       class_: 'str' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The full qualified class name of the new protocol class
        should be as ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.link.link.Link.__proto__` registry.

    Arguments:
        code: protocol code as in :class:`~pcapkit.const.reg.ethertype.EtherType`
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.Protocol` subclass
        class\_: class name

    """
    if isinstance(module, str):
        module = cast('ModuleDescriptor[Protocol]', ModuleDescriptor(module, class_))

    Link.register(code, module)
    logger.info('registered ethertype protocol: %s', code.name)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    register_protocol(module)


###############################################################################
# Internet Layer Registries
###############################################################################


@overload
def register_transtype(code: 'TransType', module: 'ModuleDescriptor[Protocol] | Type[Protocol]') -> 'None': ...
@overload
def register_transtype(code: 'TransType', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.protocols.internet.internet.Internet.__proto__
def register_transtype(code: 'TransType', module: 'str | ModuleDescriptor[Protocol] | Type[Protocol]',
                       class_: 'str' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The full qualified class name of the new protocol class
        should be as ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.internet.internet.Internet.__proto__` registry.

    Arguments:
        code: protocol code as in :class:`~pcapkit.const.reg.transtype.TransType`
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.Protocol` subclass
        class\_: class name

    """
    if isinstance(module, str):
        module = cast('ModuleDescriptor[Protocol]', ModuleDescriptor(module, class_))

    Internet.register(code, module)
    logger.info('registered transtype protocol: %s', code.name)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    register_protocol(module)


# NOTE: pcapkit.protocols.internet.internet.IPv4
def register_ipv4_option(code: 'IPv4_OptionNumber', meth: 'str | tuple[IPv4_OptionParser, IPv4_OptionConstructor]', *,
                         schema: 'Optional[Type[Schema_IPv4_Option]]' = None) -> 'None':
    """Register an option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.internet.internet.IPv4` internal registry.

    Args:
        code: :class:`IPv4 <pcapkit.protocols.internet.ipv4.IPv4>` option code as
            in :class:`~pcapkit.const.ipv4.option_number.OptionNumber`.
        meth: Method name or callable to parse and/or construct the option.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the option.
            It should be a subclass of :class:`pcapkit.protocols.schema.internet.ipv4.Option`.

    """
    if isinstance(meth, str) and not hasattr(IPv4, f'_read_opt_{meth}'):
        raise RegistryError('method must be a valid IPv4 option parser function')

    IPv4.register_option(code, meth)
    if schema is not None:
        Schema_IPv4_Option.register(code, schema)
    logger.info('registered IPv4 option parser: %s', code.name)


# NOTE: pcapkit.protocols.internet.hip.HIP
def register_hip_parameter(code: 'HIP_Parameter', meth: 'str | tuple[HIP_ParameterParser, HIP_ParameterConstructor]', *,
                           schema: 'Optional[Type[Schema_HIP_Parameter]]' = None) -> 'None':
    """Register a parameter parser.

    The function will register the given parameter parser to the
    :data:`pcapkit.protocols.internet.hip.HIP` internal registry.

    Args:
        code: :class:`~pcapkit.protocols.internet.hip.HIP` parameter code as
            in :class:`~pcapkit.const.hip.parameter.Parameter`.
        meth: Method name or callable to parse and/or construct the parameter.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the parameter.
            It should be a subclass of :class:`pcapkit.protocols.schema.internet.hip.Parameter`.

    """
    if isinstance(meth, str) and not hasattr(HIP, f'_read_param_{meth}'):
        raise RegistryError('method must be a valid HIP parameter parser function')

    HIP.register_parameter(code, meth)
    if schema is not None:
        Schema_HIP_Parameter.register(code, schema)
    logger.info('registered HIP parameter parser: %s', code.name)


# NOTE: pcapkit.protocols.internet.hopopt.HOPOPT.__option__
def register_hopopt_option(code: 'IPv6_Option', meth: 'str | tuple[HOPOPT_OptionParser, HOPOPT_OptionConstructor]', *,
                           schema: 'Optional[Type[Schema_HOPOPT_Option]]' = None) -> 'None':
    """Register an option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.internet.hopopt.HOPOPT.__option__` registry.

    Args:
        code: :class:`~pcapkit.protocols.internet.hopopt.HOPOPT` option code as
            in :class:`~pcapkit.const.ipv6.option.Option`.
        meth: Method name or callable to parse and/or construct the option.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the option.
            It should be a subclass of :class:`pcapkit.protocols.schema.internet.hopopt.Option`.

    """
    if isinstance(meth, str) and not hasattr(HOPOPT, f'_read_opt_{meth}'):
        raise RegistryError('method must be a valid HOPOPT option parser function')

    HOPOPT.register_option(code, meth)
    if schema is not None:
        Schema_HOPOPT_Option.register(code, schema)
    logger.info('registered HOPOPT option parser: %s', code.name)


# NOTE: pcapkit.protocols.internet.ipv6_opts.IPv6_Opts.__option__
def register_ipv6_opts_option(code: 'IPv6_Option', meth: 'str | tuple[IPv6_Opts_OptionParser, IPv6_Opts_OptionConstructor]', *,
                              schema: 'Optional[Type[Schema_IPv6_Opts_Option]]' = None) -> 'None':
    """Register an option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.internet.ipv6_opts.IPv6_Opts.__option__` registry.

    Args:
        code: :class:`IPv6-Opts <pcapkit.protocols.internet.ipv6_opts.IPv6_Opts>`
            option code as in :class:`~pcapkit.const.ipv6.option.Option`.
        meth: Method name or callable to parse and/or construct the option.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the option.
            It should be a subclass of :class:`pcapkit.protocols.schema.internet.ipv6_opts.Option`.

    """
    if isinstance(meth, str) and not hasattr(IPv6_Opts, f'_read_opt_{meth}'):
        raise RegistryError('method must be a valid IPv6-Opts option parser function')

    IPv6_Opts.register_option(code, meth)
    if schema is not None:
        Schema_IPv6_Opts_Option.register(code, schema)
    logger.info('registered IPv6-Opts option parser: %s', code.name)


# NOTE: pcapkit.protocols.internet.ipv6_route.IPv6_Route.__routing__
def register_ipv6_route_routing(code: 'IPv6_Routing', meth: 'str | tuple[IPv6_Route_TypeParser, IPv6_Route_TypeConstructor]', *,
                                schema: 'Optional[Type[Schema_IPv6_Route_RoutingType]]' = None) -> 'None':
    """Register a routing data parser.

    The function will register the given routing data parser to the
    :data:`pcapkit.protocols.internet.ipv6_route.IPv6_Route.__routing__` registry.

    Args:
        code: :class:`IPv6-Route <pcapkit.protocols.internet.ipv6_route.IPv6_Route>`
            data type code as in :class:`~pcapkit.const.ipv6.routing.Routing`.
        meth: Method name or callable to parse and/or construct the data.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the routing data.
            It should be a subclass of :class:`pcapkit.protocols.schema.internet.ipv6_route.RoutingType`.

    """
    if isinstance(meth, str) and not hasattr(IPv6_Route, f'_read_data_type_{meth}'):
        raise RegistryError('method must be a valid IPv6-Route routing data parser function')

    IPv6_Route.register_routing(code, meth)
    if schema is not None:
        Schema_IPv6_Route_RoutingType.register(code, schema)
    logger.info('registered IPv6-Route routing data parser: %s', code.name)


# NOTE: pcapkit.protocols.internet.mh.MH.__message__
def register_mh_message(code: 'MH_Packet', meth: 'str | tuple[MH_PacketParser, MH_PacketConstructor]', *,
                        schema: 'Optional[Type[Schema_MH_Packet]]' = None) -> 'None':
    """Register a MH message type parser.

    The function will register the given message type parser to the
    :data:`pcapkit.protocols.internet.mh.MH.__message__` registry.

    Args:
        code: :class:`~pcapkit.protocols.internet.mh.MH>`
            data type code as in :class:`~pcapkit.const.mh.packet.Packet`.
        meth: Method name or callable to parse and/or construct the data.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the message type.
            It should be a subclass of :class:`pcapkit.protocols.schema.internet.mh.Packet`.

    """
    if isinstance(meth, str) and not hasattr(MH, f'_read_msg_{meth}'):
        raise RegistryError('method must be a valid MH message type parser function')

    MH.register_message(code, meth)
    if schema is not None:
        Schema_MH_Packet.register(code, schema)
    logger.info('registered MH message type parser: %s', code.name)


# NOTE: pcapkit.protocols.internet.mh.MH.__option__
def register_mh_option(code: 'MH_Option', meth: 'str | tuple[MH_OptionParser, MH_OptionConstructor]', *,
                       schema: 'Optional[Type[Schema_MH_Option]]' = None) -> 'None':
    """Register a MH option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.internet.mh.MH.__option__` registry.

    Args:
        code: :class:`~pcapkit.protocols.internet.mh.MH>`
            data type code as in :class:`~pcapkit.const.mh.option.Option`.
        meth: Method name or callable to parse and/or construct the data.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the message type.
            It should be a subclass of :class:`pcapkit.protocols.schema.internet.mh.Option`.

    """
    if isinstance(meth, str) and not hasattr(MH, f'_read_opt_{meth}'):
        raise RegistryError('method must be a valid MH option parser function')

    MH.register_option(code, meth)
    if schema is not None:
        Schema_MH_Option.register(code, schema)
    logger.info('registered MH option parser: %s', code.name)


# NOTE: pcapkit.protocols.internet.mh.MH.__extension__
def register_mh_extension(code: 'MH_CGAExtension', meth: 'str | tuple[MH_ExtensionParser, MH_ExtensionConstructor]',
                          schema: 'Optional[Type[Schema_MH_CGAExtension]]' = None) -> 'None':
    """Register a CGA extension parser.

    The function will register the given CGA extension to the
    :data:`pcapkit.protocols.internet.mh.MH.__extension__` registry.

    Args:
        code: :class:`~pcapkit.protocols.internet.mh.MH>`
            data type code as in :class:`~pcapkit.const.mh.cga_extension.CGAExtension`.
        meth: Method name or callable to parse and/or construct the data.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the message type.
            It should be a subclass of :class:`pcapkit.protocols.schema.internet.mh.CGAExtension`.

    """
    if isinstance(meth, str) and not hasattr(MH, f'_read_ext_{meth}'):
        raise RegistryError('method must be a valid MH CGA extension function')

    MH.register_extension(code, meth)
    if schema is not None:
        Schema_MH_CGAExtension.register(code, schema)
    logger.info('registered MH CGA extension: %s', code.name)


###############################################################################
# Transport Layer Registries
###############################################################################


@overload
def register_apptype(code: 'int', module: 'ModuleDescriptor[Protocol] | Type[Protocol]', *, proto: 'TransportProtocol | str') -> 'None': ...
@overload
def register_apptype(code: 'Enum_AppType', module: 'ModuleDescriptor[Protocol] | Type[Protocol]', *, proto: 'TransportProtocol | str' = ...) -> 'None': ...
@overload
def register_apptype(code: 'int', module: 'str', class_: 'str', *, proto: 'TransportProtocol | str') -> 'None': ...
@overload
def register_apptype(code: 'Enum_AppType', module: 'str', class_: 'str', *, proto: 'TransportProtocol | str' = ...) -> 'None': ...


def register_apptype(code: 'int | Enum_AppType', module: 'str | ModuleDescriptor[Protocol] | Type[Protocol]',
                     class_: 'str' = NULL, *, proto: 'TransportProtocol | str' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The full qualified class name of the new protocol class
        should be as ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.transport.tcp.TCP.__proto__` and/or
    :data:`pcapkit.protocols.transport.udp.UDP.__proto__` registry.

    Arguments:
        code: port number
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.Protocol` subclass
        class\_: class name
        proto: protocol name (must be a valid transport protocol)

    See Also:
        * :func:`pcapkit.foundation.registry.register_tcp`
        * :func:`pcapkit.foundation.registry.register_udp`

    """
    if isinstance(code, Enum_AppType):
        if proto is NULL:
            proto = code.proto
        code = code.port
    if isinstance(module, str):
        module = cast('ModuleDescriptor[Protocol]', ModuleDescriptor(module, class_))

    _reg = False
    if isinstance(proto, str):
        proto = TransportProtocol.get(proto.lower())

    for test, cls in cast('dict[TransportProtocol, Type[Protocol]]', {
        TransportProtocol.tcp: TCP,
        TransportProtocol.udp: UDP,
    }).items():
        if test not in proto:
            continue

        cls.register(code, module)
        logger.info('registered %s port: %s', test.name, code)
        _reg = True

    if not _reg:
        raise RegistryError(f'unknown transport protocol: {proto.name}')

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    register_protocol(module)


@overload
def register_tcp(code: 'int | Enum_AppType', module: 'ModuleDescriptor[Protocol] | Type[Protocol]') -> 'None': ...
@overload
def register_tcp(code: 'int | Enum_AppType', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.protocols.transport.tcp.TCP.__proto__
def register_tcp(code: 'int | Enum_AppType', module: 'str | ModuleDescriptor[Protocol] | Type[Protocol]',
                 class_: 'str' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The full qualified class name of the new protocol class
        should be as ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.transport.tcp.TCP.__proto__` registry.

    Arguments:
        code: port number
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.Protocol` subclass
        class\_: class name

    """
    if isinstance(code, Enum_AppType):
        code = code.port
    if isinstance(module, str):
        module = cast('ModuleDescriptor[Protocol]', ModuleDescriptor(module, class_))

    TCP.register(code, module)
    logger.info('registered TCP port: %s', code)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    register_protocol(module)


# NOTE: pcapkit.protocols.transport.tcp.TCP.__option__
def register_tcp_option(code: 'TCP_Option', meth: 'str | tuple[TCP_OptionParser, TCP_OptionConstructor]', *,
                        schema: 'Optional[Type[Schema_TCP_Option]]' = None) -> 'None':
    """Register an option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.transport.tcp.TCP.__option__` registry.

    Args:
        code: :class:`~pcapkit.protocols.transport.tcp.TCP` option code as in
            :class:`~pcapkit.const.tcp.option.Option`.
        meth: Method name or callable to parse and/or construct the option.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the option.
            It should be a subclass of :class:`pcapkit.protocols.schema.transport.tcp.Option`.

    """
    if isinstance(meth, str) and not hasattr(TCP, f'_read_mode_{meth}'):
        raise RegistryError('method must be a TCP option parser function')

    TCP.register_option(code, meth)
    if schema is not None:
        Schema_TCP_Option.register(code, schema)
    logger.info('registered TCP option parser: %s', code.name)


# NOTE: pcapkit.protocols.transport.tcp.TCP.__mp_option__
def register_tcp_mp_option(code: 'TCP_MPTCPOption', meth: 'str | tuple[TCP_MPOptionParser, TCP_MPOptionConstructor]', *,
                           schema: 'Optional[Type[Schema_TCP_MPTCP]]' = None) -> 'None':
    """Register an MPTCP option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.transport.tcp.TCP.__mp_option__` registry.

    Args:
        code: Multipath :class:`~pcapkit.protocols.transport.tcp.TCP` option code as in
            :class:`~pcapkit.const.tcp.mp_tcp_option.MPTCPOption`.
        meth: Method name or callable to parse and/or construct the option.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the option.
            It should be a subclass of :class:`pcapkit.protocols.schema.transport.tcp.MPTCP`.

    """
    if isinstance(meth, str) and not hasattr(TCP, f'_read_mptcp_{meth}'):
        raise RegistryError('method must be a MPTCP option parser function')

    TCP.register_mp_option(code, meth)
    if schema is not None:
        Schema_TCP_MPTCP.register(code, schema)
    logger.info('registered MPTCP option parser: %s', code.name)


@overload
def register_udp(code: 'int | Enum_AppType', module: 'ModuleDescriptor[Protocol] | Type[Protocol]') -> 'None': ...
@overload
def register_udp(code: 'int | Enum_AppType', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.protocols.transport.udp.UDP.__proto__
def register_udp(code: 'int | Enum_AppType', module: 'str | ModuleDescriptor[Protocol] | Type[Protocol]',
                 class_: 'str' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The full qualified class name of the new protocol class
        should be as ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.transport.udp.UDP.__proto__` registry.

    Arguments:
        code: port number
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.Protocol` subclass
        class\_: class name

    """
    if isinstance(code, Enum_AppType):
        code = code.port
    if isinstance(module, str):
        module = cast('ModuleDescriptor[Protocol]', ModuleDescriptor(module, class_))

    UDP.register(code, module)
    logger.info('registered UDP port: %s', code)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    register_protocol(module)


###############################################################################
# Application Layer Registries
###############################################################################


# NOTE: pcapkit.protocols.application.httpv2.HTTPv2.__frame__
def register_http_frame(code: 'HTTP_Frame', meth: 'str | tuple[HTTP_FrameParser, HTTP_FrameConstructor]', *,
                        schema: 'Optional[Type[Schema_HTTP_FrameType]]' = None) -> 'None':
    """Registered a frame parser.

    The function will register the given frame parser to the
    :data:`pcapkit.protocols.application.httpv2.HTTP.__frame__` registry.

    Args:
        code: :class:`HTTP/2 <pcapkit.protocols.application.httpv2.HTTP>` frame type
            code as in :class:`~pcapkit.const.http.frame.Frame`.
        meth: Method name or callable to parse and/or construct the frame.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the frame.
            It should be a subclass of :class:`pcapkit.protocols.schema.application.httpv2.FrameType`.

    """
    if isinstance(meth, str) and not hasattr(HTTPv2, f'_read_http_{meth}'):
        raise RegistryError('method must be a frame parser function')

    HTTPv2.register_frame(code, meth)
    if schema is not None:
        Schema_HTTP_FrameType.register(code, schema)
    logger.info('registered HTTP/2 frame parser: %s', code.name)


###############################################################################
# Miscellaneous Protocol Registries
###############################################################################


# NOTE: pcapkit.protocols.misc.pcapng.PCAPNG.__block__
def register_pcapng_block(code: 'PCAPNG_BlockType', meth: 'str | tuple[PCAPNG_BlockParser, PCAPNG_BlockConstructor]', *,
                          schema: 'Optional[Type[Schema_PCAPNG_BlockType]]' = None) -> 'None':
    """Registered a block parser.

    The function will register the given block parser to the
    :data:`pcapkit.protocols.misc.pcapng.PCAPNG.__block__` registry.

    Args:
        code: :class:`HTTP/2 <pcapkit.protocols.misc.pcapng.PCAPNG>` block type
            code as in :class:`~pcapkit.const.pcapng.block_type.BlockType`.
        meth: Method name or callable to parse and/or construct the block.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the block.
            It should be a subclass of :class:`pcapkit.protocols.schema.misc.pcapng.BlockType`.

    """
    if isinstance(meth, str) and not hasattr(PCAPNG, f'_read_block_{meth}'):
        raise RegistryError('method must be a block parser function')

    PCAPNG.register_block(code, meth)
    if schema is not None:
        Schema_PCAPNG_BlockType.register(code, schema)
    logger.info('registered PCAP-NG block parser: %s', code.name)


# NOTE: pcapkit.protocols.misc.pcapng.PCAPNG.__option__
def register_pcapng_option(code: 'PCAPNG_OptionType', meth: 'str | tuple[PCAPNG_OptionParser, PCAPNG_OptionConstructor]', *,
                           schema: 'Optional[Type[Schema_PCAPNG_Option]]' = None) -> 'None':
    """Registered a option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.misc.pcapng.PCAPNG.__option__` registry.

    Args:
        code: :class:`PCAPNG <pcapkit.protocols.misc.pcapng.PCAPNG>` option type
            code as in :class:`~pcapkit.const.pcapng.option_type.OptionType`.
        meth: Method name or callable to parse and/or construct the option.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the option.
            It should be a subclass of :class:`pcapkit.protocols.schema.misc.pcapng.Option`.

    """
    if isinstance(meth, str) and not hasattr(PCAPNG, f'_read_option_{meth}'):
        raise RegistryError('method must be a option parser function')

    PCAPNG.register_option(code, meth)
    if schema is not None:
        Schema_PCAPNG_Option.register(code, schema)
    logger.info('registered PCAP-NG option parser: %s', code.name)


# NOTE: pcapkit.protocols.misc.pcapng.PCAPNG.__record__
def register_pcapng_record(code: 'PCAPNG_RecordType', meth: 'str | tuple[PCAPNG_RecordParser, PCAPNG_RecordConstructor]', *,
                           schema: 'Optional[Type[Schema_PCAPNG_NameResolutionRecord]]' = None) -> 'None':
    """Registered a name resolution record parser.

    The function will register the given name resolution record parser to the
    :data:`pcapkit.protocols.misc.pcapng.PCAPNG.__record__` registry.

    Args:
        code: :class:`PCAPNG <pcapkit.protocols.misc.pcapng.PCAPNG>` name
            resolution record type code as in :class:`~pcapkit.const.pcapng.record_type.RecordType`.
        meth: Method name or callable to parse and/or construct the name
            resolution record.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the name resolution record.
            It should be a subclass of :class:`pcapkit.protocols.schema.misc.pcapng.NameResolutionRecord`.

    """
    if isinstance(meth, str) and not hasattr(PCAPNG, f'_read_record_{meth}'):
        raise RegistryError('method must be a name resolution record parser function')

    PCAPNG.register_record(code, meth)
    if schema is not None:
        Schema_PCAPNG_NameResolutionRecord.register(code, schema)
    logger.info('registered PCAP-NG name resolution record parser: %s', code.name)


# NOTE: pcapkit.protocols.misc.pcapng.PCAPNG.__secrets__
def register_pcapng_secrets(code: 'PCAPNG_SecretsType', meth: 'str | tuple[PCAPNG_SecretsParser, PCAPNG_SecretsConstructor]', *,
                            schema: 'Optional[Type[Schema_PCAPNG_DSBSecrets]]' = None) -> 'None':
    """Registered a decryption secrets parser.

    The function will register the given decryption secrets parser to the
    :data:`pcapkit.protocols.misc.pcapng.PCAPNG.__secrets__` registry.

    Args:
        code: :class:`PCAPNG <pcapkit.protocols.misc.pcapng.PCAPNG>` decryption
            secrets type code as in :class:`~pcapkit.const.pcapng.secrets_type.SecretsType`.
        meth: Method name or callable to parse and/or construct the decryption secrets.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the decryption secrets.
            It should be a subclass of :class:`pcapkit.protocols.schema.misc.pcapng.DSBSecrets`.

    """
    if isinstance(meth, str) and not hasattr(PCAPNG, f'_read_secrets_{meth}'):
        raise RegistryError('method must be a decryption secrets parser function')

    PCAPNG.register_secrets(code, meth)
    if schema is not None:
        Schema_PCAPNG_DSBSecrets.register(code, schema)
    logger.info('registered PCAP-NG decryption secrets parser: %s', code.name)
