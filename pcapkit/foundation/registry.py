# -*- coding: utf-8 -*-
"""Registry Management
=========================

This module provides the registry management for :mod:`pcapkit`, as the module
contains various registry points.

"""
import importlib
from typing import TYPE_CHECKING

from dictdumper import Dumper

from pcapkit.foundation.extraction import Extractor
from pcapkit.foundation.traceflow import TraceFlow
from pcapkit.protocols import __proto__ as protocol_registry
from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
from pcapkit.protocols.internet.hopopt import HOPOPT
from pcapkit.protocols.internet.internet import Internet
from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
from pcapkit.protocols.internet.ipv6_route import IPv6_Route
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.misc.pcap.frame import Frame
from pcapkit.protocols.protocol import Protocol
from pcapkit.protocols.transport.tcp import TCP
from pcapkit.protocols.transport.udp import UDP
from pcapkit.utilities.exceptions import RegistryError
from pcapkit.utilities.logging import logger

if TYPE_CHECKING:
    from typing import Callable, Type

    from mypy_extensions import NamedArg
    from typing_extensions import Literal

    from pcapkit.const.http.frame import Frame as HTTP_Frame
    from pcapkit.const.ipv6.option import Option as IPv6_Option
    from pcapkit.const.ipv6.routing import Routing as IPv6_Routing
    from pcapkit.const.reg.ethertype import EtherType
    from pcapkit.const.reg.linktype import LinkType
    from pcapkit.const.reg.transtype import TransType
    from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as TCP_MPTCPOption
    from pcapkit.const.tcp.option import Option as TCP_Option
    from pcapkit.corekit.multidict import OrderedMultiDict
    from pcapkit.protocols.data.application.httpv2 import HTTP as DataType_HTTPv2
    from pcapkit.protocols.data.internet.hopopt import Option as DataType_HOPOPT_Option
    from pcapkit.protocols.data.internet.ipv6_opts import Option as DataType_IPv6_Opts_Option
    from pcapkit.protocols.data.internet.ipv6_route import \
        RoutingType as DataType_IPv6_Route_RoutingType
    from pcapkit.protocols.data.transport.tcp import MPTCP as DataType_TCP_MPTCP
    from pcapkit.protocols.data.transport.tcp import Option as DataType_TCP_Option

    #from pcapkit.protocols.application.httpv2 import FrameParser as HTTP_FrameParser
    HTTP_FrameParser = Callable[[HTTPv2, HTTP_Frame, int, str, int], DataType_HTTPv2]
    #from pcapkit.protocols.internet.hopopt import OptionParser as HOPOPT_OptionParser
    HOPOPT_OptionParser = Callable[[HOPOPT, IPv6_Option, int, bool,
                                    NamedArg(OrderedMultiDict[IPv6_Option, DataType_HOPOPT_Option], 'options')],
                                   DataType_HOPOPT_Option]
    #from pcapkit.protocols.internet.ipv6_opts import OptionParser as IPv6_Opts_OptionParser
    IPv6_Opts_OptionParser = Callable[[IPv6_Opts, IPv6_Option, int, bool,
                                       NamedArg(OrderedMultiDict[IPv6_Option, DataType_IPv6_Opts_Option], 'options')],
                                      DataType_IPv6_Opts_Option]
    #from pcapkit.protocols.internet.ipv6_route import TypeParser as IPv6_Route_TypeParser
    IPv6_Route_TypeParser = Callable[[IPv6_Route, int], DataType_IPv6_Route_RoutingType]
    #from pcapkit.protocols.transport.tcp import MPOptionParser as TCP_MPOptionParser
    TCP_MPOptionParser = Callable[[TCP, TCP_MPTCPOption, int, str,
                                   NamedArg(OrderedMultiDict[TCP_Option, DataType_TCP_Option], 'options')],
                                  DataType_TCP_MPTCP]
    #from pcapkit.protocols.transport.tcp import OptionParser as TCP_OptionParser
    TCP_OptionParser = Callable[[TCP, TCP_Option,
                                 NamedArg(OrderedMultiDict[TCP_Option, DataType_TCP_Option], 'options')],
                                DataType_TCP_Option]

__all__ = [
    'register_protocol',

    'register_linktype', 'register_pcap',
    'register_ethertype', 'register_transtype',
    'register_port', 'register_tcp_port', 'register_udp_port',

    'register_output', 'register_extractor', 'register_traceflow',

    'register_hopopt', 'register_ipv6_opts', 'register_ipv6_route',
    'register_tcp', 'register_mptcp',
    'register_http',
]

###############################################################################
# pcapkit.protocols.Protocol.__proto__
###############################################################################


def register_protocol(protocol: 'Type[Protocol]') -> 'None':
    """registered protocol class.

    The protocol class must be a subclass of
    :class:`~pcapkit.protocols.protocol.Protocol`, and will be registered to
    the :data:`pcapkit.protocols.__proto__` registry.

    Args:
        protocol: Protocol class.

    """
    if not issubclass(protocol, Protocol):
        raise RegistryError('protocol must be a Protocol subclass')

    protocol_registry[protocol.__name__.upper()] = protocol
    logger.info('registered protocol: %s', protocol.__name__)


###############################################################################
# pcapkit.foundation.extraction.Extractor.__output__
###############################################################################


def register_extractor(format: 'str', module: 'str', class_: 'str', ext: 'str') -> 'None':  # pylint: disable=redefined-builtin
    r"""registered a new dumper class.

    Notes:
        The full qualified class name of the new dumper class
        should be as ``{module}.{class_}``.

    The function will register the given dumper class to the
    :data:`pcapkit.foundation.extraction.Extractor.__output__` registry.

    Arguments:
        format: format name
        module: module name
        class\_: class name
        ext: file extension

    """
    dumper = getattr(importlib.import_module(module), class_)
    if not issubclass(dumper, Dumper):
        raise RegistryError('dumper must be a Dumper subclass')

    Extractor.register(format, module, class_, ext)
    logger.info('registered extractor output: %s', format)


###############################################################################
# pcapkit.foundation.traceflow.TraceFlow.__output__
###############################################################################


def register_traceflow(format: 'str', module: 'str', class_: 'str', ext: 'str') -> 'None':  # pylint: disable=redefined-builtin
    r"""registered a new dumper class.

    Notes:
        The full qualified class name of the new dumper class
        should be as ``{module}.{class_}``.

    The function will register the given dumper class to the
    :data:`pcapkit.foundation.traceflow.TraceFlow.__output__` registry.

    Arguments:
        format: format name
        module: module name
        class\_: class name
        ext: file extension

    """
    dumper = getattr(importlib.import_module(module), class_)
    if not issubclass(dumper, Dumper):
        raise RegistryError('dumper must be a Dumper subclass')

    TraceFlow.register(format, module, class_, ext)
    logger.info('registered traceflow output: %s', format)


###############################################################################
# pcapkit.protocols.application.httpv2.HTTPv2.__frame__
###############################################################################


def register_http(code: 'HTTP_Frame', meth: 'str | HTTP_FrameParser') -> 'None':
    """registered a frame parser.

    The function will register the given frame parser to the
    :data:`pcapkit.protocols.application.httpv2.HTTPv2.__frame__` registry.

    Args:
        code: :class:`HTTP/2 <pcapkit.protocols.application.httpv2.HTTPv2>` frame type
            code as in :class:`~pcapkit.const.http.frame.Frame`.
        meth: Method name or callable to parse the frame.

    """
    if isinstance(meth, str) and not hasattr(HTTPv2, f'_read_http_{meth}'):
        raise RegistryError('method must be a frame parser function')

    HTTPv2.register_frame(code, meth)
    logger.info('registered HTTP/2 frame parser: %s', code.name)


###############################################################################
# pcapkit.protocols.internet.hopopt.HOPOPT.__option__
###############################################################################


def register_hopopt(code: 'IPv6_Option', meth: 'str | HOPOPT_OptionParser') -> 'None':
    """Register an option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.internet.hopopt.HOPOPT.__option__` registry.

    Args:
        code: :class:`~pcapkit.protocols.internet.hopopt.HOPOPT` option code as
            in :class:`~pcapkit.const.ipv6.option.Option`.
        meth: Method name or callable to parse the option.

    """
    if isinstance(meth, str) and not hasattr(HOPOPT, f'_read_opt_{meth}'):
        raise RegistryError('method must be a HOPOPT option parser function')

    HOPOPT.register_option(code, meth)
    logger.info('registered HOPOPT option parser: %s', code.name)


###############################################################################
# pcapkit.protocols.internet.internet.Internet.__proto__
###############################################################################


def register_transtype(code: 'TransType', module: str, class_: str) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The full qualified class name of the new protocol class
        should be as ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.internet.internet.Internet.__proto__` registry.

    Arguments:
        code: protocol code as in :class:`~pcapkit.const.reg.transtype.TransType`
        module: module name
        class\_: class name

    """
    protocol = getattr(importlib.import_module(module), class_)
    if not issubclass(protocol, Protocol):
        raise RegistryError('protocol must be a Protocol subclass')

    Internet.register(code, module, class_)
    logger.info('registered transtype protocol: %s', code.name)

    # register protocol to protocol registry
    register_protocol(protocol)


###############################################################################
# pcapkit.protocols.internet.ipv6_opts.IPv6_Opts.__option__
###############################################################################


def register_ipv6_opts(code: 'IPv6_Option', meth: 'str | IPv6_Opts_OptionParser') -> 'None':
    """Register an option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.internet.ipv6_opts.IPv6_Opts.__option__` registry.

    Args:
        code: :class:`IPv6-Opts <pcapkit.protocols.internet.ipv6_opts.IPv6_Opts>`
            option code as in :class:`~pcapkit.const.ipv6.option.Option`.
        meth: Method name or callable to parse the option.

    """
    if isinstance(meth, str) and not hasattr(IPv6_Opts, f'_read_opt_{meth}'):
        raise RegistryError('method must be a IPv6_Opts option parser function')

    IPv6_Opts.register_option(code, meth)
    logger.info('registered IPv6_Opts option parser: %s', code.name)


###############################################################################
# pcapkit.protocols.internet.ipv6_route.IPv6_Route.__routing__
###############################################################################


def register_ipv6_route(code: 'IPv6_Routing', meth: 'str | IPv6_Route_TypeParser') -> 'None':
    r"""Register an routing data parser.

    The function will register the given routing data parser to the
    :data:`pcapkit.protocols.internet.ipv6_route.IPv6_Route.__routing__` registry.

    Args:
        code: :class:`IPv6-Route <pcapkit.protocols.internet.ipv6_route.IPv6_Route>`
            data type code as in :class:`~pcapkit.const.ipv6.routing.Routing`.
        meth: Method name or callable to parse the data.

    """
    if isinstance(meth, str) and not hasattr(IPv6_Route, f'_read_data_type_{meth}'):
        raise RegistryError('method must be a IPv6_Route routing data parser function')

    IPv6_Route.register_routing(code, meth)
    logger.info('registered IPv6_Route routing data parser: %s', code.name)


###############################################################################
# pcapkit.protocols.link.link.Link.__proto__
###############################################################################


def register_ethertype(code: 'EtherType', module: str, class_: str) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The full qualified class name of the new protocol class
        should be as ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.link.link.Link.__proto__` registry.

    Arguments:
        code: protocol code as in :class:`~pcapkit.const.reg.ethertype.EtherType`
        module: module name
        class\_: class name

    """
    protocol = getattr(importlib.import_module(module), class_)
    if not issubclass(protocol, Protocol):
        raise RegistryError('protocol must be a Protocol subclass')

    Link.register(code, module, class_)
    logger.info('registered ethertype protocol: %s', code.name)

    # register protocol to protocol registry
    register_protocol(protocol)


###############################################################################
# pcapkit.protocols.misc.pcap.frame.Frame.__proto__
###############################################################################


def register_pcap(code: 'LinkType', module: str, class_: str) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The full qualified class name of the new protocol class
        should be as ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.misc.pcap.frame.Frame.__proto__` registry.

    Arguments:
        code: protocol code as in :class:`~pcapkit.const.reg.linktype.LinkType`
        module: module name
        class\_: class name

    """
    protocol = getattr(importlib.import_module(module), class_)
    if not issubclass(protocol, Protocol):
        raise RegistryError('protocol must be a Protocol subclass')

    Frame.register(code, module, class_)
    logger.info('registered PCAP frame protocol: %s', code.name)

    # register protocol to protocol registry
    register_protocol(protocol)


###############################################################################
# pcapkit.protocols.transport.tcp.TCP.__option__
###############################################################################


def register_tcp(code: 'TCP_Option', meth: 'str | TCP_OptionParser') -> 'None':
    """Register an option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.transport.tcp.TCP.__option__` registry.

    Args:
        code: :class:`~pcapkit.protocols.transport.tcp.TCP` option code as in
            :class:`~pcapkit.const.tcp.option.Option`.
        meth: Method name or callable to parse the option.

    """
    if isinstance(meth, str) and not hasattr(TCP, f'_read_mode_{meth}'):
        raise RegistryError('method must be a TCP option parser function')

    TCP.register_option(code, meth)
    logger.info('registered TCP option parser: %s', code.name)


###############################################################################
# pcapkit.protocols.transport.tcp.TCP.__mp_option__
###############################################################################


def register_mptcp(code: 'TCP_MPTCPOption', meth: 'str | TCP_MPOptionParser') -> 'None':
    """Register an MPTCP option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.transport.tcp.TCP.__mp_option__` registry.

    Args:
        code: Multipath :class:`~pcapkit.protocols.transport.tcp.TCP` option code as in
            :class:`~pcapkit.const.tcp.mp_tcp_option.MPTCPOption`.
        meth: Method name or callable to parse the option.

    """
    if isinstance(meth, str) and not hasattr(TCP, f'_read_mptcp_{meth}'):
        raise RegistryError('method must be a MPTCP option parser function')

    TCP.register_mp_option(code, meth)
    logger.info('registered MPTCP option parser: %s', code.name)


###############################################################################
# pcapkit.protocols.transport.tcp.TCP.__proto__
###############################################################################


def register_tcp_port(code: 'int', module: str, class_: str) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The full qualified class name of the new protocol class
        should be as ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.transport.tcp.TCP.__proto__` registry.

    Arguments:
        code: port number
        module: module name
        class\_: class name

    """
    protocol = getattr(importlib.import_module(module), class_)
    if not issubclass(protocol, Protocol):
        raise RegistryError('protocol must be a Protocol subclass')

    TCP.register(code, module, class_)
    logger.info('registered TCP port: %s', code)

    # register protocol to protocol registry
    register_protocol(protocol)


###############################################################################
# pcapkit.protocols.transport.udp.UDP.__proto__
###############################################################################


def register_udp_port(code: 'int', module: str, class_: str) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The full qualified class name of the new protocol class
        should be as ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.transport.udp.UDP.__proto__` registry.

    Arguments:
        code: port number
        module: module name
        class\_: class name

    """
    protocol = getattr(importlib.import_module(module), class_)
    if not issubclass(protocol, Protocol):
        raise RegistryError('protocol must be a Protocol subclass')

    UDP.register(code, module, class_)
    logger.info('registered UDP port: %s', code)

    # register protocol to protocol registry
    register_protocol(protocol)


###############################################################################
# Combinations
###############################################################################


def register_output(format: 'str', module: 'str', class_: 'str', ext: 'str') -> 'None':  # pylint: disable=redefined-builtin
    r"""registered a new dumper class.

    Notes:
        The full qualified class name of the new dumper class
        should be as ``{module}.{class_}``.

    The function will register the given dumper class to the
    :data:`pcapkit.foundation.traceflow.TraceFlow.__output__` and
    :data:`pcapkit.foundation.extraction.Extractor.__output__` registry.

    See Also:
        * :func:`pcapkit.foundation.registry.register_extractor`
        * :func:`pcapkit.foundation.registry.register_traceflow`

    Arguments:
        format: format name
        module: module name
        class\_: class name
        ext: file extension

    """
    dumper = getattr(importlib.import_module(module), class_)
    if not issubclass(dumper, Dumper):
        raise RegistryError('dumper must be a Dumper subclass')

    Extractor.register(format, module, class_, ext)
    TraceFlow.register(format, module, class_, ext)
    logger.info('registered output format: %s', dumper.__name__)


def register_linktype(code: 'LinkType', module: str, class_: str) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The full qualified class name of the new protocol class
        should be as ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.misc.pcap.frame.Frame.__proto__` registry.

    See Also:
        * :func:`pcapkit.foundation.registry.register_pcap`

    Arguments:
        code: protocol code as in :class:`~pcapkit.const.reg.linktype.LinkType`
        module: module name
        class\_: class name

    """
    protocol = getattr(importlib.import_module(module), class_)
    if not issubclass(protocol, Protocol):
        raise RegistryError('protocol must be a Protocol subclass')

    Frame.register(code, module, class_)
    logger.info('registered linktype protocol: %s', code.name)

    # register protocol to protocol registry
    register_protocol(protocol)


def register_port(proto: 'Literal["tcp", "udp"]', code: 'int', module: str, class_: str) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The full qualified class name of the new protocol class
        should be as ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.transport.tcp.TCP.__proto__` and/or
    :data:`pcapkit.protocols.transport.udp.UDP.__proto__` registry.

    See Also:
        * :func:`pcapkit.foundation.registry.register_tcp_port`
        * :func:`pcapkit.foundation.registry.register_udp_port`

    Arguments:
        proto: protocol name (must be ``tcp`` or ``udp``)
        code: port number
        module: module name
        class\_: class name

    """
    if proto == 'tcp':
        cls = TCP
    elif proto == 'udp':
        cls = UDP  # type: ignore[assignment]
    else:
        raise RegistryError('protocol must be "tcp" or "udp"')

    protocol = getattr(importlib.import_module(module), class_)
    if not issubclass(protocol, Protocol):
        raise RegistryError('protocol must be a Protocol subclass')

    cls.register(code, module, class_)
    logger.info('registered %s port: %s', proto.upper(), code)

    # register protocol to protocol registry
    register_protocol(protocol)
