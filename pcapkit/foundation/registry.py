# -*- coding: utf-8 -*-
"""Registry Management
=========================

.. module:: pcapkit.foundation.registry

This module provides the registry management for :mod:`pcapkit`, as the module
contains various registry points.

"""
import importlib
from typing import TYPE_CHECKING

from dictdumper import Dumper

from pcapkit.foundation.engines import Engine
from pcapkit.foundation.extraction import Extractor
from pcapkit.foundation.traceflow import TraceFlow
from pcapkit.protocols import __proto__ as protocol_registry
from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
from pcapkit.protocols.internet.hip import HIP
from pcapkit.protocols.internet.hopopt import HOPOPT
from pcapkit.protocols.internet.internet import Internet
from pcapkit.protocols.internet.ipv4 import IPv4
from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
from pcapkit.protocols.internet.ipv6_route import IPv6_Route
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.misc.pcap.frame import Frame
from pcapkit.protocols.misc.pcapng import PCAPNG
from pcapkit.protocols.protocol import Protocol
from pcapkit.protocols.transport.tcp import TCP
from pcapkit.protocols.transport.udp import UDP
from pcapkit.utilities.exceptions import RegistryError
from pcapkit.utilities.logging import logger

if TYPE_CHECKING:
    from typing import Type

    from typing_extensions import Literal

    from pcapkit.const.hip.parameter import Parameter as HIP_Parameter
    from pcapkit.const.http.frame import Frame as HTTP_Frame
    from pcapkit.const.ipv4.option_number import OptionNumber as IPv4_OptionNumber
    from pcapkit.const.ipv6.option import Option as IPv6_Option
    from pcapkit.const.ipv6.routing import Routing as IPv6_Routing
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

    'register_linktype', 'register_pcap', 'register_pcapng',
    'register_ethertype', 'register_transtype',
    'register_port', 'register_tcp_port', 'register_udp_port',

    'register_output',
    'register_extractor_dumper', 'register_extractor_engine',
    'register_traceflow',

    'register_pcapng_block', 'register_pcapng_option', 'register_pcapng_secrets',
    'register_pcapng_record',
    'register_hopopt', 'register_ipv6_opts', 'register_ipv6_route',
    'register_ipv4', 'register_hip',
    'register_tcp', 'register_mptcp',
    'register_http',
]

###############################################################################
# pcapkit.protocols.Protocol
###############################################################################


def register_protocol(protocol: 'Type[Protocol]') -> 'None':
    """Registered protocol class.

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
# pcapkit.foundation.extraction.Extractor
###############################################################################


def register_extractor_dumper(format: 'str', module: 'str', class_: 'str', ext: 'str') -> 'None':  # pylint: disable=redefined-builtin
    r"""Registered a new dumper class.

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

    Extractor.register_dumper(format, module, class_, ext)
    logger.info('registered extractor output dumper: %s', format)


def register_extractor_engine(engine: 'str', module: 'str', class_: 'str') -> 'None':  # pylint: disable=redefined-builtin
    r"""Registered a new engine class.

    Notes:
        The full qualified class name of the new engine class
        should be as ``{module}.{class_}``.

    The function will register the given engine class to the
    :data:`pcapkit.foundation.extraction.Extractor.__engine__` registry.

    Arguments:
        engine: engine name
        module: module name
        class\_: class name

    """
    engine_cls = getattr(importlib.import_module(module), class_)
    if not issubclass(engine_cls, Engine):
        raise RegistryError('engine must be a Engine subclass')

    Extractor.register_engine(engine, module, class_)
    logger.info('registered extractor engine: %s', engine)


###############################################################################
# pcapkit.foundation.traceflow.TraceFlow
###############################################################################


def register_traceflow(format: 'str', module: 'str', class_: 'str', ext: 'str') -> 'None':  # pylint: disable=redefined-builtin
    r"""Registered a new dumper class.

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
# pcapkit.protocols.application.httpv2.HTTPv2
###############################################################################


def register_http(code: 'HTTP_Frame', meth: 'str | tuple[HTTP_FrameParser, HTTP_FrameConstructor]') -> 'None':
    """Registered a frame parser.

    The function will register the given frame parser to the
    :data:`pcapkit.protocols.application.httpv2.HTTPv2.__frame__` registry.

    Args:
        code: :class:`HTTP/2 <pcapkit.protocols.application.httpv2.HTTPv2>` frame type
            code as in :class:`~pcapkit.const.http.frame.Frame`.
        meth: Method name or callable to parse and/or construct the frame.

    """
    if isinstance(meth, str) and not hasattr(HTTPv2, f'_read_http_{meth}'):
        raise RegistryError('method must be a frame parser function')

    HTTPv2.register_frame(code, meth)
    logger.info('registered HTTP/2 frame parser: %s', code.name)


###############################################################################
# pcapkit.protocols.internet.hip.HIP
###############################################################################


def register_hip(code: 'HIP_Parameter', meth: 'str | tuple[HIP_ParameterParser, HIP_ParameterConstructor]') -> 'None':
    """Register a parameter parser.

    The function will register the given parameter parser to the
    :data:`pcapkit.protocols.internet.hip.HIP` internal registry.

    Args:
        code: :class:`~pcapkit.protocols.internet.hip.HIP` parameter code as
            in :class:`~pcapkit.const.hip.parameter.Parameter`.
        meth: Method name or callable to parse and/or construct the parameter.

    """
    if isinstance(meth, str) and not hasattr(HIP, f'_read_param_{meth}'):
        raise RegistryError('method must be a valid HIP parameter parser function')

    HIP.register_parameter(code, meth)
    logger.info('registered HIP parameter parser: %s', code.name)


###############################################################################
# pcapkit.protocols.internet.hopopt.HOPOPT
###############################################################################


def register_hopopt(code: 'IPv6_Option', meth: 'str | tuple[HOPOPT_OptionParser, HOPOPT_OptionConstructor]') -> 'None':
    """Register an option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.internet.hopopt.HOPOPT.__option__` registry.

    Args:
        code: :class:`~pcapkit.protocols.internet.hopopt.HOPOPT` option code as
            in :class:`~pcapkit.const.ipv6.option.Option`.
        meth: Method name or callable to parse and/or construct the option.

    """
    if isinstance(meth, str) and not hasattr(HOPOPT, f'_read_opt_{meth}'):
        raise RegistryError('method must be a valid HOPOPT option parser function')

    HOPOPT.register_option(code, meth)
    logger.info('registered HOPOPT option parser: %s', code.name)


###############################################################################
# pcapkit.protocols.internet.internet.Internet
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
# pcapkit.protocols.internet.internet.IPv4
###############################################################################


def register_ipv4(code: 'IPv4_OptionNumber', meth: 'str | tuple[IPv4_OptionParser, IPv4_OptionConstructor]') -> 'None':
    """Register an option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.internet.internet.IPv4` internal registry.

    Args:
        code: :class:`IPv4 <pcapkit.protocols.internet.internet.IPv4>` option code as
            in :class:`~pcapkit.const.ipv4.option_number.OptionNumber`.
        meth: Method name or callable to parse and/or construct the option.

    """
    if isinstance(meth, str) and not hasattr(IPv4, f'_read_opt_{meth}'):
        raise RegistryError('method must be a valid IPv4 option parser function')

    IPv4.register_option(code, meth)
    logger.info('registered IPv4 option parser: %s', code.name)


###############################################################################
# pcapkit.protocols.internet.ipv6_opts.IPv6_Opts
###############################################################################


def register_ipv6_opts(code: 'IPv6_Option', meth: 'str | tuple[IPv6_Opts_OptionParser, IPv6_Opts_OptionConstructor]') -> 'None':
    """Register an option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.internet.ipv6_opts.IPv6_Opts.__option__` registry.

    Args:
        code: :class:`IPv6-Opts <pcapkit.protocols.internet.ipv6_opts.IPv6_Opts>`
            option code as in :class:`~pcapkit.const.ipv6.option.Option`.
        meth: Method name or callable to parse and/or construct the option.

    """
    if isinstance(meth, str) and not hasattr(IPv6_Opts, f'_read_opt_{meth}'):
        raise RegistryError('method must be a valid IPv6-Opts option parser function')

    IPv6_Opts.register_option(code, meth)
    logger.info('registered IPv6_Opts option parser: %s', code.name)


###############################################################################
# pcapkit.protocols.internet.ipv6_route.IPv6_Route
###############################################################################


def register_ipv6_route(code: 'IPv6_Routing', meth: 'str | tuple[IPv6_Route_TypeParser, IPv6_Route_TypeConstructor]') -> 'None':
    r"""Register an routing data parser.

    The function will register the given routing data parser to the
    :data:`pcapkit.protocols.internet.ipv6_route.IPv6_Route.__routing__` registry.

    Args:
        code: :class:`IPv6-Route <pcapkit.protocols.internet.ipv6_route.IPv6_Route>`
            data type code as in :class:`~pcapkit.const.ipv6.routing.Routing`.
        meth: Method name or callable to parse and/or construct the data.

    """
    if isinstance(meth, str) and not hasattr(IPv6_Route, f'_read_data_type_{meth}'):
        raise RegistryError('method must be a valid IPv6-Route routing data parser function')

    IPv6_Route.register_routing(code, meth)
    logger.info('registered IPv6_Route routing data parser: %s', code.name)


###############################################################################
# pcapkit.protocols.link.link.Link
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
# pcapkit.protocols.misc.pcap.frame.Frame
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
    logger.info('registered PCAP linktype protocol: %s', code.name)

    # register protocol to protocol registry
    register_protocol(protocol)


###############################################################################
# pcapkit.protocols.misc.pcapng.PCAPNG
###############################################################################


def register_pcapng(code: 'LinkType', module: str, class_: str) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The full qualified class name of the new protocol class
        should be as ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.misc.pcapng.PCAPNG.__proto__` registry.

    Arguments:
        code: protocol code as in :class:`~pcapkit.const.reg.linktype.LinkType`
        module: module name
        class\_: class name

    """
    protocol = getattr(importlib.import_module(module), class_)
    if not issubclass(protocol, Protocol):
        raise RegistryError('protocol must be a Protocol subclass')

    PCAPNG.register(code, module, class_)
    logger.info('registered PCAP-NG linktype protocol: %s', code.name)

    # register protocol to protocol registry
    register_protocol(protocol)


def register_pcapng_block(code: 'PCAPNG_BlockType', meth: 'str | tuple[PCAPNG_BlockParser, PCAPNG_BlockConstructor]') -> 'None':
    """Registered a block parser.

    The function will register the given block parser to the
    :data:`pcapkit.protocols.misc.pcapng.PCAPNG.__block__` registry.

    Args:
        code: :class:`HTTP/2 <pcapkit.protocols.misc.pcapng.PCAPNG>` block type
            code as in :class:`~pcapkit.const.pcapng.block_type.BlockType`.
        meth: Method name or callable to parse and/or construct the block.

    """
    if isinstance(meth, str) and not hasattr(PCAPNG, f'_read_block_{meth}'):
        raise RegistryError('method must be a block parser function')

    PCAPNG.register_block(code, meth)
    logger.info('registered PCAP-NG block parser: %s', code.name)


def register_pcapng_option(code: 'PCAPNG_OptionType', meth: 'str | tuple[PCAPNG_OptionParser, PCAPNG_OptionConstructor]') -> 'None':
    """Registered a option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.misc.pcapng.PCAPNG.__option__` registry.

    Args:
        code: :class:`PCAPNG <pcapkit.protocols.misc.pcapng.PCAPNG>` option type
            code as in :class:`~pcapkit.const.pcapng.option_type.OptionType`.
        meth: Method name or callable to parse and/or construct the option.

    """
    if isinstance(meth, str) and not hasattr(PCAPNG, f'_read_option_{meth}'):
        raise RegistryError('method must be a option parser function')

    PCAPNG.register_option(code, meth)
    logger.info('registered PCAP-NG option parser: %s', code.name)


def register_pcapng_record(code: 'PCAPNG_RecordType', meth: 'str | tuple[PCAPNG_RecordParser, PCAPNG_RecordConstructor]') -> 'None':
    """Registered a name resolution record parser.

    The function will register the given name resolution record parser to the
    :data:`pcapkit.protocols.misc.pcapng.PCAPNG.__record__` registry.

    Args:
        code: :class:`PCAPNG <pcapkit.protocols.misc.pcapng.PCAPNG>` name
            resolution record type code as in :class:`~pcapkit.const.pcapng.record_type.RecordType`.
        meth: Method name or callable to parse and/or construct the name
            resolution record.

    """
    if isinstance(meth, str) and not hasattr(PCAPNG, f'_read_record_{meth}'):
        raise RegistryError('method must be a name resolution record parser function')

    PCAPNG.register_record(code, meth)
    logger.info('registered PCAP-NG name resolution record parser: %s', code.name)


def register_pcapng_secrets(code: 'PCAPNG_SecretsType', meth: 'str | tuple[PCAPNG_SecretsParser, PCAPNG_SecretsConstructor]') -> 'None':
    """Registered a decryption secrets parser.

    The function will register the given decryption secrets parser to the
    :data:`pcapkit.protocols.misc.pcapng.PCAPNG.__secrets__` registry.

    Args:
        code: :class:`PCAPNG <pcapkit.protocols.misc.pcapng.PCAPNG>` decryption
            secrets type code as in :class:`~pcapkit.const.pcapng.secrets_type.SecretsType`.
        meth: Method name or callable to parse and/or construct the decryption secrets.

    """
    if isinstance(meth, str) and not hasattr(PCAPNG, f'_read_secrets_{meth}'):
        raise RegistryError('method must be a decryption secrets parser function')

    PCAPNG.register_secrets(code, meth)
    logger.info('registered PCAP-NG decryption secrets parser: %s', code.name)


###############################################################################
# pcapkit.protocols.transport.tcp.TCP
###############################################################################


def register_tcp(code: 'TCP_Option', meth: 'str | tuple[TCP_OptionParser, TCP_OptionConstructor]') -> 'None':
    """Register an option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.transport.tcp.TCP.__option__` registry.

    Args:
        code: :class:`~pcapkit.protocols.transport.tcp.TCP` option code as in
            :class:`~pcapkit.const.tcp.option.Option`.
        meth: Method name or callable to parse and/or construct the option.

    """
    if isinstance(meth, str) and not hasattr(TCP, f'_read_mode_{meth}'):
        raise RegistryError('method must be a TCP option parser function')

    TCP.register_option(code, meth)
    logger.info('registered TCP option parser: %s', code.name)


def register_mptcp(code: 'TCP_MPTCPOption', meth: 'str | tuple[TCP_MPOptionParser, TCP_MPOptionConstructor]') -> 'None':
    """Register an MPTCP option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.transport.tcp.TCP.__mp_option__` registry.

    Args:
        code: Multipath :class:`~pcapkit.protocols.transport.tcp.TCP` option code as in
            :class:`~pcapkit.const.tcp.mp_tcp_option.MPTCPOption`.
        meth: Method name or callable to parse and/or construct the option.

    """
    if isinstance(meth, str) and not hasattr(TCP, f'_read_mptcp_{meth}'):
        raise RegistryError('method must be a MPTCP option parser function')

    TCP.register_mp_option(code, meth)
    logger.info('registered MPTCP option parser: %s', code.name)


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
# pcapkit.protocols.transport.udp.UDP
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
    r"""Registered a new dumper class.

    Notes:
        The full qualified class name of the new dumper class
        should be as ``{module}.{class_}``.

    The function will register the given dumper class to the
    :data:`pcapkit.foundation.traceflow.TraceFlow.__output__` and
    :data:`pcapkit.foundation.extraction.Extractor.__output__` registry.

    See Also:
        * :func:`pcapkit.foundation.registry.register_extractor_dumper`
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

    Extractor.register_dumper(format, module, class_, ext)
    TraceFlow.register(format, module, class_, ext)
    logger.info('registered output format: %s', dumper.__name__)


def register_linktype(code: 'LinkType', module: str, class_: str) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The full qualified class name of the new protocol class
        should be as ``{module}.{class_}``.

    The function will register the given protocol class to the
    following registries:

    - :data:`pcapkit.protocols.misc.pcap.frame.Frame.__proto__`
    - :data:`pcapkit.protocols.misc.pcapng.PCAPNG.__proto__`

    See Also:
        * :func:`pcapkit.foundation.registry.register_pcap`
        * :func:`pcapkit.foundation.registry.register_pcapng`

    Arguments:
        code: protocol code as in :class:`~pcapkit.const.reg.linktype.LinkType`
        module: module name
        class\_: class name

    """
    protocol = getattr(importlib.import_module(module), class_)
    if not issubclass(protocol, Protocol):
        raise RegistryError('protocol must be a Protocol subclass')

    Frame.register(code, module, class_)
    PCAPNG.register(code, module, class_)
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
