# -*- coding: utf-8 -*-
"""Protocol Registries
=========================

.. module:: pcapkit.foundation.registry.protocols

This module provides the protocol registries for :mod:`pcapkit`.

"""
import collections.abc
import enum
from typing import TYPE_CHECKING, cast, overload

import aenum

from pcapkit.const.reg.apptype import AppType as Enum_AppType
from pcapkit.const.reg.apptype import TransportProtocol
from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.const.sctp.payload_protocol_identifier import \
    PayloadProtocolIdentifier as Enum_PayloadProtocolIdentifier
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
from pcapkit.protocols.transport.sctp import SCTP
from pcapkit.protocols.transport.tcp import TCP
from pcapkit.protocols.transport.udp import UDP
from pcapkit.utilities.exceptions import RegistryError
from pcapkit.utilities.logging import get_logger
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from typing import Any, Iterator, Optional, Type

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
    from pcapkit.const.sctp.payload_protocol_identifier import \
        PayloadProtocolIdentifier as SCTP_PayloadProtocolIdentifier
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
    'register_protocol_code',

    'register_linktype',
    'register_pcap', 'register_pcapng',

    'register_ethertype',

    'register_transtype',
    'register_ipv4_option', 'register_hip_parameter', 'register_hopopt_option',
    'register_ipv6_opts_option', 'register_ipv6_route_routing',
    'register_mh_message', 'register_mh_option', 'register_mh_extension',

    'register_apptype',
    'register_tcp', 'register_udp', 'register_sctp',
    'register_tcp_option', 'register_tcp_mp_option',

    'register_http_frame',

    'register_pcapng_block', 'register_pcapng_option', 'register_pcapng_secrets',
    'register_pcapng_record',
]

#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)

NULL = '(null)'


# NOTE: pcapkit.protocols.__proto__
def register_protocol(protocol: 'Type[Protocol]') -> 'None':
    """Registered protocol class.

    The protocol class must be a subclass of
    :class:`~pcapkit.protocols.protocol.Protocol`, and will be registered to
    the :data:`pcapkit.protocols.__proto__` registry.

    The registry is keyed on ``protocol.__name__.upper()``, which is **not**
    unique across this package: three dispatchable protocol classes are all
    named ``HTTP`` -- the generic base
    :class:`pcapkit.protocols.application.http.HTTP` and the two version
    implementations :class:`pcapkit.protocols.application.httpv1.HTTP` and
    :class:`pcapkit.protocols.application.httpv2.HTTP` -- so all three compete
    for the single key ``'HTTP'``. Registering one of them replaces whichever
    was there, and the replacement is observable through every reader of the
    registry, e.g. :meth:`ProtocolBase.expand_comp
    <pcapkit.protocols.protocol.ProtocolBase.expand_comp>`, which resolves a
    bare protocol name through it.

    Per #675 the overwrite is now reported rather than silent, matching
    :meth:`ProtocolBase.register
    <pcapkit.protocols.protocol.ProtocolBase.register>` and the other
    overwrite-warning registries.

    The guard here reads "key present **and** incumbent is a different
    class" -- presence alone is not enough. This registry's key is *derived*
    from the class rather than supplied by a caller, and this function is the
    funnel every wrapper registrar calls -- :func:`register_tcp`,
    :func:`register_udp`, :func:`register_apptype`, :func:`register_linktype`
    and the rest all end in ``register_protocol(module)``. So registering one
    class under two codes, a supported and documented thing to do, reaches
    this function twice with the same class and nothing at stake; a
    presence-only guard would warn about an overwrite that overwrote nothing.
    Warning on the harmless case is not free: it is what teaches a caller to
    filter :exc:`~pcapkit.utilities.warnings.RegistryWarning` wholesale, and
    that filter is what would then hide the ``HTTP`` collision this warning
    exists to surface. The sibling ``register`` methods across the package --
    each keyed on a caller-supplied ``code`` rather than a name derived from
    the class -- apply the same identity criterion as of GitHub issue #718;
    before that they warned on presence alone, and none of them does now.

    Making the key itself unique would resolve the collision rather than
    merely reporting it, but it is a registry-format change that the bare-name
    readers outside this module cannot absorb on their own -- the registry is a
    documented public attribute, and its readers look a bare name up and then
    degrade *silently* on a miss rather than raising, so a re-keying would not
    announce itself either. :meth:`ProtocolBase.expand_comp
    <pcapkit.protocols.protocol.ProtocolBase.expand_comp>` falls back to the
    name as a plain string, and the ``protocol`` properties on
    :class:`~pcapkit.foundation.reassembly.reassembly.ReassemblyMeta` and
    :class:`~pcapkit.foundation.traceflow.traceflow.TraceFlowMeta` fall back to
    :class:`~pcapkit.protocols.misc.raw.Raw`. Re-keying is therefore part of the
    registry redesign in #514, and reporting the collision here is the step that
    redesign is sequenced behind.

    Args:
        protocol: Protocol class.

    Raises:
        pcapkit.utilities.exceptions.RegistryError: If ``protocol`` is not a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass.

    Warns:
        pcapkit.utilities.warnings.RegistryWarning: If the registry already
            holds a *different* class under this protocol's name, i.e. the
            registration displaced another protocol class. Re-registering the
            same class under the same name is silent.

    """
    if not issubclass(protocol, Protocol):
        raise RegistryError(f'protocol must be a Protocol subclass, not {protocol!r}')

    name = protocol.__name__.upper()
    incumbent = protocol_registry.get(name)
    if incumbent is not None and incumbent is not protocol:
        incumbent_repr, protocol_repr = repr(incumbent), repr(protocol)
        if incumbent_repr == protocol_repr:
            # #710: two *distinct* objects whose repr() -- for an ordinary
            # class, its module plus qualname -- happens to coincide, e.g. a
            # factory that builds a fresh closure-local class of the same
            # name on every call. Appending __module__/__qualname__ would not
            # help here: that is exactly what the coinciding repr() already
            # renders, so both sides would still print identically. id() is
            # the fallback that actually differs, so it is only added in this
            # branch -- the common case, two genuinely different classes,
            # keeps the plain repr() and stays free of the extra noise.
            incumbent_repr = f'{incumbent_repr} (id={id(incumbent):#x})'
            protocol_repr = f'{protocol_repr} (id={id(protocol):#x})'
        warn(f'protocol {name} already registered, overwriting {incumbent_repr} '
             f'with {protocol_repr}', RegistryWarning)

    protocol_registry[name] = protocol
    logger.debug('registered protocol: %s', protocol.__name__)


#: Enum type -> the class(es) owning the :attr:`ProtocolBase.__proto__
#: <pcapkit.protocols.protocol.ProtocolBase.__proto__>` dispatch registry
#: keyed by that enum type -- the "registry-of-registries" that lets
#: ``code=`` infer a destination from a key's own type, per #514. This is
#: not an invention: it is exactly the targeting
#: :func:`register_ethertype`, :func:`register_transtype`,
#: :func:`register_linktype` and :func:`register_sctp` already hard-code by
#: hand, moved into one table so :func:`register_protocol_code` can consult
#: it. ``LinkType`` naming two classes is deliberate, not ambiguous --
#: :func:`register_linktype` already fans out to both.
_CODE_DESTINATIONS: 'dict[type, tuple[Type[Protocol], ...]]' = {
    Enum_EtherType: (Link,),
    Enum_TransType: (Internet,),
    Enum_PayloadProtocolIdentifier: (SCTP,),
    Enum_LinkType: (Frame, PCAPNG),
}


def _iter_code_targets(code: 'Any') -> 'Iterator[tuple[Type[Protocol], Any]]':
    """Flatten a ``code=`` argument into ``(destination, key)`` pairs.

    Args:
        code: See :func:`register_protocol_code`.

    Yields:
        One ``(destination, key)`` pair per registration the caller asked
        for -- possibly several, e.g. a single :class:`~pcapkit.const.reg.\
linktype.LinkType` member yields both :class:`Frame` and :class:`PCAPNG`.

    Raises:
        RegistryError: If a value has no destination it can name or infer;
            see :func:`register_protocol_code`.

    """
    if isinstance(code, dict):
        yield from code.items()
        return

    if isinstance(code, (enum.Enum, aenum.Enum)):
        destinations = _CODE_DESTINATIONS.get(type(code))
        if destinations is None:
            raise RegistryError(
                f'no destination registry is known for enum type {type(code).__name__!r} '
                f'(key {code!r}); pass an explicit destination, e.g. code={{SomeClass: {code!r}}}')
        for destination in destinations:
            yield destination, code
        return

    if isinstance(code, (str, bytes)):
        raise RegistryError(f'code must be an enum member, a {{destination: key}} mapping, or an '
                            f'iterable thereof, not {code!r}')

    if isinstance(code, collections.abc.Iterable):
        for item in code:
            yield from _iter_code_targets(item)
        return

    raise RegistryError(f'raw key {code!r} has no destination registry it can infer; pass an '
                        f'explicit destination, e.g. code={{TCP: {code!r}}}')


def register_protocol_code(protocol: 'Type[Protocol]', code: 'Any') -> 'None':
    r"""Register ``protocol`` into the next-layer dispatch registry (or
    registries) named by ``code``.

    This is what backs the ``code`` keyword of
    :meth:`ProtocolBase.__init_subclass__
    <pcapkit.protocols.protocol.ProtocolBase.__init_subclass__>`; it can also
    be called directly to register a class that declined at class-definition
    time.

    ``code`` is normalised into a flat sequence of targets, where each item
    is either:

    * an enum member, whose *type* is looked up in a small table mapping
      enum type to the class(es) owning the matching ``__proto__`` --
      :class:`~pcapkit.const.reg.ethertype.EtherType` to
      :class:`~pcapkit.protocols.link.link.Link`,
      :class:`~pcapkit.const.reg.transtype.TransType` to
      :class:`~pcapkit.protocols.internet.internet.Internet`,
      :class:`~pcapkit.const.sctp.payload_protocol_identifier.PayloadProtocolIdentifier`
      to :class:`~pcapkit.protocols.transport.sctp.SCTP`, and
      :class:`~pcapkit.const.reg.linktype.LinkType` to *both*
      :class:`~pcapkit.protocols.misc.pcap.frame.Frame` **and**
      :class:`~pcapkit.protocols.misc.pcapng.PCAPNG`; or
    * a :class:`dict` mapping an explicit destination class to a key -- the
      only form accepted for a bare :class:`int`, since e.g. a port number
      does not say by itself whether it means
      :class:`~pcapkit.protocols.transport.tcp.TCP` or
      :class:`~pcapkit.protocols.transport.udp.UDP`;

    or an iterable of either, to register ``protocol`` into several
    registries from one call -- e.g. a
    :class:`~pcapkit.protocols.link.l2tp.L2TP` subclass reachable both by its
    IP protocol number and by a UDP port:

    .. code-block:: python

       register_protocol_code(L2TPv3, [TransType.L2TP, {UDP: 1701}])

    The explicit mapping form is accepted for any key, even one whose type
    could be inferred -- being more explicit than required is never an
    error.

    Note:
        That example names ``L2TPv3``, which this package does not implement
        yet, rather than :class:`~pcapkit.protocols.link.l2tpv2.L2TPv2`. It is
        v3 that is genuinely reachable both ways: :rfc:`3931` §4.1.1 puts it
        directly over IP on protocol 115 and §4.1.2 puts it over UDP on port
        1701. :class:`L2TPv2 <pcapkit.protocols.link.l2tpv2.L2TPv2>` answers on
        port 1701 only, and registering *it* at ``TransType.L2TP`` would point
        the :rfc:`2661` parser at a v3-over-IP header -- see
        :class:`~pcapkit.protocols.link.l2tp.L2TP` and GitHub issue #548 for
        what that produced when measured.

    Args:
        protocol: Protocol class to register.
        code: Registration key(s); see above.

    Raises:
        RegistryError: If a bare :class:`int` (or any other non-enum, non-
            mapping value) is given without an explicit destination, or if
            an enum member's type names no known destination registry --
            inference refuses rather than guesses.

    """
    for destination, key in _iter_code_targets(code):
        destination.register(key, protocol)
        logger.debug('registered %s into %s.__proto__: %s', protocol.__name__,
                     destination.__name__, key)


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
    logger.debug('registered linktype protocol: %s', code.name)

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
    logger.debug('registered PCAP linktype protocol: %s', code.name)

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
    logger.debug('registered PCAP-NG linktype protocol: %s', code.name)

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
    logger.debug('registered ethertype protocol: %s', code.name)

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
    logger.debug('registered transtype protocol: %s', code.name)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    register_protocol(module)


# NOTE: pcapkit.protocols.internet.ipv4.IPv4.__option__
def register_ipv4_option(code: 'IPv4_OptionNumber', meth: 'str | tuple[IPv4_OptionParser, IPv4_OptionConstructor]', *,
                         schema: 'Optional[Type[Schema_IPv4_Option]]' = None) -> 'None':
    """Register an option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.internet.ipv4.IPv4.__option__` registry.

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
    logger.debug('registered IPv4 option parser: %s', code.name)


# NOTE: pcapkit.protocols.internet.hip.HIP.__parameter__
def register_hip_parameter(code: 'HIP_Parameter', meth: 'str | tuple[HIP_ParameterParser, HIP_ParameterConstructor]', *,
                           schema: 'Optional[Type[Schema_HIP_Parameter]]' = None) -> 'None':
    """Register a parameter parser.

    The function will register the given parameter parser to the
    :data:`pcapkit.protocols.internet.hip.HIP.__parameter__` registry.

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
        meth: Method name or callable to parse and/or construct the option.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the option.
            It should be a subclass of :class:`pcapkit.protocols.schema.internet.hopopt.Option`.

    """
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
        meth: Method name or callable to parse and/or construct the option.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the option.
            It should be a subclass of :class:`pcapkit.protocols.schema.internet.ipv6_opts.Option`.

    """
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
        meth: Method name or callable to parse and/or construct the data.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the routing data.
            It should be a subclass of :class:`pcapkit.protocols.schema.internet.ipv6_route.RoutingType`.

    """
    if isinstance(meth, str) and not hasattr(IPv6_Route, f'_read_data_type_{meth}'):
        raise RegistryError('method must be a valid IPv6-Route routing data parser function')

    IPv6_Route.register_routing(code, meth)
    if schema is not None:
        Schema_IPv6_Route_RoutingType.register(code, schema)
    logger.debug('registered IPv6-Route routing data parser: %s', code.name)


# NOTE: pcapkit.protocols.internet.mh.MH.__message__
def register_mh_message(code: 'MH_Packet', meth: 'str | tuple[MH_PacketParser, MH_PacketConstructor]', *,
                        schema: 'Optional[Type[Schema_MH_Packet]]' = None) -> 'None':
    """Register a MH message type parser.

    The function will register the given message type parser to the
    :data:`pcapkit.protocols.internet.mh.MH.__message__` registry.

    Args:
        code: :class:`~pcapkit.protocols.internet.mh.MH`
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
    logger.debug('registered MH message type parser: %s', code.name)


# NOTE: pcapkit.protocols.internet.mh.MH.__option__
def register_mh_option(code: 'MH_Option', meth: 'str | tuple[MH_OptionParser, MH_OptionConstructor]', *,
                       schema: 'Optional[Type[Schema_MH_Option]]' = None) -> 'None':
    """Register a MH option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.internet.mh.MH.__option__` registry.

    Args:
        code: :class:`~pcapkit.protocols.internet.mh.MH`
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
    logger.debug('registered MH option parser: %s', code.name)


# NOTE: pcapkit.protocols.internet.mh.MH.__extension__
def register_mh_extension(code: 'MH_CGAExtension', meth: 'str | tuple[MH_ExtensionParser, MH_ExtensionConstructor]', *,
                          schema: 'Optional[Type[Schema_MH_CGAExtension]]' = None) -> 'None':
    """Register a CGA extension parser.

    The function will register the given CGA extension to the
    :data:`pcapkit.protocols.internet.mh.MH.__extension__` registry.

    Args:
        code: :class:`~pcapkit.protocols.internet.mh.MH`
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
    logger.debug('registered MH CGA extension: %s', code.name)


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

    Important:
        :class:`~pcapkit.protocols.transport.sctp.SCTP` is deliberately **not**
        part of this fan-out, even for application types that name ``sctp`` in
        their :class:`~pcapkit.const.reg.apptype.TransportProtocol`. Its
        :data:`~pcapkit.protocols.transport.sctp.SCTP.__proto__` registry is
        keyed by the DATA chunk's payload protocol identifier rather than by
        port number, so writing a port number into it would dispatch on a
        number from the wrong registry. Use
        :func:`pcapkit.foundation.registry.register_sctp` instead.

    See Also:
        * :func:`pcapkit.foundation.registry.register_tcp`
        * :func:`pcapkit.foundation.registry.register_udp`
        * :func:`pcapkit.foundation.registry.register_sctp`

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
        logger.debug('registered %s port: %s', test.name, code)
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
    logger.debug('registered TCP port: %s', code)

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
    logger.debug('registered TCP option parser: %s', code.name)


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
    logger.debug('registered MPTCP option parser: %s', code.name)


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
    logger.debug('registered UDP port: %s', code)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    register_protocol(module)


@overload
def register_sctp(code: 'int | SCTP_PayloadProtocolIdentifier', module: 'ModuleDescriptor[Protocol] | Type[Protocol]') -> 'None': ...
@overload
def register_sctp(code: 'int | SCTP_PayloadProtocolIdentifier', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.protocols.transport.sctp.SCTP.__proto__
def register_sctp(code: 'int | SCTP_PayloadProtocolIdentifier', module: 'str | ModuleDescriptor[Protocol] | Type[Protocol]',
                  class_: 'str' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The full qualified class name of the new protocol class
        should be as ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.transport.sctp.SCTP.__proto__` registry.

    Arguments:
        code: payload protocol identifier (PPID), as in
            :class:`~pcapkit.const.sctp.payload_protocol_identifier.PayloadProtocolIdentifier`
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.Protocol` subclass
        class\_: class name

    Important:
        Unlike :func:`register_tcp` and :func:`register_udp`, ``code`` is a
        *payload protocol identifier* taken from the DATA chunk, **not** a port
        number: SCTP names its upper layer per DATA chunk rather than per
        association. See :rfc:`9260#section-3.3.1`.

    """
    if isinstance(module, str):
        module = cast('ModuleDescriptor[Protocol]', ModuleDescriptor(module, class_))

    SCTP.register(code, module)
    logger.debug('registered SCTP payload protocol identifier: %s', code)

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
    logger.debug('registered HTTP/2 frame parser: %s', code.name)


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
    logger.debug('registered PCAP-NG block parser: %s', code.name)


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
    logger.debug('registered PCAP-NG option parser: %s', code.name)


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
    logger.debug('registered PCAP-NG name resolution record parser: %s', code.name)


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
    logger.debug('registered PCAP-NG decryption secrets parser: %s', code.name)
