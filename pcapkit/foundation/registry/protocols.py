# -*- coding: utf-8 -*-
"""Protocol Registries
=========================

.. module:: pcapkit.foundation.registry.protocols

This module provides the protocol registries for :mod:`pcapkit`.

.. versionchanged:: 1.5.0

   ``NULL``, the default of every ``class_`` argument here, is now the
   :data:`pcapkit.corekit.sentinels.NULL` sentinel; in 1.4.x it was the
   string ``'(null)'`` (:issue:`833`).

"""
import collections.abc
import enum
import threading
from typing import TYPE_CHECKING, cast, overload

import aenum

from pcapkit.const.hip.parameter import Parameter as HIP_Parameter
from pcapkit.const.http.frame import Frame as HTTP_Frame
from pcapkit.const.icmp.type import Type as ICMPv4_Type
from pcapkit.const.icmpv6.type import Type as ICMPv6_Type
from pcapkit.const.ipv4.option_number import OptionNumber as IPv4_OptionNumber
from pcapkit.const.ipv6.option import Option as IPv6_Option
from pcapkit.const.ipv6.routing import Routing as IPv6_Routing
from pcapkit.const.ipx.packet import Packet as IPX_Packet
from pcapkit.const.mh.cga_extension import CGAExtension as MH_CGAExtension
from pcapkit.const.mh.option import Option as MH_Option
from pcapkit.const.mh.packet import Packet as MH_Packet
from pcapkit.const.pcapng.block_type import BlockType as PCAPNG_BlockType
from pcapkit.const.pcapng.option_type import OptionType as PCAPNG_OptionType
from pcapkit.const.pcapng.record_type import RecordType as PCAPNG_RecordType
from pcapkit.const.pcapng.secrets_type import SecretsType as PCAPNG_SecretsType
from pcapkit.const.reg.apptype import AppType as Enum_AppType
from pcapkit.const.reg.apptype import TransportProtocol
from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.const.sctp.cause_code import CauseCode as SCTP_CauseCode
from pcapkit.const.sctp.chunk import Chunk as SCTP_Chunk
from pcapkit.const.sctp.parameter import Parameter as SCTP_Parameter
from pcapkit.const.sctp.payload_protocol_identifier import \
    PayloadProtocolIdentifier as Enum_PayloadProtocolIdentifier
from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as TCP_MPTCPOption
from pcapkit.const.tcp.option import Option as TCP_Option
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.sentinels import NULL
from pcapkit.protocols import __proto__ as protocol_registry
from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
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
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.misc.pcap.frame import Frame
from pcapkit.protocols.misc.pcapng import PCAPNG
from pcapkit.protocols.protocol import ProtocolBase
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
from pcapkit.protocols.schema.transport.sctp import Chunk as Schema_SCTP_Chunk
from pcapkit.protocols.schema.transport.sctp import ErrorCause as Schema_SCTP_ErrorCause
from pcapkit.protocols.schema.transport.sctp import Parameter as Schema_SCTP_Parameter
from pcapkit.protocols.schema.transport.tcp import MPTCP as Schema_TCP_MPTCP
from pcapkit.protocols.schema.transport.tcp import Option as Schema_TCP_Option
from pcapkit.protocols.transport.sctp import SCTP
from pcapkit.protocols.transport.tcp import TCP
from pcapkit.protocols.transport.udp import UDP
from pcapkit.utilities.exceptions import RegistryError
from pcapkit.utilities.logging import get_logger
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from typing import Any, Callable, Iterator, Optional, Type

    from pcapkit.const.reg.ethertype import EtherType
    from pcapkit.const.reg.linktype import LinkType
    from pcapkit.const.reg.transtype import TransType
    from pcapkit.const.sctp.payload_protocol_identifier import \
        PayloadProtocolIdentifier as SCTP_PayloadProtocolIdentifier
    from pcapkit.corekit.sentinels import NullType
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
    from pcapkit.protocols.transport.sctp import CauseConstructor as SCTP_CauseConstructor
    from pcapkit.protocols.transport.sctp import CauseParser as SCTP_CauseParser
    from pcapkit.protocols.transport.sctp import ChunkConstructor as SCTP_ChunkConstructor
    from pcapkit.protocols.transport.sctp import ChunkParser as SCTP_ChunkParser
    from pcapkit.protocols.transport.sctp import ParameterConstructor as SCTP_ParameterConstructor
    from pcapkit.protocols.transport.sctp import ParameterParser as SCTP_ParameterParser
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
    'register_ipx',
    'register_icmp_type',
    'register_ipv4_option', 'register_hip_parameter', 'register_hopopt_option',
    'register_ipv6_opts_option', 'register_ipv6_route_routing',
    'register_mh_message', 'register_mh_option', 'register_mh_extension',

    'register_apptype',
    'register_tcp', 'register_udp', 'register_sctp',
    'register_tcp_option', 'register_tcp_mp_option',
    'register_sctp_chunk', 'register_sctp_parameter', 'register_sctp_cause',

    'register_http_frame',

    'register_pcapng_block', 'register_pcapng_option', 'register_pcapng_secrets',
    'register_pcapng_record',
]

#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)


# NOTE: pcapkit.protocols.__proto__
def register_protocol(protocol: 'Type[ProtocolBase]') -> 'None':
    """Register a protocol class.

    The protocol class must be a subclass of
    :class:`~pcapkit.protocols.protocol.ProtocolBase`, and will be registered to
    the :data:`pcapkit.protocols.__proto__` registry.

    The registry is keyed on ``protocol.__name__.upper()``, which is **not**
    unique across this package: several dispatchable protocol classes are
    named ``HTTP`` -- the generic base
    :class:`pcapkit.protocols.application.http.HTTP` and the version
    implementations :class:`pcapkit.protocols.application.httpv1.HTTP` and
    :class:`pcapkit.protocols.application.httpv2.HTTP` -- so they all compete
    for the single key ``'HTTP'``. Registering one of them replaces whichever
    was there, and the replacement is observable through every reader of the
    registry, e.g. :meth:`Protocol.expand_comp
    <pcapkit.protocols.protocol.Protocol.expand_comp>`, which resolves a
    bare protocol name through it. Per :issue:`675` the overwrite is reported,
    matching :meth:`Protocol.register
    <pcapkit.protocols.protocol.Protocol.register>` and the other
    overwrite-warning registries.

    The guard reads "key present **and** incumbent is a different class" --
    presence alone is not enough. This registry's key is *derived* from the
    class rather than supplied by a caller, and this function is the funnel
    every wrapper registrar calls -- :func:`register_tcp`, :func:`register_udp`,
    :func:`register_apptype`, :func:`register_linktype` and the rest all end by
    calling it with their class, and registering their code back undoes that
    call's write (:issue:`1505`). So registering one class under two codes, a
    supported and documented thing to do, reaches this function twice with the
    same class and nothing at stake; a presence-only guard would warn about an
    overwrite that overwrote nothing. Warning on the harmless case is not free:
    it teaches a caller to filter
    :exc:`~pcapkit.utilities.warnings.RegistryWarning` wholesale, and that
    filter would then hide the ``HTTP`` collision this warning exists to
    surface. The sibling ``register`` methods across the package, each keyed on a
    caller-supplied ``code``, apply the same identity criterion (:issue:`718`).

    Making the key itself unique would resolve the collision rather than
    merely reporting it, but it is a registry-format change that the bare-name
    readers outside this module cannot absorb on their own -- the registry is a
    documented public attribute, and its readers look a bare name up and then
    degrade *silently* on a miss rather than raising, so a re-keying would not
    announce itself either. :meth:`Protocol.expand_comp
    <pcapkit.protocols.protocol.Protocol.expand_comp>` falls back to the
    name as a plain string, and the ``protocol`` properties on
    :class:`~pcapkit.foundation.reassembly.reassembly.ReassemblyMeta` and
    :class:`~pcapkit.foundation.traceflow.traceflow.TraceFlowMeta` fall back to
    :class:`~pcapkit.protocols.misc.raw.Raw`. The registry redesign of
    :issue:`514` keeps this key, and its thread records the shared namespace as
    a risk that design does not resolve, so the collision is reported here
    rather than fixed.

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
    if not isinstance(protocol, type):
        raise RegistryError(f'protocol must be a class, not {protocol!r}')
    if not issubclass(protocol, ProtocolBase):
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


#: Sentinel for a name :data:`pcapkit.protocols.__proto__` did not hold.
_MISSING = object()


class _NameLease:
    """A :data:`pcapkit.protocols.__proto__` entry a code registration put there.

    Each code registrar below ends by naming its class in the by-name registry,
    and :mod:`pcapkit.foundation.registry` has no ``unregister``: a code is
    undone by registering the entry it displaced (:issue:`1363`). Without a
    record of that by-name write, handing a code back would restore the code and
    leave the name behind (:issue:`1505`). A lease records what the write
    displaced and which codes still dispatch to the class, so the last of them
    to be handed back puts the displaced entry back, or removes the name if it
    was new.

    A lease is one write, not one class: the same class can hold two leases on
    a name -- e.g. a built-in registered at one port over a custom class
    shadowing it at another -- and each undoes only its own write.

    """

    __slots__ = ('name', 'protocol', 'displaced', 'codes')

    def __init__(self, name: 'str', protocol: 'Type[ProtocolBase]', displaced: 'Any') -> 'None':
        #: The key written in :data:`pcapkit.protocols.__proto__`.
        self.name = name
        #: The class written under it.
        self.protocol = protocol
        #: The entry it displaced, or :data:`_MISSING` for a new name.
        self.displaced = displaced
        #: ``(destination, code)`` registrations still holding the lease.
        self.codes = set()  # type: set[tuple[type, Any]]


#: Name -> its leases, oldest first. Each lease displaced the one below it,
#: unless the name was written by other means in between; the last is the one
#: a lookup sees, unless the name has been written since.
_NAME_LEASES = {}  # type: dict[str, list[_NameLease]]
#: ``(destination, code)`` -> the lease its registration holds.
_CODE_LEASES = {}  # type: dict[tuple[type, Any], _NameLease]
#: Serialises the lease tables above, so concurrent registrars cannot tear them.
_LEASE_LOCK = threading.RLock()


def _fold_lease(stack: 'list[_NameLease]', index: 'int') -> 'None':
    """Retire ``stack[index]``, a lease now displacing its own class.

    That happens once the lease between it and an earlier write of the same
    class is handed back, e.g. a custom ``IPv4`` released from under the
    built-in ``IPv4`` registered over it. Undoing it would change nothing, so
    its codes move to the lease below when that is the same class, and
    otherwise -- the class was named by other means -- hold nothing.

    Args:
        stack: The name's leases, oldest first.
        index: Position of the lease to retire.

    """
    lease = stack.pop(index)
    below = stack[index - 1] if index > 0 else None
    if below is not None and below.protocol is not lease.protocol:
        below = None
    for target in lease.codes:
        if _CODE_LEASES.get(target) is not lease:
            continue
        if below is None:
            del _CODE_LEASES[target]
        else:
            below.codes.add(target)
            _CODE_LEASES[target] = below


def _release_name(target: 'tuple[type, Any]') -> 'None':
    """Hand back the lease ``target``'s registration held.

    Once no code holds the lease, it leaves its name's stack. On top, it puts
    the name back to the entry it displaced, or removes a new name -- unless the
    name was written by other means since, in which case that write stands.
    Buried, it hands what it displaced to the lease above, if that lease
    displaced it.

    Args:
        target: The ``(destination, code)`` being registered over.

    """
    lease = _CODE_LEASES.pop(target, None)
    if lease is None:
        return
    lease.codes.discard(target)
    if lease.codes:
        return

    stack = _NAME_LEASES.get(lease.name, [])
    index = next((i for i, item in enumerate(stack) if item is lease), None)
    if index is None:
        return
    del stack[index]
    if index < len(stack):
        above = stack[index]
        if above.displaced is lease.protocol:
            above.displaced = lease.displaced
            if above.displaced is above.protocol:
                _fold_lease(stack, index)
    elif protocol_registry.get(lease.name) is lease.protocol:
        if lease.displaced is _MISSING:
            protocol_registry.pop(lease.name, None)
        else:
            protocol_registry[lease.name] = lease.displaced
        logger.debug('released protocol: %s', lease.protocol.__name__)
    if not stack:
        _NAME_LEASES.pop(lease.name, None)


def _register_name(protocol: 'Type[ProtocolBase]', *targets: 'tuple[type, Any]') -> 'None':
    """Name ``protocol`` in :data:`pcapkit.protocols.__proto__` for ``targets``.

    The tail of every code registrar: :func:`register_protocol`, preceded by
    releasing whatever each target code held before, and followed by a lease
    when the write changed the name, so that registering the code back undoes
    it (:issue:`1505`). A name already showing ``protocol`` -- shipped, defined
    by a :class:`~pcapkit.protocols.protocol.Protocol` subclass, or
    registered directly -- is not leased, so no restore takes it away; one
    showing it through a lease extends that lease to ``targets``.

    Args:
        protocol: Protocol class just registered -- and so validated -- at ``targets``.
        *targets: The ``(destination, code)`` pairs it was registered at.

    """
    name = protocol.__name__.upper()
    with _LEASE_LOCK:
        stack = _NAME_LEASES.get(name)
        if stack and stack[-1].protocol is protocol and protocol_registry.get(name) is protocol:
            current = stack[-1]  # type: Optional[_NameLease]
        else:
            current = None
        for target in targets:
            if current is None or _CODE_LEASES.get(target) is not current:
                _release_name(target)

        incumbent = protocol_registry.get(name, _MISSING)
        register_protocol(protocol)
        if protocol_registry.get(name) is not protocol:
            return

        stack = _NAME_LEASES.get(name)
        if incumbent is not protocol:
            lease = _NameLease(name, protocol, incumbent)
            _NAME_LEASES.setdefault(name, []).append(lease)
        elif stack and stack[-1].protocol is protocol:
            lease = stack[-1]
        else:
            return
        lease.codes.update(targets)
        for target in targets:
            _CODE_LEASES[target] = lease


def _iter_code_targets(code: 'Any') -> 'Iterator[tuple[Type[ProtocolBase], Any]]':
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
        # NOTE: read with ``getattr``, not out of the type's own ``vars()`` as
        # the ``__proto_key__`` check in ``register_protocol_code`` does. That
        # read is deliberately non-inheriting because a protocol subclass can
        # own a registry keyed by something other than its parent's -- Loopback
        # does. No enum registry can be in that position: declaring a
        # destination means having members, and aenum refuses to extend an
        # enumeration with members, so none of these registries has a subclass
        # and none can gain one. The one enum registry that is subclassed is
        # AppType, a memberless base partitioned by transport protocol, and its
        # subclass relationship is irrelevant here only because AppType itself
        # declares no ``__proto_dest__`` at all -- the inheriting read finds
        # nothing to inherit, so none of its parts reaches this branch. A
        # class-level destination would in fact be the wrong model for it:
        # ``register_apptype`` routes each member to the registry named by that
        # member's own transport protocol, which one shared destination for the
        # whole family could not express.
        destinations = getattr(type(code), '__proto_dest__', None)
        if not destinations:
            raise RegistryError(
                f'no destination registry is known for enum type {type(code).__name__!r} '
                f'(key {code!r}); pass an explicit destination, e.g. code={{SomeClass: {code!r}}}')
        for descriptor in destinations:
            yield descriptor.klass, code
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


def register_protocol_code(protocol: 'Type[ProtocolBase]', code: 'Any') -> 'None':
    r"""Register ``protocol`` into the next-layer dispatch registry (or
    registries) named by ``code``.

    This is what backs the ``code`` class keyword of
    :class:`~pcapkit.protocols.protocol.ProtocolBase` subclasses; it can also
    be called directly to register a class that declined at class-definition
    time.

    ``code`` is normalised into a flat sequence of targets, where each item
    is either:

    * an enum member, whose *type* names the class(es) owning the matching
      ``__proto__`` in its
      :attr:`__proto_dest__ <pcapkit.const.reg.ethertype.EtherType.__proto_dest__>` --
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
        That example names ``L2TPv3``, which this package does not implement,
        rather than :class:`~pcapkit.protocols.link.l2tpv2.L2TPv2`. It is
        v3 that is genuinely reachable both ways: :rfc:`3931` §4.1.1 puts it
        directly over IP on protocol 115 and §4.1.2 puts it over UDP on port
        1701. :class:`L2TPv2 <pcapkit.protocols.link.l2tpv2.L2TPv2>` answers on
        port 1701 only, and registering *it* at
        :attr:`TransType.L2TP <pcapkit.const.reg.transtype.TransType.L2TP>` would point the
        :rfc:`2661` parser at a v3-over-IP header -- see :class:`~pcapkit.protocols.link.l2tp.L2TP`
        and GitHub issue :issue:`548` for what that produced when measured.

    Args:
        protocol: Protocol class to register.
        code: Registration key(s); see above.

    Raises:
        RegistryError: If a bare :class:`int` (or any other non-enum,
            non-mapping value) is given without an explicit destination, or if
            an enum member's type declares no
            :attr:`__proto_dest__ <pcapkit.const.reg.ethertype.EtherType.__proto_dest__>` --
            inference refuses rather than guesses; or if a key is not of the
            type its destination's registry is keyed by, as its typed registrar
            would reject it, e.g. ``{Frame: TransType.ICMP}``. What a registry is
            keyed by is read from the
            :attr:`__proto_key__ <pcapkit.protocols.link.link.Link.__proto_key__>`
            declared by the class owning it, so a destination sharing another's
            registry is checked as its owner is, and one whose owner declares no
            pairing is not checked. Every target is checked before any is
            registered, so a rejected ``code`` leaves every registry as it was
            (:issue:`2268`).

    """
    targets = list(_iter_code_targets(code))
    for destination, key in targets:
        owner = next((klass for klass in getattr(destination, '__mro__', ())
                      if '__proto__' in vars(klass)), None)
        if owner is None:
            continue

        # NOTE: the pairing is read out of the owner's own ``vars()`` rather than
        # with ``getattr``, which walks the MRO and would hand a class keeping a
        # registry of its own its parent's pairing --
        # :attr:`Loopback.__proto__ <pcapkit.protocols.link.loopback.Loopback.__proto__>`
        # is keyed by address family rather than by EtherType, so inheriting
        # :class:`Link`'s would reject every key it does accept. A class is
        # checked against the registry it owns, or not at all.
        pairing = vars(owner).get('__proto_key__')
        if pairing is not None:
            kind, number = pairing
            _check_code(key, kind, owner, number=number)

    for destination, key in targets:
        destination.register(key, protocol)
        logger.debug('registered %s into %s.__proto__: %s', protocol.__name__,
                     destination.__name__, key)


def _check_code(code: 'Any', kind: 'type', target: 'Type[ProtocolBase]', *,
                number: 'bool' = False) -> 'None':
    """Reject a registration key that is not a member of the enum its
    destination registry is keyed by.

    Each registrar typed on one enum calls this before touching any registry,
    as does :func:`register_protocol_code` for an inferred or explicitly
    named destination, so a bad ``code`` leaves every registry as it was
    (:issue:`2186`). The check is on the type, not the value: the registry
    enums compare equal to their values, so a member of another enum would
    key the entry of the member it equals, e.g.
    :attr:`TransType.ICMP <pcapkit.const.reg.transtype.TransType.ICMP>` would
    replace :attr:`LinkType.ETHERNET <pcapkit.const.reg.linktype.LinkType.ETHERNET>`
    (:issue:`2224`).

    Args:
        code: Registration key handed to the registrar.
        kind: Enum the registrar is typed on.
        target: Protocol class whose registry ``code`` is destined for, named in
            the error message so a rejection says *whose* registry rejected the
            key rather than only what it wanted -- its callers share one
            message, and several of them are typed on the same enum.
        number: Whether a bare :class:`int` is a valid key too, as for the
            registrars keyed on a port number or a payload protocol identifier.

    Raises:
        RegistryError: If ``code`` is not a member of ``kind`` and, with
            ``number``, not an :class:`int` either. A member of another enum is
            rejected even where an :class:`int` is accepted, and so is a
            :class:`bool`, which would otherwise key ``0`` or ``1``
            (:issue:`2269`).

    """
    if isinstance(code, kind):
        return
    member = isinstance(code, (enum.Enum, aenum.Enum))
    if number and isinstance(code, int) and not isinstance(code, bool) and not member:
        return
    expected = f'an int or a member of {kind.__name__}' if number else f'a member of {kind.__name__}'
    if member:
        raise RegistryError(f'{target.__name__}: code must be {expected}, not a member of '
                            f'{type(code).__name__}: {code!r}')
    raise RegistryError(f'{target.__name__}: code must be {expected}, not {code!r}')


###############################################################################
# Top-Level Registries
###############################################################################


@overload
def register_linktype(code: 'LinkType', module: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None': ...
@overload
def register_linktype(code: 'LinkType', module: 'str', class_: 'str') -> 'None': ...


def register_linktype(code: 'LinkType', module: 'str | ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]',
                      class_: 'str | NullType' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The fully qualified class name of the new protocol class
        should be ``{module}.{class_}``.

    The function will register the given protocol class to the
    following registries:

    - :data:`pcapkit.protocols.misc.pcap.frame.Frame.__proto__`
    - :data:`pcapkit.protocols.misc.pcapng.PCAPNG.__proto__`

    Arguments:
        code: protocol code as in :class:`~pcapkit.const.reg.linktype.LinkType`
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass
        class\_: class name

    See Also:
        * :func:`pcapkit.foundation.registry.protocols.register_pcap`
        * :func:`pcapkit.foundation.registry.protocols.register_pcapng`

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.reg.linktype.LinkType`
            member, e.g. a member of another enum, or ``module``
            is not a :class:`~pcapkit.protocols.protocol.ProtocolBase`
            subclass.

    """
    # NOTE: this writes into both Frame's and PCAP-NG's registries, which are
    # keyed alike, so the key check is the same for either and Frame names it.
    # :func:`register_pcap` and :func:`register_pcapng` name one each.
    _check_code(code, Enum_LinkType, Frame)
    if isinstance(module, str):
        module = cast('ModuleDescriptor[ProtocolBase]', ModuleDescriptor(module, class_))

    Frame.register(code, module)
    PCAPNG.register(code, module)
    logger.debug('registered linktype protocol: %s', code.name)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    _register_name(module, (Frame, code), (PCAPNG, code))


@overload
def register_pcap(code: 'LinkType', module: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None': ...
@overload
def register_pcap(code: 'LinkType', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.protocols.misc.pcap.frame.Frame.__proto__
def register_pcap(code: 'LinkType', module: 'str | ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]',
                  class_: 'str | NullType' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The fully qualified class name of the new protocol class
        should be ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.misc.pcap.frame.Frame.__proto__` registry.

    Arguments:
        code: protocol code as in :class:`~pcapkit.const.reg.linktype.LinkType`
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass
        class\_: class name

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.reg.linktype.LinkType`
            member, e.g. a member of another enum, or ``module``
            is not a :class:`~pcapkit.protocols.protocol.ProtocolBase`
            subclass.

    """
    _check_code(code, Enum_LinkType, Frame)
    if isinstance(module, str):
        module = cast('ModuleDescriptor[ProtocolBase]', ModuleDescriptor(module, class_))

    Frame.register(code, module)
    logger.debug('registered PCAP linktype protocol: %s', code.name)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    _register_name(module, (Frame, code))


@overload
def register_pcapng(code: 'LinkType', module: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None': ...
@overload
def register_pcapng(code: 'LinkType', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.protocols.misc.pcapng.PCAPNG.__proto__
def register_pcapng(code: 'LinkType', module: 'str | ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]',
                    class_: 'str | NullType' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The fully qualified class name of the new protocol class
        should be ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.misc.pcapng.PCAPNG.__proto__` registry.

    Arguments:
        code: protocol code as in :class:`~pcapkit.const.reg.linktype.LinkType`
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass
        class\_: class name

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.reg.linktype.LinkType`
            member, e.g. a member of another enum, or ``module``
            is not a :class:`~pcapkit.protocols.protocol.ProtocolBase`
            subclass.

    """
    _check_code(code, Enum_LinkType, PCAPNG)
    if isinstance(module, str):
        module = cast('ModuleDescriptor[ProtocolBase]', ModuleDescriptor(module, class_))

    PCAPNG.register(code, module)
    logger.debug('registered PCAP-NG linktype protocol: %s', code.name)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    _register_name(module, (PCAPNG, code))


###############################################################################
# Link Layer Registries
###############################################################################


@overload
def register_ethertype(code: 'EtherType', module: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None': ...
@overload
def register_ethertype(code: 'EtherType', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.protocols.link.link.Link.__proto__
def register_ethertype(code: 'EtherType', module: 'str | ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]',
                       class_: 'str | NullType' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The fully qualified class name of the new protocol class
        should be ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.link.link.Link.__proto__` registry.

    Arguments:
        code: protocol code as in :class:`~pcapkit.const.reg.ethertype.EtherType`
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass
        class\_: class name

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.reg.ethertype.EtherType`
            member, e.g. a member of another enum, or ``module``
            is not a :class:`~pcapkit.protocols.protocol.ProtocolBase`
            subclass.

    """
    _check_code(code, Enum_EtherType, Link)  # type: ignore[type-abstract]
    if isinstance(module, str):
        module = cast('ModuleDescriptor[ProtocolBase]', ModuleDescriptor(module, class_))

    Link.register(code, module)
    logger.debug('registered ethertype protocol: %s', code.name)

    # register protocol to protocol registry
    if isinstance(module, ModuleDescriptor):
        module = module.klass
    _register_name(module, (Link, code))


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
def register_ipx(code: 'IPX_Packet', module: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None': ...
@overload
def register_ipx(code: 'IPX_Packet', module: 'str', class_: 'str') -> 'None': ...


# NOTE: pcapkit.protocols.internet.ipx.IPX.__proto__
def register_ipx(code: 'IPX_Packet', module: 'str | ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]',
                 class_: 'str | NullType' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The fully qualified class name of the new protocol class
        should be ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.internet.ipx.IPX.__proto__` registry.

    Arguments:
        code: IPX Packet Type as in :class:`~pcapkit.const.ipx.packet.Packet`
        module: module name or module descriptor or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass
        class\_: class name

    Important:
        Unlike :func:`register_transtype`, ``code`` is an IPX Packet Type, **not**
        an IP protocol number: :class:`~pcapkit.protocols.internet.ipx.IPX`
        keeps a registry of its own (:issue:`2169`).

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.ipx.packet.Packet`
            member, e.g. a :class:`~pcapkit.const.reg.transtype.TransType`
            member, or ``module`` is not a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass.

    .. versionadded:: 1.6.0

    """
    _check_code(code, IPX_Packet, IPX)
    if isinstance(module, str):
        module = cast('ModuleDescriptor[ProtocolBase]', ModuleDescriptor(module, class_))

    IPX.register(code, module)
    logger.debug('registered IPX packet type protocol: %s', code.name)

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
    :data:`pcapkit.protocols.transport.tcp.TCP.__proto__` and/or
    :data:`pcapkit.protocols.transport.udp.UDP.__proto__` registry.

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
        :class:`~pcapkit.protocols.transport.sctp.SCTP` is deliberately **not**
        one of the registries this writes to, so naming ``sctp`` here is an error
        rather than a no-op. Its
        :data:`~pcapkit.protocols.transport.sctp.SCTP.__proto__` registry is
        keyed by the DATA chunk's payload protocol identifier rather than by
        port number, so writing a port number into it would dispatch on a
        number from the wrong registry. Use
        :func:`pcapkit.foundation.registry.protocols.register_sctp` instead.

    See Also:
        * :func:`pcapkit.foundation.registry.protocols.register_tcp`
        * :func:`pcapkit.foundation.registry.protocols.register_udp`
        * :func:`pcapkit.foundation.registry.protocols.register_sctp`

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


# NOTE: pcapkit.protocols.transport.tcp.TCP.__proto__
def register_tcp(code: 'int | Enum_AppType', module: 'str | ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]',
                 class_: 'str | NullType' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The fully qualified class name of the new protocol class
        should be ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.transport.tcp.TCP.__proto__` registry.

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


# NOTE: pcapkit.protocols.transport.tcp.TCP.__option__
def register_tcp_option(code: 'TCP_Option', meth: 'str | tuple[TCP_OptionParser, TCP_OptionConstructor]', *,
                        schema: 'Optional[Type[Schema_TCP_Option]]' = None) -> 'None':
    """Register an option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.transport.tcp.TCP.__option__` registry.

    Args:
        code: :class:`~pcapkit.protocols.transport.tcp.TCP` option code as in
            :class:`~pcapkit.const.tcp.option.Option`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the option. A name names the
            ``_read_mode_*`` and ``_make_mode_*`` methods, and has to name
            an existing ``_read_mode_*`` one.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the option.
            It should be a subclass of :class:`pcapkit.protocols.schema.transport.tcp.Option`.

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


# NOTE: pcapkit.protocols.transport.tcp.TCP.__mp_option__
def register_tcp_mp_option(code: 'TCP_MPTCPOption', meth: 'str | tuple[TCP_MPOptionParser, TCP_MPOptionConstructor]', *,
                           schema: 'Optional[Type[Schema_TCP_MPTCP]]' = None) -> 'None':
    """Register an MPTCP option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.transport.tcp.TCP.__mp_option__` registry.

    Args:
        code: Multipath :class:`~pcapkit.protocols.transport.tcp.TCP` option code as in
            :class:`~pcapkit.const.tcp.mp_tcp_option.MPTCPOption`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the option. A name names the
            ``_read_mptcp_*`` and ``_make_mptcp_*`` methods, and has to name
            an existing ``_read_mptcp_*`` one.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the option.
            It should be a subclass of :class:`pcapkit.protocols.schema.transport.tcp.MPTCP`.

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


# NOTE: pcapkit.protocols.transport.udp.UDP.__proto__
def register_udp(code: 'int | Enum_AppType', module: 'str | ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]',
                 class_: 'str | NullType' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The fully qualified class name of the new protocol class
        should be ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.transport.udp.UDP.__proto__` registry.

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


# NOTE: pcapkit.protocols.transport.sctp.SCTP.__proto__
def register_sctp(code: 'int | SCTP_PayloadProtocolIdentifier', module: 'str | ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]',
                  class_: 'str | NullType' = NULL) -> 'None':
    r"""Register a new protocol class.

    Notes:
        The fully qualified class name of the new protocol class
        should be ``{module}.{class_}``.

    The function will register the given protocol class to the
    :data:`pcapkit.protocols.transport.sctp.SCTP.__proto__` registry.

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


# NOTE: pcapkit.protocols.transport.sctp.SCTP.__chunk__
def register_sctp_chunk(code: 'SCTP_Chunk', meth: 'str | tuple[SCTP_ChunkParser, SCTP_ChunkConstructor]', *,
                        schema: 'Optional[Type[Schema_SCTP_Chunk]]' = None) -> 'None':
    """Register a chunk parser.

    The function will register the given chunk parser to the
    :data:`pcapkit.protocols.transport.sctp.SCTP.__chunk__` registry.

    Args:
        code: :class:`~pcapkit.protocols.transport.sctp.SCTP` chunk type as in
            :class:`~pcapkit.const.sctp.chunk.Chunk`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the chunk. A name names the
            ``_read_chunk_*`` and ``_make_chunk_*`` methods, and has to name
            an existing ``_read_chunk_*`` one.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the chunk.
            It should be a subclass of :class:`pcapkit.protocols.schema.transport.sctp.Chunk`.

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


# NOTE: pcapkit.protocols.transport.sctp.SCTP.__parameter__
def register_sctp_parameter(code: 'SCTP_Parameter',
                            meth: 'str | tuple[SCTP_ParameterParser, SCTP_ParameterConstructor]', *,
                            schema: 'Optional[Type[Schema_SCTP_Parameter]]' = None) -> 'None':
    """Register a chunk parameter parser.

    The function will register the given chunk parameter parser to the
    :data:`pcapkit.protocols.transport.sctp.SCTP.__parameter__` registry.

    Args:
        code: :class:`~pcapkit.protocols.transport.sctp.SCTP` chunk parameter type
            as in :class:`~pcapkit.const.sctp.parameter.Parameter`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the parameter. A name names the
            ``_read_param_*`` and ``_make_param_*`` methods, and has to name
            an existing ``_read_param_*`` one.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the parameter.
            It should be a subclass of :class:`pcapkit.protocols.schema.transport.sctp.Parameter`.

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


# NOTE: pcapkit.protocols.transport.sctp.SCTP.__cause__
def register_sctp_cause(code: 'SCTP_CauseCode', meth: 'str | tuple[SCTP_CauseParser, SCTP_CauseConstructor]', *,
                        schema: 'Optional[Type[Schema_SCTP_ErrorCause]]' = None) -> 'None':
    """Register an error cause parser.

    The function will register the given error cause parser to the
    :data:`pcapkit.protocols.transport.sctp.SCTP.__cause__` registry.

    Args:
        code: :class:`~pcapkit.protocols.transport.sctp.SCTP` error cause code as
            in :class:`~pcapkit.const.sctp.cause_code.CauseCode`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the cause. A name names the
            ``_read_cause_*`` and ``_make_cause_*`` methods, and has to name
            an existing ``_read_cause_*`` one.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the cause.
            It should be a subclass of :class:`pcapkit.protocols.schema.transport.sctp.ErrorCause`.

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


###############################################################################
# Application Layer Registries
###############################################################################


# NOTE: pcapkit.protocols.application.httpv2.HTTP.__frame__
def register_http_frame(code: 'HTTP_Frame', meth: 'str | tuple[HTTP_FrameParser, HTTP_FrameConstructor]', *,
                        schema: 'Optional[Type[Schema_HTTP_FrameType]]' = None) -> 'None':
    """Register a frame parser.

    The function will register the given frame parser to the
    :data:`pcapkit.protocols.application.httpv2.HTTP.__frame__` registry.

    Args:
        code: :class:`HTTP/2 <pcapkit.protocols.application.httpv2.HTTP>` frame type
            code as in :class:`~pcapkit.const.http.frame.Frame`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the frame. A name names the
            ``_read_http_*`` and ``_make_http_*`` methods, and has to name
            an existing ``_read_http_*`` one.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the frame.
            It should be a subclass of :class:`pcapkit.protocols.schema.application.httpv2.FrameType`.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.http.frame.Frame`
            member, e.g. a member of another enum, or ``meth``
            is a name with no matching ``_read_http_*`` method.

    """
    _check_code(code, HTTP_Frame, HTTPv2)
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
    """Register a block parser.

    The function will register the given block parser to the
    :data:`pcapkit.protocols.misc.pcapng.PCAPNG.__block__` registry.

    Args:
        code: :class:`PCAPNG <pcapkit.protocols.misc.pcapng.PCAPNG>` block type
            code as in :class:`~pcapkit.const.pcapng.block_type.BlockType`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the block. A name names the
            ``_read_block_*`` and ``_make_block_*`` methods, and has to name
            an existing ``_read_block_*`` one.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the block.
            It should be a subclass of :class:`pcapkit.protocols.schema.misc.pcapng.BlockType`.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.pcapng.block_type.BlockType`
            member, e.g. a member of another enum, or ``meth``
            is a name with no matching ``_read_block_*`` method.

    """
    _check_code(code, PCAPNG_BlockType, PCAPNG)
    if isinstance(meth, str) and not hasattr(PCAPNG, f'_read_block_{meth}'):
        raise RegistryError('method must be a block parser function')

    PCAPNG.register_block(code, meth)
    if schema is not None:
        Schema_PCAPNG_BlockType.register(code, schema)
    logger.debug('registered PCAP-NG block parser: %s', code.name)


# NOTE: pcapkit.protocols.misc.pcapng.PCAPNG.__option__
def register_pcapng_option(code: 'PCAPNG_OptionType', meth: 'str | tuple[PCAPNG_OptionParser, PCAPNG_OptionConstructor]', *,
                           schema: 'Optional[Type[Schema_PCAPNG_Option]]' = None) -> 'None':
    """Register an option parser.

    The function will register the given option parser to the
    :data:`pcapkit.protocols.misc.pcapng.PCAPNG.__option__` registry.

    Args:
        code: :class:`PCAPNG <pcapkit.protocols.misc.pcapng.PCAPNG>` option type
            code as in :class:`~pcapkit.const.pcapng.option_type.OptionType`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the option. A name names the
            ``_read_option_*`` and ``_make_option_*`` methods, and has to name
            an existing ``_read_option_*`` one.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the option.
            It should be a subclass of :class:`pcapkit.protocols.schema.misc.pcapng.Option`.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.pcapng.option_type.OptionType`
            member, e.g. a member of another enum, or ``meth``
            is a name with no matching ``_read_option_*`` method.

    """
    _check_code(code, PCAPNG_OptionType, PCAPNG)
    if isinstance(meth, str) and not hasattr(PCAPNG, f'_read_option_{meth}'):
        raise RegistryError('method must be a option parser function')

    PCAPNG.register_option(code, meth)
    if schema is not None:
        Schema_PCAPNG_Option.register(code, schema)
    logger.debug('registered PCAP-NG option parser: %s', code.name)


# NOTE: pcapkit.protocols.misc.pcapng.PCAPNG.__record__
def register_pcapng_record(code: 'PCAPNG_RecordType', meth: 'str | tuple[PCAPNG_RecordParser, PCAPNG_RecordConstructor]', *,
                           schema: 'Optional[Type[Schema_PCAPNG_NameResolutionRecord]]' = None) -> 'None':
    """Register a name resolution record parser.

    The function will register the given name resolution record parser to the
    :data:`pcapkit.protocols.misc.pcapng.PCAPNG.__record__` registry.

    Args:
        code: :class:`PCAPNG <pcapkit.protocols.misc.pcapng.PCAPNG>` name
            resolution record type code as in :class:`~pcapkit.const.pcapng.record_type.RecordType`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the name resolution record. A name names the
            ``_read_record_*`` and ``_make_record_*`` methods, and has to name
            an existing ``_read_record_*`` one.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the name resolution record.
            It should be a subclass of :class:`pcapkit.protocols.schema.misc.pcapng.NameResolutionRecord`.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.pcapng.record_type.RecordType`
            member, e.g. a member of another enum, or ``meth``
            is a name with no matching ``_read_record_*`` method.

    """
    _check_code(code, PCAPNG_RecordType, PCAPNG)
    if isinstance(meth, str) and not hasattr(PCAPNG, f'_read_record_{meth}'):
        raise RegistryError('method must be a name resolution record parser function')

    PCAPNG.register_record(code, meth)
    if schema is not None:
        Schema_PCAPNG_NameResolutionRecord.register(code, schema)
    logger.debug('registered PCAP-NG name resolution record parser: %s', code.name)


# NOTE: pcapkit.protocols.misc.pcapng.PCAPNG.__secrets__
def register_pcapng_secrets(code: 'PCAPNG_SecretsType', meth: 'str | tuple[PCAPNG_SecretsParser, PCAPNG_SecretsConstructor]', *,
                            schema: 'Optional[Type[Schema_PCAPNG_DSBSecrets]]' = None) -> 'None':
    """Register a decryption secrets parser.

    The function will register the given decryption secrets parser to the
    :data:`pcapkit.protocols.misc.pcapng.PCAPNG.__secrets__` registry.

    Args:
        code: :class:`PCAPNG <pcapkit.protocols.misc.pcapng.PCAPNG>` decryption
            secrets type code as in :class:`~pcapkit.const.pcapng.secrets_type.SecretsType`.
        meth: Method name, or a ``(parser, constructor)`` pair of callables, to
            parse and construct the decryption secrets. A name names the
            ``_read_secrets_*`` and ``_make_secrets_*`` methods, and has to name
            an existing ``_read_secrets_*`` one.
        schema: :class:`~pcapkit.protocols.schema.schema.Schema` class for the decryption secrets.
            It should be a subclass of :class:`pcapkit.protocols.schema.misc.pcapng.DSBSecrets`.

    Raises:
        RegistryError: If ``code`` is not a :class:`~pcapkit.const.pcapng.secrets_type.SecretsType`
            member, e.g. a member of another enum, or ``meth``
            is a name with no matching ``_read_secrets_*`` method.

    """
    _check_code(code, PCAPNG_SecretsType, PCAPNG)
    if isinstance(meth, str) and not hasattr(PCAPNG, f'_read_secrets_{meth}'):
        raise RegistryError('method must be a decryption secrets parser function')

    PCAPNG.register_secrets(code, meth)
    if schema is not None:
        Schema_PCAPNG_DSBSecrets.register(code, schema)
    logger.debug('registered PCAP-NG decryption secrets parser: %s', code.name)
