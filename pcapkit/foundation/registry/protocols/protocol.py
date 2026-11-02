# -*- coding: utf-8 -*-
"""Protocol Base Registries
==============================

.. module:: pcapkit.foundation.registry.protocols.protocol

This module provides the protocol registries the per-layer modules beside it
build on: :func:`register_protocol` for the by-name registry
:data:`pcapkit.protocols.__proto__`, :func:`register_protocol_code` for the
next-layer registries a ``code`` names, and the validation and by-name
bookkeeping every registrar shares.

.. versionadded:: 1.6.0

   Moved here from the single :file:`pcapkit/foundation/registry/protocols.py`
   module. The :mod:`pcapkit.foundation.registry.protocols` package exports
   this module's public functions (:issue:`2578`).

"""
import collections.abc
import enum
import threading
from typing import TYPE_CHECKING

import aenum

from pcapkit.corekit.sentinels import MISSING
from pcapkit.protocols import __proto__ as protocol_registry
from pcapkit.protocols.protocol import ProtocolBase
from pcapkit.utilities.exceptions import RegistryError
from pcapkit.utilities.logging import get_logger
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from typing import Any, Iterator, Optional, Type

__all__ = [
    'register_protocol',
    'register_protocol_code',
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

    The registry is keyed on ``protocol.__name__.upper()``, which nothing makes
    unique: two protocol classes of the same name, such as a user's class
    named after a shipped one, compete for one key. Registering one of them
    replaces whichever was there, and the replacement is observable through
    every reader of the registry, e.g. :meth:`Protocol.expand_comp
    <pcapkit.protocols.protocol.Protocol.expand_comp>`, which resolves a
    bare protocol name through it. Per :issue:`675` the overwrite is reported,
    matching :meth:`Protocol.register
    <pcapkit.protocols.protocol.Protocol.register>` and the other
    overwrite-warning registries.

    The guard reads "key present **and** incumbent is a different class" --
    presence alone is not enough. This registry's key is *derived* from the
    class rather than supplied by a caller, and this function is the funnel
    every wrapper registrar calls --
    :func:`~pcapkit.foundation.registry.protocols.transport.register_tcp`,
    :func:`~pcapkit.foundation.registry.protocols.transport.register_udp`,
    :func:`~pcapkit.foundation.registry.protocols.transport.register_apptype`,
    :func:`~pcapkit.foundation.registry.protocols.misc.register_linktype` and
    the rest all end by calling it with their class, and registering their
    code back undoes that call's write (:issue:`1505`). So registering one class under two codes, a
    supported and documented thing to do, reaches this function twice with the
    same class and nothing at stake; a presence-only guard would warn about an
    overwrite that overwrote nothing. Warning on the harmless case is not free:
    it teaches a caller to filter
    :exc:`~pcapkit.utilities.warnings.RegistryWarning` wholesale, and that
    filter would then hide the name collision this warning exists to
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

    .. versionchanged:: 1.6.0

       The HTTP member classes are named
       :class:`~pcapkit.protocols.application.httpv1.HTTPv1` and
       :class:`~pcapkit.protocols.application.httpv2.HTTPv2`, so registering
       one keeps its own key and no longer displaces
       :class:`~pcapkit.protocols.application.http.HTTP` under ``'HTTP'``
       (:issue:`2529`).

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
        #: The entry it displaced, or :data:`~pcapkit.corekit.sentinels.MISSING` for a new name.
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
        if lease.displaced is MISSING:
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

        incumbent = protocol_registry.get(name, MISSING)
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
      to :class:`~pcapkit.protocols.transport.sctp.SCTP`,
      :class:`~pcapkit.const.linux.arphrd.ARPHRD` to
      :class:`~pcapkit.protocols.link.linux_sll.LinuxSLL`, and
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


def _check_code(code: 'Any', kind: 'Optional[type]', target: 'Type[ProtocolBase]', *,
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
        kind: Enum the registrar is typed on, or :data:`None` for a registry
            keyed by a number no enum names, which takes a bare :class:`int`
            only (:issue:`2511`).
        target: Protocol class whose registry ``code`` is destined for, named in
            the error message so a rejection says *whose* registry rejected the
            key rather than only what it wanted -- its callers share one
            message, and several of them are typed on the same enum.
        number: Whether a bare :class:`int` is a valid key too, as for the
            registrars keyed on a port number or a payload protocol identifier.
            Implied when ``kind`` is :data:`None`.

    Raises:
        RegistryError: If ``code`` is not a member of ``kind`` and, with
            ``number``, not an :class:`int` either. A member of another enum is
            rejected even where an :class:`int` is accepted, and so is a
            :class:`bool`, which would otherwise key ``0`` or ``1``
            (:issue:`2269`).

    """
    if kind is not None and isinstance(code, kind):
        return
    number = number or kind is None
    member = isinstance(code, (enum.Enum, aenum.Enum))
    if number and isinstance(code, int) and not isinstance(code, bool) and not member:
        return
    if kind is None:
        expected = 'an int'
    elif number:
        expected = f'an int or a member of {kind.__name__}'
    else:
        expected = f'a member of {kind.__name__}'
    if member:
        raise RegistryError(f'{target.__name__}: code must be {expected}, not a member of '
                            f'{type(code).__name__}: {code!r}')
    raise RegistryError(f'{target.__name__}: code must be {expected}, not {code!r}')
