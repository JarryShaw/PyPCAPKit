# -*- coding: utf-8 -*-
"""Application Layer Protocol Numbers
========================================

.. module:: pcapkit.vendor.reg.apptype.apptype

This module contains the vendor crawler for **Application Layer Protocol Numbers**,
which is automatically generating :class:`pcapkit.const.reg.apptype.apptype.AppType`.

It also carries the machinery the four per-transport crawlers in this package
share -- the one pass over IANA's CSV that groups its rows, and the templates
that render them -- since all five read the same registry and differ only in
which rows they claim. See :class:`~pcapkit.vendor.reg.apptype.tcp.TCP` and its
siblings for those.

"""

import collections
import csv
import keyword
import re
import sys
import textwrap
from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info, info_final
from pcapkit.utilities.warnings import VendorRuntimeWarning, warn
from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter, OrderedDict
    from typing import Callable, Iterable, Optional

__all__ = ['AppType']

#: Transport protocols the registry is partitioned over, in the order
#: :class:`~pcapkit.const.reg.apptype.apptype.TransportProtocol` declares them.
#: A registry row naming none of these -- IANA leaves the column empty -- is not
#: an assignment to anything, so it is documented rather than declared.
TRANSPORTS = ('tcp', 'udp', 'sctp', 'dccp')

#: Per-process cache of the parsed registry, keyed by :attr:`Vendor.LINK`.
#:
#: The five crawlers in this package read one 1.1 MB CSV between them, and
#: :meth:`Vendor._request` is per-instance, so ``pcapkit-vendor`` would otherwise
#: fetch the same file from IANA five times in a row for a single run.
_CACHE = {}  # type: dict[str, list[str]]

#: The canonical service for each port IANA assigns more than one to, per
#: transport protocol, as ``{transport: {port: service name}}``.
#:
#: IANA genuinely registers three services on TCP/80 -- ``http``, ``www`` and
#: ``www-http`` -- and gives no precedence among them, so the registry cannot
#: derive which one a port lookup should answer with. Registry row order does not
#: supply it either: taken alone it answers 28 of these 44 pairs the way the rest
#: of the world does and 16 of them differently, giving ``l2f`` for 1701 and
#: ``shilp`` for 2049.
#:
#: So this follows the industry convention instead, taken from :file:`/etc/services`
#: -- the same answer :func:`socket.getservbyport` gives. Each entry is the first
#: name that file lists for the ``(port, transport)`` pair **that IANA also
#: registers there**: :file:`/etc/services` carries local names of its own, e.g.
#: ``jetdirect`` on 9100/tcp, and this registry is IANA's rather than the host's.
#:
#: Curated rather than read at crawl time on purpose: :file:`/etc/services` is not
#: present on every platform and differs between the ones that have it, so reading
#: it would make the generated modules depend on the machine that generated them.
#: A colliding port with no entry here warns and falls back to IANA's oldest row.
CANONICAL = {
    'tcp': {
        42: 'nameserver', 63: 'whois++', 80: 'http', 105: 'csnet-ns', 113: 'auth',
        351: 'matip-type-b', 352: 'dtag-ste-sb', 465: 'urd', 631: 'ipp', 666: 'mdqs',
        888: 'cddbp', 999: 'garcon', 1525: 'prospero-np', 1701: 'l2tp',
        1989: 'tr-rsrb-p3', 1992: 'stun-p3', 2049: 'nfs', 3000: 'hbci',
        3002: 'exlm-agent', 3478: 'stun', 4444: 'krb524', 5349: 'stuns',
        9100: 'hp-pdl-datastr',
    },
    'udp': {
        42: 'nameserver', 63: 'whois++', 80: 'http', 105: 'csnet-ns',
        351: 'matip-type-b', 352: 'dtag-ste-sb', 512: 'biff', 666: 'mdqs',
        750: 'kerberos-iv', 999: 'applix', 1525: 'prospero-np', 1701: 'l2tp',
        1989: 'tr-rsrb-p3', 1992: 'stun-p3', 2049: 'nfs', 3000: 'hbci',
        3002: 'exlm-agent', 3478: 'stun', 4444: 'krb524', 5349: 'stuns',
        9100: 'hp-pdl-datastr',
    },
    'sctp': {},
    'dccp': {},
}  # type: dict[str, dict[int, str]]

#: Template for the transport-agnostic base registry, i.e. the one module in this
#: package that carries :class:`~...TransportProtocol`, the member shape and the
#: lookup, and no members at all.
BASE = lambda NAME, DOCS, FLAG, TABLE, MISS, MODL: f'''\
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""{(name := DOCS.split(' [', maxsplit=1)[0])}
{'=' * (len(name) + 6)}

.. module:: {MODL.replace('vendor', 'const')}

This module contains the constant enumeration for **{name}**,
which is automatically generated from :class:`{MODL}.{NAME}`.

"""
import keyword
import re
from typing import TYPE_CHECKING, cast

from aenum import IntEnum, StrEnum, extend_enum

__all__ = ['TransportProtocol', '{NAME}']

if TYPE_CHECKING:
    from typing import Any, Optional, Type

    from pcapkit.corekit.multidict import MultiDict


class TransportProtocol(IntEnum):
    """Transport layer protocol."""

    # mypy has no aenum plugin, so this class is a plain class to it: every
    # member below is a literal int rather than an auto()-valued one -- GitHub
    # issue #808 dropped the IntFlag base, so auto() would number sequentially
    # instead of by the power-of-two spacing the values must keep -- and a
    # literal infers as int while the TransportProtocol annotations that use
    # each member (__transport__, and the proto default on __new__, get and
    # get_all) expect TransportProtocol. cast is the identity function at run
    # time, so this changes nothing that runs -- see GitHub issue #770, which
    # cast only this member while the rest still inferred Any from auto().
    # mypy.ini sets warn_redundant_casts, so if aenum ever ships type stubs
    # letting it infer TransportProtocol on its own, these casts start
    # erroring instead of lingering as dead scaffolding.
    #: No transport protocol. ``TransportProtocol(0) is undefined`` and
    #: ``bool(undefined)`` is ``False``; it is the ``proto`` sentinel default
    #: for ``__transport__``, ``__new__``, ``get`` and ``get_all``, and what
    #: the base registry's ``_missing_`` extends unassigned/reserved rows from.
    undefined = cast('TransportProtocol', 0)

    #: Transmission Control Protocol. Value fixed at ``1`` rather than
    #: renumbered sequentially -- GitHub issue #808 dropped the ``IntFlag``
    #: base once nothing built a composite, but did not revisit the four
    #: values themselves, which predate this class and are not its call to
    #: renumber.
    tcp = cast('TransportProtocol', 1)
    #: User Datagram Protocol. See ``tcp`` above for why the value stays ``2``
    #: rather than becoming sequential.
    udp = cast('TransportProtocol', 2)
    #: Stream Control Transmission Protocol. See ``tcp`` above for why the
    #: value stays ``4`` rather than becoming sequential.
    sctp = cast('TransportProtocol', 4)
    #: Datagram Congestion Control Protocol. See ``tcp`` above for why the
    #: value stays ``8`` rather than becoming sequential.
    dccp = cast('TransportProtocol', 8)

    @staticmethod
    def get(key: 'int | str') -> 'TransportProtocol':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.

        :meta private:
        """
        if isinstance(key, int):
            return TransportProtocol(key)
        if key.lower() in TransportProtocol.__members__:
            return TransportProtocol[key.lower()]  # type: ignore[misc]
        # NOTE: maintainer ruling on this PR (#836): "Do not allow extension
        # of TransportProtocol at all." A name that is not a declared member
        # used to mint a brand-new one here, at ``max_val + 1`` (before that,
        # ``max_val * 2``) -- an unbounded, ever-growing set of transport
        # protocols nothing ever asked for. There is nothing left to walk
        # now: it is simply refused, exactly like any other unrecognised
        # name -- including one spelling a composite, e.g. ``'tcp|udp'``.
        # ``'|'`` used to be intercepted here on its own, so a composite in
        # disguise never got minted into a member whose own name lied about
        # being a single transport; the owner's further ruling on this PR
        # retired that special case along with the rest of the composite
        # handling once TransportProtocol stopped being a Flag at all:
        # "since it's no longer a Flag, `|` joined values are no longer
        # parsed and accepted, we will treat it as a whole, instead of
        # splitting." A ``'|'``-joined name is therefore not special any
        # more -- it is simply not the name of a declared member, and gets
        # the same message as any other one that is not.
        raise ValueError(f'{{key!r}} is not a valid {{TransportProtocol.__name__}}')

    # NOTE: ``_missing_`` used to range-check ``value`` and then defer to
    # :mod:`aenum`'s own ``Flag._missing_``, which is what composed an
    # unrecognised bit combination into a pseudo-member -- ``TransportProtocol(3)``
    # returning ``tcp|udp`` -- GitHub issue #647's guard against that composing
    # *anything*, including values no member declares. GitHub issue #808 removed
    # the ``IntFlag`` base once nothing built a composite, and with it the only
    # reason this method existed: a plain :class:`~aenum.IntEnum` already raises
    # ``ValueError`` for a value no member declares, with no ``_missing_`` of
    # its own needed to get there, so declaring one here would only be
    # reproducing what the base class already does.


class {NAME}(StrEnum):
    """[{NAME}] {DOCS}

    This is the transport-agnostic base of the per-transport registries in
    :mod:`pcapkit.const.reg.apptype`, and it declares **no members of its own**.
    IANA keys every assignment on a ``(service, port, transport)`` triple, so a
    service belongs to the registry of the transport protocol that carries it --
    :class:`~pcapkit.const.reg.apptype.tcp.TCP`,
    :class:`~pcapkit.const.reg.apptype.udp.UDP`,
    :class:`~pcapkit.const.reg.apptype.sctp.SCTP` or
    :class:`~pcapkit.const.reg.apptype.dccp.DCCP`. Being memberless is also what
    makes it subclassable at all, since :mod:`aenum` refuses to extend an
    enumeration that already has members.

    Note:
        The rows below are the registry entries whose **transport protocol column
        is empty**. A blank transport is not an assignment to anything, so there
        is no registry they could be members of and they are documented here
        instead. Most are historic service or IP-protocol names with no port
        either; the rest are IANA's own reserved, unassigned and withdrawn
        markers.

    {TABLE}

    """

    if TYPE_CHECKING:
        #: Service name.
        svc: 'str'
        #: Port number.
        port: 'int'
        #: Transport protocol carrying the service, i.e. the single transport
        #: protocol of the registry this member lives in.
        proto: 'TransportProtocol'

    #: Transport protocol whose assignments this registry holds. The base
    #: registry holds none, so it names none.
    __transport__: 'TransportProtocol' = TransportProtocol.undefined

    #: Members of this registry, keyed on port number -- a
    #: :class:`~pcapkit.corekit.multidict.MultiDict` because IANA genuinely
    #: assigns several services to one port, and a plain mapping would keep only
    #: the last of them.
    #:
    #: Declared here as :obj:`None` and overridden in each subclass: a mutable
    #: class attribute declared on this class would be *shared* by all four
    #: subclasses, so they would collide with each other exactly as the ports of
    #: one transport used to collide inside the old flat registry.
    __registry__: 'Optional[MultiDict[int, {NAME}]]' = None

    #: Registry class owning each transport protocol, i.e. what
    #: :meth:`get` delegates to when called on this class rather than on one of
    #: them. Populated by :mod:`pcapkit.const.reg.apptype` once all four have
    #: been imported, since this module cannot import its own subclasses.
    __registries__: 'dict[TransportProtocol, Type[{NAME}]]' = {{}}

    #: Canonical service per port, for the ports carrying more than one. The base
    #: registry has no members and so no collisions.
    __canonical__: 'dict[int, str]' = {{}}

    def __new__(cls, value: 'int', name: 'str' = '<null>',
                proto: 'TransportProtocol' = TransportProtocol.undefined) -> 'Type[{NAME}]':
        temp = f'{{name}} [{{value}} - {{proto.name}}]'

        obj = str.__new__(cls, temp)
        obj._value_ = temp

        obj.svc = name
        obj.port = value
        obj.proto = proto

        # NOTE: the value is the formatted string above rather than the port, so
        # two services on one port stay two canonical members instead of one
        # member and an alias -- an alias would answer to the other's name.
        if cls.__registry__ is None:
            raise ValueError(f'{{cls.__name__}} holds no members; they belong to its per-transport '
                             'subclasses')
        cls.__registry__.add(value, obj)

        return obj

    @property
    def aliases(self) -> 'tuple[{NAME}, ...]':
        """Other services sharing :attr:`port` in this member's own registry.

        GitHub issue #807. No storage of its own: IANA already keeps every
        colliding service as its own member of :data:`__registry__`, keyed on
        the shared port -- :meth:`get_all` already walks that same bucket to
        answer with the aliases after the canonical member, so this is exactly
        that bucket, minus ``self``. Derived fresh on every access rather than
        cached once, since :meth:`register_alias` can add a new member to the
        bucket at any time and a cached tuple would go stale the moment one is
        -- the same reason the ``_value_`` :meth:`__new__` sets never grows an
        alias list of its own; see :meth:`__repr__` and :meth:`__str__`, which
        do.

        Returns:
            Every other member this registry holds at :attr:`port`, in
            :data:`__registry__`'s row order, or an empty :class:`tuple` when
            nothing else collides -- never :obj:`None`, so a caller never has
            to guard the read.

        """
        return tuple(member for member in self.__registry__.getlist(self.port)  # type: ignore[union-attr]
                     if member is not self)

    def __repr__(self) -> 'str':
        # NOTE: GitHub issue #807. The suffix below is the only difference from
        # the plain form GitHub issue #806 already fixed: it is appended only
        # when :attr:`aliases` is non-empty, so every member that does not
        # share its port with another service -- the vast majority -- renders
        # exactly as it did before this issue. Registering a new alias through
        # :meth:`register_alias` changes what *every* member already on that
        # port renders, immediately, since :attr:`aliases` is derived fresh on
        # each call rather than fixed at construction.
        base = f'<{{self.__class__.__name__}}.{{self.svc}}: {{self.port}} [{{self.proto.name}}]'
        aliases = self.aliases
        if not aliases:
            return f'{{base}}>'
        return f'{{base}} (aliases: {{", ".join(alias.svc for alias in aliases)}})>'

    def __str__(self) -> 'str':
        # NOTE: same suffix as __repr__, for the same reason, and -- like that
        # suffix, and unlike everything else this formats -- never folded into
        # ``_value_``. GitHub issue #807's hard constraint: ``_value_`` is the
        # live key in ``_value2member_map_``, built once when the class is
        # created, while aliases are registerable at runtime through
        # :meth:`register_alias`; baking the alias list into ``_value_`` would
        # go stale the moment one is registered after the fact. One
        # consequence worth stating plainly rather than leaving for a doctest
        # to trip over: ``str(member) == member.value`` already breaks at
        # class-creation time for every port that statically carries more
        # than one service (94 such members as shipped);
        # :meth:`register_alias` merely adds to that set at runtime.
        base = f'{{self.svc}} [{{self.port}} - {{self.proto.name}}]'
        aliases = self.aliases
        if not aliases:
            return base
        return f'{{base}} (aliases: {{", ".join(alias.svc for alias in aliases)}})'

    def __int__(self) -> 'int':
        return self.port

    def __lt__(self, other: '{NAME}') -> 'bool':
        return self.port < other

    def __gt__(self, other: '{NAME}') -> 'bool':
        return self.port > other

    def __le__(self, other: '{NAME}') -> 'bool':
        return self.port <= other

    def __ge__(self, other: '{NAME}') -> 'bool':
        return self.port >= other

    def __eq__(self, other: 'Any') -> 'bool':
        return self.port == other

    def __ne__(self, other: 'Any') -> 'bool':
        return self.port != other

    def __hash__(self) -> 'int':
        return hash(self.port)

    @classmethod
    def _dispatch(cls, key: 'int', proto: 'TransportProtocol | str | int') -> 'Type[{NAME}]':
        """The registry that owns ``proto``, or ``cls`` where it is one already.

        Args:
            key: Port number the caller is looking up, validated here so that
                every entry point rejects a non-port identically.
            proto: Transport protocol, as a member, its name, or a bare
                :class:`int`. That last shape is not merely defensive: GitHub
                issue #808 dropped ``TransportProtocol``'s ``IntFlag`` base, so
                ``TransportProtocol.a | TransportProtocol.b`` -- built by hand,
                the same as any caller passing a literal port-transport bitmask
                -- falls through to ``int.__or__`` and returns a bare
                :class:`int` rather than a member. Never split back into the
                transports its bits would each name -- owner ruling on this PR
                (#836) -- so it is refused as a whole exactly like any other
                value naming no registry.

        Returns:
            The registry class to search.

        Raises:
            ValueError: If ``key`` is not a port number, or if ``proto`` --
                member or bare int, composite or not -- names no registry to
                delegate to.

        """
        # NOTE: this registry resolves ports, not service names. The old string
        # branch tested ``key in __members_proto__``, which is keyed by transport
        # protocol, so a name never matched and the miss path minted a brand-new
        # member with port -1 -- GitHub issue #734's silent junk. Rejecting a
        # non-port outright is the honest answer, and it has to happen before the
        # miss path, which formats ``key`` into an f-string.
        if not isinstance(key, int):
            raise ValueError(f'{{key!r}} is not a valid port number for {{cls.__name__}}')
        if cls.__registry__ is not None:
            return cls

        if isinstance(proto, str):
            proto = TransportProtocol.get(proto.lower())

        # NOTE: a direct dict lookup covers every genuine single transport --
        # one of the four real members, or a bare int equal to one of their
        # values -- since ``__registries__`` keys compare by the same
        # int-valued hash/eq every member and bare int alike already use. The
        # cast is for mypy alone: ``dict.get`` accepts any hashable key at run
        # time regardless of its declared key type, but mypy holds ``.get`` to
        # the dict's own ``TransportProtocol`` keys, and does not know ``proto``
        # can genuinely be a bare :class:`int` here now that GitHub issue #808
        # dropped the ``IntFlag`` base -- see the annotation on ``proto`` above.
        subclass = cls.__registries__.get(cast('TransportProtocol', proto))
        if subclass is not None:
            return subclass

        # NOTE: everything that reaches here names no registry, and nothing
        # below decodes ``proto``'s bits looking for a partial answer. A
        # genuine member reaching this point is ``undefined`` -- the four
        # real transports would already have resolved above, and
        # :meth:`TransportProtocol.get` cannot mint anything else, per this
        # PR's own maintainer ruling against extending TransportProtocol at
        # all -- and a bare :class:`int` is refused exactly the same way
        # whether it is a single stray bit, e.g. ``17``, or a composite of
        # several real transports, e.g. ``3`` (``tcp | udp``). That composite
        # case used to get its own
        # :exc:`~pcapkit.utilities.exceptions.ProtocolError`, decoded through
        # :func:`~pcapkit.utilities.compat.show_flag_values` and naming every
        # transport whose bit was set -- the fix for GitHub issue #759, where
        # resolving a composite by picking its lowest set bit dispatched
        # every one containing ``tcp`` into the TCP registry regardless of
        # what else it named. The owner's further ruling on this PR (#836)
        # retired that decoding along with the rest of the composite
        # handling: "since it's no longer a Flag, `|` joined values are no
        # longer parsed and accepted, we will treat it as a whole, instead of
        # splitting." So ``AppType.get(80, proto=3)`` now says "3 names no
        # transport protocol registry" rather than naming ``tcp`` and ``udp``
        # individually -- the same answer a caller resolving a parsed port
        # already gets right, since it knows which single transport carried
        # it and passes that one bit, and the same answer a caller wanting
        # every service on a port already has to ask each registry for in
        # turn regardless.
        raise ValueError(f'{{proto!r}} names no transport protocol registry of '
                         f'{{cls.__name__}}')

    @classmethod
    def get(cls, key: 'int', *,
            proto: 'TransportProtocol | str | int' = TransportProtocol.undefined) -> '{NAME}':
        """Backport support for original codes.

        Args:
            key: Port number to look up.
            proto: Transport protocol carrying ``key``. Selects the registry to
                search when called on :class:`{NAME}` itself, which holds no
                members; ignored when called on one of those registries, each of
                which already knows its own transport. **One** transport protocol
                when it does select, since one registry is what a port lookup can
                answer from -- a member's own ``proto`` names exactly one, so
                passing it straight back in always resolves, while a composite
                built by hand is refused rather than resolved to a guess.

        Returns:
            The **canonical** service for ``key``. IANA assigns several services
            to some ports -- ``80`` carries ``http``, ``www`` and ``www-http`` --
            and names no precedence among them, so :data:`__canonical__` supplies
            the one the rest of the world answers with. The others remain real,
            named members and are reached through :meth:`get_all`.

        Raises:
            ValueError: If called on a class that holds no members, i.e. on
                :class:`{NAME}` itself, with a ``proto`` naming no registry to
                delegate to. Also for a ``key`` that is not a port number, since
                this registry resolves ports and not service names -- including
                one outside ``0..65535``, whose rejection by :meth:`_missing_` this
                method propagates rather than minting over, so that ``get`` is
                never more permissive than ``{NAME}(...)``. Also covers a
                ``proto`` naming more than one transport protocol -- a
                composite built by hand is refused as a whole rather than
                answered from any one of the registries it names -- see
                :meth:`_dispatch`.

        :meta private:
        """
        owner = cls._dispatch(key, proto)

        matched = owner.__registry__.getlist(key)  # type: ignore[union-attr]
        if matched:
            canonical = owner.__canonical__.get(key)
            if canonical is not None:
                for member in matched:
                    if member.svc == canonical:
                        return member
            # NOTE: IANA's oldest row, for a port whose collision postdates
            # :data:`__canonical__` -- including one :func:`~aenum.extend_enum`
            # created, which must not displace what the registry already
            # answered with.
            return matched[0]

        # NOTE: :meth:`_missing_` answers :obj:`None` for a port it holds no row
        # for, which is what minting is for, and *raises* for a value that is not a
        # port at all. Catching that rejection was GitHub issue #758's defect: it
        # minted ``PORT_999999_tcp`` and ``PORT_-1_tcp``, the latter a name no
        # attribute access can reach, and left ``get`` more permissive than
        # ``{NAME}(...)``, which has always raised here. The rejection now
        # propagates, so both entry points answer an out-of-range port identically.
        ret = owner._missing_(key)
        if ret is None:
            ret = extend_enum(owner, f'PORT_{{key}}_{{owner.__transport__.name}}',
                              key, 'unknown', owner.__transport__)
        return ret

    @classmethod
    def get_all(cls, key: 'int', *,
                proto: 'TransportProtocol | str | int' = TransportProtocol.undefined) -> 'tuple[{NAME}, ...]':
        """Every service IANA assigns to a port, canonical first.

        :meth:`get` answers with one member because that is what a port lookup
        means everywhere else -- :func:`socket.getservbyport` returns a single
        name -- but IANA really did register all three services on TCP/80, and
        discarding two of them would be inventing a registry it does not have.
        This is how the rest are reached.

        Args:
            key: Port number to look up.
            proto: Transport protocol carrying ``key``, as for :meth:`get`.

        Returns:
            The canonical member followed by its aliases, in registry row order.
            Never empty: a port with no assignment goes through :meth:`get`, so it
            is minted rather than answered with an empty result.

        Raises:
            ValueError: As :meth:`get`.

        """
        owner = cls._dispatch(key, proto)

        canonical = owner.get(key)
        matched = owner.__registry__.getlist(key)  # type: ignore[union-attr]
        return (canonical, *(member for member in matched if member is not canonical))

    @classmethod
    def register_alias(cls, port: 'int', name: 'str') -> '{NAME}':
        """Register ``name`` as a new alias on ``port``, in this registry alone.

        GitHub issue #807's third ask, deliberately scoped to **this**
        per-transport registry: ``TCP.register_alias(...)`` never touches
        :class:`UDP`'s members, which is what keeps an alias registered on one
        transport from leaking onto a transport IANA never assigned it -- e.g.
        registering ``www`` as an alias of ``http`` on :class:`TCP` and
        :class:`UDP` leaves it absent from :class:`SCTP`'s port 80, exactly as
        IANA itself never registered it there.

        No new storage: the new member simply joins :data:`__registry__` at
        ``port``, through the same :func:`~aenum.extend_enum` call :meth:`get`
        already uses to mint an unknown one below. It is then reachable
        through :attr:`aliases` on every other member already on ``port``, and
        vice versa, with nothing further to keep in sync.

        The Python attribute name is derived from ``name`` through the same
        sanitising steps the generator uses for every statically declared
        member's -- ``www-http`` becomes ``www_http`` at
        :meth:`~pcapkit.vendor.default.Vendor.safe_name`, reproduced below
        (minus its fallback; see Raises below) rather than imported, since
        this module is generated *from* :mod:`pcapkit.vendor` and importing
        back would run a crawler built for one pass over IANA's CSV for what
        is otherwise a plain attribute lookup. It has to be ``name``, not
        ``port`` and a counter: an alias whose own name does not resolve
        through subscription is most of the point of registering one, and
        ``TCP['www_http']`` resolving is exactly what lets a caller reach an
        alias the same way every statically declared member already is.

        Args:
            port: Port number to register the alias under. Must already carry
                at least one member of this registry -- aliasing names a
                second service on a port that already has one, rather than
                declaring a fresh port out of nothing, which stays the
                generator's job (or, for an unassigned port, :meth:`get`'s own
                mint-on-miss).
            name: The alias's service name, i.e. what :attr:`svc` reads on the
                new member -- kept exactly as given, unlike the identifier
                sanitised from it below. Checked against every member already
                on ``port`` so the same name is never registered twice.

        Returns:
            The newly minted member.

        Raises:
            ValueError: If called on a class that holds no members, i.e. on
                :class:`{NAME}` itself, which is not one of the four
                per-transport registries; if ``port`` carries no member of
                this registry yet; if ``name`` already names one of the
                members already there; if ``name`` sanitises to text that is
                not a valid Python identifier at all -- empty, or leading with
                a digit; or if the identifier it does sanitise to already
                names an unrelated member of this registry.

        """
        if cls.__registry__ is None:
            raise ValueError(f'{{cls.__name__}} holds no members; register the alias on one '
                             'of its per-transport subclasses instead')

        existing = cls.__registry__.getlist(port)
        if not existing:
            raise ValueError(f'{{port!r}} is not yet a member of {{cls.__name__}}; register the '
                             'canonical service before aliasing it')
        if any(member.svc == name for member in existing):
            raise ValueError(f'{{name!r}} is already registered on port {{port}} of {{cls.__name__}}')

        # NOTE: mirrors Vendor.safe_name (pcapkit/vendor/default.py)'s
        # sanitising steps -- strip a parenthetical aside, collapse whitespace
        # to single underscores, replace every remaining non-word character
        # with ``_``, then collapse and trim the underscores that step leaves
        # behind. ``rename``'s further dedup -- appending ``_{{port}}`` when a
        # name already recurs elsewhere in the registry -- is deliberately
        # not reproduced: that decision is curated from a full CSV pass at
        # generation time, and synthesising a different fallback name here
        # would be exactly the silent rename the collision check below
        # refuses to do instead. ``safe_name``'s own fallback -- minting
        # ``{{cls.__name__}}_{{residue}}`` when the sanitised residue is not a
        # valid identifier -- is not reproduced either: this method raises
        # instead (see Raises above), so the 58 members the generator mints
        # that way in the shipped const (28 TCP, 29 UDP, 1 SCTP, 0 DCCP) are
        # names this runtime path refuses rather than accepts.
        stripped = re.sub(r'\\(.*\\)', '', name)
        collapsed = '_'.join(stripped.split())
        replaced = re.sub(r'\\W', '_', collapsed)
        identifier = '_'.join(filter(None, replaced.split('_')))
        # NOTE: matches process()'s own keyword guard below -- a name that
        # sanitises to a reserved word is not usable as an attribute as is,
        # and a trailing underscore is the same fix the generator already
        # applies to a statically declared member with the same problem.
        if keyword.iskeyword(identifier):
            identifier = f'{{identifier}}_'

        if not identifier.isidentifier():
            raise ValueError(f'{{name!r}} has no valid Python identifier to register '
                             f'{{cls.__name__}} with (sanitises to {{identifier!r}})')
        if identifier in cls.__members__:
            raise ValueError(f'{{identifier!r}} already names a member of {{cls.__name__}}; '
                             'choose a name whose identifier does not collide')

        return extend_enum(cls, identifier, port, name, cls.__transport__)

    @classmethod
    def _missing_(cls, value: 'int') -> 'Optional[{NAME}]':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not ({FLAG}):
            raise ValueError(f'{{value!r}} is not a valid {{cls.__name__}}')
        # NOTE: extending this class would give it a member, and aenum then
        # refuses to subclass it -- permanently, for every registry not yet
        # imported. The spans below belong to whichever registry was asked, never
        # to this one.
        if cls.__registry__ is None:
            raise ValueError(f'{{value!r}} is not a valid {{cls.__name__}}')
        # NOTE: most spans are IANA's unassigned and reserved markers, which name
        # no transport protocol and so answer every registry. A span that does name
        # one tests ``cls.__transport__`` and answers that registry alone --
        # GitHub issue #760, where source order decided instead and a UDP lookup in
        # 6000-6063 came back carrying ``tcp``. A registry a named span excludes
        # falls through to a mint, which is what IANA assigning it nothing means.
        {MISS}
        {'' if ''.join(MISS.splitlines()[-1:]).startswith('return') else 'return super()._missing_(value)'}
'''.strip()  # type: Callable[[str, str, str, str, str, str], str]

#: Template for a per-transport registry, i.e. the four modules holding the
#: members of one transport protocol and nothing else.
TRANSPORT = lambda NAME, DOCS, PROTO, CANON, TABLE, ENUM, MODL: f'''\
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""{(name := DOCS.split(' [', maxsplit=1)[0])}
{'=' * (len(name) + 6)}

.. module:: {MODL.replace('vendor', 'const')}

This module contains the constant enumeration for **{name}**,
which is automatically generated from :class:`{MODL}.{NAME}`.

"""
from pcapkit.const.reg.apptype.apptype import AppType, TransportProtocol
from pcapkit.corekit.multidict import MultiDict

__all__ = ['{NAME}']


class {NAME}(AppType):
    """[{NAME}] {DOCS}

    Every member's :attr:`~pcapkit.const.reg.apptype.apptype.AppType.proto` is
    ``{PROTO}`` and nothing else, so it labels the registry the member lives in
    rather than restating the whole set IANA assigned the service. A service
    registered on several transports is a separate member of each of their
    registries, which is where that set is read off.

    Note:
        The rows below are this transport's registry entries with **no port
        number assigned**. IANA leaves the port column empty for historic
        service names it never gave a port, so there is nothing for a member to
        be valued on and they are documented here instead.

    {TABLE}

    """

    #: Transport protocol whose assignments this registry holds.
    __transport__: 'TransportProtocol' = TransportProtocol.{PROTO}

    #: Members of this registry, keyed on port number. Declared per registry
    #: rather than inherited, since one mapping shared by all four would put
    #: every transport's ports in the same key space.
    __registry__: 'MultiDict[int, {NAME}]' = MultiDict()

    #: The canonical service for each port IANA assigns more than one to, i.e.
    #: what :meth:`~pcapkit.const.reg.apptype.apptype.AppType.get` answers with.
    #: Taken from :file:`/etc/services`, which is what
    #: :func:`socket.getservbyport` reads -- IANA names no precedence among the
    #: services it registers on one port, and registry row order does not supply
    #: one either. The rest stay reachable through
    #: :meth:`~pcapkit.const.reg.apptype.apptype.AppType.get_all`.
    __canonical__: 'dict[int, str]' = {CANON}

    {ENUM}
'''.strip()  # type: Callable[[str, str, str, str, str, str, str], str]


@info_final
class Record(Info):
    """One registry entry, as grouped by :meth:`AppType.records`.

    IANA's CSV carries one row per ``(service, port, transport)`` triple, so a
    service on both TCP and UDP is two rows that become one member. This is what
    they are merged into.

    Every field a merge has to grow is a container, appended to in place, because
    :class:`~pcapkit.corekit.infoclass.Info` refuses attribute assignment. That is
    the right shape here anyway: the comment used to be accumulated by string
    surgery, re-deriving from its own output whether it had been merged already.

    """

    #: Service name, as IANA spells it.
    svc: 'str'
    #: Port number as text, or ``'-1'`` where IANA assigned none.
    port: 'str'
    #: Transport protocol names carrying the service, normalised to a set. The
    #: registry repeats a transport across rows often enough that accumulating
    #: the expression as text produced ``tcp | tcp | udp | udp``.
    protos: 'set[str]'
    #: Wrapped ``#:`` comment, one per merged registry row.
    parts: 'list[str]'
    #: Single-line description per merged row, for a ``list-table`` cell.
    cells: 'list[str]'


class AppType(Vendor):
    """Application Layer Protocol Numbers"""

    #: Transport protocol whose assignments this crawler renders; :obj:`None` for
    #: the base registry, which renders the rows belonging to no transport.
    TRANSPORT = None  # type: Optional[str]

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 65535'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv'

    def _request(self) -> 'list[str]':
        """Fetch the registry, at most once per process.

        See Also:
            :data:`_CACHE`

        """
        cached = _CACHE.get(self.LINK)
        if cached is None:
            cached = _CACHE[self.LINK] = super()._request()
        return cached

    def count(self, data: 'list[str]') -> 'Counter[str]':
        """Count field records."""
        reader = csv.reader(data)
        next(reader)  # header
        return collections.Counter(map(lambda item: '[%s] %s' % (item[2], item[0].strip() or self.safe_name(item[3].strip())),
                                       filter(lambda item: len(item[1].split('-')) != 2, reader)))

    @staticmethod
    def wrap_comment(text: 'str') -> 'str':
        """Wraps long-length text to shorter lines of comments.

        Args:
            text: Source text.

        Returns:
            Wrapped comments.

        """
        return '\n    #:   '.join(textwrap.wrap(text.strip(), 76))

    @staticmethod
    def flag(protos: 'Iterable[str]') -> 'str':
        """Render transport protocol names as a ``TransportProtocol`` expression.

        Args:
            protos: Transport protocol names.

        Returns:
            Source text for the member's ``proto`` argument, with the protocols
            in the order the enumeration declares them so that the same set
            always renders the same way.

        """
        order = TRANSPORTS + ('undefined',)
        return ' | '.join(f'TransportProtocol.{proto}'
                          for proto in sorted(protos, key=order.index))

    @staticmethod
    def tabulate(title: 'str', widths: 'tuple[int, ...]', header: 'tuple[str, ...]',
                 rows: 'list[tuple[str, ...]]') -> 'str':
        """Render rows as a reST ``list-table`` for a class docstring.

        The entries this registry documents rather than declares are only
        reachable through the docs, so they are emitted as a table
        :mod:`sphinx.ext.autodoc` renders in place rather than as comments it
        drops.

        Args:
            title: Table caption.
            widths: Relative column widths.
            header: Column headings.
            rows: Table body, one tuple per row.

        Returns:
            Source text for the table, indented to sit inside a class docstring.
            Blank lines are emitted truly empty, since
            :meth:`Vendor.__init__` discards a whitespace-only one and reST needs
            the one between a directive's options and its body.

        """
        lines = [
            f'.. list-table:: {title}',
            '   :header-rows: 1',
            '   :widths: %s' % ' '.join(map(str, widths)),  # pylint: disable=consider-using-f-string
            '',
        ]
        for row in [header, *rows]:
            for index, cell in enumerate(row):
                wrapped = textwrap.wrap(cell, 68, break_long_words=False) or ['N/A']
                bullet = '* - ' if not index else '  - '
                lines.append(f'   {bullet}{wrapped[0]}')
                lines.extend(f'       {part}' for part in wrapped[1:])

        return '\n'.join('' if not line else line if not index else f'    {line}'
                         for index, line in enumerate(lines))

    def records(self, data: 'list[str]') -> 'tuple[OrderedDict[str, Record], list[str]]':
        """Group registry data into one entry per member.

        This is the whole of the registry, before any transport protocol claims
        part of it -- the grouping is shared because a name's suffix depends on
        what else the registry holds, so partitioning first would give one
        service two names in two registries.

        Args:
            data: Registry data.

        Returns:
            Entries in registry row order, keyed by member name, and the
            ``_missing_`` branches for the rows that name a port *range* rather
            than a port.

        """
        reader = csv.reader(data)
        next(reader)  # header

        line = collections.OrderedDict()  # type: OrderedDict[str, Record]
        miss = []  # type: list[str]

        for item in reader:
            svc = item[0].strip().lower() or self.safe_name(item[3].strip()).lower()
            port = item[1].strip() or '-1'
            proto = item[2].strip().lower() or 'undefined'
            desc = item[3].strip()

            temp = []  # type: list[str]
            for rfc in filter(None, map(lambda s: s.strip(), re.split(r'\[|\]', item[8]))):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    match = re.fullmatch(r'RFC(?P<rfc>\d+)(, Section (?P<sec>.*?))?', rfc)
                    if match is None:
                        temp.append(f'[{rfc}]')
                    else:
                        if match.group('sec') is not None:
                            temp.append(f'[:rfc:`{match.group("rfc")}#{match.group("sec")}`]')
                        else:
                            temp.append(f'[:rfc:`{match.group("rfc")}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            text = re.sub(r'\s+', r' ',
                          '[%s] %s %s' % (item[2].strip().upper() or 'N/A',
                                          desc, ''.join(temp))).strip()  # pylint: disable=consider-using-f-string
            cmmt = self.wrap_comment(text)

            try:
                code, _ = port, int(port)
                if port == '-1':
                    code = 'null'
                renm = self.rename(svc, code)

                if f'{renm}_{code}' in line:
                    renm = f'{renm}_{code}'

                if renm in line:
                    if port == line[renm].port:
                        line[renm].protos.add(proto)
                        line[renm].parts.append(cmmt)
                        line[renm].cells.append(text)
                    else:
                        line[f'{renm}_{line[renm].port}'] = line[renm]
                        line[f'{renm}_{code}'] = Record(svc=svc, port=port, protos={proto},
                                                        parts=[cmmt], cells=[text])
                        del line[renm]
                else:
                    line[renm] = Record(svc=svc, port=port, protos={proto},
                                        parts=[cmmt], cells=[text])
            except ValueError:
                start, stop = port.split('-')

                # NOTE: a span IANA assigns to a transport protocol is claimed by
                # that registry alone, through a test on ``cls.__transport__``.
                # Source order decided instead until GitHub issue #760: the only
                # two spans registered on more than one transport -- 6000-6063 and
                # 6665-6669 -- rendered the same condition twice, leaving the
                # second copy unreachable, so *every* registry answered with the
                # first row's. That is not merely a duplicate to collapse: the
                # 6665-6669 rows are two different services, ``ircu`` on TCP and
                # IANA's ``reserved`` marker on UDP, so one merged branch carrying
                # ``tcp | udp`` would have to discard one of them.
                #
                # A span naming no transport protocol is an unassigned or reserved
                # marker belonging to whichever registry was asked, so it carries
                # no test and keeps answering all four.
                flag = self.flag([proto])
                claim = '' if proto == 'undefined' else f' and cls.__transport__ is {flag}'

                miss.append(f'if {start} <= value <= {stop}{claim}:')
                miss.append(f'    #: {cmmt}')
                miss.append(f"    return extend_enum(cls, f'{self.safe_name(svc)}_{{value}}', "
                            f"value, {svc!r}, {flag})")

        return line, miss

    def process(self, data: 'list[str]') -> 'tuple[list[str], list[str]]':
        """Process registry data.

        Args:
            data: Registry data.

        Returns:
            The member declarations this crawler's registry owns -- none, for the
            base registry -- and the ``_missing_`` branches, which only the base
            registry renders since it is where ``_missing_`` lives.

        """
        line, miss = self.records(data)
        if self.TRANSPORT is None:
            return [], miss

        enum = []  # type: list[str]
        for key, record in line.items():
            if self.TRANSPORT not in record.protos or record.port == '-1':
                continue
            if keyword.iskeyword(key):
                key = '%s_' % key

            # NOTE: the member's ``proto`` is this registry's own transport
            # protocol and nothing else, so it is a single bit -- GitHub issue
            # #806. Rendering ``record.protos`` here instead put the whole
            # ``(service, port)`` IANA set on every member, which made
            # ``TCP.http.proto`` name UDP and SCTP as well. That was a second
            # copy of what the four registries already encode, it is the copy
            # that could drift, and being multi-bit it was refused by every
            # entry point that consumed it.
            pres = f"{key} = {record.port}, {record.svc!r}, {self.flag([self.TRANSPORT])}"
            if len(record.parts) > 1:
                # NOTE: a merged entry describes each registry row it came from,
                # as one bullet per row. The single-row form re-indents its own
                # wrapped continuations instead; the bulleted form does not need
                # that, since the bullet already supplies the hanging indent.
                sufs = '#: - %s' % '\n    #: - '.join(record.parts)
            else:
                sufs = '#: %s' % record.parts[0].replace('    #:   ', '    #: ')

            enum.append(f'{sufs}\n    {pres}')
        return enum, []

    def canonical(self, data: 'list[str]') -> 'str':
        """Render this registry's canonical-service mapping.

        Args:
            data: Registry data.

        Returns:
            Source text for the ``__canonical__`` dict literal, holding an entry
            for every port this registry assigns more than one service to.

        Warns:
            VendorRuntimeWarning: If IANA has begun assigning several services to
                a port :data:`CANONICAL` has no entry for. The lookup falls back
                to the oldest row, which is a guess, so the curated table needs
                the port adding from :file:`/etc/services`.

        """
        if self.TRANSPORT is None:
            return '{}'

        line, _ = self.records(data)
        ports = collections.Counter(
            int(record.port) for record in line.values()
            if self.TRANSPORT in record.protos and record.port != '-1')

        curated = CANONICAL[self.TRANSPORT]
        entries = {}  # type: dict[int, str]
        for port in sorted(port for port, count in ports.items() if count > 1):
            if port not in curated:
                warn(f'{self.NAME}: no canonical service curated for port {port}; '
                     f"falling back to IANA's oldest row", VendorRuntimeWarning, stacklevel=2)
                continue
            entries[port] = curated[port]

        if not entries:
            return '{}'
        body = ',\n        '.join(f'{port}: {svc!r}' for port, svc in entries.items())
        return f'{{\n        {body},\n    }}'

    def table(self, data: 'list[str]') -> 'str':
        """Render the entries this registry documents rather than declares.

        Args:
            data: Registry data.

        Returns:
            Source text for a reST ``list-table``.

        """
        line, _ = self.records(data)

        if self.TRANSPORT is None:
            return self.tabulate(
                'Service names assigned no transport protocol',
                (25, 10, 65), ('Service Name', 'Port', 'Description'),
                [(f'``{record.svc}``',
                  'N/A' if record.port == '-1' else record.port,
                  '; '.join(record.cells))
                 for record in line.values() if not record.protos.intersection(TRANSPORTS)],
            )

        return self.tabulate(
            'Service names assigned no port number',
            (30, 70), ('Service Name', 'Description'),
            [(f'``{record.svc}``', '; '.join(record.cells))
             for record in line.values()
             if self.TRANSPORT in record.protos and record.port == '-1'],
        )

    def context(self, data: 'list[str]') -> 'str':
        """Generate constant context.

        Args:
            data: CSV data.

        Returns:
            Constant context.

        """
        enum, miss = self.process(data)
        TABLE = self.table(data)

        if self.TRANSPORT is None:
            MISS = '\n        '.join(map(lambda s: s.rstrip(), miss)).strip()
            return BASE(self.NAME, self.DOCS, self.FLAG, TABLE, MISS, self.__module__)

        ENUM = '\n\n    '.join(map(lambda s: s.rstrip(), enum)).strip()
        return TRANSPORT(self.NAME, self.DOCS, self.TRANSPORT, self.canonical(data),
                         TABLE, ENUM, self.__module__)


if __name__ == '__main__':
    sys.exit(AppType())  # type: ignore[arg-type]
