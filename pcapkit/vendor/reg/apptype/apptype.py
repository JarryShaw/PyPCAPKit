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
# pylint: disable=line-too-long,consider-using-f-string
"""{(name := DOCS.split(' [', maxsplit=1)[0])}
{'=' * (len(name) + 6)}

.. module:: {MODL.replace('vendor', 'const')}

This module contains the constant enumeration for **{name}**,
which is automatically generated from :class:`{MODL}.{NAME}`.

"""
from typing import TYPE_CHECKING, cast

from aenum import IntFlag, StrEnum, auto, extend_enum

from pcapkit.utilities.compat import show_flag_values

__all__ = ['TransportProtocol', '{NAME}']

if TYPE_CHECKING:
    from typing import Any, Optional, Type

    from pcapkit.corekit.multidict import MultiDict


class TransportProtocol(IntFlag):
    """Transport layer protocol."""

    # mypy has no aenum plugin, so this class is a plain class to it: a bare
    # ``0`` here infers as int while the auto()-valued members below infer as
    # Any, and only this member then disagrees with the TransportProtocol
    # annotations that use it. cast is the identity function at run time, so
    # this changes nothing that runs -- see GitHub issue #770. mypy.ini sets
    # warn_redundant_casts, so if aenum ever ships type stubs letting it infer
    # TransportProtocol on its own, this cast starts erroring instead of
    # lingering as dead scaffolding.
    #: No transport protocol. ``TransportProtocol(0) is undefined`` and
    #: ``bool(undefined)`` is ``False``; it is the ``proto`` sentinel default
    #: for ``__transport__``, ``__new__``, ``get`` and ``get_all``, and what
    #: the base registry's ``_missing_`` extends unassigned/reserved rows from.
    undefined = cast('TransportProtocol', 0)

    #: Transmission Control Protocol.
    tcp = auto()
    #: User Datagram Protocol.
    udp = auto()
    #: Stream Control Transmission Protocol.
    sctp = auto()
    #: Datagram Congestion Control Protocol.
    dccp = auto()

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
        max_val = max(TransportProtocol.__members__.values())
        return extend_enum(TransportProtocol, key.lower(), max_val * 2)

    @classmethod
    def _missing_(cls, value: 'int') -> 'TransportProtocol':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        Raises:
            ValueError: If ``value`` sets a bit no member declares.

        Note:
            This is what makes an unrecognised transport protocol *rejected*
            rather than accepted -- GitHub issue #647's fix for this registry.
            :mod:`aenum` on its own is permissive here and composes whatever bits
            it is handed: measured on aenum 3.1.17 with this method removed,
            ``TransportProtocol(-1)`` returns ``tcp|udp|sctp|dccp``, which is
            #647's recorded defect for this class verbatim, and
            ``TransportProtocol(16)`` returns a member whose ``name`` is
            :obj:`None`. Declared bits still compose, since a service assigned to
            several transport protocols is the ordinary case rather than the
            exception.

        """
        if not (isinstance(value, int) and 0 <= value <= max(cls.__members__.values()) * 2 - 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)


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
        #: Transport protocol.
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
        temp = '%s [%d - %s]' % (name, value, proto.name)

        obj = str.__new__(cls, temp)
        obj._value_ = temp

        obj.svc = name
        obj.port = value
        obj.proto = proto

        # NOTE: the value is the formatted string above rather than the port, so
        # two services on one port stay two canonical members instead of one
        # member and an alias -- an alias would answer to the other's name.
        if cls.__registry__ is None:
            raise ValueError('%s holds no members; they belong to its per-transport '
                             'subclasses' % cls.__name__)
        cls.__registry__.add(value, obj)

        return obj

    def __repr__(self) -> 'str':
        return "<%s.%s: %d [%s]>" % (self.__class__.__name__, self.svc, self.port, self.proto.name)

    def __str__(self) -> 'str':
        return '%s [%d - %s]' % (self.svc, self.port, self.proto.name)

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
    def _dispatch(cls, key: 'int', proto: 'TransportProtocol | str') -> 'Type[{NAME}]':
        """The registry that owns ``proto``, or ``cls`` where it is one already.

        Args:
            key: Port number the caller is looking up, validated here so that
                every entry point rejects a non-port identically.
            proto: Transport protocol, as a flag or its name.

        Returns:
            The registry class to search.

        Raises:
            ValueError: If ``key`` is not a port number, or if ``cls`` holds no
                members and ``proto`` names no registry to delegate to.

        """
        # NOTE: this registry resolves ports, not service names. The old string
        # branch tested ``key in __members_proto__``, which is keyed by transport
        # protocol, so a name never matched and the miss path minted a brand-new
        # member with port -1 -- GitHub issue #734's silent junk. Rejecting a
        # non-port outright is the honest answer, and it has to happen before the
        # miss path, which formats ``key`` with ``%d``.
        if not isinstance(key, int):
            raise ValueError('%r is not a valid port number for %s' % (key, cls.__name__))
        if cls.__registry__ is not None:
            return cls

        if isinstance(proto, str):
            proto = TransportProtocol.get(proto.lower())
        for namespace in show_flag_values(proto):
            subclass = cls.__registries__.get(TransportProtocol(namespace))
            if subclass is not None:
                return subclass
        raise ValueError('%r names no transport protocol registry of %s'
                         % (proto, cls.__name__))

    @classmethod
    def get(cls, key: 'int', *,
            proto: 'TransportProtocol | str' = TransportProtocol.undefined) -> '{NAME}':
        """Backport support for original codes.

        Args:
            key: Port number to look up.
            proto: Transport protocol carrying ``key``. Selects the registry to
                search when called on :class:`{NAME}` itself, which holds no
                members; ignored when called on one of those registries, each of
                which already knows its own transport.

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
                never more permissive than ``{NAME}(...)``.

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
            ret = extend_enum(owner, 'PORT_%d_%s' % (key, owner.__transport__.name),
                              key, 'unknown', owner.__transport__)
        return ret

    @classmethod
    def get_all(cls, key: 'int', *,
                proto: 'TransportProtocol | str' = TransportProtocol.undefined) -> 'tuple[{NAME}, ...]':
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
    def _missing_(cls, value: 'int') -> 'Optional[{NAME}]':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not ({FLAG}):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        # NOTE: extending this class would give it a member, and aenum then
        # refuses to subclass it -- permanently, for every registry not yet
        # imported. The spans below belong to whichever registry was asked, never
        # to this one.
        if cls.__registry__ is None:
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
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
# pylint: disable=line-too-long,consider-using-f-string
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

    Members carry the **whole** transport protocol set IANA assigned the service,
    not just ``{PROTO}``, so a service registered on several transports appears in
    each of their registries with its
    :attr:`~pcapkit.const.reg.apptype.apptype.AppType.proto` intact.

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
                miss.append(f"    return extend_enum(cls, '{self.safe_name(svc)}_%d' % value, "
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

            pres = f"{key} = {record.port}, {record.svc!r}, {self.flag(record.protos)}"
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
