# -*- coding: utf-8 -*-
"""Generate the option-coverage sample captures, and the case table behind them.

The other generators in this directory cover the *parse* path for common
protocols. What they do not cover is the option, chunk, parameter and block
space -- and in particular they do not cover the **construction** side of it at
all, the ``_make_*`` methods and the schema ``pack`` path. This module closes
that gap, and it is deliberately built the other way round from its siblings:
they know which packets they want and spell them out, whereas this one asks the
library which codes it claims to support and then exercises every one of them.

=============================== =============================================
Capture                         Codes
=============================== =============================================
:file:`options-tcp.pcap`        TCP options and Multipath TCP subtypes
:file:`options-ipv4.pcap`       IPv4 options
:file:`options-ipv6.pcap`       HOPOPT, IPv6-Opts and IPv6-Route
:file:`options-transport.pcap`  SCTP chunks, parameters and error causes,
                                and HTTP/2 frames
:file:`options-internet.pcap`   Mobility Header messages, options and
                                extensions, and HIP parameters
=============================== =============================================

Each frame carries exactly one item of exactly one code, so a parse failure
names the option that caused it instead of a soup of several. Every frame is an
Ethernet envelope around octets that :mod:`pcapkit` itself constructed, rather
than a packet assembled by :mod:`scapy` from its own protocol model. That is the
point: the octets under test are the library's own output, so a capture is a
record of what this version of ``pcapkit`` builds, and re-parsing it exercises
``_read_*`` against ``_make_*``.

Only the codes that construct *successfully* can appear in a capture -- there
are no octets for the ones that do not. Roughly a fifth of the space does not,
and that shortfall is not swept up: it is recorded case by case in
:file:`tests/protocols/test_option_roundtrip_unit.py`, against the defect that
causes it.

Why the case table is not a list of options
-------------------------------------------

:func:`cases` walks the dispatch registries -- ``TCP.__option__``,
``SCTP.__chunk__``, ``MH.__message__`` and the rest -- so a code registered
tomorrow appears here tomorrow, and the unit test fails until somebody gives it
a case. What the tables below hold is only the *arguments*, which cannot be
derived: each option means something different, so each needs its own value.
Most need nothing at all, since nearly every ``_make_*`` in the tree is fully
defaulted; an entry exists where the default is degenerate (a zero-length
variable field), machine-dependent, or outright rejected.

Every one of these registries is a :class:`collections.defaultdict` held on a
*class* attribute, so ``registry[code]`` inserts on a miss and permanently grows
a registry shared by every instance in the process. Nothing here subscripts one:
:func:`cases` only ever *iterates*, which touches nothing, and :func:`handler` --
which resolves one particular code, and so cannot iterate -- goes through
:meth:`ProtocolBase._lookup_registry
<pcapkit.protocols.protocol.ProtocolBase._lookup_registry>` instead.

IPv4 and HIP have no such registry yet -- they dispatch on the attribute name
``_make_opt_${name}`` / ``_make_param_${name}`` -- so for those two the source
of truth is the enumeration crossed with the presence of the handler, which is
what :func:`_named_registry` builds.

Determinism
-----------

The captures have to regenerate byte-identically; a fixture that churns is
worse than none, because every unrelated change then shows up as a diff. Four
things would otherwise vary between runs and are pinned:

1. Frame timestamps, from :data:`EPOCH` rather than the clock.
2. The order cases are emitted in, from :func:`sort_key` rather than from
   registry iteration order -- which is insertion order, and therefore an
   implementation detail of whichever module last registered a code.
3. ``MH``'s ``MESG_ID_OPTION_TYPE``, whose ``_make_opt_mesg_id`` falls back to
   :meth:`datetime.datetime.now` when given neither ``timestamp`` nor
   ``interval``. It is given one below.
4. Anything reading the host. No case here uses PCAP-NG's
   ``_make_option_if_os``, which defaults to the live :mod:`platform` string.

Two deliberate deviations from the sibling generators
----------------------------------------------------

Almost every import of :mod:`pcapkit` and of :mod:`scapy` in this module is
inside the function that needs it, which is why :mod:`pylint`'s
``import-outside-toplevel`` is switched off for the file rather than argued with
forty times. Both are load-bearing. :mod:`scapy` is needed only by
:func:`generate`, while the case table and :func:`roundtrip` are useful without
it -- the unit-tier test uses both and has to run on a checkout that installed no
:mod:`scapy`, so a top-level import would make that test skip for a dependency it
never touches. The :mod:`pcapkit` imports are deferred so that importing this
module does not drag in every protocol in the tree, which is what lets the unit
test purge :mod:`pcapkit` and *then* load the case table without the two
orderings fighting.

:func:`roundtrip` puts a :func:`signal.alarm` deadline around each case. That
is not defensive dressing: GitHub issue #431 is a parser defect that
degenerates into a loop making no progress, ``HOPOPT``'s ``SMF_DPD`` reaches it,
and without a deadline ``make samples`` does not fail -- it *hangs*, taking the
whole build with it. A signal is what interrupts it, because the loop is pure
Python and holds the GIL for the whole of an iteration, so no watchdog thread
would ever get to run.

"""

# Deferring these is the design, not an oversight -- see the module docstring.
# pylint: disable=import-outside-toplevel

from __future__ import annotations

import collections
import datetime
import pathlib
import signal
import warnings
from typing import TYPE_CHECKING, NamedTuple

from pcapkit.protocols.protocol import ProtocolBase

if TYPE_CHECKING:
    from typing import Any, Callable, Iterator, Optional

__all__ = ['generate', 'cases', 'roundtrip', 'outcomes', 'Case', 'Outcome', 'FAMILIES']

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]
#: Default destination directory for the generated captures.
SAMPLE = ROOT / 'examples' / 'captures'

#: Capture start time, fixed so that regenerating gives identical files.
EPOCH = 1500000000.0

#: Source MAC for every generated frame.
SRC_MAC = '02:00:00:00:00:01'
#: Destination MAC for every generated frame.
DST_MAC = '02:00:00:00:00:02'
#: Source address for every generated IPv4 envelope.
SRC_IP = '192.0.2.1'
#: Destination address for every generated IPv4 envelope.
DST_IP = '198.51.100.1'
#: Source address for every generated IPv6 envelope.
SRC_IP6 = '2001:db8::1'
#: Destination address for every generated IPv6 envelope.
DST_IP6 = '2001:db8::2'

#: Seconds a single case may take before :func:`roundtrip` gives up on it and
#: records ``'TIMEOUT'``. Generous next to a working case, which takes low
#: single-digit milliseconds, and short enough that a whole sweep still ends.
DEADLINE = 5

#: Fixed instant handed to any constructor that would otherwise read the clock.
#: Timezone-aware and in the past, so it is stable and unambiguous.
FIXED_TIME = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)


class Case(NamedTuple):
    """One option-like code, and the arguments that construct it."""

    #: Family label, e.g. ``'tcp-option'``. Names the registry the code came
    #: from and, with :attr:`name`, forms the case's unique label.
    family: 'str'
    #: Registry key, i.e. the wire code. Usually an enumeration member; for
    #: ``PCAPNG.__option__`` a ``(str, int)`` tuple, since the same numeric
    #: option code means different things in different block types.
    code: 'Any'
    #: Human-readable code name, used in the case label and in test ids.
    name: 'str'
    #: Keyword arguments handed to the constructor. ``{}`` means "every
    #: default", which is what most codes need.
    kwargs: 'dict[str, Any]'

    @property
    def label(self) -> 'str':
        """``family/name``, unique across every family."""
        return f'{self.family}/{self.name}'


class Outcome(NamedTuple):
    """What one construct -> parse -> construct cycle did."""

    #: The case this describes.
    case: 'Case'
    #: The step that failed, or ``'OK'`` -- see :data:`STATUSES`.
    status: 'str'
    #: Exception type and message, or for ``'MISMATCH'`` the two hex strings.
    #: Empty for ``'OK'``.
    detail: 'str'
    #: The octets construction produced, or :data:`None` if it never got that
    #: far. Kept as :obj:`bytes` so a caller can put them straight in a frame.
    octets: 'Optional[bytes]'
    #: Warning messages raised anywhere in the cycle, deduplicated but in
    #: order. A case can be ``'OK'`` and still warn, and that is worth seeing:
    #: a silent ``SchemaWarning: packet length < 0`` means an option over-read
    #: and the octets around it are not what they appear to be.
    warnings: 'tuple[str, ...]'


#: Statuses whose octets may go into a capture, i.e. the ones whose *parse*
#: step ran to completion.
#:
#: This is a safety property, not a tidiness one. ``HOPOPT``'s ``SMF_DPD``
#: constructs perfectly well and then spins forever on the way back in, so its
#: octets are available and putting them in a fixture would produce a capture
#: that wedges every reader of it -- including the rest of this suite. A
#: ``CONSTRUCT`` or ``PARSE`` failure is milder but no more useful: the frame
#: would be one no reader can get through. So a capture carries only frames
#: that are known to parse, and the cases that do not are recorded in
#: :file:`tests/protocols/test_option_roundtrip_unit.py` instead, where a
#: failure is an assertion rather than a hang.
CAPTURABLE = ('OK', 'RECONSTRUCT', 'MISMATCH')

#: Every value :attr:`Outcome.status` can take.
#:
#: * ``'OK'`` -- constructed, parsed, reconstructed, and the octets matched.
#: * ``'CONSTRUCT'`` -- the constructor raised. Note that
#:   :meth:`ProtocolBase.__post_init__` packs *and then* unpacks, so a
#:   ``_read_*`` fault on a perfectly good pack also lands here.
#: * ``'PARSE'`` -- the octets would not parse back.
#: * ``'RECONSTRUCT'`` -- ``_make_*`` could not consume what ``_read_*``
#:   produced. This is the step a construct-then-parse test cannot see.
#: * ``'MISMATCH'`` -- both directions worked and the octets differed.
#: * ``'TIMEOUT'`` -- the case did not finish inside :data:`DEADLINE`.
STATUSES = ('OK', 'CONSTRUCT', 'PARSE', 'RECONSTRUCT', 'MISMATCH', 'TIMEOUT')


class Family(NamedTuple):
    """A registry, and how to exercise the codes in it."""

    #: Family label, copied into every :class:`Case` it yields.
    label: 'str'
    #: Zero-argument callable returning the dispatch registry, or a mapping
    #: standing in for one. Deferred so that importing this module does not
    #: import every protocol in the tree.
    registry: 'Callable[[], Any]'
    #: Zero-argument callable returning per-code keyword overrides, keyed by
    #: registry key. A code absent from the mapping is constructed with no
    #: arguments at all. Deferred for the same reason as :attr:`registry`.
    overrides: 'Callable[[], dict[Any, dict[str, Any]]]'
    #: ``build(code, kwargs)`` -> a constructed protocol carrying exactly one
    #: item of ``code``.
    build: 'Callable[[Any, dict[str, Any]], Any]'
    #: ``parse(octets)`` -> the protocol, parsed back from its own octets.
    parse: 'Callable[[bytes], Any]'
    #: ``extract(parsed)`` -> the parsed collection, in whatever form
    #: :attr:`rebuild` takes.
    extract: 'Callable[[Any], Any]'
    #: ``rebuild(collection)`` -> a protocol constructed from the *parsed*
    #: collection rather than from keyword arguments. This is the step that
    #: catches a ``_make_*`` unable to consume what its own ``_read_*`` made.
    rebuild: 'Callable[[Any], Any]'
    #: Name of the capture this family's frames go into, or :data:`None` for a
    #: family that is exercised but not captured -- see :data:`FAMILIES`.
    capture: 'Optional[str]'
    #: How the octets are wrapped into a frame -- see :func:`_frame`.
    envelope: 'Optional[str]'
    #: Next-layer protocol number for the envelope, where it needs one.
    proto: 'Optional[int]' = None


def sort_key(code: 'Any') -> 'tuple[int, str, int]':
    """Total order over registry keys, stable across runs.

    Registry iteration order is insertion order, which is an implementation
    detail of whichever module last registered a code -- so ordering emitted
    frames by it would let an unrelated import rewrite every capture. This
    orders by the numeric code where there is one, and falls back to the string
    form for the ``(str, int)`` keys of ``PCAPNG.__option__``.

    Args:
        code: Registry key: an enumeration member, an :obj:`int`, or a
            ``(str, int)`` tuple.

    Returns:
        A tuple safe to compare against this function's output for any other
        key, with numeric-keyed codes sorted ahead of tuple-keyed ones.

    """
    if isinstance(code, tuple):
        name, number = code
        return (1, str(name), int(number))
    try:
        return (0, '', int(code))
    except (TypeError, ValueError):  # pragma: no cover
        return (2, str(code), 0)


def handler(registry: 'Any', code: 'Any') -> 'Any':
    """The handler a registry holds for ``code``, without recording a miss.

    Enumerating a registry never needs this -- iterating a
    :class:`collections.defaultdict` touches nothing, which is why :func:`cases`
    only ever iterates. Asking what a *particular* code resolves to does need
    it, because ``registry[code]`` on a miss inserts the key and permanently
    grows a registry shared by every instance of the class in the process. The
    inserted value is whatever the default factory would have produced anyway,
    so it buys nothing and costs a spurious "already registered" warning from
    the next genuine ``register`` call for that code.

    Args:
        registry: A dispatch registry, or a mapping standing in for one.
        code: Registry key to resolve.

    Returns:
        The handler registered for ``code``, or the registry's fallback.

    """
    return ProtocolBase._lookup_registry(registry, code)  # pylint: disable=protected-access


def code_name(code: 'Any') -> 'str':
    """Render a registry key as a name usable in a test id.

    Args:
        code: Registry key.

    Returns:
        ``code.name`` for an enumeration member, ``'<name>_<number>'`` for a
        ``(str, int)`` key, and the plain string form for anything else.

    """
    if isinstance(code, tuple):
        name, number = code
        return f'{name}_{number}'
    return getattr(code, 'name', None) or str(code)


def _named_registry(owner: 'type', enum: 'Any', prefix: 'str',
                    attribute: 'str') -> 'Any':
    """A protocol's dispatch registry, or a stand-in derived from its handlers.

    ``IPv4`` and ``HIP`` were the last two protocols to dispatch their options
    and parameters by attribute name rather than through a registry, and for
    those there was nothing to enumerate. The equivalent source of truth is the
    enumeration crossed with the presence of the handler, which is what this
    builds when the registry is absent.

    GitHub pull request #434 gave both of them a real registry, so the fallback
    is no longer taken for either -- it is kept because it costs nothing and is
    the only thing that would notice a protocol added tomorrow without one. Both
    shapes are a :class:`collections.defaultdict`, so :func:`cases` and
    :func:`handler` cannot tell which one they were given -- and in particular
    :meth:`ProtocolBase._lookup_registry
    <pcapkit.protocols.protocol.ProtocolBase._lookup_registry>` still has a
    ``default_factory`` to fall back on.

    Args:
        owner: Protocol class holding the handler methods.
        enum: Enumeration of wire codes to consider.
        prefix: Handler-name prefix, e.g. ``'_make_opt_'``.
        attribute: Name the real registry would be held under, e.g.
            ``'__option__'``.

    Returns:
        The registry, real or derived.

    """
    existing = getattr(owner, attribute, None)
    if existing is not None:
        return existing

    found = collections.defaultdict(lambda: None)  # type: Any
    for code in enum:
        name = code.name.lower()
        if hasattr(owner, f'{prefix}{name}'):
            found[code] = name
    return found


###############################################################################
# TCP -- options, and Multipath TCP subtypes
###############################################################################

#: Header fields shared by every constructed TCP segment. Only ``options``
#: varies between cases, so a difference in the octets is a difference in the
#: option and nothing else.
#:
#: Every key here has to be spelled the way :meth:`TCP.make
#: <pcapkit.protocols.transport.tcp.TCP.make>` declares it, because ``make``
#: takes ``**kwargs`` and *silently drops* whatever it does not declare -- no
#: ``UnknownFieldWarning``, no ``TypeError``, nothing. GitHub issue #602 is
#: three keys that were spelled wrong and therefore ignored:
#:
#: * ``'seq'`` is ``seq_no``. The mapping read as sequence number 1 and every
#:   generated frame carried 0, which is what made the defect worth an issue:
#:   the captures were not the packets this table describes.
#: * ``'urgent_pointer'`` is ``urgent``. Harmless in effect, since the value
#:   asked for and the default that was used are both 0.
#: * ``'ack_flag'`` is ``ack``, and ``ack`` is the *acknowledgement flag*
#:   rather than the acknowledgement number, which is ``ack_no``. So the two
#:   were the wrong way round: ``'ack': 0`` set the flag (to a falsy 0) and
#:   ``'ack_flag': False`` set nothing at all.
#:
#: The values are unchanged from what the mapping always claimed to mean: a
#: SYN-only segment with sequence number 1, every other flag clear, and the
#: acknowledgement number, checksum and urgent pointer at zero.
TCP_BASE = {
    'srcport': 50000, 'dstport': 80, 'seq_no': 1, 'ack_no': 0,
    'ns': False, 'cwr': False, 'ece': False, 'urg': False, 'ack': False,
    'psh': False, 'rst': False, 'syn': True, 'fin': False,
    'window': 8192, 'checksum': b'\x00\x00', 'urgent': 0,
    'payload': b'',
}


def _tcp_registry() -> 'Any':
    from pcapkit.protocols.transport.tcp import TCP
    return TCP.__option__


def _tcp_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.tcp.option import Option as Enum_Option
    return {
        # Each of these four defaults to an empty variable-length field, which
        # is the one shape that never runs the field's packing loop.
        Enum_Option.SACK: {'sack': [(1, 2), (3, 4)]},
        Enum_Option.TCP_Alternate_Checksum_Data: {'data': b'\x01\x02'},
        Enum_Option.TCP_Authentication_Option: {'mac': b'\x01\x02\x03\x04'},
        Enum_Option.TCP_Fast_Open_Cookie: {'cookie': b'\x01\x02\x03\x04\x05\x06\x07\x08'},
    }


def _tcp_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.transport.tcp import TCP
    return TCP(options=[(code, kwargs)], **TCP_BASE)


def _tcp_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.transport.tcp import TCP
    return TCP(octets, len(octets))


def _tcp_extract(parsed: 'Any') -> 'Any':
    return parsed.info.options


def _tcp_rebuild(options: 'Any') -> 'Any':
    from pcapkit.protocols.transport.tcp import TCP
    return TCP(options=options, **TCP_BASE)


def _mptcp_registry() -> 'Any':
    from pcapkit.protocols.transport.tcp import TCP
    return TCP.__mp_option__


def _mptcp_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
    return {
        Enum_MPTCPOption.MP_CAPABLE: {'skey': 0x0102030405060708},
        Enum_MPTCPOption.DSS: {
            'ack': 1, 'dsn': 2, 'ssn': 3, 'dl_len': 4, 'checksum': b'\x00\x00'},
        Enum_MPTCPOption.ADD_ADDR: {'addr_id': 1, 'addr': '192.0.2.1'},
        Enum_MPTCPOption.REMOVE_ADDR: {'addr_id': [1]},
        Enum_MPTCPOption.MP_PRIO: {'addr_id': 1},
        Enum_MPTCPOption.MP_FAIL: {'dsn': 7},
        Enum_MPTCPOption.MP_FASTCLOSE: {'key': 9},
    }


def _mptcp_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.const.tcp.option import Option as Enum_Option
    from pcapkit.protocols.transport.tcp import TCP

    # The subtype travels as an argument of the enclosing Multipath TCP option
    # rather than as a registry key of its own, so it is spliced in here rather
    # than repeated in every entry of the table above.
    args = dict(kwargs)
    args['subtype'] = code
    return TCP(options=[(Enum_Option.Multipath_TCP, args)], **TCP_BASE)


###############################################################################
# IPv4 -- options
###############################################################################

#: Header fields shared by every constructed IPv4 packet.
IPV4_BASE = {'protocol': 6, 'src': '192.0.2.1', 'dst': '198.51.100.1', 'payload': b''}


def _ipv4_registry() -> 'Any':
    from pcapkit.const.ipv4.option_number import OptionNumber
    from pcapkit.protocols.internet.ipv4 import IPv4
    return _named_registry(IPv4, OptionNumber, '_make_opt_', '__option__')


def _ipv4_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.ipv4.option_number import OptionNumber
    from pcapkit.const.ipv4.protection_authority import ProtectionAuthority
    return {
        # Two authorities rather than one because two bits set in the bitmap say
        # more than one does, not because one is unrepresentable: it used to be,
        # a single ``GENSER`` (value 0) making ``_make_opt_sec`` size a
        # zero-octet bitmap and then index into it for a bare ``IndexError``, and
        # #537 fixed that arithmetic. So this is a coverage choice now and no
        # longer routes around anything.
        OptionNumber.SEC: {'authorities': [ProtectionAuthority.GENSER,
                                           ProtectionAuthority.NSA]},
        # ``counts=10``, the default, needs 43 option octets, which overflows
        # the 4-bit ``ihl``. Nine is the largest an IPv4 header can carry.
        OptionNumber.LSR: {'counts': 9},
        OptionNumber.RR: {'counts': 9},
        OptionNumber.SSR: {'counts': 9},
        # ``timestamp=None``, the default, is rejected outright.
        OptionNumber.TS: {'counts': 1, 'timestamp': [1]},
        OptionNumber.E_SEC: {'info': b'\x00'},
    }


def _ipv4_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.internet.ipv4 import IPv4
    return IPv4(options=[(code, kwargs)], **IPV4_BASE)


def _ipv4_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.internet.ipv4 import IPv4
    return IPv4(octets, len(octets))


def _ipv4_extract(parsed: 'Any') -> 'Any':
    from pcapkit.corekit.multidict import OrderedMultiDict

    # EOOL and NOP are dropped by ``_make_ipv4_options`` as padding, so the
    # header they produce has no options at all and ``info`` carries no
    # ``options`` attribute. An empty collection is the honest reading of that,
    # and it keeps the two padding codes from being reported as parse failures.
    return getattr(parsed.info, 'options', OrderedMultiDict())


def _ipv4_rebuild(options: 'Any') -> 'Any':
    from pcapkit.protocols.internet.ipv4 import IPv4
    return IPv4(options=options, **IPV4_BASE)


###############################################################################
# IPv6 extension headers -- HOPOPT, IPv6-Opts, IPv6-Route
###############################################################################


def _hopopt_registry() -> 'Any':
    from pcapkit.protocols.internet.hopopt import HOPOPT
    return HOPOPT.__option__


def _ipv6_opts_registry() -> 'Any':
    from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
    return IPv6_Opts.__option__


def _ipv6_option_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.ipv6.option import Option as Enum_Option

    # HOPOPT and IPv6-Opts key on the same enumeration and behave identically
    # on every code, so one table serves both.
    return {
        # ``nonce=0`` gives a zero-octet nonce. Only widths 3, 5, 6 and 7 pack
        # at all, because a callable-length NumberField never clears the flag
        # that says "hand struct a bytes"; 0xFFFFFF is three octets.
        Enum_Option.ILNP_Nonce: {'nonce': 0xFFFFFF},
        Enum_Option.Line_Identification_Option: {'id': b'line-1'},
    }


def _hopopt_base() -> 'dict[str, Any]':
    from pcapkit.const.reg.transtype import TransType
    return {'next': TransType.UDP, 'payload': b''}


def _hopopt_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.internet.hopopt import HOPOPT
    return HOPOPT(options=[(code, kwargs)], **_hopopt_base())


def _hopopt_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.internet.hopopt import HOPOPT
    return HOPOPT(octets, len(octets), extension=True)


def _ipv6_extract(parsed: 'Any') -> 'Any':
    from pcapkit.corekit.multidict import OrderedMultiDict
    return getattr(parsed.info, 'options', OrderedMultiDict())


def _hopopt_rebuild(options: 'Any') -> 'Any':
    from pcapkit.protocols.internet.hopopt import HOPOPT
    return HOPOPT(options=options, **_hopopt_base())


def _ipv6_opts_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
    return IPv6_Opts(options=[(code, kwargs)], **_hopopt_base())


def _ipv6_opts_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
    return IPv6_Opts(octets, len(octets), extension=True)


def _ipv6_opts_rebuild(options: 'Any') -> 'Any':
    from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
    return IPv6_Opts(options=options, **_hopopt_base())


def _ipv6_route_registry() -> 'Any':
    from pcapkit.protocols.internet.ipv6_route import IPv6_Route
    return IPv6_Route.__routing__


def _ipv6_route_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.ipv6.routing import Routing as Enum_Routing
    return {
        Enum_Routing.Source_Route: {'ip': ['2001:db8::1', '2001:db8::2']},
        Enum_Routing.Type_2_Routing_Header: {'ip': '2001:db8::2'},
        Enum_Routing.RPL_Source_Route_Header: {'ip': ['2001:db8::1', '2001:db8::2']},
    }


def _ipv6_route_base() -> 'dict[str, Any]':
    from pcapkit.const.reg.transtype import TransType
    return {'next': TransType.UDP, 'seg_left': 0, 'payload': b''}


def _ipv6_route_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.internet.ipv6_route import IPv6_Route
    return IPv6_Route(type=code, data=dict(kwargs), **_ipv6_route_base())


def _ipv6_route_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.internet.ipv6_route import IPv6_Route
    return IPv6_Route(octets, len(octets), extension=True)


def _ipv6_route_extract(parsed: 'Any') -> 'Any':
    # A routing header carries one routing type, not a collection of them, so
    # the "collection" handed on is the message itself.
    return parsed.info


def _ipv6_route_rebuild(info: 'Any') -> 'Any':
    from pcapkit.protocols.internet.ipv6_route import IPv6_Route
    return IPv6_Route(type=info.type, data=info, next=info.next,
                      seg_left=info.seg_left, payload=b'')


###############################################################################
# SCTP -- chunks, parameters and error causes
###############################################################################

#: Header fields shared by every constructed SCTP packet. ``chksum`` is pinned
#: rather than left to the CRC32c path, so a mismatch points at the chunk under
#: test and not at a recomputed checksum.
SCTP_BASE = {
    'srcport': 50000, 'dstport': 80, 'vtag': 0x11223344,
    'chksum': b'\x00\x00\x00\x00',
}


def _sctp_chunk_registry() -> 'Any':
    from pcapkit.protocols.transport.sctp import SCTP
    return SCTP.__chunk__


def _sctp_chunk_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.sctp.cause_code import CauseCode as Enum_CauseCode
    from pcapkit.const.sctp.chunk import Chunk as Enum_Chunk
    from pcapkit.const.sctp.parameter import Parameter as Enum_Parameter

    # The three-octet payloads are deliberate: they make each item's length
    # 3 (mod 4), so every case runs the PaddingField path instead of landing
    # already aligned.
    return {
        # ``data=b''`` is rejected outright -- RFC 9260 s3.3.1 wants at least
        # one octet of user data -- so this override is required, not cosmetic.
        Enum_Chunk.Payload_Data: {'data': b'\x01\x02\x03'},
        Enum_Chunk.Initiation: {
            'parameters': [(Enum_Parameter.State_Cookie, {'cookie': b'\x01\x02\x03'})]},
        Enum_Chunk.Initiation_Acknowledgement: {
            'parameters': [(Enum_Parameter.State_Cookie, {'cookie': b'\x01\x02\x03'})]},
        Enum_Chunk.Selective_Acknowledgement: {'gap_blocks': [(1, 2)], 'dup_tsn': [3]},
        # RFC 9260 s3.3.5 and s3.3.6 mandate exactly one Heartbeat Info
        # parameter, so the default -- none at all -- is structurally invalid.
        Enum_Chunk.Heartbeat_Request: {
            'parameters': [(Enum_Parameter.Heartbeat_Info, {'info': b'\x01\x02\x03'})]},
        Enum_Chunk.Heartbeat_Acknowledgement: {
            'parameters': [(Enum_Parameter.Heartbeat_Info, {'info': b'\x01\x02\x03'})]},
        Enum_Chunk.Abort: {
            'error': [(Enum_CauseCode.User_Initiated_Abort, {'info': b'\x01\x02\x03'})]},
        # ``_make_chunk_error`` documents "one or more error causes"; the
        # default gives zero.
        Enum_Chunk.Operation_Error: {
            'error': [(Enum_CauseCode.Protocol_Violation, {'info': b'\x01\x02\x03'})]},
        Enum_Chunk.State_Cookie: {'cookie': b'\x01\x02\x03'},
    }


def _sctp_chunk_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.transport.sctp import SCTP
    return SCTP(chunks=[(code, kwargs)], **SCTP_BASE)


def _sctp_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.transport.sctp import SCTP
    return SCTP(octets, len(octets))


def _sctp_extract(parsed: 'Any') -> 'Any':
    return parsed.info.chunks


def _sctp_rebuild(chunks: 'Any') -> 'Any':
    from pcapkit.protocols.transport.sctp import SCTP
    return SCTP(chunks=chunks, **SCTP_BASE)


def _sctp_param_registry() -> 'Any':
    from pcapkit.protocols.transport.sctp import SCTP
    return SCTP.__parameter__


def _sctp_param_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.sctp.parameter import Parameter as Enum_Parameter
    return {
        Enum_Parameter.Heartbeat_Info: {'info': b'\x01\x02\x03'},
        Enum_Parameter.IPv4_Address: {'address': '192.0.2.1'},
        Enum_Parameter.IPv6_Address: {'address': '2001:db8::1'},
        Enum_Parameter.State_Cookie: {'cookie': b'\x01\x02\x03'},
        # A complete unrecognised TLV -- type 0xffff, length 5, one value
        # octet -- rather than the empty default, which is not a TLV at all.
        Enum_Parameter.Unrecognized_Parameter: {'value': b'\xff\xff\x00\x05\x01'},
        Enum_Parameter.Host_Name_Address: {'name': b'localhost\x00'},
        Enum_Parameter.Supported_Address_Types: {
            'types': [Enum_Parameter.IPv4_Address, Enum_Parameter.IPv6_Address]},
    }


def _sctp_param_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.const.sctp.chunk import Chunk as Enum_Chunk
    from pcapkit.protocols.transport.sctp import SCTP

    # A parameter is not a top-level item: it travels inside a chunk, and
    # HEARTBEAT is the smallest chunk that carries an arbitrary one.
    return SCTP(chunks=[(Enum_Chunk.Heartbeat_Request,
                         {'parameters': [(code, kwargs)]})], **SCTP_BASE)


def _sctp_cause_registry() -> 'Any':
    from pcapkit.protocols.transport.sctp import SCTP
    return SCTP.__cause__


def _sctp_cause_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.sctp.cause_code import CauseCode as Enum_CauseCode
    from pcapkit.const.sctp.parameter import Parameter as Enum_Parameter
    return {
        Enum_CauseCode.Missing_Mandatory_Parameter: {
            'types': [Enum_Parameter.State_Cookie]},
        # The four causes below carry an embedded TLV, and each one's default
        # is a zero-length value, i.e. not a TLV.
        Enum_CauseCode.Unresolvable_Address: {
            'value': b'\x00\x0b\x00\x0elocalhost\x00'},
        Enum_CauseCode.Unrecognized_Chunk_Type: {'value': b'\xff\x00\x00\x05\x01'},
        Enum_CauseCode.Unrecognized_Parameters: {'value': b'\xff\xff\x00\x05\x01'},
        Enum_CauseCode.Restart_of_an_Association_with_New_Addresses: {
            'value': b'\x00\x05\x00\x08\xc0\x00\x02\x01'},
        Enum_CauseCode.User_Initiated_Abort: {'info': b'\x01\x02\x03'},
        Enum_CauseCode.Protocol_Violation: {'info': b'\x01\x02\x03'},
    }


def _sctp_cause_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.const.sctp.chunk import Chunk as Enum_Chunk
    from pcapkit.protocols.transport.sctp import SCTP

    # An error cause travels inside an ERROR (or ABORT) chunk, under the
    # keyword ``error`` rather than ``causes``.
    return SCTP(chunks=[(Enum_Chunk.Operation_Error,
                         {'error': [(code, kwargs)]})], **SCTP_BASE)


###############################################################################
# Mobility Header -- messages, options and extensions
###############################################################################

#: Header fields shared by every constructed Mobility Header. ``next`` is
#: IPv6-NoNxt, so nothing downstream has to be constructed as well.
MH_BASE = {'next': 59, 'chksum': b'\x00\x00', 'payload': b''}


def _mh_message_registry() -> 'Any':
    from pcapkit.protocols.internet.mh import MH
    return MH.__message__


def _mh_message_overrides() -> 'dict[Any, dict[str, Any]]':
    return {}


def _mh_message_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.internet.mh import MH

    # ``data`` has to be a mapping for ``make`` to dispatch on the message
    # type; a Data object takes the other branch, which is what rebuild uses.
    return MH(type=code, data=dict(kwargs), **MH_BASE)


def _mh_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.internet.mh import MH
    return MH(octets, len(octets), extension=True)


def _mh_message_extract(parsed: 'Any') -> 'Any':
    return parsed.info


def _mh_message_rebuild(message: 'Any') -> 'Any':
    from pcapkit.protocols.internet.mh import MH
    return MH(type=message.type, data=message, **MH_BASE)


def _mh_option_registry() -> 'Any':
    from pcapkit.protocols.internet.mh import MH
    return MH.__option__


def _mh_option_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.mh.ani_suboption import ANISuboption as Enum_ANISuboption
    from pcapkit.const.mh.lma_mag_suboption import \
        LMAControlledMAGSuboption as Enum_LMAControlledMAGSuboption
    from pcapkit.const.mh.option import Option as Enum_Option
    import ipaddress
    return {
        # ``{}`` makes ``_make_opt_pad`` warn and silently emit a Pad1, so the
        # PadN case would otherwise be a duplicate of the Pad1 one.
        Enum_Option.PadN: {'length': 4},
        # The authenticator has to be a multiple of 8 octets.
        Enum_Option.Authorization_Data: {'data': b'\xa5' * 8},
        Enum_Option.Mobility_Header_Link_Layer_Address_option: {
            'address': b'\x00\x11\x22\x33\x44\x55'},
        # ``(len + 6) % 4`` has to be 0.
        Enum_Option.AUTH_OPTION_TYPE: {'data': b'\xa5\xa5'},
        # Without this ``_make_opt_mesg_id`` reads the clock, and the capture
        # would differ on every regeneration.
        Enum_Option.MESG_ID_OPTION_TYPE: {'interval': FIXED_TIME},
        Enum_Option.Signature: {'signature': b'\xaa' * 4},
        Enum_Option.Permanent_Home_Keygen_Token: {'token': b'\xbb' * 8},
        Enum_Option.Experimental_Mobility_Option: {'data': b'\xcc' * 4},
        Enum_Option.Binding_Authorization_Data_for_FMIPv6: {'data': b'\xb5'},
        # The four below are not workarounds for defects: each option has a
        # minimum content its RFC requires, and the no-argument default is not a
        # well-formed instance of it. The constructors refuse it, correctly, so
        # the arguments here are what make the code reachable at all.
        #
        # ``Length`` of 0 "is not allowed" and the identifier is 1-255 octets
        # [RFC 5149 section 3]. ``'ims'`` is that RFC's own example.
        Enum_Option.Service_Selection_Mobility_Option: {'identifier': 'ims'},
        # "Both the 'K' and 'N' flags cannot be set or unset simultaneously"
        # [RFC 6463 section 4.2], so exactly one address is present and the
        # option is 18 octets long for IPv6 or 6 for IPv4. With neither given
        # the option's own length is undetermined.
        Enum_Option.Redirect_Mobility_Option: {
            'ipv6': ipaddress.IPv6Address('2001:db8::1')},
        # The option "MUST contain at least one ANI sub-option"
        # [RFC 6757 section 3]; it is a pure container and carries nothing else.
        Enum_Option.Access_Network_Identifier: {
            'suboptions': [(Enum_ANISuboption.Network_Identifier,
                            {'net_name': b'wifi',
                             'ap_name': b'\x00\x11\x22\x33\x44\x55'})]},
        # Likewise at least one LCMP sub-option [RFC 8127 section 3].
        Enum_Option.LMA_Controlled_MAG_Parameters: {
            'suboptions': [(Enum_LMAControlledMAGSuboption.Heartbeat_Control,
                            {'interval': 60, 'retransmission_delay': 3,
                             'max_retransmissions': 5})]},
    }


def _mh_carrier() -> 'Any':
    from pcapkit.const.mh.packet import Packet as Enum_Packet

    # Binding Refresh Request is the smallest message that carries an
    # arbitrary option list: two reserved octets and then the options.
    return Enum_Packet.Binding_Refresh_Request


def _mh_option_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.internet.mh import MH
    return MH(type=_mh_carrier(), data={'options': [(code, dict(kwargs))]}, **MH_BASE)


def _mh_option_extract(parsed: 'Any') -> 'Any':
    from pcapkit.corekit.multidict import OrderedMultiDict
    return getattr(parsed.info, 'options', OrderedMultiDict())


def _mh_option_rebuild(options: 'Any') -> 'Any':
    from pcapkit.protocols.internet.mh import MH
    return MH(type=_mh_carrier(), data={'options': options}, **MH_BASE)


def _mh_extension_registry() -> 'Any':
    from pcapkit.protocols.internet.mh import MH
    return MH.__extension__


def _mh_extension_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.mh.cga_extension import CGAExtension as Enum_CGAExtension
    return {Enum_CGAExtension.Multi_Prefix: {'prefixes': [0x20010db800000001]}}


def _mh_extension_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.const.mh.cga_type import CGAType as Enum_CGAType
    from pcapkit.const.mh.option import Option as Enum_Option
    from pcapkit.protocols.data.internet.mh import CGAParameter as Data_CGAParameter
    from pcapkit.protocols.internet.mh import MH

    # A CGA extension has exactly one carrier: the ``extensions`` list of a CGA
    # parameter, inside a CGA Parameters option. It has to be a *Data* model
    # rather than a schema, because ``_make_opt_cga_param`` keeps only the
    # length of the extensions it builds for a schema and throws the schemas
    # themselves away.
    # The data model annotates ``modifier`` as a CGAType and ``extensions`` as an
    # already-built OrderedMultiDict, but the constructor this feeds takes the
    # tuple form and resolves both -- so the arguments go through an untyped
    # mapping rather than being spelled as keywords a checker would reject.
    fields = {
        'modifier': Enum_CGAType.Tag_086F_CA5E_10B2_00C9_9C8C_E001_6427_7C08,
        'prefix': 0x20010db800000000,
        'collision_count': 0,
        'public_key': b'\x30\x02\xaa\xbb',
        'extensions': [(code, dict(kwargs))],
    }  # type: dict[str, Any]
    parameter = Data_CGAParameter(**fields)
    return MH(type=_mh_carrier(),
              data={'options': [(Enum_Option.CGA_Parameters,
                                 {'parameters': [parameter]})]},
              **MH_BASE)


###############################################################################
# HIP -- parameters
###############################################################################

#: Header fields shared by every constructed HIP packet.
HIP_BASE = {
    'next': 6, 'packet': 1, 'version': 2, 'checksum': b'\x00\x00',
    'controls_anonymous': False, 'shit': 0, 'rhit': 0, 'payload': b'',
}

#: Codes that are HIPv1-only, and the version their constructor demands.
HIP_VERSION = {129: 2, 128: 1}

#: How many copies of the parameter under test go in one packet.
#:
#: One, since #689. This note used to be a history of why the constant was two;
#: it is now the history of why it no longer is.
#:
#: It was two because of the defect #651 fixed. ``HIP.make`` computes the
#: header's ``len`` field as ``total_length // 8 + 4``, which is lossless only
#: when the parameter octets are a multiple of eight; and every padding site in
#: the two HIP modules aligned the *contents* to eight, ignoring the four-octet
#: type-and-length header, so a single parameter was always ``4 (mod 8)``, the
#: floor division always dropped those four octets, and ``_read_hip_param``
#: -- which compares the recovered length exactly -- rejected the library's own
#: single-parameter packets. Two copies summed to a multiple of eight, so the
#: arithmetic came out exact and the parameter constructors became reachable.
#: #651 made the padding :rfc:`7401` Section 5.2.1's
#: ``Total Length = 11 + Length - (Length + 3) % 8``, so each parameter is a
#: multiple of eight on its own and the pair stopped being needed for that --
#: measured at the time as 45 OK of 49 at one copy against 46 at two.
#:
#: What kept the pair afterwards was a short list of codes whose own packed
#: length disagreed with the ``len`` they declared, so their record was not
#: 8-aligned however the padding was computed, and a pair cancelled that
#: misalignment the same way the pre-#651 padding rule once did. #672 and #679
#: closed two of those -- ``R1_COUNTER`` (129), whose 8-octet :rfc:`7401`
#: Section 5.2.3 counter had packed as four, and ``LOCATOR_SET`` (193), whose
#: ``Length`` had been counted in 4-octet units where the RFC counts bytes --
#: which is what moved the one-copy figure from 44 to 46, level with two copies.
#:
#: Two remain, neither helped by a second copy since each fails at two copies
#: as well as at one:
#:
#: * ``HOST_ID`` declares ``len=8`` and packs 18. Recorded as
#:   ``hip-parameter/HOST_ID``.
#: * ``HIP_TRANSFORM`` is HIPv1-only -- ``_read_param_hip_transform`` raises for
#:   any other version -- while this table builds it at version 2. Recorded as
#:   ``hip-parameter/HIP_TRANSFORM``.
#:
#: A third gap here, ``R1_Counter`` (128), was closed separately by #690 and was
#: never one of the pair's cancellations above: it parsed as an
#: ``UnassignedParameter`` because the *schema* registry is keyed on the
#: ``code=`` of the class statement and ``R1CounterParameter`` declared only
#: 129 -- even though ``__parameter__``'s ``_read_param_*``/``_make_param_*``
#: entries already existed for both codes, as two hand-written dict entries,
#: not because of any name-normalisation rule. No longer recorded as of #690,
#: which registered ``R1CounterParameter`` for 128 too.
#:
#: So the pair was routing around nothing by the time #672, #679 and #690 had
#: all landed, and dropping to one copy does not change what round-trips.
#: Measured over this table's 49 HIP codes on ``5f0a1aa90`` (after #696, which
#: #689 itself waited on -- see the issue) and again after #690:
#:
#: ======================  ========  ==========
#: tree                    one copy  two copies
#: ======================  ========  ==========
#: ``5f0a1aa90``           46 OK     46 OK
#: after #690              47 OK     47 OK
#: ======================  ========  ==========
#:
#: The two gaps above are the only cases either setting fails, and neither
#: their ``status`` nor their ``defect`` moves between settings, so
#: :data:`tests.protocols.test_option_roundtrip_unit.EXPECTED_FAILURES` needed no
#: change to keep recording them accurately at one copy.
#:
#: The single-parameter case is asserted directly, and positively, by
#: ``test_a_hip_packet_carrying_one_parameter_round_trips`` in
#: :mod:`tests.protocols.test_option_roundtrip_unit`, which is also where the
#: two-copy shape is still exercised now that this constant no longer produces
#: it.
HIP_COPIES = 1


def _hip_registry() -> 'Any':
    from pcapkit.const.hip.parameter import Parameter
    from pcapkit.protocols.internet.hip import HIP
    return _named_registry(HIP, Parameter, '_make_param_', '__parameter__')


def _hip_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.hip.ecdsa_curve import ECDSACurve
    from pcapkit.const.hip.parameter import Parameter
    return {
        # ``lifetime=0`` reaches ``math.log2(0)``.
        Parameter.PUZZLE: {'lifetime': 1},
        Parameter.SOLUTION: {'lifetime': 1},
        # ``hi_curve=None`` falls through to an explicit raise.
        Parameter.HOST_ID: {'hi_curve': ECDSACurve.NIST_P_256},
        # These two are not here because the default fails -- ``counter=0``
        # constructs and parses perfectly well. They are here because a
        # zero-valued field cannot discriminate a width defect from a correct
        # one, and this parameter's width defect (#672) hid behind exactly that
        # for as long as it did. The RFC-only walk over
        # ``options-internet.pcap`` -- which takes its stride solely from
        # :rfc:`7401` Section 5.2.1's ``Total Length = 11 + Length - (Length +
        # 3) % 8`` -- read ``Length = 12``, advanced 16 over a 12-octet record,
        # landed four octets inside the second copy, and found a phantom
        # ``Type = 0, Length = 0`` record there whose "padding" was four zero
        # octets. Every octet it mis-read was zero, so its zero-padding check
        # passed and it reported no violation. Measured: patching one counter to
        # ``aabbccdd`` turned that silence into ``type 0 padding not zeroed:
        # aabbccdd``. With a non-zero counter the fixture can no longer conceal
        # a mis-stride here, whether or not the width is right -- which is the
        # reason to keep this override now that #672 has corrected the width.
        Parameter.R1_COUNTER: {'counter': 0xaabbccdd},
        Parameter.R1_Counter: {'counter': 0xaabbccdd},
    }


def _hip_base(code: 'Any') -> 'dict[str, Any]':
    base = dict(HIP_BASE)
    base['version'] = HIP_VERSION.get(int(code), 2)
    return base


def _hip_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.internet.hip import HIP

    # ``extension=True`` is not decoration. ``HIP.alias`` reads ``self._info``,
    # which ``__post_init__`` only assigns after ``read`` returns, and the sole
    # path that returns before touching it is the ``if extension`` early exit.
    # Without it every one of the 49 codes fails with ``AttributeError: 'HIP'
    # object has no attribute '_info'``.
    return HIP(parameters=[(code, kwargs)] * HIP_COPIES,
               extension=True, **_hip_base(code))


def _hip_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.internet.hip import HIP
    return HIP(octets, len(octets), extension=True)


def _hip_extract(parsed: 'Any') -> 'Any':
    from pcapkit.corekit.multidict import OrderedMultiDict
    return getattr(parsed.info, 'parameters', OrderedMultiDict())


def _hip_rebuild(parameters: 'Any') -> 'Any':
    from pcapkit.protocols.internet.hip import HIP

    # ``parameters`` is the parsed collection, so the version has to come off
    # one of its members rather than from the code being tested.
    first = next(iter(parameters), None)
    base = dict(HIP_BASE)
    if first is not None:
        base['version'] = HIP_VERSION.get(int(first), 2)
    return HIP(parameters=parameters, extension=True, **base)


###############################################################################
# HTTP/2 -- frames
###############################################################################


def _httpv2_registry() -> 'Any':
    from pcapkit.protocols.application.httpv2 import HTTP
    return HTTP.__frame__


def _httpv2_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.http.frame import Frame as Enum_Frame
    from pcapkit.const.http.setting import Setting as Enum_Setting
    return {
        # ``settings=None``, the default, matches none of the accepted forms.
        Enum_Frame.SETTINGS: {'settings': [(Enum_Setting.HEADER_TABLE_SIZE, 4096)]},
        Enum_Frame.GOAWAY: {'debug_data': b'\xde\xad'},
    }


def _httpv2_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.application.httpv2 import HTTP

    # SETTINGS and PING both reject a non-zero stream identifier, so every
    # frame uses stream 0 rather than each one picking its own.
    return HTTP(type=code, sid=0, frame=dict(kwargs))


def _httpv2_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.application.httpv2 import HTTP
    return HTTP(octets, len(octets))


def _httpv2_extract(parsed: 'Any') -> 'Any':
    return parsed.info


def _httpv2_rebuild(frame: 'Any') -> 'Any':
    from pcapkit.protocols.application.httpv2 import HTTP

    # ``flags`` is deliberately not passed on: ``HTTP.make`` rebinds it from
    # the ``_make_http_*`` return whenever ``frame`` is a mapping or a Data
    # object, so passing it would be silently ignored.
    return HTTP(type=frame.type, sid=frame.sid, frame=frame)


###############################################################################
# PCAP-NG -- blocks, block options, name records and decryption secrets
###############################################################################
#
# These four families are exercised by :func:`roundtrip` but deliberately write
# no capture, and the reason is not that a PCAP-NG capture would be
# uninteresting -- it is that the construction API cannot produce a
# *reproducible* one. ``_make_block_shb`` takes the section's byte order from
# :data:`sys.byteorder` with no way to override it, and the TLS and WireGuard
# key-log writers stamp :meth:`datetime.datetime.now` into the block body with
# no keyword to pin it. A fixture built this way would differ between a
# little-endian and a big-endian host, and the two key-log types would differ
# between one run and the next.
#
# The PCAP-NG option space is not left uncovered by that decision:
# :file:`examples/generators/pcapng.py` already builds ``profile.pcapng``,
# ``test.pcapng`` and ``many_interfaces.pcapng`` over it, hand-rolling every
# octet with :func:`struct.pack` for exactly this reason. What is added here is
# the half that generator cannot reach, since it never calls the construction
# API at all: whether ``_make_block_*`` and ``_make_option_*`` can produce what
# ``_read_block_*`` and ``_read_option_*`` consume.

#: Fixed PCAP-NG timestamp, the same instant :file:`pcapng.py` uses. Not
#: optional: leaving ``timestamp`` unset reaches ``self._info`` before
#: ``__post_init__`` has assigned it, so the "now" default is unreachable as
#: well as non-deterministic.
PCAPNG_TIME = 1500000000

#: A minimal Ethernet frame for the packet-carrying blocks: destination and
#: source address, an unassigned EtherType, and two octets of body.
#:
#: It has to be non-empty. A ``PayloadField`` whose computed length is
#: legitimately zero reads the whole remainder of the block instead of nothing,
#: which swallows the option area -- so an empty packet would silently take the
#: whole ``epb_*`` and ``pack_*`` option space with it. Sixteen octets rather
#: than the bare 14-octet header, so the Ethernet dissector does not under-run.
#: 6 octets of destination, 6 of source, the EtherType, then the body.
PCAPNG_PACKET = bytes.fromhex('02000000000102000000000288b50000')

#: A systemd journal export entry whose length is a multiple of four.
#: ``_make_block_systemd`` adds no padding, unlike every other block, so an
#: unaligned entry makes the block length invalid.
PCAPNG_JOURNAL = (b'__REALTIME_TIMESTAMP=1500000000000000\n_TRANSPORT=journal\n'
                  b'PRIORITY=6\nMESSAGE=probe.....\n\n')


def _pcapng_context() -> 'tuple[Any, Any]':
    """A one-section PCAP-NG context with one Ethernet interface in it.

    Every block other than a Section Header Block is read and written relative
    to a section, and the packet-carrying blocks resolve their snap length
    through the section's interface list, so there has to be one.

    Returns:
        The :class:`~pcapkit.foundation.engines.pcapng.Context` and the
        interface-description block registered in it.

    """
    from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType
    from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
    from pcapkit.foundation.engines.pcapng import Context
    from pcapkit.protocols.misc.pcapng import PCAPNG

    section = PCAPNG(num=0, sct=1, ctx=None,
                     type=Enum_BlockType.Section_Header_Block, block={})
    # ``Protocol.info`` is annotated as the generic data model for the protocol,
    # so a checker cannot see that a Section Header Block's is the one ``Context``
    # wants. The engine does exactly this, at
    # pcapkit/foundation/engines/pcapng.py:148.
    section_info = section.info  # type: Any
    context = Context(section_info)
    interface = PCAPNG(num=1, sct=1, ctx=context,
                       type=Enum_BlockType.Interface_Description_Block,
                       block={'linktype': Enum_LinkType.ETHERNET, 'snaplen': 0x40000})
    interface_info = interface.info  # type: Any
    context.interfaces.append(interface_info)
    return context, interface_info


def _pcapng_block(code: 'Any', block: 'dict[str, Any] | Any') -> 'Any':
    """Construct one PCAP-NG block of ``code``.

    A fresh context per call, deliberately. ``PCAPNG.__post_init__`` packs and
    then re-reads *on the same instance*, and the two halves share the
    per-instance option counter, so state left by one case would change the
    next one's result.

    Args:
        code: Block type.
        block: Block body, as a mapping of constructor arguments or as the
            parsed data model.

    Returns:
        The constructed block.

    """
    from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType
    from pcapkit.protocols.misc.pcapng import PCAPNG

    # A Section Header Block is what *starts* a section, so it is the one block
    # the engine reads with no context at all.
    context = None if code == Enum_BlockType.Section_Header_Block else _pcapng_context()[0]
    return PCAPNG(num=2, sct=1, ctx=context, type=code, block=block)


#: Block type of a Section Header Block, as it appears on the wire. The value
#: is byte-order independent by design -- that is what lets a reader work out a
#: section's endianness -- so it can be recognised before the byte order is
#: known, which is exactly what :func:`_pcapng_parse` needs.
PCAPNG_SHB_MAGIC = bytes.fromhex('0a0d0d0a')


def _pcapng_parse(octets: 'bytes') -> 'Any':
    """Parse one PCAP-NG block back from its own octets.

    The block type is read out of the octets rather than passed in, so that
    this keeps the one-argument shape every other family's ``parse`` has. It is
    the first four octets of any block, and a Section Header Block -- the one
    block read with no section context, because it is what *starts* a
    section -- is recognisable by :data:`PCAPNG_SHB_MAGIC`.

    Args:
        octets: The constructed block.

    Returns:
        The parsed block.

    """
    from pcapkit.protocols.misc.pcapng import PCAPNG

    context = None if octets[:4] == PCAPNG_SHB_MAGIC else _pcapng_context()[0]
    return PCAPNG(octets, len(octets), num=2, sct=1, ctx=context)


def _pcapng_block_registry() -> 'Any':
    from pcapkit.protocols.misc.pcapng import PCAPNG
    return PCAPNG.__block__


def _pcapng_block_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType
    from pcapkit.const.pcapng.record_type import RecordType as Enum_RecordType
    from pcapkit.const.pcapng.secrets_type import SecretsType as Enum_SecretsType
    from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
    return {
        Enum_BlockType.Interface_Description_Block: {
            'linktype': Enum_LinkType.ETHERNET, 'snaplen': 0x40000},
        Enum_BlockType.Enhanced_Packet_Block: {
            'timestamp': PCAPNG_TIME, 'packet_data': PCAPNG_PACKET},
        Enum_BlockType.Simple_Packet_Block: {'packet_data': PCAPNG_PACKET},
        # Without the terminating record the records field consumes the whole
        # block and the option area disappears.
        Enum_BlockType.Name_Resolution_Block: {
            'records': [(Enum_RecordType.nrb_record_end, {})]},
        Enum_BlockType.Interface_Statistics_Block: {'timestamp': PCAPNG_TIME},
        Enum_BlockType.systemd_Journal_Export_Block: {'entries': PCAPNG_JOURNAL},
        # ZigBee rather than the default TLS key log, whose writer stamps the
        # current time into the body and so can never round-trip.
        Enum_BlockType.Decryption_Secrets_Block: {
            'secrets_type': Enum_SecretsType.ZigBee_NWK_Key,
            'secrets_data': {'nwk_key': bytes(range(16)), 'pan_id': 0x1234}},
        Enum_BlockType.Custom_Block_that_rewriters_can_copy_into_new_files: {
            'pen': 32473, 'data': b'\x01\x02\x03\x04'},
        Enum_BlockType.Custom_Block_that_rewriters_should_not_copy_into_new_files: {
            'pen': 32473, 'data': b'\x01\x02\x03\x04'},
        Enum_BlockType.Packet_Block: {
            'timestamp': PCAPNG_TIME, 'packet_data': PCAPNG_PACKET},
    }


def _pcapng_block_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    return _pcapng_block(code, dict(kwargs))


def _pcapng_block_extract(parsed: 'Any') -> 'Any':
    return parsed.info


def _pcapng_block_rebuild(info: 'Any') -> 'Any':
    return _pcapng_block(info.type, info)


#: Which block hosts each block-option namespace, and that host's own
#: arguments. The namespace is the part of the ``_option_key`` tuple's first
#: element before the first underscore.
PCAPNG_OPTION_HOSTS = {
    'opt': 'Section_Header_Block',
    'if': 'Interface_Description_Block',
    'epb': 'Enhanced_Packet_Block',
    'ns': 'Name_Resolution_Block',
    'isb': 'Interface_Statistics_Block',
    'pack': 'Packet_Block',
}


def _pcapng_option_registry() -> 'Any':
    from pcapkit.protocols.misc.pcapng import PCAPNG
    return PCAPNG.__option__


def _pcapng_option_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.pcapng.option_type import OptionType as Enum_OptionType
    from pcapkit.protocols.misc.pcapng import _option_key
    return {
        _option_key(Enum_OptionType.opt_comment): {'comment': 'probe'},
        _option_key(Enum_OptionType.opt_custom_2988): {'pen': 32473, 'data': b'\x01\x02\x03\x04'},
        _option_key(Enum_OptionType.opt_custom_2989): {'pen': 32473, 'data': b'\x01\x02\x03\x04'},
        _option_key(Enum_OptionType.opt_custom_19372): {'pen': 32473, 'data': b'\x01\x02\x03\x04'},
        _option_key(Enum_OptionType.opt_custom_19373): {'pen': 32473, 'data': b'\x01\x02\x03\x04'},
        _option_key(Enum_OptionType.if_name): {'name': 'eth0'},
        _option_key(Enum_OptionType.if_description): {'description': 'probe interface'},
        _option_key(Enum_OptionType.if_IPv4addr): {'interface': '10.0.0.1/255.255.255.0'},
        _option_key(Enum_OptionType.if_IPv6addr): {
            'interface': '2001:db8:85a3:8d3:1319:8a2e:370:7344/64'},
        _option_key(Enum_OptionType.if_MACaddr): {'interface': '02:00:00:00:00:01'},
        _option_key(Enum_OptionType.if_EUIaddr): {'interface': '02:00:00:FF:FE:00:00:01'},
        _option_key(Enum_OptionType.if_speed): {'speed': 1000000000},
        _option_key(Enum_OptionType.if_tsresol): {'resolution': 1000000},
        _option_key(Enum_OptionType.if_tzone): {'tzone': 0},
        _option_key(Enum_OptionType.if_filter): {'expression': b'udp port 67'},
        # ``if_os`` and ``if_hardware`` default to the live platform strings, so
        # leaving them unset would make the case machine-dependent.
        _option_key(Enum_OptionType.if_os): {'os': 'probe OS'},
        _option_key(Enum_OptionType.if_hardware): {'hardware': 'probe adapter'},
        _option_key(Enum_OptionType.if_fcslen): {'fcs_length': 4},
        _option_key(Enum_OptionType.if_tsoffset): {'offset': 0},
        _option_key(Enum_OptionType.if_txspeed): {'speed': 1000000000},
        _option_key(Enum_OptionType.if_rxspeed): {'speed': 1000000000},
        _option_key(Enum_OptionType.epb_hash): {'hash': b'\x01\x02\x03\x04'},
        _option_key(Enum_OptionType.epb_verdict): {'value': b'\x01'},
        _option_key(Enum_OptionType.ns_dnsname): {'name': 'resolver.example'},
        _option_key(Enum_OptionType.ns_dnsIP4addr): {'ip': '10.0.0.53'},
        # The default is the IPv4 literal ``'8.8.8.8'``, which the v6 field
        # rejects outright.
        _option_key(Enum_OptionType.ns_dnsIP6addr): {'ip': '2001:db8::35'},
        _option_key(Enum_OptionType.isb_starttime): {'timestamp': PCAPNG_TIME},
        _option_key(Enum_OptionType.isb_endtime): {'timestamp': PCAPNG_TIME},
        _option_key(Enum_OptionType.isb_ifrecv): {'packets': 4},
        _option_key(Enum_OptionType.isb_ifdrop): {'packets': 1},
        _option_key(Enum_OptionType.isb_filteraccept): {'packets': 4},
        _option_key(Enum_OptionType.isb_osdrop): {'packets': 0},
        _option_key(Enum_OptionType.isb_usrdeliv): {'packets': 3},
        _option_key(Enum_OptionType.pack_hash): {'hash': b'\x01\x02\x03\x04'},
    }


def _pcapng_option_enum(key: 'Any') -> 'Any':
    """The enumeration member behind an ``_option_key`` tuple.

    ``PCAPNG.__option__`` is keyed by ``(name, value)`` tuples because the same
    numeric option code means different things in different block types, but
    the construction API takes the enumeration member.

    Args:
        key: The ``(str, int)`` registry key.

    Returns:
        The matching :class:`~pcapkit.const.pcapng.option_type.OptionType`.

    Raises:
        KeyError: If no member matches, which would mean the registry and the
            enumeration have diverged.

    """
    from pcapkit.const.pcapng.option_type import OptionType as Enum_OptionType
    from pcapkit.protocols.misc.pcapng import _option_key

    # The enumeration is an :mod:`aenum` one, whose metaclass does not advertise
    # ``__iter__`` to a type checker even though it iterates perfectly well.
    members = Enum_OptionType  # type: Any
    for member in members:
        if _option_key(member) == key:
            return member
    raise KeyError(f'no OptionType matches registry key {key!r}')


def _pcapng_option_host(key: 'Any') -> 'tuple[Any, dict[str, Any]]':
    """The block type that carries option ``key``, and its own arguments."""
    from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType

    namespace = str(key[0]).split('_', 1)[0]
    name = PCAPNG_OPTION_HOSTS[namespace]
    code = getattr(Enum_BlockType, name)
    return code, dict(_pcapng_block_overrides().get(code, {}))


def _pcapng_option_build(key: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    code, block = _pcapng_option_host(key)
    block['options'] = [(_pcapng_option_enum(key), dict(kwargs))]
    return _pcapng_block(code, block)


def _pcapng_option_rebuild(info: 'Any') -> 'Any':
    """Rebuild an option's host block, taking only the options from the parse.

    The host's own fields come from :func:`_pcapng_block_overrides` rather than
    from the parsed block, and that is the point. Reconstructing the whole block
    from ``info`` would drop the captured payload of a packet-carrying block --
    ``_make_block_epb`` and its siblings never restore ``packet_data``, and the
    data model has nowhere to keep it -- so every ``epb_*`` and ``pack_*``
    option would be reported as a mismatch on account of a defect that has
    nothing to do with the option. Re-supplying the host fields isolates the
    option, which is what this family is measuring.

    Args:
        info: The parsed block.

    Returns:
        The reconstructed block.

    """
    block = dict(_pcapng_block_overrides().get(info.type, {}))
    block['options'] = info.options
    return _pcapng_block(info.type, block)


def _pcapng_record_registry() -> 'Any':
    from pcapkit.protocols.misc.pcapng import PCAPNG
    return PCAPNG.__record__


def _pcapng_record_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.pcapng.record_type import RecordType as Enum_RecordType
    return {
        Enum_RecordType.nrb_record_ipv4: {'ip': '10.0.0.1', 'names': ['gateway.example']},
        # The default is the IPv4 literal ``'127.0.0.1'``, which the v6 field
        # rejects outright.
        Enum_RecordType.nrb_record_ipv6: {'ip': '2001:db8::1', 'names': ['v6.example']},
    }


def _pcapng_record_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType
    from pcapkit.const.pcapng.record_type import RecordType as Enum_RecordType

    records = [(code, dict(kwargs))]
    if code != Enum_RecordType.nrb_record_end:
        # A record list has to be terminated, or the records field eats the
        # rest of the block.
        records.append((Enum_RecordType.nrb_record_end, {}))
    return _pcapng_block(Enum_BlockType.Name_Resolution_Block, {'records': records})


def _pcapng_record_extract(parsed: 'Any') -> 'Any':
    return parsed.info.records


def _pcapng_record_rebuild(records: 'Any') -> 'Any':
    from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType
    return _pcapng_block(Enum_BlockType.Name_Resolution_Block, {'records': records})


def _pcapng_secrets_registry() -> 'Any':
    from pcapkit.protocols.misc.pcapng import PCAPNG
    return PCAPNG.__secrets__


def _pcapng_secrets_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.pcapng.secrets_type import SecretsType as Enum_SecretsType
    from pcapkit.corekit.multidict import OrderedMultiDict
    from pcapkit.protocols.misc.pcapng import TLSKeyLabel, WireGuardKeyLabel
    return {
        Enum_SecretsType.TLS_Key_Log: {
            'entries': {TLSKeyLabel.CLIENT_RANDOM: OrderedMultiDict(
                [(bytes(range(0x20, 0x40)), bytes(range(0x40, 0x70)))])}},
        Enum_SecretsType.WireGuard_Key_Log: {
            'entries': OrderedMultiDict(
                [(WireGuardKeyLabel.LOCAL_STATIC_PRIVATE_KEY, bytes(range(32)))])},
        Enum_SecretsType.ZigBee_NWK_Key: {'nwk_key': bytes(range(16)), 'pan_id': 0x1234},
        Enum_SecretsType.ZigBee_APS_Key: {
            'aps_key': bytes(range(16)), 'pan_id': 0x1234, 'short_address': 0xABCD},
    }


def _pcapng_secrets_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType
    return _pcapng_block(Enum_BlockType.Decryption_Secrets_Block,
                         {'secrets_type': code, 'secrets_data': dict(kwargs)})


###############################################################################
# The families, and the cycle
###############################################################################

#: Every family this module exercises, in the order their frames are emitted.
FAMILIES = (
    Family('tcp-option', _tcp_registry, _tcp_overrides,
           _tcp_build, _tcp_parse, _tcp_extract, _tcp_rebuild,
           capture='options-tcp.pcap', envelope='ipv4', proto=6),
    Family('tcp-mptcp', _mptcp_registry, _mptcp_overrides,
           _mptcp_build, _tcp_parse, _tcp_extract, _tcp_rebuild,
           capture='options-tcp.pcap', envelope='ipv4', proto=6),
    Family('ipv4-option', _ipv4_registry, _ipv4_overrides,
           _ipv4_build, _ipv4_parse, _ipv4_extract, _ipv4_rebuild,
           capture='options-ipv4.pcap', envelope='ethernet-ipv4'),
    Family('hopopt-option', _hopopt_registry, _ipv6_option_overrides,
           _hopopt_build, _hopopt_parse, _ipv6_extract, _hopopt_rebuild,
           capture='options-ipv6.pcap', envelope='ipv6', proto=0),
    Family('ipv6-opts-option', _ipv6_opts_registry, _ipv6_option_overrides,
           _ipv6_opts_build, _ipv6_opts_parse, _ipv6_extract, _ipv6_opts_rebuild,
           capture='options-ipv6.pcap', envelope='ipv6', proto=60),
    Family('ipv6-route-type', _ipv6_route_registry, _ipv6_route_overrides,
           _ipv6_route_build, _ipv6_route_parse, _ipv6_route_extract,
           _ipv6_route_rebuild,
           capture='options-ipv6.pcap', envelope='ipv6', proto=43),
    Family('sctp-chunk', _sctp_chunk_registry, _sctp_chunk_overrides,
           _sctp_chunk_build, _sctp_parse, _sctp_extract, _sctp_rebuild,
           capture='options-transport.pcap', envelope='ipv4', proto=132),
    Family('sctp-parameter', _sctp_param_registry, _sctp_param_overrides,
           _sctp_param_build, _sctp_parse, _sctp_extract, _sctp_rebuild,
           capture='options-transport.pcap', envelope='ipv4', proto=132),
    Family('sctp-cause', _sctp_cause_registry, _sctp_cause_overrides,
           _sctp_cause_build, _sctp_parse, _sctp_extract, _sctp_rebuild,
           capture='options-transport.pcap', envelope='ipv4', proto=132),
    Family('httpv2-frame', _httpv2_registry, _httpv2_overrides,
           _httpv2_build, _httpv2_parse, _httpv2_extract, _httpv2_rebuild,
           capture='options-transport.pcap', envelope='tcp'),
    Family('mh-message', _mh_message_registry, _mh_message_overrides,
           _mh_message_build, _mh_parse, _mh_message_extract, _mh_message_rebuild,
           capture='options-internet.pcap', envelope='ipv6', proto=135),
    Family('mh-option', _mh_option_registry, _mh_option_overrides,
           _mh_option_build, _mh_parse, _mh_option_extract, _mh_option_rebuild,
           capture='options-internet.pcap', envelope='ipv6', proto=135),
    Family('mh-extension', _mh_extension_registry, _mh_extension_overrides,
           _mh_extension_build, _mh_parse, _mh_option_extract, _mh_option_rebuild,
           capture='options-internet.pcap', envelope='ipv6', proto=135),
    Family('hip-parameter', _hip_registry, _hip_overrides,
           _hip_build, _hip_parse, _hip_extract, _hip_rebuild,
           capture='options-internet.pcap', envelope='ipv6', proto=139),
    # The four PCAP-NG families write no capture -- see the section comment
    # above ``PCAPNG_TIME`` for why the construction API cannot make a
    # reproducible one, and what already covers that space instead.
    Family('pcapng-block', _pcapng_block_registry, _pcapng_block_overrides,
           _pcapng_block_build, _pcapng_parse, _pcapng_block_extract,
           _pcapng_block_rebuild, capture=None, envelope=None),
    # Both of these reconstruct from the parsed *block* rather than from the
    # option or secrets collection alone, because neither collection records
    # which block type carried it -- but the option family re-supplies the
    # host's own fields on the way, for the reason ``_pcapng_option_rebuild``
    # gives.
    Family('pcapng-option', _pcapng_option_registry, _pcapng_option_overrides,
           _pcapng_option_build, _pcapng_parse, _pcapng_block_extract,
           _pcapng_option_rebuild, capture=None, envelope=None),
    Family('pcapng-record', _pcapng_record_registry, _pcapng_record_overrides,
           _pcapng_record_build, _pcapng_parse, _pcapng_record_extract,
           _pcapng_record_rebuild, capture=None, envelope=None),
    Family('pcapng-secrets', _pcapng_secrets_registry, _pcapng_secrets_overrides,
           _pcapng_secrets_build, _pcapng_parse, _pcapng_block_extract,
           _pcapng_block_rebuild, capture=None, envelope=None),
)

#: The families keyed by label, for a caller that wants just one.
FAMILY_MAP = {family.label: family for family in FAMILIES}

#: Codes deliberately left out of the case list, with the reason.
#:
#: The padding options are dropped by every ``_make_*_options`` in the tree --
#: it discards them and inserts its own padding to reach the alignment the
#: protocol wants -- so a case for one would assert only that construction
#: ignores its own input, which it does. They are kept for TCP, where the
#: dropping is symmetric and the case is a genuine round trip of an
#: option-less header, and skipped where a second padding code would merely
#: duplicate the first.
SKIP = {
    ('tcp-option', 'End_of_Option_List'): 'padding, dropped by _make_tcp_options',
    ('tcp-option', 'No_Operation'): 'padding, dropped by _make_tcp_options',
    # Multipath TCP is the envelope for the whole tcp-mptcp family, so a case
    # here would silently duplicate whichever subtype it defaulted to.
    ('tcp-option', 'Multipath_TCP'): 'envelope for the tcp-mptcp family',
    # Pad1 and PadN are both discarded by _make_hopopt_options, so the two
    # cases emit byte-identical option-less headers.
    ('hopopt-option', 'PadN'): 'padding, indistinguishable from Pad1 here',
    ('ipv6-opts-option', 'PadN'): 'padding, indistinguishable from Pad1 here',
}


def cases(families: 'Optional[tuple[Family, ...]]' = None) -> 'list[Case]':
    """Every code every family registry claims to support, as a case.

    The list comes from the registries rather than from a table, which is what
    lets :file:`tests/protocols/test_option_roundtrip_unit.py` notice that a
    newly registered code has no case yet.

    Args:
        families: Families to enumerate; :data:`FAMILIES` if not given.

    Returns:
        The cases, ordered by family and then by :func:`sort_key`, so two runs
        produce the same list and therefore the same captures.

    """
    out = []  # type: list[Case]
    for family in (FAMILIES if families is None else families):
        registry = family.registry()
        overrides = family.overrides()
        for code in sorted(registry, key=sort_key):
            name = code_name(code)
            if (family.label, name) in SKIP:
                continue
            # A code missing from ``overrides`` means "every default", which is
            # what most of them want.
            out.append(Case(family.label, code, name, dict(overrides.get(code, {}))))
    return out


def roundtrip(case: 'Case', deadline: 'int' = DEADLINE) -> 'Outcome':
    """Construct ``case``, parse it back, construct it again, compare.

    The third step is the one that earns its keep. A ``_make_*`` that takes
    only keyword arguments, and cannot consume the data model its own
    ``_read_*`` produced, still passes a construct-then-parse test and fails
    here.

    Args:
        case: The case to exercise.
        deadline: Whole seconds to allow, or ``0`` for no deadline. See the
            module docstring for why there is one at all.

    Returns:
        An :class:`Outcome` naming the step that failed, or ``'OK'``.

    """
    family = FAMILY_MAP[case.family]
    # Bound inside the ``with`` below and read after it, so it is declared here.
    # Non-optional, unlike the ``octets`` field of the ``Outcome`` it ends up in:
    # every path that reaches the comparison at the bottom has been through a
    # successful construction, and saying so keeps the ``.hex()`` there honest.
    octets = b''
    again = b''

    with _deadline(deadline), warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter('always')

        def seen() -> 'tuple[str, ...]':
            """Warning messages so far, deduplicated but in order.

            :exc:`ResourceWarning` is dropped. It is raised by the garbage
            collector rather than by the code under test, so whichever case
            happens to be running when a file object from somewhere else is
            finalised would otherwise be blamed for it -- which is exactly what
            happened: a ``.pcapng`` handle left open by a sibling generator was
            reported against ``hopopt-option/Router_Alert``.
            """
            return tuple(dict.fromkeys(
                str(entry.message) for entry in caught
                if not issubclass(entry.category, ResourceWarning)))

        try:
            octets = bytes(family.build(case.code, case.kwargs))
        except TimeoutError as exc:
            return Outcome(case, 'TIMEOUT', str(exc), None, seen())
        except Exception as exc:  # pylint: disable=broad-except
            # Broad on purpose: the point is to find out *what* a constructor
            # does when it is wrong, and narrowing this to ProtocolError would
            # let an AttributeError or a KeyError -- which is what most of the
            # current defects raise -- abort the sweep rather than be recorded
            # as this case's result.
            return Outcome(case, 'CONSTRUCT', f'{type(exc).__name__}: {exc}', None, seen())

        try:
            parsed = family.extract(family.parse(octets))
        except TimeoutError as exc:
            return Outcome(case, 'TIMEOUT', str(exc), octets, seen())
        except Exception as exc:  # pylint: disable=broad-except
            return Outcome(case, 'PARSE', f'{type(exc).__name__}: {exc}', octets, seen())

        try:
            again = bytes(family.rebuild(parsed))
        except TimeoutError as exc:
            return Outcome(case, 'TIMEOUT', str(exc), octets, seen())
        except Exception as exc:  # pylint: disable=broad-except
            return Outcome(case, 'RECONSTRUCT', f'{type(exc).__name__}: {exc}',
                           octets, seen())

        warned = seen()

    if octets != again:
        return Outcome(case, 'MISMATCH', f'{octets.hex()} != {again.hex()}',
                       octets, warned)
    return Outcome(case, 'OK', '', octets, warned)


class _deadline:  # pylint: disable=invalid-name
    """Raise :exc:`TimeoutError` in the body after ``seconds`` seconds.

    Written as a class rather than a :func:`contextlib.contextmanager` so that
    it can be entered alongside :func:`warnings.catch_warnings` in one ``with``
    statement without the generator machinery swallowing the alarm.

    A no-op where :data:`signal.SIGALRM` is missing (Windows) or where the
    caller asked for no deadline. That is a deliberate degradation rather than
    a hard failure: without an interval timer the only alternative would be to
    refuse to generate the captures at all.

    """

    def __init__(self, seconds: 'int') -> 'None':
        #: Whole seconds to allow. :func:`signal.alarm` counts in whole
        #: seconds, so this cannot usefully be fractional.
        self.seconds = seconds
        #: Whether the alarm was actually armed, and so needs disarming.
        self.armed = False
        #: Handler displaced by :meth:`__enter__`, restored by :meth:`__exit__`.
        self.previous = None  # type: Any

    def __enter__(self) -> '_deadline':
        if self.seconds <= 0 or not hasattr(signal, 'SIGALRM'):
            return self

        def expire(signum: 'int', frame: 'Any') -> 'None':
            raise TimeoutError(f'did not finish within {self.seconds}s')

        self.previous = signal.signal(signal.SIGALRM, expire)
        signal.alarm(self.seconds)
        self.armed = True
        return self

    def __exit__(self, *exc_info: 'Any') -> 'None':
        if self.armed:
            # Cancel before restoring, so an alarm firing between the two
            # cannot be delivered to whatever handler was installed before.
            signal.alarm(0)
            signal.signal(signal.SIGALRM, self.previous)
            self.armed = False


def outcomes(families: 'Optional[tuple[Family, ...]]' = None,
             deadline: 'int' = DEADLINE) -> 'Iterator[Outcome]':
    """Run :func:`roundtrip` over :func:`cases`.

    Args:
        families: Families to enumerate; :data:`FAMILIES` if not given.
        deadline: Whole seconds to allow each case.

    Yields:
        One :class:`Outcome` per case, in case order.

    """
    for case in cases(families):
        yield roundtrip(case, deadline)


def _frame(family: 'Family', octets: 'bytes', index: 'int') -> 'Any':
    """Wrap constructed octets in the envelope that makes them decodable.

    Args:
        family: The family the octets came from, which decides the envelope.
        octets: The octets :func:`roundtrip` constructed.
        index: Position within the capture, used as the IPv4 identification so
            that two frames carrying identical options still differ somewhere.

    Returns:
        A :mod:`scapy` packet, with its timestamp already pinned.

    Raises:
        ValueError: If ``family`` names an envelope this function does not know.

    """
    from scapy.all import IP, IPv6, Ether, Raw, TCP  # pylint: disable=no-name-in-module

    link = Ether(src=SRC_MAC, dst=DST_MAC)
    if family.envelope == 'ethernet-ipv4':
        # The octets *are* the IPv4 header, options and all, so nothing may be
        # put between them and the link layer -- and because the payload is a
        # bare ``Raw``, scapy has nothing to infer the EtherType from and falls
        # back to its default of 0x9000. That decodes as Loopback, not IPv4, so
        # the type is stated here rather than left to be guessed.
        frame = link / Raw(octets)
        frame.type = 0x0800
    elif family.envelope == 'ipv4':
        frame = link / IP(src=SRC_IP, dst=DST_IP, proto=family.proto,
                          id=index, ttl=64) / Raw(octets)
    elif family.envelope == 'ipv6':
        frame = link / IPv6(src=SRC_IP6, dst=DST_IP6, nh=family.proto,
                            hlim=64) / Raw(octets)
    elif family.envelope == 'tcp':
        frame = (link / IP(src=SRC_IP, dst=DST_IP, id=index, ttl=64)
                 / TCP(sport=50000, dport=80, flags='A', seq=1, ack=1)
                 / Raw(octets))
    else:  # pragma: no cover
        raise ValueError(f'unknown envelope {family.envelope!r}')

    # A fixed epoch plus the frame's own index, rather than the clock.
    frame.time = EPOCH + index
    return frame


def generate(dest: 'pathlib.Path | None' = None) -> 'list[pathlib.Path]':
    """Write the option-coverage sample captures.

    Args:
        dest: Destination directory; ``examples/captures/`` under the
            repository root, if not given. Created if it does not exist.

    Returns:
        The paths written, in the order they were written.

    """
    from scapy.all import wrpcap  # pylint: disable=no-name-in-module

    dest = SAMPLE if dest is None else pathlib.Path(dest)
    dest.mkdir(parents=True, exist_ok=True)

    buckets = {}  # type: dict[str, list[Any]]
    unreachable = {}  # type: dict[str, str]
    warned = {}  # type: dict[str, tuple[str, ...]]

    for outcome in outcomes():
        family = FAMILY_MAP[outcome.case.family]
        if family.capture is None:
            # Exercised, but deliberately not captured.
            continue
        if outcome.status not in CAPTURABLE:
            unreachable[outcome.case.label] = f'{outcome.status}: {outcome.detail}'
            continue
        if outcome.warnings:
            warned[outcome.case.label] = outcome.warnings

        octets = outcome.octets
        if octets is None:  # pragma: no cover
            # Unreachable: every status in CAPTURABLE got past construction, so
            # it has octets. Narrowed explicitly rather than asserted, because a
            # generator should not abort a whole run over a bookkeeping slip.
            continue

        frames = buckets.setdefault(family.capture, [])
        frames.append(_frame(family, octets, len(frames)))

    written = []  # type: list[pathlib.Path]
    for name in sorted(buckets):
        path = dest / name
        wrpcap(str(path), buckets[name])
        written.append(path)

    total = sum(len(frames) for frames in buckets.values())
    print(f'options: {total} capturable case(s) across {len(written)} capture(s); '
          f'{len(unreachable)} case(s) left out')
    for label in sorted(unreachable):
        print(f'  [left out]  {label}: {unreachable[label]}')
    for label in sorted(warned):
        print(f'  [warned]    {label}: {"; ".join(warned[label])}')
    return written


if __name__ == '__main__':
    for sample in generate():
        print(f'{str(sample.relative_to(ROOT)):<32s} {sample.stat().st_size:8d} octets')
