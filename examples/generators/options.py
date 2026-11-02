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
                                HTTP/2 frames, and DCCP options
:file:`options-internet.pcap`   Mobility Header messages, options and
                                extensions, and HIP parameters
=============================== =============================================

Each frame carries exactly one item of exactly one code, so a parse failure
names the option that caused it instead of a soup of several. Every frame is an
Ethernet envelope around octets that :mod:`pcapkit` itself constructed, rather
than a packet assembled by :mod:`scapy` from its own protocol model. That is the
point: the octets under test are the library's own output, so a capture is a
record of what this version of ``pcapkit`` builds, and re-parsing it exercises
``_read_*`` against ``_make_*``. HOPOPT's Jumbo Payload case is the exception,
carrying a genuine jumbogram -- see :func:`_jumbogram_datagram`.

Only the codes that construct *successfully* can appear in a capture -- there
are no octets for the ones that do not. A failing case in a captured family
makes :func:`generate` raise once the rest are written, so a broken or foreign
library cannot pass for a smaller fixture set. Every other failure is recorded
case by case in :file:`tests/protocols/test_option_roundtrip_unit.py`, against
the defect that causes it.

Why the case table is not a list of options
-------------------------------------------

:func:`cases` walks the dispatch registries -- ``TCP.__option__``,
``SCTP.__chunk__``, ``MH.__message__`` and the rest -- so a code registered
tomorrow appears here tomorrow, and the unit test fails until somebody gives it
a case. The families live one protocol per module under
:file:`examples/generators/option_families/`, so that an added family is an
added file (#2615), and what their tables hold is only the *arguments*, which
cannot be derived: each option means something different, so each needs its
own value. Most need nothing at all, since nearly every ``_make_*`` in the tree is fully
defaulted; an entry exists where the default is degenerate (a zero-length
variable field), machine-dependent, or outright rejected.

Every one of these registries is a :class:`collections.defaultdict` held on a
*class* attribute, so ``registry[code]`` inserts on a miss and permanently grows
a registry shared by every instance in the process. Nothing here subscripts one:
:func:`cases` only ever *iterates*, which touches nothing, and :func:`handler` --
which resolves one particular code, and so cannot iterate -- goes through
:meth:`ProtocolBase._lookup_registry
<pcapkit.protocols.protocol.ProtocolBase._lookup_registry>` instead.

IPv4 and HIP are read through :func:`_named_registry`, which returns the
protocol's own registry and, for a protocol without one, falls back to the
enumeration crossed with the presence of the ``_make_opt_${name}`` /
``_make_param_${name}`` handler.

Determinism
-----------

The captures have to regenerate byte-identically; a fixture that churns is
worse than none, because every unrelated change then shows up as a diff. These
would otherwise vary between runs, and are pinned:

1. Frame timestamps, from :data:`EPOCH` rather than the clock.
2. The order cases are emitted in, from :func:`sort_key` rather than from
   registry iteration order -- which is insertion order, and therefore an
   implementation detail of whichever module last registered a code.
3. ``MH``'s ``MESG_ID_OPTION_TYPE``, whose ``_make_opt_mesg_id`` falls back to
   :meth:`datetime.datetime.now` when given neither ``timestamp`` nor
   ``interval``. It is given one below.
4. Anything reading the host. No case here uses PCAP-NG's
   ``_make_option_if_os``, which defaults to the live :mod:`platform` string.

Deliberate deviations from the sibling generators
-------------------------------------------------

Every import of :mod:`pcapkit` and of :mod:`scapy` in this module is
inside the function that needs it, which is why :mod:`pylint`'s
``import-outside-toplevel`` is switched off for the file rather than argued with
at every import. Both are load-bearing. :mod:`scapy` is needed only by
:func:`generate`, while the case table and :func:`roundtrip` are useful without
it -- the unit-tier test uses both and has to run on a checkout that installed no
:mod:`scapy`, so a top-level import would make that test skip for a dependency it
never touches. The :mod:`pcapkit` imports are deferred so that importing this
module does not drag in every protocol in the tree, which is what lets the unit
test purge :mod:`pcapkit` and *then* load the case table without the two
orderings fighting.

:func:`roundtrip` puts a :func:`signal.alarm` deadline around each case. That
is not defensive dressing: it guards against a parser defect that degenerates
into a loop making no progress, as GitHub issue #431 did on ``HOPOPT``'s
``SMF_DPD``. Without a deadline ``make samples`` does not fail on such a case --
it *hangs*, taking the whole build with it. A signal is what interrupts it, because the loop is pure
Python and holds the GIL for the whole of an iteration, so no watchdog thread
would ever get to run. The deadline is wall-clock time, so a stalled runner
can trip it on a case that normally takes milliseconds (#1428):
:data:`TIMEOUT_SCALE_ENV` stretches it without disarming it. It also repeats
every second until :func:`roundtrip` has the :exc:`TimeoutError`, because one
raise can be lost: a finaliser the cyclic collector runs reports it to
:func:`sys.unraisablehook` and drops it, and an ``except OSError`` drops it too,
:exc:`TimeoutError` being one. A single alarm would then leave the case running
for good (#1889).

"""

# Deferring these is the design, not an oversight -- see the module docstring.
# pylint: disable=import-outside-toplevel

from __future__ import annotations

import collections
import datetime
import importlib.util
import math
import os
import pathlib
import signal
import sys
import warnings
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from types import ModuleType
    from typing import Any, Callable, Iterator, Optional

__all__ = ['generate', 'cases', 'roundtrip', 'outcomes', 'Case', 'Outcome', 'FAMILIES']

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]

# Resolve pcapkit from this tree rather than from the install -- see
# make_samples.py (#1343).
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

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

#: Jumbo Payload Length of the ``hopopt-option/Jumbo_Payload`` case: the least
#: a jumbogram may carry, one more than the 16-bit Payload Length holds
#: (:rfc:`2675#section-2`). See :func:`_jumbogram_datagram`.
JUMBO_LEN = 0x10000
#: Snapshot length of a capture whose frames all fit in it: scapy's default,
#: which every capture but a jumbogram's carries.
SNAPLEN = 0xFFFF
#: Snapshot length of a capture holding a longer frame: libpcap's
#: ``MAXIMUM_SNAPLEN``. A libpcap reader cuts a record to the file's snaplen, so
#: a jumbogram under :data:`SNAPLEN` would reach it truncated.
JUMBO_SNAPLEN = 262144

#: Seconds a single case may take before :func:`roundtrip` gives up on it and
#: records ``'TIMEOUT'``, before :data:`TIMEOUT_SCALE_ENV` stretches it. A working
#: case takes low single-digit milliseconds, so this is headroom for a stalled
#: runner rather than for slow code (#1428), and it matches the per-case budget
#: :file:`tests/protocols/test_option_roundtrip_unit.py` gives the same cycle. A
#: case that never finishes still trips it, so a sweep still ends.
DEADLINE = 30

#: Environment variable multiplying every :func:`roundtrip` deadline -- the same
#: one :func:`tests._support.scale_timeout` reads, so one setting stretches the
#: suite's hang guards and this one together. Read here rather than imported,
#: because this module runs as a standalone script with no :mod:`tests` package.
TIMEOUT_SCALE_ENV = 'PCAPKIT_TEST_TIMEOUT_SCALE'

#: Longest deadline :func:`scale_deadline` hands out: one day, as in
#: :mod:`tests._support`. :func:`signal.alarm` takes a C ``int`` and raises
#: :exc:`OverflowError` past it, after the handler would already be installed.
MAX_DEADLINE = 86400

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
#: This is a safety property, not a tidiness one. A case that constructs
#: perfectly well and then spins forever on the way back in, as ``HOPOPT``'s
#: ``SMF_DPD`` did under GitHub issue #431, has octets available, and putting
#: them in a fixture would produce a capture that wedges every reader of it --
#: including the rest of this suite. A
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
#: * ``'TIMEOUT'`` -- the case did not finish inside :data:`DEADLINE`, as
#:   stretched by :data:`TIMEOUT_SCALE_ENV`.
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
    from pcapkit.protocols.protocol import ProtocolBase
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

    A protocol that dispatches its options or parameters by attribute name
    rather than through a registry has nothing to enumerate. The equivalent
    source of truth is the enumeration crossed with the presence of the
    handler, which is what this builds when the registry is absent.

    ``IPv4`` and ``HIP``, read through here, both have a real registry (#429),
    so the fallback is not taken for either -- it is kept because it costs nothing and is
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
# The families, and the cycle
###############################################################################

#: The directory holding the family modules: one file per protocol, holding
#: that protocol's families and their argument tables, so that a family added
#: in one change and a family added in another touch different files (#2615).
FAMILY_DIR = ROOT / 'examples' / 'generators' / 'option_families'


class _Generator:
    """This module as its family modules read it: its globals, looked up live."""

    def __getattr__(self, name: 'str') -> 'Any':
        try:
            return globals()[name]
        except KeyError:
            raise AttributeError(f'{__name__!r} has no attribute {name!r}') from None


def _family_modules() -> 'dict[str, ModuleType]':
    """Load every module of :data:`FAMILY_DIR`, in file name order, keyed by stem.

    Each is loaded by path, as this module is, with ``generator`` bound before
    its body runs, so that it builds its :class:`Family` entries and reaches
    the shared helpers here as ``generator.<name>``. Each declares
    ``FAMILIES``, the families it adds, and may declare ``SKIP``, its entries
    of :data:`SKIP`.

    Returns:
        The loaded modules.

    Raises:
        RuntimeError: If a module cannot be loaded.

    """
    modules = {}  # type: dict[str, ModuleType]
    for path in sorted(FAMILY_DIR.glob('*.py')):
        spec = importlib.util.spec_from_file_location(f'{__name__}_{path.stem}', path)
        if spec is None or spec.loader is None:  # pragma: no cover
            raise RuntimeError(f'cannot load the option family module {path}')
        module = importlib.util.module_from_spec(spec)
        setattr(module, 'generator', _Generator())
        spec.loader.exec_module(module)
        modules[path.stem] = module
    return modules


#: Each family module, keyed by its file stem.
FAMILY_MODULES = _family_modules()

#: Every family this module exercises, in the order their frames are emitted:
#: those of each family module, in file name order.
FAMILIES = tuple(family for module in FAMILY_MODULES.values() for family in module.FAMILIES)

#: The families keyed by label, for a caller that wants just one.
FAMILY_MAP = {family.label: family for family in FAMILIES}

#: Codes deliberately left out of the case list, keyed by ``(family label,
#: code name)``, with the reason: the ``SKIP`` of each family module, merged.
SKIP = {key: reason for module in FAMILY_MODULES.values()
        for key, reason in getattr(module, 'SKIP', {}).items()}


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
        deadline: Whole seconds to allow, or ``0`` for no deadline. A non-zero
            deadline is stretched by :data:`TIMEOUT_SCALE_ENV`. See the module
            docstring for why there is one at all.

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

    # The deadline is entered last, so it is torn down first: nothing of
    # catch_warnings runs on the way out while it can still fire. The body
    # settles it on every way out before :meth:`_deadline.__exit__` is entered
    # (#1889): the ``finally`` covers finishing and a :exc:`BaseException`, and
    # each ``except`` clause settles it first too, because a clause builds its
    # outcome before the ``finally`` runs. A repeat firing after that, at
    # ``__exit__``'s entry included, is a no-op. Attribute stores rather than a
    # method call, which would give a repeat already due one more place to land.
    with warnings.catch_warnings(record=True) as caught, _deadline(deadline) as limit:
        warnings.simplefilter('always')
        try:
            def seen() -> 'tuple[str, ...]':
                """Warning messages so far, deduplicated but in order.

                :exc:`ResourceWarning` is dropped. It is raised by the garbage
                collector rather than by the code under test, so whichever case
                happens to be running when a file object from somewhere else is
                finalised would otherwise be blamed for it -- which is exactly
                what happened: a ``.pcapng`` handle left open by a sibling
                generator was reported against ``hopopt-option/Router_Alert``.
                """
                return tuple(dict.fromkeys(
                    str(entry.message) for entry in caught
                    if not issubclass(entry.category, ResourceWarning)))

            try:
                octets = bytes(family.build(case.code, case.kwargs))
            except TimeoutError as exc:
                limit.settled = True
                return Outcome(case, 'TIMEOUT', str(exc), None, seen())
            except Exception as exc:  # pylint: disable=broad-except
                limit.settled = True
                # Broad on purpose: the point is to find out *what* a
                # constructor does when it is wrong, and narrowing this to
                # ProtocolError would let an AttributeError or a KeyError --
                # which is what most defects here raise -- abort the
                # sweep rather than be recorded as this case's result.
                return Outcome(case, 'CONSTRUCT', f'{type(exc).__name__}: {exc}', None,
                               seen())

            try:
                parsed = family.extract(family.parse(octets))
            except TimeoutError as exc:
                limit.settled = True
                return Outcome(case, 'TIMEOUT', str(exc), octets, seen())
            except Exception as exc:  # pylint: disable=broad-except
                limit.settled = True
                return Outcome(case, 'PARSE', f'{type(exc).__name__}: {exc}', octets,
                               seen())

            try:
                again = bytes(family.rebuild(parsed))
            except TimeoutError as exc:
                limit.settled = True
                return Outcome(case, 'TIMEOUT', str(exc), octets, seen())
            except Exception as exc:  # pylint: disable=broad-except
                limit.settled = True
                return Outcome(case, 'RECONSTRUCT', f'{type(exc).__name__}: {exc}',
                               octets, seen())
        finally:
            limit.settled = True

    # Read after the deadline is gone; ``caught`` outlives the ``with``.
    warned = seen()
    if octets != again:
        return Outcome(case, 'MISMATCH', f'{octets.hex()} != {again.hex()}',
                       octets, warned)
    return Outcome(case, 'OK', '', octets, warned)


def scale_deadline(seconds: 'int') -> 'int':
    """Stretch a per-case deadline by :data:`TIMEOUT_SCALE_ENV`.

    The same contract as :func:`tests._support.scale_timeout`, restated because
    this module cannot import from :mod:`tests`. Read on every call, so a test
    can set the variable for itself. Unset or blank, the deadline applies as
    written. A value that is not a positive finite number is refused rather than
    ignored: falling back to ``1`` would quietly undo a scale CI asked for, and a
    zero would disarm the guard. A scale stretching the deadline past
    :data:`MAX_DEADLINE` is refused the same way.

    Args:
        seconds: The deadline as given to :func:`roundtrip`.

    Returns:
        Whole seconds, at least one -- :func:`signal.alarm` counts in whole
        seconds, and an alarm of zero is no alarm at all.

    Raises:
        ValueError: If :data:`TIMEOUT_SCALE_ENV` is malformed, or scales
            ``seconds`` past :data:`MAX_DEADLINE`.

    """
    raw = os.environ.get(TIMEOUT_SCALE_ENV, '').strip()
    try:
        scale = float(raw) if raw else 1.0
    except ValueError:
        scale = math.nan
    if not (math.isfinite(scale) and scale > 0):
        raise ValueError(f'{TIMEOUT_SCALE_ENV} must be a positive number, not {raw!r}')
    # Compared before rounding: the product of two finite floats can still be
    # infinite, and ``math.ceil`` raises on that rather than returning.
    scaled = seconds * scale
    if not scaled <= MAX_DEADLINE:
        raise ValueError(f'{TIMEOUT_SCALE_ENV}={raw!r} stretches a {seconds}s deadline '
                         f'past the {MAX_DEADLINE}s ceiling')
    return max(1, math.ceil(scaled))


class _deadline:  # pylint: disable=invalid-name
    """Raise :exc:`TimeoutError` in the body after ``seconds`` seconds.

    ``seconds`` is stretched by :func:`scale_deadline` on entry, and the
    :exc:`TimeoutError` names the stretched value -- the seconds actually
    allowed.

    Each raise re-arms the alarm for one more second, so the raise repeats until
    :attr:`settled` is set (#1889). One raise is not enough: one that lands in a
    finaliser, or in an ``except OSError``, never reaches the body, and a single
    alarm would leave a hung case hung. The body must set :attr:`settled` before
    it leaves: :meth:`__exit__` sets it too, but a firing handled as
    :meth:`__exit__` is entered runs before it can.

    Written as a class rather than a :func:`contextlib.contextmanager` so that
    it can be entered alongside :func:`warnings.catch_warnings` in one ``with``
    statement without the generator machinery swallowing the alarm.

    A no-op where :data:`signal.SIGALRM` is missing (Windows) or where the
    caller asked for no deadline. That is a deliberate degradation rather than
    a hard failure: without an interval timer the only alternative would be to
    refuse to generate the captures at all.

    """

    def __init__(self, seconds: 'int') -> 'None':
        #: Whole seconds to allow: as given, then as scaled once entered.
        #: :func:`signal.alarm` counts in whole seconds, so this cannot usefully
        #: be fractional.
        self.seconds = seconds
        #: Whether the alarm was actually armed, and so needs disarming.
        self.armed = False
        #: Handler displaced by :meth:`__enter__`, restored by :meth:`__exit__`.
        self.previous = None  # type: Any
        #: Set by the body before it leaves, and by :meth:`__exit__` as a
        #: backstop: a firing after that does nothing, so it cannot interrupt
        #: the way out.
        self.settled = False

    def __enter__(self) -> '_deadline':
        if self.seconds <= 0 or not hasattr(signal, 'SIGALRM'):
            return self
        # Scaled before the handler goes in, so a malformed scale raises with
        # nothing installed that would need restoring.
        self.seconds = scale_deadline(self.seconds)

        def expire(signum: 'int', frame: 'Any') -> 'None':  # pylint: disable=unused-argument
            if self.settled:
                return
            # Re-armed before raising, so a raise that never reaches the body
            # is followed by another one.
            signal.alarm(1)
            raise TimeoutError(f'did not finish within {self.seconds}s')

        self.previous = signal.signal(signal.SIGALRM, expire)
        signal.alarm(self.seconds)
        self.armed = True
        return self

    def __exit__(self, *exc_info: 'Any') -> 'None':
        # For a body that left without settling: a firing from here to the
        # cancel below must not re-arm and raise, which would skip the restore.
        # One handled on entry, before this line runs, is not stopped by it --
        # only a body that settles before leaving stops that, as roundtrip does.
        self.settled = True
        if self.armed:
            # Cancel before restoring, so an alarm firing between the two
            # cannot be delivered to whatever handler was installed before.
            signal.alarm(0)
            # Cancelling does not withdraw an alarm that has fired but is not yet
            # delivered, which on GraalPy it can still be: delivered once the
            # previous handler is back -- ``SIG_DFL``, under pytest -- it ends the
            # worker (#2084, #2090). Ignoring the signal discards a pending one.
            signal.signal(signal.SIGALRM, signal.SIG_IGN)
            signal.signal(signal.SIGALRM, self.previous)
            self.armed = False


def outcomes(families: 'Optional[tuple[Family, ...]]' = None,
             deadline: 'int' = DEADLINE) -> 'Iterator[Outcome]':
    """Run :func:`roundtrip` over :func:`cases`.

    Args:
        families: Families to enumerate; :data:`FAMILIES` if not given.
        deadline: Whole seconds to allow each case, before
            :data:`TIMEOUT_SCALE_ENV` stretches it.

    Yields:
        One :class:`Outcome` per case, in case order.

    """
    for case in cases(families):
        yield roundtrip(case, deadline)


def _jumbogram_datagram(octets: 'bytes', jumbo: 'int') -> 'bytes':
    """The UDP datagram that makes a jumbogram up to its Jumbo Payload Length.

    With a Payload Length of 0 it is the Jumbo Payload Length that says where
    the packet ends, so the octets after the Hop-by-Hop Options header have to
    fill it, or the frame is a jumbogram cut short. The header names UDP as its
    next header, as ``_hopopt_base`` in
    :file:`examples/generators/option_families/ipv6.py` has every HOPOPT case
    do, so they are a datagram of zeros to the Discard port [:rfc:`863`], with the checksum
    :rfc:`8200#section-8.1` has a receiver verify. Its length fits UDP's Length
    field, which :rfc:`2675#section-4` therefore leaves as is. The checksum is
    the one's complement sum of :rfc:`1071`, computed here rather than by
    :mod:`scapy`, so that the unit-tier test can build the datagram on a leg
    that installs no :mod:`scapy`.

    Args:
        octets: The Hop-by-Hop Options header, as :func:`roundtrip` built it.
        jumbo: Its Jumbo Payload Length.

    Returns:
        The datagram, ``jumbo - len(octets)`` octets long.

    Raises:
        ValueError: If the header does not name UDP, or the octets it leaves
            are not the length of a UDP datagram.

    """
    import ipaddress

    size = jumbo - len(octets)
    if octets[0] != 17 or not 8 <= size <= 0xFFFF:
        raise ValueError(f'cannot fill a {jumbo}-octet jumbogram after a {len(octets)}-octet '
                         f'header naming next header {octets[0]} with a UDP datagram')

    head = (50000).to_bytes(2, 'big') + (9).to_bytes(2, 'big') + size.to_bytes(2, 'big')
    data = bytes(size - 8)
    pseudo = (ipaddress.IPv6Address(SRC_IP6).packed + ipaddress.IPv6Address(DST_IP6).packed
              + size.to_bytes(4, 'big') + bytes(3) + bytes([17]))
    # The sum of the 16-bit words, an odd octet padded with a zero, with every
    # carry folded back in; the checksum is its complement.
    covered = pseudo + head + bytes(2) + data + bytes(size % 2)
    total = sum(int.from_bytes(covered[i:i + 2], 'big') for i in range(0, len(covered), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    # A computed checksum of zero goes out as all ones, since zero means none.
    value = (~total & 0xFFFF) or 0xFFFF
    return head + value.to_bytes(2, 'big') + data


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
    from scapy.all import IP, TCP, Ether, IPv6, Raw  # pylint: disable=no-name-in-module

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
        from pcapkit.protocols.schema.internet.ipv6 import jumbo_payload_length

        # A Jumbo Payload option where it makes the packet a jumbogram gets a
        # genuine one: a Payload Length of 0 (RFC 2675 section 3, #1687), and
        # octets to make up the Jumbo Payload Length.
        jumbo = None if family.proto is None else jumbo_payload_length(family.proto, octets)
        if jumbo is None:
            frame = link / IPv6(src=SRC_IP6, dst=DST_IP6, nh=family.proto,
                                hlim=64) / Raw(octets)
        else:
            frame = link / IPv6(src=SRC_IP6, dst=DST_IP6, nh=family.proto, hlim=64,
                                plen=0) / Raw(octets + _jumbogram_datagram(octets, jumbo))
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

    Raises:
        RuntimeError: If any captured case was left out, after the captures
            that could be built have been written.

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
        frames = buckets[name]
        snaplen = SNAPLEN if max(len(frame) for frame in frames) <= SNAPLEN else JUMBO_SNAPLEN
        wrpcap(str(path), frames, snaplen=snaplen)
        written.append(path)

    total = sum(len(frames) for frames in buckets.values())
    print(f'options: {total} capturable case(s) across {len(written)} capture(s); '
          f'{len(unreachable)} case(s) left out')
    for label in sorted(unreachable):
        print(f'  [left out]  {label}: {unreachable[label]}')
    for label in sorted(warned):
        print(f'  [warned]    {label}: {"; ".join(warned[label])}')

    # On a correct tree every captured case constructs and parses, so a case
    # left out means the library is broken or is not this tree's (#1343). Fail
    # rather than hand back a silently smaller fixture set.
    if unreachable:
        import pcapkit
        raise RuntimeError(f'options: {len(unreachable)} case(s) left out of the captures, '
                           f'built with pcapkit from {pathlib.Path(pcapkit.__file__).parent}')
    return written


if __name__ == '__main__':
    for sample in generate():
        print(f'{str(sample.relative_to(ROOT)):<32s} {sample.stat().st_size:8d} octets')
