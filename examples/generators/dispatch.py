# -*- coding: utf-8 -*-
"""Enumerate the ``__proto__`` dispatch registries, and probe every entry.

:file:`pcapkit/foundation/registry/protocols/` documents the registries that
decide *which* :class:`~pcapkit.protocols.protocol.Protocol` subclass parses the
next layer. No other module enumerates them: several
test modules reference ``__proto__``, and
:file:`tests/protocols/test_registry_runtime.py` checks that a table entry
*resolves* to the right class object, but that is a weaker property than the one
that actually matters -- it is satisfied by a table whose target could not parse
a packet if it tried.
:file:`tests/protocols/test_dispatch_bindings_unit.py` asserts on the parsed
protocol chain for exactly that reason: as its own docstring records, a
protocol can be reachable from no table at all, and unable to parse a packet
if it were. But that module hand-picks
its cases rather than enumerating, so it guards the entries someone
remembered rather than the registries themselves. See GitHub issue #496.

This module is the ``__proto__`` counterpart to
:file:`examples/generators/options.py` and deliberately mirrors its shape: a
:data:`FAMILIES` table drives :func:`cases`, which walks each registry rather
than a hardcoded list, so a code registered tomorrow gets a case -- or fails the
harness -- tomorrow. Each family lives in a module of its own under
:file:`examples/generators/dispatch_families/`, beside its entries of
:data:`PINNED_TARGETS`, so that an added family is an added file (#2615).
What differs is the *check* itself. The option harness
round-trips construct -> parse -> construct and compares octets; dispatch has no
such symmetry to exploit, so :func:`probe` instead builds one minimal envelope
per code, decodes it the way the library itself would (through
:func:`pcapkit.extract` for the packet-level tables, or by handing the
:class:`~pcapkit.protocols.misc.pcap.frame.Frame` bytes straight to
:func:`pcapkit.extract` for the pcap/pcapng link-type tables, which is the
same call with a different global header), and asks whether the resulting
:class:`~pcapkit.corekit.protochain.ProtoChain` actually contains the class
:data:`PINNED_TARGETS` says the code is *supposed* to reach -- not merely that
the alias string looks right, since several of these classes rename themselves
on the wire (:class:`~pcapkit.protocols.application.rarp.RARP` reports ``'ARP'`` for
``oper in (1, 2)``; :class:`~pcapkit.protocols.internet.hip.HIP` reports
``'HIPv2'``), and a table entry whose target *is*
:class:`~pcapkit.protocols.misc.raw.Raw` itself is not a defect.

The expected class is deliberately **not** read out of the registry under
test. Read from there (``target=_resolve(entry)``), the check would be
self-referential: dispatch would always "reach" whatever the table said,
because that is the very value being checked against. Deleting an entry would
still be caught, as a pinned target no case reaches, by
:meth:`~tests.protocols.test_dispatch_registry_unit.DispatchRegistryTests
.test_cases_match_the_pinned_targets`, but *retargeting* one --
entry present, registry size unchanged, class wrong -- would pass silently,
since nothing independent of the table would say what the table should hold.
:data:`PINNED_TARGETS` is that independent record, and :attr:`Case.registered`
keeps the registry's own current answer alongside it purely as a diagnostic,
so a mismatch between the two is reported as what it is rather than folded
into "dispatch failed".

Some entries are known to degrade to :class:`Raw`, for reasons
recorded in :data:`KNOWN_DEGRADED` rather than fixed here -- this module reports
defects, it does not carry workarounds for them. They are
:class:`~pcapkit.protocols.transport.sctp.SCTP` payload protocol identifiers
reaching :class:`~pcapkit.protocols.application.ngap.NGAP`, and neither is a
defect: building a well-formed PER-encoded ``NGAP-PDU`` is out of scope for
a minimal dispatch probe, so both use the same placeholder payload
:meth:`~tests.protocols.transport.test_sctp_unit.SCTPUnitTests.test_ppid_dispatch_hook`
already does, and for the same documented reason -- one PPID is DTLS-wrapped
and :attr:`SCTP.__proto__ <pcapkit.protocols.transport.sctp.SCTP.__proto__>`
maps it to NGAP rather than through DTLS; the other degrades
identically because the payload is not an aligned PER encoding, exactly as
that test's own docstring records.

This module constructs its own octets and reads no capture under
:file:`examples/captures/`, so -- like its sibling -- it belongs to the unit
tier and runs on a fresh checkout with nothing generated.

"""
from __future__ import annotations

import importlib.util
import inspect
import os
import pathlib
import struct
import sys
import tempfile
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from types import ModuleType
    from typing import Any, Callable, Optional

__all__ = ['cases', 'probe', 'outcomes', 'Case', 'Outcome', 'Family', 'FAMILIES',
          'KNOWN_DEGRADED', 'code_name']

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]

# Resolve pcapkit from this tree rather than from the install -- see
# make_samples.py (#1343).
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

#: Fixed capture start time, kept for parity with :mod:`examples.generators.options`
#: even though nothing here is written to disk.
EPOCH = 1500000000

#: TCP header fields held constant across every case that needs a TCP segment.
#: Only ``dstport``/``payload`` vary.
#:
#: Every key is a parameter :meth:`TCP.make <pcapkit.protocols.transport.tcp.TCP.make>`
#: declares, which is not a style point: ``ack`` is the acknowledgement *flag*,
#: not the number, and ``seq``, ``ack_flag`` and ``urgent_pointer`` are not
#: parameters at all. An undeclared keyword raises
#: :exc:`~pcapkit.utilities.exceptions.UnsupportedCall` (#617); without that
#: check, ``make``'s trailing ``**kwargs`` absorbs and discards it, and a segment
#: built from such a mapping carries sequence number ``0`` whatever it says
#: (#602).
_TCP_BASE = dict(srcport=50000, seq_no=1, ack_no=0, ns=False, cwr=False, ece=False,
                 urg=False, ack=False, psh=False, rst=False, syn=True,
                 fin=False, window=8192, checksum=b'\x00\x00', urgent=0)


###############################################################################
# Shared plumbing.
###############################################################################


def _resolve(entry: 'Any') -> 'Any':
    """The class a registry entry names, whether it is a class or a descriptor.

    Args:
        entry: One ``__proto__`` value -- either a
            :class:`~pcapkit.corekit.module.ModuleDescriptor` or a
            :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass directly.

    Returns:
        The resolved protocol class.

    """
    from pcapkit.corekit.module import ModuleDescriptor
    return entry.klass if isinstance(entry, ModuleDescriptor) else entry


def code_name(code: 'Any', enum: 'Optional[Any]' = None) -> 'str':
    """Render a registry key as a name usable in a test id.

    Many ``__proto__`` tables are keyed entirely by enumeration members, whose
    own ``.name`` is used directly. ``Link.__proto__`` and the port tables hold
    bare :class:`int` keys as well -- :func:`_resolve` does not care, since
    dict lookup does not distinguish an :class:`~enum.IntEnum` member from the
    plain :class:`int` it equals, but a case label needs a name. ``enum`` is
    consulted where an enumeration member equals such a key, which is
    ``Link.__proto__``'s 0x8137 for IPX, so that label reads
    ``Novell_Inc_0x8137`` rather than the opaque ``33079``. A port number has
    no enumeration to consult, so it keeps its plain string form and its family
    is given no ``enum``.

    Args:
        code: Registry key.
        enum: Enumeration to consult when ``code`` has no ``.name`` of its own.

    Returns:
        ``code.name``, or the matching enumeration member's name, or the plain
        string form as a last resort.

    """
    name = getattr(code, 'name', None)
    if name is not None:
        return name
    if enum is not None:
        try:
            return enum(code).name
        except (ValueError, KeyError):  # pragma: no cover
            pass
    return str(code)


def _pcap_bytes(frames: 'tuple[bytes, ...]', linktype: 'int') -> 'bytes':
    """A minimal little-endian PCAP file (v2.4) holding ``frames``.

    Args:
        frames: Frame octets, one per record.
        linktype: Global header ``LinkType``.

    Returns:
        The file's raw octets.

    """
    buf = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 262144, int(linktype))
    for index, frame in enumerate(frames):
        buf += struct.pack('<IIII', EPOCH + index, 0, len(frame), len(frame))
        buf += frame
    return buf


def _pcapng_bytes(linktype: 'Any', packet_data: 'bytes') -> 'bytes':
    """A minimal PCAP-NG file: one section, one interface, one packet block.

    Built through :mod:`pcapkit`'s own :class:`~pcapkit.protocols.misc.pcapng.PCAPNG`
    construction API rather than hand-rolled :mod:`struct` packing, the same way
    :func:`examples.generators.option_families.pcapng._pcapng_context` does -- GitHub issue
    #496 judged hand-building a valid SHB+IDB+EPB stream riskier than
    the check was worth, and this sidesteps that by reusing the library's own
    ``make`` path, which is exactly what is under test one layer further down
    anyway.

    Args:
        linktype: The interface's ``LinkType``, i.e. the code under test.
        packet_data: The Enhanced Packet Block's payload.

    Returns:
        The file's raw octets.

    """
    from pcapkit.const.pcapng.block_type import BlockType
    from pcapkit.foundation.engines.pcapng import Context
    from pcapkit.protocols.misc.pcapng import PCAPNG

    shb = PCAPNG(num=0, sct=1, ctx=None, type=BlockType.Section_Header_Block, block={})
    context = Context(shb.info)
    idb = PCAPNG(num=1, sct=1, ctx=context, type=BlockType.Interface_Description_Block,
                block={'linktype': linktype, 'snaplen': 0x40000})
    context.interfaces.append(idb.info)
    epb = PCAPNG(num=2, sct=1, ctx=context, type=BlockType.Enhanced_Packet_Block,
                block={'timestamp': EPOCH, 'packet_data': packet_data})
    return bytes(shb) + bytes(idb) + bytes(epb)


def _extract_first(data: 'bytes', suffix: 'str') -> 'Any':
    """Write ``data`` to a temporary capture and return its first frame.

    Args:
        data: Raw capture file octets (PCAP or PCAP-NG).
        suffix: Filename suffix, e.g. ``'.pcap'`` or ``'.pcapng'`` -- cosmetic,
            since format is sniffed from the magic number, but keeps a stray
            temp file recognisable under a debugger.

    Returns:
        The first extracted frame, whose ``.protochain`` is what callers check.
        The frame is held in memory, so it outlives the capture, whose
        directory is removed on every path out (#2664).

    """
    import pcapkit

    with tempfile.TemporaryDirectory(prefix='pcapkit-dispatch-') as directory:
        path = os.path.join(directory, f'probe{suffix}')
        with open(path, 'wb') as file:
            file.write(data)

        with pcapkit.extract(fin=path, nofile=True, store=True, ip=True, tcp=True,
                             reassembly=False) as extraction:
            return extraction.frame[0]


def _tcp(dstport: 'int', payload: 'bytes' = b'') -> 'bytes':
    """A minimal TCP segment to ``dstport``."""
    from pcapkit.protocols.transport.tcp import TCP
    return bytes(TCP(dstport=dstport, payload=payload, **_TCP_BASE))


def _udp(dstport: 'int', payload: 'bytes' = b'') -> 'bytes':
    """A minimal UDP datagram to ``dstport``."""
    from pcapkit.protocols.transport.udp import UDP
    return bytes(UDP(srcport=50000, dstport=dstport, payload=payload))


def _ip4(protocol: 'int', payload: 'bytes') -> 'bytes':
    """A minimal option-less IPv4 header carrying ``payload``."""
    from pcapkit.protocols.internet.ipv4 import IPv4
    return bytes(IPv4(protocol=protocol, src='192.0.2.1', dst='198.51.100.1', payload=payload))


def _ip6(next_: 'int', payload: 'bytes') -> 'bytes':
    """A minimal IPv6 header carrying ``payload``."""
    from pcapkit.protocols.internet.ipv6 import IPv6
    return bytes(IPv6(next=next_, src='2001:db8::1', dst='2001:db8::2', payload=payload))


def _ethernet(ethertype: 'int', payload: 'bytes') -> 'bytes':
    """A minimal Ethernet II frame carrying ``payload``."""
    from pcapkit.protocols.link.ethernet import Ethernet
    return bytes(Ethernet(type=ethertype, payload=payload))


def _loopback(family: 'int', payload: 'bytes', byteorder: 'str' = 'little') -> 'bytes':
    """A BSD loopback header carrying ``payload``."""
    from pcapkit.protocols.link.loopback import Loopback
    return bytes(Loopback(family=family, byteorder=byteorder, payload=payload))


def _linux_sll(payload: 'bytes') -> 'bytes':
    """A ``LINUX_SLL`` header carrying ``payload``."""
    from pcapkit.protocols.link.linux_sll1 import LinuxSLL1
    return bytes(LinuxSLL1(payload=payload))


def _linux_sll2(payload: 'bytes') -> 'bytes':
    """A ``LINUX_SLL2`` header carrying ``payload``."""
    from pcapkit.protocols.link.linux_sll2 import LinuxSLL2
    return bytes(LinuxSLL2(payload=payload))


def _linux_sll_payload(arphrd_type: 'Any') -> 'tuple[int, bytes]':
    """The ``protocol_type`` and payload of a cooked header on a registered ``arphrd_type``.

    Shared by the ``linux_sll`` and ``linux_sll2`` families, which probe
    :attr:`LinuxSLL.__proto__ <pcapkit.protocols.link.linux_sll.LinuxSLL.__proto__>`
    through each version.

    Args:
        arphrd_type: A key of that table.

    Returns:
        The ``protocol_type`` to write, and the registered target's own wire bytes.

    Raises:
        LookupError: If ``arphrd_type`` has no payload builder here.

    """
    from pcapkit.const.linux.arphrd import ARPHRD

    if arphrd_type == ARPHRD.FRAD:
        from pcapkit.protocols.link.frad import FRAD
        return 0, bytes(FRAD(nlpid=0xCC, payload=_ip4(6, _tcp(9999))))
    if arphrd_type in (ARPHRD.IPGRE, ARPHRD.IP6GRE):
        from pcapkit.protocols.link.gre import GRE
        return 0x0800, bytes(GRE(protocol_type=0x0800, payload=_ip4(6, _tcp(9999))))
    if arphrd_type == ARPHRD.IEEE80211_RADIOTAP:
        from pcapkit.protocols.link.ieee802_11 import IEEE802_11
        from pcapkit.protocols.link.radiotap import Radiotap
        ack = bytes(IEEE802_11(type='Control', subtype='ACK', addr1='02:00:00:00:00:01'))
        return 0, bytes(Radiotap(payload=ack))
    if arphrd_type == ARPHRD.NETLINK:
        from pcapkit.protocols.link.netlink import Netlink
        return 0, bytes(Netlink(nlmsg_type=3, nlmsg_seq=1, byteorder='little',
                                payload=b'\xaa\xbb\xcc\xdd'))
    raise LookupError(f'linux_sll: no payload builder for {arphrd_type!r}')  # pragma: no cover


###############################################################################
# The families, the cases, and the probe.
###############################################################################


class Family(NamedTuple):
    """A ``__proto__`` registry, and how to probe one of its codes."""

    #: Family label, copied into every :class:`Case` it yields.
    label: 'str'
    #: Zero-argument callable returning the registry, or a mapping standing in
    #: for one. Deferred so that importing this module does not import every
    #: protocol in the tree.
    registry: 'Callable[[], Any]'
    #: ``build(code)`` -> the extracted top-level frame, whose ``.protochain``
    #: is what :func:`probe` checks. Raises on a code with no case.
    build: 'Callable[[Any], Any]'
    #: Enumeration :func:`code_name` falls back to for a bare-:class:`int` key.
    enum: 'Optional[Any]' = None


#: The directory holding the family modules: one file per ``__proto__`` table,
#: per tables registered together, or per member of the versioned family base
#: owning a table (#2592), so that a family added in one change and a family
#: added in another touch different files (#2615).
FAMILY_DIR = ROOT / 'examples' / 'generators' / 'dispatch_families'


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
    the shared plumbing above as ``generator.<name>``. Each declares
    ``FAMILIES``, the families it adds, and ``PINNED_TARGETS``, their entries
    of :data:`PINNED_TARGETS`.

    Returns:
        The loaded modules.

    Raises:
        RuntimeError: If a module cannot be loaded.

    """
    modules = {}  # type: dict[str, ModuleType]
    for path in sorted(FAMILY_DIR.glob('*.py')):
        spec = importlib.util.spec_from_file_location(f'{__name__}_{path.stem}', path)
        if spec is None or spec.loader is None:  # pragma: no cover
            raise RuntimeError(f'cannot load the dispatch family module {path}')
        module = importlib.util.module_from_spec(spec)
        setattr(module, 'generator', _Generator())
        spec.loader.exec_module(module)
        modules[path.stem] = module
    return modules


#: Each family module, keyed by its file stem.
FAMILY_MODULES = _family_modules()

#: Every family this module exercises: those of each family module, in file
#: name order. Each module's docstring names the issue its table came from.
FAMILIES = tuple(family for module in FAMILY_MODULES.values() for family in module.FAMILIES)

#: The families keyed by label, for a caller -- :func:`probe` -- that wants
#: just one.
FAMILY_MAP = {family.label: family for family in FAMILIES}


#: The class each case is *supposed* to dispatch to, pinned independently of
#: whatever the live registry holds: the ``PINNED_TARGETS`` of each family
#: module, merged.
#:
#: With the expected target read straight out of the table under test
#: (``target=_resolve(entry)``), a *mis-pointed* entry would pass silently --
#: dispatch would always "reach" whatever the corrupted table said, because
#: that is the very value being checked against. Deleting an entry would still
#: be caught, as a pinned target no case reaches, by
#: :meth:`~tests.protocols.test_dispatch_registry_unit.DispatchRegistryTests
#: .test_cases_match_the_pinned_targets`, but retargeting one --
#: entry present, registry size unchanged, class wrong -- would not be caught
#: by anything. Recording the expected ``(module, name)`` here, by hand, the
#: same way :data:`KNOWN_DEGRADED` records degraded cases by hand, means a
#: table entry that does not say what this module expects is a mismatch
#: against a fixed point rather than against itself.
#:
#: Keyed by :attr:`Case.label`. A code whose label is missing here builds a
#: :class:`Case` with ``target=None`` -- see
#: :meth:`~tests.protocols.test_dispatch_registry_unit.DispatchRegistryTests
#: .test_every_case_has_a_pinned_target`, which is the "registered but
#: unpinned" guard this table gives for free, the same way
#: :data:`examples.generators.options.FAMILIES` gives
#: ``test_every_registered_code_has_a_case``.
PINNED_TARGETS = {label: target for module in FAMILY_MODULES.values()
                  for label, target in module.PINNED_TARGETS.items()}


def _pinned_class(label: 'str') -> 'Optional[Any]':
    """The class :data:`PINNED_TARGETS` names for ``label``, or :data:`None`.

    Args:
        label: A :attr:`Case.label`.

    Returns:
        The pinned class, or :data:`None` if ``label`` is not in the table --
        which is itself the "registered but unpinned" signal.

    """
    entry = PINNED_TARGETS.get(label)
    if entry is None:
        return None
    module, name = entry
    import importlib
    return getattr(importlib.import_module(module), name)


class Case(NamedTuple):
    """One registered code, the class it is pinned to, and what the table says today."""

    #: Family label, e.g. ``'internet'``.
    family: 'str'
    #: Registry key, i.e. the wire code.
    code: 'Any'
    #: Human-readable code name, used in the case label and in test ids.
    name: 'str'
    #: The class :data:`PINNED_TARGETS` says :attr:`code` *should* dispatch to
    #: -- recorded independently of the registry, not read out of it. This is
    #: what :func:`probe` checks dispatch against. :data:`None` if
    #: :data:`PINNED_TARGETS` has no entry for this case's :attr:`label`.
    target: 'Any'
    #: The class :attr:`code` is *currently* registered against, resolved from
    #: whatever the table holds right now -- a
    #: :class:`~pcapkit.corekit.module.ModuleDescriptor` or a class directly.
    #: Diagnostic only: comparing this against :attr:`target` is what pins
    #: down a mis-pointed entry as distinct from a dispatch failure somewhere
    #: further down the chain.
    registered: 'Any'

    @property
    def label(self) -> 'str':
        """``family/name``, unique across every family."""
        return f'{self.family}/{self.name}'


class Outcome(NamedTuple):
    """What one dispatch probe found."""

    #: The case this describes.
    case: 'Case'
    #: ``str(frame.protochain)``, or ``''`` if construction/extraction raised.
    chain: 'str'
    #: Whether :attr:`Case.target` is one of the *actual* classes in the
    #: resulting :class:`~pcapkit.corekit.protochain.ProtoChain` --
    #: ``target in frame.protochain.protocols``, strict class identity, not
    #: ``target in frame.protochain``. The latter also matches on the layer's
    #: alias string and on ``Type.id()``, which is right for telling a
    #: renamed-on-the-wire class (RARP reporting itself as ``'ARP'``) from a
    #: wrong one -- but wrong here, because :class:`~pcapkit.protocols.misc.raw.Raw`
    #: itself constructs with ``alias=`` set to the *dispatching* code's own
    #: name (``Raw.__post_init__``, pcapkit/protocols/misc/raw.py), so a
    #: mis-pointed registry entry still renders its original code's name and
    #: would satisfy the string check while no instance of the pinned class
    #: exists anywhere in the chain.
    reached: 'bool'
    #: Exception type and message, if building or extracting the envelope
    #: raised outright rather than merely dispatching somewhere else. Empty
    #: otherwise.
    detail: 'str'
    #: The first ``'error'`` value found anywhere in the parsed frame's nested
    #: info mapping, or ``''`` if none is present. This is what
    #: :func:`pcapkit.corekit.decorators.beholder` records when a dissector
    #: raises and gets replaced with :class:`~pcapkit.protocols.misc.raw.Raw`,
    #: so it is the fragment :data:`KNOWN_DEGRADED` pins against.
    error: 'str'


def _find_error(info: 'Any') -> 'str':
    """The first ``'error'`` value in ``info``, searched depth-first.

    Args:
        info: A mapping, as returned by
            :meth:`~pcapkit.corekit.infoclass.Info.to_dict`, or any value
            nested within one.

    Returns:
        The first non-empty ``'error'`` string found, or ``''``.

    """
    if isinstance(info, dict):
        value = info.get('error')
        if isinstance(value, str) and value:
            return value
        for nested in info.values():
            found = _find_error(nested)
            if found:
                return found
    return ''


def cases(families: 'Optional[tuple[Family, ...]]' = None) -> 'list[Case]':
    """Every code every family registry holds, as a case.

    The list comes from the registries rather than from a hand-written table,
    which is what lets :file:`tests/protocols/test_dispatch_registry_unit.py`
    notice that a newly registered code has no case yet. Iterating a
    :class:`collections.defaultdict` touches nothing -- unlike subscripting one,
    which inserts on a miss and permanently grows a registry shared by every
    instance of the class in the process -- so this only ever calls
    ``registry.items()``.

    Args:
        families: Families to enumerate; :data:`FAMILIES` if not given.

    Returns:
        The cases, ordered by family and then by the registry key's ``int``
        value, so two runs produce the same list.

    """
    out = []  # type: list[Case]
    for family in (FAMILIES if families is None else families):
        registry = family.registry()
        enum = family.enum() if family.enum is not None else None
        for code, entry in sorted(registry.items(), key=lambda kv: int(kv[0])):
            name = code_name(code, enum)
            label = f'{family.label}/{name}'
            out.append(Case(family.label, code, name, _pinned_class(label), _resolve(entry)))
    return out


def probe(case: 'Case') -> 'Outcome':
    """Build ``case``'s envelope, decode it, and check dispatch reached the pinned target.

    The check is against :attr:`Case.target` -- :data:`PINNED_TARGETS`,
    recorded independently of the registry -- not against
    :attr:`Case.registered`, which is only ever what the table under test
    currently claims. Checking a table against itself would let a
    mis-pointed entry pass silently; see :data:`PINNED_TARGETS`.

    Args:
        case: The case to exercise.

    Returns:
        The probe's outcome. ``reached`` is trivially :data:`False`, with no
        attempt to build or decode anything, when :attr:`Case.target` is
        :data:`None` -- an unpinned case has no target to reach.

    """
    if case.target is None:
        return Outcome(case, '', False, 'no entry in PINNED_TARGETS for this case', '')

    family = FAMILY_MAP[case.family]
    try:
        frame = family.build(case.code)
    except Exception as exc:  # pylint: disable=broad-except
        # Broad on purpose, matching examples.generators.options.roundtrip: the
        # point is to see what a bad dispatch actually does, not to pre-filter
        # exception types and let something unanticipated abort the sweep.
        return Outcome(case, '', False, f'{type(exc).__name__}: {exc}', '')

    chain = str(frame.protochain)
    # Strict class identity via .protocols -- not the ``in``/``index`` methods
    # ProtoChain itself defines, which also match on the *alias string* and
    # on Type.id(). That is deliberate there (RARP reports itself as 'ARP' for
    # some ``oper`` values, and is still the RARP class), but it is exactly
    # the loophole that let a mis-pointed registry entry through here: several
    # dissectors -- Raw chief among them, in ``Raw.__post_init__``
    # (pcapkit/protocols/misc/raw.py) -- construct with ``alias=`` set to
    # the *dispatching* code's own name, so a code named ``AH`` retargeted at
    # Raw still renders as ``'...:AH'`` and still satisfies ``AH in
    # protochain`` on the string alone, even though no AH instance exists
    # anywhere in the chain. ``.protocols`` holds the actual ``type(instance)``
    # for each layer, which that substitution cannot spoof.
    # A dispatcher target -- abstract, or defining ``_dispatch_version`` -- puts the
    # member it picked in the chain, so a subclass of it counts as reaching it
    # (IGMP -> IGMPv1/IGMPv2, HTTP -> HTTPv1/HTTPv2, #2524).
    dispatcher = (inspect.isabstract(case.target)
                  or '_dispatch_version' in vars(case.target))
    reached = any(klass is case.target or (dispatcher and issubclass(klass, case.target))
                  for klass in frame.protochain.protocols)
    error = '' if reached else _find_error(frame.info.to_dict())
    return Outcome(case, chain, reached, '', error)


def outcomes(families: 'Optional[tuple[Family, ...]]' = None) -> 'list[Outcome]':
    """:func:`probe` over every case in :func:`cases`."""
    return [probe(case) for case in cases(families)]


#: Codes known to degrade to :class:`~pcapkit.protocols.misc.raw.Raw`, each
#: with the ``'error'`` fragments it may report and the reason it degrades.
#: Recorded, not fixed -- GitHub issue #496 is a test-harness change and none
#: of these classes is this module's to touch.
#:
#: This copy is what the ``__main__`` summary counts. The checks run against
#: the copy :class:`~tests.protocols.test_dispatch_registry_unit.DispatchRegistryTests`
#: keeps of it, both ways, as for
#: :data:`examples.generators.options.EXPECTED_FAILURES`: a case listed there
#: must still fail to reach its target, or the entry is stale; a case *not*
#: listed there must reach its target, or a fresh regression has gone
#: unnoticed. :meth:`~tests.protocols.test_dispatch_registry_unit.DispatchRegistryTests
#: .test_known_degraded_matches_the_generator` holds the two copies to each
#: other.
KNOWN_DEGRADED = {
    # NGAP is registered for both of its PPIDs. Building a well-formed
    # PER-encoded NGAP-PDU is out of scope for a minimal dispatch probe --
    # this uses the same placeholder payload (``b'ngap-pdu'``)
    # test_sctp_unit.py::test_ppid_dispatch_hook
    # does, which is not an aligned PER encoding and fails inside NGAP's own
    # decoder. The *reason* reported depends on the environment: where the
    # optional ``pycrate`` dependency is installed the decoder runs and reports
    # a malformed PDU, and where it is not, NGAP reports the missing
    # dependency instead. Both are the same placeholder-payload limitation, so
    # the entry accepts either: CI installs ``[NGAP]`` and reports the first,
    # and a local run without ``pycrate`` reports the second.
    'sctp/PayloadProtocolIdentifier_3GPP_NG_Application_Protocol': (
        ('malformed NGAP-PDU', 'needs the optional "pycrate" dependency'),
        'placeholder payload is not an aligned PER NGAP-PDU; building '
            'one is out of scope for a minimal dispatch probe, not a '
            'library defect'),
    # PPID 66 is NGAP wrapped in a DTLS record, and the registry maps it to
    # NGAP rather than through DTLS -- registered so the PPID
    # is *named*, per the registry's own comment in
    # pcapkit/protocols/transport/sctp.py, not because it decodes. The same
    # placeholder payload fails the same way, for the same reason.
    'sctp/PayloadProtocolIdentifier_3GPP_NGAP_over_DTLS_over_SCTP': (
        ('malformed NGAP-PDU', 'needs the optional "pycrate" dependency'),
        'PPID 66 is not routed through DTLS, and the same placeholder '
            'payload is not a DTLS record either'),
}


if __name__ == '__main__':
    total = 0
    degraded = 0
    for outcome in outcomes():
        total += 1
        marker = 'OK' if outcome.reached else 'DEGRADED'
        if not outcome.reached:
            degraded += 1
        print(f'{marker:>8s}  {outcome.case.label:<48s} {outcome.chain or outcome.detail}')
    print(f'dispatch: {total} case(s), {degraded} degraded, '
         f'{len(KNOWN_DEGRADED)} recorded in KNOWN_DEGRADED')
