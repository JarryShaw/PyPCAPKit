# -*- coding: utf-8 -*-
"""Enumerate the seven ``__proto__`` dispatch registries, and probe every entry.

:file:`pcapkit/foundation/registry/protocols.py` documents the registries that
decide *which* :class:`~pcapkit.protocols.protocol.Protocol` subclass parses the
next layer -- 38 entries across seven tables. Nothing enumerated them: several
test modules reference ``__proto__``, and
:file:`tests/protocols/test_registry_runtime.py` checks that a table entry
*resolves* to the right class object, but that is a weaker property than the one
that actually matters -- it is satisfied by a table whose target could not parse
a packet if it tried.
:file:`tests/protocols/test_dispatch_bindings_unit.py` exists because exactly
that shipped once: its own docstring records that
:class:`~pcapkit.protocols.link.ospf.OSPF` "was reachable from no table at all
and could not have parsed a packet if it had been". But that module hand-picks
its eleven cases rather than enumerating, so it guards the entries someone
remembered rather than the registries themselves. See GitHub issue #496.

This module is the ``__proto__`` counterpart to
:file:`examples/generators/options.py` and deliberately mirrors its shape: a
:data:`FAMILIES` table drives :func:`cases`, which walks each registry rather
than a hardcoded list, so a code registered tomorrow gets a case -- or fails the
harness -- tomorrow. What differs is the *check* itself. The option harness
round-trips construct -> parse -> construct and compares octets; dispatch has no
such symmetry to exploit, so :func:`probe` instead builds one minimal envelope
per code, decodes it the way the library itself would (through
:func:`pcapkit.extract` for the six packet-level tables, or by handing the
:class:`~pcapkit.protocols.misc.pcap.frame.Frame` bytes straight to
:func:`pcapkit.extract` for the two pcap/pcapng link-type tables, which is the
same call with a different global header), and asks whether the resulting
:class:`~pcapkit.corekit.protochain.ProtoChain` actually contains the class
:data:`PINNED_TARGETS` says the code is *supposed* to reach -- not merely that
the alias string looks right, since several of these classes rename themselves
on the wire (:class:`~pcapkit.protocols.link.arp.RARP` reports ``'ARP'`` for
``oper in (1, 2)``; :class:`~pcapkit.protocols.internet.hip.HIP` reports
``'HIPv2'``) and one table entry's target *is* itself
:class:`~pcapkit.protocols.misc.raw.Raw` rather than a defect.

The expected class is deliberately **not** read out of the registry under
test. An earlier version of this module did exactly that
(``target=_resolve(entry)``), which made the check self-referential: dispatch
always "reached" whatever the table currently said, because that was the very
value being checked against. Deleting an entry was still caught, by the exact
per-family counts in
:meth:`~tests.protocols.test_dispatch_registry_unit.DispatchRegistryTests
.test_cases_cover_every_table_named_in_the_issue`, but *retargeting* one --
entry present, registry size unchanged, class wrong -- passed silently, since
nothing independent of the table said what the table should have held.
:data:`PINNED_TARGETS` is that independent record, and :attr:`Case.registered`
keeps the registry's own current answer alongside it purely as a diagnostic,
so a mismatch between the two is reported as what it is rather than folded
into "dispatch failed".

Four of the 38 entries are known to degrade to :class:`Raw` today, for reasons
recorded in :data:`KNOWN_DEGRADED` rather than fixed here -- this module reports
defects, it does not carry workarounds for them. Two are
:class:`~pcapkit.protocols.internet.ipx.IPX` (GitHub issue #492: ``Socket(0)``
is not a valid member, and :class:`IPX() <pcapkit.protocols.internet.ipx.IPX>`
cannot even be constructed with no arguments, let alone parsed); the other two
are both :class:`~pcapkit.protocols.transport.sctp.SCTP` payload protocol
identifiers reaching :class:`~pcapkit.protocols.application.ngap.NGAP`. Neither
is a defect: building a well-formed PER-encoded ``NGAP-PDU`` is out of scope for
a minimal dispatch probe, so both use the same placeholder payload
:meth:`~tests.protocols.transport.test_sctp_unit.SCTPUnitTests.test_ppid_dispatch_hook`
already does, and for the same documented reason -- one PPID is DTLS-wrapped,
which pcapkit implements no DTLS for, and the other degrades identically
because the payload is not an aligned PER encoding, exactly as that test's own
docstring records.

This module constructs its own octets and reads no capture under
:file:`examples/captures/`, so -- like its sibling -- it belongs to the unit
tier and runs on a fresh checkout with nothing generated.

"""
from __future__ import annotations

import os
import struct
import tempfile
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from typing import Any, Callable, Optional

__all__ = ['cases', 'probe', 'outcomes', 'Case', 'Outcome', 'Family', 'FAMILIES',
          'KNOWN_DEGRADED', 'code_name']

#: Fixed capture start time, kept for parity with :mod:`examples.generators.options`
#: even though nothing here is written to disk.
EPOCH = 1500000000

#: TCP header fields held constant across every case that needs a TCP segment.
#: Only ``dstport``/``payload`` vary.
_TCP_BASE = dict(srcport=50000, seq=1, ack=0, ns=False, cwr=False, ece=False,
                 urg=False, ack_flag=False, psh=False, rst=False, syn=True,
                 fin=False, window=8192, checksum=b'\x00\x00', urgent_pointer=0)


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

    Most ``__proto__`` tables are keyed entirely by enumeration members, whose
    own ``.name`` is used directly. ``Link.__proto__`` and
    ``Internet.__proto__`` each hold one entry keyed by a bare :class:`int`
    instead (0x8137 for IPX, in ``Link``'s case) -- :func:`_resolve` does not
    care, since dict lookup does not distinguish an :class:`~enum.IntEnum`
    member from the plain :class:`int` it equals, but a case label needs a
    name. ``enum`` is consulted for that one, so the label reads
    ``Novell_Inc_0x8137`` rather than the opaque ``33079``.

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
    :func:`examples.generators.options._pcapng_context` does -- GitHub issue
    #496 judged hand-building a valid SHB+IDB+EPB stream by hand riskier than
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

    """
    import pcapkit

    path = os.path.join(tempfile.mkdtemp(prefix='pcapkit-dispatch-'), f'probe{suffix}')
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


###############################################################################
# Link -- EtherType.
###############################################################################


def _link_registry() -> 'Any':
    from pcapkit.protocols.link.link import Link
    return Link.__proto__


def _link_payload(code: 'int') -> 'bytes':
    """The registered target's own wire bytes for ``code``, as an Ethernet payload."""
    from pcapkit.const.reg.ethertype import EtherType

    if code == EtherType.Address_Resolution_Protocol:
        from pcapkit.protocols.link.arp import ARP
        return bytes(ARP(oper=1))
    if code == EtherType.Reverse_Address_Resolution_Protocol:
        from pcapkit.protocols.link.rarp import RARP
        # ARP/RARP/InARP/DRARP all report their alias from the wire ``oper``
        # field rather than from the dispatching EtherType (link/arp.py:176-190
        # per #496), so ``oper`` has to land in the RARP range (3, 4) or this
        # would silently probe ARP instead while still "passing".
        return bytes(RARP(oper=3))
    if code == EtherType.Customer_VLAN_Tag_Type:
        from pcapkit.protocols.link.c_tag import C_Tag
        return bytes(C_Tag(vid=200, type=0x0800, payload=_ip4(6, _tcp(9999))))
    if code == EtherType.IEEE_Std_802_1Q_Service_VLAN_tag_identifier:
        from pcapkit.protocols.link.s_tag import S_Tag
        return bytes(S_Tag(vid=100, type=0x0800, payload=_ip4(6, _tcp(9999))))
    if code == EtherType.Internet_Protocol_version_4:
        return _ip4(6, _tcp(9999))
    if code == EtherType.Internet_Protocol_version_6:
        return _ip6(6, _tcp(9999))
    if code == 0x8137:  # Novell IPX -- see KNOWN_DEGRADED.
        # ``IPX()`` cannot even be constructed with no arguments (#492:
        # ``Socket(0)`` is not a valid member), so there is no well-formed IPX
        # payload to probe with; this is a deliberately IPX-shaped run of zero
        # octets, enough to dispatch to the class and watch it fail to parse.
        return b'\x00' * 30
    raise LookupError(f'link: no payload builder for {code!r}')  # pragma: no cover


def _link_build(code: 'int') -> 'Any':
    frame = _ethernet(int(code), _link_payload(code))
    return _extract_first(_pcap_bytes((frame,), linktype=1), '.pcap')


###############################################################################
# Internet -- TransType.
###############################################################################

#: Codes dispatched over an IPv4 outer header.
_INTERNET_OVER_IPV4 = frozenset({4, 6, 17, 50, 51, 89, 111, 132})


def _internet_registry() -> 'Any':
    from pcapkit.protocols.internet.internet import Internet
    return Internet.__proto__


def _internet_payload(code: 'int') -> 'bytes':
    """The registered target's own wire bytes for ``code``."""
    from pcapkit.const.reg.transtype import TransType

    if code == TransType.HOPOPT:
        from pcapkit.protocols.internet.hopopt import HOPOPT
        return bytes(HOPOPT(options=[], next=6, payload=_tcp(9999)))
    if code == TransType.IPv4:  # IP-in-IP.
        return _ip4(6, _tcp(9999))
    if code == TransType.TCP:
        return _tcp(9999)
    if code == TransType.UDP:
        return _udp(9999)
    if code == TransType.IPv6:
        return _ip6(6, _tcp(9999))
    if code == TransType.IPv6_Route:
        from pcapkit.const.ipv6.routing import Routing
        from pcapkit.protocols.internet.ipv6_route import IPv6_Route
        return bytes(IPv6_Route(type=Routing.Type_2_Routing_Header, data={'ip': '2001:db8::2'},
                                next=6, seg_left=0, payload=_tcp(9999)))
    if code == TransType.IPv6_Frag:
        from pcapkit.protocols.internet.ipv6_frag import IPv6_Frag
        return bytes(IPv6_Frag(next=17, id=1, offset=0, mf=False, payload=_udp(9999)))
    if code == TransType.ESP:
        from pcapkit.protocols.internet.esp import ESP
        return bytes(ESP(spi=0x1234, seq=1, payload=b'\x01\x02\x03\x04'))
    if code == TransType.AH:
        from pcapkit.protocols.internet.ah import AH
        return bytes(AH(next=TransType.TCP, spi=0x1234, seq=1, icv=b'\x00' * 12,
                        payload=_tcp(9999)))
    if code == TransType.IPv6_NoNxt:
        # The registered target for this code *is* Raw -- there is no
        # dissector to hand it, "no next header" is the whole point -- so any
        # non-empty payload demonstrates the same thing an empty one would.
        return b'\x01\x02\x03'
    if code == TransType.IPv6_Opts:
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
        return bytes(IPv6_Opts(options=[], next=6, payload=_tcp(9999)))
    if code == TransType.IPX_in_IP:  # See KNOWN_DEGRADED -- same #492 as Link's IPX.
        return b'\x00' * 30
    if code == TransType.SCTP:
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.transport.sctp import SCTP
        return bytes(SCTP(srcport=50000, dstport=80, vtag=0x11223344, chksum=b'\x00' * 4,
                          chunks=[(Chunk.Payload_Data, {'data': b'\x01\x02\x03'})]))
    if code == TransType.Mobility_Header:
        from pcapkit.const.mh.packet import Packet
        from pcapkit.protocols.internet.mh import MH
        return bytes(MH(next=6, chksum=b'\x00\x00', type=Packet.Binding_Refresh_Request,
                        data={'options': []}, payload=_tcp(9999)))
    if code == TransType.HIP:
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP
        # Two copies of one parameter, not one -- HIP.make's header length
        # arithmetic loses four octets for a lone parameter and the packet is
        # then rejected on the way back in; see HIP_COPIES in
        # examples/generators/options.py for the full explanation. Only the
        # dispatch into HIP is under test here, so which parameter travels
        # inside it does not matter.
        return bytes(HIP(parameters=[(Parameter.SEQ, {})] * 2, extension=True,
                         next=6, packet=1, version=2, checksum=b'\x00\x00',
                         controls_anonymous=False, shit=0, rhit=0, payload=_tcp(9999)))
    if code == TransType.OSPFIGP:
        from pcapkit.protocols.link.ospf import OSPF
        return bytes(OSPF())
    raise LookupError(f'internet: no payload builder for {code!r}')  # pragma: no cover


def _internet_build(code: 'int') -> 'Any':
    payload = _internet_payload(code)
    if int(code) in _INTERNET_OVER_IPV4:
        frame = _ethernet(0x0800, _ip4(int(code), payload))
    else:
        frame = _ethernet(0x86DD, _ip6(int(code), payload))
    return _extract_first(_pcap_bytes((frame,), linktype=1), '.pcap')


###############################################################################
# TCP / UDP -- port.
###############################################################################

_TCP_PORT_PAYLOAD = {
    20: b'binary-file-contents',
    21: b'USER anonymous\r\n',
    80: b'GET / HTTP/1.1\r\nHost: probe.invalid\r\n\r\n',
    8080: b'GET / HTTP/1.1\r\nHost: probe.invalid\r\n\r\n',
}

#: An L2TPv2 data message with every optional field absent, matching
#: :func:`tests.protocols.test_dispatch_bindings_unit.l2tp_data`.
_L2TP_DATA = struct.pack('!HHH', 0x0002, 0x1234, 0x5678) + b'\xff\x03\x00\x21PPP'

_UDP_PORT_PAYLOAD = {
    80: b'GET / HTTP/1.1\r\nHost: probe.invalid\r\n\r\n',
    1701: _L2TP_DATA,
    8080: b'GET / HTTP/1.1\r\nHost: probe.invalid\r\n\r\n',
}


def _tcp_registry() -> 'Any':
    from pcapkit.protocols.transport.tcp import TCP
    return TCP.__proto__


def _tcp_build(port: 'int') -> 'Any':
    payload = _TCP_PORT_PAYLOAD.get(port)
    if payload is None:
        raise LookupError(f'tcp: no payload builder for port {port!r}')
    frame = _ethernet(0x0800, _ip4(6, _tcp(port, payload)))
    return _extract_first(_pcap_bytes((frame,), linktype=1), '.pcap')


def _udp_registry() -> 'Any':
    from pcapkit.protocols.transport.udp import UDP
    return UDP.__proto__


def _udp_build(port: 'int') -> 'Any':
    payload = _UDP_PORT_PAYLOAD.get(port)
    if payload is None:
        raise LookupError(f'udp: no payload builder for port {port!r}')
    frame = _ethernet(0x0800, _ip4(17, _udp(port, payload)))
    return _extract_first(_pcap_bytes((frame,), linktype=1), '.pcap')


###############################################################################
# SCTP -- payload protocol identifier.
###############################################################################


def _sctp_registry() -> 'Any':
    from pcapkit.protocols.transport.sctp import SCTP
    return SCTP.__proto__


def _sctp_build(ppid: 'Any') -> 'Any':
    from pcapkit.const.sctp.chunk import Chunk
    from pcapkit.protocols.transport.sctp import SCTP

    sctp = bytes(SCTP(srcport=50000, dstport=80, vtag=0x11223344, chksum=b'\x00' * 4,
                      chunks=[(Chunk.Payload_Data, {'ppid': ppid, 'data': b'ngap-pdu'})]))
    frame = _ethernet(0x0800, _ip4(132, sctp))
    return _extract_first(_pcap_bytes((frame,), linktype=1), '.pcap')


###############################################################################
# Frame (PCAP) / PCAPNG -- LinkType.
###############################################################################


def _pcap_frame_registry() -> 'Any':
    from pcapkit.protocols.misc.pcap.frame import Frame
    return Frame.__proto__


def _linktype_payload(code: 'Any') -> 'tuple[bytes, bool]':
    """The bytes to put in one capture record for LinkType ``code``.

    Args:
        code: The ``LinkType`` under test.

    Returns:
        The record's octets, and whether they still need an Ethernet wrapper
        (true for :attr:`~pcapkit.const.reg.linktype.LinkType.ETHERNET`, false
        for the two raw-IP link types, which carry no link layer at all).

    """
    from pcapkit.const.reg.linktype import LinkType

    if code == LinkType.ETHERNET:
        return _ip4(6, _tcp(9999)), True
    if code == LinkType.IPV4:
        return _ip4(6, _tcp(9999)), False
    if code == LinkType.IPV6:
        return _ip6(6, _tcp(9999)), False
    raise LookupError(f'linktype: no payload builder for {code!r}')  # pragma: no cover


def _pcap_frame_build(code: 'Any') -> 'Any':
    payload, wrap = _linktype_payload(code)
    record = _ethernet(0x0800, payload) if wrap else payload
    return _extract_first(_pcap_bytes((record,), linktype=int(code)), '.pcap')


def _pcapng_registry() -> 'Any':
    from pcapkit.protocols.misc.pcapng import PCAPNG
    return PCAPNG.__proto__


def _pcapng_build(code: 'Any') -> 'Any':
    payload, wrap = _linktype_payload(code)
    record = _ethernet(0x0800, payload) if wrap else payload
    return _extract_first(_pcapng_bytes(code, record), '.pcapng')


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


def _link_enum() -> 'Any':
    from pcapkit.const.reg.ethertype import EtherType
    return EtherType


def _internet_enum() -> 'Any':
    from pcapkit.const.reg.transtype import TransType
    return TransType


#: Every family this module exercises, one per ``__proto__`` table named in
#: GitHub issue #496.
FAMILIES = (
    Family('link', _link_registry, _link_build, _link_enum),
    Family('internet', _internet_registry, _internet_build, _internet_enum),
    Family('tcp', _tcp_registry, _tcp_build),
    Family('udp', _udp_registry, _udp_build),
    Family('sctp', _sctp_registry, _sctp_build),
    Family('pcap-frame', _pcap_frame_registry, _pcap_frame_build),
    Family('pcapng-frame', _pcapng_registry, _pcapng_build),
)

#: The families keyed by label, for a caller -- :func:`probe` -- that wants
#: just one.
FAMILY_MAP = {family.label: family for family in FAMILIES}


#: The class each case is *supposed* to dispatch to, pinned independently of
#: whatever the live registry currently holds.
#:
#: This is the fix for a gap in the first version of this harness: with the
#: expected target read straight out of the table under test
#: (``target=_resolve(entry)``), a *mis-pointed* entry passed silently --
#: dispatch always "reached" whatever the corrupted table said, because that
#: was the very value being checked against. Deleting an entry was still
#: caught, by the count guard in
#: :meth:`~tests.protocols.test_dispatch_registry_unit.DispatchRegistryTests
#: .test_cases_cover_every_table_named_in_the_issue`, but retargeting one --
#: entry present, registry size unchanged, class wrong -- was not caught by
#: anything. Recording the expected ``(module, name)`` here, by hand, the same
#: way :data:`KNOWN_DEGRADED` records defects by hand, means a table entry
#: that no longer says what this module expects is a mismatch against a fixed
#: point rather than against itself.
#:
#: Keyed by :attr:`Case.label`. A code whose label is missing here builds a
#: :class:`Case` with ``target=None`` -- see
#: :meth:`~tests.protocols.test_dispatch_registry_unit.DispatchRegistryTests
#: .test_every_case_has_a_pinned_target`, which is the "registered but
#: unpinned" guard this table gives for free, the same way
#: :data:`examples.generators.options.FAMILIES` gives
#: ``test_every_registered_code_has_a_case``.
PINNED_TARGETS = {
    # -- Link.__proto__ (EtherType) -------------------------------------------
    'link/Address_Resolution_Protocol': ('pcapkit.protocols.link.arp', 'ARP'),
    'link/Reverse_Address_Resolution_Protocol': ('pcapkit.protocols.link.rarp', 'RARP'),
    'link/Customer_VLAN_Tag_Type': ('pcapkit.protocols.link.c_tag', 'C_Tag'),
    'link/IEEE_Std_802_1Q_Service_VLAN_tag_identifier': ('pcapkit.protocols.link.s_tag', 'S_Tag'),
    'link/Internet_Protocol_version_4': ('pcapkit.protocols.internet.ipv4', 'IPv4'),
    'link/Internet_Protocol_version_6': ('pcapkit.protocols.internet.ipv6', 'IPv6'),
    'link/Novell_Inc_0x8137': ('pcapkit.protocols.internet.ipx', 'IPX'),

    # -- Internet.__proto__ (TransType) ---------------------------------------
    'internet/HOPOPT': ('pcapkit.protocols.internet.hopopt', 'HOPOPT'),
    'internet/IPv4': ('pcapkit.protocols.internet.ipv4', 'IPv4'),
    'internet/TCP': ('pcapkit.protocols.transport.tcp', 'TCP'),
    'internet/UDP': ('pcapkit.protocols.transport.udp', 'UDP'),
    'internet/IPv6': ('pcapkit.protocols.internet.ipv6', 'IPv6'),
    'internet/IPv6_Route': ('pcapkit.protocols.internet.ipv6_route', 'IPv6_Route'),
    'internet/IPv6_Frag': ('pcapkit.protocols.internet.ipv6_frag', 'IPv6_Frag'),
    'internet/ESP': ('pcapkit.protocols.internet.esp', 'ESP'),
    'internet/AH': ('pcapkit.protocols.internet.ah', 'AH'),
    'internet/IPv6_NoNxt': ('pcapkit.protocols.misc.raw', 'Raw'),
    'internet/IPv6_Opts': ('pcapkit.protocols.internet.ipv6_opts', 'IPv6_Opts'),
    'internet/IPX_in_IP': ('pcapkit.protocols.internet.ipx', 'IPX'),
    'internet/Mobility_Header': ('pcapkit.protocols.internet.mh', 'MH'),
    'internet/HIP': ('pcapkit.protocols.internet.hip', 'HIP'),
    'internet/SCTP': ('pcapkit.protocols.transport.sctp', 'SCTP'),
    'internet/OSPFIGP': ('pcapkit.protocols.link.ospf', 'OSPF'),

    # -- TCP.__proto__ (port) --------------------------------------------------
    'tcp/20': ('pcapkit.protocols.application.ftp', 'FTP_DATA'),
    'tcp/21': ('pcapkit.protocols.application.ftp', 'FTP'),
    'tcp/80': ('pcapkit.protocols.application.httpv1', 'HTTP'),
    'tcp/8080': ('pcapkit.protocols.application.httpv1', 'HTTP'),

    # -- UDP.__proto__ (port) --------------------------------------------------
    'udp/80': ('pcapkit.protocols.application.http', 'HTTP'),
    'udp/1701': ('pcapkit.protocols.link.l2tpv2', 'L2TPv2'),
    'udp/8080': ('pcapkit.protocols.application.http', 'HTTP'),

    # -- SCTP.__proto__ (payload protocol identifier) --------------------------
    'sctp/PayloadProtocolIdentifier_3GPP_NG_Application_Protocol':
        ('pcapkit.protocols.application.ngap', 'NGAP'),
    'sctp/PayloadProtocolIdentifier_3GPP_NGAP_over_DTLS_over_SCTP':
        ('pcapkit.protocols.application.ngap', 'NGAP'),

    # -- Frame.__proto__ (pcap LinkType) ---------------------------------------
    'pcap-frame/ETHERNET': ('pcapkit.protocols.link', 'Ethernet'),
    'pcap-frame/IPV4': ('pcapkit.protocols.internet', 'IPv4'),
    'pcap-frame/IPV6': ('pcapkit.protocols.internet', 'IPv6'),

    # -- PCAPNG.__proto__ (LinkType) --------------------------------------------
    'pcapng-frame/ETHERNET': ('pcapkit.protocols.link', 'Ethernet'),
    'pcapng-frame/IPV4': ('pcapkit.protocols.internet', 'IPv4'),
    'pcapng-frame/IPV6': ('pcapkit.protocols.internet', 'IPv6'),
}


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
    #: name (pcapkit/protocols/misc/raw.py:144), so a mis-pointed registry
    #: entry still renders its original code's name and would satisfy the
    #: string check while no instance of the pinned class exists anywhere in
    #: the chain.
    reached: 'bool'
    #: Exception type and message, if building or extracting the envelope
    #: raised outright rather than merely dispatching somewhere else. Empty
    #: otherwise.
    detail: 'str'
    #: The first ``'error'`` value found anywhere in the parsed frame's nested
    #: info mapping, or ``''`` if none is present. This is what
    #: :func:`pcapkit.utilities.decorators.beholder` records when a dissector
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
    currently claims. Checking a table against itself is what let a
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
    # dissectors -- Raw chief among them, in
    # pcapkit/protocols/misc/raw.py:144 -- construct with ``alias=`` set to
    # the *dispatching* code's own name, so a code named ``AH`` retargeted at
    # Raw still renders as ``'...:AH'`` and still satisfies ``AH in
    # protochain`` on the string alone, even though no AH instance exists
    # anywhere in the chain. ``.protocols`` holds the actual ``type(instance)``
    # for each layer, which that substitution cannot spoof.
    reached = case.target in frame.protochain.protocols
    error = '' if reached else _find_error(frame.info.to_dict())
    return Outcome(case, chain, reached, '', error)


def outcomes(families: 'Optional[tuple[Family, ...]]' = None) -> 'list[Outcome]':
    """:func:`probe` over every case in :func:`cases`."""
    return [probe(case) for case in cases(families)]


#: Codes known to degrade to :class:`~pcapkit.protocols.misc.raw.Raw` today,
#: with the defect that causes it. Recorded, not fixed -- GitHub issue #496 is
#: a test-harness change and none of these classes is this module's to touch.
#:
#: Each entry is checked both ways, the same as
#: :data:`examples.generators.options.EXPECTED_FAILURES`: a case listed here
#: must still fail to reach its target, or the entry is stale and the defect it
#: names has been fixed; a case *not* listed here must reach its target, or a
#: fresh regression has gone unnoticed.
KNOWN_DEGRADED = {
    # NGAP is registered for both PPIDs (SCTP.__proto__ is a defaultdict of
    # exactly two entries). Building a well-formed PER-encoded NGAP-PDU is out
    # of scope for a minimal dispatch probe -- this uses the same placeholder
    # payload (``b'ngap-pdu'``) test_sctp_unit.py::test_ppid_dispatch_hook
    # does, which is not an aligned PER encoding and fails inside NGAP's own
    # decoder. The *reason* reported depends on the environment: where the
    # optional ``pycrate`` dependency is installed the decoder runs and reports
    # a malformed PDU, and where it is not, NGAP reports the missing
    # dependency instead. Both are the same placeholder-payload limitation, so
    # the entry accepts either -- CI installs ``.[test]``, which deliberately
    # excludes ``[NGAP]``, and pinning only the first reason failed there.
    'sctp/PayloadProtocolIdentifier_3GPP_NG_Application_Protocol': (
        ('malformed NGAP-PDU', 'needs the optional "pycrate" dependency'),
        'pcapkit/protocols/application/ngap.py -- b\'ngap-pdu\' is not an '
            'aligned PER NGAP-PDU; this is a placeholder-payload limitation of '
            'the probe, not a library defect'),
    # PPID 66 is NGAP wrapped in a DTLS record, and pcapkit implements no
    # DTLS -- registered so the PPID is *named*, per the registry's own
    # comment in pcapkit/protocols/transport/sctp.py, not because it decodes.
    # The same placeholder payload fails the same way, for the same reason.
    'sctp/PayloadProtocolIdentifier_3GPP_NGAP_over_DTLS_over_SCTP': (
        ('malformed NGAP-PDU', 'needs the optional "pycrate" dependency'),
        'pcapkit implements no DTLS; the payload is meant to be a DTLS record '
            'wrapping an NGAP-PDU, and the placeholder used here is neither'),
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
