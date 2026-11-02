# -*- coding: utf-8 -*-
"""The ``internet`` family: ``Internet.__proto__``, keyed by TransType (#496).

A family module of :file:`examples/generators/dispatch.py`, which loads it by
path and binds ``generator`` to itself before this body runs (#2615).

"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

#: :file:`examples/generators/dispatch.py`, which its loader binds here
#: before this body runs.
generator = globals()['generator']  # type: Any

#: Codes dispatched over an IPv4 outer header, one per line. ICMP (1) is
#: canonically IPv4-only -- its IPv6 equivalent is ICMPv6 (58), dispatched
#: separately below. IGMP (2) is likewise IPv4-only -- multicast's IPv6
#: equivalent is MLD, which rides in ICMPv6 rather than as its own IP protocol
#: number (#2439).
_OVER_IPV4 = frozenset({
    1,    # ICMP
    2,    # IGMP
    4,    # IPv4
    6,    # TCP
    17,   # UDP
    50,   # ESP
    51,   # AH
    89,   # OSPFIGP
    111,  # IPX_in_IP
    132,  # SCTP
})


def _registry() -> 'Any':
    from pcapkit.protocols.internet.internet import Internet
    return Internet.__proto__


def _payload(code: 'int') -> 'bytes':
    """The registered target's own wire bytes for ``code``."""
    from pcapkit.const.reg.transtype import TransType

    _ip4, _ip6, _tcp, _udp = generator._ip4, generator._ip6, generator._tcp, generator._udp
    if code == TransType.HOPOPT:
        from pcapkit.protocols.internet.hopopt import HOPOPT
        return bytes(HOPOPT(options=[], next=6, payload=_tcp(9999)))
    if code == TransType.IPv4:  # IP-in-IP.
        return _ip4(6, _tcp(9999))
    if code == TransType.ICMP:
        from pcapkit.protocols.internet.icmpv4 import ICMPv4

        # NOTE: the checksum is left uncomputed (#2470).
        return bytes(ICMPv4(type=8, code=0,
                            body={'id': 1, 'seq': 1, 'data': b'ping'}))
    if code == TransType.IPv6_ICMP:
        from pcapkit.protocols.internet.icmpv6 import ICMPv6

        # NOTE: the checksum is left uncomputed (#2470).
        return bytes(ICMPv6(type=128, code=0,
                            body={'id': 1, 'seq': 1, 'data': b'ping'}))
    if code == TransType.TCP:
        return _tcp(9999)
    if code == TransType.UDP:
        return _udp(9999)
    if code == TransType.DCCP:
        from pcapkit.protocols.transport.dccp import DCCP
        return bytes(DCCP(srcport=50000, dstport=9999, seq=1, payload=b'\x01\x02\x03'))
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
    if code == TransType.IGMP:
        from pcapkit.const.igmp.type import Type
        from pcapkit.protocols.internet.igmpv2 import IGMPv2

        # A General Query: an IGMPv1/v2 message is the 8-octet header and
        # nothing else, so there is no further payload to wrap. A nonzero
        # max_resp_time makes it IGMPv2, the class IGMP dispatches it to.
        return bytes(IGMPv2(type=Type.IGMP_Membership_Query, max_resp_time=100, group='0.0.0.0'))
    if code == TransType.IPv6_NoNxt:
        # The registered target for this code *is* Raw -- there is no
        # dissector to hand it, "no next header" is the whole point -- so any
        # non-empty payload demonstrates the same thing an empty one would.
        return b'\x01\x02\x03'
    if code == TransType.IPv6_Opts:
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
        return bytes(IPv6_Opts(options=[], next=6, payload=_tcp(9999)))
    if code == TransType.IPX_in_IP:
        from pcapkit.protocols.internet.ipx import IPX
        return bytes(IPX())
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

        # Only the dispatch into HIP is under test here, so which parameter
        # travels inside it does not matter.
        return bytes(HIP(parameters=[(Parameter.SEQ, {})], extension=True,
                         next=6, packet=1, version=2, checksum=b'\x00\x00',
                         controls_anonymous=False, shit=0, rhit=0, payload=_tcp(9999)))
    if code == TransType.OSPFIGP:
        from pcapkit.protocols.application.ospf import OSPF
        return bytes(OSPF())
    if code == TransType.Shim6:
        # #904: no dedicated dissector exists for Shim6 -- IPv6_Ext
        # parses only the two octets RFC 6564 §4 guarantees (next header,
        # Hdr Ext Len), so this is hand-built rather than constructed
        # through a class: next=TCP(6), Hdr Ext Len=0 -> an 8-octet header,
        # six of them padding.
        return bytes([int(TransType.TCP), 0]) + b'\x00' * 6 + _tcp(9999)
    raise LookupError(f'internet: no payload builder for {code!r}')  # pragma: no cover


def _build(code: 'int') -> 'Any':
    payload = _payload(code)
    if int(code) in _OVER_IPV4:
        frame = generator._ethernet(0x0800, generator._ip4(int(code), payload))
    else:
        frame = generator._ethernet(0x86DD, generator._ip6(int(code), payload))
    return generator._extract_first(generator._pcap_bytes((frame,), linktype=1), '.pcap')


#: The families this module adds.
FAMILIES = (
    generator.Family('internet', _registry, _build),
)

#: The class each case of :data:`FAMILIES` is pinned to, as
#: :data:`examples.generators.dispatch.PINNED_TARGETS` describes.
PINNED_TARGETS = {
    'internet/HOPOPT': ('pcapkit.protocols.internet.hopopt', 'HOPOPT'),
    'internet/IPv4': ('pcapkit.protocols.internet.ipv4', 'IPv4'),
    'internet/ICMP': ('pcapkit.protocols.internet.icmpv4', 'ICMPv4'),
    'internet/TCP': ('pcapkit.protocols.transport.tcp', 'TCP'),
    'internet/UDP': ('pcapkit.protocols.transport.udp', 'UDP'),
    'internet/DCCP': ('pcapkit.protocols.transport.dccp', 'DCCP'),
    'internet/IPv6': ('pcapkit.protocols.internet.ipv6', 'IPv6'),
    'internet/IPv6_ICMP': ('pcapkit.protocols.internet.icmpv6', 'ICMPv6'),
    'internet/IPv6_Route': ('pcapkit.protocols.internet.ipv6_route', 'IPv6_Route'),
    'internet/IPv6_Frag': ('pcapkit.protocols.internet.ipv6_frag', 'IPv6_Frag'),
    'internet/ESP': ('pcapkit.protocols.internet.esp', 'ESP'),
    'internet/AH': ('pcapkit.protocols.internet.ah', 'AH'),
    'internet/IGMP': ('pcapkit.protocols.internet.igmp', 'IGMP'),
    'internet/IPv6_NoNxt': ('pcapkit.protocols.misc.raw', 'Raw'),
    'internet/IPv6_Opts': ('pcapkit.protocols.internet.ipv6_opts', 'IPv6_Opts'),
    'internet/IPX_in_IP': ('pcapkit.protocols.internet.ipx', 'IPX'),
    'internet/Mobility_Header': ('pcapkit.protocols.internet.mh', 'MH'),
    'internet/HIP': ('pcapkit.protocols.internet.hip', 'HIP'),
    'internet/SCTP': ('pcapkit.protocols.transport.sctp', 'SCTP'),
    'internet/OSPFIGP': ('pcapkit.protocols.application.ospf', 'OSPF'),
    # #904: Shim6 (140) is registered directly at IPv6_Ext, which parses
    # the RFC 6564 §4 generic layout, as Shim6 has no dedicated dissector.
    # Without the entry the default factory would resolve it to Raw.
    'internet/Shim6': ('pcapkit.protocols.internet.ipv6_ext', 'IPv6_Ext'),
}
