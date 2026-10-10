# -*- coding: utf-8 -*-
"""Link-layer edge cases round-trip byte for byte. C.f. #1202.

Ethernet, the 802.1Q/802.1ad tags, ARP and RARP, L2TPv2, the BSD loopback
and OSPF, at their minimum and maximum lengths, with reserved bits set, with
zero-length addresses and offset pads, and with unassigned codes. The harness
and the meaning of each table are in :mod:`tests.protocols._edge_roundtrip`.

Every case builds its own octets in memory and reads no capture.

"""

from __future__ import annotations

import struct
import unittest

from tests.protocols import _edge_roundtrip as edge
from tests.protocols._edge_roundtrip import Case, MakeCase, Reject

ETHERNET = 'pcapkit.protocols.link.ethernet:Ethernet'
C_TAG = 'pcapkit.protocols.link.c_tag:C_Tag'
S_TAG = 'pcapkit.protocols.link.s_tag:S_Tag'
ARP = 'pcapkit.protocols.link.arp:ARP'
RARP = 'pcapkit.protocols.application.rarp:RARP'
L2TPV2 = 'pcapkit.protocols.link.l2tpv2:L2TPv2'
LOOPBACK = 'pcapkit.protocols.link.loopback:Loopback'
OSPF = 'pcapkit.protocols.application.ospf:OSPF'

#: Destination and source MAC.
MACS = bytes.fromhex('0123456789ab') + bytes.fromhex('fedcba987654')


def arp(htype: int = 1, ptype: int = 0x0800, hlen: int = 6, plen: int = 4,
        oper: int = 1, tail: bytes = b'') -> bytes:
    """An ARP packet whose addresses are ``2 * (hlen + plen)`` counting octets."""
    return (struct.pack('!HHBBH', htype, ptype, hlen, plen, oper)
            + bytes(i % 256 for i in range(2 * (hlen + plen))) + tail)


def ospf(type_: int = 1, plen: 'int | None' = None, auth: int = 0,
         auth_data: bytes = bytes(8), body: bytes = b'', version: int = 2) -> bytes:
    """An OSPF header, then ``body``; Packet Length counts both by default."""
    plen = 24 + len(body) if plen is None else plen
    return struct.pack('!BBH4s4s2sH', version, type_, plen, bytes([1, 2, 3, 4]), bytes(4),
                       b'\xab\xcd', auth) + auth_data + body


CASES = (
    # -- Ethernet ----------------------------------------------------------
    Case('ethernet/header-only-unknown-type', ETHERNET, MACS + b'\x88\xb5'),
    Case('ethernet/header-only-ipv4-type', ETHERNET, MACS + b'\x08\x00'),
    Case('ethernet/length-field-0', ETHERNET, MACS + b'\x00\x00' + b'x'),
    Case('ethernet/length-field-1500', ETHERNET, MACS + b'\x05\xdc' + b'xyzw'),
    Case('ethernet/unassigned-type-ffff', ETHERNET, MACS + b'\xff\xff' + b'abc'),
    Case('ethernet/broadcast-46-zero-octets', ETHERNET, b'\xff' * 6 + MACS[6:] + b'\x88\xb5' + bytes(46)),
    Case('ethernet/max-1514', ETHERNET, MACS + b'\x88\xb5' + bytes(range(256)) * 5 + bytes(220)),
    # -- 802.1Q / 802.1ad --------------------------------------------------
    Case('c-tag/pcp7-dei-vid4095', C_TAG, b'\xff\xff\x88\xb5' + b'pl'),
    Case('c-tag/vid0-no-payload', C_TAG, b'\x00\x00\x88\xb5'),
    Case('c-tag/header-only-ipv4-type', C_TAG, b'\x20\x01\x08\x00'),
    Case('s-tag/dei-then-c-tag', S_TAG, b'\x1f\xff\x81\x00' + b'\x00\x01\x88\xb5'),
    # -- ARP / RARP --------------------------------------------------------
    Case('arp/hlen0-plen0', ARP, arp(hlen=0, plen=0)),
    Case('arp/reply', ARP, arp(oper=2)),
    Case('arp/oper-0-unassigned', ARP, arp(oper=0)),
    Case('arp/oper-ffff-unassigned', ARP, arp(oper=0xffff)),
    Case('arp/htype-fffe-unassigned', ARP, arp(htype=0xfffe)),
    Case('arp/ptype-unknown-plen3', ARP, arp(ptype=0x1234, plen=3)),
    Case('arp/ipv6-plen16', ARP, arp(ptype=0x86dd, plen=16)),
    Case('arp/hlen255', ARP, arp(hlen=255)),
    Case('arp/18-octet-trailer', ARP, arp(tail=bytes(18))),
    Case('rarp/request-reverse', RARP, arp(oper=3)),
    Case('rarp/oper-unassigned', RARP, arp(oper=0x7fff)),
    # -- L2TPv2 ------------------------------------------------------------
    Case('l2tpv2/minimal', L2TPV2, b'\x00\x02' + b'\x00\x01\x00\x02'),
    Case('l2tpv2/control-every-field', L2TPV2, b'\xc8\x02' + b'\x00\x0c' + b'\x00\x01\x00\x02\x00\x03\x00\x04'),
    Case('l2tpv2/offset-0', L2TPV2, b'\x02\x02' + b'\x00\x01\x00\x02' + b'\x00\x00' + b'pp'),
    Case('l2tpv2/offset-3-nonzero-pad', L2TPV2,
         b'\x02\x02' + b'\x00\x01\x00\x02' + b'\x00\x03' + b'\xaa\xbb\xcc' + b'pp'),
    Case('l2tpv2/offset-past-the-data', L2TPV2, b'\x02\x02' + b'\x00\x01\x00\x02' + b'\x00\x09' + b'pp'),
    Case('l2tpv2/reserved-bits', L2TPV2, b'\x34\xf2' + b'\x00\x01\x00\x02' + b'pp'),
    Case('l2tpv2/priority', L2TPV2, b'\x01\x02' + b'\x00\x01\x00\x02' + b'pp'),
    Case('l2tpv2/every-flag-and-reserved', L2TPV2, b'\xff\xf2' + b'\x00\x0e' + bytes(8) + b'\x00\x00'),
    Case('l2tpv2/length-exact', L2TPV2, b'\x40\x02' + b'\x00\x0a' + b'\x00\x01\x00\x02' + b'pp'),
    Case('l2tpv2/length-short-of-the-data', L2TPV2, b'\x40\x02' + b'\x00\x08' + b'\x00\x01\x00\x02' + b'pp'),
    Case('l2tpv2/length-short-of-the-header', L2TPV2, b'\x40\x02' + b'\x00\x02' + b'\x00\x01\x00\x02' + b'pp'),
    Case('l2tpv2/length-past-the-data', L2TPV2, b'\x40\x02' + b'\x00\x40' + b'\x00\x01\x00\x02' + b'pp'),
    Case('l2tpv2/version-3', L2TPV2, b'\x00\x03' + b'\x00\x01\x00\x02'),
    # -- BSD loopback (#1574) ----------------------------------------------
    Case('loopback/header-only-ipv4-little', LOOPBACK, b'\x02\x00\x00\x00'),
    Case('loopback/header-only-ipv6-big', LOOPBACK, b'\x00\x00\x00\x1e'),
    Case('loopback/family-0', LOOPBACK, bytes(4) + b'xyz'),
    Case('loopback/family-osi-7', LOOPBACK, b'\x07\x00\x00\x00' + b'xyz'),
    Case('loopback/family-ffffffff', LOOPBACK, b'\xff' * 4 + b'xyz'),
    Case('loopback/both-halves-set', LOOPBACK, b'\x02\x00\x02\x00' + b'xyz'),
    Case('loopback/ipv4-short-of-a-header', LOOPBACK, b'\x00\x00\x00\x02' + b'\x45\x00'),
    # -- OSPF --------------------------------------------------------------
    Case('ospf/hello-header-only', OSPF, ospf()),
    Case('ospf/type-0-unassigned', OSPF, ospf(type_=0)),
    Case('ospf/type-255-unassigned', OSPF, ospf(type_=255)),
    Case('ospf/auth-simple-password', OSPF, ospf(auth=1, auth_data=b'password')),
    Case('ospf/auth-ffff-unassigned', OSPF, ospf(auth=0xffff, auth_data=b'\xff' * 8)),
    Case('ospf/auth-cryptographic-digest', OSPF,
         ospf(auth=2, auth_data=b'\x00\x00\x01\x10\x00\x00\x00\x07', body=bytes(4)) + b'\x11' * 16),
    Case('ospf/packet-length-short-of-the-data', OSPF, ospf(plen=24) + b'zz'),
    Case('ospf/packet-length-past-the-data', OSPF, ospf(plen=200)),
    Case('ospf/version-3', OSPF, ospf(version=3)),
    Case('ospf/lsu-body', OSPF, ospf(type_=4, body=bytes(range(20)))),
)

MAKE_CASES = (
    MakeCase('ethernet/make/default', ETHERNET, {}),
    MakeCase('ethernet/make/unassigned-type', ETHERNET, {'type': 0xffff, 'payload': b'xy'}),
    MakeCase('c-tag/make/every-tci-bit', C_TAG, {'pcp': 7, 'dei': True, 'vid': 4095, 'type': 0x88b5}),
    MakeCase('arp/make/zero-length-addresses', ARP,
             {'hlen': 0, 'plen': 0, 'sha': b'', 'spa': b'', 'tha': b'', 'tpa': b''}),
    MakeCase('arp/make/unassigned-oper', ARP, {'oper': 0xffff}),
    MakeCase('l2tpv2/make/every-optional-field', L2TPV2,
             {'type': 1, 'length_flag': True, 'ns': 1, 'nr': 2, 'offset': 0, 'priority': True}),
    MakeCase('l2tpv2/make/offset-pad', L2TPV2, {'offset': 3, 'padding': b'\x01\x02\x03', 'payload': b'pp'}),
    MakeCase('l2tpv2/make/reserved-bits', L2TPV2, {'reserved': 0x34f0}),
    MakeCase('loopback/make/default', LOOPBACK, {}),
    MakeCase('loopback/make/ipv6-darwin-big', LOOPBACK, {'family': 30, 'byteorder': 'big', 'payload': b'xy'}),
    MakeCase('loopback/make/unassigned-family-little', LOOPBACK,
             {'family': 0xffff, 'byteorder': 'little', 'payload': b'xy'}),
    MakeCase('ospf/make/default', OSPF, {}),
    MakeCase('ospf/make/unassigned-codes', OSPF, {'type': 200, 'auth_type': 9}),
)

REJECTED = {
    'l2tpv2/version-3': Reject('ProtocolError', 'L2TPv2: invalid version: 3'),
}

KNOWN_FAILURES = ()  # type: tuple[edge.Gap, ...]


@unittest.skipUnless(edge.HAS_RUNTIME, 'runtime dependencies not installed')
class LinkEdgeRoundTripTests(edge.EdgeRoundTripBase):
    """Link-layer edge cases."""

    CASES = CASES
    MAKE_CASES = MAKE_CASES
    REJECTED = REJECTED
    KNOWN_FAILURES = KNOWN_FAILURES


if __name__ == '__main__':
    unittest.main()
