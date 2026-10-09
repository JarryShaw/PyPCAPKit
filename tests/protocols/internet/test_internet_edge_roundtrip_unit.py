# -*- coding: utf-8 -*-
"""Internet-layer edge cases round-trip byte for byte. C.f. #1202.

IPv4 and its option area, IPX, IPv6 and every extension header (standalone, in
extension mode, and inside an IPv6 chain), HIP, MH, AH and ESP, at their
minimum and maximum lengths, with reserved bits set, with zero-length options
and pads, and with unassigned codes. Per-code option coverage is
:mod:`tests.protocols.test_option_roundtrip_unit`'s; these are the header-level
cases it does not build. The harness is :mod:`tests.protocols._edge_roundtrip`.

Every case builds its own octets in memory and reads no capture.

"""

from __future__ import annotations

import struct
import unittest

from tests.protocols import _edge_roundtrip as edge
from tests.protocols._edge_roundtrip import Case, MakeCase, Reject

IPV4 = 'pcapkit.protocols.internet.ipv4:IPv4'
IPX = 'pcapkit.protocols.internet.ipx:IPX'
IPV6 = 'pcapkit.protocols.internet.ipv6:IPv6'
HOPOPT = 'pcapkit.protocols.internet.hopopt:HOPOPT'
IPV6_OPTS = 'pcapkit.protocols.internet.ipv6_opts:IPv6_Opts'
IPV6_ROUTE = 'pcapkit.protocols.internet.ipv6_route:IPv6_Route'
IPV6_FRAG = 'pcapkit.protocols.internet.ipv6_frag:IPv6_Frag'
AH = 'pcapkit.protocols.internet.ah:AH'
ESP = 'pcapkit.protocols.internet.esp:ESP'
MH = 'pcapkit.protocols.internet.mh:MH'
HIP = 'pcapkit.protocols.internet.hip:HIP'

EXT = {'extension': True}


def _checksum(octets: bytes) -> int:
    total = sum(int.from_bytes(octets[i:i + 2].ljust(2, b'\x00'), 'big')
                for i in range(0, len(octets), 2))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def ipv4(options: bytes = b'', payload: bytes = b'', proto: int = 253, frag: int = 0,
         tos: int = 0, ttl: int = 64, tlen: 'int | None' = None, ihl: 'int | None' = None,
         version: int = 4, checksum: bool = True) -> bytes:
    """An IPv4 header with ``options``, then ``payload``."""
    ihl = (20 + len(options)) // 4 if ihl is None else ihl
    tlen = 20 + len(options) + len(payload) if tlen is None else tlen
    head = struct.pack('!BBHHHBBH4s4s', (version << 4) | ihl, tos, tlen, 0x1234, frag, ttl,
                       proto, 0, bytes([192, 0, 2, 1]), bytes([198, 51, 100, 1])) + options
    if checksum:
        head = head[:10] + _checksum(head).to_bytes(2, 'big') + head[12:]
    return head + payload


def ipx(tlen: 'int | None' = None, tc: int = 0, ptype: int = 0, body: bytes = b'',
        checksum: bytes = b'\xff\xff') -> bytes:
    """An IPX header, then ``body``."""
    tlen = 30 + len(body) if tlen is None else tlen
    return (checksum + struct.pack('!HBB', tlen, tc, ptype) + bytes(4) + b'\x01' * 6
            + b'\x04\x51' + bytes(4) + b'\x02' * 6 + b'\x04\x52' + body)


def ipv6(nxt: int, body: bytes, tc: int = 0, fl: int = 0, plen: 'int | None' = None,
         hlim: int = 64) -> bytes:
    """An IPv6 header from ``::1`` to ``::2``, then ``body``."""
    plen = len(body) if plen is None else plen
    return (struct.pack('!IHBB', (6 << 28) | (tc << 20) | fl, plen, nxt, hlim)
            + bytes(15) + b'\x01' + bytes(15) + b'\x02' + body)


def opts(nxt: int, area: bytes) -> bytes:
    """A HOPOPT/IPv6-Opts header holding ``area``, which must fill it."""
    assert not (len(area) + 2) % 8, len(area)
    return bytes([nxt, (len(area) + 2) // 8 - 1]) + area


def rpl(cmpr_i: int, cmpr_e: int, count: int) -> bytes:
    """An RPL Source Route header of ``count`` addresses, no next header."""
    addrs = (16 - cmpr_i) * (count - 1) + (16 - cmpr_e)
    pad = -addrs % 8
    return (bytes([59, (addrs + pad) // 8, 3, 1, (cmpr_i << 4) | cmpr_e, pad << 4, 0, 0])
            + bytes(range(1, addrs + 1)) + bytes(pad))


def hip(params: bytes = b'', pkt: int = 16, version: int = 2, fixed: int = 1,
        controls: int = 0, nxt: int = 59, leading: int = 0) -> bytes:
    """A HIP header from HIT ``11..`` to ``22..``, then ``params``."""
    return (bytes([nxt, len(params) // 8 + 4, (leading << 7) | pkt, (version << 4) | fixed])
            + b'\x00\x00' + struct.pack('!H', controls) + b'\x11' * 16 + b'\x22' * 16 + params)


def hip_param(code: int, body: bytes) -> bytes:
    """A HIP parameter padded per :rfc:`7401#section-5.2.1`."""
    total = 11 + len(body) - (len(body) + 3) % 8
    return struct.pack('!HH', code, len(body)) + body + bytes(total - 4 - len(body))


#: A Binding Update's fixed part, with a 4-octet option area to follow.
MH_BU = bytes([59, 1, 5, 0]) + bytes(2) + b'\x00\x01' + bytes(4)

#: Extension headers on their own, next header 59: label -> (class, octets,
#: IPv6 next-header value that carries it).
EXTENSIONS = {
    'hopopt/pad1-x6': (HOPOPT, opts(59, bytes(6)), 0),
    'hopopt/padn-nonzero-contents': (HOPOPT, opts(59, b'\x01\x04\xde\xad\xbe\xef'), 0),
    'hopopt/padn-0-then-pad1s': (HOPOPT, opts(59, b'\x01\x00' + bytes(4)), 0),
    'hopopt/unassigned-skip': (HOPOPT, opts(59, b'\x1e\x04\xaa\xbb\xcc\xdd'), 0),
    'hopopt/unassigned-discard': (HOPOPT, opts(59, b'\x7e\x00\x01\x02\x00\x00'), 0),
    'hopopt/unassigned-zero-length': (HOPOPT, opts(59, b'\x3e\x00\x01\x02\x00\x00'), 0),
    'hopopt/max-length-2048': (HOPOPT, opts(59, (b'\x01\xff' + bytes(255)) * 7 + b'\x01\xf5' + bytes(245)), 0),
    'hopopt/router-alert-unassigned-value': (HOPOPT, opts(59, b'\x05\x02\xff\xff\x01\x00'), 0),
    'hopopt/jumbo-payload-0': (HOPOPT, opts(59, b'\xc2\x04' + bytes(4)), 0),
    'ipv6-opts/pad1-x6': (IPV6_OPTS, opts(59, bytes(6)), 60),
    'ipv6-opts/padn-nonzero-contents': (IPV6_OPTS, opts(59, b'\x01\x04\x01\x02\x03\x04'), 60),
    'ipv6-opts/unassigned': (IPV6_OPTS, opts(59, b'\xfe\x04\x01\x02\x03\x04'), 60),
    'ipv6-route/unassigned-type': (IPV6_ROUTE, bytes([59, 0, 200, 3]) + b'\xaa\xbb\xcc\xdd', 43),
    'ipv6-route/unassigned-type-24-octets': (IPV6_ROUTE, bytes([59, 2, 250, 0]) + bytes(range(20)), 43),
    'ipv6-route/type0-no-address': (IPV6_ROUTE, bytes([59, 0, 0, 0]) + bytes(4), 43),
    'ipv6-route/type0-reserved-set': (IPV6_ROUTE, bytes([59, 2, 0, 1]) + b'\xff' * 4 + bytes(16), 43),
    'ipv6-route/type2-reserved-set': (IPV6_ROUTE, bytes([59, 2, 2, 1]) + b'\x12\x34\x56\x78' + bytes(16), 43),
    'ipv6-route/rpl-uncompressed': (IPV6_ROUTE, rpl(0, 0, 1), 43),
    'ipv6-route/rpl-cmpr-15-15-x8': (IPV6_ROUTE, rpl(15, 15, 8), 43),
    'ipv6-route/rpl-cmpr-8-8-x2': (IPV6_ROUTE, rpl(8, 8, 2), 43),
    'ipv6-route/rpl-cmpr-15-0-x1': (IPV6_ROUTE, rpl(15, 0, 1), 43),
    'ipv6-route/rpl-cmpr-0-15-pad7': (IPV6_ROUTE, rpl(0, 15, 1), 43),
    'ipv6-route/rpl-cmpr-12-13-pad1': (IPV6_ROUTE, rpl(12, 13, 2), 43),
    'ipv6-frag/reserved-octet-set': (IPV6_FRAG, bytes([59, 0xff, 0, 0]) + b'\x00\x00\x00\x01', 44),
    'ipv6-frag/every-bit-set': (IPV6_FRAG, bytes([59, 0, 0xff, 0xff]) + b'\xff' * 4, 44),
    'ipv6-frag/atomic': (IPV6_FRAG, bytes([59, 0, 0, 0]) + bytes(4), 44),
    'ah/icv-empty': (AH, bytes([59, 1, 0, 0]) + b'\x00\x00\x00\x01' + b'\x00\x00\x00\x02', 51),
    'ah/reserved-set': (AH, bytes([59, 1, 0xff, 0xff]) + b'\x00\x00\x00\x01' + b'\x00\x00\x00\x02', 51),
    'ah/icv-12': (AH, bytes([59, 4, 0, 0]) + bytes(8) + b'\x11' * 12, 51),
    'ah/max-length-1028': (AH, bytes([59, 255, 0, 0]) + bytes(8) + b'\x22' * 1016, 51),
    'mh/brr-reserved-set': (MH, bytes([59, 1, 0, 0]) + bytes(2) + b'\xff\xff' + b'\x01\x06' + bytes(6), 135),
    'mh/hoti-reserved-set': (MH, bytes([59, 1, 1, 0]) + bytes(2) + b'\xff\xff' + bytes(8), 135),
    'mh/bu-every-flag': (MH, bytes([59, 1, 5, 0]) + bytes(2) + b'\x00\x01' + b'\xff' * 4 + b'\x01\x02\x00\x00', 135),
    'mh/bu-unassigned-option': (MH, MH_BU + b'\xfe\x02\x01\x02', 135),
    'mh/bu-zero-length-option': (MH, MH_BU + b'\xfe\x00\x00\x00', 135),
    'mh/bu-padn-nonzero-contents': (MH, MH_BU + b'\x01\x02\xde\xad', 135),
    'mh/bu-pad1-x4': (MH, MH_BU + bytes(4), 135),
    'mh/ba-unassigned-status': (MH, bytes([59, 1, 6, 0]) + bytes(2) + b'\x7f\xff' + b'\x00\x01' + bytes(6), 135),
    'mh/be-unassigned-status': (MH, bytes([59, 2, 7, 0]) + bytes(2) + b'\xff\x00' + bytes(16), 135),
    'mh/unassigned-type': (MH, bytes([59, 0, 200, 0]) + bytes(2) + b'\xab\xcd', 135),
    'mh/unassigned-type-16-octets': (MH, bytes([59, 1, 250, 0]) + bytes(2) + bytes(range(10)), 135),
    'mh/unassigned-type-max-length': (MH, bytes([59, 255, 200, 0]) + bytes(2) + bytes(2042), 135),
}

CASES = (
    # -- IPv4 --------------------------------------------------------------
    Case('ipv4/min-header-no-payload', IPV4, ipv4()),
    Case('ipv4/reserved-flag-set', IPV4, ipv4(frag=0x8000, payload=b'ab')),
    Case('ipv4/df-mf-max-offset', IPV4, ipv4(frag=0x7fff, payload=b'ab')),
    Case('ipv4/tos-ff', IPV4, ipv4(tos=0xff)),
    Case('ipv4/ttl-0', IPV4, ipv4(ttl=0)),
    Case('ipv4/protocol-255-reserved', IPV4, ipv4(proto=255, payload=b'xx')),
    Case('ipv4/protocol-200-unassigned', IPV4, ipv4(proto=200, payload=b'xx')),
    Case('ipv4/wrong-checksum', IPV4, ipv4(checksum=False)),
    Case('ipv4/ihl-15-nop-pad', IPV4, ipv4(options=b'\x01' * 40)),
    Case('ipv4/ihl-15-eool-pad', IPV4, ipv4(options=bytes(40))),
    Case('ipv4/eool-then-nonzero-pad', IPV4, ipv4(options=b'\x00\xaa\xbb\xcc')),
    Case('ipv4/nop-eool-eool-eool', IPV4, ipv4(options=b'\x01\x00\x00\x00')),
    Case('ipv4/rr-length-3-no-slot', IPV4, ipv4(options=b'\x07\x03\x04\x00')),
    Case('ipv4/rr-max-length-39', IPV4, ipv4(options=b'\x07\x27\x04' + bytes(36) + b'\x00')),
    Case('ipv4/unassigned-option-length-2', IPV4, ipv4(options=b'\x1f\x02\x00\x00')),
    Case('ipv4/unassigned-option-copied', IPV4, ipv4(options=b'\x9f\x04\xaa\xbb')),
    Case('ipv4/unassigned-option-max-length-40', IPV4, ipv4(options=b'\x7f\x28' + bytes(38))),
    Case('ipv4/ts-unassigned-flag', IPV4, ipv4(options=b'\x44\x0c\x05\x0f' + bytes(8))),
    Case('ipv4/ts-overflow-15', IPV4, ipv4(options=b'\x44\x0c\x0d\xf1' + bytes(8))),
    Case('ipv4/router-alert-unassigned-value', IPV4, ipv4(options=b'\x94\x04\xff\xff')),
    Case('ipv4/security-length-3', IPV4, ipv4(options=b'\x82\x03\x01\x00')),
    Case('ipv4/total-length-short-of-the-data', IPV4, ipv4(tlen=20) + bytes(6)),
    Case('ipv4/total-length-short-of-the-header', IPV4, ipv4(options=b'\x01' * 4, tlen=20)),
    Case('ipv4/total-length-past-the-data', IPV4, ipv4(tlen=100, payload=b'ab')),
    Case('ipv4/tcp-no-payload', IPV4, ipv4(proto=6)),
    Case('ipv4/udp-3-octet-payload', IPV4, ipv4(proto=17, payload=b'\x00\x01\x00')),
    Case('ipv4/version-6', IPV4, ipv4(version=6)),
    Case('ipv4/ihl-4', IPV4, ipv4(ihl=4)),
    # -- IPX ---------------------------------------------------------------
    Case('ipx/min-header', IPX, ipx()),
    Case('ipx/transport-control-255', IPX, ipx(tc=255)),
    Case('ipx/unassigned-packet-type', IPX, ipx(ptype=0xee, body=b'zz')),
    Case('ipx/length-short-of-the-data', IPX, ipx(tlen=30) + b'\x00'),
    Case('ipx/checksum-not-ffff', IPX, ipx(checksum=b'\x12\x34')),
    Case('ipx/length-past-the-data', IPX, ipx(tlen=60, body=b'abc')),
    # -- IPv6 --------------------------------------------------------------
    Case('ipv6/no-next-header-empty', IPV6, ipv6(59, b'')),
    Case('ipv6/no-next-header-with-octets', IPV6, ipv6(59, b'junk')),
    Case('ipv6/class-and-label-max', IPV6, ipv6(59, b'', tc=255, fl=0xfffff)),
    Case('ipv6/hop-limit-0', IPV6, ipv6(59, b'', hlim=0)),
    Case('ipv6/next-200-unassigned', IPV6, ipv6(200, b'xyz')),
    Case('ipv6/payload-length-short-of-the-data', IPV6, ipv6(253, b'ab', plen=1)),
    Case('ipv6/payload-length-0-with-octets', IPV6, ipv6(253, b'ab', plen=0)),
    Case('ipv6/payload-length-past-the-data', IPV6, ipv6(253, b'ab', plen=100)),
    Case('ipv6/hopopt-dstopts-route-frag', IPV6,
         ipv6(0, opts(60, bytes(6)) + opts(43, b'\x01\x04' + bytes(4))
              + bytes([44, 0, 200, 0]) + bytes(4) + bytes([59, 0, 0, 0]) + bytes(4))),
    Case('ipv6/ah-then-frag', IPV6, ipv6(51, bytes([44, 1, 0, 0]) + bytes(8) + bytes([59, 0, 0, 1]) + bytes(4))),
    Case('ipv6/hopopt-then-trailer', IPV6, ipv6(0, opts(59, bytes(6)), plen=8) + b'\x00\x00'),
    Case('ipv6/esp', IPV6, ipv6(50, b'\x00\x00\x00\x01\x00\x00\x00\x02' + bytes(8))),
    *(Case(label, cls, raw) for label, (cls, raw, _) in EXTENSIONS.items()),
    *(Case(f'{label}/extension', cls, raw, EXT) for label, (cls, raw, _) in EXTENSIONS.items()),
    *(Case(f'{label}/in-ipv6', IPV6, ipv6(nxt, raw)) for label, (cls, raw, nxt) in EXTENSIONS.items()),
    # In extension mode the header owns only its own 8 octets, not the UDP datagram after it.
    Case('hopopt/udp-payload/extension', HOPOPT, opts(17, bytes(6)) + b'\x9c\x40\x9c\x41\x00\x0a\x00\x00ab', EXT, 8),
    # -- ESP ---------------------------------------------------------------
    Case('esp/spi-seq-only', ESP, b'\x00\x00\x00\x01\x00\x00\x00\x02'),
    Case('esp/opaque-payload', ESP, b'\x00\x00\x00\x01\x00\x00\x00\x02' + bytes(8)),
    Case('esp/opaque-payload/extension', ESP, b'\x00\x00\x00\x01\x00\x00\x00\x02' + bytes(8), EXT),
    # -- HIP ---------------------------------------------------------------
    Case('hip/no-parameters', HIP, hip(), EXT),
    Case('hip/packet-type-0-reserved', HIP, hip(pkt=0), EXT),
    Case('hip/packet-type-127-unassigned', HIP, hip(pkt=127), EXT),
    Case('hip/version-1', HIP, hip(version=1), EXT),
    Case('hip/version-15', HIP, hip(version=15), EXT),
    Case('hip/every-control-bit', HIP, hip(controls=0xffff), EXT),
    Case('hip/unassigned-parameter', HIP, hip(hip_param(0x3fff, b'abc')), EXT),
    Case('hip/unassigned-parameter-empty', HIP, hip(hip_param(0x3fff, b'')), EXT),
    Case('hip/unassigned-critical-parameter', HIP, hip(hip_param(0x0101, b'\x01\x02\x03\x04\x05')), EXT),
    Case('hip/parameter-nonzero-pad', HIP, hip(struct.pack('!HH', 0x3fff, 1) + b'\x01\xff\xff\xff'), EXT),
    Case('hip/seq-max', HIP, hip(hip_param(385, b'\xff' * 4)), EXT),
    Case('hip/next-tcp-no-payload', HIP, hip(nxt=6), EXT),
    Case('hip/no-parameters/not-extension', HIP, hip()),
    Case('hip/fixed-bit-clear', HIP, hip(fixed=0), EXT),
    Case('hip/leading-bit-set', HIP, hip(leading=1), EXT),
)

MAKE_CASES = (
    MakeCase('ipv4/make/default', IPV4, {}),
    MakeCase('ipv4/make/unassigned-protocol', IPV4, {'protocol': 200, 'payload': b'x'}),
    MakeCase('ipv4/make/df-mf-max-offset-ttl-0', IPV4, {'df': True, 'mf': True, 'offset': 8191, 'ttl': 0}),
    MakeCase('ipx/make/default', IPX, {}),
    MakeCase('ipv6/make/default', IPV6, {}),
    MakeCase('ipv6/make/max-fields', IPV6, {'traffic_class': 255, 'flow_label': 0xfffff, 'next': 59, 'hop_limit': 0}),
    MakeCase('ipv6-frag/make/every-field-max', IPV6_FRAG,
             {'next': 59, 'reserved_octet': b'\xff', 'offset': 8191, 'reserved': 3, 'mf': True, 'id': 0xffffffff}),
    MakeCase('ah/make/reserved-set', AH, {'next': 59, 'reserved': 0xffff, 'spi': 1, 'seq': 2, 'icv': bytes(4)}),
    MakeCase('ah/make/icv-empty', AH, {'next': 59}),
    MakeCase('esp/make/default', ESP, {}),
    MakeCase('hip/make/default', HIP, {'next': 59}, EXT),
    MakeCase('hip/make/every-control-bit', HIP,
             {'next': 59, 'controls_reserved': 0x7fff, 'controls_anonymous': True, 'packet': 127}, EXT),
)

REJECTED = {
    'ipv4/version-6': Reject('ProtocolError', '[IPv4] invalid version: 6'),
    'ipv4/ihl-4': Reject('ProtocolError', 'resolved to a negative length'),
}

KNOWN_FAILURES = ()  # type: tuple[edge.Gap, ...]


@unittest.skipUnless(edge.HAS_RUNTIME, 'runtime dependencies not installed')
class InternetEdgeRoundTripTests(edge.EdgeRoundTripBase):
    """Internet-layer edge cases."""

    CASES = CASES
    MAKE_CASES = MAKE_CASES
    REJECTED = REJECTED
    KNOWN_FAILURES = KNOWN_FAILURES


if __name__ == '__main__':
    unittest.main()
