# -*- coding: utf-8 -*-
"""An RPL source route header (IPv6-Route type 3) rebuilds byte for byte.

GitHub issue #1456: inside IPv6, the parser restores the ``dst`` prefix of each
compressed address, and :meth:`IPv6_Route._make_data_type_rpl
<pcapkit.protocols.internet.ipv6_route.IPv6_Route._make_data_type_rpl>` wrote
the decoded address back at its full 16 octets, so a header with ``CmprI`` or
``CmprE`` above zero grew on rebuild.

GitHub issue #1457: a header the capture cut inside its address list was split
by the octets read rather than by ``Hdr Ext Len``, so a short run decoded as an
IPv4 address or raised a builtins :exc:`ValueError`, and the rebuild wrote a
smaller ``Hdr Ext Len``.

A cut that leaves ``Pad`` octets unread still rebuilds with them zero-filled;
that is the corekit short-read defect, #1458, so those cases only check that
the octets read come back first and ``Hdr Ext Len`` is kept.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import ipaddress
import unittest
import warnings

from tests._support import reimport_once_per_class

SRC = ipaddress.IPv6Address('2001:db8::1').packed
DST = ipaddress.IPv6Address('2001:db8:aa:bb:cc:dd:ee:ff').packed


def ipv6(route: bytes) -> bytes:
    """Wrap ``route`` in an IPv6 header from ``SRC`` to ``DST``."""
    return (bytes([0x60, 0, 0, 0]) + len(route).to_bytes(2, 'big') + bytes([43, 64])
            + SRC + DST + route)


def rpl(cmpr_i: int, cmpr_e: int, count: int, extra_pad: int = 0) -> bytes:
    """Build an RPL header carrying ``count`` addresses."""
    area = (count - 1) * (16 - cmpr_i) + (16 - cmpr_e)
    pad = (-area) % 8 + extra_pad
    body = bytes((i * 7 + 3) % 256 for i in range(area))
    hdr_ext_len = (area + pad) // 8
    return bytes([59, hdr_ext_len, 3, count, (cmpr_i << 4) | cmpr_e, pad << 4, 0, 0]) + body + bytes(pad)


def headers():
    """Every ``CmprI``/``CmprE`` pair, one to three addresses, minimal and widened ``Pad``."""
    for cmpr_i in range(16):
        for cmpr_e in range(16):
            for count in (1, 2, 3):
                minimal = (-((count - 1) * (16 - cmpr_i) + (16 - cmpr_e))) % 8
                for extra in (0, 8):
                    if minimal + extra <= 15:
                        yield (cmpr_i, cmpr_e, count, extra), rpl(cmpr_i, cmpr_e, count, extra)


class TestIPv6RouteRPLRoundTrip(unittest.TestCase):
    """Pin the rebuild of RPL source route headers, on their own and inside IPv6."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        warnings.simplefilter('ignore')
        self.addCleanup(warnings.resetwarnings)

    def rebuild(self, cls, raw: bytes) -> bytes:
        return cls.from_data(cls(raw, len(raw)).info).data

    def test_issue_1456_compressed_header_inside_ipv6(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6

        raw = ipv6(bytes([59, 2, 3, 1, 0x88, 0, 0, 0]) + bytes(range(1, 17)))
        self.assertEqual(len(raw), 64)
        self.assertEqual(self.rebuild(IPv6, raw), raw)

    def test_issue_1457_cut_address_is_kept_as_read(self) -> None:
        from pcapkit.protocols.internet.ipv6_route import IPv6_Route

        route = bytes([59, 2, 3, 1, 0, 0, 0, 0]) + bytes(range(1, 17))
        for cut in (12, 23):
            with self.subTest(cut=cut):
                info = IPv6_Route(route[:cut], cut).info
                self.assertEqual(info.ip, (route[8:cut],))
                self.assertEqual(self.rebuild(IPv6_Route, route[:cut]), route[:cut])

    def test_issue_1457_cut_keeps_hdr_ext_len(self) -> None:
        from pcapkit.protocols.internet.ipv6_route import IPv6_Route

        route = bytes([59, 2, 3, 1, 0x88, 0, 0, 0]) + bytes(range(1, 17))
        self.assertEqual(self.rebuild(IPv6_Route, route[:12]), route[:12])

    def test_every_compression_rebuilds(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.internet.ipv6_route import IPv6_Route

        for label, route in headers():
            with self.subTest(case=label):
                self.assertEqual(self.rebuild(IPv6_Route, route), route)
                self.assertEqual(self.rebuild(IPv6, ipv6(route)), ipv6(route))

    def test_every_cut_rebuilds(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.internet.ipv6_route import IPv6_Route

        # Two addresses put a cut in both ``Addresses[1..n-1]`` and ``Addresses[n]``.
        for label, route in headers():
            if label[2:] != (2, 0):
                continue
            pad = route[5] >> 4
            for cut in range(8, len(route)):
                with self.subTest(case=label, cut=cut):
                    alone = self.rebuild(IPv6_Route, route[:cut])
                    inner = self.rebuild(IPv6, ipv6(route)[:40 + cut])
                    if pad == 0:
                        self.assertEqual(alone, route[:cut])
                        self.assertEqual(inner, ipv6(route)[:40 + cut])
                    else:  # unread ``Pad`` octets are zero-filled (#1458)
                        self.assertEqual(alone[:cut], route[:cut])
                        self.assertEqual(inner[:40 + cut], ipv6(route)[:40 + cut])
                        self.assertEqual(alone[1], route[1])

    def test_make_parse_rebuilds(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.internet.ipv6_route import IPv6_Route

        dst = ipaddress.IPv6Address(DST)
        for shared in (0, 4, 8, 15, 16):
            for count in (1, 2, 3):
                addrs = [ipaddress.IPv6Address(DST[:shared] + bytes([0x40 + j]) * (16 - shared))
                         for j in range(count)]
                with self.subTest(shared=shared, count=count):
                    made = IPv6_Route(type=3, dst=dst, data={'ip': addrs}, seg_left=count).data
                    self.assertEqual(self.rebuild(IPv6_Route, made), made)
                    packet = ipv6(made)
                    self.assertEqual(self.rebuild(IPv6, packet), packet)
                    route = list(IPv6(packet, len(packet)).extension_headers.values())[0].info
                    self.assertEqual(list(route.ip), addrs)
                    self.assertLessEqual(route.cmpr_e, 15)

    def test_make_without_addresses_is_rejected(self) -> None:
        from pcapkit.protocols.internet.ipv6_route import IPv6_Route
        from pcapkit.utilities.exceptions import ProtocolError

        for dst in (None, ipaddress.IPv6Address(DST)):
            with self.subTest(dst=dst):
                with self.assertRaisesRegex(ProtocolError, 'needs at least one address'):
                    IPv6_Route(type=3, dst=dst, data={'ip': []})


if __name__ == '__main__':
    unittest.main()
