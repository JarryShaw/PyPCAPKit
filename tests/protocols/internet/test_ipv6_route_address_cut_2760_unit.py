# -*- coding: utf-8 -*-
"""A Type 0 Routing header cut inside its addresses reads no address past the cut.

GitHub issue #2760: a Type 0 Routing header the capture cut inside its addresses held every
address its Hdr Ext Len leaves room for, those past the cut read as ``::`` from no octet of
the capture. The address list ends with the data instead, as a list of schema items does
(#2756): the address the cut lands inside is read as far as it was captured, with zeros
after, and no address is made up past it.

The header keeps the length it declares, which its rebuild writes as captured, so every
cut rebuilds as its octets, from its info and from the info's dict, on its own and behind
IPv6 alike.

The headers are built here; this module is unit-tier and reads no capture file.

"""
from __future__ import annotations

import ipaddress
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): hand-picked parse -> rebuild round trips.
__tier__ = 'ALL'

#: The addresses of the header.
ADDRESSES = ('2001:db8::1', '2001:db8::2', '2001:db8::3')
#: A Type 0 Routing header naming no next header, its Hdr Ext Len sized for
#: :data:`ADDRESSES`, three segments left (RFC 2460, section 4.4).
ROUTE = (bytes([59, 2 * len(ADDRESSES), 0, len(ADDRESSES)]) + bytes(4)
         + b''.join(ipaddress.IPv6Address(address).packed for address in ADDRESSES))


def begun(keep: int) -> 'tuple[str, ...]':
    """The addresses the first ``keep`` octets of :data:`ROUTE` begin, the last read as its
    octets with zeros after them."""
    cut = ROUTE[:keep]
    return tuple(str(ipaddress.IPv6Address(cut[at:at + 16].ljust(16, b'\x00'))) for at in range(8, keep, 16))


class AddressListCutTests(unittest.TestCase):
    """A header cut inside its addresses holds the addresses its octets begin, and rebuilds."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.protocols.internet.ipv6_route.protocol import IPv6_Route

        self.IPv6, self.Route = IPv6, IPv6_Route
        catcher = warnings.catch_warnings()
        catcher.__enter__()
        self.addCleanup(catcher.__exit__, None, None, None)
        warnings.simplefilter('ignore')

    def parses(self, keep: int) -> 'dict[str, tuple[Any, Any, bytes]]':
        """:data:`ROUTE` cut ``keep`` octets in, parsed on its own and behind IPv6 declaring
        all of it: each as the protocol, its Routing header and the octets."""
        packet = wire.ipv6(ROUTE, nxt=43)
        raw = packet[:40 + keep]
        alone, framed = self.Route(ROUTE[:keep], keep), self.IPv6(raw, len(raw))
        (route,) = [ext for ext in framed.extension_headers.values() if isinstance(ext, self.Route)]
        return {'alone': (alone, alone, ROUTE[:keep]), 'framed': (framed, route, raw)}

    def test_the_cuts_reach_every_address(self) -> None:
        self.assertEqual(len(ROUTE), 8 + 16 * len(ADDRESSES))
        self.assertEqual(tuple(map(str, self.Route(ROUTE, len(ROUTE)).info.ip)), ADDRESSES)

    def test_a_cut_header_holds_the_addresses_it_begins(self) -> None:
        for keep in range(8, len(ROUTE)):
            for shape, (_, route, _) in self.parses(keep).items():
                with self.subTest(captured=keep, shape=shape):
                    self.assertEqual(tuple(map(str, route.info.ip)), begun(keep))
                    self.assertEqual(route.info.length, len(ROUTE))

    def test_a_cut_inside_the_second_address_reads_as_captured(self) -> None:
        for shape, (_, route, _) in self.parses(8 + 16 + 6).items():
            with self.subTest(shape=shape):
                self.assertEqual(tuple(map(str, route.info.ip)), ('2001:db8::1', '2001:db8::'))

    def test_a_cut_rebuilds_as_captured(self) -> None:
        for keep in range(8, len(ROUTE)):
            for shape, (proto, route, raw) in self.parses(keep).items():
                for path, layer, octets in (('outer', proto, raw), ('route', route, ROUTE[:keep])):
                    with self.subTest(captured=keep, shape=shape, layer=path):
                        cls = type(layer)
                        self.assertEqual(cls.from_data(layer.info).data, octets)
                        self.assertEqual(cls.from_data(layer.info.to_dict()).data, octets)

    def test_a_whole_header_is_the_control(self) -> None:
        for shape, (proto, route, raw) in self.parses(len(ROUTE)).items():
            with self.subTest(shape=shape):
                self.assertIsNone(route.info.get('__short_read__'))
                self.assertEqual(tuple(map(str, route.info.ip)), ADDRESSES)
                self.assertEqual(type(proto).from_data(proto.info).data, raw)


if __name__ == '__main__':
    unittest.main()
