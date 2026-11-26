# -*- coding: utf-8 -*-
"""A stop at an IPv6 extension header ends the frame there (#3067).

:class:`~pcapkit.protocols.internet.ipv6.protocol.IPv6` walked its extension headers past
a ``protocol=`` stop naming one of them, so ``protocol='IPv6_Frag'`` still parsed the
UDP behind the Fragment header, while ``IPv6.analyze`` kept a reassembled payload
behind it raw (#2945). The walk now ends at the header the stop matches, by name or by
class, and the rest of the packet is the raw upper layer, named for that header's Next
Header, as a frame keeps the next layer of any layer it stops at.

A ``layer=`` stop needs nothing of its own: every extension header is in IPv6's own
layer, so a layer stop matching one has stopped IPv6 before the walk.

Every case builds its own octets in memory and reads no capture. Classes are imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import struct
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class
from tests.foundation.reassembly.test_dtls_handshake_reassembly_2440_unit import _extract, _pcap
from tests.foundation.reassembly.test_reassembly_parse_options_2933_unit import DNS, _fragments

if TYPE_CHECKING:
    from typing import Any

#: Source and destination addresses.
ADDRS = (bytes.fromhex('20010db8000000000000000000000001')
         + bytes.fromhex('20010db8000000000000000000000002'))

#: A UDP header and its payload.
UDP = bytes.fromhex('c822138900280000') + bytes(range(0x40, 0x60))


def datagram(code: int, payload: bytes) -> bytes:
    """An IPv6 datagram with Next Header ``code`` and ``payload``."""
    return (bytes.fromhex('60000000') + len(payload).to_bytes(2, 'big')
            + bytes((code, 64)) + ADDRS + payload)


def options(code: int) -> bytes:
    """A Hop-by-Hop or Destination Options header holding a PadN option."""
    return bytes((code, 0, 1, 4, 0, 0, 0, 0))


def routing(code: int) -> bytes:
    """A Routing header of type 0 with no segments left."""
    return bytes((code, 0, 0, 0, 0, 0, 0, 0))


def fragment(code: int) -> bytes:
    """An atomic Fragment header, walked as if unfragmented."""
    return bytes((code, 0, 0, 0)) + (110308).to_bytes(4, 'big')


def ah(code: int) -> bytes:
    """An Authentication Header with a 12-octet ICV."""
    return bytes((code, 4, 0, 0)) + struct.pack('!II', 0x100, 1) + bytes(12)


def mobility(code: int) -> bytes:
    """A Mobility Header carrying a Binding Refresh Request."""
    return bytes((code, 0, 0, 0, 0, 0, 0, 0))


def hip(code: int) -> bytes:
    """A HIPv2 I1 packet with no parameters."""
    return bytes((code, 4, 1, 0x21)) + bytes(36)


#: The headers of :data:`CHAIN`, in wire order: the stop naming each, its Next Header
#: code, and the builder of its octets.
WALK = (('HOPOPT', 0, options), ('IPv6_Route', 43, routing),
        ('IPv6_Frag', 44, fragment), ('IPv6_Opts', 60, options))

#: Headers the walk ends at on its own, each carrying UDP alone.
TERMINAL = (('AH', 51, ah), ('MH', 135, mobility), ('HIP', 139, hip))


def chain(headers: 'Any') -> 'tuple[bytes, list[bytes]]':
    """A datagram of ``headers`` then :data:`UDP`, and the octets past each header."""
    octets = UDP
    codes = [code for _, code, _ in headers] + [17]
    for (_, _, build), code in reversed(list(zip(headers, codes[1:]))):
        octets = build(code) + octets
    rests, rest = [], octets
    for _, _, build in headers:
        rest = rest[len(build(0)):]
        rests.append(rest)
    return datagram(codes[0], octets), rests


#: A HOPOPT, Routing, Fragment and Destination Options chain carrying UDP.
CHAIN, RESTS = chain(WALK)


class _Case(unittest.TestCase):

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def parse(self, data: bytes, **stops: 'Any') -> 'Any':
        from pcapkit.protocols.internet.ipv6.protocol import IPv6

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            ipv6 = IPv6(data, **stops)
        self.assertEqual(ipv6.data, data)
        return ipv6

    def assert_stopped(self, ipv6: 'Any', headers: 'Any', code: int, rest: bytes) -> None:
        """``ipv6`` walked ``headers`` alone, the rest raw under Next Header ``code``."""
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.protocols.misc.raw.protocol import Raw

        self.assertEqual([type(ext).__name__ for ext in ipv6.extension_headers.values()],
                         [name for name, _, _ in headers])
        self.assertIs(type(ipv6.payload), Raw)
        self.assertEqual(ipv6.payload.info.protocol, TransType(code))
        self.assertEqual(ipv6.payload.data, rest)
        self.assertEqual(ipv6.info.protocol, TransType(code))
        self.assertEqual(IPv6.from_data(ipv6.info).data, ipv6.data)


class FragmentStopTests(_Case):
    """A frame ends at a stop at its Fragment header, as ``analyze`` does."""

    def test_a_stop_at_the_fragment_header_keeps_its_upper_layer_raw(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.protocols.internet.ipv6_frag.protocol import IPv6_Frag
        from pcapkit.protocols.misc.raw.protocol import Raw

        first, later = _fragments('ipv6', DNS, 17)
        for stop in ('IPv6_Frag', IPv6_Frag):
            with self.subTest(stop=stop):
                extractor = _extract(self, _pcap([first, later]), protocol=stop, reassembly=['ipv6'])
                head, tail = extractor.frame
                self.assertEqual(str(head.protochain), 'Ethernet:IPv6:IPv6-Frag:UDP')
                self.assertNotIn('UDP', head)
                ipv6 = head['IPv6']
                self.assertIs(type(ipv6.payload), Raw)
                self.assertEqual(ipv6.payload.data, DNS[:16])
                self.assertEqual(ipv6.payload.info,
                                 IPv6.analyze(TransType.UDP, DNS[:16], protocol=stop).info)

                # a later fragment's slice was raw already, and reassembly still
                # takes the split at the Fragment header the stop matched
                self.assertEqual(str(tail.protochain), 'Ethernet:IPv6:IPv6-Frag:Raw')
                self.assertIsNone(tail['IPv6'].payload.info.protocol)
                datagram_, = extractor.reassembly.ipv6
                self.assertIs(type(datagram_.packet), Raw)
                self.assertEqual(bytes(datagram_.packet), DNS)

    def test_a_walk_past_the_fragment_header_stops_there(self) -> None:
        ipv6 = self.parse(CHAIN, protocol='IPv6_Frag')
        self.assertEqual(str(ipv6.protochain), 'IPv6:HOPOPT:IPv6-Route:IPv6-Frag:IPv6_Opts')
        self.assert_stopped(ipv6, WALK[:3], 60, RESTS[2])
        self.assertEqual(ipv6.info.fragment.payload, RESTS[2])


class HeaderStopTests(_Case):
    """A stop at any other header the walk parses ends the walk there."""

    def test_a_stop_at_a_chained_header_keeps_the_rest_raw(self) -> None:
        whole = self.parse(CHAIN)
        codes = [code for _, code, _ in WALK[1:]] + [17]
        for index, (name, _, _) in enumerate(WALK):
            if name == 'IPv6_Frag':
                continue
            with self.subTest(stop=name):
                ipv6 = self.parse(CHAIN, protocol=name)
                self.assert_stopped(ipv6, WALK[:index + 1], codes[index], RESTS[index])
                self.assertEqual([ext.info for ext in ipv6.extension_headers.values()],
                                 [ext.info for ext in whole.extension_headers.values()][:index + 1])
                # NOTE: A stop short of the Fragment header leaves no split for reassembly.
                self.assertIs('fragment' in ipv6.info, index >= 2)

    def test_a_stop_at_a_terminal_header_keeps_the_rest_raw(self) -> None:
        for name, code, build in TERMINAL:
            with self.subTest(stop=name):
                ipv6 = self.parse(datagram(code, build(17) + UDP), protocol=name)
                self.assert_stopped(ipv6, ((name, code, build),), 17, UDP)


class ClassStopTests(_Case):
    """A stop given as a class matches as its name does."""

    def test_a_class_valued_stop_ends_the_walk_at_its_header(self) -> None:
        classes = [type(ext) for ext in self.parse(CHAIN).extension_headers.values()]
        codes = [code for _, code, _ in WALK[1:]] + [17]
        for index, ((name, _, _), klass) in enumerate(zip(WALK, classes)):
            with self.subTest(stop=klass):
                ipv6 = self.parse(CHAIN, protocol=klass)
                self.assert_stopped(ipv6, WALK[:index + 1], codes[index], RESTS[index])
                self.assertEqual(ipv6.info, self.parse(CHAIN, protocol=name).info)

    def test_the_family_base_stops_at_the_first_header(self) -> None:
        from pcapkit.protocols.internet.ipv6_ext.protocol import IPv6_Ext

        # NOTE: ``IPv6_Ext.id()`` lists every member, so it matches the first header walked.
        for stop in (IPv6_Ext, 'IPv6_Ext'):
            with self.subTest(stop=stop):
                ipv6 = self.parse(CHAIN, protocol=stop)
                self.assertEqual(str(ipv6.protochain), 'IPv6:HOPOPT:IPv6_Route')
                self.assert_stopped(ipv6, WALK[:1], 43, RESTS[0])


class LayerStopTests(_Case):
    """A ``layer=`` stop reaches the walk only through IPv6's own."""

    def test_a_layer_stop_composes_with_a_header_stop(self) -> None:
        ipv6 = self.parse(CHAIN, layer='Transport', protocol='IPv6_Opts')
        self.assertEqual(str(ipv6.protochain), 'IPv6:HOPOPT:IPv6-Route:IPv6-Frag:IPv6-Opts:UDP')
        self.assert_stopped(ipv6, WALK, 17, UDP)

        # NOTE: Every extension header is in IPv6's layer, so a layer stop matching one
        # stops IPv6 itself, and the walk parses none.
        ipv6 = self.parse(CHAIN, layer='Internet')
        self.assertEqual(str(ipv6.protochain), 'IPv6:HOPOPT')
        self.assert_stopped(ipv6, (), 0, CHAIN[40:])


if __name__ == '__main__':
    unittest.main()
