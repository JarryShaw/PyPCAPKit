# -*- coding: utf-8 -*-
"""A payload captured short of the next layer's header is kept as raw octets.

GitHub issue #1170. Every ``_import_next_layer`` parsed the next layer from
whatever octets were captured, however few, and only picked
:class:`~pcapkit.protocols.misc.null.NoPayload` for a declared length of zero.
:meth:`Schema.unpack <pcapkit.protocols.schema.schema.Schema.unpack>` zero-fills
the fields the stream ends inside, so
:meth:`~pcapkit.protocols.protocol.ProtocolBase.from_data` rebuilt a header that
was never captured. A payload with no captured octets is now a ``NoPayload``,
and one short of the next layer's header a
:class:`~pcapkit.protocols.misc.raw.Raw`.

"""
from __future__ import annotations

import importlib.util
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: A complete 20-octet IPv4 header declaring a 300-octet UDP datagram.
IPV4 = bytes.fromhex('4500012ca8370000fa11178a00000000ffffffff')
#: A complete 40-octet IPv6 header declaring a 168-octet UDP payload.
IPV6 = bytes.fromhex('6000000000a81140') + bytes(15) + b'\x01' + bytes(15) + b'\x02'
#: A UDP header (port 53 to 53, length 32) and the first of its payload octets.
UDP = bytes.fromhex('0035003500200000ab')
#: An Ethernet header carrying IPv4.
ETHERNET = bytes.fromhex('ffffffffffff0000000000010800')


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ShortNextLayerHeaderTests(unittest.TestCase):
    """The rebuild of a short payload is the octets that were captured."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_ipv6_header_without_payload_octets(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.misc.null import NoPayload

        parsed = IPv6(IPV6, len(IPV6))
        self.assertIsInstance(parsed.payload, NoPayload)
        self.assertEqual(IPv6.from_data(parsed.info).data, IPV6)

    def test_ipv6_partial_udp_header(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.misc.raw import Raw

        packet = IPV6 + UDP[:4]
        parsed = IPv6(packet, len(packet))
        self.assertIsInstance(parsed.payload, Raw)
        self.assertEqual(IPv6.from_data(parsed.info).data, packet)

    def test_ipv4_partial_udp_header(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.misc.raw import Raw

        for size in (1, 4, 7):
            with self.subTest(size=size):
                packet = IPV4 + UDP[:size]
                parsed = IPv4(packet, len(packet))
                self.assertIsInstance(parsed.payload, Raw)
                self.assertEqual(parsed.payload.data, UDP[:size])
                self.assertEqual(IPv4.from_data(parsed.info).data, packet)

    def test_udp_header_without_payload_octets(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.misc.null import NoPayload
        from pcapkit.protocols.transport.udp import UDP as UDP_

        packet = IPV4 + UDP[:8]
        parsed = IPv4(packet, len(packet))
        self.assertIsInstance(parsed.payload, UDP_)
        self.assertIsInstance(parsed.payload.payload, NoPayload)
        self.assertEqual(IPv4.from_data(parsed.info).data, packet)

    def test_ipv4_header_cut_short(self) -> None:
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.protocols.misc.raw import Raw

        frame = ETHERNET + IPV4[:18]
        parsed = Ethernet(frame, len(frame))
        self.assertIsInstance(parsed.payload, Raw)
        self.assertEqual(Ethernet.from_data(parsed.info).data, frame)

    def test_header_shorter_than_its_length_hint_still_parses(self) -> None:
        # A 12-octet L2TPv2 ZLB acknowledgement (flags T, L and S) is a whole
        # header, though ``L2TPv2.__length_hint__`` reports its 16-octet form.
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.link.l2tpv2 import L2TPv2

        zlb = bytes.fromhex('c802000c000100000001' '0002')
        udp = bytes.fromhex('06a506a5') + (8 + len(zlb)).to_bytes(2, 'big') + b'\x00\x00' + zlb
        ipv4 = IPV4[:2] + (20 + len(udp)).to_bytes(2, 'big') + IPV4[4:]
        packet = ipv4 + udp
        parsed = IPv4(packet, len(packet))
        self.assertIsInstance(parsed.payload.payload, L2TPv2)
        self.assertEqual(parsed.payload.payload.info.length, 12)

    def test_captured_header_is_still_parsed(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.transport.udp import UDP as UDP_

        packet = IPV4 + UDP
        parsed = IPv4(packet, len(packet))
        self.assertIsInstance(parsed.payload, UDP_)
        self.assertEqual(parsed.payload.info.srcport.port, 53)


if __name__ == '__main__':
    unittest.main()
