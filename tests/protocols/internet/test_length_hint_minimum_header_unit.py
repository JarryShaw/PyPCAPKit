# -*- coding: utf-8 -*-
"""Every ``__length_hint__`` is its protocol's minimum header length.

GitHub issue #1173. :meth:`~pcapkit.protocols.protocol.ProtocolBase._parse_next_layer`
keeps a next layer as :class:`~pcapkit.protocols.misc.raw.Raw` when fewer octets
were captured than its ``__length_hint__`` (:issue:`1170`). ``IPv6_Route`` hinted
4 octets and ``MH`` 6, though each header is at least 8, so a stream of 4--7 or
6--7 octets was parsed and rebuilt as a full 8-octet header. ``HOPOPT`` and
``IPv6_Opts`` hinted 2 for the same 8-octet minimum. An application layer's
payload reaches the same guard through
:meth:`ProtocolBase._import_next_layer <pcapkit.protocols.protocol.ProtocolBase._import_next_layer>`.

"""
from __future__ import annotations

import importlib.util
import unittest
import unittest.mock

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


def ipv4(proto: int) -> bytes:
    """A complete 20-octet IPv4 header declaring a 300-octet ``proto`` payload."""
    return bytes.fromhex('4500012ca8370000fa') + bytes([proto]) + bytes.fromhex('178a00000000ffffffff')


#: An OSPFv2 Hello header with no authentication, declaring a 27-octet packet.
OSPF_HEADER = bytes.fromhex('0201001b010203040000000000000000') + bytes(8)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class LengthHintMinimumHeaderTests(unittest.TestCase):
    """A stream short of the minimum header rebuilds exactly what was captured."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_hints_are_the_eight_octet_minimum(self) -> None:
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
        from pcapkit.protocols.internet.ipv6_route import IPv6_Route
        from pcapkit.protocols.internet.mh import MH

        for klass in (IPv6_Route, MH, HOPOPT, IPv6_Opts):
            with self.subTest(klass=klass.__name__):
                self.assertEqual(object.__new__(klass).__length_hint__(), 8)

    def test_short_routing_and_mobility_headers_are_raw(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.misc.raw import Raw

        for proto, sizes in ((43, range(4, 8)), (135, range(6, 8))):
            for size in sizes:
                with self.subTest(proto=proto, size=size):
                    packet = ipv4(proto) + bytes(size)
                    parsed = IPv4(packet, len(packet))
                    self.assertIsInstance(parsed.payload, Raw)
                    self.assertEqual(IPv4.from_data(parsed.info).data, packet)

    def test_complete_headers_still_parse(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.internet.ipv6_route import IPv6_Route
        from pcapkit.protocols.internet.mh import MH

        for proto, klass in ((43, IPv6_Route), (135, MH)):
            with self.subTest(klass=klass.__name__):
                packet = ipv4(proto) + bytes([59]) + bytes(7)
                parsed = IPv4(packet, len(packet))
                self.assertIsInstance(parsed.payload, klass)
                self.assertEqual(parsed.payload.length, 8)

    def test_application_payload_goes_through_the_guard(self) -> None:
        from pcapkit.protocols.application.ospf import OSPF
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.protocol import ProtocolBase

        packet = OSPF_HEADER + b'\xab\xcd\xef'
        guard = ProtocolBase._parse_next_layer
        with unittest.mock.patch.object(ProtocolBase, '_parse_next_layer', side_effect=guard) as spy:
            parsed = OSPF(packet, len(packet))
        self.assertIsInstance(parsed.payload, Raw)
        self.assertEqual(parsed.payload.data, b'\xab\xcd\xef')
        self.assertEqual([call.args[0] for call in spy.call_args_list], [Raw])


if __name__ == '__main__':
    unittest.main()
