# -*- coding: utf-8 -*-
"""An IPv4 packet with no captured payload octets carries no payload layer.

GitHub issue #1167. :meth:`IPv4.read <pcapkit.protocols.internet.ipv4.IPv4.read>`
handed the next layer the length the header declared even when the capture held
none of its octets, so its UDP layer was parsed from an empty stream into an
all-zero header, and :meth:`~pcapkit.protocols.protocol.ProtocolBase.from_data`
rebuilt those 8 octets as if they had been on the wire. Such a payload is now a
:class:`~pcapkit.protocols.misc.null.NoPayload`. ``test.pcapng`` frame 3, cut
inside the IPv4 header itself (18 of 20 octets), is kept as raw octets
(:issue:`1170`).

The capture case reads a generated sample, so this module belongs to the
fixture-dependent tier. The in-memory cases need no capture.

"""
from __future__ import annotations

import importlib.util
import unittest

from tests._support import close_extractor, reimport_once_per_class, sample_path

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: A complete 20-octet IPv4 header declaring a 300-octet UDP datagram.
HEADER = bytes.fromhex('4500012ca8370000fa11178a00000000ffffffff')


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HeaderTruncatedPayloadTests(unittest.TestCase):
    """No payload octets captured means no payload layer parsed or rebuilt."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_capture_cut_inside_the_header(self) -> None:
        from pcapkit.interface import extract
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.protocols.misc.raw import Raw

        extractor = extract(fin=sample_path('test.pcapng'), fout='/tmp/out', format='tree',
                            store=True, nofile=True)
        self.addCleanup(close_extractor, extractor)
        parsed = list(extractor.frame)[2][Ethernet]

        # 18 octets are short of the 20-octet IPv4 header, so they are kept as
        # raw octets (:issue:`1170`) rather than parsed into a ``dst`` whose low
        # half is zero-filled, and the rebuild is exactly what was captured.
        self.assertIsInstance(parsed.payload, Raw)
        self.assertEqual(parsed.payload.data, bytes.fromhex('4500012ca8370000fa11178a00000000ffff'))
        self.assertEqual(Ethernet.from_data(parsed.info).data, parsed.data)

    def test_header_without_payload_octets(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.misc.null import NoPayload

        parsed = IPv4(HEADER, len(HEADER))
        self.assertIsInstance(parsed.payload, NoPayload)
        self.assertEqual(IPv4.from_data(parsed.info).data, HEADER)

    def test_captured_payload_is_still_parsed(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.transport.udp import UDP

        segment = bytes.fromhex('0035003500200000')
        parsed = IPv4(HEADER + segment, len(HEADER + segment))
        self.assertIsInstance(parsed.payload, UDP)
        self.assertEqual(parsed.payload.info.srcport.port, 53)


if __name__ == '__main__':
    unittest.main()
