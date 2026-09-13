from __future__ import annotations

import importlib.util
import unittest

from tests._support import close_extractor, purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPv6ExtensionRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _extract(self, sample: str):
        from pcapkit.interface import extract

        extractor = extract(fin=sample, fout='/tmp/out', format='tree', store=True, nofile=True)
        self.addCleanup(close_extractor, extractor)
        return extractor

    def test_ipv6_fragment_chain_records_extension_header_metadata(self) -> None:
        extractor = self._extract('sample/ipv6.pcap')
        frame = extractor.frame[12]
        ipv6 = frame.payload.payload
        frag = list(ipv6.extension_headers.values())[0]
        udp = ipv6.payload

        self.assertEqual(str(frame.protochain), 'Ethernet:IPv6:IPv6-Frag:UDP:Raw')
        self.assertEqual(ipv6.info.next.name, 'IPv6_Frag')
        self.assertEqual(ipv6.info.protocol.name, 'UDP')
        self.assertEqual(ipv6.info.hdr_len, 48)
        self.assertEqual(ipv6.info.raw_len, 1448)
        self.assertEqual([key.name for key in ipv6.extension_headers.keys()], ['IPv6_Frag'])

        self.assertEqual(frag.name, 'Fragment Header for IPv6')
        self.assertEqual(frag.alias, 'IPv6-Frag')
        self.assertEqual(frag.info.offset, 0)
        self.assertTrue(frag.info.mf)
        self.assertEqual(frag.info.id, 110308)

        self.assertEqual(int(udp.info.srcport), 4352)
        self.assertEqual(int(udp.info.dstport), 1)
        self.assertEqual(udp.info.len, 1)
        self.assertEqual(type(udp.payload).__name__, 'Raw')

        self.assertEqual(len(ipv6.info.fragment.header), 48)
        self.assertEqual(len(ipv6.info.fragment.payload), 1448)

    def test_ipv6_fragment_extension_forbids_direct_payload_accessors(self) -> None:
        from pcapkit.utilities.exceptions import UnsupportedCall

        extractor = self._extract('sample/ipv6.pcap')
        frame = extractor.frame[15]
        ipv6 = frame.payload.payload
        frag = list(ipv6.extension_headers.values())[0]

        self.assertEqual(str(frame.protochain), 'Ethernet:IPv6:IPv6-Frag:UDP:Raw')
        self.assertEqual(frag.info.offset, 543)
        self.assertFalse(frag.info.mf)
        self.assertEqual(frag.info.id, 110308)
        self.assertEqual(ipv6.info.raw_len, 434)
        self.assertEqual(len(ipv6.info.fragment.payload), 434)

        with self.assertRaises(UnsupportedCall):
            _ = frag.payload
        with self.assertRaises(UnsupportedCall):
            _ = frag.protocol
        with self.assertRaises(UnsupportedCall):
            _ = frag.protochain


if __name__ == '__main__':
    unittest.main()
