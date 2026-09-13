from __future__ import annotations

import asyncio
import importlib.util
import sys
import unittest

from tests._support import close_extractor, purge_modules

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))
HAS_DPKT = importlib.util.find_spec('dpkt') is not None
HAS_SCAPY = importlib.util.find_spec('scapy') is not None
HAS_PYSHARK = importlib.util.find_spec('pyshark') is not None


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class EngineRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_default_engine_exposes_native_frame_objects(self) -> None:
        from pcapkit.interface import extract

        extractor = extract(fin='sample/in.pcap', fout='/tmp/out', format='tree', store=True, nofile=True, engine='default')
        self.addCleanup(close_extractor, extractor)

        self.assertEqual(extractor.length, 6)
        self.assertEqual(type(extractor.frame[0]).__name__, 'Frame')
        self.assertEqual(str(extractor.frame[0].protochain), 'Ethernet:IPv6:IPv6_ICMP')

    @unittest.skipUnless(HAS_DPKT, 'dpkt not installed')
    def test_dpkt_engine_returns_dpkt_packets_and_toolkit_chain(self) -> None:
        from pcapkit.interface import extract
        from pcapkit.toolkit.dpkt import packet2chain

        extractor = extract(fin='sample/in.pcap', fout='/tmp/out', format='tree', store=True, nofile=True, engine='dpkt')
        self.addCleanup(close_extractor, extractor)

        frame = extractor.frame[0]
        self.assertEqual(extractor.length, 6)
        self.assertEqual(type(frame).__name__, 'Ethernet')
        self.assertEqual(packet2chain(frame), 'Ethernet:IP6:ICMP6')

    @unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
    def test_scapy_engine_returns_scapy_packets(self) -> None:
        from pcapkit.interface import extract

        extractor = extract(fin='sample/in.pcap', fout='/tmp/out', format='tree', store=True, nofile=True, engine='scapy')
        self.addCleanup(close_extractor, extractor)

        frame = extractor.frame[0]
        self.assertEqual(extractor.length, 6)
        self.assertEqual(type(frame).__name__, 'Raw')
        self.assertGreater(len(bytes(frame)), 0)

    @unittest.skipUnless(HAS_PYSHARK, 'pyshark not installed')
    def test_pyshark_engine_currently_breaks_on_modern_asyncio(self) -> None:
        from pcapkit.interface import extract

        asyncio.set_event_loop(asyncio.new_event_loop())
        if not hasattr(asyncio, 'set_child_watcher'):
            asyncio.set_child_watcher = lambda watcher: None  # type: ignore[attr-defined]

        if sys.version_info >= (3, 14):
            with self.assertRaises(AttributeError):
                extract(fin='sample/in.pcap', fout='/tmp/out', format='tree', store=True, nofile=True, engine='pyshark')
        else:
            extractor = extract(fin='sample/in.pcap', fout='/tmp/out', format='tree', store=True, nofile=True, engine='pyshark')
            self.addCleanup(close_extractor, extractor)
            self.assertGreater(extractor.length, 0)


if __name__ == '__main__':
    unittest.main()
