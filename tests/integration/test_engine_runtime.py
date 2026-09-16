from __future__ import annotations

import asyncio
import importlib.util
import sys
import unittest

from tests._support import close_extractor, purge_modules, sample_path

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

        extractor = extract(fin=sample_path('in.pcap'), fout='/tmp/out', format='tree', store=True, nofile=True, engine='default')
        self.addCleanup(close_extractor, extractor)

        self.assertEqual(extractor.length, 6)
        self.assertEqual(type(extractor.frame[0]).__name__, 'Frame')
        self.assertEqual(str(extractor.frame[0].protochain), 'Ethernet:IPv6:IPv6_ICMP')

    @unittest.skipUnless(HAS_DPKT, 'dpkt not installed')
    def test_dpkt_engine_returns_dpkt_packets_and_toolkit_chain(self) -> None:
        from pcapkit.interface import extract
        from pcapkit.toolkit.dpkt import packet2chain

        extractor = extract(fin=sample_path('in.pcap'), fout='/tmp/out', format='tree', store=True, nofile=True, engine='dpkt')
        self.addCleanup(close_extractor, extractor)

        frame = extractor.frame[0]
        self.assertEqual(extractor.length, 6)
        self.assertEqual(type(frame).__name__, 'Ethernet')
        self.assertEqual(packet2chain(frame), 'Ethernet:IP6:ICMP6')

    @unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
    def test_scapy_engine_returns_scapy_packets(self) -> None:
        # #406: this asserted ``Raw`` -- the engine imported only ``scapy.sendrecv``,
        # so scapy's layer registries were empty and every frame came back
        # undissected. ``Ether`` is what the capture actually holds: frame 1 of
        # in.pcap is an Ethernet frame carrying an ICMPv6 neighbour solicitation over
        # IPv6, which is exactly what the two tests above independently report for the
        # same frame -- 'Ethernet:IPv6:IPv6_ICMP' from the default engine and
        # 'Ethernet:IP6:ICMP6' from DPKT. The three chains are three libraries'
        # spellings of one frame, so scapy agreeing here is parity, not a new claim.
        from pcapkit.interface import extract
        from pcapkit.toolkit.scapy import packet2chain

        extractor = extract(fin=sample_path('in.pcap'), fout='/tmp/out', format='tree', store=True, nofile=True, engine='scapy')
        self.addCleanup(close_extractor, extractor)

        frame = extractor.frame[0]
        self.assertEqual(extractor.length, 6)
        self.assertEqual(type(frame).__name__, 'Ether')
        self.assertEqual(packet2chain(frame),
                         'Ethernet:IPv6:ICMPv6 Neighbor Discovery - Neighbor Solicitation:'
                         'ICMPv6 Neighbor Discovery Option - Source Link-Layer Address')
        self.assertGreater(len(bytes(frame)), 0)

    @unittest.skipUnless(HAS_PYSHARK, 'pyshark not installed')
    def test_pyshark_engine_is_refused_before_asyncio_can_break(self) -> None:
        """On 3.14 the engine is declined by the preflight, not by pyshark.

        This test used to assert the raw :exc:`AttributeError` from inside
        ``pyshark``, which was the honest description of the behaviour until
        :meth:`PyShark.unsupported_reason
        <pcapkit.foundation.engines.pyshark.PyShark.unsupported_reason>` began
        answering the question first. The preflight now names the interpreter as
        the cause and falls back, so the exception never happens -- and the
        extraction succeeds with ``pcapkit``'s own parser rather than failing.

        """
        from pcapkit.interface import extract
        from pcapkit.utilities.warnings import EngineWarning

        asyncio.set_event_loop(asyncio.new_event_loop())
        if not hasattr(asyncio, 'set_child_watcher'):
            asyncio.set_child_watcher = lambda watcher: None  # type: ignore[attr-defined]

        if sys.version_info >= (3, 14):
            with self.assertWarns(EngineWarning) as caught:
                extractor = extract(fin=sample_path('in.pcap'), fout='/tmp/out', format='tree', store=True, nofile=True, engine='pyshark')
            self.addCleanup(close_extractor, extractor)

            # The warning has to name the engine and the reason: "engine
            # unavailable" on its own sends the reader looking at their capture.
            message = str(caught.warnings[0].message)
            self.assertIn('PyShark', message)
            self.assertIn('3.14', message)

            # And the fall back is a working extraction, not an empty one.
            self.assertEqual(extractor.length, 6)
        else:
            extractor = extract(fin=sample_path('in.pcap'), fout='/tmp/out', format='tree', store=True, nofile=True, engine='pyshark')
            self.addCleanup(close_extractor, extractor)
            self.assertGreater(extractor.length, 0)


if __name__ == '__main__':
    unittest.main()
