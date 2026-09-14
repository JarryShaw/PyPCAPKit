# -*- coding: utf-8 -*-
"""End-to-end parity between the extraction engines.

Translates :file:`examples/legacy_smoke/test_engine.py`, which ran the same
capture through each engine and wrote four reports nobody compared, into
assertions that the engines agree.

``pyshark`` is left out on purpose. It needs :program:`tshark`, which is not
installed here, and on Python 3.14 it fails inside its own
``get_event_loop()`` before it reads a byte;
:file:`tests/integration/test_engine_runtime.py` already pins that. The
``pipeline`` and ``server`` engines are commented out in the original script and
are not covered here either.

"""
from __future__ import annotations

import unittest

from tests._support import sample_path
from tests.integration._helpers import HAS_DPKT, HAS_RUNTIME, HAS_SCAPY, EndToEndTestCase

#: Captures every engine is run over, with the frame count each must report.
#: All three are small: the point is agreement, not throughput.
PARITY_CAPTURES = {
    'in.pcap': 6,
    'arp.pcap': 2,
    'tcp.pcap': 7,
    'http6.cap': 26,
}

#: Engines to compare, with the gate that decides whether each is available.
ENGINES = (
    ('default', HAS_RUNTIME),
    ('dpkt', HAS_DPKT),
    ('scapy', HAS_SCAPY),
)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class EngineParityTests(EndToEndTestCase):
    """The same capture through every available engine."""

    def available(self) -> 'list[str]':
        return [name for name, present in ENGINES if present]

    def test_every_engine_reports_the_same_frame_count(self) -> None:
        for capture, expected in PARITY_CAPTURES.items():
            counts = {}
            for engine in self.available():
                with self.subTest(capture=capture, engine=engine):
                    extractor = self.extract(fin=sample_path(capture), nofile=True,
                                             store=False, engine=engine)
                    counts[engine] = extractor.length
                    self.assertEqual(extractor.length, expected)

            with self.subTest(capture=capture):
                self.assertEqual(set(counts.values()), {expected})

    def test_every_engine_writes_a_report(self) -> None:
        for engine in self.available():
            with self.subTest(engine=engine):
                extractor = self.extract(fin=sample_path('in.pcap'),
                                         fout=self.out(f'{engine}-report'),
                                         format='tree', store=False, engine=engine)

                report = self.tmp_path / f'{engine}-report.txt'
                self.assertEqual(extractor.output, str(report))
                self.assertTrue(report.is_file())
                self.assertGreater(report.stat().st_size, 0)
                self.assertIn('Frame 6', report.read_text(encoding='utf-8'))

    def test_engine_macro_selects_the_same_engine_as_its_name(self) -> None:
        # The legacy scripts pass ``engine=pcapkit.PCAPKit`` rather than the
        # string, so the macro and the name have to be interchangeable.
        import pcapkit

        by_macro = self.extract(fin=sample_path('tcp.pcap'), nofile=True, store=True,
                                engine=pcapkit.PCAPKit)
        by_name = self.extract(fin=sample_path('tcp.pcap'), nofile=True, store=True,
                               engine='default')

        self.assertEqual(pcapkit.PCAPKit, 'default')
        self.assertEqual(by_macro.length, by_name.length)
        self.assertEqual([str(frame.protochain) for frame in by_macro.frame],
                         [str(frame.protochain) for frame in by_name.frame])

    @unittest.skipUnless(HAS_DPKT, 'dpkt not installed')
    def test_dpkt_engine_agrees_on_the_protocol_chain(self) -> None:
        # The engines hand back their own packet objects, so the chains are
        # spelled differently; the toolkit is what maps one onto the other.
        from pcapkit.toolkit.dpkt import packet2chain

        native = self.extract(fin=sample_path('in.pcap'), nofile=True, store=True,
                              engine='default')
        foreign = self.extract(fin=sample_path('in.pcap'), nofile=True, store=True,
                               engine='dpkt')

        self.assertEqual(str(native.frame[0].protochain), 'Ethernet:IPv6:IPv6_ICMP')
        self.assertEqual(packet2chain(foreign.frame[0]), 'Ethernet:IP6:ICMP6')
        self.assertEqual(str(native.frame[2].protochain), 'Ethernet:IPv4:TCP')
        self.assertEqual(packet2chain(foreign.frame[2]), 'Ethernet:IP:TCP')

    @unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
    def test_scapy_engine_returns_the_same_link_layer_bytes(self) -> None:
        native = self.extract(fin=sample_path('arp.pcap'), nofile=True, store=True,
                              engine='default')
        foreign = self.extract(fin=sample_path('arp.pcap'), nofile=True, store=True,
                               engine='scapy')

        self.assertEqual(len(native.frame), len(foreign.frame))
        for number, (mine, theirs) in enumerate(zip(native.frame, foreign.frame), start=1):
            with self.subTest(frame=number):
                # scapy does not know this capture's link type and hands back one
                # opaque ``Raw`` layer holding the whole 60 octet frame, padded to
                # the Ethernet minimum. Its first fourteen octets are the Ethernet
                # header that the default engine parsed into a layer of its own.
                captured = bytes(theirs)
                self.assertEqual(len(captured), 60)
                self.assertEqual(captured[:14], bytes(mine['Ethernet'].packet.header))


if __name__ == '__main__':
    unittest.main()
