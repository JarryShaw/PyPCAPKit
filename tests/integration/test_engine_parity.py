# -*- coding: utf-8 -*-
"""End-to-end runs of each extraction engine over the same captures.

Translates :file:`examples/legacy_smoke/test_engine.py`, which ran the same
capture through each engine and wrote four reports nobody checked, into
assertions on what each engine reports, against constants.

``pyshark`` is left out on purpose -- not for want of :program:`tshark`, which
the ``pypcap-parity`` job (the one whose selection collects this file)
installs, but because on Python 3.14 it fails inside its own
``get_event_loop()`` before it reads a byte, so it cannot take part in a check
that runs on every version;
:file:`tests/integration/test_engine_runtime.py` already pins that. The
``pipeline`` and ``server`` engines are commented out in the original script and
are not covered here either.

"""
from __future__ import annotations

import unittest

from tests._support import sample_path
from tests.integration._helpers import HAS_DPKT, HAS_RUNTIME, HAS_SCAPY, EndToEndTestCase

#: Test tier (#1958): compares the engines, whose releases vary by interpreter, on
#: hand-picked captures.
__tier__ = 'ALL'

#: Captures every engine is run over, with the frame count each must report.
#: All are small: the point is what each engine reports, not throughput.
PARITY_CAPTURES = {
    'in.pcap': 6,
    'arp.pcap': 2,
    'tcp.pcap': 7,
    'http6.cap': 26,
}

#: The Ethernet header of each frame of ``arp.pcap``, as captured.
ARP_ETHERNET_HEADERS = (bytes.fromhex('000c297d1db4000c2919dc610806'),
                        bytes.fromhex('000c2919dc61000c297d1db40806'))

#: Engines to run, with the gate that decides whether each is available.
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

    def test_every_engine_reports_the_frame_count(self) -> None:
        for capture, expected in PARITY_CAPTURES.items():
            for engine in self.available():
                with self.subTest(capture=capture, engine=engine):
                    extractor = self.extract(fin=sample_path(capture), nofile=True,
                                             store=False, engine=engine)
                    self.assertEqual(extractor.length, expected)

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
    def test_dpkt_engine_spells_the_protocol_chain_in_its_own_names(self) -> None:
        # The engine hands back dpkt's own packet objects, and the toolkit spells
        # their chain in dpkt's names.
        from pcapkit.toolkit.dpkt import packet2chain

        foreign = self.extract(fin=sample_path('in.pcap'), nofile=True, store=True,
                               engine='dpkt')

        self.assertEqual(packet2chain(foreign.frame[0]), 'Ethernet:IP6:ICMP6')
        self.assertEqual(packet2chain(foreign.frame[2]), 'Ethernet:IP:TCP')

    @unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
    def test_scapy_engine_returns_every_link_layer_octet(self) -> None:
        foreign = self.extract(fin=sample_path('arp.pcap'), nofile=True, store=True,
                               engine='scapy')

        self.assertEqual(len(foreign.frame), len(ARP_ETHERNET_HEADERS))
        for number, (frame, header) in enumerate(zip(foreign.frame, ARP_ETHERNET_HEADERS), start=1):
            with self.subTest(frame=number):
                # Re-serialising scapy's frame reproduces the whole 60 octet frame,
                # padded to the Ethernet minimum, its first fourteen octets the
                # Ethernet header as captured: the engine accounts for every
                # captured octet, whatever it calls the layers it splits it into.
                #
                # #406: this comment used to say scapy "does not know this capture's
                # link type and hands back one opaque ``Raw`` layer". That was the
                # missing-layer-registry bug, not a property of the capture --
                # arp.pcap is link type 1 and scapy now dissects it as
                # ``Ethernet / ARP / Padding``. The assertions below still pass
                # either way, because ``bytes()`` of a dissected frame is the same
                # octet string as ``bytes()`` of an undissected one.
                captured = bytes(frame)
                self.assertEqual(len(captured), 60)
                self.assertEqual(captured[:14], header)


if __name__ == '__main__':
    unittest.main()
