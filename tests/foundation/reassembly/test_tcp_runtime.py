from __future__ import annotations

import importlib.util
import unittest

from tests._support import close_extractor, purge_modules, sample_path

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TCPReassemblyRuntimeTests(unittest.TestCase):
    """TCP reassembly end to end, through the extractor, on a sample capture.

    This lives in a ``*_runtime.py`` module rather than beside the unit tests
    because it reads a generated capture: ``examples/captures/`` holds only a
    handful of committed fixtures, and the rest are rebuilt by
    ``examples/generators/make_samples.py``. The unit-test workflow skips this
    file for exactly that reason, and the integration workflow generates the
    fixtures before running it.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_sample_capture_reassembles_every_stream_byte_exactly(self) -> None:
        """``test.pcap`` through :func:`~pcapkit.interface.extract`.

        The capture has out-of-order segments, a retransmission, and a segment
        recovered only after a later one, all with realistic initial sequence
        numbers -- so it exercises the whole path rather than the reassembler
        alone. Each datagram is compared against the octets rebuilt
        independently from the frames it names, by placing each segment's
        payload at its own sequence number, which is what makes the comparison
        a check rather than a restatement.

        """
        from pcapkit import extract

        extractor = extract(fin=sample_path('test.pcap'), fout='/tmp/out', format='tree',
                            store=True, nofile=True, tcp=True, reassembly=True,
                            reasm_strict=True)
        self.addCleanup(close_extractor, extractor)

        frames = {frame.info.number: frame for frame in extractor.frame}
        datagrams = extractor.reassembly.tcp
        self.assertEqual(len(datagrams), 4)

        for datagram in datagrams:
            with self.subTest(index=datagram.index):
                segments = []
                for number in datagram.index:
                    tcp = frames[number]['TCP']
                    payload = bytes(tcp.packet.payload)
                    if payload:
                        segments.append((tcp.info.seq, payload))

                origin = min(seq for (seq, _) in segments)
                expected = bytearray(max(seq - origin + len(payload)
                                         for (seq, payload) in segments))
                for (seq, payload) in segments:
                    expected[seq - origin:seq - origin + len(payload)] = payload

                self.assertTrue(datagram.completed)
                self.assertIsNotNone(datagram.packet)
                self.assertEqual(datagram.payload, bytes(expected))

        # the four messages the fixture is built around, by length and opening
        self.assertEqual(sorted(len(datagram.payload) for datagram in datagrams),
                         [110, 269, 3642, 4587])
        self.assertEqual(sorted(bytes(datagram.payload[:4]) for datagram in datagrams),
                         [b'GET ', b'HTTP', b'HTTP', b'POST'])


if __name__ == '__main__':
    unittest.main()
