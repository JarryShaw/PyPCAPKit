from __future__ import annotations

import importlib.util
import struct
import unittest

from tests._support import purge_modules, sample_path

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PcapFrameRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_frame_exposes_expected_public_metadata(self) -> None:
        from pcapkit.interface import extract

        extractor = extract(fin=sample_path('in.pcap'), fout='/tmp/out', format='tree', store=True, nofile=True)
        frame = extractor.frame[0]

        self.assertEqual(frame.name, 'Frame 1')
        self.assertEqual(str(frame.protochain), 'Ethernet:IPv6:IPv6_ICMP')
        self.assertEqual(frame.protochain.aliases, ('Ethernet', 'IPv6', 'IPv6_ICMP'))
        self.assertEqual(frame.index('IPv6'), 1)
        self.assertEqual(frame.info.number, 1)
        self.assertEqual(frame.info.cap_len, frame.info.len)

    def test_frame_packet_and_payload_walk_protocol_stack(self) -> None:
        from pcapkit.interface import extract

        extractor = extract(fin=sample_path('arp.pcap'), fout='/tmp/out', format='tree', store=True, nofile=True)
        frame = extractor.frame[0]

        self.assertEqual(type(frame.packet).__name__, 'Packet')
        self.assertEqual(type(frame.payload).__name__, 'Ethernet')
        self.assertEqual(type(frame.payload.payload).__name__, 'ARP')
        self.assertEqual(type(frame.payload.payload.payload).__name__, 'Raw')

    def test_frame_info_records_protocol_summary(self) -> None:
        from pcapkit.interface import extract

        extractor = extract(fin=sample_path('arp.pcap'), fout='/tmp/out', format='tree', store=True, nofile=True)
        frame = extractor.frame[0]

        self.assertEqual(frame.info.protocols, 'Ethernet:ARP:Raw')
        self.assertIsNotNone(frame.info.ethernet)
        self.assertEqual(frame.payload.name, 'Ethernet Protocol')
        self.assertEqual(frame.payload.payload.name, 'Address Resolution Protocol')
        self.assertEqual(frame.payload.payload.payload.name, 'Unknown')

    def test_extracted_frames_carry_their_own_record_bytes(self) -> None:
        """#357, through the whole extractor rather than one ``Frame``.

        ``arp.pcap`` holds two records of identical length, which is the shape
        that made the defect legible: frame 1's payload was frame 2's record
        header onwards, and frame 2 -- having nothing left to read -- came back
        as 16 octets instead of 76. The unit-tier counterpart in
        :file:`tests/protocols/misc/pcap/test_header_frame_unit.py` drives
        ``Frame`` directly; this one goes through
        :func:`pcapkit.interface.extract`, which is the path every caller
        actually uses.

        """
        from pcapkit.interface import extract

        path = sample_path('arp.pcap')
        with open(path, 'rb') as stream:
            raw = stream.read()

        records = []
        offset = 24
        while offset < len(raw):
            incl_len, = struct.unpack_from('<I', raw, offset + 8)
            records.append((offset, 16 + incl_len))
            offset += 16 + incl_len
        self.assertEqual(records, [(24, 76), (100, 76)])

        extractor = extract(fin=path, store=True, nofile=True)
        self.assertEqual(len(extractor.frame), len(records))

        for frame, (start, total) in zip(extractor.frame, records):
            expected = raw[start:start + total]
            self.assertEqual(bytes(frame), expected)
            self.assertEqual(frame.packet.header, expected[:16])
            self.assertEqual(frame.packet.payload, expected[16:])
            # the nested layer was always right -- it is parsed from the
            # schema's payload rather than from the frame's raw data -- so this
            # pins the two to each other, which is what was broken
            self.assertEqual(bytes(frame.payload), expected[16:16 + frame.info.len])


if __name__ == '__main__':
    unittest.main()
