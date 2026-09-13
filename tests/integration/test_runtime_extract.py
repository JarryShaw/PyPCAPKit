from __future__ import annotations

import importlib.util
import os
import unittest

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class RuntimeExtractionTests(unittest.TestCase):
    def test_extract_reads_small_pcap_sample(self) -> None:
        from pcapkit.interface import extract

        extractor = extract(fin='sample/in.pcap', fout='/tmp/pypcapkit-out', format='tree', store=True, nofile=True)

        self.assertEqual(extractor.length, 6)
        self.assertEqual(len(extractor.frame), 6)
        self.assertEqual(extractor.magic_number, b'\xd4\xc3\xb2\xa1')

    def test_extract_reads_arp_sample(self) -> None:
        from pcapkit.interface import extract

        extractor = extract(fin='sample/arp.pcap', fout='/tmp/pypcapkit-out', format='tree', store=True, nofile=True)

        self.assertEqual(extractor.length, 2)
        self.assertEqual(len(extractor.frame), 2)

    def test_manual_iteration_mode_yields_frames(self) -> None:
        from pcapkit.interface import extract

        extractor = extract(fin='sample/in.pcap', fout='/tmp/pypcapkit-out', format='tree', store=False, nofile=True, auto=False)
        first = next(extractor)
        second = extractor()

        self.assertEqual(type(first).__name__, 'Frame')
        self.assertEqual(type(second).__name__, 'Frame')

    def test_reassemble_and_trace_factories_build_runtime_objects(self) -> None:
        from pcapkit.interface import reassemble, trace

        self.assertEqual(type(reassemble('IPv4')).__name__, 'IPv4')
        self.assertEqual(type(reassemble('IPv6')).__name__, 'IPv6')
        self.assertEqual(type(reassemble('TCP')).__name__, 'TCP')
        self.assertEqual(type(trace('TCP', fout=None, format=None)).__name__, 'TCP')


if __name__ == '__main__':
    unittest.main()
