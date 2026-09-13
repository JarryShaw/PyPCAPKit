from __future__ import annotations

import importlib.util
import unittest

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PcapngRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_dhcp_pcapng_extracts_successfully(self) -> None:
        from pcapkit.interface import extract

        extractor = extract(fin='sample/dhcp.pcapng', fout='/tmp/out', format='tree', store=True, nofile=True)
        self.assertGreater(extractor.length, 0)

    def test_dhcp_big_endian_pcapng_extracts_successfully(self) -> None:
        from pcapkit.interface import extract

        extractor = extract(fin='sample/dhcp_big_endian.pcapng', fout='/tmp/out', format='tree', store=True, nofile=True)
        self.assertGreater(extractor.length, 0)

    def test_dhcp_little_endian_pcapng_extracts_successfully(self) -> None:
        from pcapkit.interface import extract

        extractor = extract(fin='sample/dhcp_little_endian.pcapng', fout='/tmp/out', format='tree', store=True, nofile=True)
        self.assertGreater(extractor.length, 0)

    def test_additional_pcapng_samples_extract_successfully(self) -> None:
        from pcapkit.interface import extract

        samples = (
            'sample/test.pcapng',
            'sample/many_interfaces.pcapng',
            'sample/profile.pcapng',
        )
        for sample in samples:
            with self.subTest(sample=sample):
                extractor = extract(fin=sample, fout='/tmp/out', format='tree', store=True, nofile=True)
                self.assertGreater(extractor.length, 0)


if __name__ == '__main__':
    unittest.main()
