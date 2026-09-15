# -*- coding: utf-8 -*-
"""What ``files=True`` actually writes to disk.

GH-358: every per-frame report landed with two dots before its extension --
``Frame 1..json``, ``Global Header..txt``, ``Section Header 1..plist``. The name
was composed as ``f'{name}.{ext._fext}'`` while ``_fext`` still carried its own
leading dot, so the separator was supplied twice.

The unit-tier half of this lives in :file:`tests/foundation/test_extraction.py`
and pins :meth:`Extractor.make_name
<pcapkit.foundation.extraction.Extractor.make_name>` to returning a bare
extension. This module checks the thing the user sees: the names on disk, for
both engines and every format that reaches a file. A test of ``make_name`` alone
would keep passing if an engine started supplying the dot twice again, so the
two are complementary rather than redundant.

"""
from __future__ import annotations

import importlib.util
import unittest

from tests.integration._helpers import EndToEndTestCase
from tests._support import sample_path

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Output formats that ``files=True`` can be driven with, and the extension each
#: is expected to land on.
#:
#: Three registered formats are deliberately absent, each because it raises
#: before any file is named -- so none of them can say anything about how a name
#: is composed, and all three are separate defects from GH-358:
#:
#: * ``'pcap'`` and ``'cap'`` -- ``PCAPIO.__init__`` wants a ``protocol``
#:   keyword that the extractor never supplies, so they fail with
#:   ``TypeError: PCAPIO.__init__() missing 1 required keyword-only argument``.
#: * ``'text'`` -- :attr:`Extractor.__output__
#:   <pcapkit.foundation.extraction.Extractor.__output__>` maps it to
#:   ``dictdumper.Text``, which :mod:`dictdumper` does not export, so it fails
#:   with ``AttributeError: module 'dictdumper' has no attribute 'Text'``.
FORMATS = {
    'json': '.json',
    'plist': '.plist',
    'xml': '.plist',
    'tree': '.txt',
    'txt': '.txt',
}


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class FilesOutputNamingTests(EndToEndTestCase):
    """Per-frame filenames written under ``files=True``."""

    def _names(self, capture: 'str', fmt: 'str') -> 'list[str]':
        """Sorted names of the files one ``files=True`` extraction wrote."""
        out = self.out(f'{capture.rsplit(".", 1)[0]}-{fmt}')
        self.extract(fin=sample_path(capture), fout=out, format=fmt,
                     files=True, store=False)
        import pathlib
        return sorted(entry.name for entry in pathlib.Path(out).iterdir())

    def test_pcap_per_frame_names_carry_exactly_one_dot(self) -> None:
        for fmt, suffix in FORMATS.items():
            with self.subTest(format=fmt):
                names = self._names('arp.pcap', fmt)

                self.assertEqual(names, [f'Frame 1{suffix}', f'Frame 2{suffix}',
                                         f'Global Header{suffix}'])
                for name in names:
                    self.assertEqual(name.count('.'), 1, name)
                    self.assertNotIn('..', name)

    def test_pcapng_per_frame_names_carry_exactly_one_dot(self) -> None:
        for fmt, suffix in FORMATS.items():
            with self.subTest(format=fmt):
                names = self._names('test.pcapng', fmt)

                # every block type the capture holds, not just the frames
                self.assertIn(f'Frame 1{suffix}', names)
                self.assertIn(f'Section Header 1{suffix}', names)
                self.assertIn(f'Interface Description 1{suffix}', names)
                for name in names:
                    self.assertEqual(name.count('.'), 1, name)
                    self.assertNotIn('..', name)

    def test_single_file_output_still_carries_exactly_one_dot(self) -> None:
        """The non-``files`` branch, which was already right and must stay right.

        ``make_name`` appends the extension itself here, so moving the dot out of
        ``_fext`` had to move it into this branch's f-string; a mistake would
        show up as ``report`` with no suffix, or ``report..json``.

        """
        for fmt, suffix in FORMATS.items():
            with self.subTest(format=fmt):
                extractor = self.extract(fin=sample_path('arp.pcap'),
                                         fout=self.out(f'report-{fmt}'),
                                         format=fmt, store=False)

                self.assertEqual(extractor.output, self.out(f'report-{fmt}{suffix}'))
                self.assertEqual(extractor.output.count('.'), 1)

    def test_output_name_already_carrying_the_suffix_is_left_alone(self) -> None:
        extractor = self.extract(fin=sample_path('arp.pcap'),
                                 fout=self.out('kept.json'), format='json',
                                 store=False)

        self.assertEqual(extractor.output, self.out('kept.json'))


if __name__ == '__main__':
    unittest.main()
