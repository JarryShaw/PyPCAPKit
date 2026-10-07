# -*- coding: utf-8 -*-
"""The JSON report of :file:`test.pcapng` parses (GitHub issue #1152).

The fixture's decryption secrets block keys its TLS key log entries by a raw
:class:`bytes` client random, whose repr holds both a ``"`` and a ``\\``.
:class:`dictdumper.json.JSON` wrote that key unescaped, and :func:`json.load`
stopped at line 1019 with ``Expecting ':' delimiter``.

This module is fixture-tier by its ``_regression.py`` name -- ``test.pcapng`` is
generated rather than committed (see :mod:`tests._tiers`).

"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest

from tests._support import close_extractor, reimport_once_per_class, sample_path

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: The fixture's client random as the writer renders it, i.e. the ``bytes`` repr
#: of every character from ``0x20`` to ``0x3F``.
RAW_BYTES_KEY = """b' !"#$%&\\'()*+,-./0123456789:;<=>?'"""


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestPcapngJSONReportTests(unittest.TestCase):
    """The ``json`` report of :file:`test.pcapng`."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

        tmpdir = tempfile.TemporaryDirectory(prefix='pcapkit-1152-')
        self.addCleanup(tmpdir.cleanup)
        self.tmp_path = pathlib.Path(tmpdir.name)

    def test_the_json_report_parses_and_keeps_the_bytes_key(self) -> None:
        """The report loads, and the client random reads back unchanged."""
        from pcapkit.interface import extract

        output = self.tmp_path / 'test.pcapng.json'
        extractor = extract(fin=sample_path('test.pcapng'), fout=str(output), format='json',
                            store=False, extension=False)
        self.addCleanup(close_extractor, extractor)

        with output.open(encoding='utf-8') as file:
            report = json.load(file)

        entries = [frame['secrets_data']['entries'] for frame in report.values()
                   if isinstance(frame, dict) and 'secrets_data' in frame]
        self.assertEqual(len(entries), 1)
        self.assertIn(RAW_BYTES_KEY, entries[0]['CLIENT_RANDOM'][0])


if __name__ == '__main__':
    unittest.main()
