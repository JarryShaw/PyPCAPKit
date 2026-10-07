# -*- coding: utf-8 -*-
"""Regression tests for #1127: extraction with ``format='pcap'``.

:class:`~pcapkit.foundation.extraction.Extractor` creates the output writer at
the engine's global-header step, via
:meth:`~pcapkit.foundation.extraction.Extractor._open_output`, because
:class:`~pcapkit.dumpkit.pcap.PCAPIO` needs that header's link type, byte order
and timestamp resolution to write its own.

"""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
import warnings

from pcapkit.interface import extract
from pcapkit.utilities.exceptions import FormatError
from pcapkit.utilities.warnings import FormatWarning
from tests._support import sample_path

HAS_DPKT = importlib.util.find_spec('dpkt') is not None
HAS_SCAPY = importlib.util.find_spec('scapy') is not None


def _extract(fin: str, fout: str, **kwargs):
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        return extract(fin=fin, fout=fout, nofile=False, **kwargs)


def _read(path: str) -> bytes:
    with open(path, 'rb') as file:
        return file.read()


class PCAPOutputTests(unittest.TestCase):

    def test_pcap_output_reproduces_the_input(self) -> None:
        for fmt in ('pcap', 'cap'):
            with self.subTest(format=fmt), tempfile.TemporaryDirectory() as tmp:
                extractor = _extract(sample_path('in.pcap'), os.path.join(tmp, 'out'), format=fmt)
                self.assertEqual(extractor.format, 'pcap')
                self.assertEqual(_read(extractor.output), _read(sample_path('in.pcap')))

    def test_split_pcap_output_writes_one_capture_per_frame(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            extractor = _extract(sample_path('in.pcap'), os.path.join(tmp, 'out'),
                                 format='pcap', files=True)
            self.assertEqual(extractor.format, 'pcap')
            header = _read(sample_path('in.pcap'))[:24]
            self.assertEqual(_read(os.path.join(extractor.output, 'Global Header.pcap')), header)
            for num in range(1, extractor.length + 1):
                path = os.path.join(extractor.output, f'Frame {num}.pcap')
                self.assertEqual(_read(path)[:24], header)
                self.assertEqual(_extract(path, os.path.join(tmp, 'again'), format='json').length, 1)

    def test_zero_frame_capture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            empty = os.path.join(tmp, 'empty.pcap')
            with open(empty, 'wb') as file:
                file.write(_read(sample_path('in.pcap'))[:24])
            extractor = _extract(empty, os.path.join(tmp, 'out'), format='pcap')
            self.assertEqual(extractor.format, 'pcap')
            self.assertEqual(_read(extractor.output), _read(empty))

    def test_pcapng_input_cannot_be_written_as_pcap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(FormatError, 'PCAP output is not supported'):
                _extract(sample_path('dhcp.pcapng'), os.path.join(tmp, 'out'), format='pcap')
            self.assertEqual(os.listdir(tmp), [])

    def test_other_formats_are_unaffected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            extractor = _extract(sample_path('in.pcap'), os.path.join(tmp, 'out'), format='json')
            with open(extractor.output, encoding='utf-8') as file:
                records = json.load(file)
        self.assertEqual(extractor.format, 'json')
        self.assertEqual(list(records)[0], 'Global Header')
        self.assertEqual(len(records), 1 + extractor.length)


class ThirdPartyEngineTests(unittest.TestCase):
    """These engines' frames carry no octets, so PCAP output falls back to JSON."""

    def _check(self, engine: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertWarnsRegex(FormatWarning, "does not support 'format=pcap'"):
                extractor = extract(fin=sample_path('in.pcap'), fout=os.path.join(tmp, 'out'),
                                    format='pcap', engine=engine, nofile=False)
            self.assertEqual(extractor.format, 'json')
            with open(extractor.output, encoding='utf-8') as file:
                self.assertEqual(list(json.load(file))[0], 'Global Header')

    @unittest.skipUnless(HAS_DPKT, 'dpkt not installed')
    def test_dpkt(self) -> None:
        self._check('dpkt')

    @unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
    def test_scapy(self) -> None:
        self._check('scapy')


if __name__ == '__main__':
    unittest.main()
