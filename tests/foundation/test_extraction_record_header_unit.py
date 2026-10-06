# -*- coding: utf-8 -*-
"""Regression tests for #1104: the third-party engines share :meth:`Extractor.record_header`.

`DPKT`_, `Scapy`_ and `PyShark`_ each call
:meth:`~pcapkit.foundation.extraction.Extractor.record_header` at setup, so their
output opens with the header record the built-in engines write -- ``Global
Header`` for PCAP, ``Section Header 1`` for PCAP-NG -- and
:attr:`~pcapkit.foundation.extraction.Extractor.format` is set at header time,
which is what makes it work on a capture with no frames.

`PyShark`_ cannot run on the 3.14 interpreter these tests use, so it is driven
through a stand-in ``pyshark`` module.

.. _DPKT: https://dpkt.readthedocs.io
.. _Scapy: https://scapy.net
.. _PyShark: https://kiminewt.github.io/pyshark

"""
from __future__ import annotations

import importlib
import importlib.util
import json
import os
import tempfile
import types
import unittest
import warnings
from unittest import mock

from pcapkit.interface import extract
from tests._support import sample_path

HAS_DPKT = importlib.util.find_spec('dpkt') is not None
HAS_SCAPY = importlib.util.find_spec('scapy') is not None


def _run(fin: str, engine: str, tmp: str, **kwargs):
    """Extract ``fin`` to JSON under ``tmp``, returning the extractor and its records."""
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        extractor = extract(fin=fin, fout=os.path.join(tmp, 'out'), engine=engine,
                            format='json', nofile=False, **kwargs)
    with open(extractor.output, encoding='utf-8') as file:
        return extractor, json.load(file)


def _empty_pcap(tmp: str) -> str:
    """A PCAP file holding only the global header of ``in.pcap``."""
    path = os.path.join(tmp, 'empty.pcap')
    with open(sample_path('in.pcap'), 'rb') as src, open(path, 'wb') as dst:
        dst.write(src.read(24))
    return path


class _HeaderStepCases:
    """Shared cases, run once per real third-party engine."""

    engine: str

    def test_pcap_output_opens_with_the_global_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _, default = _run(sample_path('in.pcap'), 'default', tmp)
        with tempfile.TemporaryDirectory() as tmp:
            extractor, records = _run(sample_path('in.pcap'), self.engine, tmp)
        self.assertEqual(type(extractor.engine).__name__, self.engine_class)
        self.assertEqual(list(records)[0], 'Global Header')
        self.assertEqual(records['Global Header'], default['Global Header'])
        self.assertEqual(len(records), 1 + extractor.length)

    def test_pcapng_output_opens_with_the_section_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _, records = _run(sample_path('dhcp.pcapng'), self.engine, tmp)
        self.assertEqual(list(records)[0], 'Section Header 1')

    def test_zero_frame_capture_has_a_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            extractor, records = _run(_empty_pcap(tmp), self.engine, tmp)
            self.assertEqual(extractor.format, 'json')
        self.assertEqual(list(records), ['Global Header'])

    def test_split_output_writes_a_global_header_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = extract(fin=sample_path('in.pcap'), fout=os.path.join(tmp, 'out'),
                                engine=self.engine, format='json', files=True, nofile=False)
            self.assertEqual(extractor.format, 'json')
            self.assertIn('Global Header.json', os.listdir(os.path.join(tmp, 'out')))


@unittest.skipUnless(HAS_DPKT, 'dpkt not installed')
class DPKTHeaderStepTests(_HeaderStepCases, unittest.TestCase):
    engine = 'dpkt'
    engine_class = 'DPKT'


@unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
class ScapyHeaderStepTests(_HeaderStepCases, unittest.TestCase):
    engine = 'scapy'
    engine_class = 'Scapy'


class PySharkHeaderStepTests(unittest.TestCase):
    """`PyShark`_ through a stand-in module, so neither it nor :program:`tshark` is needed."""

    def _run(self, fin: str, packets: list):
        from pcapkit.foundation.engines.pyshark import PyShark

        # The dotted-string patch re-reads ``pyshark`` as an attribute of ``pcapkit.toolkit``,
        # which breaks on 3.10 when that attribute of ``pcapkit`` is not the object in
        # ``sys.modules`` (what a module-table restore can leave). Patch the submodule
        # object from ``sys.modules``, which is also where the engine imports it from.
        toolkit = importlib.import_module('pcapkit.toolkit.pyshark')

        class FakeCapture:
            def __init__(self, *args, **kwargs) -> None:
                self.packets = iter(packets)

            def next(self):
                return next(self.packets)

            def close(self) -> None:
                pass

        fake = types.ModuleType('pyshark')
        fake.FileCapture = FakeCapture  # type: ignore[attr-defined]
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict('sys.modules', {'pyshark': fake}), \
                mock.patch.object(PyShark, 'unsupported_reason', return_value=None), \
                mock.patch.object(toolkit, 'packet2dict', return_value={'packet': True}):
            extractor, records = _run(fin, 'pyshark', tmp)
            fmt = extractor.format
        self.assertIsInstance(extractor.engine, PyShark)
        return fmt, records

    def test_pcap_output_opens_with_the_global_header(self) -> None:
        packet = types.SimpleNamespace(number='1')
        fmt, records = self._run(sample_path('in.pcap'), [packet])
        self.assertEqual(fmt, 'json')
        self.assertEqual(list(records), ['Global Header', 'Frame 1'])

    def test_zero_frame_capture_has_a_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fmt, records = self._run(_empty_pcap(tmp), [])
        self.assertEqual(fmt, 'json')
        self.assertEqual(list(records), ['Global Header'])


if __name__ == '__main__':
    unittest.main()
