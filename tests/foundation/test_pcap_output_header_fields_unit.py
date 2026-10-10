# -*- coding: utf-8 -*-
"""Regression tests for #1165: ``format='pcap'`` keeps ``thiszone``, ``sigfigs``
and ``snaplen``.

The PCAP engine passes all three from the input's global header to
:meth:`~pcapkit.foundation.extraction.Extractor._open_output`, so
:class:`~pcapkit.dumpkit.pcap.PCAPIO` writes them back instead of the
:class:`~pcapkit.protocols.misc.pcap.header.Header` defaults.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load. Under
plain :mod:`unittest` a sibling class leaves its own re-import in
:data:`sys.modules`; the extractor resolves ``PCAPIO`` from there, and a
load-time ``extract`` would test it against a stale ``DumperBase`` and hand
the writer a :class:`dict` instead of the frame's info (#1523).

"""
from __future__ import annotations

import importlib
import os
import struct
import tempfile
import unittest
import warnings

from tests._support import purge_modules, reimport_once_per_class, sample_path

#: Values that differ from every :class:`~pcapkit.protocols.misc.pcap.header.Header`
#: default (``0``, ``0`` and ``262144``).
THISZONE, SIGFIGS, SNAPLEN = -3600, 7, 1514


def _extract(fin: str, fout: str, **kwargs):
    from pcapkit.interface import extract

    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        return extract(fin=fin, fout=fout, nofile=False, format='pcap', **kwargs)


def _read(path: str) -> bytes:
    with open(path, 'rb') as file:
        return file.read()


def _with_header_fields(data: bytes) -> bytes:
    """Rewrite bytes 8--20 of a PCAP file in the byte order of its magic number."""
    endian = '<' if data[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    return data[:8] + struct.pack(f'{endian}iII', THISZONE, SIGFIGS, SNAPLEN) + data[20:]


class PCAPOutputHeaderFieldsTests(unittest.TestCase):

    def setUp(self) -> None:
        reimport_once_per_class(self)
        self.tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(self.tmp.cleanup)
        self.input = os.path.join(self.tmp.name, 'in.pcap')
        with open(self.input, 'wb') as file:
            file.write(_with_header_fields(_read(sample_path('in.pcap'))))

    def test_whole_capture_round_trips_byte_identically(self) -> None:
        extractor = _extract(self.input, os.path.join(self.tmp.name, 'out'))
        self.assertEqual(_read(extractor.output), _read(self.input))

    def test_a_newer_import_left_by_a_sibling_is_the_one_used(self) -> None:
        # What a sibling class leaves behind under plain unittest (#1523).
        purge_modules(['pcapkit'])
        live = importlib.import_module('pcapkit.foundation.extraction').Extractor
        extractor = _extract(self.input, os.path.join(self.tmp.name, 'out'))
        self.assertIs(type(extractor), live)
        self.assertEqual(_read(extractor.output), _read(self.input))

    def test_split_mode_headers_carry_the_fields(self) -> None:
        extractor = _extract(self.input, os.path.join(self.tmp.name, 'split'), files=True)
        header = _read(self.input)[:24]
        self.assertEqual(_read(os.path.join(extractor.output, 'Global Header.pcap')), header)
        self.assertGreater(extractor.length, 0)
        for num in range(1, extractor.length + 1):
            self.assertEqual(_read(os.path.join(extractor.output, f'Frame {num}.pcap'))[:24], header)

    def test_zero_frame_capture(self) -> None:
        empty = os.path.join(self.tmp.name, 'empty.pcap')
        with open(empty, 'wb') as file:
            file.write(_read(self.input)[:24])
        extractor = _extract(empty, os.path.join(self.tmp.name, 'empty-out'))
        self.assertEqual(_read(extractor.output), _read(empty))


if __name__ == '__main__':
    unittest.main()
