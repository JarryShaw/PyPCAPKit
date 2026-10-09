# -*- coding: utf-8 -*-
"""A binary stream with no :obj:`str` ``name`` is a valid ``fin`` (#1506).

``fin`` is documented and typed as ``str | IO[bytes]`` -- "file name to be read
or a binary IO object" -- on both :func:`pcapkit.extract` and
:class:`~pcapkit.foundation.extraction.Extractor`. Two things on the way in
assumed more than that and raised :exc:`AttributeError` on an
:class:`io.BytesIO` before a single frame was read:

* :meth:`Extractor.make_name <pcapkit.foundation.extraction.Extractor.make_name>`
  read ``fin.name``, which a :class:`io.BytesIO` does not have. The name only
  labels the input -- the output name comes from ``fout`` alone -- so a stream
  without one is now labelled after its type, ``<BytesIO>``.
* The magic number, and the PCAP-NG engine's block type, are read with
  ``peek``, which :class:`io.BufferedReader` has and :class:`typing.IO` does not.

The engines whose library opens the input by path -- Scapy, PyShark, PyPCAP and
pcap-ct -- cannot read such a stream at all, so they refuse it with
:exc:`~pcapkit.utilities.exceptions.UnsupportedCall` instead.

"""

from __future__ import annotations

import importlib.util
import io
import os
import tempfile
import unittest
from unittest import mock

from tests._support import sample_path

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'pcapkit runtime dependencies are not installed')
class TestUnnamedStream(unittest.TestCase):
    """``fin`` given as a stream that has no :obj:`str` ``name``."""

    def _frames(self, capture: str) -> tuple[int, 'object', io.BytesIO]:
        """Extract ``capture`` from a :class:`io.BytesIO`, and count it by path too."""
        import pcapkit  # pylint: disable=import-outside-toplevel

        path = sample_path(capture)
        expected = len(pcapkit.extract(fin=path, nofile=True).frame)
        with open(path, 'rb') as file:
            stream = io.BytesIO(file.read())
        return expected, pcapkit.extract(fin=stream, nofile=True), stream

    def test_pcap_from_bytesio(self) -> None:
        expected, extractor, stream = self._frames('in.pcap')
        self.assertGreater(expected, 0)
        self.assertEqual(len(extractor.frame), expected)  # type: ignore[attr-defined]
        self.assertEqual(extractor.input, '<BytesIO>')  # type: ignore[attr-defined]
        self.assertFalse(stream.closed, 'the caller owns the stream (#610)')

    def test_pcapng_from_bytesio(self) -> None:
        expected, extractor, stream = self._frames('dhcp.pcapng')
        self.assertGreater(expected, 0)
        self.assertEqual(len(extractor.frame), expected)  # type: ignore[attr-defined]
        self.assertFalse(stream.closed, 'the caller owns the stream (#610)')

    def test_output_name_comes_from_fout(self) -> None:
        import pcapkit  # pylint: disable=import-outside-toplevel

        with open(sample_path('in.pcap'), 'rb') as file:
            data = file.read()
        with tempfile.TemporaryDirectory() as tmp:
            fout = os.path.join(tmp, 'out')
            extractor = pcapkit.extract(fin=io.BytesIO(data), fout=fout, format='json')
            self.assertEqual(extractor.output, f'{fout}.json')
            self.assertTrue(os.path.isfile(f'{fout}.json'))

    def test_non_str_name_is_a_placeholder(self) -> None:
        """A stream opened on a descriptor has an :obj:`int` ``name``."""
        import pcapkit  # pylint: disable=import-outside-toplevel

        path = sample_path('in.pcap')
        with open(os.open(path, os.O_RDONLY), 'rb') as stream:
            self.assertIsInstance(stream.name, int)
            extractor = pcapkit.extract(fin=stream, nofile=True)
            self.assertEqual(extractor.input, '<BufferedReader>')
            self.assertEqual(len(extractor.frame), len(pcapkit.extract(fin=path, nofile=True).frame))

    def test_make_name_labels_by_name_or_type(self) -> None:
        from pcapkit.foundation.extraction import Extractor  # pylint: disable=import-outside-toplevel

        stream = io.BytesIO()
        self.assertEqual(Extractor.make_name(stream, nofile=True)[0], '<BytesIO>')
        stream.name = 'capture.pcap'  # type: ignore[attr-defined]
        self.assertEqual(Extractor.make_name(stream, nofile=True)[0], 'capture.pcap')


@unittest.skipUnless(HAS_RUNTIME, 'pcapkit runtime dependencies are not installed')
class TestPathEngines(unittest.TestCase):
    """Engines that open the input by path refuse an unnamed stream up front.

    Scapy and PyShark hand ``Extractor._ifnm`` to their library as a file name,
    so before the refusal the ``<BytesIO>`` label was opened as a path --
    ``FileNotFoundError`` from inside :mod:`scapy`. The refusal is raised by
    :class:`~pcapkit.foundation.extraction.Extractor` itself, before the engine
    is constructed, so it does not depend on the engine being able to run.

    """

    def _data(self) -> bytes:
        with open(sample_path('in.pcap'), 'rb') as file:
            return file.read()

    def _assert_refused(self, engine: str) -> None:
        import pcapkit  # pylint: disable=import-outside-toplevel
        from pcapkit.utilities.exceptions import UnsupportedCall  # pylint: disable=import-outside-toplevel

        stream = io.BytesIO(self._data())
        with self.assertRaises(UnsupportedCall) as caught:
            pcapkit.extract(fin=stream, nofile=True, engine=engine)  # type: ignore[arg-type]
        self.assertIn(f"'Extractor(engine={engine})' requires a file on disk", str(caught.exception))
        self.assertIn('BytesIO', str(caught.exception))
        self.assertFalse(stream.closed, 'the caller owns the stream (#610)')

    @unittest.skipUnless(importlib.util.find_spec('scapy') is not None, 'scapy is not installed')
    def test_scapy_refuses_unnamed_stream(self) -> None:
        self._assert_refused('scapy')

    @unittest.skipUnless(importlib.util.find_spec('pyshark') is not None, 'pyshark is not installed')
    def test_pyshark_refuses_unnamed_stream(self) -> None:
        # NOTE: PyShark rules itself out on some interpreters (CPython 3.14), and
        # the extraction would then fall back to the default engine, which reads
        # the stream perfectly well. Clear that reason so the refusal is what is
        # under test; it fires before any PyShark code runs.
        from pcapkit.foundation.engines.pyshark import PyShark  # pylint: disable=import-outside-toplevel

        with mock.patch.object(PyShark, 'unsupported_reason', return_value=None):
            self._assert_refused('pyshark')

    def test_named_stream_is_not_refused(self) -> None:
        """A stream with a real ``name`` gives the path engine a path to open."""
        from pcapkit.foundation.extraction import Extractor  # pylint: disable=import-outside-toplevel

        path = sample_path('in.pcap')
        with mock.patch.object(Extractor, 'run'), open(path, 'rb') as stream:
            extractor = Extractor(fin=stream, nofile=True, engine='scapy')
            self.assertEqual(extractor.input, path)

    @unittest.skipUnless(importlib.util.find_spec('dpkt') is not None, 'dpkt is not installed')
    def test_dpkt_reads_unnamed_stream(self) -> None:
        import pcapkit  # pylint: disable=import-outside-toplevel

        expected = len(pcapkit.extract(fin=sample_path('in.pcap'), nofile=True, engine='dpkt').frame)
        stream = io.BytesIO(self._data())
        extractor = pcapkit.extract(fin=stream, nofile=True, engine='dpkt')
        self.assertEqual(extractor._exnam, 'dpkt')  # pylint: disable=protected-access
        self.assertGreater(expected, 0)
        self.assertEqual(len(extractor.frame), expected)
        self.assertFalse(stream.closed, 'the caller owns the stream (#610)')


if __name__ == '__main__':
    unittest.main()
