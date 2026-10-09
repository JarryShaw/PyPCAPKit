# -*- coding: utf-8 -*-
"""The stream proxies live in :mod:`pcapkit.corekit.io` (#1516).

:class:`~pcapkit.corekit.io.PeekableStream` gives a seekable stream without
``peek`` one, for :class:`~pcapkit.foundation.extraction.Extractor` (#1506,
#1509). :class:`~pcapkit.corekit.io.NamedStream` gives a stream the ``name``
:func:`pcapfile.savefile.load_savefile` reads, for the PyPCAPFile engine. Both
were file-local, as ``_PeekableStream`` in :mod:`pcapkit.foundation.extraction`
and ``_NamedStream`` in :mod:`pcapkit.foundation.engines.pypcapfile`, and moved
beside :class:`~pcapkit.corekit.io.SeekableReader` unchanged.

Every class is imported from its new module inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import gc
import importlib.util
import io
import unittest
from unittest import mock

from tests._support import reimport_once_per_class, sample_path

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class TestPeekableStream(unittest.TestCase):
    """:class:`~pcapkit.corekit.io.PeekableStream` peeks and forwards the rest."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_exported(self) -> None:
        import pcapkit.corekit.io as corekit_io  # pylint: disable=import-outside-toplevel

        self.assertIn('PeekableStream', corekit_io.__all__)

    def test_peek_does_not_consume(self) -> None:
        from pcapkit.corekit.io import PeekableStream  # pylint: disable=import-outside-toplevel

        stream = PeekableStream(io.BytesIO(b'abcdef'))
        self.assertEqual(stream.peek(3), b'abc')
        self.assertEqual(stream.tell(), 0)
        self.assertEqual(stream.read(2), b'ab')
        self.assertEqual(stream.peek(10), b'cdef')
        self.assertEqual(stream.tell(), 2)

    def test_peek_of_nothing_returns_one_octet(self) -> None:
        """``peek(0)``, the default, still returns an octet, as :meth:`io.BufferedReader.peek` does."""
        from pcapkit.corekit.io import PeekableStream  # pylint: disable=import-outside-toplevel

        stream = PeekableStream(io.BytesIO(b'abc'))
        self.assertEqual(stream.peek(), b'a')
        self.assertEqual(stream.peek(0), b'a')
        self.assertEqual(stream.tell(), 0)

    def test_peek_at_eof_is_empty(self) -> None:
        from pcapkit.corekit.io import PeekableStream  # pylint: disable=import-outside-toplevel

        stream = PeekableStream(io.BytesIO(b'ab'))
        stream.read()
        self.assertEqual(stream.peek(4), b'')
        self.assertEqual(stream.tell(), 2)

    def test_peek_restores_the_position_when_the_read_fails(self) -> None:
        from pcapkit.corekit.io import PeekableStream  # pylint: disable=import-outside-toplevel

        raw = mock.Mock(spec=['tell', 'read', 'seek'])
        raw.tell.return_value = 3
        raw.read.side_effect = OSError('boom')
        with self.assertRaises(OSError):
            PeekableStream(raw).peek(2)
        raw.read.assert_called_once_with(2)
        raw.seek.assert_called_once_with(3, io.SEEK_SET)

    def test_other_attributes_are_the_streams_own(self) -> None:
        from pcapkit.corekit.io import PeekableStream  # pylint: disable=import-outside-toplevel

        raw = io.BytesIO(b'abcdef')
        raw.name = 'given.pcap'  # type: ignore[attr-defined]
        stream = PeekableStream(raw)
        self.assertEqual(stream.name, 'given.pcap')
        self.assertTrue(stream.seekable())
        self.assertEqual(stream.seek(4), 4)
        self.assertEqual(raw.tell(), 4)
        self.assertEqual(stream.getvalue(), b'abcdef')
        self.assertEqual(stream.read1(), b'ef')
        with self.assertRaises(AttributeError):
            stream.no_such_attribute  # pylint: disable=pointless-statement

    def test_dropping_the_proxy_leaves_the_stream_open(self) -> None:
        """Not an :class:`io.IOBase`, so no finaliser closes the caller's stream (#610)."""
        from pcapkit.corekit.io import PeekableStream  # pylint: disable=import-outside-toplevel

        raw = io.BytesIO(b'abc')
        stream = PeekableStream(raw)
        self.assertNotIsInstance(stream, io.IOBase)
        del stream
        gc.collect()
        self.assertFalse(raw.closed)

    @unittest.skipUnless(HAS_RUNTIME, 'pcapkit runtime dependencies are not installed')
    def test_extractor_wraps_a_peekless_stream_in_it(self) -> None:
        from pcapkit.corekit.io import PeekableStream  # pylint: disable=import-outside-toplevel
        from pcapkit.foundation.extraction import Extractor  # pylint: disable=import-outside-toplevel

        with open(sample_path('in.pcap'), 'rb') as file:
            raw = io.BytesIO(file.read())
        extractor = Extractor(fin=raw, nofile=True, auto=False)
        self.assertIs(type(extractor._ifile), PeekableStream)  # pylint: disable=protected-access
        self.assertIs(extractor._ifile._stream, raw)  # type: ignore[attr-defined] # pylint: disable=protected-access


class TestNamedStream(unittest.TestCase):
    """:class:`~pcapkit.corekit.io.NamedStream` carries a name and forwards reads."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_exported(self) -> None:
        import pcapkit.corekit.io as corekit_io  # pylint: disable=import-outside-toplevel

        self.assertIn('NamedStream', corekit_io.__all__)

    def test_name_is_the_given_one(self) -> None:
        from pcapkit.corekit.io import NamedStream  # pylint: disable=import-outside-toplevel

        raw = io.BytesIO(b'')
        raw.name = 'own.pcap'  # type: ignore[attr-defined]
        self.assertEqual(NamedStream(raw, 'given.pcap').name, 'given.pcap')

    def test_reads_forward_to_the_stream(self) -> None:
        from pcapkit.corekit.io import NamedStream  # pylint: disable=import-outside-toplevel

        stream = NamedStream(io.BytesIO(b'abcdef'), 'given.pcap')
        self.assertEqual(stream.read(2), b'ab')
        self.assertEqual(stream.read(), b'cdef')
        self.assertEqual(stream.read(), b'')

    def test_read_passes_the_size_through(self) -> None:
        from pcapkit.corekit.io import NamedStream  # pylint: disable=import-outside-toplevel

        raw = mock.Mock(spec=['read'])
        raw.read.return_value = b'x'
        stream = NamedStream(raw, 'given.pcap')
        self.assertEqual(stream.read(), b'x')
        self.assertEqual(stream.read(5), b'x')
        self.assertEqual(raw.read.call_args_list, [mock.call(-1), mock.call(5)])

    def test_nothing_but_read_is_forwarded(self) -> None:
        """A read-only proxy: no ``__getattr__``, so the stream's other methods are not reachable."""
        from pcapkit.corekit.io import NamedStream  # pylint: disable=import-outside-toplevel

        stream = NamedStream(io.BytesIO(b'abc'), 'given.pcap')
        for name in ('seek', 'tell', 'peek', 'close', 'closed'):
            with self.subTest(name=name):
                self.assertFalse(hasattr(stream, name))

    def test_names_a_seekable_reader(self) -> None:
        """The case it exists for: :class:`~pcapkit.corekit.io.SeekableReader` has no ``name``."""
        from pcapkit.corekit.io import NamedStream, SeekableReader  # pylint: disable=import-outside-toplevel

        reader = SeekableReader(io.BytesIO(b'abcdef'), buffer_size=4)
        self.assertFalse(hasattr(reader, 'name'))
        stream = NamedStream(reader, 'given.pcap')
        self.assertEqual(stream.name, 'given.pcap')
        self.assertEqual(stream.read(4), b'abcd')
        self.assertEqual(reader.tell(), 4)
        reader.close()

    def test_pypcapfile_engine_uses_it(self) -> None:
        from pcapkit.corekit.io import NamedStream  # pylint: disable=import-outside-toplevel
        from pcapkit.foundation.engines import pypcapfile  # pylint: disable=import-outside-toplevel

        self.assertIs(pypcapfile.NamedStream, NamedStream)


if __name__ == '__main__':
    unittest.main()
