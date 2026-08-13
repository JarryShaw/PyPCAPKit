from __future__ import annotations

import io
import os
import tempfile
import unittest
from unittest import mock

from tests._support import bootstrap_core_modules, load_module, purge_modules


class SeekableReaderTests(unittest.TestCase):
    def _close_reader(self, reader) -> None:
        reader._buffer_view.release()
        reader.close()

    def setUp(self) -> None:
        purge_modules(['pcapkit'])
        modules = bootstrap_core_modules()
        self.exceptions = modules['exceptions']
        self.io_module = load_module('pcapkit.corekit.io', 'pcapkit/corekit/io.py')
        self.SeekableReader = self.io_module.SeekableReader

    def test_read_and_seek_round_trip(self) -> None:
        reader = self.SeekableReader(io.BytesIO(b'abcdef'), buffer_size=4)

        self.assertEqual(reader.read(3), b'abc')
        self.assertEqual(reader.tell(), 3)
        reader.seek(1)
        self.assertEqual(reader.read(2), b'bc')
        self.assertEqual(reader.peek(2), b'de')
        self._close_reader(reader)

    def test_seek_before_buffer_start_requires_saved_buffer(self) -> None:
        reader = self.SeekableReader(io.BytesIO(b'abcdef'), buffer_size=4)
        reader.read(6)

        with self.assertRaises(self.exceptions.SeekError):
            reader.seek(0)

        self._close_reader(reader)

    def test_saved_buffer_allows_rewinding_before_memory_window(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            path = temp.name
        try:
            reader = self.SeekableReader(io.BytesIO(b'abcdef'), buffer_size=4, buffer_save=True, buffer_path=path)
            reader.read(6)
            reader.seek(0)
            self.assertEqual(reader.read(2), b'ab')
            self._close_reader(reader)
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_truncate_rejects_negative_sizes(self) -> None:
        reader = self.SeekableReader(io.BytesIO(b'abcdef'), buffer_size=4)
        with self.assertRaises(self.exceptions.TruncateError):
            reader.truncate(-1)
        self._close_reader(reader)

    def test_write_operations_raise_unsupported_operation(self) -> None:
        reader = self.SeekableReader(io.BytesIO(b'abcdef'), buffer_size=4)
        with self.assertRaises(self.exceptions.UnsupportedOperation):
            reader.write(b'x')
        with self.assertRaises(self.exceptions.UnsupportedOperation):
            reader.writelines([b'x'])
        self._close_reader(reader)

    def test_detach_raises_when_underlying_stream_has_no_detach(self) -> None:
        reader = self.SeekableReader(io.BytesIO(b'abcdef'), buffer_size=4)
        with self.assertRaises((self.exceptions.UnsupportedOperation, io.UnsupportedOperation)):
            reader.detach()
        self._close_reader(reader)

    def test_readinto_variants_fill_preallocated_buffers(self) -> None:
        reader = self.SeekableReader(io.BytesIO(b'abcdef'), buffer_size=4)
        buf = bytearray(3)
        count = reader.readinto(buf)
        self.assertEqual(count, 3)
        self.assertEqual(bytes(buf), b'abc')

        buf2 = bytearray(2)
        count2 = reader.readinto1(buf2)
        self.assertEqual(count2, 2)
        self.assertEqual(bytes(buf2), b'de')
        self._close_reader(reader)

    def test_metadata_close_and_raw_property_edges(self) -> None:
        stream = io.BytesIO(b'abc')
        reader = self.SeekableReader(stream, buffer_size=2, stream_closing=False)

        self.assertFalse(reader.closed)
        self.assertIs(reader.raw, stream)
        with self.assertRaises(self.exceptions.UnsupportedCall):
            reader.raw = stream
        with self.assertRaises(io.UnsupportedOperation):
            reader.fileno()
        self.assertFalse(reader.isatty())
        self.assertTrue(reader.readable())
        reader.flush()
        self._close_reader(reader)
        self.assertTrue(reader.closed)
        self.assertFalse(stream.closed)
        reader.close()

    def test_buffer_save_default_path_and_rollover_reads(self) -> None:
        reader = self.SeekableReader(io.BytesIO(b'abcdefghij'), buffer_size=4, buffer_save=True)
        path = reader._buffer_path
        try:
            self.assertTrue(path)
            self.assertEqual(reader.read(6), b'abcdef')
            self.assertGreaterEqual(reader._buffer_set, 2)
            reader.seek(0)
            self.assertEqual(reader.read1(2), b'ab')
            reader.seek(1)
            self.assertTrue(reader.peek(2).startswith(b'bc'))
        finally:
            self._close_reader(reader)

    def test_readline_readlines_and_buffer_completion_paths(self) -> None:
        reader = self.SeekableReader(io.BytesIO(b'alpha\nbeta\ngamma'), buffer_size=8)
        self.assertEqual(reader.readline(None), b'alpha\n')
        reader.seek(0)
        self.assertEqual(reader.readline(3), b'alp')
        self.assertEqual(reader.readline(10), b'ha\n')
        self.assertEqual(reader.readlines(5), [b'beta\n'])
        self.assertEqual(reader.readlines(None), [b'gamma'])
        self._close_reader(reader)

    def test_seek_variants_warnings_and_truncate_sizes(self) -> None:
        reader = self.SeekableReader(io.BytesIO(b'abcdef'), buffer_size=4)

        with self.assertRaises(self.exceptions.SeekError):
            reader.seek(-1)
        with self.assertRaises(self.exceptions.SeekError):
            reader.seek(0, 99)
        reader.read(2)
        self.assertEqual(reader.seek(-1, io.SEEK_CUR), 1)
        self.assertEqual(reader.seek(-1, io.SEEK_END), 3)
        with mock.patch('pcapkit.corekit.io.warn') as warn:
            self.assertEqual(reader.seek(20), 6)
        warn.assert_called_once()

        self.assertTrue(reader.seekable())
        self.assertFalse(reader.writeable())
        self.assertEqual(reader.truncate(None), 0)
        self.assertEqual(reader.truncate(6), 6)
        self.assertEqual(reader.truncate(2), 2)
        self._close_reader(reader)

    def test_read_read1_and_peek_fallback_stream_methods(self) -> None:
        class ReadOnly:
            def __init__(self, data: bytes) -> None:
                self._stream = io.BytesIO(data)

            def read(self, size=-1):
                return self._stream.read(size)

            def readline(self, size=-1):
                return self._stream.readline(size)

            def readable(self):
                return True

            def flush(self):
                return None

            def isatty(self):
                return False

            def close(self):
                return self._stream.close()

        stream = ReadOnly(b'abcdef')
        reader = self.SeekableReader(stream, buffer_size=3)
        self.assertEqual(reader.read(None), b'abcdef')
        self._close_reader(reader)

        reader = self.SeekableReader(ReadOnly(b'abcdef'), buffer_size=3)
        self.assertEqual(reader.read1(None), b'abcdef')
        self._close_reader(reader)

        reader = self.SeekableReader(ReadOnly(b'abcdef'), buffer_size=3)
        self.assertEqual(reader.peek(2), b'ab')
        with self.assertRaises(self.exceptions.UnsupportedOperation):
            reader.detach()
        self._close_reader(reader)

    def test_buffered_readline_read_read1_and_peek_paths(self) -> None:
        reader = self.SeekableReader(io.BytesIO(b'abc\ndef'), buffer_size=6)
        self.assertEqual(reader.read(3), b'abc')
        reader.seek(1)
        self.assertEqual(reader.readline(5), b'bc\n')
        self._close_reader(reader)

        reader = self.SeekableReader(io.BytesIO(b'abcdef'), buffer_size=6)
        self.assertEqual(reader.read(3), b'abc')
        reader.seek(1)
        self.assertEqual(reader.read(5), b'bcdef')
        self._close_reader(reader)

        reader = self.SeekableReader(io.BytesIO(b'abcdef'), buffer_size=6)
        self.assertEqual(reader.read(3), b'abc')
        reader.seek(1)
        self.assertEqual(reader.read1(1), b'b')
        reader.seek(1)
        self.assertEqual(reader.peek(1), b'b')
        self._close_reader(reader)

        class Peekable:
            def __init__(self, data: bytes) -> None:
                self._stream = io.BytesIO(data)

            def read(self, size=-1):
                return self._stream.read(size)

            def peek(self, size=0):
                pos = self._stream.tell()
                data = self._stream.read(size)
                self._stream.seek(pos)
                return data

            def readline(self, size=-1):
                return self._stream.readline(size)

            def readable(self):
                return True

            def flush(self):
                return None

            def isatty(self):
                return False

            def close(self):
                return self._stream.close()

        reader = self.SeekableReader(Peekable(b'abcdef'), buffer_size=3)
        self.assertEqual(reader.peek(2), b'ab')
        self._close_reader(reader)

    def test_saved_readline_and_empty_buffer_refill_edges(self) -> None:
        reader = self.SeekableReader(io.BytesIO(b'abc\ndef'), buffer_size=4, buffer_save=True)
        self.assertEqual(reader.read(6), b'abc\nde')
        reader.seek(0)
        self.assertEqual(reader.readline(2), b'ab')
        self._close_reader(reader)

        reader = self.SeekableReader(io.BytesIO(b'abc'), buffer_size=4)
        self.assertEqual(reader.read(), b'abc')
        self.assertEqual(reader.readlines(5), [])
        self._close_reader(reader)



if __name__ == '__main__':
    unittest.main()
