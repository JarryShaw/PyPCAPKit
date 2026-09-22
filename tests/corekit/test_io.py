from __future__ import annotations

import io
import os
import tempfile
import unittest
from unittest import mock

from tests._support import bootstrap_core_modules, load_module, purge_modules


class SeekableReaderTests(unittest.TestCase):
    def _close_reader(self, reader) -> None:
        reader.close()
        self.assertTrue(reader.closed)

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
        with mock.patch.object(self.io_module, 'warn') as warn:
            self.assertEqual(reader.seek(20), 6)
        warn.assert_called_once()

        self.assertTrue(reader.seekable())
        self.assertFalse(reader.writeable())
        # NOTE: an omitted size means the current position, per :meth:`io.IOBase.truncate`.
        # The position is 6 and the buffer starts at 2, so 4 octets of it are kept. This
        # asserted 0 until issue #622, which is what an omitted size was resized to.
        self.assertEqual(reader._buffer_set, 2)
        self.assertEqual(reader.truncate(None), 4)
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

    def test_truncate_keeps_the_content_and_not_the_padding(self) -> None:
        """Issue #622, verbatim: the octets already read survive a truncation.

        The buffer holds its content at ``[0:_buffer_cur]`` and nothing but unwritten
        padding after it, so slicing the *buffer's* tail for the octets to keep -- rather
        than the content's -- kept the padding and threw the content away. ``b'abcde'``
        discriminates between the two: the content's last four octets are ``b'abcd'``,
        the buffer's are ``b'\\x00\\x00\\x00\\x00'``, which uniform data could not tell
        apart.

        """
        reader = self.SeekableReader(io.BytesIO(b'abcde'))

        self.assertEqual(reader.read(4), b'abcd')
        self.assertEqual(reader.truncate(8), 8)
        self.assertEqual(reader.seek(0), 0)

        # NOTE: the stream holds five octets, so five is the whole of what an eight octet
        # request can be answered with; it returned b'\x00\x00\x00e' before the fix -- four
        # octets, the content displaced by the padding, and one octet of it lost outright.
        self.assertEqual(reader.read(8), b'abcde')
        self._close_reader(reader)

    def test_truncate_pads_and_keeps_on_the_side_the_bookkeeping_expects(self) -> None:
        """A truncation never keeps padding in preference to content.

        Each case distinguishes head from tail handling, since the expected buffer is the
        same octets in a different place: growing ``b'abcd'`` to 8 gives
        ``b'abcd\\x00\\x00\\x00\\x00'`` one way round and ``b'\\x00\\x00\\x00\\x00abcd'`` the
        other. The sizes are deliberately 3, 5, 7 and 8 rather than all multiples of one
        number, so a fix that is off by a constant cannot pass the table.

        A reduction below the content keeps the most recent octets and advances
        ``_buffer_set`` past the dropped ones, which is what holds
        ``_buffer_set + _buffer_cur`` at the stream's consumption point -- asserted here as
        ``read_size``, since that is how many octets each case has taken off the stream.

        """
        cases = [
            # (buffer_size, octets read, truncate size, expected buffer, expected _buffer_set)
            (4, 4, 8, b'abcd\x00\x00\x00\x00', 0),   # grown: the new area is at the tail
            (4, 4, 3, b'bcd', 1),                    # reduced below the content
            (8, 6, 3, b'def', 3),                    # reduced well below the content
            (8, 3, 5, b'abc\x00\x00', 0),            # reduced, but above the content
            (8, 5, 7, b'abcde\x00\x00', 0),          # grown by one octet only
            (8, 4, 8, b'abcd\x00\x00\x00\x00', 0),   # unchanged in size: a control
        ]
        for buffer_size, read_size, size, expected, expected_set in cases:
            with self.subTest(buffer_size=buffer_size, read_size=read_size, size=size):
                reader = self.SeekableReader(io.BytesIO(b'abcdefghijkl'), buffer_size=buffer_size)
                self.assertEqual(reader.read(read_size), b'abcdefghijkl'[:read_size])

                self.assertEqual(reader.truncate(size), size)
                self.assertEqual(bytes(reader._buffer.getvalue()), expected)
                self.assertEqual(reader._buffer_set, expected_set)
                # NOTE: the content pointer indexes the buffer, so it cannot be left
                # pointing past the end of it.
                self.assertLessEqual(reader._buffer_cur, reader._buffer_size)
                # NOTE: and the pair still has to say how far the stream has been read.
                self.assertEqual(reader._buffer_set + reader._buffer_cur, read_size)
                self._close_reader(reader)

    def test_truncate_keeps_the_window_base_in_step_with_the_stream(self) -> None:
        """A reduction that left ``_buffer_set`` alone made the next seek read wrong octets.

        ``seek`` treats ``_buffer_set + _buffer_cur`` as how far the stream has been
        consumed, and reads ahead from there to fill a gap. A reduction that shrank the
        window without advancing its base left that sum short of the stream -- here it
        would say 3 where 8 octets had been read -- so the fill fetched the octets at 8
        and labelled them as the ones at 3. Nothing raised; ``read(1)`` at offset 6 simply
        returned ``b'l'`` instead of ``b'g'``.

        The data is non-uniform so the mislabelled octets are distinguishable from the
        right ones, which is the whole of what this test turns on.

        """
        reader = self.SeekableReader(io.BytesIO(b'abcdefghijklmnop'), buffer_size=8)

        self.assertEqual(reader.read(8), b'abcdefgh')
        self.assertEqual(reader.truncate(3), 3)

        # the three most recent octets, and a base that still accounts for the other five
        self.assertEqual(bytes(reader._buffer.getvalue()), b'fgh')
        self.assertEqual(reader._buffer_set, 5)
        self.assertEqual(reader._buffer_cur, 3)

        self.assertEqual(reader.seek(6), 6)
        self.assertEqual(reader.read(1), b'g')
        self._close_reader(reader)

    def test_truncate_leaves_the_position_where_it_was(self) -> None:
        """:meth:`io.IOBase.truncate` does not move the position, and neither may this one.

        The truncation here is to the size the buffer already has, so its *content* is the
        same either way and only the position can account for the difference: reading from
        a position reset to zero returns ``b'ab'``, reading from the preserved position
        returns ``b'cd'``.

        """
        reader = self.SeekableReader(io.BytesIO(b'abcdefgh'), buffer_size=8)

        self.assertEqual(reader.read(4), b'abcd')
        self.assertEqual(reader.seek(2), 2)
        self.assertEqual(reader._buffer.tell(), 2)

        self.assertEqual(reader.truncate(8), 8)
        self.assertEqual(reader.tell(), 2)
        self.assertEqual(reader._buffer.tell(), 2)
        self.assertEqual(reader.read(2), b'cd')
        self._close_reader(reader)

    def test_truncate_without_a_size_resizes_to_the_current_position(self) -> None:
        """An omitted size means the current position, not zero."""
        reader = self.SeekableReader(io.BytesIO(b'abcdefgh'), buffer_size=8)

        self.assertEqual(reader.read(5), b'abcde')
        self.assertEqual(reader.tell(), 5)

        self.assertEqual(reader.truncate(), 5)
        self.assertEqual(reader._buffer_size, 5)
        self.assertEqual(bytes(reader._buffer.getvalue()), b'abcde')
        self._close_reader(reader)

    def test_truncate_below_the_content_leaves_the_reader_usable(self) -> None:
        """A truncation has to bring ``_buffer_cur`` down with the buffer it indexes.

        Left above the new size it addressed octets the buffer no longer has, and the next
        read raised ``ValueError: memoryview assignment: lvalue and rvalue have different
        structures`` from :meth:`_write_buffer` rather than returning anything.

        """
        reader = self.SeekableReader(io.BytesIO(b'abcdefghijkl'), buffer_size=8)

        self.assertEqual(reader.read(6), b'abcdef')
        self.assertEqual(reader.truncate(3), 3)
        self.assertEqual(reader._buffer_cur, 3)
        self.assertEqual(reader._buffer_set, 3)
        self.assertEqual(reader.read(1), b'g')
        self._close_reader(reader)

    def test_truncate_to_nothing_leaves_the_reader_usable(self) -> None:
        """Truncating the buffer away entirely still has to leave reads working.

        ``truncate(0)`` is the only way to reach a buffer of no size: the constructor
        refuses one, since ``io.BufferedReader`` rejects a non-positive ``buffer_size``
        with ``ValueError: buffer size must be strictly positive``. The next read then
        went to ``_write_buffer``, whose ``buf[-self._buffer_size:]`` is ``buf[-0:]`` --
        the whole of the octets just read rather than none of them -- and assigning
        those to a buffer with no room raised ``ValueError``.

        Reading forward is all that can still work: with nothing buffered there is no
        lookback, so seeking back has to fail, and it does.

        """
        reader = self.SeekableReader(io.BytesIO(b'abcde'), buffer_size=5)

        self.assertEqual(reader.truncate(0), 0)
        self.assertEqual(reader.read(1), b'a')
        self.assertEqual(reader.read(2), b'bc')
        self.assertEqual(reader.tell(), 3)
        with self.assertRaises(self.exceptions.SeekError):
            reader.seek(0)
        self._close_reader(reader)

    def test_buffered_read_returns_every_buffered_octet(self) -> None:
        """A read served from the buffer stops at the content, not one octet short of it.

        The existing round trip at :meth:`test_buffered_readline_read_read1_and_peek_paths`
        cannot see this: it seeks to 1, where ``_buffer_cur - 1`` happens to equal the
        octets actually available, so the two candidate caps agree. Seeking to 0 separates
        them -- four octets are available and the old cap allowed three, making up the
        fourth from the stream *past* the octet it had skipped.

        """
        reader = self.SeekableReader(io.BytesIO(b'abcde'), buffer_size=8)
        self.assertEqual(reader.read(4), b'abcd')
        self.assertEqual(reader.seek(0), 0)
        self.assertEqual(reader.read(5), b'abcde')  # was b'abce': four octets, d dropped
        self.assertEqual(reader.tell(), 5)
        self._close_reader(reader)

        # NOTE: an unbounded read must not hand back the padding behind the content
        # either; this returned b'abcd\x00\x00\x00\x00e' before the fix.
        reader = self.SeekableReader(io.BytesIO(b'abcde'), buffer_size=8)
        self.assertEqual(reader.read(4), b'abcd')
        self.assertEqual(reader.seek(0), 0)
        self.assertEqual(reader.read(-1), b'abcde')
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
