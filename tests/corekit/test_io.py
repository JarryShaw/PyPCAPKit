from __future__ import annotations

import _pyio
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

    def test_truncate_buffer_rejects_negative_sizes(self) -> None:
        reader = self.SeekableReader(io.BytesIO(b'abcdef'), buffer_size=4)
        with self.assertRaises(self.exceptions.TruncateError):
            reader._truncate_buffer(-1)
        self._close_reader(reader)

    def test_write_operations_raise_unsupported_operation(self) -> None:
        reader = self.SeekableReader(io.BytesIO(b'abcdef'), buffer_size=4)
        with self.assertRaises(self.exceptions.UnsupportedOperation):
            reader.write(b'x')
        with self.assertRaises(self.exceptions.UnsupportedOperation):
            reader.writelines([b'x'])
        self._close_reader(reader)

    def test_truncate_refuses_on_a_stream_that_reports_itself_unwritable(self) -> None:
        """Issue #645: ``truncate`` is gated on ``writable()``, and this reader is not writable.

        :meth:`io.IOBase.writable` documents the gate for both methods it guards -- "If
        :data:`False`, :meth:`write` and :meth:`truncate` will raise :exc:`OSError`" -- and
        :meth:`~pcapkit.corekit.io.SeekableReader.writable` returns :data:`False` here. Two of
        the three writability-gated methods already honoured that: ``write`` and ``writelines``
        raise. ``truncate`` returned its new size instead, so a caller that checked
        ``writable()`` first -- which is exactly what the contract invites -- got a surprise
        either way round.

        Every form is asserted, since the omitted-size form takes a different path through the
        method than an explicit size and only the explicit one would have been noticed.

        """
        for args in [(), (0,), (4,), (None,)]:
            with self.subTest(args=args):
                reader = self.SeekableReader(io.BytesIO(b'abcdef'), buffer_size=4)
                self.assertFalse(reader.writable())

                with self.assertRaises(self.exceptions.UnsupportedOperation) as caught:
                    reader.truncate(*args)
                # NOTE: the contract names OSError, so the refusal has to be one. pcapkit's
                # UnsupportedOperation subclasses io.UnsupportedOperation, which subclasses
                # OSError, so the in-library exception satisfies the stdlib contract as it
                # stands -- there is no choice to make between the two here.
                self.assertIsInstance(caught.exception, OSError)
                self.assertIsInstance(caught.exception, io.UnsupportedOperation)
                self._close_reader(reader)

    def test_truncate_refuses_with_the_same_exception_the_stdlib_reader_raises(self) -> None:
        """The property, rather than the behaviour: parity with CPython's own buffered reader.

        Asserting "it raises" pins the fix; asserting "it raises *what a read-only
        :class:`io.BufferedReader` raises*" pins the reason for it, and is what stops this being
        re-opened by an argument about which exception the contract means. The stdlib's type is
        captured by *running* the same call on a real read-only file object rather than being
        named here, so the assertion tracks CPython instead of restating a belief about it.

        Both implementations are checked. The accelerated :class:`io.BufferedReader` raises
        ``io.UnsupportedOperation: truncate``; the pure-Python ``_pyio.BufferedReader``
        raises ``io.UnsupportedOperation: File or stream is not writable.`` from
        ``_BufferedIOMixin.truncate``'s ``_checkWritable()``. The messages differ and the type
        does not, which is why the type is what is asserted.

        """
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            temp.write(b'abcdef')
            path = temp.name
        try:
            baselines = {}

            with open(path, 'rb') as accelerated:
                self.assertIsInstance(accelerated, io.BufferedReader)
                self.assertFalse(accelerated.writable())
                with self.assertRaises(OSError) as caught:
                    accelerated.truncate()
                baselines['io.BufferedReader'] = type(caught.exception)

            class NonWritableRaw(_pyio.RawIOBase):
                """A raw stream that reads and does not write, as ``SeekableReader``'s is."""

                def readable(self) -> bool:
                    return True

                def writable(self) -> bool:
                    return False

                def readinto(self, buffer) -> int:
                    return 0

            with _pyio.BufferedReader(NonWritableRaw()) as pure_python:
                self.assertFalse(pure_python.writable())
                with self.assertRaises(OSError) as caught:
                    pure_python.truncate()
                baselines['_pyio.BufferedReader'] = type(caught.exception)

            for name, expected in baselines.items():
                with self.subTest(baseline=name, expected=expected.__name__):
                    reader = self.SeekableReader(io.BytesIO(b'abcdef'), buffer_size=4)
                    # NOTE: the premise of the comparison -- both report themselves unwritable,
                    # so both are in the state the contract gates ``truncate`` on.
                    self.assertFalse(reader.writable())
                    with self.assertRaises(expected):
                        reader.truncate()
                    self._close_reader(reader)
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_writable_is_the_method_the_io_protocol_consults(self) -> None:
        """Issue #645: the override was spelled ``writeable``, so it overrode nothing.

        The :mod:`io` API spells it ``writable``. With the misspelling in place,
        ``'writable' in SeekableReader.__dict__`` was :data:`False` and
        ``SeekableReader.writable is io.IOBase.writable`` was :data:`True` -- so :mod:`io`,
        :mod:`shutil` and any third-party caller read the inherited value and never saw the one
        defined in this file. Both returned :data:`False`, which is the coincidence that hid it:
        there was no symptom to notice, and editing the misspelled method would silently have
        had no effect.

        The identity assertion is the load-bearing one. ``writable()`` returning :data:`False`
        passed before the fix too, by inheritance, so a value-only test cannot tell the two
        trees apart.

        """
        self.assertIn('writable', self.SeekableReader.__dict__)
        self.assertIsNot(self.SeekableReader.writable, io.IOBase.writable)
        self.assertNotIn('writeable', self.SeekableReader.__dict__)

        reader = self.SeekableReader(io.BytesIO(b'abcdef'), buffer_size=4)
        # NOTE: the reader genuinely cannot write -- ``write`` raises -- so False is the honest
        # answer, and the reporting was never the dishonest half. Only where it was *defined*
        # was wrong, and the guard on ``truncate`` was missing.
        self.assertFalse(reader.writable())
        self.assertFalse(hasattr(reader, 'writeable'))
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
        self.assertFalse(reader.writable())
        # NOTE: an omitted size means the current position, per :meth:`io.IOBase.truncate`.
        # The position is 6 and the buffer starts at 2, so 4 octets of it are kept. This
        # asserted 0 until issue #622, which is what an omitted size was resized to.
        self.assertEqual(reader._buffer_set, 2)
        self.assertEqual(reader._truncate_buffer(None), 4)
        self.assertEqual(reader._truncate_buffer(6), 6)
        self.assertEqual(reader._truncate_buffer(2), 2)
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

    def test_truncate_buffer_keeps_the_content_and_not_the_padding(self) -> None:
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
        self.assertEqual(reader._truncate_buffer(8), 8)
        self.assertEqual(reader.seek(0), 0)

        # NOTE: the stream holds five octets, so five is the whole of what an eight octet
        # request can be answered with; it returned b'\x00\x00\x00e' before the fix -- four
        # octets, the content displaced by the padding, and one octet of it lost outright.
        self.assertEqual(reader.read(8), b'abcde')
        self._close_reader(reader)

    def test_truncate_buffer_pads_and_keeps_on_the_side_the_bookkeeping_expects(self) -> None:
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

                self.assertEqual(reader._truncate_buffer(size), size)
                self.assertEqual(bytes(reader._buffer.getvalue()), expected)
                self.assertEqual(reader._buffer_set, expected_set)
                # NOTE: the content pointer indexes the buffer, so it cannot be left
                # pointing past the end of it.
                self.assertLessEqual(reader._buffer_cur, reader._buffer_size)
                # NOTE: and the pair still has to say how far the stream has been read.
                self.assertEqual(reader._buffer_set + reader._buffer_cur, read_size)
                self._close_reader(reader)

    def test_truncate_buffer_keeps_the_window_base_in_step_with_the_stream(self) -> None:
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
        self.assertEqual(reader._truncate_buffer(3), 3)

        # the three most recent octets, and a base that still accounts for the other five
        self.assertEqual(bytes(reader._buffer.getvalue()), b'fgh')
        self.assertEqual(reader._buffer_set, 5)
        self.assertEqual(reader._buffer_cur, 3)

        self.assertEqual(reader.seek(6), 6)
        self.assertEqual(reader.read(1), b'g')
        self._close_reader(reader)

    def test_truncate_buffer_leaves_the_position_where_it_was(self) -> None:
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

        self.assertEqual(reader._truncate_buffer(8), 8)
        self.assertEqual(reader.tell(), 2)
        self.assertEqual(reader._buffer.tell(), 2)
        self.assertEqual(reader.read(2), b'cd')
        self._close_reader(reader)

    def test_truncate_buffer_without_a_size_resizes_to_the_current_position(self) -> None:
        """An omitted size means the current position, not zero."""
        reader = self.SeekableReader(io.BytesIO(b'abcdefgh'), buffer_size=8)

        self.assertEqual(reader.read(5), b'abcde')
        self.assertEqual(reader.tell(), 5)

        self.assertEqual(reader._truncate_buffer(), 5)
        self.assertEqual(reader._buffer_size, 5)
        self.assertEqual(bytes(reader._buffer.getvalue()), b'abcde')
        self._close_reader(reader)

    def test_truncate_buffer_below_the_content_leaves_the_reader_usable(self) -> None:
        """A truncation has to bring ``_buffer_cur`` down with the buffer it indexes.

        Left above the new size it addressed octets the buffer no longer has, and the next
        read raised ``ValueError: memoryview assignment: lvalue and rvalue have different
        structures`` from :meth:`_write_buffer` rather than returning anything.

        """
        reader = self.SeekableReader(io.BytesIO(b'abcdefghijkl'), buffer_size=8)

        self.assertEqual(reader.read(6), b'abcdef')
        self.assertEqual(reader._truncate_buffer(3), 3)
        self.assertEqual(reader._buffer_cur, 3)
        self.assertEqual(reader._buffer_set, 3)
        self.assertEqual(reader.read(1), b'g')
        self._close_reader(reader)

    def test_truncate_buffer_to_nothing_leaves_the_reader_usable(self) -> None:
        """Truncating the buffer away entirely still has to leave reads working.

        ``_truncate_buffer(0)`` is the only way to reach a buffer of no size: the constructor
        refuses one, since ``io.BufferedReader`` rejects a non-positive ``buffer_size``
        with ``ValueError: buffer size must be strictly positive``. The next read then
        went to ``_write_buffer``, whose ``buf[-self._buffer_size:]`` is ``buf[-0:]`` --
        the whole of the octets just read rather than none of them -- and assigning
        those to a buffer with no room raised ``ValueError``.

        Reading forward is all that can still work: with nothing buffered there is no
        lookback, so seeking back has to fail, and it does.

        """
        reader = self.SeekableReader(io.BytesIO(b'abcde'), buffer_size=5)

        self.assertEqual(reader._truncate_buffer(0), 0)
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

    # ------------------------------------------------------------------ #
    # issue #643 -- position bookkeeping across operations
    # ------------------------------------------------------------------ #

    def _pipe_stream(self, data: bytes):
        """A non-seekable stream with neither ``peek`` nor ``read1`` -- i.e. a pipe.

        ``SeekableReader``'s only production consumer wraps exactly this kind of stream
        (``pcapkit/foundation/extraction.py``, where a non-seekable input is wrapped and
        then peeked), and the branches it selects differ from the ones a
        :class:`io.BytesIO` selects: with no ``peek`` of its own, :meth:`peek` has to do a
        real consuming read on it and stash the result in the buffer.

        """
        class Pipe:
            def __init__(self, payload: bytes) -> None:
                self._stream = io.BytesIO(payload)
                self.consumed = 0

            def read(self, size=-1):
                buf = self._stream.read(size)
                self.consumed += len(buf)
                return buf

            def readline(self, size=-1):
                buf = self._stream.readline(size)
                self.consumed += len(buf)
                return buf

            def readable(self):
                return True

            def seekable(self):
                return False

            def flush(self):
                return None

            def isatty(self):
                return False

            def close(self):
                return self._stream.close()

        return Pipe(data)

    def test_a_refused_seek_leaves_the_position_untouched(self) -> None:
        """A ``seek`` that raises must not have moved the position on its way out.

        Each ``whence`` branch assigned ``_tell`` before anything validated the result, so a
        refusal left the position at the rejected target with the resync at the end of
        :meth:`seek` -- the one thing that puts the buffer's cursor back in step -- skipped.
        A caller that catches :exc:`SeekError` and reasonably takes the position to be
        unchanged then read from the rejected offset instead, silently and with no second
        error to show for it.

        The octet asserted after the refusal is what makes this discriminating:
        ``test_seek_before_buffer_start_requires_saved_buffer`` above drives the identical
        path but stops at ``assertRaises``, and the whole defect lives in what happens next.
        Two buffer sizes, so neither result can be an artefact of one window geometry.

        """
        reader = self.SeekableReader(io.BytesIO(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'), buffer_size=2)
        self.assertEqual(reader.read(13), b'ABCDEFGHIJKLM')
        with self.assertRaises(self.exceptions.SeekError):
            reader.seek(8)
        self.assertEqual(reader.tell(), 13)          # was 8, the rejected target
        self.assertEqual(reader.read(1), b'N')       # was b'L', the octet at 11
        self._close_reader(reader)

        reader = self.SeekableReader(io.BytesIO(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'), buffer_size=4)
        self.assertEqual(reader.read(6), b'ABCDEF')
        with self.assertRaises(self.exceptions.SeekError):
            reader.seek(0)
        self.assertEqual(reader.tell(), 6)           # was 0
        self.assertEqual(reader.read(1), b'G')       # was b'C', the octet at 2
        self._close_reader(reader)

    def test_seek_refuses_a_negative_absolute_position_under_every_whence(self) -> None:
        """``SEEK_CUR`` and ``SEEK_END`` did arithmetic and never looked at the result.

        Only ``SEEK_SET`` checked its offset, so an absolute position below zero was
        reachable through the other two: ``tell()`` came back ``-100`` and ``-96``. The
        asymmetry is the defect -- the same impossible request was a clean ``negative seek
        value`` under one ``whence`` and a misleading ``cannot seek before the beginning of
        the buffer`` under the others, which conflates a position that cannot exist with one
        that has merely slid out of the window, the latter being ordinary and recoverable
        with ``buffer_save=True``.

        The offsets are large enough to cross zero, which is what the existing
        ``seek(-1, io.SEEK_CUR)`` assertions do not do.

        """
        for whence, offset, message in [
            (io.SEEK_SET, -1, 'negative seek value -1'),
            (io.SEEK_CUR, -100, 'negative seek value -100'),
            (io.SEEK_END, -100, 'negative seek value -96'),   # buf_end is 4
        ]:
            with self.subTest(whence=whence, offset=offset):
                reader = self.SeekableReader(io.BytesIO(b'abcdef'), buffer_size=4)
                with self.assertRaises(self.exceptions.SeekError) as ctx:
                    reader.seek(offset, whence)
                self.assertEqual(str(ctx.exception), message)
                self.assertEqual(reader.tell(), 0)
                self._close_reader(reader)

    def test_seek_refuses_a_negative_position_with_a_saved_buffer_too(self) -> None:
        """With ``buffer_save=True`` the refusal was skipped and the seek reported success.

        The window refusal is conditional on there being no buffer file, since a saved
        buffer really can supply octets from before the window. A negative absolute position
        is not that case, and with a file the old code fell straight through and *returned*
        ``-5`` as though the seek had worked. The failure then surfaced on an unrelated call
        as a bare ``OSError: [Errno 22] Invalid argument`` out of the middle of
        :meth:`read`, from a line only reachable because :meth:`seek` had accepted something
        it should not have.

        """
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            path = temp.name
        try:
            reader = self.SeekableReader(io.BytesIO(b'abcdefghij'), buffer_size=4,
                                         buffer_save=True, buffer_path=path)
            with self.assertRaises(self.exceptions.SeekError) as ctx:
                reader.seek(-5, io.SEEK_CUR)     # returned -5, no exception at all
            self.assertEqual(str(ctx.exception), 'negative seek value -5')
            self.assertEqual(reader.tell(), 0)
            self.assertEqual(reader.read(1), b'a')   # was OSError: [Errno 22]
            self._close_reader(reader)
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_peek_does_not_move_what_the_next_read_returns(self) -> None:
        """A preview must leave the position alone, and the buffer's cursor is part of it.

        :meth:`peek` correctly never touched ``_tell``, but its buffered branch read
        *through* ``self._buffer``, advancing that :class:`io.BytesIO`'s own cursor. Nothing
        put it back, so ``_tell`` was right, the cursor was wrong, and the next buffered
        read started from the wrong octet -- while ``tell()`` reported the same number in
        both runs, leaving the caller no way to tell them apart. Each case here therefore
        asserts against a **control run** that omits only the ``peek``.

        Both branches are covered, because they drift by different routes. The
        :class:`io.BytesIO` case takes the buffered branch. The pipe case takes the other
        one: with no ``peek`` of its own the stream is read for real and the result handed to
        ``_write_buffer``, which writes through the memoryview and so leaves the cursor
        wherever it already was -- five octets adrift, replaying the first octets ever
        buffered.

        The data starts at ``\\x01`` rather than ``\\x00`` deliberately: ``\\x00`` is exactly
        the buffer's NUL padding, so data containing it cannot distinguish a real octet from
        a padded one.

        """
        data = bytes(range(1, 51))

        reader = self.SeekableReader(io.BytesIO(data), buffer_size=16)
        reader.read(8)
        reader.seek(2)
        control = reader.read(3)
        self.assertEqual(control, b'\x03\x04\x05')
        self._close_reader(reader)

        reader = self.SeekableReader(io.BytesIO(data), buffer_size=16)
        reader.read(8)
        reader.seek(2)
        self.assertEqual(reader.peek(3), b'\x03\x04\x05')
        self.assertEqual(reader.tell(), 2)
        # the cursor is the position's other half, and a preview may not have moved it
        self.assertEqual(reader._buffer.tell(), reader._tell - reader._buffer_set)
        self.assertEqual(reader.read(3), control)   # was b'\x06\x07\x08'
        self._close_reader(reader)

        stream = self._pipe_stream(data)
        reader = self.SeekableReader(stream, buffer_size=16, stream_closing=False)
        reader.read(8)
        control = reader.read(4)
        self.assertEqual(control, b'\x09\x0a\x0b\x0c')
        self._close_reader(reader)

        stream = self._pipe_stream(data)
        reader = self.SeekableReader(stream, buffer_size=16, stream_closing=False)
        reader.read(8)
        self.assertEqual(reader.peek(4), b'\x09\x0a\x0b\x0c')
        self.assertEqual(reader.tell(), 8)
        self.assertEqual(reader.read(4), control)   # was b'\x01\x02\x03\x04'
        self._close_reader(reader)

    # ------------------------------------------------------------------ #
    # issue #644 -- the count-less-one measured from the wrong origin
    # ------------------------------------------------------------------ #

    def test_buffered_reads_return_every_octet_available_from_the_position(self) -> None:
        """``min(size, _buffer_cur - 1)`` is wrong twice, and both halves are asserted here.

        ``_buffer_cur`` counts from the window's base, not from the position being read
        from, so it offers octets that lie *behind* the position; and the ``- 1`` is short of
        even that. What is genuinely available is
        ``_buffer_set + _buffer_cur - _tell``, which is what each path now asks for.

        The two halves fail differently, so each gets its own case:

        * The ``- 1`` alone, isolated by seeking to the window's base. The cap is one short,
          the shortfall is made up from the raw stream -- which has already moved past the
          octet that was skipped -- and the octet is dropped from the *middle* of the answer.
        * The wrong origin, isolated by seeking strictly inside the buffered region. This is
          the worse of the two: the buffer is allocated full of NUL padding, so over-asking
          returns real octets followed by padding at the *correct length*, which makes
          ``size_rem`` zero and skips the top-up entirely -- so the real octets are never
          fetched at all.

        ``read`` already carried the corrected count before this change; ``readline``,
        ``read1`` and ``peek`` are the three sites that did not. All four are asserted, the
        first as a regression guard.

        """
        # the `- 1` alone: seek to the base, ask for more than the cap allowed
        for method, data, size, expected in [
            ('read', b'abcde', 5, b'abcde'),                  # was b'abce'
            ('readline', b'abcde\nfghij\n', 6, b'abcde\n'),   # was b'abce\n'
            ('read1', b'abcde', 4, b'abcd'),                  # was b'abc'
            ('peek', b'abcde', 4, b'abcd'),                   # was b'abc'
        ]:
            with self.subTest(half='count-less-one', method=method):
                reader = self.SeekableReader(io.BytesIO(data))
                self.assertEqual(reader.read(4), b'abcd')
                self.assertEqual(reader.seek(0), 0)
                self.assertEqual(getattr(reader, method)(size), expected)
                self._close_reader(reader)

        # the wrong origin: seek strictly inside the buffered region, ask past its end
        for method, data, size, expected in [
            ('read', b'0123456789' + b'X' * 20, 8, b'56789XXX'),   # was b'56789\x00\x00\x00'
            ('readline', b'0123456789\n' + b'X' * 20, 8, b'56789\n'),
            ('read1', b'0123456789' + b'X' * 20, 8, b'56789'),
            ('peek', b'0123456789' + b'X' * 20, 8, b'56789'),
        ]:
            with self.subTest(half='wrong-origin', method=method):
                reader = self.SeekableReader(io.BytesIO(data))
                self.assertEqual(reader.read(10), b'0123456789')
                self.assertEqual(reader.seek(5), 5)
                got = getattr(reader, method)(size)
                self.assertEqual(got, expected)
                # NOTE: whatever the length, none of it may be the buffer's NUL padding --
                # that substitution is the defect, and the data has no NUL in it.
                self.assertNotIn(b'\x00', got)
                self._close_reader(reader)

    def test_an_unbounded_buffered_readline_still_finishes_the_line(self) -> None:
        """Capping ``readline`` at the buffer must not truncate a line that runs past it.

        With no size the old cap was ``min(-1, _buffer_cur - 1) == -1``, i.e. uncapped, and
        :meth:`io.BytesIO.readline` then ran off the content into the NUL padding behind it.
        Capping at the content is right, but on its own it would leave an unbounded
        ``readline`` stopping at the window's edge rather than at the newline, so the
        continuation from the stream now runs for a negative size as well -- the same shape
        :meth:`read` already had.

        """
        reader = self.SeekableReader(io.BytesIO(b'abcdefghij\nklm'), buffer_size=8)
        self.assertEqual(reader.read(4), b'abcd')
        self.assertEqual(reader.seek(0), 0)
        self.assertEqual(reader.readline(), b'abcdefghij\n')
        self.assertEqual(reader.tell(), 11)
        self._close_reader(reader)

    # ------------------------------------------------------------------ #
    # the invariant both issues turn on
    # ------------------------------------------------------------------ #

    def test_the_window_base_and_content_pointer_track_the_stream_consumption(self) -> None:
        """``_buffer_set + _buffer_cur`` is how far the stream has been read, always.

        This is the invariant #633's first revision broke, turning a loud
        :exc:`ValueError` into silent data corruption: :meth:`seek` reads the pair as the
        stream's consumption point and reads ahead from it to fill a gap, so a pair that
        under-reports makes the next forward seek splice octets in from the wrong absolute
        offset without complaining. It is asserted directly here, against a stream that
        counts what has actually been taken off it, after *every* operation rather than at
        the end -- an output assertion can pass while the bookkeeping behind it is already
        wrong, which is exactly how that revision got as far as review.

        Deriving the buffer's cursor from ``_tell`` at each point of use is what preserves
        the pair by construction: nothing clamps or adjusts either member to make a read fit,
        so neither can drift from what ``_write_buffer`` recorded.

        """
        stream = self._pipe_stream(b'abcdefghijklmnop')
        reader = self.SeekableReader(stream, buffer_size=8, stream_closing=False)

        operations = [
            ('read', lambda: reader.read(5), b'abcde'),
            ('peek', lambda: reader.peek(3), b'fgh'),
            ('read', lambda: reader.read(3), b'fgh'),
            ('seek', lambda: reader.seek(2), 2),
            ('readline', lambda: reader.readline(4), b'cdef'),
            ('read1', lambda: reader.read1(2), b'gh'),
            ('_truncate_buffer', lambda: reader._truncate_buffer(4), 4),
            ('read', lambda: reader.read(2), b'ij'),
        ]
        for name, operation, expected in operations:
            with self.subTest(operation=name, expected=expected):
                self.assertEqual(operation(), expected)
                self.assertEqual(reader._buffer_set + reader._buffer_cur, stream.consumed)
                self.assertGreaterEqual(reader._tell, 0)
                self.assertGreaterEqual(reader._buffer_set, 0)
                self.assertLessEqual(reader._buffer_cur, reader._buffer_size)
                self.assertEqual(len(reader._buffer.getvalue()), reader._buffer_size)
        self._close_reader(reader)

    def test_a_position_the_window_has_dropped_is_refused_not_guessed(self) -> None:
        """A read from before the window raises, rather than answering from the wrong octet.

        :meth:`_truncate_buffer` advances the window's base past the octets it drops, which can
        leave a position already set sitting before it. :meth:`seek` refuses that position
        outright -- the stream cannot be rewound to re-supply the octets, so there is
        nothing to read -- but the buffered read paths reached it too, by way of a position
        set *before* the truncation rather than after, and answered from whatever offset the
        cursor happened to hold. Here that returned ``b'c'``, the octet at 2, for a read at
        1.

        Refusing it is the same answer :meth:`seek` already gives, and turns the last silent
        wrong answer in this family into a loud one.

        """
        reader = self.SeekableReader(io.BytesIO(b'abcdefghijkl'), buffer_size=8)

        self.assertEqual(reader.read(4), b'abcd')
        self.assertEqual(reader.seek(1), 1)
        self.assertEqual(reader._truncate_buffer(2), 2)
        self.assertEqual(reader._buffer_set, 2)          # the window now starts at 2
        self.assertEqual(reader.tell(), 1)               # and the position is behind it

        with self.assertRaises(self.exceptions.SeekError):
            reader.read(1)                               # was b'c', the octet at 2
        with self.assertRaises(self.exceptions.SeekError):
            reader.seek(1)
        self._close_reader(reader)

    def test_a_zero_length_read_is_answered_without_consulting_the_window(self) -> None:
        """A request for no octets must not be refused for having nowhere to read from.

        The refusal in the previous test is on the window, and the window has nothing to say
        about a request that wants nothing: every one of these returned ``b''`` before the
        refusal existed, and a zero-length read failing on position grounds is not a
        behaviour either issue asked for. Checking the window before looking at the requested
        size made all four of them raise from a position :meth:`_truncate_buffer` had stranded.

        The same position is asserted both ways round, which is what makes this a statement
        about the *size* rather than about the state: at size zero all four return, and the
        test above shows ``read(1)`` from that identical state still raising.

        Only the buffered branch is short-circuited. A bare ``peek()`` on a position at or
        past the buffered content still goes to the raw stream, whose own ``peek(0)`` may
        return a whole buffer's worth, so the healthy cases here pin that down too.

        """
        for stranded in (False, True):
            for method, args in [('read', (0,)), ('read1', (0,)), ('readline', (0,)),
                                 ('peek', (0,)), ('peek', ())]:
                with self.subTest(stranded=stranded, method=method, args=args):
                    reader = self.SeekableReader(io.BytesIO(b'abcdefghijkl'), buffer_size=8)
                    self.assertEqual(reader.read(4), b'abcd')
                    self.assertEqual(reader.seek(1), 1)
                    if stranded:
                        self.assertEqual(reader._truncate_buffer(2), 2)
                        self.assertEqual(reader._buffer_set, 2)
                        self.assertLess(reader.tell(), reader._buffer_set)

                    self.assertEqual(getattr(reader, method)(*args), b'')
                    self.assertEqual(reader.tell(), 1)   # and nothing moved
                    self._close_reader(reader)


if __name__ == '__main__':
    unittest.main()
