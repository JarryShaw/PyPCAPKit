# -*- coding: utf-8 -*-
""":class:`~pcapkit.corekit.io.SeekableReader` over a stream that answers short (#1586).

One read of a pipe, or of a raw stream, may return fewer octets than were asked
for at any point; only an empty read means the stream has ended. The reader took
the first answer as all there was in three places, and the frame readers, which
measure what is left with ``seek(0, SEEK_END)``, took that for the end of the
capture:

* ``read(n)`` made one read of the stream, so it came back short mid-stream.
* ``seek(0, SEEK_END)`` was the buffer's far edge. Once the buffer had filled,
  that is exactly how far the stream has been read, so nothing more was read,
  and the first record ending there measured nothing left after it.
* A forward ``seek`` made one read too, and landed wherever that read ended --
  short of the target, or past it when the stream answered more than the gap.

Each test here fails on ``e9f3340f7``, the parent of the fix.

"""

import io
import unittest
import warnings

from tests._support import reimport_once_per_class

#: Octets the stream holds: more than a few buffers' worth.
DATA = bytes(range(256)) * 4


class ShortReads(io.RawIOBase):
    """A non-seekable raw stream answering at most ``chunk`` octets per read."""

    def __init__(self, data: 'bytes', chunk: 'int') -> None:
        super().__init__()
        self._data = data
        self._pos = 0
        self._chunk = chunk

    @property
    def consumed(self) -> int:
        """Octets read from the stream so far."""
        return self._pos

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def readinto(self, buffer: 'bytearray | memoryview') -> int:  # type: ignore[override]
        size = min(len(buffer), self._chunk, len(self._data) - self._pos)
        buffer[:size] = self._data[self._pos:self._pos + size]
        self._pos += size
        return size


class TestShortReads(unittest.TestCase):
    """A short answer from the stream is not the end of it."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def reader(self, data: 'bytes' = DATA, chunk: 'int' = 3, size: 'int' = 16) -> 'object':
        from pcapkit.corekit.io import SeekableReader  # pylint: disable=import-outside-toplevel

        reader = SeekableReader(ShortReads(data, chunk), buffer_size=size, stream_closing=False)
        self.addCleanup(reader.close)
        return reader

    def test_read_returns_every_octet_asked_for(self) -> None:
        """``read(10)`` over three-octet answers returned three octets."""
        reader = self.reader()
        self.assertEqual(reader.read(10), DATA[:10])
        # half from the buffer, half from the stream
        reader.seek(5)
        self.assertEqual(reader.read(10), DATA[5:15])
        self.assertEqual(reader.tell(), 15)

    def test_readinto_fills_the_buffer_it_is_given(self) -> None:
        reader = self.reader()
        buffer = bytearray(10)
        self.assertEqual(reader.readinto(buffer), 10)
        self.assertEqual(bytes(buffer), DATA[:10])

    def test_read_comes_back_short_only_at_the_end_of_the_stream(self) -> None:
        reader = self.reader(DATA[:20])
        self.assertEqual(reader.read(100), DATA[:20])
        self.assertEqual(reader.read(1), b'')

    def test_end_of_stream_is_a_buffer_past_the_position(self) -> None:
        """Before the buffer fills, the end was where one three-octet read left it."""
        reader = self.reader()
        self.assertEqual(reader.seek(0, io.SEEK_END), 16)
        self.assertEqual(reader.seek(0), 0)
        self.assertEqual(reader.read(16), DATA[:16])

    def test_end_of_stream_after_the_buffer_has_filled(self) -> None:
        """The #1586 cut-off: a full buffer's edge measured nothing left to read.

        This is what a frame reader does at the first octet of every record, so
        the record after the one that filled the buffer was taken for the end of
        the capture -- 870 of the 1,117 frames of ``http.pcap``.

        """
        reader = self.reader(chunk=4096)
        self.assertEqual(reader.read(40), DATA[:40])

        current = reader.tell()
        self.assertEqual(reader.seek(0, io.SEEK_END) - current, 16)   # was 0
        self.assertEqual(reader.seek(current), current)
        self.assertEqual(reader.read(16), DATA[40:56])

    def test_end_of_stream_is_the_real_end_when_that_comes_first(self) -> None:
        reader = self.reader(DATA[:50])
        self.assertEqual(reader.read(40), DATA[:40])
        self.assertEqual(reader.seek(0, io.SEEK_END), 50)
        self.assertEqual(reader.read(1), b'')

    def test_forward_seek_lands_on_its_target_over_short_answers(self) -> None:
        """A seek past the octets read stopped at the end of one three-octet read."""
        reader = self.reader()
        self.assertEqual(reader.seek(10), 10)                          # was 3
        self.assertEqual(reader.read(2), DATA[10:12])

    def test_forward_seek_does_not_overshoot_its_target(self) -> None:
        """The read that filled the gap asked for more than it, and the seek landed there."""
        from pcapkit.corekit.io import SeekableReader  # pylint: disable=import-outside-toplevel

        reader = SeekableReader(io.BytesIO(DATA), buffer_size=16, stream_closing=False)
        self.addCleanup(reader.close)
        self.assertEqual(reader.seek(1), 1)                            # was 4
        self.assertEqual(reader.read(2), DATA[1:3])

    def test_end_of_stream_reads_ahead_only_as_far_as_asked(self) -> None:
        """An engine that needs fewer octets measured does not wait for a buffer's worth.

        On a live stream a read past what has arrived waits for the writer, so the
        engines set ``_read_ahead_size`` to the record they are about to read.

        """
        reader = self.reader(DATA[:30], chunk=4096)
        reader._read_ahead_size = 10  # pylint: disable=protected-access
        self.assertEqual(reader.seek(0, io.SEEK_END), 10)
        self.assertEqual(reader.raw.consumed, 10)    # was 16: the whole buffer's worth
        self.assertEqual(reader.seek(0), 0)
        self.assertEqual(reader.read(30), DATA[:30])

    def test_reading_ahead_past_the_buffer_grows_it(self) -> None:
        """A record longer than the buffer is held whole, from its first octet on.

        The frame readers measure a record from its first octet and then seek back to
        it. Capped at the buffer, the read-ahead measured it short; read on, the record
        slid out of the buffer, and the seek back failed with ``cannot seek before the
        beginning of the buffer``.

        """
        reader = self.reader(chunk=7)
        self.assertEqual(reader.read(8), DATA[:8])
        reader._read_ahead_size = 40  # pylint: disable=protected-access
        self.assertEqual(reader.seek(0, io.SEEK_END), 48)          # was 24: 8 + 16
        self.assertEqual(reader.seek(8), 8)
        self.assertEqual(reader.read(40), DATA[8:48])

    def test_reading_ahead_a_bogus_length_stops_at_the_real_end(self) -> None:
        """A length read from a damaged record is read as far as the stream goes."""
        reader = self.reader(DATA[:50], chunk=4096)
        reader._read_ahead_size = 1 << 40  # pylint: disable=protected-access
        self.assertEqual(reader.seek(0, io.SEEK_END), 50)          # was 16
        self.assertEqual(reader.seek(0), 0)
        self.assertEqual(reader.read(), DATA[:50])

    def test_close_after_the_stream_was_closed(self) -> None:
        """A stream its owner closed first made :meth:`close` raise, from a finaliser too.

        Measured on a dpkt ``NeedData``: the extractor left with the reader, which was
        collected after the caller closed its stream, and printed ``Exception ignored
        ... ValueError: I/O operation on closed file``.

        """
        from pcapkit.corekit.io import SeekableReader  # pylint: disable=import-outside-toplevel

        stream = ShortReads(DATA, 3)
        reader = SeekableReader(stream, buffer_size=16, stream_closing=False)
        self.assertEqual(reader.read(4), DATA[:4])
        stream.close()
        reader.close()                               # was ValueError
        self.assertTrue(reader.closed)

    def test_seek_past_a_stream_that_ended_inside_the_buffer_is_silent(self) -> None:
        """As a seek past the end of a file is. A frame reader makes one over a cut record."""
        import pcapkit.utilities.warnings as pcapkit_warnings  # pylint: disable=import-outside-toplevel

        reader = self.reader(DATA[:10])
        self.assertEqual(reader.read(10), DATA[:10])
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            self.assertEqual(reader.seek(20), 10)
        self.assertEqual(
            [w for w in caught if issubclass(w.category, pcapkit_warnings.SeekWarning)], [])


if __name__ == '__main__':
    unittest.main()
