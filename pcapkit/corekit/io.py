# -*- coding: utf-8 -*-
"""Seekable I/O Object
=========================

.. module:: pcapkit.corekit.io

:mod:`pcapkit.corekit.io` contains seekable I/O object
:class:`~pcapkit.corekit.io.SeekableReader`, which is a customised
implementation to :class:`io.BufferedReader`.

"""
import io
import tempfile
from typing import TYPE_CHECKING, cast

from pcapkit.utilities.exceptions import (SeekError, TruncateError, UnsupportedCall,
                                          UnsupportedOperation, stacklevel)
from pcapkit.utilities.warnings import SeekWarning, warn

if TYPE_CHECKING:
    from io import BytesIO, RawIOBase
    from typing import IO, Iterable, Optional

    from typing_extensions import Buffer

__all__ = ['SeekableReader']


class SeekableReader(io.BufferedReader):
    """Seekable buffered reader.

    A buffered binary stream providing higher-level access to a readable, non seekable
    :class:`~io.RawIOBase` raw binary stream. It inherits :class:`~io.BufferedIOBase`.

    When reading data from this object, a larger amount of data may be requested from the
    underlying raw stream, and kept in an internal buffer. The buffered data can then be returned
    directly on subsequent reads.

    The constructor creates a :class:`~io.BufferedReader` for the given readable ``raw`` stream and
    ``buffer_size``. If ``buffer_size`` is omitted, :data:`~io.DEFAULT_BUFFER_SIZE` is used.

    Args:
        raw: Underlying raw stream.
        buffer_size: Buffer size.
        buffer_save: Whether to save buffer to file.
        buffer_path: Path to save buffer.
        stream_closing: Whether the stream should be closed upon exiting.

    """

    if TYPE_CHECKING:
        #: Whether the stream should be closed upon exiting.
        _closing: 'bool'

        #: Whether the stream is closed.
        _closed: 'bool'
        #: Underlying raw stream.
        _stream: 'IO[bytes]'

        #: Current position of the stream.
        _tell: 'int'

        #: Buffer.
        _buffer: 'BytesIO'
        #: Buffer view.
        _buffer_view: 'memoryview'

        #: Buffer size.
        _buffer_size: 'int'
        #: Buffer start position.
        _buffer_set: 'int'
        #: Buffer current position.
        _buffer_cur: 'int'

        #: Path to save buffer.
        _buffer_path: 'str'
        #: File to save buffer.
        _buffer_file: 'IO[bytes] | None'

    @property
    def closed(self) -> 'bool':
        """:data:`True` if the stream is closed."""
        return self._closed

    @property
    def raw(self) -> 'RawIOBase':
        """The underlying raw stream (a :class:`~io.RawIOBase` instance) that
        :class:`~io.BufferedIOBase` deals with. This is not part of the :class:`~io.BufferedIOBase`
        API and may not exist on some implementations."""
        return cast('RawIOBase', self._stream)

    @raw.setter
    def raw(self, raw: 'RawIOBase', /) -> 'None':
        raise UnsupportedCall("can't set attribute")

    def __init__(self, raw: 'IO[bytes]', buffer_size: 'int' = io.DEFAULT_BUFFER_SIZE,
                 buffer_save: 'bool' = False, buffer_path: 'Optional[str]' = None, *,
                 stream_closing: 'bool' = True) -> 'None':
        super().__init__(cast('RawIOBase', raw), buffer_size)

        self._closed = False
        self._closing = stream_closing

        self._stream = raw
        self._buffer = io.BytesIO(bytearray(buffer_size))

        self._buffer_view = self._buffer.getbuffer()
        self._buffer_size = buffer_size

        if buffer_save:
            if buffer_path is None:
                self._buffer_file = tempfile.NamedTemporaryFile('wb', buffering=0)
                self._buffer_path = self._buffer_file.name
            else:
                self._buffer_file = open(buffer_path, 'wb', buffering=0)
                self._buffer_path = buffer_path
        else:
            self._buffer_file = None
            self._buffer_path = ''

        self._tell = self._buffer_set = self._buffer_cur = 0

    def _write_buffer(self, buf: 'bytes', /) -> 'None':
        if self._buffer_file is not None:
            self._buffer_file.write(buf)
            self._buffer_file.flush()

        buf_len = len(buf)
        old_ptr = self._buffer_cur
        self._buffer_cur += buf_len

        if self._buffer_cur > self._buffer_size:
            if buf_len >= self._buffer_size:
                self._buffer_view[:] = buf[-self._buffer_size:]
            else:
                self._buffer_view[:-buf_len] = self._buffer_view[old_ptr - (self._buffer_size - buf_len):old_ptr]
                self._buffer_view[-buf_len:] = buf

            self._buffer_set += self._buffer_cur - self._buffer_size
            self._buffer_cur = self._buffer_size

            # move the pointer to the end of the original contents
            self._buffer.seek(-buf_len, io.SEEK_END)
        else:
            self._buffer_view[old_ptr:self._buffer_cur] = buf

    def close(self) -> 'None':
        """Flush and close this stream. This method has no effect if the file is already closed.
        Once the file is closed, any operation on the file (e.g. reading or writing) will raise
        a :exc:`ValueError`.

        As a convenience, it is allowed to call this method more than once; only the first call,
        however, will have an effect.

        """
        if self.closed:
            return
        self.flush()

        if self._closing:
            self._stream.close()
        if self._buffer_file is not None:
            self._buffer_file.close()
        self._buffer.close()

        self._closed = True

    def fileno(self) -> 'int':
        """Return the underlying file descriptor (an integer) of the stream if it exists.
        An :exc:`OSError` is raised if the IO object does not use a file descriptor."""
        return self._stream.fileno()

    def flush(self) -> 'None':
        """Flush the write buffers of the stream if applicable. This does nothing for
        read-only and non-blocking streams."""
        if self._buffer_file is not None:
            self._buffer_file.flush()
        self._stream.flush()

    def isatty(self) -> 'bool':
        """Return :data:`True` if the stream is interactive (i.e., connected to a
        terminal/tty device)."""
        return self._stream.isatty()

    def readable(self) -> 'bool':
        """Return :data:`True` if the stream can be read from. If :data:`False`,
        :meth:`read` will raise :exc:`OSError`."""
        return self._stream.readable()

    def readline(self, size: 'int | None' = -1, /) -> 'bytes':
        r"""Read and return one line from the stream. If ``size`` is specified, at most
        ``size`` bytes will be read.

        The line terminator is always ``b'\n'`` for binary files; for text files, the
        ``newline`` argument to :func:`open` can be used to select the line
        terminator(s) recognized.

        """
        if size is None:
            size = -1

        if self._tell >= self._buffer_set + self._buffer_cur:
            buf = self._stream.readline(size)
            self._write_buffer(buf)
        else:
            if self._buffer_file is not None and self._tell < self._buffer_set:
                with open(self._buffer_path, 'rb') as temp_file:
                    temp_file.seek(self._tell, io.SEEK_SET)
                    buf = temp_file.readline(size)
            else:
                buf = self._buffer.readline(min(size, self._buffer_cur - 1))

            if not buf.endswith(b'\n') and (size_rem := size - len(buf)) > 0:
                buf_tmp = self._stream.readline(size_rem)
                self._write_buffer(buf_tmp)
                buf += buf_tmp

        self._tell += len(buf)
        return buf

    def readlines(self, hint: 'int' = -1, /) -> 'list[bytes]':
        """Read and return a list of lines from the stream. ``hint`` can be specified to control
        the number of lines read: no more lines will be read if the total size (in
        bytes/characters) of all lines so far exceeds ``hint``.

        ``hint`` values of ``0`` or less, as well as :obj:`None`, are treated as no hint.

        Note that it's already possible to iterate on file objects using ``for line in file: ...``
        without calling :meth:`file.readlines() <readlines>`.

        """
        if hint is None or hint <= 0:
            lines = []  # type: list[bytes]
            while True:
                line = self.readline()
                if not line:
                    break
                lines.append(line)
            return lines

        size = 0
        lines = []
        while size < hint:
            line = self.readline(hint - size)
            if not line:
                break
            lines.append(line)
            size += len(line)
        return lines

    def seek(self, offset: 'int', whence: 'int' = io.SEEK_SET, /) -> 'int':
        """Change the stream position to the given byte ``offset``. ``offset`` is interpreted
        relative to the position indicated by ``whence``. The default value for ``whence`` is
        :data:`~io.SEEK_SET`. Values for ``whence`` are:

        * :data:`~io.SEEK_SET` or ``0`` - start of the stream (the default); ``offset`` should
          be zero or positive
        * :data:`~io.SEEK_CUR` or ``1`` - current stream position; ``offset`` may be negative
        * :data:`~io.SEEK_END` or ``2`` - end of the stream; ``offset`` is usually negative

        Return the new absolute position.

        """
        # NOTE: we mark the end of buffer content to the end of buffer
        # so that it may trigger the IO to read more data to fill in
        # the content.
        buf_end = self._buffer_set + self._buffer_size
        #buf_end = self._buffer_set + self._buffer_cur

        if whence == io.SEEK_SET:
            if offset < 0:
                raise SeekError(f'negative seek value {offset}')
            self._tell = offset
        elif whence == io.SEEK_CUR:
            self._tell += offset
        elif whence == io.SEEK_END:
            self._tell = buf_end + offset
        else:
            raise SeekError(f'invalid whence ({whence}, should be {io.SEEK_SET}, {io.SEEK_CUR} or {io.SEEK_END})')

        if self._tell >= self._buffer_set:
            if self._tell > buf_end:
                warn(f'seek beyond the end of the buffer: {self._tell} > {buf_end}',
                     SeekWarning, stacklevel=stacklevel())
            if self._tell > (tmp_end := self._buffer_set + self._buffer_cur):
                # NOTE: if we do need to seek beyond the existing contents,
                # then we'll do a quick read to make up the contents; the
                # size of the read is set to be 1/4 size of the buffer or
                # the size of the content to be read, whichever is larger.
                # However, the length to fill must not be larger than the
                # buffer size itself.
                tmp_len = min(max(self._tell - tmp_end, self._buffer_size // 4), self._buffer_size)
                self._tell = tmp_end

                tmp_buf = self.read1(tmp_len)
                self._tell = tmp_end + len(tmp_buf)
            self._buffer.seek(self._tell - self._buffer_set, io.SEEK_SET)
        else:
            if self._buffer_file is None:
                raise SeekError(f'cannot seek before the beginning of the buffer: {self._tell} < {self._buffer_set}')
            self._buffer.seek(0, io.SEEK_SET)
        return self._tell

    def seekable(self) -> 'bool':
        """Return :data:`True` if the stream supports random access. If :data:`False`,
        :meth:`seek`, :meth:`tell` and :meth:`truncate` will raise :exc:`OSError`."""
        return True

    def tell(self) -> 'int':
        """Return the current stream position."""
        return self._tell

    def truncate(self, size: 'int | None' = None, /) -> 'int':
        """Resize the stream to the given ``size`` in bytes (or the current position if ``size`` is
        not specified). The current stream position isn't changed. This resizing can extend or
        reduce the current file size. In case of extension, the contents of the new file area
        depend on the platform (on most systems, additional bytes are zero-filled). The new file
        size is returned."""
        if size is None:
            size = 0
        if size < 0:
            raise TruncateError(f'negative size value {size}')
        self._buffer_view.release()

        if size > self._buffer_size:
            self._buffer = io.BytesIO(self._buffer.getvalue().zfill(size - self._buffer_size))
            self._buffer_view = self._buffer.getbuffer()
        else:
            # keep the last ``size`` bytes
            temp = self._buffer.getvalue()

            self._buffer.truncate(size)
            self._buffer_view = self._buffer.getbuffer()

            self._buffer_view[:] = temp[-size:]

        self._buffer_size = size
        return self._buffer_size

    def writeable(self) -> 'bool':
        """Return :obj:`True` if the stream supports writing. If :obj:`False`, :meth:`write` and
        :meth:`truncate` will raise :exc:`OSError`."""
        return False

    def writelines(self, lines: 'Iterable[Buffer]', /) -> 'None':
        """Write a list of lines to the stream. Line separators are not added, so it is usual for
        each of the lines provided to have a line separator at the end."""
        raise UnsupportedOperation('write')

    def detach(self) -> 'RawIOBase':
        """Separate the underlying raw stream from the buffer and return it.

        After the raw stream has been detached, the buffer is in an unusable state.

        Some buffers, like :class:`~io.BytesIO`, do not have the concept of a single raw stream to
        return from this method. They raise :exc:`~io.UnsupportedOperation`.

        """
        if hasattr(self._stream, 'detach'):
            return self._stream.detach()
        raise UnsupportedOperation('detach')

    def read(self, size: 'int | None' = -1, /) -> 'bytes':
        """Read and return ``size`` bytes, or if ``size`` is not given or negative, until EOF or if
        the read call would block in non-blocking mode."""
        if size is None or size < 0:
            size = -1

        if self._tell >= self._buffer_set + self._buffer_cur:
            buf = self._stream.read(size)
            self._write_buffer(buf)
        else:
            if self._buffer_file is not None and self._tell < self._buffer_set:
                with open(self._buffer_path, 'rb') as temp_file:
                    temp_file.seek(self._tell, io.SEEK_SET)
                    buf = temp_file.read(size)
            else:
                buf = self._buffer.read(min(size, self._buffer_cur - 1))

            size_rem = -1
            if size < 0 or (size_rem := size - len(buf)) > 0:
                buf_tmp = self._stream.read(size_rem)
                self._write_buffer(buf_tmp)
                buf += buf_tmp

        self._tell += len(buf)
        return buf

    def read1(self, size: 'int | None' = -1, /) -> 'bytes':
        """Read and return up to ``size`` bytes with only one call on the raw stream. If at least
        one byte is buffered, only buffered bytes are returned. Otherwise, one raw stream read call
        is made."""
        if size is None:
            size = -1

        if self._tell >= self._buffer_set + self._buffer_cur:
            if hasattr(self._stream, 'read1'):
                buf = self._stream.read1(size)
            else:
                buf = self._stream.read(size)
            self._write_buffer(buf)
        else:
            if self._buffer_file is not None and self._tell < self._buffer_set:
                with open(self._buffer_path, 'rb') as temp_file:
                    temp_file.seek(self._tell, io.SEEK_SET)
                    buf = temp_file.read1(size)
            else:
                buf = self._buffer.read1(min(size, self._buffer_cur - 1))

            if not buf:  # only if the buffer is empty
                size_rem = -1
                if size < 0 or (size_rem := size - len(buf)) > 0:
                    if hasattr(self._stream, 'read1'):
                        buf_tmp = self._stream.read1(size_rem)
                    else:
                        buf_tmp = self._stream.read(size_rem)
                    self._write_buffer(buf_tmp)
                    buf += buf_tmp

        self._tell += len(buf)
        return buf

    def readinto(self, b: 'Buffer', /) -> 'int':
        """Read bytes into a pre-allocated, writable :term:`bytes-like object` ``b`` and return the
        number of bytes read. For example, ``b`` might be a :obj:`bytearray`.

        Like :meth:`read`, multiple reads may be issued to the underlying raw stream, unless the
        latter is interactive.

        A :exc:`BlockingIOError` is raised if the underlying raw stream is in non blocking-mode,
        and has no data available at the moment.

        """
        if TYPE_CHECKING:
            b = cast('memoryview', b)

        buf = self.read(len(b))
        buf_len = len(buf)

        b[:buf_len] = buf
        return buf_len

    def readinto1(self, b: 'Buffer', /) -> 'int':
        """Read bytes into a pre-allocated, writable :term:`bytes-like object` ``b``, using at most
        one call to the underlying raw stream's :meth:`read` (or :meth:`readinto`) method. Return
        the number of bytes read.

        A :exc:`BlockingIOError` is raised if the underlying raw stream is in non blocking-mode,
        and has no data available at the moment.

        """
        if TYPE_CHECKING:
            b = cast('memoryview', b)

        buf = self.read1(len(b))
        buf_len = len(buf)

        b[:buf_len] = buf
        return buf_len

    def write(self, b: 'Buffer', /) -> 'int':
        """Write the given :term:`bytes-like object`, ``b``, and return the number of bytes written
        (always equal to the length of ``b`` in bytes, since if the write fails an :exc:`OSError`
        will be raised).  Depending on the actual implementation, these bytes may be readily written
        to the underlying stream, or held in a buffer for performance and latency reasons.

        When in non-blocking mode, a :exc:`BlockingIOError` is raised if the data needed to be
        written to the raw stream but it couldn't accept all the data without blocking.

        The caller may release or mutate ``b`` after this method returns, so the implementation
        should only access ``b`` during the method call.

        """
        raise UnsupportedOperation('write')

    def peek(self, size: 'int' = 0) -> 'bytes':
        """Return bytes from the stream without advancing the position.

        At most one single read on the raw stream is done to satisfy the call.
        The number of bytes returned may be less or more than requested.

        """
        if self._tell >= self._buffer_set + self._buffer_cur:
            if hasattr(self._stream, 'peek'):
                buf = self._stream.peek(size)
            else:
                buf = self._stream.read(size)
                self._write_buffer(buf)
        else:
            if self._buffer_file is not None and self._tell < self._buffer_set:
                with open(self._buffer_path, 'rb') as temp_file:
                    temp_file.seek(self._tell, io.SEEK_SET)
                    buf = temp_file.peek(size)
            else:
                buf = self._buffer.read(min(size, self._buffer_cur - 1))

            if not buf and len(buf) < size:  # only if the buffer is empty and/or not enough
                size_rem = -1
                if size < 0 or (size_rem := size - len(buf)) > 0:
                    if hasattr(self._stream, 'peek'):
                        buf_tmp = self._stream.peek(size_rem)
                    else:
                        buf_tmp = self._stream.read(size_rem)
                        self._write_buffer(buf_tmp)
                        buf += buf_tmp
        return buf
