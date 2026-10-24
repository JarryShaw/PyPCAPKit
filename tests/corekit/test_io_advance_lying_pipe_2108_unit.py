# -*- coding: utf-8 -*-
""":func:`~pcapkit.corekit.io.advance` reads past a record on a pipe that only says it can seek (#2108).

On Windows before CPython 3.16 a pipe's ``seekable()`` is :data:`True` and its
``seek`` silently does nothing (CPython gh-86768). A frame reader built directly
on a caller's stream -- ``Frame(file, ...)`` or ``PCAPNG(file, ...)`` -- hands that
stream to :func:`advance` unwrapped, which then "skipped" a record without moving.
:class:`LyingPipe` reproduces such a pipe on any platform, over a real
:func:`os.pipe`.

"""

from __future__ import annotations

import io
import os
import pathlib
import tempfile
import threading
import unittest

from tests._support import reimport_once_per_class, scale_timeout

#: Test tier (#1958): exercises stream semantics, which differ by interpreter.
__tier__ = 'ALL'


class LyingPipe(io.RawIOBase):
    """The read end of a pipe, claiming to seek as a Windows pipe does."""

    def __init__(self, fd: 'int') -> None:
        super().__init__()
        self._file = os.fdopen(fd, 'rb', buffering=0)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def seek(self, offset: 'int', whence: 'int' = io.SEEK_SET) -> int:
        return offset if whence == io.SEEK_SET else 0

    def tell(self) -> int:
        return 0

    def fileno(self) -> int:
        return self._file.fileno()

    def readinto(self, buffer: 'bytearray | memoryview') -> int:  # type: ignore[override]
        return self._file.readinto(buffer)  # type: ignore[return-value]

    def close(self) -> None:
        self._file.close()
        super().close()


class TestAdvanceOnLyingPipe(unittest.TestCase):
    """:func:`advance` trusts ``seekable()`` only where a seek really moves."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_a_pipe_claiming_to_seek_is_read_past(self) -> None:
        """Raw, and buffered as ``sys.stdin.buffer`` is: the octets after the skip come next."""
        from pcapkit.corekit.io import advance  # pylint: disable=import-outside-toplevel

        data = b'A' * 10_000 + b'next record'
        for buffered in (False, True):
            with self.subTest(buffered=buffered):
                read_fd, write_fd = os.pipe()

                def write() -> None:
                    with os.fdopen(write_fd, 'wb', buffering=0) as stream:
                        stream.write(data)

                thread = threading.Thread(target=write, daemon=True)
                thread.start()
                pipe = LyingPipe(read_fd)
                stream = io.BufferedReader(pipe) if buffered else pipe
                try:
                    advance(stream, 10_000)  # type: ignore[arg-type]
                    self.assertEqual(stream.read(), b'next record')
                finally:
                    stream.close()
                    thread.join(scale_timeout(30))

    def test_a_regular_file_and_a_stream_without_a_descriptor_still_seek(self) -> None:
        """Seeking, unlike reading, may land past the end, as an absolute seek would."""
        from pcapkit.corekit.io import advance  # pylint: disable=import-outside-toplevel

        data = b'0123456789'
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / 'capture.bin'
            path.write_bytes(data)
            with open(path, 'rb') as file:
                advance(file, 25)
                self.assertEqual(file.tell(), 25)
        stream = io.BytesIO(data)
        advance(stream, 25)
        self.assertEqual(stream.tell(), 25)


if __name__ == '__main__':
    unittest.main()
