# -*- coding: utf-8 -*-
"""A pipe that says it can seek and does not still yields every frame (#2097).

On Windows before CPython 3.16 a pipe's ``seekable()`` is :data:`True` and its
``seek`` silently does nothing (CPython gh-86768). Guards against ``Extractor``
taking that at its word, skipping :class:`~pcapkit.corekit.io.SeekableReader`, and
losing the octets its look at the magic number read. :class:`LyingPipe` reproduces
such a pipe on any platform, over a real :func:`os.pipe`.

"""

from __future__ import annotations

import importlib.util
import io
import os
import pathlib
import struct
import tempfile
import threading
import unittest
import warnings

from tests._support import reimport_once_per_class, scale_timeout

#: Test tier (#1958): exercises stream semantics, which differ by interpreter.
__tier__ = 'ALL'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


def make_pcap(count: 'int' = 50) -> 'bytes':
    """A little-endian PCAP capture of ``count`` Ethernet frames."""
    out = [struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
    for index in range(count):
        data = b'\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x88\xb5' + bytes([index]) * (46 + index)
        out.append(struct.pack('<IIII', 1_700_000_000 + index, index, len(data), len(data)) + data)
    return b''.join(out)


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


@unittest.skipUnless(HAS_RUNTIME, 'pcapkit runtime dependencies are not installed')
class TestPipeClaimingToSeek(unittest.TestCase):
    """Every frame from a pipe whose ``seekable()`` lies, as from a path."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def extract(self, fin: 'object') -> 'list[bytes]':
        import pcapkit  # pylint: disable=import-outside-toplevel

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = pcapkit.extract(fin=fin, nofile=True)
        return [bytes(frame) for frame in extractor.frame]  # type: ignore[attr-defined]

    def by_pipe(self, data: 'bytes', buffered: 'bool') -> 'list[bytes]':
        read_fd, write_fd = os.pipe()

        def write() -> None:
            with os.fdopen(write_fd, 'wb', buffering=0) as stream:
                stream.write(data)

        thread = threading.Thread(target=write, daemon=True)
        thread.start()
        stream = LyingPipe(read_fd)
        fin = io.BufferedReader(stream) if buffered else stream
        try:
            return self.extract(fin)
        finally:
            fin.close()
            thread.join(scale_timeout(30))

    def test_every_frame_from_a_pipe_claiming_to_seek(self) -> None:
        """Raw, as ``os.fdopen(fd, 'rb', buffering=0)``, and buffered, as ``sys.stdin.buffer``."""
        data = make_pcap()
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / 'capture.pcap'
            path.write_bytes(data)
            expected = self.extract(str(path))
        self.assertEqual(len(expected), 50)
        for buffered in (False, True):
            with self.subTest(buffered=buffered):
                self.assertEqual(self.by_pipe(data, buffered), expected)

    def test_a_regular_file_and_a_stream_without_a_descriptor_are_not_wrapped(self) -> None:
        """Only a stream whose descriptor is not a regular file loses the fast path."""
        import pcapkit  # pylint: disable=import-outside-toplevel
        from pcapkit.corekit.io import SeekableReader  # pylint: disable=import-outside-toplevel

        data = make_pcap(3)
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / 'capture.pcap'
            path.write_bytes(data)
            with open(path, 'rb') as file, warnings.catch_warnings():
                warnings.simplefilter('ignore')
                extractor = pcapkit.extract(fin=file, nofile=True)
                self.assertIs(extractor._ifile, file)  # pylint: disable=protected-access
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                extractor = pcapkit.extract(fin=io.BytesIO(data), nofile=True)
            self.assertNotIsInstance(extractor._ifile, SeekableReader)  # pylint: disable=protected-access
            self.assertEqual(len(extractor.frame), 3)  # type: ignore[attr-defined]


if __name__ == '__main__':
    unittest.main()
