# -*- coding: utf-8 -*-
"""An ``Extractor`` whose constructor raises has closed the input it opened (#2100).

Guards against only a ``KeyboardInterrupt`` reaching ``_cleanup``, which leaves the
file open until collection after a ``FormatError`` out of ``__init__``, and the
exception holds the frame that keeps it alive. Windows then refuses to delete the
file (``WinError 32``); POSIX hides it, so the handles are recorded here instead.

"""

from __future__ import annotations

import builtins
import importlib.util
import io
import pathlib
import struct
import tempfile
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class

#: Test tier (#1958): exercises finalisation and stream ownership.
__tier__ = 'ALL'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: A PCAP-NG section header block.
SHB = struct.pack('<IIIHHqI', 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
#: An enhanced packet block on interface 0, which no interface block describes.
EPB = struct.pack('<IIIIIII', 6, 92, 0, 0, 0, 60, 60) + bytes(60) + struct.pack('<I', 92)


class Unseekable(io.RawIOBase):
    """A non-seekable raw stream over ``data``."""

    def __init__(self, data: 'bytes') -> None:
        super().__init__()
        self._data = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: 'bytearray | memoryview') -> int:  # type: ignore[override]
        return self._data.readinto(buffer)


@unittest.skipUnless(HAS_RUNTIME, 'pcapkit runtime dependencies are not installed')
class TestConstructorRaises(unittest.TestCase):
    """The input is released as the constructor raises, by the ownership rule (#610)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp_path = pathlib.Path(tmp.name)

    def extract(self, fin: 'object', **kwargs: 'object') -> 'BaseException':
        import pcapkit  # pylint: disable=import-outside-toplevel
        from pcapkit.utilities.exceptions import FormatError  # pylint: disable=import-outside-toplevel

        with warnings.catch_warnings(), self.assertRaises(FormatError) as caught:
            warnings.simplefilter('ignore')
            pcapkit.extract(fin=fin, nofile=True, **kwargs)
        return caught.exception

    def opened_by_path(self, data: 'bytes') -> 'tuple[list[io.BufferedReader], BaseException]':
        """Extract ``data`` by path, and return the handles the extractor opened."""
        import pcapkit.foundation.extraction as extraction  # pylint: disable=import-outside-toplevel

        path = self.tmp_path / 'capture.pcapng'
        path.write_bytes(data)
        handles = []  # type: list[io.BufferedReader]

        def recording_open(*args: 'object', **kwargs: 'object') -> 'io.BufferedReader':
            handle = builtins.open(*args, **kwargs)  # type: ignore[call-overload]
            handles.append(handle)
            return handle

        with mock.patch.object(extraction, 'open', recording_open, create=True):
            error = self.extract(str(path))
        self.assertEqual(len(handles), 1)
        return handles, error

    def test_a_format_error_while_reading_frames_closes_the_input(self) -> None:
        handles, error = self.opened_by_path(SHB + EPB)
        self.assertIn('interface', str(error))
        self.assertTrue(handles[0].closed)

    def test_an_unknown_format_closes_the_input_and_keeps_its_error(self) -> None:
        handles, error = self.opened_by_path(b'\x00' * 64)
        self.assertIn('unknown file format', str(error))
        self.assertTrue(handles[0].closed)

    def test_a_stream_the_caller_gave_is_left_open(self) -> None:
        path = self.tmp_path / 'capture.pcapng'
        path.write_bytes(SHB + EPB)
        with open(path, 'rb') as file:
            self.extract(file)
            self.assertFalse(file.closed)

        stream = Unseekable(SHB + EPB)
        self.extract(stream, buffer_save=True)
        self.assertFalse(stream.closed)


if __name__ == '__main__':
    unittest.main()
