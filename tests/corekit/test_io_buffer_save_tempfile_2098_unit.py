# -*- coding: utf-8 -*-
"""``SeekableReader``'s own buffer file can be read back on Windows, and never leaks (#2098).

With ``buffer_save`` and no ``buffer_path`` the reader made a
:func:`tempfile.NamedTemporaryFile` and later opened it again by name, which
Windows refuses while the first handle is open: ``PermissionError: [Errno 13]``.
:class:`RefusingReopen` applies that rule on any platform.

"""

from __future__ import annotations

import builtins
import errno
import gc
import importlib.util
import io
import os
import struct
import tempfile
import unittest
import warnings
from unittest import mock

from tests._support import bootstrap_core_modules, load_module, reimport_once_per_class

#: Test tier (#1958): exercises finalisation and stream semantics.
__tier__ = 'ALL'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class RefusingReopen:
    """Windows' rule: a ``NamedTemporaryFile`` cannot be opened again while it is open."""

    def __init__(self) -> None:
        self.held = []  # type: list[object]
        self._factory = tempfile.NamedTemporaryFile

    def named(self, *args: 'object', **kwargs: 'object') -> 'object':
        file = self._factory(*args, **kwargs)  # type: ignore[call-overload]
        self.held.append(file)
        return file

    def open(self, file: 'object', *args: 'object', **kwargs: 'object') -> 'object':
        for temp in self.held:
            if file == temp.name and not temp.closed:  # type: ignore[attr-defined]
                raise PermissionError(errno.EACCES, 'Permission denied', file)
        return builtins.open(file, *args, **kwargs)  # type: ignore[call-overload]


class TestBufferFile(unittest.TestCase):
    """The default buffer file reads back, and goes away with the reader."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        bootstrap_core_modules()
        self.io_module = load_module('pcapkit.corekit.io', 'pcapkit/corekit/io.py')
        self.SeekableReader = self.io_module.SeekableReader

    def test_the_buffer_reads_back_where_a_temporary_file_cannot_be_reopened(self) -> None:
        rule = RefusingReopen()
        with mock.patch('tempfile.NamedTemporaryFile', rule.named), \
                mock.patch.object(self.io_module, 'open', rule.open, create=True):
            reader = self.SeekableReader(io.BytesIO(b'abcdefghij'), buffer_size=4, buffer_save=True)
            try:
                self.assertEqual(reader.read(6), b'abcdef')
                reader.seek(0)
                self.assertEqual(reader.read(3), b'abc')
                self.assertEqual(reader.peek(2)[:2], b'de')
                self.assertEqual(reader.readline(), b'defghij')
            finally:
                reader.close()

    def test_close_removes_the_temporary_file(self) -> None:
        reader = self.SeekableReader(io.BytesIO(b'abcdefghij'), buffer_size=4, buffer_save=True)
        path = reader._buffer_path  # pylint: disable=protected-access
        reader.read()
        self.assertTrue(os.path.isfile(path))
        reader.close()
        self.assertFalse(os.path.exists(path))
        reader.close()

    def test_collection_removes_the_temporary_file_of_an_unclosed_reader(self) -> None:
        reader = self.SeekableReader(io.BytesIO(b'abcdefghij'), buffer_size=4, buffer_save=True)
        path = reader._buffer_path  # pylint: disable=protected-access
        reader.read()
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', ResourceWarning)
            del reader
            gc.collect()
        self.assertFalse(os.path.exists(path))

    def test_a_buffer_path_the_caller_gave_is_kept(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'buffer.bin')
            reader = self.SeekableReader(io.BytesIO(b'abcdefghij'), buffer_size=4,
                                         buffer_save=True, buffer_path=path)
            reader.read()
            reader.close()
            with open(path, 'rb') as file:
                self.assertEqual(file.read(), b'abcdefghij')


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
class TestExtractorBufferFile(unittest.TestCase):
    """``Extractor(buffer_save=True)`` over a pipe leaves no temporary file behind."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_an_extraction_removes_its_buffer_file(self) -> None:
        import pcapkit  # pylint: disable=import-outside-toplevel

        frame = b'\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x88\xb5' + bytes(46)
        record = struct.pack('<IIII', 1_700_000_000, 0, len(frame), len(frame)) + frame
        data = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + record * 200
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = pcapkit.extract(fin=Unseekable(data), nofile=True, buffer_save=True)
        buffer_path = extractor._ifile._buffer_path  # pylint: disable=protected-access
        self.assertTrue(buffer_path)
        self.assertEqual(len(extractor.frame), 200)  # type: ignore[attr-defined]
        self.assertFalse(os.path.exists(buffer_path))


if __name__ == '__main__':
    unittest.main()
