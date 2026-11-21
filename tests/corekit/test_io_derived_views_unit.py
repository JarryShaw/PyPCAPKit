# -*- coding: utf-8 -*-
""":class:`~pcapkit.corekit.io.SeekableReader` releases each slice of its buffer view.

A slice of the :class:`memoryview` the reader holds over its :class:`io.BytesIO`
exports that buffer until the slice is released. CPython releases it as the
expression ends; PyPy 3.12 only once the collector reaches it, so
:meth:`~pcapkit.corekit.io.SeekableReader.close` closes a buffer some slice still
exports, and raises :exc:`BufferError`. ``HeldSlices`` keeps every slice alive as
PyPy's collector does, and each test here fails without the fix.

"""

import io
import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): exercises buffer semantics, which differ by interpreter.
__tier__ = 'ALL'

#: Octets the stream holds: more than a buffer's worth.
DATA = bytes(range(64))
#: Buffer size: small enough for a second read to slide the window.
BUFFER_SIZE = 16


class HeldSlices:
    """A buffer view whose slices stay alive until the test ends."""

    def __init__(self, view: 'memoryview') -> None:
        self.view = view
        self.slices = []  # type: list[memoryview]

    def __getitem__(self, key: 'slice') -> 'memoryview':
        item = self.view[key]
        self.slices.append(item)
        return item

    def __setitem__(self, key: 'slice', value: 'object') -> None:
        self.view[key] = value

    def __len__(self) -> int:
        return len(self.view)

    def release(self) -> None:
        self.view.release()


class SeekableReaderReleasesItsSlicesTests(unittest.TestCase):
    """Every path that slices the buffer view leaves the buffer closable."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def reader(self) -> 'tuple[object, HeldSlices]':
        from pcapkit.corekit.io import SeekableReader  # pylint: disable=import-outside-toplevel

        reader = SeekableReader(io.BytesIO(DATA), buffer_size=BUFFER_SIZE, stream_closing=False)
        # pylint: disable=protected-access
        held = HeldSlices(reader._buffer_view)
        reader._buffer_view = held
        self.addCleanup(self.release, held)
        return reader, held

    @staticmethod
    def release(held: 'HeldSlices') -> None:
        for view in held.slices:
            view.release()

    def check(self, reader: 'object', held: 'HeldSlices') -> None:
        self.assertTrue(held.slices)
        reader.close()  # type: ignore[attr-defined]
        self.assertTrue(reader._buffer.closed)  # type: ignore[attr-defined]  # pylint: disable=protected-access

    def test_buffered_reads(self) -> None:
        for method in ('read', 'read1', 'readline', 'peek'):
            with self.subTest(method=method):
                reader, held = self.reader()
                self.assertEqual(reader.read(8), DATA[:8])  # type: ignore[attr-defined]
                self.assertEqual(reader.seek(0), 0)  # type: ignore[attr-defined]
                self.assertEqual(getattr(reader, method)(4)[:4], DATA[:4])
                self.check(reader, held)

    def test_a_sliding_write(self) -> None:
        reader, held = self.reader()
        self.assertEqual(reader.read(10), DATA[:10])  # type: ignore[attr-defined]
        self.assertEqual(reader.read(10), DATA[10:20])  # type: ignore[attr-defined]
        self.check(reader, held)


if __name__ == '__main__':
    unittest.main()
