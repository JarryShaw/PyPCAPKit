# -*- coding: utf-8 -*-
"""GraalPy behaviours :mod:`pcapkit.corekit` does not depend on (#1963).

Each was measured on GraalPy 25.4 and does not happen on CPython, so each class
here stands in for GraalPy's behaviour and checks the module does not lean on
CPython's:

* :class:`io.BytesIO` ``read``, ``read1`` and ``readline`` from the start of an
  exported buffer can hand back :obj:`bytes` sharing its memory, so without the
  fix :class:`~pcapkit.corekit.io.SeekableReader` returns octets that its next
  write to the buffer then changes.
* ``dict.__init__`` and ``dict.update`` given ``(key, value)`` pairs store them
  through a subclass's ``__setitem__``, so without the fix ``MultiDict(MultiDict)``,
  and a ``MultiDict`` restored from pairs of its state, wrap every value list in
  another.

On GraalPy itself, ``test_end_of_stream_reads_ahead_only_as_far_as_asked`` in
``test_io_seekable_reader_short_reads_1586_unit.py`` and the ``MultiDict`` copies
in ``test_multidict.py`` fail without the fixes.

"""

import io
import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): pins GraalPy-only semantics, so it must run on every
#: interpreter leg.
__tier__ = 'ALL'

#: Octets the stream holds: more than a buffer's worth.
DATA = bytes(range(64))
#: A line longer than GraalPy's shared-read threshold, then more data.
LINES = b'x' * 12 + b'\n' + bytes(range(32))


class AliasingBytesIO(io.BytesIO):
    """A buffer whose reads return a view of its own memory, as GraalPy's can.

    On GraalPy, once :meth:`getbuffer` has exported the buffer, a read of more than
    eight octets from its start returns :obj:`bytes` that a later write through the
    export changes. A :class:`memoryview` of the same octets does the same here.

    """

    def _view(self, size: 'int | None') -> 'memoryview':
        start = self.tell()
        view = self.getbuffer()
        end = len(view) if size is None or size < 0 else min(start + size, len(view))
        self.seek(end)
        return view[start:end]

    def read(self, size: 'int | None' = -1, /) -> 'memoryview':  # type: ignore[override]
        return self._view(size)

    def read1(self, size: 'int | None' = -1, /) -> 'memoryview':  # type: ignore[override]
        return self._view(size)

    def readline(self, size: 'int | None' = -1, /) -> 'memoryview':  # type: ignore[override]
        start = self.tell()
        view = self._view(size)
        eol = view.tobytes().find(b'\n')
        if eol < 0:
            return view
        self.seek(start + eol + 1)
        return view[:eol + 1]


class SeekableReaderCopiesItsBufferTests(unittest.TestCase):
    """Octets the reader returned stay as they were when it slides its buffer."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def reader(self, data: 'bytes') -> 'object':
        from pcapkit.corekit.io import SeekableReader  # pylint: disable=import-outside-toplevel

        reader = SeekableReader(io.BytesIO(data), buffer_size=16, stream_closing=False)
        # pylint: disable=protected-access
        reader._buffer_view.release()
        reader._buffer = AliasingBytesIO(bytearray(reader._buffer_size))
        reader._buffer_view = reader._buffer.getbuffer()
        self.addCleanup(reader.close)
        return reader

    def check(self, method: 'str', data: 'bytes', size: 'int') -> None:
        reader = self.reader(data)
        self.assertEqual(reader.read(16), data[:16])
        self.assertEqual(reader.seek(0), 0)

        got = getattr(reader, method)(size)
        self.assertEqual(got, data[:len(got)])
        self.assertGreater(len(got), 8)

        # the next read from the stream slides the buffer over every octet in it
        self.assertEqual(reader.seek(16), 16)
        self.assertEqual(reader.read(32), data[16:48])
        self.assertEqual(got, data[:len(got)])
        self.assertIsInstance(got, bytes)

    def test_read(self) -> None:
        self.check('read', DATA, 10)

    def test_read1(self) -> None:
        self.check('read1', DATA, 10)

    def test_readline(self) -> None:
        self.check('readline', LINES, -1)


class PairsThroughSetitem(dict):
    """:class:`dict`, with GraalPy's ``__init__`` and ``update``: pairs go through ``__setitem__``.

    :class:`~pcapkit.corekit.multidict.MultiDict` reaches :obj:`dict` through
    :func:`super`, as Werkzeug's does, so a class deriving from it and then from
    this one puts this in its place, as GraalPy's :obj:`dict` would be.

    """

    def __init__(self, *args: 'object', **kwargs: 'object') -> None:  # pylint: disable=super-init-not-called
        self._store(dict.__init__, args, kwargs)

    def update(self, *args: 'object', **kwargs: 'object') -> None:
        self._store(dict.update, args, kwargs)

    def _store(self, method: 'object', args: 'tuple', kwargs: 'dict') -> None:
        """Pairs through ``self.__setitem__``, anything else as :class:`dict` stores it."""
        if args and not isinstance(args[0], dict):
            method(self, **kwargs)  # type: ignore[operator]
            for key, value in args[0]:
                self[key] = value
            return
        method(self, *args, **kwargs)  # type: ignore[operator]


class MultiDictCopyTests(unittest.TestCase):
    """``MultiDict(MultiDict)`` keeps each key's values as they were."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def multidict(self) -> 'type':
        """A :class:`~pcapkit.corekit.multidict.MultiDict` over :class:`PairsThroughSetitem`."""
        from pcapkit.corekit.multidict import MultiDict  # pylint: disable=import-outside-toplevel

        class GraalMultiDict(MultiDict, PairsThroughSetitem):  # type: ignore[misc]
            """A :class:`~pcapkit.corekit.multidict.MultiDict` on GraalPy's :obj:`dict`."""

        return GraalMultiDict

    def test_the_stand_in_wraps_pairs_as_graalpy_does(self) -> None:
        """A guard on the stand-in, not on the fix: it passes with or without it.

        The tests below fail without the fix only because the stand-in stores
        pairs through ``__setitem__``, as GraalPy does, and a plain dict as is.
        Without this, a stand-in that lost either would let them pass vacuously.

        """
        cls = self.multidict()
        # MultiDict's ``super()`` reaches the stand-in, not :obj:`dict`
        self.assertEqual([c.__name__ for c in cls.__mro__[1:4]],
                         ['MultiDict', 'PairsThroughSetitem', 'dict'])

        for method in (PairsThroughSetitem.__init__, PairsThroughSetitem.update):
            with self.subTest(method=method.__name__):
                data = cls()
                method(data, [('a', [5, 6])])
                self.assertEqual(dict.__getitem__(data, 'a'), [[5, 6]])
                method(data, {'b': [7]})
                self.assertEqual(dict.__getitem__(data, 'b'), [7])

    def test_a_copy_keeps_the_value_lists(self) -> None:
        cls = self.multidict()
        data = cls([('a', 5), ('a', 6), ('b', 3)])
        copied = cls(data)
        self.assertEqual(copied.getlist('a'), [5, 6])
        self.assertEqual(copied.getlist('b'), [3])

    def test_state_restored_from_pairs_keeps_the_value_lists(self) -> None:
        cls = self.multidict()
        state = cls([('a', 5), ('a', 6), ('b', 3)]).__getstate__()
        restored = cls()
        restored.__setstate__(state.items())
        self.assertEqual(restored.getlist('a'), [5, 6])
        self.assertEqual(restored.getlist('b'), [3])


if __name__ == '__main__':
    unittest.main()
