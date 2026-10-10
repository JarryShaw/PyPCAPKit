# -*- coding: utf-8 -*-
"""Copying or pickling a :class:`~pcapkit.corekit.io.PeekableStream` follows its stream (#1524).

:mod:`copy` and :mod:`pickle` build the proxy without calling ``__init__``, then
ask it for ``__setstate__``. ``__getattr__`` forwarded that to ``self._stream``,
which was not set yet, so the lookup of ``_stream`` came back through
``__getattr__`` until :exc:`RecursionError`. It now refuses ``_stream`` and every
dunder, and the default protocols do what they do for any wrapper: a shallow
copy shares the stream, while a deep copy or a pickle copies it, and so works
exactly when the stream's own does.

Every class is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, so :mod:`pickle` finds the
same class object it was handed.

"""

import copy
import io
import pickle
import tempfile
import unittest

from tests._support import reimport_once_per_class

#: What :class:`_CopiesItself` returns from its own ``__deepcopy__``.
_COPIED = 'the stream copied itself'


class _CopiesItself:
    """A stream stand-in with a ``__deepcopy__`` of its own."""

    def __deepcopy__(self, memo: 'dict[int, object]') -> 'str':
        return _COPIED


class TestPeekableStreamCopy(unittest.TestCase):
    """:mod:`copy` and :mod:`pickle` on a proxy over an :class:`io.BytesIO`."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_copy_shares_the_stream(self) -> None:
        from pcapkit.corekit.io import PeekableStream  # pylint: disable=import-outside-toplevel

        raw = io.BytesIO(b'abcdef')
        raw.seek(2)
        stream = PeekableStream(raw)
        clone = copy.copy(stream)
        self.assertIs(type(clone), PeekableStream)
        self.assertIsNot(clone, stream)
        self.assertIs(clone._stream, raw)  # pylint: disable=protected-access
        self.assertEqual(clone.peek(2), b'cd')
        self.assertEqual(clone.read(1), b'c')
        self.assertEqual(stream.tell(), 3)

    def test_deepcopy_copies_the_stream(self) -> None:
        from pcapkit.corekit.io import PeekableStream  # pylint: disable=import-outside-toplevel

        raw = io.BytesIO(b'abcdef')
        raw.seek(2)
        clone = copy.deepcopy(PeekableStream(raw))
        self.assertIs(type(clone), PeekableStream)
        self.assertIsNot(clone._stream, raw)  # pylint: disable=protected-access
        self.assertEqual(clone.tell(), 2)
        self.assertEqual(clone.peek(2), b'cd')
        self.assertEqual(clone.read(), b'cdef')
        self.assertEqual(raw.tell(), 2)

    def test_pickle_round_trip_from_protocol_2(self) -> None:
        from pcapkit.corekit.io import PeekableStream  # pylint: disable=import-outside-toplevel

        for protocol in range(2, pickle.HIGHEST_PROTOCOL + 1):
            with self.subTest(protocol=protocol):
                raw = io.BytesIO(b'abcdef')
                raw.seek(2)
                clone = pickle.loads(pickle.dumps(PeekableStream(raw), protocol))
                self.assertIs(type(clone), PeekableStream)
                self.assertIsNot(clone._stream, raw)  # pylint: disable=protected-access
                self.assertEqual(clone.tell(), 2)
                self.assertEqual(clone.peek(2), b'cd')
                self.assertEqual(clone.read(), b'cdef')
                self.assertEqual(raw.tell(), 2)

    def test_pickle_below_protocol_2_fails_as_the_stream_does(self) -> None:
        """:class:`io.BytesIO` itself does not pickle at protocols 0 and 1, so neither does the proxy."""
        from pcapkit.corekit.io import PeekableStream  # pylint: disable=import-outside-toplevel

        for protocol in (0, 1):
            with self.subTest(protocol=protocol):
                raw = io.BytesIO(b'abcdef')
                with self.assertRaises(TypeError) as own:
                    pickle.dumps(raw, protocol)
                with self.assertRaises(TypeError) as proxied:
                    pickle.dumps(PeekableStream(raw), protocol)
                self.assertEqual(str(proxied.exception), str(own.exception))

    def test_an_unpicklable_stream_is_refused_as_the_stream_refuses(self) -> None:
        """An open file neither deep-copies nor pickles, so the proxy over one does neither."""
        from pcapkit.corekit.io import PeekableStream  # pylint: disable=import-outside-toplevel

        with tempfile.TemporaryFile() as raw:
            stream = PeekableStream(raw)
            self.assertIs(copy.copy(stream)._stream, raw)  # pylint: disable=protected-access
            with self.assertRaises(TypeError) as own:
                copy.deepcopy(raw)
            with self.assertRaises(TypeError) as proxied:
                copy.deepcopy(stream)
            self.assertEqual(str(proxied.exception), str(own.exception))
            for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
                with self.subTest(protocol=protocol):
                    with self.assertRaises(TypeError) as own:
                        pickle.dumps(raw, protocol)
                    with self.assertRaises(TypeError) as proxied:
                        pickle.dumps(stream, protocol)
                    self.assertEqual(str(proxied.exception), str(own.exception))

    def test_an_uninitialised_proxy_has_no_attributes(self) -> None:
        """What :mod:`copy` and :mod:`pickle` hold before restoring the state: no ``_stream`` to forward to."""
        from pcapkit.corekit.io import PeekableStream  # pylint: disable=import-outside-toplevel

        stream = PeekableStream.__new__(PeekableStream)
        self.assertFalse(hasattr(stream, '_stream'))
        with self.assertRaises(AttributeError):
            stream.read  # pylint: disable=pointless-statement

    def test_dunders_are_the_proxys_own(self) -> None:
        """A stream's ``__setstate__`` or ``__deepcopy__`` is not applied to the proxy."""
        from pcapkit.corekit.io import PeekableStream  # pylint: disable=import-outside-toplevel

        raw = io.BytesIO(b'abc')
        self.assertTrue(hasattr(raw, '__setstate__'))
        self.assertFalse(hasattr(PeekableStream(raw), '__setstate__'))

        clone = copy.deepcopy(PeekableStream(_CopiesItself()))  # type: ignore[arg-type]
        self.assertIs(type(clone), PeekableStream)
        self.assertEqual(clone._stream, _COPIED)  # pylint: disable=protected-access


if __name__ == '__main__':
    unittest.main()
