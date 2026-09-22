# -*- coding: utf-8 -*-
"""Who closes the input stream -- :class:`~pcapkit.foundation.extraction.Extractor` or its caller.

#610. :meth:`Extractor._cleanup <pcapkit.foundation.extraction.Extractor._cleanup>`
had the ownership test inverted, so it did both halves of the wrong thing at once:

* ``fin`` given as a **path**, where ``Extractor`` called :func:`open` itself and
  the handle is therefore its own, was **never closed** -- one leaked descriptor
  per extraction, for the life of the process. That is the ``ResourceWarning``
  #606 was tripping over from three unrelated pull requests (#577, #596, #600);
  #606 made the assertion in :file:`tests/utilities/test_stacklevel.py` immune to
  foreign warnings, which fixed the CI signal but could not fix the leak, because
  the leak is in library code.
* ``fin`` given as an **open stream**, which belongs to the caller, **was**
  closed. That is the more dangerous half: it is silent data loss for anyone who
  passes a file they still intend to read from, and there is no warning and no
  error to notice it by.

The same inverted polarity appeared a second time, at the
:class:`~pcapkit.corekit.io.SeekableReader` that wraps a non-seekable input:
``stream_closing=not self._flag_s`` asked for the caller's stream to be closed
along with the wrapper. Since a handle ``Extractor`` opens itself is always
seekable and so never wrapped, that argument was effectively a constant
:data:`True`, and every non-seekable caller-supplied stream was closed.

Why the counting here is done the hard way
------------------------------------------

A leak test that cannot fail is worse than none, so these do not assert "no
warning was raised" -- a proposition that holds just as well when the test has
stopped exercising anything. They **count handles**, by two independent means:

* :func:`opened_handles` patches :func:`builtins.open` for the duration of the
  call and keeps the file objects ``Extractor`` opened, so the count of those
  still open afterwards is a direct measurement rather than an inference. This
  works on every platform.
* :func:`fd_count` counts the process's own file descriptors that resolve to the
  capture, through :file:`/proc/self/fd`. That measures the *descriptor* rather
  than the Python wrapper around it, which is the thing that actually runs out.
  It is Linux-only and skipped elsewhere.

Both were measured against ``6c3d1b0d9`` before the fix: path-given leaked
exactly 1, stream-given left the caller's handle closed and unreadable.

"""

from __future__ import annotations

import builtins
import gc
import importlib.util
import io
import os
import unittest
from unittest import mock

from tests._support import sample_path

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Whether file descriptors can be counted on this platform. ``/proc/self/fd`` is
#: Linux; the :func:`builtins.open` measurement below covers the rest.
HAS_PROC_FD = os.path.isdir('/proc/self/fd')


def fd_count(target: str) -> int:
    """How many of this process's open descriptors resolve to ``target``.

    Args:
        target: Absolute path to count descriptors for. Resolved with
            :func:`os.path.realpath`, because that is the form
            :file:`/proc/self/fd` reports.

    Returns:
        The number of matching descriptors, or ``-1`` where :file:`/proc` is
        unavailable -- callers guard on :data:`HAS_PROC_FD` rather than reading
        the sentinel as a count.

    """
    if not HAS_PROC_FD:
        return -1
    wanted = os.path.realpath(target)
    total = 0
    for entry in os.listdir('/proc/self/fd'):
        try:
            if os.readlink(f'/proc/self/fd/{entry}') == wanted:
                total += 1
        except OSError:
            # The descriptor went away between listing and reading it, which is
            # ordinary and not a match.
            continue
    return total


class _NonSeekableRaw(io.RawIOBase):
    """A raw stream that cannot seek, to be wrapped in a :class:`io.BufferedReader`.

    Together they reproduce ``sys.stdin.buffer``: a buffered reader -- so it has
    ``peek`` -- over a raw stream that answers :data:`False` to ``seekable``, which
    is what makes :class:`~pcapkit.foundation.extraction.Extractor` wrap the input
    in a :class:`~pcapkit.corekit.io.SeekableReader`.

    """

    name = 'in.pcap'

    def __init__(self, payload: 'bytes') -> None:
        super().__init__()
        self._payload = payload
        self._pos = 0

    def readable(self) -> 'bool':
        return True

    def seekable(self) -> 'bool':
        return False

    def readinto(self, buffer: 'bytearray') -> 'int':  # type: ignore[override]
        chunk = self._payload[self._pos:self._pos + len(buffer)]
        buffer[:len(chunk)] = chunk
        self._pos += len(chunk)
        return len(chunk)


class _OpenRecorder:
    """Records the handles :func:`builtins.open` returned for one path.

    Patching :func:`builtins.open` rather than reading a private attribute keeps
    the measurement independent of *how* :class:`Extractor` stores the handle, so
    the test still counts something if that changes.

    """

    def __init__(self, path: 'str') -> None:
        self.path = os.path.realpath(path)
        self.handles = []  # type: list[io.IOBase]
        self._real = builtins.open

    def __call__(self, file, *args, **kwargs):  # type: ignore[no-untyped-def]
        handle = self._real(file, *args, **kwargs)
        try:
            matched = isinstance(file, (str, bytes, os.PathLike)) \
                and os.path.realpath(os.fsdecode(file)) == self.path
        except (TypeError, ValueError):  # pragma: no cover
            matched = False
        if matched:
            self.handles.append(handle)
        return handle

    @property
    def still_open(self) -> 'int':
        """How many of the recorded handles have not been closed."""
        return sum(1 for handle in self.handles if not handle.closed)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ExtractorClosesWhatItOpens(unittest.TestCase):
    """``fin`` as a path: the handle is ``Extractor``'s, so ``Extractor`` closes it."""

    def test_path_given_extraction_leaks_no_handle(self) -> None:
        """Nothing is left open on the capture once ``extract`` has returned.

        Measured two ways, so a future change that defeats one still fails on the
        other. Before #610 both reported exactly one handle left open.

        """
        import pcapkit

        capture = sample_path('in.pcap')
        before = fd_count(capture)

        recorder = _OpenRecorder(capture)
        with mock.patch.object(builtins, 'open', recorder):
            extractor = pcapkit.extract(fin=capture, nofile=True, store=False)

        self.assertTrue(recorder.handles,
                        'Extractor did not open the capture at all, so this test '
                        'has stopped measuring the thing it was written for')

        with self.subTest(measurement='builtins.open handles still open'):
            self.assertEqual(recorder.still_open, 0,
                             f'{recorder.still_open} of {len(recorder.handles)} '
                             'handle(s) Extractor opened are still open')

        if HAS_PROC_FD:
            with self.subTest(measurement='/proc/self/fd descriptors'):
                self.assertEqual(fd_count(capture), before,
                                 'the descriptor count for the capture did not '
                                 'return to where it started')

        # Keep the extractor alive to here: a leak that CPython's reference
        # counting has already cleaned up because the object went out of scope is
        # not the leak this measures.
        del extractor
        gc.collect()

    def test_extractor_abandoned_before_eof_still_releases_its_handle(self) -> None:
        """An ``auto=False`` extraction dropped part way through leaks nothing.

        ``_cleanup`` is reached on end of file, on interrupt, and from
        :meth:`Extractor.run`, so a caller that iterates a few frames and then
        drops the extractor reaches none of them -- which is precisely what
        :file:`tests/integration/test_runtime_extract.py` does, and was the second
        of the two ``in.pcap`` warnings #610 counted. The finaliser is the
        backstop; the deterministic route is the context manager.

        """
        import pcapkit

        capture = sample_path('in.pcap')
        before = fd_count(capture)

        recorder = _OpenRecorder(capture)
        with mock.patch.object(builtins, 'open', recorder):
            extractor = pcapkit.extract(fin=capture, nofile=True, store=False,
                                        auto=False)
            next(extractor)          # one frame of six, then walk away
            extractor()              # and a second, through the call form

        self.assertTrue(recorder.handles,
                        'Extractor did not open the capture, so this test has '
                        'stopped measuring anything')
        self.assertEqual(recorder.still_open, 1,
                         'the extraction is mid-flight, so its handle should be '
                         'open at this point')

        del extractor
        gc.collect()

        with self.subTest(measurement='builtins.open handles still open'):
            self.assertEqual(recorder.still_open, 0,
                             f'{recorder.still_open} handle(s) survived the '
                             'extractor being dropped')

        if HAS_PROC_FD:
            with self.subTest(measurement='/proc/self/fd descriptors'):
                self.assertEqual(fd_count(capture), before,
                                 'the descriptor for the capture outlived the '
                                 'extractor that opened it')

    def test_cleanup_is_safe_to_reach_twice(self) -> None:
        """``_cleanup`` runs twice for one extraction, and closing twice is fine.

        Its own docstring records the two routes -- the EOF path and
        :meth:`Extractor.run` -- so now that the path-given case actually closes
        the handle, the second call has to tolerate an already-closed one.

        """
        import pcapkit

        capture = sample_path('in.pcap')
        extractor = pcapkit.extract(fin=capture, nofile=True, store=False)
        self.assertTrue(extractor._ifile.closed)

        extractor._cleanup()  # must not raise
        self.assertTrue(extractor._ifile.closed)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ExtractorLeavesTheCallersStreamAlone(unittest.TestCase):
    """``fin`` as an open stream: it is the caller's, and closing it is data loss."""

    def test_caller_supplied_stream_stays_open_and_readable(self) -> None:
        """The caller can still read its own file after ``extract`` returns.

        ``closed`` alone would be a thin assertion, so the read is done as well:
        the failure this guards against is a caller losing access to a file it
        still holds, and that is what actually demonstrates it. Before #610 the
        handle came back closed and the read raised
        ``ValueError: seek of closed file``.

        """
        import pcapkit

        capture = sample_path('in.pcap')
        with open(capture, 'rb') as handle:
            extractor = pcapkit.extract(fin=handle, nofile=True, store=False)

            with self.subTest(check='handle not closed'):
                self.assertFalse(handle.closed,
                                 "Extractor closed the caller's stream")

            with self.subTest(check='handle still readable'):
                handle.seek(0)
                self.assertEqual(handle.read(4), b'\xd4\xc3\xb2\xa1',
                                 'the magic number should still be readable from '
                                 "the caller's own handle")

            del extractor

    def test_non_seekable_stream_survives_its_seekable_wrapper(self) -> None:
        """A wrapped stream is the caller's; the wrapper is ``Extractor``'s.

        A non-seekable input is wrapped in a
        :class:`~pcapkit.corekit.io.SeekableReader`, which ``Extractor``
        constructed and so may close -- but ``stream_closing`` has to keep the
        caller's stream underneath it open. That argument was
        ``not self._flag_s``, i.e. always :data:`True` here, so the stream went
        down with the wrapper.

        """
        import pcapkit
        from pcapkit.corekit.io import SeekableReader

        capture = sample_path('in.pcap')
        with open(capture, 'rb') as source:
            payload = source.read()

        # A ``BufferedReader`` over a non-seekable raw stream, which is the shape
        # ``sys.stdin.buffer`` has -- and stdin is the input that actually reaches
        # this path, since ``pcapkit/__main__.py`` hands it over for ``fin='-'``.
        # A bare non-seekable :class:`io.BytesIO` is *not* usable here: lacking
        # ``peek`` it takes a different branch of ``SeekableReader`` that mis-reads
        # the first record, which is why the existing suite only ever drives one
        # with ``Extractor.run`` patched out.
        stream = io.BufferedReader(_NonSeekableRaw(payload))
        extractor = pcapkit.extract(fin=stream, nofile=True, store=False)

        self.assertIsInstance(extractor._ifile, SeekableReader,
                              'a non-seekable input should have been wrapped, '
                              'without which this test proves nothing')

        with self.subTest(check='wrapper closed'):
            self.assertTrue(extractor._ifile.closed,
                            "Extractor should close the wrapper it built")

        with self.subTest(check="caller's stream still open"):
            self.assertFalse(stream.closed,
                             "Extractor closed the caller's stream through the "
                             'wrapper')

        stream.close()


class OwnershipRuleInIsolation(unittest.TestCase):
    """``_owns_input`` and ``__del__`` without constructing a real extraction.

    These need no capture and no runtime dependencies, so they run in the unit
    tier unconditionally.

    """

    @staticmethod
    def _uninitialised():  # type: ignore[no-untyped-def]
        """An ``Extractor`` that never ran its constructor."""
        from pcapkit.foundation.extraction import Extractor

        return object.__new__(Extractor)

    def test_ownership_follows_the_flag_and_the_wrapper(self) -> None:
        """The rule, stated once, over the three shapes an input can have."""
        from pcapkit.corekit.io import SeekableReader

        cases = (
            ('path given, plain handle', True, io.BytesIO(b''), True),
            ('stream given by the caller', False, io.BytesIO(b''), False),
            ('stream given, wrapped by us', False,
             mock.MagicMock(spec=SeekableReader), True),
        )
        for label, flag_s, ifile, owned in cases:
            with self.subTest(case=label):
                extractor = self._uninitialised()
                extractor._flag_s = flag_s
                extractor._ifile = ifile
                self.assertIs(extractor._owns_input(), owned)

    def test_finaliser_tolerates_a_half_built_instance(self) -> None:
        """``__del__`` on an instance whose constructor failed must not raise.

        ``_flag_s`` is assigned early in ``__init__`` and ``_ifile`` only much
        later, so a constructor that raises in between -- an unreadable path, an
        unknown output format -- leaves exactly this state. A finaliser that
        raised here would print an ignored exception on every such failure and
        bury the real one.

        """
        half_built = self._uninitialised()
        half_built._flag_s = True                       # set; ``_ifile`` is not
        self.assertFalse(half_built._owns_input(),
                         'with no stream there is nothing to own')
        half_built.__del__()                            # must not raise

        bare = self._uninitialised()
        bare.__del__()                                  # nor with no flag either

    def test_finaliser_leaves_a_stream_it_does_not_own(self) -> None:
        """The caller's stream survives the extractor being collected."""
        given = self._uninitialised()
        given._flag_s = False
        given._ifile = io.BytesIO(b'data')
        given.__del__()
        self.assertFalse(given._ifile.closed)

    def test_finaliser_closes_a_stream_it_does_own(self) -> None:
        """A handle opened by ``Extractor`` is released even without ``_cleanup``."""
        owned = self._uninitialised()
        owned._flag_s = True
        owned._ifile = io.BytesIO(b'data')
        owned.__del__()
        self.assertTrue(owned._ifile.closed)

    def test_finaliser_swallows_an_unclosable_stream(self) -> None:
        """A close that fails during shutdown is not worth an ignored exception."""
        wedged = self._uninitialised()
        wedged._flag_s = True
        wedged._ifile = mock.Mock(closed=False, close=mock.Mock(side_effect=ValueError))
        wedged.__del__()                                # must not raise
        wedged._ifile.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
