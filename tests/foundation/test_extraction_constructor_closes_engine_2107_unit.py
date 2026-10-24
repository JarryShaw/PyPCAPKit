# -*- coding: utf-8 -*-
"""An ``Extractor`` whose constructor raises after choosing an engine closes it (#2107).

#2100 closed the input such a constructor owns, but not the engine, so an
engine's own resources -- PyShark's ``tshark`` process and temporary file -- were
left for collection. Closing it must not replace the error that stopped the
constructor, even when the close raises too.

The constructor does that through ``_cleanup(failed=True)``, and ``__exit__``
through the same ``_release``, so there is one close path. A failed constructor
must not finish the flow tracer, as its capture never reached its end, and may
have no engine at all.

"""

from __future__ import annotations

import builtins
import importlib.util
import io
import pathlib
import struct
import tempfile
import types
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Callable

#: Test tier (#1958): exercises finalisation and stream ownership.
__tier__ = 'ALL'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)
HAS_PYSHARK = importlib.util.find_spec('pyshark') is not None

#: A PCAP global header, little-endian, Ethernet; the fake engine never reads it.
PCAP = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def fake_trace(calls: 'list[str]') -> 'types.SimpleNamespace':
    """A flow tracer manager whose ``tcp.finish`` is recorded into ``calls``."""
    return types.SimpleNamespace(tcp=types.SimpleNamespace(finish=lambda: calls.append('finish')))


@unittest.skipUnless(HAS_RUNTIME, 'pcapkit runtime dependencies are not installed')
class TestConstructorClosesEngine(unittest.TestCase):
    """The chosen engine is closed as the constructor raises, and its error kept."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.path = pathlib.Path(tmp.name) / 'capture.pcap'
        self.path.write_bytes(PCAP)
        #: Every extractor a fake engine was built for, in order.
        self.extractors = []  # type: list[Any]

    def engine(self, fail_in: 'str', close_raises: 'bool', calls: 'list[str]',
               original: 'BaseException') -> 'type':
        """A fake engine raising ``original`` in ``fail_in``, recording into ``calls``.

        Its ``run`` swaps in a flow tracer whose ``finish`` is recorded as well,
        and keeps the extractor in :attr:`extractors` for the test to inspect.

        """
        # pylint: disable=import-outside-toplevel
        from pcapkit.foundation.engines.engine import EngineBase
        from pcapkit.utilities.exceptions import UnsupportedCall

        extractors = self.extractors

        class Raising(EngineBase):
            name = 'raising'
            module = 'raising'

            def run(self) -> None:
                extractors.append(self._extractor)
                self._extractor._trace = fake_trace(calls)  # type: ignore[assignment]  # pylint: disable=protected-access
                if fail_in == 'run':
                    raise original

            def read_frame(self) -> None:
                raise original

            def close(self) -> None:
                calls.append('close')
                if close_raises:
                    raise UnsupportedCall('close failed')

        return Raising

    @staticmethod
    def selecting(engine: 'type') -> 'Callable[[Any], type]':
        """A stand-in for ``Extractor._select_engine`` that picks ``engine``.

        It leaves the pcap backend probe behind as the real method does, which
        ``run`` enters around the engine's constructor (#2113).

        """
        from pcapkit.foundation.engines import _pcap_backend  # pylint: disable=import-outside-toplevel

        def select_engine(extractor: 'Any') -> 'type':
            extractor._exprb = _pcap_backend.Memo()  # pylint: disable=protected-access
            return engine

        return select_engine

    @staticmethod
    def recording_open() -> 'tuple[list[io.BufferedReader], Callable[..., io.BufferedReader]]':
        """An :func:`open` that records the handles it returns."""
        handles = []  # type: list[io.BufferedReader]

        def recording_open(*args: 'Any', **kwargs: 'Any') -> 'io.BufferedReader':
            handle = builtins.open(*args, **kwargs)  # pylint: disable=consider-using-with,unspecified-encoding
            handles.append(handle)
            return handle

        return handles, recording_open

    def trace_kwargs(self) -> 'dict[str, Any]':
        """Arguments enabling TCP flow tracing, writing under the test's own directory."""
        return {'trace': True, 'tcp': True, 'trace_format': 'json',
                'trace_fout': str(self.path.parent / 'trace')}

    def extract(self, fail_in: 'str', close_raises: 'bool' = False, **kwargs: 'Any'
                ) -> 'tuple[BaseException, BaseException, list[str], list[io.BufferedReader]]':
        """Extract with a fake engine raising in ``fail_in``; return what happened."""
        # pylint: disable=import-outside-toplevel
        import pcapkit.foundation.extraction as extraction
        from pcapkit.utilities.exceptions import FormatError

        original = FormatError(f'raised in {fail_in}')
        calls = []  # type: list[str]
        engine = self.engine(fail_in, close_raises, calls, original)
        handles, recording_open = self.recording_open()

        with mock.patch.object(extraction.Extractor, '_select_engine', self.selecting(engine)), \
                mock.patch.object(extraction, 'open', recording_open, create=True), \
                warnings.catch_warnings(), self.assertRaises(FormatError) as caught:
            warnings.simplefilter('ignore')
            extraction.Extractor(fin=str(self.path), nofile=True, **kwargs)
        return original, caught.exception, calls, handles

    def test_a_raising_run_closes_the_engine_and_keeps_its_error(self) -> None:
        original, raised, calls, handles = self.extract('run')
        self.assertIs(raised, original)
        self.assertEqual(calls, ['close'])
        self.assertEqual(len(handles), 1)
        self.assertTrue(handles[0].closed)

    def test_a_raising_read_frame_closes_the_engine_and_keeps_its_error(self) -> None:
        original, raised, calls, handles = self.extract('read_frame')
        self.assertIs(raised, original)
        self.assertEqual(calls, ['close'])
        self.assertTrue(handles[0].closed)

    def test_a_raising_close_does_not_replace_the_original_error(self) -> None:
        original, raised, calls, handles = self.extract('run', close_raises=True)
        self.assertIs(raised, original)
        self.assertIsNone(raised.__context__)
        self.assertEqual(calls, ['close'])
        self.assertTrue(handles[0].closed)

    def test_a_failed_constructor_does_not_finish_the_trace(self) -> None:
        for fail_in in ('run', 'read_frame'):
            with self.subTest(fail_in=fail_in):
                self.extractors.clear()
                original, raised, calls, handles = self.extract(fail_in, **self.trace_kwargs())
                self.assertIs(raised, original)
                self.assertEqual(calls, ['close'], 'the trace was finished, or the engine left open')
                self.assertTrue(handles[0].closed)
                self.assertFalse(self.extractors[0]._flag_e)  # pylint: disable=protected-access

    def test_an_unknown_format_cleans_up_without_an_engine(self) -> None:
        # pylint: disable=import-outside-toplevel
        import pcapkit.foundation.extraction as extraction
        from pcapkit.utilities.exceptions import FormatError

        self.path.write_bytes(bytes(24))
        handles, recording_open = self.recording_open()
        cleanup = extraction.Extractor._cleanup  # pylint: disable=protected-access
        with mock.patch.object(extraction.Extractor, '_cleanup', autospec=True,
                               side_effect=cleanup) as spy, \
                mock.patch.object(extraction, 'open', recording_open, create=True), \
                warnings.catch_warnings(), self.assertRaises(FormatError) as caught:
            warnings.simplefilter('ignore')
            extraction.Extractor(fin=str(self.path), nofile=True, **self.trace_kwargs())

        self.assertIn('unknown file format', str(caught.exception))
        self.assertEqual(spy.call_count, 1)
        self.assertEqual(spy.call_args.kwargs, {'failed': True})
        self.assertNotIn('_exeng', vars(spy.call_args.args[0]))
        self.assertTrue(handles[0].closed)

    def test_failed_cleanup_with_no_engine_closes_only_the_input(self) -> None:
        import pcapkit.foundation.extraction as extraction  # pylint: disable=import-outside-toplevel

        calls = []  # type: list[str]
        extractor = extraction.Extractor.__new__(extraction.Extractor)
        handle = builtins.open(self.path, 'rb')  # pylint: disable=consider-using-with
        self.addCleanup(handle.close)
        vars(extractor).update(
            _ifile=handle, _ifnm=str(self.path), _flag_s=True, _flag_e=False, _flag_t=True,
            _tcp=True, _frnum=0, _finalizer=None, _trace=fake_trace(calls),
        )

        extractor._cleanup(failed=True)  # pylint: disable=protected-access
        self.assertTrue(handle.closed)
        self.assertEqual(calls, [])
        self.assertFalse(extractor._flag_e)  # pylint: disable=protected-access
        extractor._cleanup(failed=True)  # a second call is safe  # pylint: disable=protected-access

    def test_exit_closes_through_the_shared_path(self) -> None:
        # pylint: disable=import-outside-toplevel
        import pcapkit.foundation.extraction as extraction
        from pcapkit.utilities.exceptions import FormatError, UnsupportedCall

        release = extraction.Extractor._release  # pylint: disable=protected-access
        for close_raises in (False, True):
            with self.subTest(close_raises=close_raises):
                calls = []  # type: list[str]
                engine = self.engine('nowhere', close_raises, calls, FormatError('unused'))
                handles, recording_open = self.recording_open()
                with mock.patch.object(extraction.Extractor, '_select_engine', self.selecting(engine)), \
                        mock.patch.object(extraction.Extractor, '_release', autospec=True,
                                          side_effect=release) as spy, \
                        mock.patch.object(extraction, 'open', recording_open, create=True), \
                        warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    extractor: Any = extraction.Extractor(fin=str(self.path), nofile=True, auto=False,
                                                          **self.trace_kwargs())
                    if close_raises:
                        # ``__exit__`` lets the close's error out, as it always has.
                        with self.assertRaises(UnsupportedCall), extractor:
                            pass
                    else:
                        with extractor:
                            pass

                spy.assert_called_once_with(extractor)
                self.assertEqual(calls, ['close'], '__exit__ finished the trace, or left the engine open')
                self.assertTrue(handles[0].closed)
                self.assertFalse(extractor._flag_e)  # pylint: disable=protected-access

    @unittest.skipUnless(HAS_PYSHARK, 'pyshark is not installed')
    def test_pyshark_close_before_run_is_a_no_op(self) -> None:
        from pcapkit.foundation.engines.pyshark import PyShark  # pylint: disable=import-outside-toplevel

        engine = PyShark(mock.sentinel.extractor)
        engine.close()
        engine.close()


if __name__ == '__main__':
    unittest.main()
