# -*- coding: utf-8 -*-
"""A raising flow tracing callback at the end of a capture still releases the input. C.f. #2857.

``Extractor._cleanup`` ran ``TraceFlow.finish()`` before ``_release()``, so a
callback raising from ``finish()`` skipped the release: with ``auto=False`` the
input file the extractor opened stayed open, and its engine unclosed, until
``__exit__`` or collection. Under ``auto=True`` the constructor's own handler
released them. The release runs on that path too, as under ``failed``, so the
callback's error is the one raised.

Every case builds its own octets, written to a temporary file the extractor
opens by path or handed to it as a stream, and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import contextlib
import importlib.util
import io
import os
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import close_extractor, reimport_once_per_class
from tests.foundation._roundtrip import ethernet, ipv4, pcap, tcp

if TYPE_CHECKING:
    from typing import Any, Callable

#: Test tier (#1958): file handles held open and closed on an exception's path,
#: which differ by interpreter.
__tier__ = 'ALL'

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))

SECOND = 1_500_000_000


def capture() -> bytes:
    """A PCAP savefile of one TCP flow, opened by a SYN and never closed, so ``finish()`` ends it."""
    return pcap([(SECOND + number, 0, ethernet(ipv4(tcp(bytes([number]) * 4, seq=1000 * number,
                                                         syn=number == 0), proto=6), 0x0800))
                 for number in range(3)])


def descriptors(path: str) -> int:
    """How many of this process's descriptors resolve to ``path``; ``-1`` where none can be listed."""
    if not os.path.isdir('/proc/self/fd'):
        return -1
    target, count = os.path.realpath(path), 0
    for name in os.listdir('/proc/self/fd'):
        with contextlib.suppress(OSError):
            count += os.readlink(os.path.join('/proc/self/fd', name)) == target
    return count


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class RaisingTraceCallbackReleasesTests(unittest.TestCase):
    """The input and the engine are released whether or not ``finish()`` raises."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.foundation.traceflow.tcp import TCP

        tmpdir = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(tmpdir.cleanup)
        self.root = tmpdir.name
        self.path = os.path.join(self.root, 'flow.pcap')
        with open(self.path, 'wb') as file:
            file.write(capture())

        self.calls = []  # type: list[str]

        def refuse(index: 'Any') -> None:
            self.calls.append(index.label)
            raise RuntimeError('callback refused')

        TCP.register_callback(refuse)
        self.addCleanup(TCP.__callback_fn__.remove, refuse)

    def extractor(self, fin: 'Any' = None, **kwargs: 'Any') -> 'Any':
        """An extractor tracing TCP flows of ``fin``, by default the file at :attr:`path`."""
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.options import TraceFlowOptions

        trace = TraceFlowOptions(protocols=['tcp'], fout=os.path.join(self.root, 'trace'), format='json')
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = Extractor(self.path if fin is None else fin, traceflow=trace, **kwargs)
        self.addCleanup(close_extractor, extractor)
        return extractor

    def drain(self, step: 'Callable[[], Any]') -> None:
        """Call ``step`` until the callback's error ends it, as a caller driving ``auto=False`` does."""
        with warnings.catch_warnings(), self.assertRaisesRegex(RuntimeError, 'callback refused'):
            warnings.simplefilter('ignore')
            while True:
                step()

    def assertReleased(self, extractor: 'Any') -> None:  # pylint: disable=invalid-name
        """The input this extractor opened is closed, by handle and descriptor, and nothing backs it up."""
        self.assertTrue(extractor._ifile.closed)
        self.assertIn(descriptors(self.path), (0, -1))
        self.assertFalse(extractor._finalizer.alive)
        self.assertTrue(extractor._flag_e)

    def test_issue_reproduction(self) -> None:
        """#2857: iterating an ``auto=False`` extractor to the end, the input is closed after the raise."""
        extractor = self.extractor(auto=False)
        self.drain(lambda: next(extractor))
        self.assertEqual(len(self.calls), 1)
        self.assertReleased(extractor)

    def test_call_form_releases_too(self) -> None:
        """``extractor()`` reaches the same cleanup as ``next()``, and releases the same way."""
        extractor = self.extractor(auto=False)
        self.drain(extractor)
        self.assertReleased(extractor)

    def test_engine_is_closed(self) -> None:
        """The engine is closed on that path as well as the input."""
        from pcapkit.foundation.engines.pcap import PCAP

        extractor = self.extractor(auto=False)
        with mock.patch.object(PCAP, 'close', autospec=True, side_effect=PCAP.close) as close:
            self.drain(lambda: next(extractor))
        close.assert_called_once_with(extractor.engine)

    def test_callback_error_outlives_a_raising_engine_close(self) -> None:
        """An engine whose close also raises does not replace the callback's error, nor keep the input."""
        from pcapkit.foundation.engines.pcap import PCAP

        extractor = self.extractor(auto=False)
        with mock.patch.object(PCAP, 'close', side_effect=OSError('engine refused')):
            self.drain(lambda: next(extractor))
        self.assertReleased(extractor)

    def test_callers_stream_stays_open(self) -> None:
        """The release keeps to ownership: the engine is closed, a stream the caller supplied is not."""
        from pcapkit.foundation.engines.pcap import PCAP

        stream = io.BytesIO(capture())
        extractor = self.extractor(stream, auto=False)
        with mock.patch.object(PCAP, 'close', autospec=True, side_effect=PCAP.close) as close:
            self.drain(lambda: next(extractor))
        close.assert_called_once_with(extractor.engine)
        self.assertFalse(stream.closed)
        self.assertEqual(stream.getvalue(), capture())


if __name__ == '__main__':
    unittest.main()
