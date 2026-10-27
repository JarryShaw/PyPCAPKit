# -*- coding: utf-8 -*-
"""Reassembly, trace, engine-fallback and output-format messages in the house form. C.f. #2303.

Every rejection message here is lowercase and quotes the rejected value with
:func:`repr`, and every engine fallback is worded ``using default engine
instead``. Guards against :func:`~pcapkit.interface.core.reassemble` and
:func:`~pcapkit.interface.core.trace` raising a capitalised
``Unsupported ... protocol: foo``; against
:func:`~pcapkit.interface.misc.follow_tcp_stream` wording its engine fallback
otherwise than :class:`~pcapkit.foundation.extraction.Extractor` does, or
naming the engine it has no reassembly adapter for unquoted; and against
:meth:`Extractor.make_name
<pcapkit.foundation.extraction.Extractor.make_name>` and
:meth:`TraceFlowBase.make_fout
<pcapkit.foundation.traceflow.traceflow.TraceFlowBase.make_fout>` leaving the
rejected format bare -- which for the empty format ends the message at the
colon with nothing after it. Each message is pinned whole.

"""

import os
import tempfile
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class, sample_path


class TestMessageForm(unittest.TestCase):
    """Each message is lowercase and quotes the rejected value with :func:`repr`."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_reassemble_unsupported_protocol(self) -> None:
        from pcapkit.interface.core import reassemble
        from pcapkit.utilities.exceptions import FormatError

        with self.assertRaises(FormatError) as context:
            reassemble('foo')
        self.assertEqual(str(context.exception), "unsupported reassembly protocol: 'foo'")

    def test_trace_unsupported_protocol(self) -> None:
        from pcapkit.interface.core import trace
        from pcapkit.utilities.exceptions import FormatError

        with self.assertRaises(FormatError) as context:
            trace('foo', fout=None, format=None)
        self.assertEqual(str(context.exception), "unsupported flow tracing protocol: 'foo'")

    def test_follow_tcp_stream_engine_fallback(self) -> None:
        from pcapkit.interface.misc import follow_tcp_stream
        from pcapkit.utilities.warnings import EngineWarning

        with tempfile.TemporaryDirectory() as tmp, warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            follow_tcp_stream(fin=sample_path('in.pcap'), fout=tmp, engine='pyshark')
        self.assertEqual([str(w.message) for w in caught if issubclass(w.category, EngineWarning)],
                         ["unsupported extraction engine: 'pyshark'; using default engine instead"])

    def test_follow_tcp_stream_engine_without_a_reassembly_adapter(self) -> None:
        from pcapkit.foundation.engines.engine import Engine
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.interface.misc import follow_tcp_stream
        from pcapkit.utilities.warnings import EngineWarning

        class UnitEngine(Engine[object]):  # no ``engine=``, so not registered here
            __engine_name__ = 'UnitEngine'
            __engine_module__ = __name__

            def run(self) -> 'None':
                pass

            def read_frame(self) -> 'object':
                # ``Extractor.record_frames`` reads until EOF, and
                # ``follow_tcp_stream`` runs the extraction itself, so there is
                # no ``auto=False`` to stop it short of this.
                raise EOFError

        # ``__engine__`` is one global table shared by every engine class, so
        # the registration is rolled back.
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(Extractor.__engine__), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            Extractor.register_engine('unit-engine', UnitEngine)
            streams = follow_tcp_stream(fin=sample_path('in.pcap'), fout=tmp,
                                        engine='unit-engine')
        self.assertEqual(streams, ())
        self.assertEqual([str(w.message) for w in caught if issubclass(w.category, EngineWarning)],
                         ["unsupported extraction engine for TCP stream following: "
                          "'UnitEngine'; returning no streams"])

    def test_extractor_engine_fallback(self) -> None:
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.utilities.warnings import EngineWarning

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            Extractor(fin=sample_path('in.pcap'), nofile=True, store=False, engine='no-such-engine')
        self.assertEqual([str(w.message) for w in caught if issubclass(w.category, EngineWarning)],
                         ["unsupported extraction engine: 'no-such-engine'; using default engine instead"])

    def test_make_name_unknown_output_format(self) -> None:
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.utilities.exceptions import FormatError

        # The only output-format rejection an ``Extractor`` reaches. The
        # ``FormatWarning`` in ``Extractor.__init__`` fires on ``ext is None``,
        # which ``make_name`` -- called earlier in the same constructor, and
        # only when ``nofile=False``, which is also the warning's condition --
        # has already raised on, so that warning is unreachable.
        for fmt, pinned in (('no-such-format', "unknown output format: 'no-such-format'"),
                            ('', "unknown output format: ''")):
            with self.subTest(format=fmt), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(FormatError) as context:
                    Extractor(fin=sample_path('in.pcap'), fout=os.path.join(tmp, 'out'),
                              format=fmt, auto=False)
                self.assertEqual(str(context.exception), pinned)

    def test_make_fout_unsupported_output_format(self) -> None:
        from pcapkit.foundation.traceflow.tcp import TCP
        from pcapkit.utilities.warnings import FormatWarning

        # ``__output__`` is a defaultdict, so the lookup inserts ``'foo'``; put
        # the registry back afterwards.
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(TCP.__output__), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            TCP.make_fout(tmp, 'foo')
        self.assertEqual([str(w.message) for w in caught if issubclass(w.category, FormatWarning)],
                         ["unsupported output format: 'foo'; disabled file output feature"])


if __name__ == '__main__':
    unittest.main()
