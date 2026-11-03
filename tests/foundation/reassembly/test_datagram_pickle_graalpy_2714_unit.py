# -*- coding: utf-8 -*-
"""A reassembled datagram pickles under protocol 0 and 1 on GraalPy (#2714).

Below protocol 2, :meth:`object.__reduce_ex__` hands an instance to
``copyreg._reduce_ex``, which walks the class's MRO for the first base that is not a
heap type and calls that base on the instance unless it is :class:`object`. Every
:class:`~pcapkit.corekit.infoclass.Info` derives from :class:`typing.Generic`, a heap
type on CPython, so the walk passes it there. GraalPy builds ``Generic`` as a
built-in, so its walk stops at it and raises ``TypeError: typing.Generic() takes no
arguments``: for a reassembled datagram, the ``DatagramID`` it holds and the
``ReassemblyData`` holding it alike. #2433 routes ``Deferred`` round the walk;
``ReduceAsProtocol2`` routes every ``Info`` round it, by reducing as protocol 2 does.

Pickling does not resolve the deferred ``packet``. A failing subtest's report renders
the datagram with :func:`repr`, which does, so a test pickling one datagram under each
protocol in turn finds it resolved once protocol 0 fails.

GraalPy is not installed here, so the stand-in of
:mod:`tests.utilities.test_pickle_graalpy_2714_unit` replaces ``copyreg._reduce_ex``
with GraalPy's walk, treating ``Generic`` as a built-in.

"""

from __future__ import annotations

import pickle
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class
from tests.foundation.reassembly.test_dtls_handshake_reassembly_2440_unit import (_extract, _frame,
                                                                                  _pcap)
from tests.foundation.reassembly.test_dtls_reassembly_parity_2531_unit import COMPLETE
from tests.foundation.reassembly.test_ip_tcp_analysis_2581_unit import (CONTAINERS, FRAMES,
                                                                        _analysis, _held, _parsed)
from tests.utilities.test_pickle_graalpy_2714_unit import _graalpy_walk

if TYPE_CHECKING:
    from typing import Any, Callable, Iterator

#: Test tier (#1958): pickling, whose protocols differ by interpreter.
__tier__ = 'ALL'


class DatagramPickleTests(unittest.TestCase):
    """Each engine's datagram pickles under every protocol, through GraalPy's walk."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _engines(self) -> 'Iterator[tuple[str, str, Any, Any, Callable[[Any], Any]]]':
        """``(kind, container, datagram, function, value)`` for each engine.

        ``function`` is the engine's analysis function, and ``value`` makes what it
        returns comparable by value.

        """
        from pcapkit.foundation.analysis import dtls_handshake

        for container, write in CONTAINERS:
            for kind, (frames, _) in FRAMES.items():
                extractor = _extract(self, write(frames), reassembly=True, ip=True, tcp=True)
                datagram, = getattr(extractor.reassembly, kind)
                yield kind, container, datagram, _analysis(kind)[0], _parsed
            extractor = _extract(self, write([_frame(record) for record in COMPLETE]),
                                 reassembly=True, dtls=True)
            datagram, = extractor.reassembly.dtls
            yield 'dtls', container, datagram, dtls_handshake, lambda packet: packet

    def test_a_datagram_pickles_under_every_protocol(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Deferred

        for kind, container, datagram, function, value in self._engines():
            held = _held(datagram)
            self.assertIsInstance(held, Deferred)
            expected = value(function(datagram))
            for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
                with self.subTest(kind=kind, container=container, protocol=protocol):
                    with _graalpy_walk():
                        datagram.__reduce_ex__(protocol)
                        copy = pickle.loads(pickle.dumps(datagram, protocol=protocol))
                    self.assertIs(_held(datagram), held)
                    self.assertIsInstance(_held(copy), Deferred)
                    self.assertIs(type(copy.id), type(datagram.id))
                    self.assertEqual(copy.id, datagram.id)
                    self.assertEqual(value(copy.packet), expected)

    def test_the_reassembly_result_pickles_under_every_protocol(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Deferred, ReassemblyData

        reassembly = _extract(self, _pcap(FRAMES['ipv4'][0]), reassembly=True, ip=True).reassembly
        held = _held(reassembly.ipv4[0])
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            with self.subTest(protocol=protocol):
                with _graalpy_walk():
                    copy = pickle.loads(pickle.dumps(reassembly, protocol=protocol))
                self.assertIs(type(copy), ReassemblyData)
                self.assertEqual((len(copy.ipv4), copy.ipv6, copy.tcp, copy.dtls),
                                 (1, reassembly.ipv6, reassembly.tcp, reassembly.dtls))
                self.assertIsInstance(_held(copy.ipv4[0]), Deferred)
                self.assertIs(_held(reassembly.ipv4[0]), held)


if __name__ == '__main__':
    unittest.main()
