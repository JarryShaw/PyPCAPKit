from __future__ import annotations

import importlib.util
from ipaddress import ip_address
import pathlib
import tempfile
import unittest

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TCPTraceFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _packet(self, *, index: int, src: str = '192.0.2.1', dst: str = '198.51.100.2',
                srcport: int = 12345, dstport: int = 443, syn: bool = False,
                fin: bool = False, timestamp: float = 1.25, frame: object | None = None):
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.traceflow.data.tcp import Packet

        if frame is None:
            frame = {'frame': index}
        return Packet(LinkType.ETHERNET, index, frame, syn, fin, ip_address(src), ip_address(dst),
                      srcport, dstport, timestamp)

    def test_tcp_trace_ipv4_fin_submit_cache_callback_and_dump(self) -> None:
        from pcapkit.dumpkit.null import NotImplementedIO
        from pcapkit.foundation.traceflow.tcp import TCP

        TCP.register_dumper('unit-null', NotImplementedIO, '.unit')
        callbacks = []
        TCP.register_callback(callbacks.append)

        with tempfile.TemporaryDirectory() as tempdir:
            trace = TCP(tempdir, 'unit-null')
            first = self._packet(index=1, syn=True)
            label = trace.trace(first)
            self.assertEqual(label, '192.0.2.1_12345-198.51.100.2_443-1.25')
            self.assertEqual(trace.index[0].index, (1,))
            self.assertIs(trace.submit(), trace.submit())

            output = trace.trace(self._packet(index=2, timestamp=1.5), output=True)
            self.assertIsInstance(output, NotImplementedIO)

            trace.dump(self._packet(index=3, timestamp=1.75, frame={'payload': 'dumped'}))
            finished_output = trace.trace(self._packet(index=4, fin=True, timestamp=2.0), output=True)
            self.assertIsInstance(finished_output, NotImplementedIO)

            final_index, = trace.index
            self.assertEqual(final_index.index, (1, 2, 3, 4))
            self.assertEqual(final_index.label, label)
            self.assertEqual(final_index.fpout, f'{tempdir}/{label}.unit')
            self.assertEqual(callbacks[-1], final_index)

    def test_tcp_trace_ipv6_label_and_no_extension_output_path(self) -> None:
        from pcapkit.foundation.traceflow.tcp import TCP

        with tempfile.TemporaryDirectory() as tempdir:
            trace = TCP(tempdir, 'unknown-unit-format')
            packet = self._packet(index=1, src='2001:db8::1', dst='2001:db8::2',
                                  timestamp=3.5)
            label = trace.trace(packet)
            self.assertNotIn(':', label)
            self.assertIn('2001.db8..1_12345-2001.db8..2_443-3.5', label)

            finished = self._packet(index=2, src='2001:db8::1', dst='2001:db8::2',
                                    fin=True, timestamp=4.0)
            trace.trace(finished)
            final_index, = trace.index
            self.assertIsNone(final_index.fpout)
            self.assertEqual(final_index.index, (1, 2))
            self.assertFalse(pathlib.Path(tempdir, f'{label}.None').exists())


if __name__ == '__main__':
    unittest.main()
