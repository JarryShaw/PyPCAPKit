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
        """One direction, traced with ``bidirectional=False``.

        This is the per-direction behaviour flow tracing had before conversations
        became one flow, and it is still reachable on request -- so a single FIN
        closes the flow, since in that mode a flow *is* one direction.

        """
        from pcapkit.dumpkit.null import NotImplementedIO
        from pcapkit.foundation.traceflow.tcp import TCP

        TCP.register_dumper('unit-null', NotImplementedIO, '.unit')
        callbacks = []
        TCP.register_callback(callbacks.append)

        with tempfile.TemporaryDirectory() as tempdir:
            trace = TCP(tempdir, 'unit-null', bidirectional=False)
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
            # every frame is "forward" when a flow is a single direction
            self.assertEqual(final_index.forward, (1, 2, 3, 4))
            self.assertEqual(final_index.reverse, ())

    def _reply(self, **kwargs):
        """A packet travelling the other way down the same connection."""
        return self._packet(src='198.51.100.2', dst='192.0.2.1',
                            srcport=443, dstport=12345, **kwargs)

    def test_both_halves_of_a_connection_are_one_flow(self) -> None:
        """The two directions share a buffer, a label and an output file.

        Keyed on (source, destination) they were two flows with two labels and two
        dump files, leaving a caller to pair them up by reading the labels.

        """
        from pcapkit.dumpkit.null import NotImplementedIO
        from pcapkit.foundation.traceflow.tcp import TCP

        TCP.register_dumper('unit-null', NotImplementedIO, '.unit')

        with tempfile.TemporaryDirectory() as tempdir:
            trace = TCP(tempdir, 'unit-null')

            # the client opens the conversation, so its direction is "forward"
            label = trace.trace(self._packet(index=1, syn=True))
            self.assertEqual(label, '192.0.2.1_12345-198.51.100.2_443-1.25')

            # ... and the server's reply joins that flow rather than minting a
            # label of its own
            self.assertEqual(trace.trace(self._reply(index=2, syn=True, timestamp=1.5)), label)
            self.assertEqual(len(trace._buffer), 1)

            flow, = trace.index
            self.assertEqual(flow.index, (1, 2))
            self.assertEqual(flow.forward, (1,))
            self.assertEqual(flow.reverse, (2,))

    def test_a_conversation_closes_only_once_both_halves_have_finished(self) -> None:
        """One FIN is half a teardown, so it must not close the flow.

        Closing on the first FIN would cut the peer's FIN and the final
        acknowledgement out of the flow -- and they would then open a *second*
        flow under the same buffer ID, which is the split bidirectional tracing
        exists to remove.

        """
        from pcapkit.dumpkit.null import NotImplementedIO
        from pcapkit.foundation.traceflow.tcp import TCP

        TCP.register_dumper('unit-null', NotImplementedIO, '.unit')

        with tempfile.TemporaryDirectory() as tempdir:
            trace = TCP(tempdir, 'unit-null')
            trace.trace(self._packet(index=1, syn=True))
            trace.trace(self._reply(index=2, timestamp=1.5))

            # the client finishes; the server has not
            trace.trace(self._packet(index=3, fin=True, timestamp=1.75))
            self.assertEqual(len(trace._buffer), 1, 'flow closed on a half teardown')
            self.assertEqual(trace._stream, [])

            # a retransmitted FIN from the same endpoint is still one endpoint
            trace.trace(self._packet(index=4, fin=True, timestamp=1.8))
            self.assertEqual(trace._stream, [])

            # now the server finishes too
            trace.trace(self._reply(index=5, fin=True, timestamp=2.0))
            self.assertEqual(len(trace._buffer), 0)
            flow, = trace._stream
            self.assertEqual(flow.index, (1, 2, 3, 4, 5))
            self.assertEqual(flow.forward, (1, 3, 4))
            self.assertEqual(flow.reverse, (2, 5))

    def test_the_buffer_id_is_canonical_and_stays_a_tuple(self) -> None:
        """Both directions reduce to the same key, whichever is seen first.

        The key has to stay a plain :obj:`tuple`: it is a :obj:`dict` key, and an
        :class:`~pcapkit.corekit.infoclass.Info` cannot be one, because inheriting
        :class:`collections.abc.Mapping` sets ``__hash__`` to :data:`None`.

        """
        from pcapkit.foundation.traceflow.tcp import TCP

        with tempfile.TemporaryDirectory() as tempdir:
            trace = TCP(tempdir, 'unknown-unit-format')
            forward = trace.make_bufid(self._packet(index=1))
            reverse = trace.make_bufid(self._reply(index=2))
            self.assertEqual(forward, reverse)
            self.assertIs(type(forward), tuple)
            hash(forward)  # a key that cannot be hashed is not a key

            oneway = TCP(tempdir, 'unknown-unit-format', bidirectional=False)
            self.assertNotEqual(oneway.make_bufid(self._packet(index=1)),
                                oneway.make_bufid(self._reply(index=2)))

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
