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
                fin: bool = False, rst: bool = False, timestamp: float = 1.25,
                frame: object | None = None, seq: int = 0, ack: int = 0,
                payload: bytes = b''):
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.traceflow.data.tcp import Packet

        if frame is None:
            frame = {'frame': index}
        return Packet(LinkType.ETHERNET, index, frame, syn, fin, rst, ip_address(src),
                      ip_address(dst), srcport, dstport, timestamp,
                      seq, ack, b'tcp-header', bytearray(payload))

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

    def test_a_four_way_close_keeps_its_final_acknowledgement(self) -> None:
        """The whole close belongs to the flow, the last ACK included.

        A four-way close is FIN, ACK, FIN, ACK, so the final acknowledgement
        arrives *after* the second FIN. Submitting the flow on the second FIN --
        or, worse, on the first -- drops that ACK from it and lets the ACK open a
        fresh buffer under the same canonical buffer ID, which
        :meth:`test_a_reused_port_pair_does_not_join_the_closed_connection` shows
        a later connection then merges into. So a teardown records itself and
        finalises nothing.

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

            # the server's FIN completes the exchange, but not the conversation:
            # its acknowledgement is still to come, so nothing is finalised yet
            trace.trace(self._reply(index=5, fin=True, timestamp=2.0))
            self.assertEqual(len(trace._buffer), 1)
            self.assertEqual(trace._stream, [])

            # ... and here it is, in the flow where it belongs
            trace.trace(self._packet(index=6, timestamp=2.25))
            # ... as is a duplicate of it, which no rule naming "the last packet
            # of the exchange" could have accommodated
            trace.trace(self._packet(index=7, timestamp=2.5))

            flow, = trace.index
            self.assertEqual(flow.index, (1, 2, 3, 4, 5, 6, 7))
            self.assertEqual(flow.forward, (1, 3, 4, 6, 7))
            self.assertEqual(flow.reverse, (2, 5))

    def test_a_reused_port_pair_does_not_join_the_closed_connection(self) -> None:
        """A new connection on the same endpoints is a second flow.

        This is the defect the review found. With the flow submitted on the second
        FIN, the final ACK arrived after the buffer had been popped and opened a
        stray one-packet buffer under the same canonical buffer ID; the next
        connection to reuse the endpoints then merged into that stray buffer, and
        two unrelated connections came back as one flow.

        A SYN is what proves the previous connection can receive nothing further,
        so it is what finalises the old flow and starts a new one.

        """
        from pcapkit.dumpkit.null import NotImplementedIO
        from pcapkit.foundation.traceflow.tcp import TCP

        TCP.register_dumper('unit-null', NotImplementedIO, '.unit')
        callbacks = []
        TCP.register_callback(callbacks.append)

        with tempfile.TemporaryDirectory() as tempdir:
            trace = TCP(tempdir, 'unit-null')

            # connection one: handshake, data, and a full four-way close
            trace.trace(self._packet(index=1, syn=True, timestamp=1.0))
            trace.trace(self._reply(index=2, syn=True, timestamp=1.1))
            trace.trace(self._packet(index=3, fin=True, timestamp=1.2))
            trace.trace(self._reply(index=4, timestamp=1.3))
            trace.trace(self._reply(index=5, fin=True, timestamp=1.4))
            trace.trace(self._packet(index=6, timestamp=1.5))

            # connection two: the very same address and port pair, reused. Its SYN
            # is what finalises the first flow, so that is where the first flow's
            # callback fires -- carrying the whole conversation, final ACK
            # included, rather than a truncated one.
            fired = len(callbacks)
            trace.trace(self._packet(index=7, syn=True, timestamp=9.0))
            self.assertEqual(len(callbacks), fired + 1)
            self.assertEqual(callbacks[-1].index, (1, 2, 3, 4, 5, 6))

            trace.trace(self._reply(index=8, syn=True, timestamp=9.1))

            # ``finish`` is what Extractor._cleanup calls at the end of a capture;
            # after it every flow has been finalised, so ``index`` reports them in
            # the order they closed rather than open-buffers-first
            trace.finish()
            first, second = trace.index
            self.assertEqual(first.index, (1, 2, 3, 4, 5, 6),
                             'the second connection joined the first')
            self.assertEqual(second.index, (7, 8))
            self.assertNotEqual(first.label, second.label)

    def test_the_peers_syn_ack_joins_the_flow_rather_than_splitting_it(self) -> None:
        """A SYN-ACK carries SYN too, and must not be read as a new connection.

        Which is why the rule is gated on the teardown having been seen: a SYN-ACK
        cannot arrive after both endpoints have finished, or after a reset. Without
        that gate every connection whose handshake was captured would split in two
        at its second frame.

        """
        from pcapkit.foundation.traceflow.tcp import TCP

        with tempfile.TemporaryDirectory() as tempdir:
            trace = TCP(tempdir, 'unknown-unit-format')
            trace.trace(self._packet(index=1, syn=True, timestamp=1.0))
            trace.trace(self._reply(index=2, syn=True, timestamp=1.1))

            flow, = trace.index
            self.assertEqual(flow.index, (1, 2))

    def test_a_reset_ends_the_connection_as_a_close_does(self) -> None:
        """RST is the other way a connection ends, and was not modelled at all.

        Without the flag reaching the tracer a reset connection looked merely
        idle, so a later connection reusing the endpoints merged into it -- the
        same contamination as the FIN case, by a different route.

        """
        from pcapkit.foundation.traceflow.tcp import TCP

        with tempfile.TemporaryDirectory() as tempdir:
            trace = TCP(tempdir, 'unknown-unit-format')
            trace.trace(self._packet(index=1, syn=True, timestamp=1.0))
            trace.trace(self._reply(index=2, rst=True, timestamp=1.1))

            # the reset is recorded but does not itself finalise the flow
            self.assertEqual(len(trace._buffer), 1)
            bufid, = trace._buffer
            self.assertTrue(trace._buffer[bufid].reset)

            # a new connection on the same endpoints is a second flow
            trace.trace(self._packet(index=3, syn=True, timestamp=9.0))
            trace.finish()
            first, second = trace.index
            self.assertEqual(first.index, (1, 2))
            self.assertEqual(second.index, (3,))

    def test_a_half_open_connection_is_still_reported_at_end_of_capture(self) -> None:
        """A conversation with no teardown must not simply vanish.

        Nothing supersedes it, so ``finish`` -- which
        :meth:`Extractor._cleanup <pcapkit.foundation.extraction.Extractor._cleanup>`
        calls at the end of the capture -- is what finalises it and fires its
        callback. ``submit`` reports it either way, so that reading ``index``
        part-way through a capture is not destructive.

        """
        from pcapkit.foundation.traceflow.tcp import TCP

        callbacks = []
        TCP.register_callback(callbacks.append)

        with tempfile.TemporaryDirectory() as tempdir:
            trace = TCP(tempdir, 'unknown-unit-format')
            trace.trace(self._packet(index=1, syn=True, timestamp=1.0))
            trace.trace(self._reply(index=2, timestamp=1.1))

            # reported, but not finalised -- and reading it changed nothing
            flow, = trace.index
            self.assertEqual(flow.index, (1, 2))
            self.assertEqual(len(trace._buffer), 1)
            self.assertEqual(trace._stream, [])

            before = len(callbacks)
            trace.finish()
            self.assertEqual(len(trace._buffer), 0)
            flow, = trace.index
            self.assertEqual(flow.index, (1, 2))
            self.assertEqual(len(callbacks), before + 1)

            # idempotent: Extractor._cleanup can run twice for one extraction
            trace.finish()
            self.assertEqual(len(callbacks), before + 1)
            self.assertEqual(len(trace.index), 1)

    def test_the_application_layer_is_not_reassembled_unless_asked_for(self) -> None:
        """``analyse`` is off by default, and off means nothing is buffered.

        Reassembling a flow's payload is a cost tracing does not otherwise pay, so
        a caller who only wanted frame numbers must not be charged for it.

        """
        from pcapkit.foundation.traceflow.tcp import TCP

        with tempfile.TemporaryDirectory() as tempdir:
            trace = TCP(tempdir, 'unknown-unit-format')
            trace.trace(self._packet(index=1, syn=True, seq=0))
            trace.trace(self._reply(index=2, timestamp=1.5, seq=0, payload=b'hello'))

            bufid, = trace._buffer
            self.assertIsNone(trace._buffer[bufid].reassembly)

            flow, = trace.index
            self.assertIsNone(flow.packet)

    def test_analyse_gives_a_flow_its_application_layer_per_direction(self) -> None:
        """One reassembled datagram per direction, parsed on demand.

        The tracer does not reassemble the stream itself -- it feeds
        :class:`~pcapkit.foundation.reassembly.tcp.TCP`, which is why the segments
        below are delivered *out of order* and still come back in sequence order.
        A tracer concatenating payloads as they arrived would return ``b'worldhello'``.

        Every segment here carries the default ``ack=0``, which is the *only*
        reason the count is one per direction -- see
        :meth:`test_each_exchange_of_a_multi_round_trip_flow_is_its_own_datagram`
        for what a real, advancing acknowledgement number does.

        """
        from pcapkit.foundation.traceflow.tcp import TCP

        with tempfile.TemporaryDirectory() as tempdir:
            trace = TCP(tempdir, 'unknown-unit-format', analyse=True)

            # client: SYN, then the second half of its request before the first
            trace.trace(self._packet(index=1, syn=True, seq=100))
            trace.trace(self._packet(index=2, seq=106, payload=b'world', timestamp=1.5))
            trace.trace(self._packet(index=3, seq=101, payload=b'hello', timestamp=1.6))
            # server: one reply
            trace.trace(self._reply(index=4, seq=500, payload=b'reply', timestamp=1.7))

            flow, = trace.index
            datagrams = flow.packet
            self.assertIsNotNone(datagrams)
            self.assertEqual(len(datagrams), 2,
                             'one acknowledgement number each way, so one datagram each way')

            payloads = {dgram.id.src[1]: bytes(dgram.payload) for dgram in datagrams}
            # sequence order, not arrival order -- this is the reassembler's work
            self.assertEqual(payloads[12345], b'helloworld')
            self.assertEqual(payloads[443], b'reply')

    def test_each_exchange_of_a_multi_round_trip_flow_is_its_own_datagram(self) -> None:
        """A direction yields one datagram per acknowledgement number, not one total.

        The reassembler buckets as ``self._buffer[BUFID].ack[ACK]`` and emits one
        datagram per bucket, and :meth:`~pcapkit.foundation.traceflow.tcp.TCP._make_segment`
        passes ``ack`` through untouched. So the count follows the *conversation*:
        the acknowledgement number advances exactly when the peer has spoken, which
        splits each direction at its message boundaries and leaves every datagram's
        payload one application message that can be parsed on its own.

        Pinned because the sibling test above holds ``ack`` at its default of zero
        throughout, and so cannot see this: it is the one shape in which "one
        datagram per direction" is the whole truth.

        """
        from pcapkit.foundation.traceflow.tcp import TCP

        with tempfile.TemporaryDirectory() as tempdir:
            trace = TCP(tempdir, 'unknown-unit-format', analyse=True)

            # three request/response round trips on one connection, with the
            # acknowledgement number advancing as it does on any real exchange
            trace.trace(self._packet(index=1, syn=True, seq=100, ack=0))
            trace.trace(self._reply(index=2, syn=True, seq=500, ack=101, timestamp=1.3))
            trace.trace(self._packet(index=3, seq=101, ack=501, timestamp=1.4))
            trace.trace(self._packet(index=4, seq=101, ack=501, payload=b'req1', timestamp=1.5))
            trace.trace(self._reply(index=5, seq=501, ack=105, payload=b'resp1', timestamp=1.6))
            trace.trace(self._packet(index=6, seq=105, ack=506, payload=b'req2', timestamp=1.7))
            trace.trace(self._reply(index=7, seq=506, ack=109, payload=b'resp2', timestamp=1.8))
            trace.trace(self._packet(index=8, seq=109, ack=511, payload=b'req3', timestamp=1.9))
            trace.trace(self._reply(index=9, seq=511, ack=113, payload=b'resp3', timestamp=2.0))

            flow, = trace.index
            datagrams = flow.packet
            self.assertIsNotNone(datagrams)
            self.assertEqual(len(datagrams), 6,
                             'three exchanges each way, one datagram per exchange')

            # keyed by (source port, acknowledgement number), which is what the
            # reassembler buckets on
            got = {(dgram.id.src[1], dgram.id.ack): bytes(dgram.payload)
                   for dgram in datagrams}
            self.assertEqual(got, {
                (12345, 501): b'req1',
                (12345, 506): b'req2',
                (12345, 511): b'req3',
                (443, 105): b'resp1',
                (443, 109): b'resp2',
                (443, 113): b'resp3',
            })

            # the payload-free handshake and bare acknowledgement raise no datagram
            # of their own -- they fill no hole, so no bucket of theirs is emitted
            self.assertNotIn((12345, 0), got)
            self.assertNotIn((443, 101), got)

    def test_an_open_flows_application_layer_is_a_snapshot_of_when_it_was_read(self) -> None:
        """Reading ``packet`` on an open flow freezes it there.

        :meth:`~pcapkit.foundation.traceflow.tcp.TCP.submit` deliberately reports
        open flows without finalising them, and the
        :class:`~pcapkit.foundation.traceflow.data.data.Deferred` resolves on first
        read and is then fixed in place. So an :class:`Index` a caller kept from a
        mid-capture read cannot see segments that arrived afterwards, and nothing on
        it says so -- which is why the docstring tells callers to read after
        :meth:`~pcapkit.foundation.traceflow.tcp.TCP.finish` for a final result.

        """
        from pcapkit.foundation.traceflow.tcp import TCP

        with tempfile.TemporaryDirectory() as tempdir:
            trace = TCP(tempdir, 'unknown-unit-format', analyse=True)
            trace.trace(self._packet(index=1, syn=True, seq=100))
            trace.trace(self._packet(index=2, seq=101, payload=b'first', timestamp=1.5))

            held, = trace.index          # a caller keeping a mid-capture Index
            resolved = held.packet       # ... and resolving its Deferred here
            self.assertEqual([bytes(dgram.payload) for dgram in resolved], [b'first'])

            # the rest of the conversation reaches the buffer, but not the snapshot
            trace.trace(self._packet(index=3, seq=106, payload=b'second', timestamp=1.6))
            self.assertIs(held.packet, resolved,
                          'the resolved snapshot was rebuilt behind the caller')
            self.assertEqual([bytes(dgram.payload) for dgram in held.packet], [b'first'])

            # a fresh read does see it, because trace() cleared the submit cache
            trace.finish()
            final, = trace.index
            self.assertEqual([bytes(dgram.payload) for dgram in final.packet],
                             [b'firstsecond'])

    def test_the_application_layer_is_reassembled_only_on_first_read(self) -> None:
        """``Index.packet`` holds a :class:`Deferred` until somebody reads it.

        The same postponement reassembly uses for
        :attr:`Datagram.packet <pcapkit.foundation.reassembly.data.tcp.Datagram.packet>`,
        one layer out: the flow defers its *reassembly*, and each datagram then
        defers its own *parse*.

        """
        from pcapkit.foundation.traceflow.data.data import Deferred
        from pcapkit.foundation.traceflow.tcp import TCP

        with tempfile.TemporaryDirectory() as tempdir:
            trace = TCP(tempdir, 'unknown-unit-format', analyse=True)
            trace.trace(self._packet(index=1, syn=True, seq=100))
            trace.trace(self._packet(index=2, seq=101, payload=b'hello', timestamp=1.5))

            flow, = trace.index
            key = flow.__map__.get('packet', 'packet')
            self.assertIsInstance(flow.__dict__[key], Deferred,
                                  'the flow was reassembled before anyone asked')

            first = flow.packet
            # resolved in place, so a second read is the same object rather than a
            # second reassembly
            self.assertNotIsInstance(flow.__dict__[key], Deferred)
            self.assertIs(flow.packet, first)

            # and the mapping views report it under its own name, resolved
            self.assertIn('packet', flow)
            self.assertIs(flow.to_dict()['packet'], first)
            self.assertIs(flow['packet'], first)

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
