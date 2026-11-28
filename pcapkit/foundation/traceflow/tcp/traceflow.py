# -*- coding: utf-8 -*-
# pylint: disable=import-outside-toplevel
"""Follow TCP Streams
========================

.. module:: pcapkit.foundation.traceflow.tcp.traceflow

:mod:`pcapkit.foundation.traceflow.tcp.traceflow` is the interface to trace
TCP flows from a series of packets and connections.

"""
from typing import TYPE_CHECKING, Generic, overload

from pcapkit.foundation.traceflow.data import Deferred
from pcapkit.foundation.traceflow.tcp.data import _AT, Buffer, BufferID, Index, Packet
from pcapkit.foundation.traceflow.traceflow import TraceFlowBase
from pcapkit.protocols.transport.tcp.protocol import TCP as TCP_Protocol
from pcapkit.utilities.logging import get_logger

__all__ = ['TCP']

if TYPE_CHECKING:
    from typing import Any, Optional

    from dictdumper.dumper import Dumper
    from typing_extensions import Literal

    from pcapkit.foundation.reassembly.tcp.reassembly import TCP as TCP_Reassembly

#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)


class TCP(TraceFlowBase[BufferID, Buffer[_AT], Index, Packet[_AT]], Generic[_AT]):
    """Trace TCP flows.

    Args:
        fout: output path
        format: output format
        byteorder: output file byte order
        nanosecond: output nanosecond-resolution file flag
        bidirectional: trace both halves of a conversation as one flow
        analyze: reassemble each flow's application layer, so that
            :attr:`Index.packet <pcapkit.foundation.traceflow.tcp.data.Index.packet>`
            can be read

    Note:
        A TCP connection has two halves, and by default they are traced as **one
        flow** -- which is what "following a TCP stream" means everywhere else,
        and what this module's own title claims to do. Keying a flow on
        (source, destination) instead would put a client's packets and the
        server's replies in separate flows, separate labels and separate output
        files, leaving a caller to pair them up by inspecting the labels.

        This has consequences worth knowing:

        * The reverse half of a conversation does not produce a flow of its
          own, so a capture of *n* connections yields *n* flows rather than
          ``2n``, and one output file each rather than two.
        * **A teardown does not end a flow.** Seeing a connection close is not the
          same as knowing nothing more will arrive on its endpoints: the four-way
          close of :rfc:`9293#section-3.6` is FIN, ACK, FIN, ACK, so the
          acknowledgement that completes it follows the second FIN, and duplicates
          of that acknowledgement can follow in turn. A flow is therefore
          finalised only by proof that no more of it can come -- a new
          connection's SYN on the same endpoints, or the end of the capture
          (:meth:`finish`) -- or, given a ``timeout``, once it has been idle that
          long (:meth:`~pcapkit.foundation.traceflow.traceflow.TraceFlow.advance`).
          What the teardown does is get *recorded*, which is how that SYN is told
          from the peer's SYN-ACK; see :meth:`_ended`.

          Finalising a flow is also when its callbacks run, so they run against
          the whole conversation rather than a truncated one.

        Pass ``bidirectional=False`` to trace each direction as a flow of its
        own, finalised on that direction's FIN. That mode ignores RST.

    Note:
        With ``analyze=True`` a flow also carries its **application layer**:
        :attr:`Index.packet <pcapkit.foundation.traceflow.tcp.data.Index.packet>`
        holds the flow's reassembled datagrams, each with its payload parsed on
        demand. The tracer does not reassemble the stream itself -- it feeds
        :class:`~pcapkit.foundation.reassembly.tcp.reassembly.TCP`, which already implements
        :rfc:`815` and copes with the reordering and retransmission that a tracer
        concatenating payloads in capture order would silently corrupt.

        How many datagrams that is follows from the reassembler's own notion of a
        datagram, which is **per direction and per acknowledgement number**: it
        buckets as ``self._buffer[BUFID].ack[ACK]`` and emits one datagram per
        bucket. Since :meth:`_make_segment` passes each segment's ``ack`` through
        untouched, a direction yields one datagram per distinct acknowledgement
        number it carried -- not one datagram per direction. Three request/response
        round trips on one connection therefore give **six** datagrams, three each
        way, one per exchange:

        .. code-block:: text

           src=12345  ack=501  payload=b'req1'    src=443  ack=105  payload=b'resp1'
           src=12345  ack=506  payload=b'req2'    src=443  ack=109  payload=b'resp2'
           src=12345  ack=511  payload=b'req3'    src=443  ack=113  payload=b'resp3'

        That is deliberate rather than incidental: the acknowledgement number
        advances exactly when the peer has spoken, so bucketing on it splits a
        direction wherever the other end got a word in -- one datagram per
        **exchange**. Merging a whole direction into one stream would instead hand
        the application parser every message it ever sent, concatenated, and have
        it read only the first.

        Be precise about what that does and does not buy, though, because the
        boundary is the peer's turn and **not** the application's message
        boundary. Where an exchange is one request and one reply, the two coincide
        and each datagram's payload is a single message that
        :attr:`Datagram.packet
        <pcapkit.foundation.reassembly.tcp.data.Datagram.packet>` can parse alone.
        Where a sender **pipelines** -- several requests in flight before any reply
        -- they all carry the same acknowledgement number, so they share a bucket
        and are concatenated after all, as
        ``test_pipelined_sends_share_a_datagram_because_the_ack_never_moved`` in
        :file:`tests/foundation/traceflow/test_tcp.py` pins. So this narrows the
        concatenation to within one exchange rather than eliminating it, and an
        application parser handed a pipelined datagram still sees only the first
        message.

        A direction that carried one acknowledgement number throughout -- a single
        request and its reply, which is what most of the unit tests exercise --
        does collapse to one datagram each way, which is where "one per direction"
        holds.

        It is **off by default** because buffering every traced payload is a cost
        tracing does not otherwise pay, and tracing's per-packet cost is something
        this package deliberately keeps low. Nothing is reassembled, parsed
        or retained unless it is asked for.

    .. versionchanged:: 1.8.0

       With ``analyze=True``, a datagram's payload is parsed with the ``layer``,
       ``protocol`` and ``context`` of a :term:`default engine` extraction feeding
       the tracer, as TCP reassembly's are, where it was parsed with none of them
       (:issue:`2946`).

    """

    if TYPE_CHECKING:
        #: The reassembly segment model, imported on the first flow that needs it
        #: and cached so that :meth:`_make_segment` does not import per packet. Set
        #: only when ``analyze`` is on, which is the only time it is read.
        _reasm_packet: 'type[Any]'

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Protocol name of current flow tracing object.
    __protocol_name__ = 'TCP'
    #: Protocol of current flow tracing object.
    __protocol_type__ = TCP_Protocol

    ##########################################################################
    # Methods.
    ##########################################################################

    def dump(self, packet: 'Packet[_AT]') -> 'None':
        """Dump frame to output files.

        Arguments:
            packet: a flow packet (:term:`trace.tcp.packet`)

        The flow's output file is kept open for its next frame, as
        :meth:`~pcapkit.foundation.traceflow.traceflow.TraceFlow._write`
        describes, unless the frame ends the flow. Such a frame is written
        before the flow is finalised, so its callbacks find every frame its index
        entry lists in the file.

        """
        bufid, ends = self._record(packet)
        self._write(self._buffer[bufid].fpout, packet.frame, f'Frame {packet.index}', hold=not ends)
        if ends:
            self._finalise(bufid)

    @overload
    def trace(self, packet: 'Packet[_AT]', *, output: 'Literal[True]' = ...) -> 'Dumper': ...
    @overload
    def trace(self, packet: 'Packet[_AT]', *, output: 'Literal[False]' = ...) -> 'str': ...

    def trace(self, packet: 'Packet[_AT]', *, output: 'bool' = False) -> 'Dumper | str':
        """Trace packets.

        Arguments:
            packet: a flow packet (:term:`trace.tcp.packet`)
            output: flag if has formatted dumper

        Returns:
            If ``output`` is :data:`True`, returns the initiated
            :class:`~dictdumper.dumper.Dumper` object, which will dump data to
            the output file named after the flow label; otherwise, returns the
            flow label itself.

        Notes:
            The flow label is formatted as following, as
            :meth:`~pcapkit.foundation.traceflow.traceflow.TraceFlow._make_label`
            builds it from the packet that **opened** the flow:

            .. code-block:: python

               f'{packet.src}_{packet.srcport}-{packet.dst}_{packet.dstport}-{packet.timestamp}'

        """
        bufid, ends = self._record(packet)
        buffer = self._buffer[bufid]
        if ends:
            self._finalise(bufid)
        return buffer.fpout if output else buffer.label

    def finish(self) -> 'None':
        """Finalise every flow still being traced.

        The end of the capture can prove a bidirectional flow is over, as a new
        connection on the same endpoints can. Draining the buffer here is what lets a flow keep the
        acknowledgement that completes its close and *still* have its callback
        fired, rather than having to choose between the two.

        Idempotent: it drains the buffer, so a second call finds nothing to do.
        It also closes every output file still kept open, as
        :meth:`TraceFlow.finish <pcapkit.foundation.traceflow.traceflow.TraceFlow.finish>`
        does, even when a callback raises: the flow it was handed is finalised,
        and the flows after it stay in the buffer, unfinalised, for a later call.

        """
        try:
            for bufid in list(self._buffer):
                self._finalise(bufid)
        finally:
            self.__cached__['submit'] = None
            super().finish()

    def submit(self) -> 'tuple[Index, ...]':
        """Submit traced TCP flows.

        Returns:
            Traced TCP flow (:term:`trace.tcp.index`).

        Note:
            This reports flows still being traced **without** finalising them, so
            that reading
            :attr:`TraceFlow.index <pcapkit.foundation.traceflow.traceflow.TraceFlow.index>`
            part-way through a capture cannot disturb the tracing -- popping a
            buffer there would strand the rest of its conversation in a second
            flow. Such a flow is therefore reported here but has not fired its
            callback; :meth:`finish` is what does that, at the end of the capture.

            With ``analyze=True`` that makes an open flow's
            :attr:`Index.packet <pcapkit.foundation.traceflow.tcp.data.Index.packet>`
            a **snapshot**, and a mid-capture one. The
            :class:`~pcapkit.foundation.traceflow.data.Deferred` resolves when
            it is first read and is then fixed in place, so it holds the flow as it
            stood at *that read* -- not as it stood when this method returned, and
            not as it will stand once the conversation ends. Read it while the flow
            is open and the datagrams cover only the segments seen so far; segments
            arriving afterwards are reassembled into the buffer but cannot reach an
            already-resolved snapshot, and nothing on the returned
            :class:`~pcapkit.foundation.traceflow.tcp.data.Index`
            distinguishes one from the final result that :meth:`finish` produces.

            This call's own cache is not the cause and does not soften it: both
            :meth:`trace` and :meth:`finish` clear ``__cached__['submit']``, so a
            later call rebuilds the tuple with fresh
            :class:`~pcapkit.foundation.traceflow.data.Deferred` objects. It is
            the *previously returned*
            :class:`~pcapkit.foundation.traceflow.tcp.data.Index`, if a caller kept
            one, that cannot catch up. For a result that is final, read after
            :meth:`finish`.

        """
        if (cached := self.__cached__.get('submit')) is not None:
            return cached

        ret_submit = (*map(self._make_index, self._buffer.values()), *self._stream)

        logger.debug('submitted %d TCP flow(s), %d still open',
                     len(ret_submit), len(self._buffer))

        self.__cached__['submit'] = ret_submit
        return ret_submit

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _record(self, packet: 'Packet[_AT]') -> 'tuple[BufferID, bool]':
        """Record a packet in its flow, opening the flow or superseding an ended one.

        Arguments:
            packet: a flow packet (:term:`trace.tcp.packet`)

        Returns:
            The flow's buffer ID, and whether the packet ends the flow, which
            :meth:`trace` then finalises at once and :meth:`dump` once the frame
            is written (:issue:`2855`).

        """
        # clear cache
        self.__cached__['submit'] = None
        # time out the flows this packet's timestamp leaves idle, its own included
        self.advance(packet.timestamp)

        # Buffer Identifier -- canonical, hence direction-independent, when
        # tracing bidirectionally
        BUFID = self.make_bufid(packet)
        SYN = packet.syn  # Synchronise Flag (Establishment)
        FIN = packet.fin  # Finish Flag (Termination)
        RST = packet.rst  # Reset Flag (Abrupt Termination)
        # the half of the conversation this packet was sent by
        END = (packet.src, packet.srcport)  # type: tuple[_AT, int]

        # A SYN arriving on a flow whose teardown has already been observed is a
        # *new* connection reusing the endpoints, and the only signal that proves
        # the previous one can receive nothing further. It is what finalises a
        # bidirectional flow mid-capture; everything else is finalised by
        # :meth:`finish` at the end of the capture.
        #
        # The state test matters. A SYN alone does not mean "new connection" --
        # the peer's SYN-ACK carries the flag too, and it belongs to the flow the
        # client's SYN just opened. Gating on the teardown having been seen tells
        # the two apart without needing the ACK flag: a SYN-ACK cannot arrive
        # after both endpoints have finished, or after a reset.
        if self._bidir and BUFID in self._buffer and SYN and self._ended(self._buffer[BUFID]):
            logger.debug('TCP flow %s superseded by a new connection on the same endpoints',
                         self._buffer[BUFID].label)
            self._finalise(BUFID)

        # initialise buffer with BUFID
        if BUFID not in self._buffer:
            label = self._make_label(packet)
            logger.debug('new TCP flow %s', label)
            self._buffer[BUFID] = Buffer(
                fpout=self._make_fpout(label, packet.protocol),
                index=[],
                label=label,
                origin=END,
                forward=[],
                reverse=[],
                fin=set(),
                reset=False,
                reassembly=self._make_reassembly(),
            )

        # trace frame record
        buffer = self._buffer[BUFID]
        self._append(buffer, packet)
        self._touch(BUFID, packet.timestamp)
        if FIN:
            buffer.fin.add(END)
        if RST:
            buffer.__update__(reset=True)
        if buffer.reassembly is not None:
            buffer.reassembly(self._make_segment(packet))

        # A *unidirectional* flow is one direction, and a direction is over when
        # its FIN goes out -- so that mode closes on FIN.
        #
        # A bidirectional flow is a whole connection, and observing its teardown
        # is not the same as knowing nothing more will arrive. The four-way close
        # is FIN, ACK, FIN, ACK: the final acknowledgement comes *after* the
        # second FIN, so submitting on the second FIN drops it from the flow and
        # lets it open a fresh buffer under the same canonical buffer ID -- which
        # a later connection reusing those endpoints then merges into. Closing on
        # the *first* FIN has the same defect one packet earlier, and duplicate
        # acknowledgements after the close would defeat any rule that tries to
        # name the last packet of the exchange.
        #
        # So a teardown does not close the flow here at all: it is recorded, and
        # the flow keeps accepting the packets that still belong to it. What
        # finalises the flow is proof that no more can come -- a new connection's
        # SYN on the same endpoints, handled above, or the end of the capture.
        return BUFID, not self._bidir and FIN

    def _make_index(self, buffer: 'Buffer[_AT]') -> 'Index':
        """Report a flow's buffer as its index entry.

        Arguments:
            buffer: a flow buffer (:term:`trace.tcp.buffer`)

        Returns:
            The flow's :term:`index <trace.tcp.index>` entry, its reassembler, if
            any, in a :class:`~pcapkit.foundation.traceflow.data.Deferred`
            unflushed: reading ``packet`` is what asks it for its datagrams, and
            their own ``packet`` is parsed later still.

        .. versionadded:: 1.10.0

        """
        return Index(
            fpout=self._output_path(buffer.label),
            index=tuple(buffer.index),
            label=buffer.label,
            forward=tuple(buffer.forward),
            reverse=tuple(buffer.reverse),
            packet=None if buffer.reassembly is None else Deferred(buffer.reassembly),
        )

    def _make_reassembly(self) -> 'Optional[TCP_Reassembly]':
        """Build the reassembler a new flow will feed, if analysis was asked for.

        Returns:
            A :class:`~pcapkit.foundation.reassembly.tcp.reassembly.TCP` reassembler of this
            flow's own, or :data:`None` when ``analyze`` is off.

        One reassembler **per flow** rather than one per tracer, so that
        :attr:`Index.packet <pcapkit.foundation.traceflow.tcp.data.Index.packet>`
        can flush this conversation's buffers without touching another's -- a
        shared instance would have to be asked for its datagrams by endpoint, and
        flushing it early would finalise flows that are still open.

        It is constructed with ``strict=False`` so that each datagram comes back
        as one contiguous payload, which is what an application-layer parse needs,
        and it inherits
        :attr:`TCP.__timeout__ <pcapkit.foundation.reassembly.tcp.reassembly.TCP.__timeout__>`
        -- no timeout -- so nothing here is evicted on a clock. It parses its
        payloads with :attr:`self._parse_keywords
        <pcapkit.foundation.traceflow.traceflow.TraceFlow._parse_keywords>`, as
        an engine's TCP reassembler does (:issue:`2946`).

        """
        if not self._analyze:
            return None

        # NOTE: imported here, since at module scope this sibling-subpackage edge joins the
        # ``foundation.extraction`` import cycle; cached per flow, not per packet.
        from pcapkit.foundation.reassembly.tcp.data import Packet as Reasm_Packet
        from pcapkit.foundation.reassembly.tcp.reassembly import TCP as TCP_Reassembly

        self._reasm_packet = Reasm_Packet
        reassembly = TCP_Reassembly(strict=False)
        reassembly._parse_keywords = dict(self._parse_keywords)
        return reassembly

    def _make_segment(self, packet: 'Packet[_AT]') -> 'Any':
        """Describe a traced packet the way the reassembler expects a segment.

        Arguments:
            packet: a flow packet (:term:`trace.tcp.packet`)

        Returns:
            A :class:`reassembly packet <pcapkit.foundation.reassembly.tcp.data.Packet>`
            for the same segment.

        The tracer does not reassemble anything itself -- it hands the segment to
        :class:`~pcapkit.foundation.reassembly.tcp.reassembly.TCP`, which already implements
        the :rfc:`815` hole-descriptor algorithm and handles the out-of-order and
        retransmitted segments a tracer concatenating payloads in capture order
        would silently corrupt. This is the whole of the translation.

        Note:
            The buffer ID is **(source, destination)** and so unidirectional, which
            is what makes each direction of the conversation reassemble separately
            even though the *flow* is keyed on the pair. The sequence number is
            passed through untouched: a SYN occupies one of its own, and
            :meth:`TCP.reassembly <pcapkit.foundation.reassembly.tcp.reassembly.TCP.reassembly>`
            is where that is accounted for.

        """
        raw_len = len(packet.payload)
        return self._reasm_packet(
            bufid=(packet.src, packet.srcport, packet.dst, packet.dstport),
            dsn=packet.seq,                      # data sequence number
            ack=packet.ack,                      # acknowledgement number
            num=packet.index,                    # original packet range number
            syn=packet.syn,                      # synchronise flag
            fin=packet.fin,                      # finish flag
            rst=packet.rst,                      # reset connection flag
            len=raw_len,                         # payload length, header excludes
            first=packet.seq,                    # first sequence number of payload
            last=packet.seq + raw_len - 1,       # last sequence number of payload
            header=packet.header,                # raw bytes type header
            payload=packet.payload,              # raw bytearray type payload
            timestamp=packet.timestamp,          # capture timestamp
        )

    @staticmethod
    def _ended(buffer: 'Buffer[_AT]') -> 'bool':
        """Whether a flow's connection has been seen to end.

        Arguments:
            buffer: a flow buffer (:term:`trace.tcp.buffer`)

        Returns:
            Whether a teardown was observed -- a **FIN from both endpoints**, the
            polite close of :rfc:`9293#section-3.6`, or a **RST** from either, the
            abrupt one of :rfc:`9293#section-3.5.3`.

        This is not the same as "nothing more will arrive on these endpoints": the
        acknowledgement that completes a four-way close, and any duplicate of it,
        still follow. It is used to tell a new connection's SYN from the peer's
        SYN-ACK, which is a question the flag alone cannot answer.

        """
        return buffer.reset or len(buffer.fin) >= 2
