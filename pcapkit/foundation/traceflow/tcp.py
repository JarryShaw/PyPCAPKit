# -*- coding: utf-8 -*-
# pylint: disable=import-outside-toplevel
"""Follow TCP Streams
========================

.. module:: pcapkit.foundation.traceflow.tcp

:mod:`pcapkit.foundation.traceflow.tcp` is the interface to trace
TCP flows from a series of packets and connections.

"""
from typing import TYPE_CHECKING, Generic, overload

from pcapkit.foundation.traceflow.data.tcp import _AT, Buffer, BufferID, Index, Packet
from pcapkit.foundation.traceflow.traceflow import TraceFlowBase as TraceFlow
from pcapkit.protocols.transport.tcp import TCP as TCP_Protocol
from pcapkit.utilities.logging import get_logger

__all__ = ['TCP']

if TYPE_CHECKING:
    from dictdumper.dumper import Dumper
    from typing_extensions import Literal

#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)


class TCP(TraceFlow[BufferID, 'Buffer[_AT]', Index, Packet[_AT]], Generic[_AT]):
    """Trace TCP flows.

    Args:
        fout: output path
        format: output format
        byteorder: output file byte order
        nanosecond: output nanosecond-resolution file flag
        bidirectional: trace both halves of a conversation as one flow
        *args: Arbitrary positional arguments.
        **kwargs: Arbitrary keyword arguments.

    Note:
        A TCP connection has two halves, and by default they are traced as **one
        flow** -- which is what "following a TCP stream" means everywhere else,
        and what this module's own title claims to do. Keying a flow on
        (source, destination) instead put a client's packets and the server's
        replies in separate flows, separate labels and separate output files,
        leaving a caller to pair them up by inspecting the labels.

        Two consequences of the change are worth knowing:

        * The reverse half of a conversation no longer produces a flow of its
          own, so a capture of *n* connections yields *n* flows rather than
          ``2n``, and one output file each rather than two.
        * **A teardown does not end a flow.** Seeing a connection close is not the
          same as knowing nothing more will arrive on its endpoints: the four-way
          close of :rfc:`9293#section-3.6` is FIN, ACK, FIN, ACK, so the
          acknowledgement that completes it follows the second FIN, and duplicates
          of that acknowledgement can follow in turn. A flow is therefore
          finalised only by proof that no more of it can come -- a new
          connection's SYN on the same endpoints, or the end of the capture
          (:meth:`finish`). What the teardown does is get *recorded*, which is how
          that SYN is told from the peer's SYN-ACK; see :meth:`_ended`.

          Finalising a flow is also when its callbacks run, so they run against
          the whole conversation rather than a truncated one.

        Pass ``bidirectional=False`` for the older per-direction behaviour: a flow
        is one direction, and closes on that direction's FIN. That mode reproduces
        what flow tracing did before conversations became one flow, RST included --
        which is to say it ignores RST, as it always did.

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Protocol name of current reassembly object.
    __protocol_name__ = 'TCP'
    #: Protocol of current reassembly object.
    __protocol_type__ = TCP_Protocol

    ##########################################################################
    # Methods.
    ##########################################################################

    def dump(self, packet: 'Packet[_AT]') -> 'None':
        """Dump frame to output files.

        Arguments:
            packet: a flow packet (:term:`trace.tcp.packet`)

        """
        # fetch flow label
        output = self.trace(packet, output=True)

        # dump files
        output(packet.frame, name=f'Frame {packet.index}')  # pylint: disable=not-callable

    def make_bufid(self, packet: 'Packet[_AT]') -> 'BufferID':
        """Derive the buffer ID a packet belongs to.

        Arguments:
            packet: a flow packet (:term:`trace.tcp.packet`)

        Returns:
            Buffer ID, i.e. ``(address, port, address, port)``.

        Tracing bidirectionally means both halves of a conversation have to land
        on the *same* key, so the two endpoints are ordered canonically -- the
        lesser ``(address, port)`` pair first -- rather than as (source,
        destination). Sorting is what makes the key direction-independent: the
        client's ``A→B`` and the server's ``B→A`` both reduce to
        ``min(A, B), max(A, B)``.

        The result stays a plain :obj:`tuple` of the same shape, which is
        deliberate and not merely convenient: it is a :obj:`dict` key, and an
        :class:`~pcapkit.corekit.infoclass.Info` cannot be one -- inheriting
        :class:`collections.abc.Mapping` sets ``__hash__`` to :data:`None`.

        Note:
            Both endpoints of a connection are of the same address family, so the
            comparison never has to order an :class:`~ipaddress.IPv4Address`
            against an :class:`~ipaddress.IPv6Address` -- which raises
            :exc:`TypeError`.

        """
        near_addr, near_port = packet.src, packet.srcport
        far_addr, far_port = packet.dst, packet.dstport
        if self._bidir and (far_addr, far_port) < (near_addr, near_port):
            return (far_addr, far_port, near_addr, near_port)
        return (near_addr, near_port, far_addr, far_port)

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
            The flow label is formatted as following:

            .. code-block:: python

               f'{packet.src}_{packet.srcport}-{packet.dst}_{info.dstport}-{packet.timestamp}'

            It is built from the packet that **opened** the flow, not from the
            canonical buffer ID, so the label still names the initiator first and
            reads the way it always did. The reverse half of a bidirectional
            conversation joins that flow rather than minting a label of its own.

        """
        # clear cache
        self.__cached__['submit'] = None

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
        # bidirectional flow mid-capture; everything else is flushed by
        # :meth:`submit` at the end of the capture.
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
            label = f'{packet.src}_{packet.srcport}-{packet.dst}_{packet.dstport}-{packet.timestamp}'
            if packet.src.version != 4:
                # ``:`` is a path separator on Windows and a drive separator
                # elsewhere in the tooling, so an IPv6 label cannot carry it
                label = label.replace(':', '.')
            logger.debug('new TCP flow %s', label)
            self._buffer[BUFID] = Buffer(
                fpout=self._foutio(fname=f'{self._fproot}/{label}{self._fdpext or ""}', protocol=packet.protocol,
                                   byteorder=self._endian, nanosecond=self._nnsecd),
                index=[],
                label=label,
                origin=END,
                forward=[],
                reverse=[],
                fin=set(),
                reset=False,
            )

        # trace frame record
        buffer = self._buffer[BUFID]
        buffer.index.append(packet.index)
        # ... and again per direction, so the merged ordering above stays
        # authoritative while each half remains recoverable on its own
        if END == buffer.origin:
            buffer.forward.append(packet.index)
        else:
            buffer.reverse.append(packet.index)
        if FIN:
            buffer.fin.add(END)
        if RST:
            buffer.__update__(reset=True)
        fpout = buffer.fpout
        label = buffer.label

        # A *unidirectional* flow is one direction, and a direction is over when
        # its FIN goes out -- so that mode keeps closing on FIN exactly as it did.
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
        if not self._bidir and FIN:
            self._finalise(BUFID)

        # return label or output object
        return fpout if output else label

    @staticmethod
    def _ended(buffer: 'Buffer[_AT]') -> 'bool':
        """Whether a flow's connection has been seen to end.

        Arguments:
            buffer: a flow buffer (:term:`trace.tcp.buffer`)

        Returns:
            Whether a teardown was observed -- a **FIN from both endpoints**, the
            polite close of :rfc:`9293#section-3.6`, or a **RST** from either, the
            abrupt one of :rfc:`9293#section-3.5.2`.

        This is not the same as "nothing more will arrive on these endpoints": the
        acknowledgement that completes a four-way close, and any duplicate of it,
        still follow. It is used to tell a new connection's SYN from the peer's
        SYN-ACK, which is a question the flag alone cannot answer.

        """
        return buffer.reset or len(buffer.fin) >= 2

    def _finalise(self, bufid: 'BufferID') -> 'Index':
        """Finalise a flow: report it, and stop tracing into it.

        Arguments:
            bufid: buffer identifier of the flow to finalise

        Returns:
            The flow's :term:`index <trace.tcp.index>` entry.

        Called once per flow, from the one place that can prove a flow is over --
        a new connection superseding it, or :meth:`submit` at the end of the
        capture. Registering the flow here rather than at teardown is what keeps
        the acknowledgement that completes a close inside the flow it belongs to.

        """
        buf = self._buffer.pop(bufid)
        label = buf.label

        logger.debug('TCP flow %s finalised after %d frame(s) (%d forward, %d reverse)',
                     label, len(buf.index), len(buf.forward), len(buf.reverse))
        index = Index(
            fpout=f'{self._fproot}/{label}{self._fdpext}' if self._fdpext is not None else None,
            index=tuple(buf.index),
            label=label,
            forward=tuple(buf.forward),
            reverse=tuple(buf.reverse),
        )
        for callback in self.__callback_fn__:
            callback(index)
        self._stream.append(index)
        return index

    def finish(self) -> 'None':
        """Finalise every flow still being traced.

        The end of the capture is the second of the two things that can prove a
        bidirectional flow is over -- the first being a new connection on the same
        endpoints. Draining the buffer here is what lets a flow keep the
        acknowledgement that completes its close and *still* have its callback
        fired, rather than having to choose between the two.

        Idempotent: it drains the buffer, so a second call finds nothing to do.

        """
        for bufid in list(self._buffer):
            self._finalise(bufid)
        self.__cached__['submit'] = None

    def submit(self) -> 'tuple[Index, ...]':
        """Submit traced TCP flows.

        Returns:
            Traced TCP flow (:term:`trace.tcp.index`).

        Note:
            This reports flows still being traced **without** finalising them, so
            that reading
            :attr:`TraceFlow.index <pcapkit.foundation.traceflow.traceflow.TraceFlowBase.index>`
            part-way through a capture cannot disturb the tracing -- popping a
            buffer there would strand the rest of its conversation in a second
            flow. Such a flow is therefore reported here but has not fired its
            callback; :meth:`finish` is what does that, at the end of the capture.

        """
        if (cached := self.__cached__.get('submit')) is not None:
            return cached

        ret = []  # type: list[Index]
        for buf in self._buffer.values():
            ret.append(Index(fpout=f"{self._fproot}/{buf.label}{self._fdpext}" if self._fdpext else None,
                             index=tuple(buf.index),
                             label=buf.label,
                             forward=tuple(buf.forward),
                             reverse=tuple(buf.reverse),))
        ret.extend(self._stream)
        ret_submit = tuple(ret)

        logger.debug('submitted %d TCP flow(s), %d still open',
                     len(ret_submit), len(self._buffer))

        self.__cached__['submit'] = ret_submit
        return ret_submit
