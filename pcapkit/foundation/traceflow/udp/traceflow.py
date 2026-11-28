# -*- coding: utf-8 -*-
"""Follow UDP Streams
========================

.. module:: pcapkit.foundation.traceflow.udp.traceflow

:mod:`pcapkit.foundation.traceflow.udp.traceflow` is the interface to trace
UDP flows from a series of packets.

"""
import functools
from typing import TYPE_CHECKING, Generic, overload

from pcapkit.foundation.traceflow.traceflow import TraceFlowBase
from pcapkit.foundation.traceflow.udp.data import _AT, Buffer, BufferID, Deferred, Index, Packet
from pcapkit.protocols.transport.udp.protocol import UDP as UDP_Protocol
from pcapkit.utilities.logging import get_logger

__all__ = ['UDP']

if TYPE_CHECKING:
    from dictdumper.dumper import Dumper
    from typing_extensions import Literal

#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)


class UDP(TraceFlowBase[BufferID, Buffer[_AT], Index, Packet[_AT]], Generic[_AT]):
    """Trace UDP flows.

    Args:
        fout: output path
        format: output format
        byteorder: output file byte order
        nanosecond: output nanosecond-resolution file flag
        bidirectional: trace both halves of a conversation as one flow
        analyze: parse each flow's application layer, so that
            :attr:`Index.packet <pcapkit.foundation.traceflow.udp.data.Index.packet>`
            can be read
        timeout: idle timeout in seconds, on the capture's clock; :data:`None`
            keeps every flow until :meth:`finish`

    Note:
        A UDP flow is the datagrams exchanged between two ``(address, port)``
        endpoints, both directions as one flow by default, as TCP's is.
        UDP has no connection (:rfc:`768`), so nothing a datagram carries can end
        its flow: a flow ends at :meth:`finish`, the end of the capture, or, given
        a ``timeout``, once that many seconds of the capture's clock pass without
        one of its datagrams
        (:meth:`~pcapkit.foundation.traceflow.traceflow.TraceFlow.advance`), as an
        IPFIX idle timeout ends one. A datagram on the same endpoints after that
        opens a new flow.

    Note:
        With ``analyze=True`` a flow also carries its **application layer**:
        :attr:`Index.packet <pcapkit.foundation.traceflow.udp.data.Index.packet>`
        holds each datagram's payload, parsed on its first read by the ports, as
        a frame's UDP layer dispatches it. A datagram is a whole message, so
        there is nothing to reassemble; one cut short by the snapshot length, or
        the first fragment of an IP datagram, is parsed as captured.

    .. versionadded:: 1.10.0

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Protocol name of current flow tracing object.
    __protocol_name__ = 'UDP'
    #: Protocol of current flow tracing object.
    __protocol_type__ = UDP_Protocol

    ##########################################################################
    # Methods.
    ##########################################################################

    def dump(self, packet: 'Packet[_AT]') -> 'None':
        """Dump frame to output files.

        Arguments:
            packet: a flow packet (:term:`trace.udp.packet`)

        The flow's output file is kept open for its next frame, as
        :meth:`~pcapkit.foundation.traceflow.traceflow.TraceFlow._write`
        describes.

        """
        bufid = self._record(packet)
        self._write(self._buffer[bufid].fpout, packet.frame, f'Frame {packet.index}')

    @overload
    def trace(self, packet: 'Packet[_AT]', *, output: 'Literal[True]' = ...) -> 'Dumper': ...
    @overload
    def trace(self, packet: 'Packet[_AT]', *, output: 'Literal[False]' = ...) -> 'str': ...

    def trace(self, packet: 'Packet[_AT]', *, output: 'bool' = False) -> 'Dumper | str':
        """Trace packets.

        Arguments:
            packet: a flow packet (:term:`trace.udp.packet`)
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
        buffer = self._buffer[self._record(packet)]
        return buffer.fpout if output else buffer.label

    def finish(self) -> 'None':
        """Finalise every flow still being traced.

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
        """Submit traced UDP flows.

        Returns:
            Traced UDP flows (:term:`trace.udp.index`), the open ones first, which
            have not fired their callbacks; :meth:`finish` is what does that.

        """
        if (cached := self.__cached__.get('submit')) is not None:
            return cached

        ret_submit = (*map(self._make_index, self._buffer.values()), *self._stream)
        logger.debug('submitted %d UDP flow(s), %d still open', len(ret_submit), len(self._buffer))

        self.__cached__['submit'] = ret_submit
        return ret_submit

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _record(self, packet: 'Packet[_AT]') -> 'BufferID':
        """Record a packet in its flow, opening the flow if none is open.

        Arguments:
            packet: a flow packet (:term:`trace.udp.packet`)

        Returns:
            The flow's buffer ID.

        """
        self.__cached__['submit'] = None
        # time out the flows this packet's timestamp leaves idle, its own included
        self.advance(packet.timestamp)

        bufid = self.make_bufid(packet)
        if bufid not in self._buffer:
            label = self._make_label(packet)
            logger.debug('new UDP flow %s', label)
            self._buffer[bufid] = Buffer(
                fpout=self._make_fpout(label, packet.protocol),
                index=[],
                label=label,
                origin=(packet.src, packet.srcport),
                forward=[],
                reverse=[],
                payload=[] if self._analyze else None,
            )

        buffer = self._buffer[bufid]
        self._append(buffer, packet)
        self._touch(bufid, packet.timestamp)
        if buffer.payload is not None:
            buffer.payload.append(((packet.srcport, packet.dstport), bytes(packet.payload)))
        return bufid

    def _make_index(self, buffer: 'Buffer[_AT]') -> 'Index':
        """Report a flow's buffer as its index entry.

        Arguments:
            buffer: a flow buffer (:term:`trace.udp.buffer`)

        Returns:
            The flow's :term:`index <trace.udp.index>` entry, its payloads, if
            kept, in a :class:`~pcapkit.foundation.traceflow.udp.data.Deferred`
            parsing them with :attr:`self._parse_keywords
            <pcapkit.foundation.traceflow.traceflow.TraceFlow._parse_keywords>`.

        """
        packet = None  # type: Deferred | None
        if buffer.payload is not None:
            analyze = functools.partial(self.protocol.analyze, **self._parse_keywords)
            packet = Deferred(analyze, tuple(buffer.payload))
        return Index(
            fpout=self._output_path(buffer.label),
            index=tuple(buffer.index),
            label=buffer.label,
            forward=tuple(buffer.forward),
            reverse=tuple(buffer.reverse),
            packet=packet,
        )
