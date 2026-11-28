# -*- coding: utf-8 -*-
"""Follow IP Conversations
=============================

.. module:: pcapkit.foundation.traceflow.ip.traceflow

:mod:`pcapkit.foundation.traceflow.ip.traceflow` is the interface to trace
IP conversations from a series of packets.

"""
import sys
from typing import TYPE_CHECKING, Generic, overload

from pcapkit.foundation.traceflow.ip.data import _AT, Buffer, BufferID, Index, Packet
from pcapkit.foundation.traceflow.traceflow import TraceFlowBase
from pcapkit.protocols.internet.ip.protocol import IP as IP_Protocol
from pcapkit.utilities.exceptions import stacklevel
from pcapkit.utilities.logging import get_logger
from pcapkit.utilities.warnings import AttributeWarning, warn

__all__ = ['IP']

if TYPE_CHECKING:
    from typing import Any, Optional

    from dictdumper.dumper import Dumper
    from typing_extensions import Literal

#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)


class IP(TraceFlowBase[BufferID, Buffer[_AT], Index, Packet[_AT]], Generic[_AT]):
    """Trace IP conversations.

    Args:
        fout: output path
        format: output format
        byteorder: output file byte order
        nanosecond: output nanosecond-resolution file flag
        bidirectional: trace both halves of a conversation as one flow
        analyze: ignored with a warning, as an IP conversation has no
            application layer of its own to analyse
        timeout: idle timeout in seconds, on the capture's clock; :data:`None`
            keeps every flow until :meth:`finish`

    Warns:
        AttributeWarning: If ``analyze`` is :data:`True`.

    Note:
        An IP conversation is the datagrams exchanged between two addresses, of
        whatever protocol they carry, both directions as one flow by default. A
        frame belongs to the conversation of its **outermost** IPv4 or IPv6
        header, the one its link carries: in an IP-in-IP tunnel (:rfc:`2003`,
        :rfc:`2473`, :rfc:`4213`) that is the tunnel's, where TCP and UDP flows
        take the innermost header's endpoints. Every fragment of a datagram
        carries that header, so each joins the conversation.

        IP has no connection to end, so a flow ends at :meth:`finish`, the end of
        the capture, or, given a ``timeout``, once that many seconds of the
        capture's clock pass without one of its datagrams
        (:meth:`~pcapkit.foundation.traceflow.traceflow.TraceFlow.advance`), as an
        IPFIX idle timeout ends one.

    .. versionadded:: 1.10.0

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Protocol name of current flow tracing object.
    __protocol_name__ = 'IP'
    #: Protocol of current flow tracing object.
    __protocol_type__ = IP_Protocol

    ##########################################################################
    # Methods.
    ##########################################################################

    def dump(self, packet: 'Packet[_AT]') -> 'None':
        """Dump frame to output files.

        Arguments:
            packet: a flow packet (:term:`trace.ip.packet`)

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
            packet: a flow packet (:term:`trace.ip.packet`)
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

               f'{packet.src}-{packet.dst}-{packet.timestamp}'

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
        """Submit traced IP conversations.

        Returns:
            Traced IP conversations (:term:`trace.ip.index`), the open ones first,
            which have not fired their callbacks; :meth:`finish` is what does that.

        """
        if (cached := self.__cached__.get('submit')) is not None:
            return cached

        ret_submit = (*map(self._make_index, self._buffer.values()), *self._stream)
        logger.debug('submitted %d IP flow(s), %d still open', len(ret_submit), len(self._buffer))

        self.__cached__['submit'] = ret_submit
        return ret_submit

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, *, fout: 'str' = './tmp', format: 'str' = 'pcap',  # pylint: disable=redefined-builtin
                 byteorder: 'Literal["little", "big"]' = sys.byteorder,
                 nanosecond: 'bool' = False, bidirectional: 'bool' = True,
                 analyze: 'bool' = False, timeout: 'Optional[float]' = None) -> 'None':
        """Initialise instance.

        Arguments:
            fout: output root path, made if missing
            format: output format
            byteorder: output file byte order
            nanosecond: output nanosecond-resolution file flag
            bidirectional: whether the two halves of a conversation are one flow
            analyze: ignored with a warning, since an IP conversation has no
                application layer of its own; trace TCP or UDP for one
            timeout: idle timeout in seconds, on the capture's clock;
                :data:`None` keeps every flow until :meth:`finish`

        Warns:
            AttributeWarning: If ``analyze`` is :data:`True`.

        """
        if analyze:
            warn(f'{self.name} flow tracing has no application layer to analyze; '
                 'so analyze=True will be ignored', AttributeWarning, stacklevel=stacklevel())
        super().__init__(fout=fout, format=format, byteorder=byteorder, nanosecond=nanosecond,
                         bidirectional=bidirectional, analyze=False, timeout=timeout)

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _endpoints(self, packet: 'Packet[_AT]') -> 'tuple[tuple[Any, ...], tuple[Any, ...]]':
        """The endpoints of a flow packet: ``(address,)`` of its source, then of its destination.

        Arguments:
            packet: a flow packet (:term:`trace.ip.packet`)

        Returns:
            The addresses alone, since IP has no ports.

        """
        return (packet.src,), (packet.dst,)

    def _record(self, packet: 'Packet[_AT]') -> 'BufferID':
        """Record a packet in its flow, opening the flow if none is open.

        Arguments:
            packet: a flow packet (:term:`trace.ip.packet`)

        Returns:
            The flow's buffer ID.

        """
        self.__cached__['submit'] = None
        # time out the flows this packet's timestamp leaves idle, its own included
        self.advance(packet.timestamp)

        bufid = self.make_bufid(packet)
        if bufid not in self._buffer:
            label = self._make_label(packet)
            logger.debug('new IP flow %s', label)
            self._buffer[bufid] = Buffer(
                fpout=self._make_fpout(label, packet.protocol),
                index=[],
                label=label,
                origin=(packet.src,),
                forward=[],
                reverse=[],
            )

        self._append(self._buffer[bufid], packet)
        self._touch(bufid, packet.timestamp)
        return bufid

    def _make_index(self, buffer: 'Buffer[_AT]') -> 'Index':
        """Report a flow's buffer as its index entry.

        Arguments:
            buffer: a flow buffer (:term:`trace.ip.buffer`)

        Returns:
            The flow's :term:`index <trace.ip.index>` entry.

        """
        return Index(
            fpout=self._output_path(buffer.label),
            index=tuple(buffer.index),
            label=buffer.label,
            forward=tuple(buffer.forward),
            reverse=tuple(buffer.reverse),
        )
