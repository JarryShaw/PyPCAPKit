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
        * A flow closes when **both** halves have sent a FIN rather than on the
          first FIN seen, since a connection is not over while one direction is
          still sending (:rfc:`9293#section-3.6`). A conversation whose reverse
          half was never captured therefore stays open until
          :meth:`submit` flushes it -- correctly, since nothing in the capture
          shows the connection closing.

        Pass ``bidirectional=False`` for the older per-direction behaviour.

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
        # SYN = packet.syn  # Synchronise Flag (Establishment)
        FIN = packet.fin  # Finish Flag (Termination)
        # the half of the conversation this packet was sent by
        END = (packet.src, packet.srcport)  # type: tuple[_AT, int]

        # # when SYN is set, reset buffer of this seesion
        # if SYN and BUFID in self._buffer:
        #     temp = self._buffer.pop(BUFID)
        #     temp['fpout'] = (self._fproot, self._fdpext)
        #     temp['index'] = tuple(temp['index'])
        #     self._stream.append(Info(temp))

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
        fpout = buffer.fpout
        label = buffer.label

        # when the session is over, submit its buffer
        #
        # NOTE: A bidirectional flow is a whole connection, and a connection is
        # not finished while either direction still is -- so it takes a FIN from
        # both endpoints, not the first FIN seen. Closing on the first would cut
        # the peer's FIN and the final acknowledgement out of the flow, and they
        # would then open a *second* flow under the same buffer ID: precisely the
        # split this is here to remove.
        closed = len(buffer.fin) >= 2 if self._bidir else FIN
        if closed:
            buf = self._buffer.pop(BUFID)
            # fpout, label = buf['fpout'], buf['label']

            logger.debug('TCP flow %s closed after %d frame(s) (%d forward, %d reverse)',
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

        # return label or output object
        return fpout if output else label

    def submit(self) -> 'tuple[Index, ...]':
        """Submit traced TCP flows.

        Returns:
            Traced TCP flow (:term:`trace.tcp.index`).

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
