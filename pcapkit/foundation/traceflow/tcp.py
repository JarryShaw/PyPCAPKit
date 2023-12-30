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

__all__ = ['TCP']

if TYPE_CHECKING:
    from dictdumper.dumper import Dumper
    from typing_extensions import Literal


class TCP(TraceFlow[BufferID, Buffer, Index, Packet[_AT]], Generic[_AT]):
    """Trace TCP flows.

    Args:
        fout: output path
        format: output format
        byteorder: output file byte order
        nanosecond: output nanosecond-resolution file flag
        *args: Arbitrary positional arguments.
        **kwargs: Arbitrary keyword arguments.

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

        """
        # clear cache
        self.__cached__['submit'] = None

        # Buffer Identifier
        BUFID = (packet.src, packet.srcport, packet.dst, packet.dstport)  # type: BufferID
        # SYN = packet.syn  # Synchronise Flag (Establishment)
        FIN = packet.fin  # Finish Flag (Termination)

        # # when SYN is set, reset buffer of this seesion
        # if SYN and BUFID in self._buffer:
        #     temp = self._buffer.pop(BUFID)
        #     temp['fpout'] = (self._fproot, self._fdpext)
        #     temp['index'] = tuple(temp['index'])
        #     self._stream.append(Info(temp))

        # initialise buffer with BUFID
        if BUFID not in self._buffer:
            if packet.src.version == 4:
                label = f'{packet.src}_{packet.srcport}-{packet.dst}_{packet.dstport}-{packet.timestamp}'
            else:
                label = f'{packet.src}_{packet.srcport}-{packet.dst}_{packet.dstport}-{packet.timestamp}'.replace(':', '.')
            self._buffer[BUFID] = Buffer(
                fpout=self._foutio(fname=f'{self._fproot}/{label}{self._fdpext or ""}', protocol=packet.protocol,
                                   byteorder=self._endian, nanosecond=self._nnsecd),
                index=[],
                label=label,
            )

        # trace frame record
        self._buffer[BUFID].index.append(packet.index)
        fpout = self._buffer[BUFID].fpout
        label = self._buffer[BUFID].label

        # when FIN is set, submit buffer of this session
        if FIN:
            buf = self._buffer.pop(BUFID)
            # fpout, label = buf['fpout'], buf['label']

            index = Index(
                fpout=f'{self._fproot}/{label}{self._fdpext}' if self._fdpext is not None else None,
                index=tuple(buf.index),
                label=label,
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
                             label=buf.label,))
        ret.extend(self._stream)
        ret_submit = tuple(ret)

        self.__cached__['submit'] = ret_submit
        return ret_submit
