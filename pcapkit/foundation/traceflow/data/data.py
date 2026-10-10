# -*- coding: utf-8 -*-
"""shared data models for flow tracing"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info, info_final
from pcapkit.corekit.packet import DeferredPacket

__all__ = ['TraceFlowData', 'Deferred', 'DeferredPacket', 'FrameRecord']

if TYPE_CHECKING:
    from decimal import Decimal
    from typing import Any, Optional

    from pcapkit.foundation.reassembly.data.tcp import Datagram as TCP_Datagram
    from pcapkit.foundation.reassembly.tcp import TCP as TCP_Reassembly
    from pcapkit.foundation.traceflow.data.tcp import Index as TCP_Index
    from pcapkit.protocols.data.misc.pcap.frame import FrameInfo as Data_FrameInfo


class Deferred:
    """A postponed reassembly of a traced flow's application layer.

    A traced flow's ``packet`` is the application-layer payload of the
    conversation, as reassembled datagrams -- one per direction and
    acknowledgement number, see :class:`~pcapkit.foundation.traceflow.tcp.TCP`.
    Producing it means reassembling the
    stream, which is neither free nor wanted by most callers of a *tracer* -- so
    the flow keeps the reassembler it was fed and this holds it until somebody
    reads
    :attr:`Index.packet <pcapkit.foundation.traceflow.data.tcp.Index.packet>`.

    Note:
        Deliberately not
        :class:`pcapkit.foundation.reassembly.data.data.Deferred`, and not shared
        with it. That one postpones a single ``analyze()`` call over bytes already
        in hand; this postpones a *submit* over a reassembler's buffers. The two
        subpackages are siblings and neither should depend on the other, so the
        few lines are written twice rather than one importing the other -- the
        same reason the two ``data/data.py`` modules mirror each other instead of
        merging.

    Args:
        reassembly: The flow's own
            :class:`~pcapkit.foundation.reassembly.tcp.TCP` reassembler, fed the
            segments of this conversation as they were traced.

    """

    __slots__ = ('reassembly',)

    def __init__(self, reassembly: 'TCP_Reassembly') -> 'None':
        self.reassembly = reassembly

    def __call__(self) -> 'tuple[TCP_Datagram, ...]':
        """Run the postponed reassembly.

        Returns:
            The conversation's reassembled datagrams, one per direction and
            acknowledgement number. Each carries its *own* postponed analysis in
            :attr:`Datagram.packet <pcapkit.foundation.reassembly.data.tcp.Datagram.packet>`,
            so parsing the payload as an application-layer protocol is still not
            paid for until that is read in turn.

        """
        return self.reassembly.datagram


class FrameRecord(dict):
    """A frame as a third-party engine's flow tracing adapter reports it.

    The mapping is the engine's own dissection of the frame, exactly as before, so
    every trace format that takes a mapping writes it unchanged. Beside it, as
    attributes the mapping does not show, it carries what the PCAP trace dumper
    reads of a frame -- :meth:`PCAPIO._append_value
    <pcapkit.dumpkit.pcap.PCAPIO._append_value>` takes ``packet``,
    ``frame_info`` and ``time_epoch`` -- so ``trace_format='pcap'`` writes the
    frame's record too (:issue:`1507`).

    Args:
        mapping: The engine's dissection of the frame.
        packet: The frame's captured octets.
        frame_info: The frame's PCAP record header.
        time_epoch: The frame's exact UNIX timestamp.

    """

    __slots__ = ('packet', 'frame_info', 'time_epoch')

    #: The frame's captured octets.
    packet: 'bytes'
    #: The frame's PCAP record header, with the fraction in the capture's own
    #: resolution.
    frame_info: 'Data_FrameInfo'
    #: The frame's exact UNIX timestamp, from which
    #: :meth:`PCAPIO._make_timestamp <pcapkit.dumpkit.pcap.PCAPIO._make_timestamp>`
    #: tells which resolution ``frame_info.ts_usec`` is in. A
    #: :class:`~decimal.Decimal`, since only that settles it exactly.
    time_epoch: 'Decimal'

    def __init__(self, mapping: 'dict[str, Any]', *, packet: 'bytes',
                 frame_info: 'Data_FrameInfo', time_epoch: 'Decimal') -> 'None':
        super().__init__(mapping)
        self.packet = packet
        self.frame_info = frame_info
        self.time_epoch = time_epoch

    def __reduce__(self) -> 'tuple[Any, ...]':
        # NOTE: spelled out because a ``dict`` subclass with ``__slots__`` cannot
        # be pickled with protocol 0 or 1 otherwise
        return _frame_record, (dict(self), self.packet, self.frame_info, self.time_epoch)


def _frame_record(mapping: 'dict[str, Any]', packet: 'bytes',
                  frame_info: 'Data_FrameInfo', time_epoch: 'Decimal') -> 'FrameRecord':
    """Rebuild a pickled :class:`FrameRecord`.

    Args:
        mapping: The engine's dissection of the frame.
        packet: The frame's captured octets.
        frame_info: The frame's PCAP record header.
        time_epoch: The frame's exact UNIX timestamp.

    Returns:
        The frame record.

    """
    return FrameRecord(mapping, packet=packet, frame_info=frame_info, time_epoch=time_epoch)


@info_final
class TraceFlowData(Info):
    """Data storage for flow tracing."""

    #: TCP traced flows.
    tcp: 'tuple[TCP_Index, ...]'

    if TYPE_CHECKING:
        def __init__(self, tcp: 'Optional[tuple[TCP_Index, ...]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long
