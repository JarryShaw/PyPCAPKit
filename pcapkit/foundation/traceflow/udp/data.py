# -*- coding: utf-8 -*-
"""data models for UDP flow tracing

.. versionadded:: 1.10.0

"""

from typing import TYPE_CHECKING, Generic, TypeVar

from pcapkit.corekit.infoclass import Info, info_final
from pcapkit.corekit.packet import DeferredPacket
from pcapkit.utilities.compat import Tuple

__all__ = ['BufferID', 'Packet', 'Buffer', 'Index', 'Deferred']

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Any, Callable, Optional

    from dictdumper.dumper import Dumper
    from typing_extensions import TypeAlias

    from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
    from pcapkit.foundation.traceflow.data import FrameRecord
    from pcapkit.protocols.misc.pcap.frame.data import Frame as Data_Frame
    from pcapkit.protocols.protocol import ProtocolBase

_AT = TypeVar('_AT', 'IPv4Address', 'IPv6Address')

#: Buffer ID, i.e. ``(address, port, address, port)``, a plain :obj:`tuple` as
#: :data:`TCP's <pcapkit.foundation.traceflow.tcp.data.BufferID>` is, for the same
#: reason; see :meth:`TraceFlow.make_bufid
#: <pcapkit.foundation.traceflow.traceflow.TraceFlow.make_bufid>`.
BufferID: 'TypeAlias' = Tuple[_AT, int, _AT, int]


class Deferred:
    """A postponed parse of a traced UDP flow's application layer.

    A UDP datagram is a whole message (:rfc:`768`), so a flow's application layer
    is its datagrams' payloads, each parsed alone, and nothing is reassembled.
    This holds them until somebody reads
    :attr:`Index.packet <pcapkit.foundation.traceflow.udp.data.Index.packet>`.

    Args:
        analyze: The parse of one payload, called with its ``(source,
            destination)`` port pair and its octets: the tracer's
            ``__protocol_type__``'s ``analyze``, bound to the stops and context
            the extraction's engine parses its frames with.
        datagrams: Each datagram's port pair and payload, in capture order.

    """

    __slots__ = ('analyze', 'datagrams')

    def __init__(self, analyze: 'Callable[[tuple[int, int], bytes], ProtocolBase]',
                 datagrams: 'tuple[tuple[tuple[int, int], bytes], ...]') -> 'None':
        self.analyze = analyze
        self.datagrams = datagrams

    def __call__(self) -> 'tuple[ProtocolBase, ...]':
        """Run the postponed parse.

        Returns:
            Each datagram's payload parsed as its application layer, looked up
            by its ports, in capture order.

        """
        return tuple(self.analyze(ports, payload) for (ports, payload) in self.datagrams)


@info_final
class Packet(Info, Generic[_AT]):
    """Data structure for a packet submitted to **UDP flow tracing**.

    See Also:
        * :meth:`pcapkit.foundation.traceflow.traceflow.TraceFlow.dump`
        * :term:`trace.udp.packet`

    """

    #: Data link type -- the PCAP global header's, or that of the PCAP-NG
    #: interface the packet was captured on.
    protocol: 'Enum_LinkType'
    #: Frame number.
    index: 'int'
    #: Extracted frame info -- the default engine's frame, a third-party
    #: engine's :class:`~pcapkit.foundation.traceflow.data.FrameRecord`, or
    #: the :obj:`dict` PyShark's adapter reports, which carries no frame record.
    frame: 'Data_Frame | FrameRecord | dict[str, Any]'
    #: Source IP.
    src: '_AT'
    #: Destination IP.
    dst: '_AT'
    #: UDP source port.
    srcport: 'int'
    #: UDP destination port.
    dstport: 'int'
    #: Frame timestamp.
    timestamp: 'float'
    #: Raw :obj:`bytes` type UDP payload, i.e. the application-layer octets the
    #: datagram carries, as captured.
    payload: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, protocol: 'Enum_LinkType', index: 'int', frame: 'Data_Frame | FrameRecord | dict[str, Any]', src: '_AT', dst: '_AT', srcport: 'int', dstport: 'int', timestamp: 'float', payload: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class Buffer(Info, Generic[_AT]):
    """Data structure for a **UDP flow tracing** buffer.

    See Also:
        * :attr:`pcapkit.foundation.traceflow.traceflow.TraceFlow.index`
        * :term:`trace.udp.buffer`

    """

    #: Output dumper object.
    fpout: 'Dumper'
    #: List of frame index, **both directions**, in capture order. This is the
    #: authoritative ordering; :attr:`forward` and :attr:`reverse` are
    #: subsequences of it.
    index: 'list[int]'
    #: Flow label, built from the packet that opened the flow, cf.
    #: :meth:`TraceFlow._make_label
    #: <pcapkit.foundation.traceflow.traceflow.TraceFlow._make_label>`.
    label: 'str'
    #: ``(address, port)`` of the endpoint whose packet opened this flow, which
    #: defines what "forward" means for it and which the :attr:`label` names first.
    origin: 'tuple[_AT, int]'
    #: List of frame index sent **by** :attr:`origin`, in capture order.
    forward: 'list[int]'
    #: List of frame index sent **to** :attr:`origin`, in capture order. Always
    #: empty when tracing unidirectionally.
    reverse: 'list[int]'
    #: Each datagram's ``(source, destination)`` port pair and payload, in
    #: capture order, or :data:`None` when the tracer was not asked to analyse
    #: the application layer.
    payload: 'Optional[list[tuple[tuple[int, int], bytes]]]'

    if TYPE_CHECKING:
        def __init__(self, fpout: 'Dumper', index: 'list[int]', label: 'str', origin: 'tuple[_AT, int]', forward: 'list[int]', reverse: 'list[int]', payload: 'Optional[list[tuple[tuple[int, int], bytes]]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class Index(DeferredPacket, Info):
    """Data structure for a traced **UDP flow**, as an index entry.

    See Also:
        * element from :attr:`pcapkit.foundation.traceflow.traceflow.TraceFlow.index`
          *tuple*
        * :term:`trace.udp.index`

    """

    #: Listing ``packet`` here is what makes :attr:`packet` lazy -- see
    #: :class:`~pcapkit.corekit.packet.DeferredPacket`.
    __additional__ = ['packet']
    #: Placeholder class :attr:`packet` may hold, for
    #: :class:`~pcapkit.corekit.packet.DeferredPacket` to resolve.
    __deferred__ = Deferred

    #: Path of the flow's output file, or :data:`None` when the output format
    #: writes no file. Open and finalised flows report the same path.
    fpout: 'Optional[str]'
    #: Tuple of frame index, **both directions**, in capture order.
    index: 'tuple[int, ...]'
    #: Flow label, built from the packet that opened the flow.
    label: 'str'
    #: Frame index of the packets travelling in the direction that opened the
    #: flow, in capture order.
    forward: 'tuple[int, ...]'
    #: Frame index of the packets travelling the other way, in capture order.
    #: Empty when tracing unidirectionally.
    reverse: 'tuple[int, ...]'
    #: Each datagram's payload parsed as its **application layer**, one per
    #: frame of :attr:`index` and in its order, or :data:`None` when the tracer
    #: was not asked for it (``analyze=False``, the default). Parsed on the
    #: first read.
    packet: 'Optional[tuple[ProtocolBase, ...]]'

    if TYPE_CHECKING:
        def __init__(self, fpout: 'Optional[str]', index: 'tuple[int, ...]', label: 'str', forward: 'tuple[int, ...]', reverse: 'tuple[int, ...]', packet: 'Optional[tuple[ProtocolBase, ...] | Deferred]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long
