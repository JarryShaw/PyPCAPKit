# -*- coding: utf-8 -*-
"""data models for IP flow tracing

.. versionadded:: 1.10.0

"""

from typing import TYPE_CHECKING, Generic, TypeVar

from pcapkit.corekit.infoclass import Info, info_final
from pcapkit.utilities.compat import Tuple

__all__ = ['BufferID', 'Packet', 'Buffer', 'Index']

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Any, Optional

    from dictdumper.dumper import Dumper
    from typing_extensions import TypeAlias

    from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
    from pcapkit.foundation.traceflow.data import FrameRecord
    from pcapkit.protocols.misc.pcap.frame.data import Frame as Data_Frame

_AT = TypeVar('_AT', 'IPv4Address', 'IPv6Address')

#: Buffer ID, i.e. ``(address, address)``, a plain :obj:`tuple` as
#: :data:`TCP's <pcapkit.foundation.traceflow.tcp.data.BufferID>` is, for the same
#: reason; see :meth:`TraceFlow.make_bufid
#: <pcapkit.foundation.traceflow.traceflow.TraceFlow.make_bufid>`.
BufferID: 'TypeAlias' = Tuple[_AT, _AT]


@info_final
class Packet(Info, Generic[_AT]):
    """Data structure for a packet submitted to **IP flow tracing**.

    See Also:
        * :meth:`pcapkit.foundation.traceflow.traceflow.TraceFlow.dump`
        * :term:`trace.ip.packet`

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
    #: Frame timestamp.
    timestamp: 'float'

    if TYPE_CHECKING:
        def __init__(self, protocol: 'Enum_LinkType', index: 'int', frame: 'Data_Frame | FrameRecord | dict[str, Any]', src: '_AT', dst: '_AT', timestamp: 'float') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class Buffer(Info, Generic[_AT]):
    """Data structure for an **IP flow tracing** buffer.

    See Also:
        * :attr:`pcapkit.foundation.traceflow.traceflow.TraceFlow.index`
        * :term:`trace.ip.buffer`

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
    #: ``(address,)`` of the endpoint whose packet opened this flow, which
    #: defines what "forward" means for it and which the :attr:`label` names first.
    origin: 'tuple[_AT]'
    #: List of frame index sent **by** :attr:`origin`, in capture order.
    forward: 'list[int]'
    #: List of frame index sent **to** :attr:`origin`, in capture order. Always
    #: empty when tracing unidirectionally.
    reverse: 'list[int]'

    if TYPE_CHECKING:
        def __init__(self, fpout: 'Dumper', index: 'list[int]', label: 'str', origin: 'tuple[_AT]', forward: 'list[int]', reverse: 'list[int]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class Index(Info):
    """Data structure for a traced **IP flow**, as an index entry.

    See Also:
        * element from :attr:`pcapkit.foundation.traceflow.traceflow.TraceFlow.index`
          *tuple*
        * :term:`trace.ip.index`

    """

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

    if TYPE_CHECKING:
        def __init__(self, fpout: 'Optional[str]', index: 'tuple[int, ...]', label: 'str', forward: 'tuple[int, ...]', reverse: 'tuple[int, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long
