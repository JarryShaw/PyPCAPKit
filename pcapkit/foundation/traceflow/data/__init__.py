# -*- coding: utf-8 -*-
"""data models for flow tracing"""

# TCP flow tracing
from pcapkit.foundation.traceflow.data.tcp import Buffer as TCP_Buffer
from pcapkit.foundation.traceflow.data.tcp import BufferID as TCP_BufferID
from pcapkit.foundation.traceflow.data.tcp import Index as TCP_Index
from pcapkit.foundation.traceflow.data.tcp import Packet as TCP_Packet

__all__ = [
    'TCP_Buffer', 'TCP_BufferID', 'TCP_Index', 'TCP_Packet',
]

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info, info_final

if TYPE_CHECKING:
    from typing import Optional


@info_final
class TraceFlowData(Info):
    """Data storage for flow tracing."""

    #: TCP traced flows.
    tcp: 'tuple[TCP_Index, ...]'

    if TYPE_CHECKING:
        def __init__(self, tcp: 'Optional[tuple[TCP_Index, ...]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long
