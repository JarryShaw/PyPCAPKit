# -*- coding: utf-8 -*-
"""shared data models for flow tracing"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info, info_final

__all__ = ['TraceFlowData']

if TYPE_CHECKING:
    from typing import Optional

    from pcapkit.foundation.traceflow.data.tcp import Index as TCP_Index


@info_final
class TraceFlowData(Info):
    """Data storage for flow tracing."""

    #: TCP traced flows.
    tcp: 'tuple[TCP_Index, ...]'

    if TYPE_CHECKING:
        def __init__(self, tcp: 'Optional[tuple[TCP_Index, ...]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long
