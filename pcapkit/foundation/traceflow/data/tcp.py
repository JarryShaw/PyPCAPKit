# -*- coding: utf-8 -*-
"""data models for TCP flow tracing"""

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
    from pcapkit.protocols.data.misc.pcap.frame import Frame as Data_Frame

_AT = TypeVar('_AT', 'IPv4Address', 'IPv6Address')

#: Buffer ID.
BufferID: 'TypeAlias' = Tuple[_AT, int, _AT, int]


@info_final
class Packet(Info, Generic[_AT]):
    """Data structure for **TCP flow tracing**.

    See Also:
        * :meth:`pcapkit.foundation.traceflow.TraceFlow.dump`
        * :term:`trace.tcp.packet`

    """

    #: Data link type from global header.
    protocol: 'Enum_LinkType'
    #: Frame number.
    index: 'int'
    #: Extracted frame info.
    frame: 'Data_Frame | dict[str, Any]'
    #: TCP synchronise (SYN) flag.
    syn: 'bool'
    #: TCP finish (FIN) flag.
    fin: 'bool'
    #: Source IP.
    src: '_AT'
    #: Destination IP.
    dst: '_AT'
    #: TCP source port.
    srcport: 'int'
    #: TCP destination port.
    dstport: 'int'
    #: Frame timestamp.
    timestamp: 'float'

    if TYPE_CHECKING:
        def __init__(self, protocol: 'Enum_LinkType', index: 'int', frame: 'Data_Frame | dict[str, Any]', syn: 'bool', fin: 'bool', src: '_AT', dst: '_AT',
                     srcport: 'int', dstport: 'int', timestamp: 'float') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class Buffer(Info):
    """Data structure for **TCP flow tracing**.

    See Also:
        * :attr:`pcapkit.foundation.traceflow.TraceFlow.index`
        * :term:`trace.tcp.buffer`

    """

    #: Output dumper object.
    fpout: 'Dumper'
    #: List of frame index.
    index: 'list[int]'
    #: Flow label generated from ``BUFID``.
    label: 'str'

    if TYPE_CHECKING:
        def __init__(self, fpout: 'Dumper',
                     index: 'list[int]', label: 'str') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class Index(Info):
    """Data structure for **TCP flow tracing**.

    See Also:
        * element from :attr:`pcapkit.foundation.traceflow.TraceFlow.index`
          *tuple*
        * :term:`trace.tcp.index`

    """

    #: Output filename if exists.
    fpout: 'Optional[str]'
    #: Tuple of frame index.
    index: 'tuple[int, ...]'
    #: Flow label generated from ``BUFID``.
    label: 'str'

    if TYPE_CHECKING:
        def __init__(self, fpout: 'Optional[str]', index: 'tuple[int, ...]',
                     label: 'str') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
