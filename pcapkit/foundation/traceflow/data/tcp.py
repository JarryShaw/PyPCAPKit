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

#: Buffer ID, i.e. ``(address, port, address, port)``.
#:
#: A plain :obj:`tuple` rather than an :class:`~pcapkit.corekit.infoclass.Info`
#: **deliberately**: :class:`~pcapkit.corekit.infoclass.Info` inherits
#: :class:`collections.abc.Mapping`, which sets ``__hash__ = None``, so an
#: :class:`~pcapkit.corekit.infoclass.Info` cannot be a :obj:`dict` key at all.
#:
#: When tracing bidirectionally -- the default -- the two endpoints are ordered
#: canonically rather than as (source, destination), so that both halves of one
#: conversation produce the same key; see
#: :meth:`TCP.make_bufid <pcapkit.foundation.traceflow.tcp.TCP.make_bufid>`. The
#: shape is unchanged either way.
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
class Buffer(Info, Generic[_AT]):
    """Data structure for **TCP flow tracing**.

    See Also:
        * :attr:`pcapkit.foundation.traceflow.TraceFlow.index`
        * :term:`trace.tcp.buffer`

    """

    #: Output dumper object.
    fpout: 'Dumper'
    #: List of frame index, **both directions**, in capture order. This is the
    #: authoritative ordering; :attr:`forward` and :attr:`reverse` are
    #: subsequences of it.
    index: 'list[int]'
    #: Flow label generated from ``BUFID``.
    label: 'str'
    #: ``(address, port)`` of the endpoint whose packet opened this flow. It
    #: defines what "forward" means for the flow, and it is the endpoint the
    #: :attr:`label` names first.
    origin: 'tuple[_AT, int]'
    #: List of frame index sent **by** :attr:`origin`, in capture order.
    forward: 'list[int]'
    #: List of frame index sent **to** :attr:`origin`, in capture order. Always
    #: empty when tracing unidirectionally, since the reverse half of the
    #: conversation is then a flow of its own.
    reverse: 'list[int]'
    #: Endpoints observed to have sent a TCP **FIN**. A bidirectional flow is a
    #: whole connection, and a connection closes only once *both* halves have
    #: finished (:rfc:`9293#section-3.6`), so the set has to be tracked rather
    #: than a single flag: submitting on the first FIN would cut the peer's FIN
    #: and the final acknowledgement out of the flow.
    fin: 'set[tuple[_AT, int]]'

    if TYPE_CHECKING:
        # NOTE: one line, however long. ``# pylint: disable`` is *line*-scoped and
        # ``unused-argument`` is reported against the ``def``, so wrapping the
        # signature leaves every parameter on a continuation line outside the
        # disable's reach -- which is why the shorter form this replaces leaked
        # three ``unused-argument`` messages of its own. Every other data model in
        # :mod:`pcapkit` writes these stubs on one line for the same reason.
        def __init__(self, fpout: 'Dumper', index: 'list[int]', label: 'str', origin: 'tuple[_AT, int]', forward: 'list[int]', reverse: 'list[int]', fin: 'set[tuple[_AT, int]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


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
    #: Tuple of frame index, **both directions**, in capture order.
    index: 'tuple[int, ...]'
    #: Flow label generated from ``BUFID``.
    label: 'str'
    #: Frame index of the packets travelling in the direction that opened the
    #: flow, in capture order. That endpoint is the one the :attr:`label` names
    #: first, so ``frame_number in index.forward`` answers "which way did this
    #: packet go" without having to take the label apart.
    forward: 'tuple[int, ...]'
    #: Frame index of the packets travelling the other way, in capture order.
    #: Empty when tracing unidirectionally, in which case
    #: :attr:`forward` ``==`` :attr:`index`.
    reverse: 'tuple[int, ...]'

    if TYPE_CHECKING:
        # NOTE: on one line, for the reason given on :class:`Buffer` above.
        def __init__(self, fpout: 'Optional[str]', index: 'tuple[int, ...]', label: 'str', forward: 'tuple[int, ...]', reverse: 'tuple[int, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long
