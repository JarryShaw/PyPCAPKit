# -*- coding: utf-8 -*-
"""data model for internetwork packet exchange"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from pcapkit.const.ipx.packet import Packet
    from pcapkit.const.ipx.socket import Socket

__all__ = [
    'IPX',

    'Address',
]


@info_final
class Address(Data):
    """Data model for IPX address."""

    #: Network number (``:`` separated).
    network: 'str'
    #: Node number (``-`` separated).
    node: 'str'
    #: Socket number (``:`` separated).
    socket: 'Socket'
    #: Full address (``:`` separated).
    addr: 'str'

    if TYPE_CHECKING:
        def __init__(self, network: 'str', node: 'str', socket: 'Socket', addr: 'str') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class IPX(Protocol):
    """Data model for Internetwork Packet Exchange."""

    #: Checksum.
    chksum: 'bytes'
    #: Packet length (header includes).
    len: 'int'
    #: Transport control (hop count).
    count: 'int'
    #: Packet type.
    type: 'Packet'
    #: Destination Address.
    dst: 'Address'
    #: Source Address.
    src: 'Address'

    if TYPE_CHECKING:
        def __init__(self, chksum: 'bytes', len: 'int', count: 'int', type: 'Packet', dst: 'Address', src: 'Address') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin,line-too-long
