# -*- coding: utf-8 -*-
"""data model for internetwork packet exchange"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data

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


@info_final
class IPX(Data):
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
