# -*- coding: utf-8 -*-
"""data model for IPv6 Routing Header"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data

if TYPE_CHECKING:
    from ipaddress import IPv6Address

    from pcapkit.const.ipv6.routing import Routing
    from pcapkit.const.reg.transtype import TransType

__all__ = [
    'IPv6_Route',

    'UnknownType', 'SourceRoute', 'Type2', 'RPL',
]


class IPv6_Route(Data):
    """Data model for IPv6-Route protocol."""

    #: Next header.
    next: 'TransType'
    #: Header extension length.
    length: 'int'
    #: Routing type.
    type: 'Routing'
    #: Segments left.
    seg_left: 'int'


@info_final
class UnknownType(IPv6_Route):
    """Data model for IPv6-Route unknown type."""

    #: Data.
    data: 'bytes'


@info_final
class SourceRoute(IPv6_Route):
    """Data model for IPv6-Route Source Route data type."""

    #: Source addresses.
    ip: 'tuple[IPv6Address, ...]'


@info_final
class Type2(IPv6_Route):
    """Data model for IPv6-Route Type 2 data type."""

    #: Address.
    ip: 'IPv6Address'


@info_final
class RPL(IPv6_Route):
    """Data model for RPL Source data type."""

    #: CmprI.
    cmpr_i: 'int'
    #: CmprE.
    cmpr_e: 'int'
    #: Pad.
    pad: 'int'
    #: Addresses.
    ip: 'tuple[IPv6Address | bytes, ...]'
