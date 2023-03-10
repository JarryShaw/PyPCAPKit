# -*- coding: utf-8 -*-
"""data model for IPv6 Routing Header"""

from typing import TYPE_CHECKING

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


class UnknownType(IPv6_Route):
    """Data model for IPv6-Route unknown type."""

    #: Data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Routing', seg_left: 'int',
                     data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long


class SourceRoute(IPv6_Route):
    """Data model for IPv6-Route Source Route data type."""

    #: Source addresses.
    ip: 'tuple[IPv6Address, ...]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Routing', seg_left: 'int',
                     ip: 'tuple[IPv6Address, ...]') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long


class Type2(IPv6_Route):
    """Data model for IPv6-Route Type 2 data type."""

    #: Address.
    ip: 'IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Routing', seg_left: 'int',
                     ip: 'IPv6Address') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long


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

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Routing', seg_left: 'int',
                     cmpr_i: 'int', cmpr_e: 'int', pad: 'int', ip: 'tuple[IPv6Address | bytes, ...]') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,redefined-builtin,line-too-long
