# -*- coding: utf-8 -*-
"""data models for OSPF protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.utilities.compat import NotRequired

if TYPE_CHECKING:
    from ipaddress import IPv4Address

    from pcapkit.const.ospf.authentication import Authentication
    from pcapkit.const.ospf.packet import Packet

__all__ = ['OSPF', 'CrytographicAuthentication']


@info_final
class CrytographicAuthentication(Data):
    """Data model for OSPF crytographic authentication."""

    #: Key ID.
    key_id: 'int'
    #: Authentication data length.
    len: 'int'
    #: Cryptographic sequence number.
    seq: 'int'


@info_final
class OSPF(Data):
    """Data model for OSPF packet."""

    #: Version number.
    version: 'int'
    #: Type.
    type: 'Packet'
    #: Packet length (header included).
    len: 'int'
    #: Router ID.
    router_id: 'IPv4Address'
    #: Area ID.
    area_id: 'IPv4Address'
    #: Checksum.
    chksum: 'bytes'
    #: Authentication type.
    autype: 'Authentication'

    #: Authentication.
    auth: 'bytes | CrytographicAuthentication' = NotRequired  # type: ignore[assignment]
