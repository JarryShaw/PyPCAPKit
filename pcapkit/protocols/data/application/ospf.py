# -*- coding: utf-8 -*-
"""data models for OSPF protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.protocol import Protocol

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

    if TYPE_CHECKING:
        def __init__(self, key_id: 'int', len: 'int', seq: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class OSPF(Protocol):
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

    if TYPE_CHECKING:
        #: Authentication.
        auth: 'bytes | CrytographicAuthentication'

        def __init__(self, version: 'int', type: 'Packet', len: 'int', router_id: 'IPv4Address',
                     area_id: 'IPv4Address', chksum: 'bytes', autype: 'Authentication') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,line-too-long,multiple-statements,redefined-builtin
