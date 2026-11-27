# -*- coding: utf-8 -*-
"""data models for OSPFv3 protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data import Protocol

if TYPE_CHECKING:
    from ipaddress import IPv4Address

    from pcapkit.const.ospf.packet import Packet

__all__ = ['OSPFv3']


@info_final
class OSPFv3(Protocol):
    """Data model for OSPFv3 packet (:rfc:`5340#appendix-A.3.1`).

    .. versionadded:: 1.8.1

    """

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
    #: Instance ID.
    instance_id: 'int'
    #: The reserved octet, as captured.
    reserved: 'bytes'

    if TYPE_CHECKING:
        #: Octets captured past the Packet Length, present only when there are
        #: any.
        trailer: 'bytes'

        def __init__(self, version: 'int', type: 'Packet', len: 'int', router_id: 'IPv4Address',
                     area_id: 'IPv4Address', chksum: 'bytes', instance_id: 'int', reserved: 'bytes') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,line-too-long,multiple-statements,redefined-builtin
