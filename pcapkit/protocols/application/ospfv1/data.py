# -*- coding: utf-8 -*-
"""data models for OSPFv1 protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data import Protocol

if TYPE_CHECKING:
    from ipaddress import IPv4Address

    from pcapkit.const.ospfv1.authentication import Authentication
    from pcapkit.const.ospfv1.packet import Packet
    from pcapkit.corekit.checksum.internet import ChecksumStatus

__all__ = ['OSPFv1']


@info_final
class OSPFv1(Protocol):
    """Data model for OSPFv1 packet (:rfc:`1131` Section A.2).

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
    #: Authentication type.
    autype: 'Authentication'
    #: Authentication, the 64-bit field as captured.
    auth: 'bytes'

    if TYPE_CHECKING:
        #: Octets captured past the Packet Length, present only when there are
        #: any.
        trailer: 'bytes'
        #: Outcome of verifying :attr:`chksum`, present only when
        #: :data:`~pcapkit.utilities.config.CHECKSUM_VERIFY` is on.
        checksum_status: 'ChecksumStatus'

        def __init__(self, version: 'int', type: 'Packet', len: 'int', router_id: 'IPv4Address',
                     area_id: 'IPv4Address', chksum: 'bytes', autype: 'Authentication', auth: 'bytes') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,line-too-long,multiple-statements,redefined-builtin
