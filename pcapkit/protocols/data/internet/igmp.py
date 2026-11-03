# -*- coding: utf-8 -*-
"""data model for internet group management protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from ipaddress import IPv4Address

    from typing_extensions import Literal

    from pcapkit.const.igmp.type import Type as Enum_Type
    from pcapkit.corekit.checksum.internet import ChecksumStatus

__all__ = ['IGMP']


@info_final
class IGMP(Protocol):
    """Data model for Internet Group Management Protocol.

    This single schema covers both IGMPv1 (:rfc:`1112#page-11`) and IGMPv2
    (:rfc:`2236#section-2`) messages: v1's 8-octet header is the same shape as
    v2's, with ``max_resp_time`` reserved at zero and fewer :attr:`type`
    values defined (:issue:`2439`). IGMPv3 (:rfc:`3376`) adds a
    group-record-list body of a materially different shape and is out of
    scope here -- see :mod:`pcapkit.protocols.data.internet.igmpv3`.

    """

    #: Version of IGMP the message was read as, ``1`` or ``2`` -- the
    #: :attr:`~pcapkit.protocols.internet.igmp.IGMP.version` of the class that
    #: read or built it. It is on no octet, since the versions share this
    #: layout, and :meth:`IGMP.from_data
    #: <pcapkit.protocols.internet.igmp.IGMP.from_data>` dispatches on it
    #: (:issue:`2574`).
    version: 'Literal[1, 2]'
    #: Message type.
    type: 'Enum_Type'
    #: Max response time, in units of 1/10 second. Meaningful only for a
    #: Membership Query under IGMPv2 (:rfc:`2236#section-2.2`); reserved and
    #: zero on every other message, including every IGMPv1 one
    #: (:rfc:`1112#page-11`).
    max_resp_time: 'int'
    #: Checksum.
    checksum: 'bytes'
    #: Group address -- the IPv4 multicast group being queried, reported or
    #: left, or ``0.0.0.0`` on a General Query.
    group: 'IPv4Address'

    if TYPE_CHECKING:
        #: Outcome of verifying :attr:`checksum`, present only when
        #: :data:`~pcapkit.utilities.config.CHECKSUM_VERIFY` is on.
        checksum_status: 'ChecksumStatus'

        def __init__(self, version: 'Literal[1, 2]', type: 'Enum_Type', max_resp_time: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
                     checksum: 'bytes', group: 'IPv4Address') -> 'None': ...
