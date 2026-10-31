# -*- coding: utf-8 -*-
"""data model for internet group management protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from ipaddress import IPv4Address
    from typing import Optional

    from pcapkit.const.igmp.record_type import RecordType as Enum_RecordType
    from pcapkit.const.igmp.type import Type as Enum_Type

__all__ = ['IGMP', 'GroupAddressMessage', 'Version3MembershipReport', 'GroupRecord']


class IGMP(Protocol):
    """Data model for Internet Group Management Protocol.

    This is the common ancestor of the two message shapes IGMP defines:
    :class:`GroupAddressMessage`, covering every IGMPv1 (:rfc:`1112`) and
    IGMPv2 (:rfc:`2236`) message plus an IGMPv3 (:rfc:`3376`) Membership
    Query, all of which share a group-address-bearing 8-octet header; and
    :class:`Version3MembershipReport`, the IGMPv3 Membership Report, whose
    body is a list of group records instead (:issue:`2439`, :issue:`2448`).

    """

    #: Message type.
    type: 'Enum_Type'
    #: Header length, in octets. IGMP has no header field of its own that
    #: states this -- unlike :class:`~pcapkit.protocols.internet.ah.AH`, it
    #: is computed from what :meth:`IGMP.read <pcapkit.protocols.internet.igmp.IGMP.read>`
    #: actually consumed, the same way :attr:`~pcapkit.protocols.data.internet.esp.ESP.length`
    #: is.
    length: 'int'


@info_final
class GroupAddressMessage(IGMP):
    """Data model for an IGMP message built around a group address.

    This single schema covers IGMPv1 and IGMPv2's Membership Query,
    Membership Report and Leave Group messages (:rfc:`1112#appendix-I`,
    :rfc:`2236#section-2`) -- which all share one 8-octet layout -- and an
    IGMPv3 Membership Query (:rfc:`3376#section-4.1`), which reuses that same
    8-octet layout and appends the source-list extension described by
    :attr:`s_flag`, :attr:`qrv`, :attr:`qqic`/:attr:`qqi` and :attr:`sources`
    below. Those five fields are :data:`None` on every IGMPv1/v2 message and
    on a bare 8-octet IGMPv3 Query (:issue:`2439`, :issue:`2448`).

    """

    #: Max response code, as received on the wire. For an IGMPv1 message this
    #: is reserved at zero; for an IGMPv2 message other than a Membership
    #: Query it is likewise zero; for a Query of either version, or an IGMPv3
    #: Query, it is the raw *Max Resp Code* octet :attr:`max_resp_time` is
    #: decoded from (:rfc:`3376#section-4.1.1`).
    max_resp_code: 'int'
    #: Max response time, in units of 1/10 second. For an IGMPv1/v2 message,
    #: or an IGMPv3 Query of 8 octets, this is :attr:`max_resp_code` taken
    #: literally. For an IGMPv3 Query carrying the source-list extension, the
    #: code is floating-point, ``(mant | 0x10) << (exp + 3)`` if at or above
    #: 128 (:rfc:`3376#section-4.1.1`).
    max_resp_time: 'int'
    #: Checksum.
    checksum: 'bytes'
    #: Group address: the IPv4 multicast group being queried, reported or
    #: left, or ``0.0.0.0`` on a General Query.
    group: 'IPv4Address'
    #: Resv, the 4 reserved high-order bits of the flags octet
    #: (:rfc:`3376#section-4.1.4`), kept as read rather than assumed zero so
    #: a round trip reproduces a non-conformant sender's octet exactly.
    #: :data:`None` unless this is an IGMPv3 Query.
    resv: 'Optional[int]'
    #: Suppress Router-Side Processing flag (:rfc:`3376#section-4.1.5`).
    #: :data:`None` unless this is an IGMPv3 Query.
    s_flag: 'Optional[bool]'
    #: Querier's Robustness Variable (:rfc:`3376#section-4.1.6`). :data:`None`
    #: unless this is an IGMPv3 Query.
    qrv: 'Optional[int]'
    #: Querier's Query Interval Code, as received on the wire. :data:`None`
    #: unless this is an IGMPv3 Query.
    qqic: 'Optional[int]'
    #: Querier's Query Interval, in seconds, decoded from :attr:`qqic` by the
    #: same formula as :attr:`max_resp_time` (:rfc:`3376#section-4.1.7`).
    #: :data:`None` unless this is an IGMPv3 Query.
    qqi: 'Optional[int]'
    #: Source addresses being queried (:rfc:`3376#section-4.1.9`).
    #: :data:`None` unless this is an IGMPv3 Query; an empty :obj:`tuple` for
    #: a General or Group-Specific Query.
    sources: 'Optional[tuple[IPv4Address, ...]]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type', length: 'int', max_resp_code: 'int',
                     max_resp_time: 'int', checksum: 'bytes', group: 'IPv4Address',
                     resv: 'Optional[int]', s_flag: 'Optional[bool]', qrv: 'Optional[int]',
                     qqic: 'Optional[int]', qqi: 'Optional[int]',
                     sources: 'Optional[tuple[IPv4Address, ...]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin,line-too-long


@info_final
class GroupRecord(Data):
    """Data model for an IGMPv3 group record (:rfc:`3376#section-4.2.4`)."""

    #: Record type.
    record_type: 'Enum_RecordType'
    #: Auxiliary data length, in 32-bit words.
    aux_data_len: 'int'
    #: Number of source addresses.
    num_sources: 'int'
    #: Multicast address this record pertains to.
    multicast_address: 'IPv4Address'
    #: Source addresses (:rfc:`3376#section-4.2.9`).
    sources: 'tuple[IPv4Address, ...]'
    #: Auxiliary data (:rfc:`3376#section-4.2.10`); always empty for a
    #: standards-conformant IGMPv3 sender, but kept as read for a receiver.
    aux_data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, record_type: 'Enum_RecordType', aux_data_len: 'int', num_sources: 'int',
                     multicast_address: 'IPv4Address', sources: 'tuple[IPv4Address, ...]',
                     aux_data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class Version3MembershipReport(IGMP):
    """Data model for an IGMPv3 Membership Report (:rfc:`3376#section-4.2`)."""

    #: Reserved octet after :attr:`type` (:rfc:`3376#section-4.2.1`), kept as
    #: read rather than assumed zero so a round trip reproduces a
    #: non-conformant sender's octet exactly.
    reserved_1: 'int'
    #: Checksum.
    checksum: 'bytes'
    #: Reserved 16 bits before :attr:`num_group_records`
    #: (:rfc:`3376#section-4.2.1`); see :attr:`reserved_1`.
    reserved_2: 'bytes'
    #: Number of group records, as received on the wire.
    num_group_records: 'int'
    #: Group records (:rfc:`3376#section-4.2.4`).
    records: 'tuple[GroupRecord, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type', length: 'int', reserved_1: 'int', checksum: 'bytes',
                     reserved_2: 'bytes', num_group_records: 'int',
                     records: 'tuple[GroupRecord, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
