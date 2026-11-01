# -*- coding: utf-8 -*-
"""data model for internet group management protocol version 3"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from ipaddress import IPv4Address

    from pcapkit.const.igmp.record_type import RecordType as Enum_RecordType
    from pcapkit.const.igmp.type import Type as Enum_Type

__all__ = ['IGMPv3', 'Query', 'Report', 'GroupRecord']


class IGMPv3(Protocol):
    """Data model for Internet Group Management Protocol version 3.

    This is the common ancestor of the two message shapes IGMPv3 defines:
    :class:`Query`, its Membership Query, extending the 8-octet group-address
    header IGMPv1/v2 also use with a source-list extension; and
    :class:`Report`, its Membership Report, whose body is a list of group
    records instead (:issue:`2439`, :issue:`2448`).

    """

    #: Message type.
    type: 'Enum_Type'
    #: Header length, in octets. IGMP has no header field of its own that
    #: states this -- unlike :class:`~pcapkit.protocols.internet.ah.AH`, it
    #: is computed from what :meth:`IGMPv3.read
    #: <pcapkit.protocols.internet.igmpv3.IGMPv3.read>` actually consumed, the
    #: same way :attr:`~pcapkit.protocols.data.internet.esp.ESP.length` is.
    length: 'int'


@info_final
class Query(IGMPv3):
    """Data model for an IGMPv3 Membership Query (:rfc:`3376#section-4.1`).

    Reached only once :meth:`IGMPv3.read <pcapkit.protocols.internet.igmpv3.IGMPv3.read>`
    has confirmed the message classifies as IGMPv3 (at least 12 octets), so
    the source-list extension fields below are always populated -- never
    :data:`None`, unlike the single-class design IGMPv1/v2 predate this one
    with.

    """

    #: Max response code, as received on the wire; the raw octet
    #: :attr:`max_resp_time` is decoded from (:rfc:`3376#section-4.1.1`).
    max_resp_code: 'int'
    #: Max response time, in units of 1/10 second, decoded from
    #: :attr:`max_resp_code`: literal if below 128, else floating-point,
    #: ``(mant | 0x10) << (exp + 3)`` (:rfc:`3376#section-4.1.1`).
    max_resp_time: 'int'
    #: Checksum.
    checksum: 'bytes'
    #: Group address: the IPv4 multicast group being queried, or ``0.0.0.0``
    #: on a General Query.
    group: 'IPv4Address'
    #: Resv, the 4 reserved high-order bits of the flags octet
    #: (:rfc:`3376#section-4.1.4`), kept as read rather than assumed zero so
    #: a round trip reproduces a non-conformant sender's octet exactly.
    resv: 'int'
    #: Suppress Router-Side Processing flag (:rfc:`3376#section-4.1.5`).
    s_flag: 'bool'
    #: Querier's Robustness Variable (:rfc:`3376#section-4.1.6`).
    qrv: 'int'
    #: Querier's Query Interval Code, as received on the wire.
    qqic: 'int'
    #: Querier's Query Interval, in seconds, decoded from :attr:`qqic` by the
    #: same formula as :attr:`max_resp_time` (:rfc:`3376#section-4.1.7`).
    qqi: 'int'
    #: Source addresses being queried (:rfc:`3376#section-4.1.9`); an empty
    #: :obj:`tuple` for a General or Group-Specific Query.
    sources: 'tuple[IPv4Address, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type', length: 'int', max_resp_code: 'int',
                     max_resp_time: 'int', checksum: 'bytes', group: 'IPv4Address',
                     resv: 'int', s_flag: 'bool', qrv: 'int', qqic: 'int', qqi: 'int',
                     sources: 'tuple[IPv4Address, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin,line-too-long


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
class Report(IGMPv3):
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
