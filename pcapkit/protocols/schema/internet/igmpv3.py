# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for internet group management protocol version 3"""

import io
from typing import TYPE_CHECKING

from pcapkit.const.igmp.record_type import RecordType as Enum_RecordType
from pcapkit.const.igmp.type import Type as Enum_Type
from pcapkit.corekit.fields.collections import ListField
from pcapkit.corekit.fields.ipaddress import IPv4AddressField
from pcapkit.corekit.fields.misc import ConditionalField, PayloadField, SchemaField, SwitchField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt16Field
from pcapkit.corekit.fields.strings import BitField, BytesField
from pcapkit.protocols.schema.schema import Schema, schema_final
from pcapkit.utilities.exceptions import ProtocolError, StreamEOFError

__all__ = ['IGMP', 'Query', 'QueryExtension', 'Report', 'GroupRecord']

if TYPE_CHECKING:
    from ipaddress import IPv4Address
    from typing import Any, Optional

    from typing_extensions import TypedDict

    from pcapkit.protocols.protocol import ProtocolBase

    class QueryFlags(TypedDict):
        """IGMPv3 Query flags field."""

        #: Reserved.
        resv: int
        #: Suppress Router-Side Processing flag.
        s_flag: int
        #: Querier's Robustness Variable.
        qrv: int


def igmpv3_body_selector(pkt: 'dict[str, Any]') -> 'SchemaField':
    """Selector function for :attr:`IGMP.body` field.

    Args:
        pkt: Packet data.

    Returns:
        Returns a :class:`~pcapkit.corekit.fields.misc.SchemaField` wrapped
        :class:`Query` or :class:`Report` instance, chosen by :attr:`IGMP.type`.

    Raises:
        ProtocolError: If :attr:`IGMP.type` is neither the Membership Query
            nor the IGMPv3 Membership Report. :meth:`IGMP._classify
            <pcapkit.protocols.internet.igmp.IGMP._classify>` is what keeps a
            genuine IGMPv1/v2 message (an 8-octet Query, or a Report/Leave
            type) from ever reaching this class in the first place; this is
            only reached when :class:`~pcapkit.protocols.internet.igmpv3.IGMP`
            is instantiated directly on a message of neither shape.

    """
    type_ = pkt['type']  # type: Enum_Type
    length = pkt['__length__']  # type: int

    if type_ == Enum_Type.IGMP_Membership_Query:
        return SchemaField(length=length, schema=Query)
    if type_ == Enum_Type.IGMPv3_Membership_Report:
        return SchemaField(length=length, schema=Report)
    raise ProtocolError(f'IGMPv3: unsupported message type: {type_!r}')


def query_extension_present(pkt: 'dict[str, Any]') -> 'bool':
    """Test function for :attr:`Query.ext`.

    Only a Query at least 12 octets long overall carries the extension
    (:rfc:`3376#section-7.1`): at least 4 octets past the 8-octet fixed
    portion. A :class:`Query` unpacked on its own, with no enclosing ``type``,
    decides by length alone.

    On the packing path ``'ext'`` is already in ``pkt``, and the question is
    whether an :class:`ext <QueryExtension>` value was given, since
    ``__length__`` is a placeholder there.

    Args:
        pkt: Packet data.

    Returns:
        Whether :attr:`Query.ext` should be parsed (unpacking) or packed
        (packing).

    """
    if 'ext' in pkt:
        return pkt['ext'] is not None
    return pkt['__length__'] >= 4


@schema_final
class QueryExtension(Schema):
    """Header schema for the IGMPv3 Query's source-list extension.

    Follows the 8-octet header every IGMP Query shares with IGMPv1/v2
    (:rfc:`3376#section-4.1`).

    """

    #: Resv/S Flag/QRV.
    flags: 'QueryFlags' = BitField(length=1, namespace={
        'resv': (0, 4),
        's_flag': (4, 1),
        'qrv': (5, 3),
    })
    #: Querier's Query Interval Code, as received on the wire; decoded into
    #: seconds by :meth:`IGMP.read <pcapkit.protocols.internet.igmpv3.IGMP.read>`
    #: per :rfc:`3376#section-4.1.7`.
    qqic: 'int' = UInt8Field()
    #: Number of source addresses.
    num_sources: 'int' = UInt16Field()
    #: Source addresses (:rfc:`3376#section-4.1.9`).
    sources: 'list[IPv4Address]' = ListField(
        length=lambda pkt: pkt['num_sources'] * 4,
        item_type=IPv4AddressField(),
    )
    #: Additional data (:rfc:`3376#section-4.1.10`): octets past the source
    #: list that a received Query may carry and that must be kept (to verify
    #: the checksum) but not otherwise acted on. Empty for a
    #: standards-conformant Query, since :meth:`IGMP.make
    #: <pcapkit.protocols.internet.igmpv3.IGMP.make>` never writes any.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, flags: 'QueryFlags', qqic: 'int', num_sources: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     sources: 'list[IPv4Address | str | bytes | int]',
                     payload: 'bytes | ProtocolBase | Schema') -> 'None': ...


@schema_final
class Query(Schema):
    """Header schema for an IGMPv3 Membership Query (:rfc:`3376#section-4.1`).

    The first 8 octets are the same shape IGMPv1/v2 share
    (:class:`~pcapkit.protocols.schema.internet.igmp.IGMP`); the extension is
    present only on a Query of 12 or more octets overall -- see
    :func:`query_extension_present`. An 8-octet Query, which this schema
    unpacks too (with :attr:`ext` :data:`None`), is not actually IGMPv3;
    :meth:`IGMP.read <pcapkit.protocols.internet.igmpv3.IGMP.read>` is what
    refuses it.

    """

    #: Max response code; the raw octet :meth:`IGMP.read
    #: <pcapkit.protocols.internet.igmpv3.IGMP.read>` decodes per
    #: :rfc:`3376#section-4.1.1`.
    max_resp_code: 'int' = UInt8Field()
    #: Checksum: the 16-bit one's complement of the one's complement sum of
    #: the message, with the checksum field itself taken as zero and no
    #: pseudo-header involved -- the whole IP payload (:rfc:`3376#section-4.1.2`).
    checksum: 'bytes' = BytesField(length=2)
    #: Group address.
    group: 'IPv4Address' = IPv4AddressField()
    #: Source-list extension (:rfc:`3376#section-4.1`), present only on a
    #: Query at least 12 octets long overall; :data:`None` otherwise -- see
    #: :func:`query_extension_present`.
    ext: 'Optional[QueryExtension]' = ConditionalField(
        SchemaField(length=lambda pkt: pkt['__length__'], schema=QueryExtension),
        query_extension_present,
    )
    #: Payload, empty for a well-formed IGMPv3 Query. Only ever actually
    #: holds anything when :attr:`ext` is :data:`None`: when it is not,
    #: :attr:`ext` was handed the whole remaining length, so this field's own
    #: share of it is always empty, and :meth:`get_payload` reads
    #: :attr:`QueryExtension.payload <QueryExtension>` instead -- see there.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, max_resp_code: 'int', checksum: 'bytes',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     group: 'IPv4Address | str | bytes | int', ext: 'Optional[QueryExtension]',
                     payload: 'bytes | ProtocolBase | Schema') -> 'None': ...

    def get_payload(self, name: 'Optional[str]' = None) -> 'bytes':
        """Get payload of :class:`Query`.

        Args:
            name: Unused; kept for signature compatibility with
                :meth:`Schema.get_payload <pcapkit.protocols.schema.schema.Schema.get_payload>`.

        Returns:
            :attr:`ext`'s own payload when :attr:`ext` is not :data:`None`
            (see :attr:`payload`'s docstring for why); :attr:`payload`
            itself otherwise.

        """
        if self.ext is not None:
            return self.ext.get_payload()  # pylint: disable=no-member
        return super().get_payload('payload')


@schema_final
class GroupRecord(Schema):
    """Header schema for an IGMPv3 group record (:rfc:`3376#section-4.2.4`)."""

    #: Record type.
    record_type: 'Enum_RecordType' = EnumField(length=1, namespace=Enum_RecordType)
    #: Auxiliary data length, in 32-bit words.
    aux_data_len: 'int' = UInt8Field(default=0)
    #: Number of source addresses.
    num_sources: 'int' = UInt16Field()
    #: Multicast address.
    multicast_address: 'IPv4Address' = IPv4AddressField()
    #: Source addresses (:rfc:`3376#section-4.2.9`).
    sources: 'list[IPv4Address]' = ListField(
        length=lambda pkt: pkt['num_sources'] * 4,
        item_type=IPv4AddressField(),
    )
    #: Auxiliary data (:rfc:`3376#section-4.2.10`).
    aux_data: 'bytes' = BytesField(
        length=lambda pkt: pkt['aux_data_len'] * 4,
        default=b'',
    )

    if TYPE_CHECKING:
        def __init__(self, record_type: 'Enum_RecordType | int', aux_data_len: 'int',
                     num_sources: 'int', multicast_address: 'IPv4Address | str | bytes | int',
                     sources: 'list[IPv4Address | str | bytes | int]',
                     aux_data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@schema_final
class Report(Schema):
    """Header schema for an IGMPv3 Membership Report's body (:rfc:`3376#section-4.2`).

    Note:
        :attr:`records` is first read with the whole remaining length, since
        the declared count cannot size it in octets (cf.
        :class:`~pcapkit.protocols.schema.internet.hip.LocatorSetParameter`).
        :meth:`post_process` keeps only the first :attr:`num_group_records`
        records and gives the rest to :attr:`payload`, which is
        :rfc:`3376#section-4.2.11`'s "Additional Data".

    """

    #: Reserved.
    reserved_1: 'int' = UInt8Field(default=0)
    #: Checksum.
    checksum: 'bytes' = BytesField(length=2)
    #: Reserved.
    reserved_2: 'bytes' = BytesField(length=2, default=b'\x00\x00')
    #: Number of group records, as received on the wire.
    num_group_records: 'int' = UInt16Field()
    #: Group records; see :meth:`post_process` for how this is kept to
    #: exactly :attr:`num_group_records` entries.
    records: 'list[GroupRecord]' = ListField(
        length=lambda pkt: pkt['__length__'],
        item_type=SchemaField(schema=GroupRecord),
    )
    #: Payload; empty for a standards-conformant message with
    #: :attr:`num_group_records` matching the octets actually present.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, reserved_1: 'int', checksum: 'bytes', reserved_2: 'bytes',
                     num_group_records: 'int', records: 'list[GroupRecord]',
                     payload: 'bytes | ProtocolBase | Schema') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':  # pylint: disable=unused-argument
        """Trim :attr:`records` to :attr:`num_group_records` and reclaim the rest as :attr:`payload`.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        if len(self.records) > self.num_group_records:
            raw = self.__buffer__['records']
            file = io.BytesIO(raw)
            valid = []  # type: list[GroupRecord]
            for _ in range(self.num_group_records):
                try:
                    valid.append(GroupRecord.unpack(file))  # type: ignore[call-arg,misc]
                except StreamEOFError:  # pragma: no cover
                    break
            consumed = file.tell()

            # NOTE: ``get_payload`` reads ``__buffer__``, and ``prepare()`` clears
            # ``__updated__`` after this runs, so the buffer must be set here too.
            self.records = valid
            self.payload = raw[consumed:]
            self.__buffer__['records'] = raw[:consumed]
            self.__buffer__['payload'] = raw[consumed:]
        return self


@schema_final
class IGMP(Schema):
    """Header schema for an IGMPv3 packet.

    :attr:`type` is common to both shapes IGMPv3 defines; everything past it
    is switched, by :func:`igmpv3_body_selector`, between :class:`Query` and
    :class:`Report` (:issue:`2439`, :issue:`2448`).

    Note:
        No :class:`~pcapkit.corekit.fields.misc.PayloadField` here: IGMP has no
        header field bounding the message, so :attr:`body` gets the whole
        length and keeps its trailing octets itself -- in
        :attr:`Query.payload` (or :attr:`QueryExtension.payload` when
        :attr:`Query.ext` is present), or :attr:`Report.payload`.
        :meth:`get_payload` delegates there.

    """

    #: Message type.
    type: 'Enum_Type' = EnumField(length=1, namespace=Enum_Type)
    #: Message body, switched on :attr:`type`.
    body: 'Query | Report' = SwitchField(selector=igmpv3_body_selector)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type | int', body: 'Query | Report | bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin

    def get_payload(self, name: 'Optional[str]' = None) -> 'bytes':  # pylint: disable=unused-argument
        """Get payload of :class:`IGMP`.

        Args:
            name: Unused; kept for signature compatibility with
                :meth:`Schema.get_payload <pcapkit.protocols.schema.schema.Schema.get_payload>`.

        Returns:
            Trailing octets of :attr:`body` -- see the class :class:`Note <IGMP>`
            above for exactly where each shape keeps them.

        """
        if isinstance(self.body, Schema):
            return self.body.get_payload()
        return b''
