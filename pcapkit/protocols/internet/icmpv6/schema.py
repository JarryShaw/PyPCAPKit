# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for ICMPv6 protocol"""

from typing import TYPE_CHECKING, cast

from pcapkit.const.icmpv6.type import Type as Enum_Type
from pcapkit.const.igmp.record_type import RecordType as Enum_RecordType
from pcapkit.corekit.const.ipheader import IP_MAX_LENGTH
from pcapkit.corekit.fields.collections import ListField
from pcapkit.corekit.fields.ipaddress import IPv6AddressField
from pcapkit.corekit.fields.misc import ConditionalField, PayloadField, SchemaField, SwitchField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt16Field, UInt32Field
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField
from pcapkit.protocols.schema import EnumSchema, Schema, schema_final
from pcapkit.utilities.contextvars import frame_depth
from pcapkit.utilities.exceptions import ProtocolError

__all__ = [
    'ICMPv6',

    'ICMPv6Type', 'Unknown', 'DestinationUnreachable', 'PacketTooBig', 'TimeExceeded',
    'ParameterProblem', 'Echo', 'MLDQuery', 'MLDv1', 'MLDv2Report',

    'MLDv2QueryExtension', 'MulticastAddressRecord',
]

if TYPE_CHECKING:
    from ipaddress import IPv6Address
    from typing import Any, Optional

    from typing_extensions import TypedDict

    from pcapkit.corekit.fields.field import FieldBase as Field

    class MLDv2QueryFlags(TypedDict):
        """MLDv2 Query flags octet.

        .. versionadded:: 1.7.0

        """

        #: Flags.
        flags: int
        #: Suppress Router-Side Processing flag.
        s_flag: int
        #: Querier's Robustness Variable.
        qrv: int


def icmpv6_data_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`ICMPv6.data` field.

    Args:
        pkt: Packet data.

    Returns:
        A :class:`~pcapkit.corekit.fields.misc.SchemaField` wrapped
        :class:`~pcapkit.protocols.internet.icmpv6.schema.ICMPv6Type` instance
        based on :attr:`ICMPv6.type <pcapkit.protocols.internet.icmpv6.schema.ICMPv6.type>`.

    """
    type = cast('Enum_Type', pkt['type'])
    schema = ICMPv6Type.registry[type]
    # NOTE: ``type``, ``code`` and ``checksum`` have already been deducted
    # from ``__length__``, so it is exactly the message body length.
    # NOTE: On its own a message is given the octets captured, so its body's length ends
    # with the data; inside a frame its lengths say where the message ends (#2848).
    packet = {} if frame_depth.get() else {'__data_end__': True}
    return SchemaField(length=cast('int', pkt['__length__']), schema=schema, packet=packet)


def mldv2_query_present(pkt: 'dict[str, Any]') -> 'bool':
    """Test function for :attr:`MLDQuery.ext`.

    A Query of 28 or more octets is MLDv2's, and one of fewer MLDv1's
    (:rfc:`9777#section-8.1`): 28 octets leave at least 4 past the 20 read
    before :attr:`MLDQuery.ext`, behind the 4 of the ICMPv6 header. A Query of
    25 to 27 octets, which neither version defines, reads as MLDv1, the octets
    past its 24 kept.

    On the packing path ``'ext'`` is already in ``pkt``, and the question is
    whether an :class:`ext <MLDv2QueryExtension>` value was given.

    Args:
        pkt: Packet data.

    Returns:
        Whether :attr:`MLDQuery.ext` should be parsed (unpacking) or packed
        (packing).

    .. versionadded:: 1.7.0

    """
    if 'ext' in pkt:
        return pkt['ext'] is not None
    return pkt['__length__'] >= 4


def mldv2_record_count(pkt: 'dict[str, Any]') -> 'int':
    """Count callback for :attr:`MLDv2Report.records`.

    Args:
        pkt: Packet data.

    Returns:
        :attr:`MLDv2Report.num_records`, for a message parsed on its own;
        otherwise ``-1``, counting none: inside a frame its lengths say where the
        message ends, and on the packing path ``'records'`` is already in
        ``pkt``. Records counted past the data are then a cut, which
        :meth:`Schema.unpack <pcapkit.protocols.schema.Schema.unpack>` records.

    Raises:
        ProtocolError: If the records counted, at the 20 fixed octets of each,
            behind the 8 octets ahead of them, reach past the
            :data:`~pcapkit.corekit.const.ipheader.IP_MAX_LENGTH` octets
            an IP payload holds, so the count is no cut but one the message
            cannot carry.

    .. versionadded:: 1.7.0

    """
    count = pkt.get('num_records')  # type: Optional[int]
    if count is None or 'records' in pkt or frame_depth.get():
        return -1
    # NOTE: The 8 octets ahead of the records count against the IP payload too.
    if 8 + 20 * count > IP_MAX_LENGTH:
        raise ProtocolError(f'ICMPv6: {count} multicast address records cannot fit in one IP payload')
    return count


@schema_final
class ICMPv6(Schema):
    """Header schema for ICMPv6 packet."""

    #: ICMPv6 type.
    type: 'Enum_Type' = EnumField(length=1, namespace=Enum_Type)
    #: ICMPv6 code.
    code: 'int' = UInt8Field()
    #: Checksum.
    checksum: 'bytes' = BytesField(length=2)
    #: Message body, selected by :attr:`type`.
    data: 'ICMPv6Type' = SwitchField(selector=icmpv6_data_selector)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Type', code: 'int', checksum: 'bytes',
                     data: 'bytes | ICMPv6Type') -> 'None': ...


class ICMPv6Type(EnumSchema[Enum_Type]):
    """Header schema for ICMPv6 type-specific message body."""

    __default__ = lambda: Unknown


@schema_final
class Unknown(ICMPv6Type):
    """Header schema for ICMPv6 message of unknown type."""

    #: Message body.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, data: 'bytes') -> 'None': ...


@schema_final
class DestinationUnreachable(ICMPv6Type, code=Enum_Type.Destination_Unreachable):
    """Header schema for ICMPv6 Destination Unreachable message."""

    #: Unused.
    unused: 'bytes' = PaddingField(length=4)
    #: As much of the invoking packet as fits the minimum IPv6 MTU.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, unused: 'bytes', data: 'bytes') -> 'None': ...


@schema_final
class PacketTooBig(ICMPv6Type, code=Enum_Type.Packet_Too_Big):
    """Header schema for ICMPv6 Packet Too Big message."""

    #: MTU of the link that could not forward the invoking packet.
    mtu: 'int' = UInt32Field()
    #: As much of the invoking packet as fits the minimum IPv6 MTU.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, mtu: 'int', data: 'bytes') -> 'None': ...


@schema_final
class TimeExceeded(ICMPv6Type, code=Enum_Type.Time_Exceeded):
    """Header schema for ICMPv6 Time Exceeded message."""

    #: Unused.
    unused: 'bytes' = PaddingField(length=4)
    #: As much of the invoking packet as fits the minimum IPv6 MTU.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, unused: 'bytes', data: 'bytes') -> 'None': ...


@schema_final
class ParameterProblem(ICMPv6Type, code=Enum_Type.Parameter_Problem):
    """Header schema for ICMPv6 Parameter Problem message."""

    #: Pointer.
    pointer: 'int' = UInt32Field()
    #: As much of the invoking packet as fits the minimum IPv6 MTU.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, pointer: 'int', data: 'bytes') -> 'None': ...


@schema_final
class Echo(ICMPv6Type, code=[Enum_Type.Echo_Request, Enum_Type.Echo_Reply]):
    """Header schema for ICMPv6 Echo Request/Reply message."""

    #: Identifier.
    id: 'int' = UInt16Field()
    #: Sequence number.
    seq: 'int' = UInt16Field()
    #: Data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, id: 'int', seq: 'int', data: 'bytes') -> 'None': ...  # pylint: disable=redefined-builtin


@schema_final
class MLDv2QueryExtension(Schema):
    """Header schema for the fields an MLDv2 Query adds (:rfc:`9777#section-5.1`).

    They follow the 24 octets of an MLDv1 Query (:rfc:`2710#section-3`).

    .. versionadded:: 1.7.0

    """

    #: Flags, S Flag and QRV.
    flags: 'MLDv2QueryFlags' = BitField(length=1, namespace={
        'flags': (0, 4),
        's_flag': (4, 1),
        'qrv': (5, 3),
    })
    #: Querier's Query Interval Code (:rfc:`9777#section-5.1.9`).
    qqic: 'int' = UInt8Field()
    #: Number of source addresses.
    num_sources: 'int' = UInt16Field()
    #: Source addresses (:rfc:`9777#section-5.1.11`).
    sources: 'list[IPv6Address]' = ListField(
        length=lambda pkt: pkt['num_sources'] * 16,
        item_type=IPv6AddressField(),
    )
    #: Additional data (:rfc:`9777#section-5.1.12`), empty for a conformant
    #: sender. What the message leaves, as a trailer takes it, so a cut ends in
    #: the field it falls in.
    data: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, flags: 'MLDv2QueryFlags', qqic: 'int', num_sources: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     sources: 'list[IPv6Address | str | bytes | int]', data: 'bytes') -> 'None': ...


@schema_final
class MLDQuery(ICMPv6Type, code=Enum_Type.Multicast_Listener_Query):
    """Header schema for an MLD Multicast Listener Query message.

    Its first 20 octets are those of an MLDv1 Query (:rfc:`2710#section-3`);
    :attr:`ext` holds what an MLDv2 Query adds (:rfc:`9777#section-5.1`), see
    :func:`mldv2_query_present`.

    .. versionadded:: 1.7.0

    """

    #: Maximum Response Delay of MLDv1, or Maximum Response Code of MLDv2.
    max_resp_code: 'int' = UInt16Field()
    #: Reserved.
    reserved: 'bytes' = BytesField(length=2)
    #: Multicast address.
    multicast_address: 'IPv6Address' = IPv6AddressField()
    #: Fields an MLDv2 Query adds, :data:`None` on an MLDv1 Query.
    ext: 'Optional[MLDv2QueryExtension]' = ConditionalField(
        SchemaField(length=lambda pkt: pkt['__length__'], schema=MLDv2QueryExtension),
        mldv2_query_present,
    )
    #: Octets past the 24 of an MLDv1 Query, what the message leaves; empty on
    #: an MLDv2 Query, whose :attr:`ext` holds them.
    data: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, max_resp_code: 'int', reserved: 'bytes',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     multicast_address: 'IPv6Address | str | bytes | int',
                     ext: 'Optional[MLDv2QueryExtension]', data: 'bytes') -> 'None': ...


@schema_final
class MLDv1(ICMPv6Type, code=[Enum_Type.Multicast_Listener_Report, Enum_Type.Multicast_Listener_Done]):
    """Header schema for an MLDv1 Multicast Listener Report or Done message (:rfc:`2710#section-3`).

    .. versionadded:: 1.7.0

    """

    #: Maximum Response Delay, zero but in a Query.
    max_resp_delay: 'int' = UInt16Field()
    #: Reserved.
    reserved: 'bytes' = BytesField(length=2)
    #: Multicast address.
    multicast_address: 'IPv6Address' = IPv6AddressField()
    #: Octets past the 24 :rfc:`2710#section-3` defines, what the message
    #: leaves.
    data: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, max_resp_delay: 'int', reserved: 'bytes',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     multicast_address: 'IPv6Address | str | bytes | int', data: 'bytes') -> 'None': ...


@schema_final
class MulticastAddressRecord(Schema):
    """Header schema for an MLDv2 multicast address record (:rfc:`9777#section-5.2`).

    .. versionadded:: 1.7.0

    """

    #: Record type (:rfc:`9777#section-5.2.13`).
    record_type: 'Enum_RecordType' = EnumField(length=1, namespace=Enum_RecordType)
    #: Auxiliary data length, in 32-bit words.
    aux_data_len: 'int' = UInt8Field(default=0)
    #: Number of source addresses.
    num_sources: 'int' = UInt16Field()
    #: Multicast address.
    multicast_address: 'IPv6Address' = IPv6AddressField()
    #: Source addresses (:rfc:`9777#section-5.2.10`).
    sources: 'list[IPv6Address]' = ListField(
        length=lambda pkt: pkt['num_sources'] * 16,
        item_type=IPv6AddressField(),
    )
    #: Auxiliary data (:rfc:`9777#section-5.2.11`).
    aux_data: 'bytes' = BytesField(
        length=lambda pkt: pkt['aux_data_len'] * 4,
        default=b'',
    )

    if TYPE_CHECKING:
        def __init__(self, record_type: 'Enum_RecordType | int', aux_data_len: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     num_sources: 'int', multicast_address: 'IPv6Address | str | bytes | int',
                     sources: 'list[IPv6Address | str | bytes | int]', aux_data: 'bytes') -> 'None': ...


@schema_final
class MLDv2Report(ICMPv6Type, code=Enum_Type.Version_2_Multicast_Listener_Report):
    """Header schema for an MLDv2 Version 2 Multicast Listener Report message (:rfc:`9777#section-5.2`).

    Note:
        :attr:`records` is read with the whole remaining length, since the count
        cannot size it in octets; :meth:`post_process` keeps the first
        :attr:`num_records` and gives the rest to :attr:`data`, the message's
        Additional Data (:rfc:`9777#section-5.2.12`). Where the data ends before
        the records counted, see :func:`mldv2_record_count`.

    .. versionadded:: 1.7.0

    """

    #: Flags (:rfc:`9777#section-5.2.3`).
    flags: 'int' = UInt16Field()
    #: Number of multicast address records, as on the wire.
    num_records: 'int' = UInt16Field()
    #: Multicast address records.
    records: 'list[MulticastAddressRecord]' = ListField(
        length=lambda pkt: pkt['__length__'],
        item_type=SchemaField(schema=MulticastAddressRecord),
        count=mldv2_record_count,
    )
    #: Additional data, empty for a conformant sender.
    data: 'bytes' = PayloadField()

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':  # pylint: disable=unused-argument
        """Trim :attr:`records` to :attr:`num_records` and reclaim the rest as :attr:`data`.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        A capture that ends past the records kept ends inside :attr:`data`, so the
        short read :meth:`unpack` recorded on :attr:`records` is moved there.

        """
        if len(self.records) > self.num_records:
            raw = self.__buffer__['records']
            valid = self.records[:self.num_records]
            consumed = len(self.__fields__['records'].pack(valid, {}))

            self.records = valid
            self.data = raw[consumed:]
            self.__buffer__['records'] = raw[:consumed]
            self.__buffer__['data'] = raw[consumed:]

            record = self.__dict__.get('__short_read__')
            if record is not None and record[0] == 'records' and record[1] > consumed:
                self.__dict__['__short_read__'] = ('data', record[1] - consumed)
        return self

    if TYPE_CHECKING:
        def __init__(self, flags: 'int', num_records: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     records: 'list[MulticastAddressRecord]', data: 'bytes') -> 'None': ...
