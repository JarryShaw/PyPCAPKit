# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for ICMPv6 protocol"""

from typing import TYPE_CHECKING, cast

from pcapkit.const.icmpv6.nd_option import NDOption as Enum_NDOption
from pcapkit.const.icmpv6.type import Type as Enum_Type
from pcapkit.const.igmp.record_type import RecordType as Enum_RecordType
from pcapkit.corekit.const.ipheader import IP_MAX_LENGTH
from pcapkit.corekit.fields.collections import ListField, OptionField
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
    'RouterSolicitation', 'RouterAdvertisement', 'NeighborSolicitation', 'NeighborAdvertisement',
    'Redirect',

    'MLDv2QueryExtension', 'MulticastAddressRecord',

    'NDOption', 'UnknownOption', 'LinkLayerAddressOption', 'PrefixInformationOption',
    'RedirectedHeaderOption', 'MTUOption', 'AdvertisementIntervalOption',
    'HomeAgentInformationOption', 'NonceOption', 'RouteInformationOption', 'RDNSSOption',
    'RAFlagsExtensionOption', 'DNSSLOption', 'CaptivePortalOption', 'PREF64Option',
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

    class RAFlags(TypedDict):
        """Router Advertisement flags octet, as IANA's Router Advertisement Flags assigns it.

        .. versionadded:: 1.9.0

        """

        #: Managed Address Configuration flag.
        m_flag: int
        #: Other Configuration flag.
        o_flag: int
        #: Mobile IPv6 Home Agent flag.
        h_flag: int
        #: Default Router Preference.
        prf: int
        #: Neighbor Discovery Proxy flag.
        p_flag: int
        #: SNAC Router flag.
        s_flag: int
        #: Reserved.
        reserved: int

    class NAFlags(TypedDict):
        """Neighbor Advertisement flags and Reserved (:rfc:`4861#section-4.4`).

        .. versionadded:: 1.9.0

        """

        #: Router flag.
        r_flag: int
        #: Solicited flag.
        s_flag: int
        #: Override flag.
        o_flag: int
        #: Reserved.
        reserved: int

    class PrefixInformationFlags(TypedDict):
        """Prefix Information option flags octet, as IANA's Prefix Information Option Flags assigns it.

        .. versionadded:: 1.9.0

        """

        #: On-link flag.
        l_flag: int
        #: Autonomous Address Configuration flag.
        a_flag: int
        #: Router Address flag.
        r_flag: int
        #: DHCPv6-PD Preferred flag.
        p_flag: int
        #: Reserved1.
        reserved1: int

    class RouteInformationFlags(TypedDict):
        """Route Information option Reserved and Prf octet (:rfc:`4191#section-2.3`).

        .. versionadded:: 1.9.0

        """

        #: Reserved, the high-order 3 bits.
        reserved1: int
        #: Route Preference.
        prf: int
        #: Reserved, the low-order 3 bits.
        reserved2: int

    class PREF64Lifetime(TypedDict):
        """PREF64 option Scaled Lifetime and PLC (:rfc:`8781#section-4`).

        .. versionadded:: 1.9.0

        """

        #: Scaled Lifetime, in units of 8 seconds.
        scaled_lifetime: int
        #: Prefix Length Code.
        plc: int


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


def nd_option_length(pkt: 'dict[str, Any]', offset: 'int') -> 'int':
    """Octets an ND option's Length declares past its first ``offset``.

    The Length counts the whole option in units of 8 octets
    (:rfc:`4861#section-4.6`).

    Args:
        pkt: Option unpacked so far.
        offset: Octets of the option ahead of the field sized.

    Returns:
        ``Length * 8 - offset``, or ``0`` for a Length too small to reach past
        ``offset``, an option
        :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_nd_options`
        refuses.

    .. versionadded:: 1.9.0

    """
    return max(pkt['length'] * 8 - offset, 0)


def rdnss_address_length(pkt: 'dict[str, Any]') -> 'int':
    """Length of :attr:`RDNSSOption.addresses`.

    Args:
        pkt: Option unpacked so far.

    Returns:
        16 octets for each of the ``(Length - 1) / 2`` addresses
        (:rfc:`8106#section-5.1`). A Length below 3 or even is one
        :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_opt_rdnss`
        refuses (:rfc:`8106#section-5.3.1`).

    .. versionadded:: 1.9.0

    """
    return max(pkt['length'] - 1, 0) // 2 * 16


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


class NDOption(EnumSchema[Enum_NDOption]):
    """Header schema for ICMPv6 Neighbor Discovery options (:rfc:`4861#section-4.6`).

    .. versionadded:: 1.9.0

    """

    __default__ = lambda: UnknownOption

    #: Option type.
    type: 'Enum_NDOption' = EnumField(length=1, namespace=Enum_NDOption)
    #: Option length, in units of 8 octets, type and length included.
    length: 'int' = UInt8Field()

    @classmethod
    def pre_unpack(cls, packet: 'dict[str, Any]') -> 'None':
        """Prepare ``packet`` data for unpacking process.

        Args:
            packet: packet data

        An option of a message parsed on its own, as
        :data:`~pcapkit.utilities.contextvars.frame_depth` tells, is read with
        ``__data_end__``: its octets end at most with the data, where the
        capture cut them (:issue:`2880`), so a field past the cut does not
        warn.

        """
        if not frame_depth.get():
            packet['__data_end__'] = True


@schema_final
class UnknownOption(NDOption):
    """Header schema for an ND option of a type not decoded.

    .. versionadded:: 1.9.0

    """

    #: Option data.
    data: 'bytes' = BytesField(length=lambda pkt: nd_option_length(pkt, 2))

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', data: 'bytes') -> 'None': ...


@schema_final
class LinkLayerAddressOption(NDOption, code=[Enum_NDOption.Source_Link_layer_Address,
                                             Enum_NDOption.Target_Link_layer_Address]):
    """Header schema for Source and Target Link-layer Address options (:rfc:`4861#section-4.6.1`).

    .. versionadded:: 1.9.0

    """

    #: Link-layer address, laid out as the link's own specification gives.
    link_layer_address: 'bytes' = BytesField(length=lambda pkt: nd_option_length(pkt, 2))

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', link_layer_address: 'bytes') -> 'None': ...


@schema_final
class PrefixInformationOption(NDOption, code=Enum_NDOption.Prefix_Information):
    """Header schema for Prefix Information options (:rfc:`4861#section-4.6.2`).

    .. versionadded:: 1.9.0

    """

    #: Prefix length.
    prefix_length: 'int' = UInt8Field()
    #: Flags, as IANA's Prefix Information Option Flags assigns them.
    flags: 'PrefixInformationFlags' = BitField(length=1, namespace={
        'l_flag': (0, 1),
        'a_flag': (1, 1),
        'r_flag': (2, 1),
        'p_flag': (3, 1),
        'reserved1': (4, 4),
    })
    #: Valid lifetime, in seconds.
    valid_lifetime: 'int' = UInt32Field()
    #: Preferred lifetime, in seconds.
    preferred_lifetime: 'int' = UInt32Field()
    #: Reserved2.
    reserved2: 'bytes' = BytesField(length=4)
    #: Prefix.
    prefix: 'IPv6Address' = IPv6AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', prefix_length: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     flags: 'PrefixInformationFlags', valid_lifetime: 'int', preferred_lifetime: 'int',
                     reserved2: 'bytes', prefix: 'IPv6Address | str | bytes | int') -> 'None': ...


@schema_final
class RedirectedHeaderOption(NDOption, code=Enum_NDOption.Redirected_Header):
    """Header schema for Redirected Header options (:rfc:`4861#section-4.6.3`).

    .. versionadded:: 1.9.0

    """

    #: Reserved.
    reserved: 'bytes' = BytesField(length=6)
    #: As much of the redirected packet as fits.
    data: 'bytes' = BytesField(length=lambda pkt: nd_option_length(pkt, 8))

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', reserved: 'bytes', data: 'bytes') -> 'None': ...


@schema_final
class MTUOption(NDOption, code=Enum_NDOption.MTU):
    """Header schema for MTU options (:rfc:`4861#section-4.6.4`).

    .. versionadded:: 1.9.0

    """

    #: Reserved.
    reserved: 'bytes' = BytesField(length=2)
    #: Recommended MTU of the link.
    mtu: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', reserved: 'bytes', mtu: 'int') -> 'None': ...


@schema_final
class AdvertisementIntervalOption(NDOption, code=Enum_NDOption.Advertisement_Interval_Option):
    """Header schema for Advertisement Interval options (:rfc:`6275#section-7.3`).

    .. versionadded:: 1.9.0

    """

    #: Reserved.
    reserved: 'bytes' = BytesField(length=2)
    #: Advertisement interval, in milliseconds.
    interval: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', reserved: 'bytes', interval: 'int') -> 'None': ...


@schema_final
class HomeAgentInformationOption(NDOption, code=Enum_NDOption.Home_Agent_Information_Option):
    """Header schema for Home Agent Information options (:rfc:`6275#section-7.4`).

    .. versionadded:: 1.9.0

    """

    #: Reserved.
    reserved: 'bytes' = BytesField(length=2)
    #: Home agent preference.
    preference: 'int' = UInt16Field()
    #: Home agent lifetime, in seconds.
    lifetime: 'int' = UInt16Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', reserved: 'bytes',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     preference: 'int', lifetime: 'int') -> 'None': ...


@schema_final
class NonceOption(NDOption, code=Enum_NDOption.Nonce_option):
    """Header schema for Nonce options (:rfc:`3971#section-5.3.2`).

    .. versionadded:: 1.9.0

    """

    #: Nonce.
    nonce: 'bytes' = BytesField(length=lambda pkt: nd_option_length(pkt, 2))

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', nonce: 'bytes') -> 'None': ...


@schema_final
class RouteInformationOption(NDOption, code=Enum_NDOption.Route_Information_Option):
    """Header schema for Route Information options (:rfc:`4191#section-2.3`).

    .. versionadded:: 1.9.0

    """

    #: Prefix length.
    prefix_length: 'int' = UInt8Field()
    #: Reserved, Route Preference and Reserved.
    flags: 'RouteInformationFlags' = BitField(length=1, namespace={
        'reserved1': (0, 3),
        'prf': (3, 2),
        'reserved2': (5, 3),
    })
    #: Route lifetime, in seconds.
    lifetime: 'int' = UInt32Field()
    #: Prefix, as many octets of it as the Length leaves.
    prefix: 'bytes' = BytesField(length=lambda pkt: nd_option_length(pkt, 8))

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', prefix_length: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     flags: 'RouteInformationFlags', lifetime: 'int', prefix: 'bytes') -> 'None': ...


@schema_final
class RDNSSOption(NDOption, code=Enum_NDOption.Recursive_DNS_Server_Option):
    """Header schema for Recursive DNS Server options (:rfc:`8106#section-5.1`).

    .. versionadded:: 1.9.0

    """

    #: Reserved.
    reserved: 'bytes' = BytesField(length=2)
    #: Lifetime, in seconds.
    lifetime: 'int' = UInt32Field()
    #: Addresses of the recursive DNS servers.
    addresses: 'list[IPv6Address]' = ListField(
        length=rdnss_address_length,
        item_type=IPv6AddressField(),
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', reserved: 'bytes',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     lifetime: 'int', addresses: 'list[IPv6Address | str | bytes | int]') -> 'None': ...


@schema_final
class RAFlagsExtensionOption(NDOption, code=Enum_NDOption.RA_Flags_Extension_Option):
    """Header schema for RA Flags Extension options (:rfc:`5175#section-4`).

    .. versionadded:: 1.9.0

    """

    #: Bits 8 onwards of IANA's Router Advertisement Flags.
    bits: 'bytes' = BytesField(length=lambda pkt: nd_option_length(pkt, 2))

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', bits: 'bytes') -> 'None': ...


@schema_final
class DNSSLOption(NDOption, code=Enum_NDOption.DNS_Search_List_Option):
    """Header schema for DNS Search List options (:rfc:`8106#section-5.2`).

    .. versionadded:: 1.9.0

    """

    #: Reserved.
    reserved: 'bytes' = BytesField(length=2)
    #: Lifetime, in seconds.
    lifetime: 'int' = UInt32Field()
    #: Domain names, each uncompressed (:rfc:`1035#section-3.1`), then zero
    #: padding.
    names: 'bytes' = BytesField(length=lambda pkt: nd_option_length(pkt, 8))

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', reserved: 'bytes',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     lifetime: 'int', names: 'bytes') -> 'None': ...


@schema_final
class CaptivePortalOption(NDOption, code=Enum_NDOption.DHCP_Captive_Portal):
    """Header schema for Captive-Portal options (:rfc:`8910#section-2.3`).

    .. versionadded:: 1.9.0

    """

    #: URI, then NUL padding.
    uri: 'bytes' = BytesField(length=lambda pkt: nd_option_length(pkt, 2))

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', uri: 'bytes') -> 'None': ...


@schema_final
class PREF64Option(NDOption, code=Enum_NDOption.PREF64_option):
    """Header schema for PREF64 options (:rfc:`8781#section-4`).

    .. versionadded:: 1.9.0

    """

    #: Scaled Lifetime and Prefix Length Code.
    lifetime: 'PREF64Lifetime' = BitField(length=2, namespace={
        'scaled_lifetime': (0, 13),
        'plc': (13, 3),
    })
    #: Highest 96 bits of the prefix.
    prefix: 'bytes' = BytesField(length=12)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_NDOption', length: 'int', lifetime: 'PREF64Lifetime',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     prefix: 'bytes') -> 'None': ...


class NDOptionField(OptionField[NDOption]):
    """The option list closing a Neighbor Discovery message (:rfc:`4861#section-4.6`).

    The list runs to the end of the message, which a message parsed on its own
    knows only as the end of the data.

    .. versionadded:: 1.9.0

    """

    def _accepts_short_read(self, option: 'NDOption') -> 'bool':  # pylint: disable=unused-argument
        """Whether an option that read past the end of the data may stand.

        Args:
            option: Option just unpacked, which read short.

        Returns:
            Whether the message was parsed on its own, as
            :data:`~pcapkit.utilities.contextvars.frame_depth` tells: its data
            then ends where it was cut (:issue:`2880`), and the option keeps the
            short read its schema records. Inside a frame its lengths say where
            the message ends, so an option past them is refused.

        """
        return not frame_depth.get()


def nd_options() -> 'NDOptionField':
    """The option list of a Neighbor Discovery message.

    Returns:
        A list of :class:`NDOption` running to the end of the message.

    .. versionadded:: 1.9.0

    """
    return NDOptionField(
        length=lambda pkt: pkt['__length__'],
        base_schema=NDOption,
        type_name='type',
        registry=NDOption.registry,
        eool=None,
    )


@schema_final
class RouterSolicitation(ICMPv6Type, code=Enum_Type.Router_Solicitation):
    """Header schema for Router Solicitation messages (:rfc:`4861#section-4.1`).

    .. versionadded:: 1.9.0

    """

    #: Reserved.
    reserved: 'bytes' = BytesField(length=4)
    #: Options.
    options: 'list[NDOption]' = nd_options()

    if TYPE_CHECKING:
        def __init__(self, reserved: 'bytes', options: 'list[NDOption | bytes]') -> 'None': ...


@schema_final
class RouterAdvertisement(ICMPv6Type, code=Enum_Type.Router_Advertisement):
    """Header schema for Router Advertisement messages (:rfc:`4861#section-4.2`).

    .. versionadded:: 1.9.0

    """

    #: Current hop limit.
    cur_hop_limit: 'int' = UInt8Field()
    #: Flags, as IANA's Router Advertisement Flags assigns them.
    flags: 'RAFlags' = BitField(length=1, namespace={
        'm_flag': (0, 1),
        'o_flag': (1, 1),
        'h_flag': (2, 1),
        'prf': (3, 2),
        'p_flag': (5, 1),
        's_flag': (6, 1),
        'reserved': (7, 1),
    })
    #: Router lifetime, in seconds.
    router_lifetime: 'int' = UInt16Field()
    #: Reachable time, in milliseconds.
    reachable_time: 'int' = UInt32Field()
    #: Retransmission timer, in milliseconds.
    retrans_timer: 'int' = UInt32Field()
    #: Options.
    options: 'list[NDOption]' = nd_options()

    if TYPE_CHECKING:
        def __init__(self, cur_hop_limit: 'int', flags: 'RAFlags', router_lifetime: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     reachable_time: 'int', retrans_timer: 'int', options: 'list[NDOption | bytes]') -> 'None': ...


@schema_final
class NeighborSolicitation(ICMPv6Type, code=Enum_Type.Neighbor_Solicitation):
    """Header schema for Neighbor Solicitation messages (:rfc:`4861#section-4.3`).

    .. versionadded:: 1.9.0

    """

    #: Reserved.
    reserved: 'bytes' = BytesField(length=4)
    #: Target address.
    target_address: 'IPv6Address' = IPv6AddressField()
    #: Options.
    options: 'list[NDOption]' = nd_options()

    if TYPE_CHECKING:
        def __init__(self, reserved: 'bytes', target_address: 'IPv6Address | str | bytes | int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     options: 'list[NDOption | bytes]') -> 'None': ...


@schema_final
class NeighborAdvertisement(ICMPv6Type, code=Enum_Type.Neighbor_Advertisement):
    """Header schema for Neighbor Advertisement messages (:rfc:`4861#section-4.4`).

    .. versionadded:: 1.9.0

    """

    #: Router, Solicited and Override flags, and Reserved.
    flags: 'NAFlags' = BitField(length=4, namespace={
        'r_flag': (0, 1),
        's_flag': (1, 1),
        'o_flag': (2, 1),
        'reserved': (3, 29),
    })
    #: Target address.
    target_address: 'IPv6Address' = IPv6AddressField()
    #: Options.
    options: 'list[NDOption]' = nd_options()

    if TYPE_CHECKING:
        def __init__(self, flags: 'NAFlags', target_address: 'IPv6Address | str | bytes | int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     options: 'list[NDOption | bytes]') -> 'None': ...


@schema_final
class Redirect(ICMPv6Type, code=Enum_Type.Redirect_Message):
    """Header schema for Redirect messages (:rfc:`4861#section-4.5`).

    .. versionadded:: 1.9.0

    """

    #: Reserved.
    reserved: 'bytes' = BytesField(length=4)
    #: Target address, the better first hop.
    target_address: 'IPv6Address' = IPv6AddressField()
    #: Destination address, the one redirected.
    destination_address: 'IPv6Address' = IPv6AddressField()
    #: Options.
    options: 'list[NDOption]' = nd_options()

    if TYPE_CHECKING:
        def __init__(self, reserved: 'bytes', target_address: 'IPv6Address | str | bytes | int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     destination_address: 'IPv6Address | str | bytes | int',
                     options: 'list[NDOption | bytes]') -> 'None': ...
