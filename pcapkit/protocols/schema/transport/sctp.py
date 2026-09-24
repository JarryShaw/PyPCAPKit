# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for stream control transmission protocol"""

from typing import TYPE_CHECKING

from pcapkit.const.reg.apptype import AppType as Enum_AppType
from pcapkit.const.reg.apptype import TransportProtocol as Enum_TransportProtocol
from pcapkit.const.sctp.cause_code import CauseCode as Enum_CauseCode
from pcapkit.const.sctp.chunk import Chunk as Enum_Chunk
from pcapkit.const.sctp.parameter import Parameter as Enum_Parameter
from pcapkit.const.sctp.payload_protocol_identifier import \
    PayloadProtocolIdentifier as Enum_PayloadProtocolIdentifier
from pcapkit.corekit.fields.collections import ListField, OptionField
from pcapkit.corekit.fields.ipaddress import IPv4AddressField, IPv6AddressField
from pcapkit.corekit.fields.misc import SchemaField
from pcapkit.corekit.fields.numbers import EnumField, UInt16Field, UInt32Field
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField
from pcapkit.protocols.schema.schema import EnumSchema, Schema, schema_final
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING

__all__ = [
    'SCTP',

    'Chunk',
    'UnknownChunk', 'DATAChunk', 'INITChunk', 'INITACKChunk', 'SACKChunk',
    'HeartbeatChunk', 'HeartbeatACKChunk', 'AbortChunk', 'ShutdownChunk',
    'ShutdownACKChunk', 'ErrorChunk', 'CookieEchoChunk', 'CookieACKChunk',
    'ShutdownCompleteChunk',

    'GapAckBlock',

    'Parameter',
    'UnknownParameter', 'HeartbeatInfoParameter', 'IPv4AddressParameter',
    'IPv6AddressParameter', 'StateCookieParameter', 'UnrecognizedParameter',
    'CookiePreservativeParameter', 'HostNameAddressParameter',
    'SupportedAddressTypesParameter',

    'ErrorCause',
    'UnknownCause', 'InvalidStreamIdentifierCause', 'MissingMandatoryParameterCause',
    'StaleCookieCause', 'OutOfResourceCause', 'UnresolvableAddressCause',
    'UnrecognizedChunkTypeCause', 'InvalidMandatoryParameterCause',
    'UnrecognizedParametersCause', 'NoUserDataCause',
    'CookieReceivedWhileShuttingDownCause',
    'RestartOfAnAssociationWithNewAddressesCause', 'UserInitiatedAbortCause',
    'ProtocolViolationCause',
]

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Any, Callable

    from pcapkit.protocols.protocol import ProtocolBase

if SPHINX_TYPE_CHECKING:  # pragma: no cover
    from typing_extensions import TypedDict

    class DATAChunkFlags(TypedDict):
        """SCTP DATA chunk flags."""

        #: (I)mmediate bit, i.e., request a SACK chunk without delay.
        I: int
        #: (U)nordered bit, i.e., no stream sequence number is assigned.
        U: int
        #: (B)eginning fragment bit.
        B: int
        #: (E)nding fragment bit.
        E: int

    class TBitFlags(TypedDict):
        """SCTP chunk flags carrying only the T bit, i.e., ABORT and
        SHUTDOWN COMPLETE chunks."""

        #: T bit, i.e., the verification tag has been reflected.
        T: int


def padding_length(pkt: 'dict[str, Any]') -> 'int':
    """Length of the trailing padding of an SCTP type-length-value structure.

    Chunks, chunk parameters and error causes are all padded with all-zero
    bytes to a multiple of four bytes, and per :rfc:`9260#section-3.2` that
    padding is **not** counted in the ``length`` field. The padding is still
    on the wire, though, so it has to be consumed for the enclosing list to
    stay aligned.

    Args:
        pkt: Packet data.

    Returns:
        Number of padding bytes, clamped to the number of bytes left in the
        enclosing structure, since :rfc:`9260#section-3.2` allows the final
        padding of a packet to be omitted.

    """
    length = pkt.get('length') or 0
    padding = -length % 4

    remaining = pkt.get('__length__')
    if not isinstance(remaining, int) or remaining < 0:
        return padding
    return min(padding, remaining)


def bounded(length: 'Callable[[dict[str, Any]], int]') -> 'Callable[[dict[str, Any]], int]':
    """Clamp a list field's computed length to the bytes actually available.

    Args:
        length: Callback computing the field's nominal length.

    Returns:
        A callback returning that length, never exceeding the bytes left in the
        enclosing structure.

    A count field and the list it counts can disagree on a malformed packet, and
    :meth:`ListField.unpack <pcapkit.corekit.fields.collections.ListField.unpack>`
    subtracts the *parsed* size of each item from its budget -- so a
    :class:`~pcapkit.corekit.fields.misc.SchemaField` item that runs out of bytes
    parses to nothing, subtracts nothing, and the loop never terminates. Clamping
    to the bytes on hand turns that hang into a short list, which the read
    handlers then reject against the declared length.

    Only list fields are wrapped: :meth:`ListField.pack
    <pcapkit.corekit.fields.collections.ListField.pack>` ignores the length
    entirely, so clamping cannot truncate anything on construction.

    """
    def callback(pkt: 'dict[str, Any]') -> 'int':
        value = length(pkt)
        remaining = pkt.get('__length__')
        if isinstance(remaining, int) and remaining >= 0:
            return min(value, remaining)
        return value
    return callback


def nested_length(base: 'int') -> 'Callable[[dict[str, Any]], int]':
    """Build a length callback for a chunk's nested type-length-value list.

    Args:
        base: Size of the chunk's fixed-length fields, including the four-byte
            chunk header.

    Returns:
        A callback returning the size of the chunk's nested list *including* the
        chunk's own trailing padding.

    The chunks that carry a nested list -- INIT, INIT ACK, HEARTBEAT,
    HEARTBEAT ACK, ABORT and ERROR -- deliberately have no separate
    :class:`~pcapkit.corekit.fields.strings.PaddingField`, and fold the chunk's
    trailing padding into the nested list's own span instead. There are two
    reasons, and both matter:

    * On parsing, a sender is allowed by :rfc:`9260#section-3.2` to leave the
      final parameter's padding out of the chunk length, so the padding has to
      be consumed whether or not the length accounts for it. Folding it into the
      list's span does that, and leaves it visible as the field's
      ``__option_padding__``.
    * On construction, a separate padding field could not compute its own size:
      :meth:`Schema.pack <pcapkit.protocols.schema.schema.Schema.pack>` passes
      one shared ``packet`` mapping down into the nested schemas, and each
      nested parameter overwrites ``packet['length']`` with *its* length, so a
      trailing field would size itself from the last parameter rather than from
      the chunk. Folding avoids the question: the constructors always declare a
      chunk length that already covers every parameter's padding, hence a
      multiple of four, hence no chunk-level padding to emit.

    """
    def callback(pkt: 'dict[str, Any]') -> 'int':
        length = pkt.get('length') or 0
        return max(length - base + (-length % 4), 0)
    return callback


class PortEnumField(EnumField):
    """Enumerated value for protocol fields.

    Args:
        length: Field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        default: Field default value, if any.
        signed: Whether the field is signed.
        byteorder: Field byte order.
        bit_length: Field bit length.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    Important:
        This class is specifically designed for :class:`~pcapkit.const.reg.apptype.AppType`
        as it is actually a :class:`~enum.StrEnum` class.

    """
    if TYPE_CHECKING:
        _namespace: 'Enum_AppType'

    def pre_process(self, value: 'int | Enum_AppType', packet: 'dict[str, Any]') -> 'int | bytes':
        """Process field value before construction (packing).

        Arguments:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        """
        if isinstance(value, Enum_AppType):
            value = value.port
        return super().pre_process(value, packet)

    def post_process(self, value: 'int | bytes', packet: 'dict[str, Any]') -> 'Enum_AppType':
        """Process field value after parsing (unpacked).

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        """
        value = super(EnumField, self).post_process(value, packet)
        return self._namespace.get(value, proto=Enum_TransportProtocol.sctp)


class ErrorCause(EnumSchema[Enum_CauseCode]):
    """Header schema for SCTP error causes."""

    __default__ = lambda: UnknownCause

    #: Cause code.
    code: 'Enum_CauseCode' = EnumField(length=2, namespace=Enum_CauseCode)
    #: Cause length.
    length: 'int' = UInt16Field()


@schema_final
class UnknownCause(ErrorCause):
    """Header schema for SCTP error causes with unknown cause codes."""

    #: Cause-specific information.
    value: 'bytes' = BytesField(length=lambda pkt: max(pkt['length'] - 4, 0))
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, code: 'Enum_CauseCode', length: 'int', value: 'bytes') -> 'None': ...


@schema_final
class InvalidStreamIdentifierCause(ErrorCause, code=Enum_CauseCode.Invalid_Stream_Identifier):
    """Header schema for SCTP invalid stream identifier error cause."""

    #: Stream identifier of the offending DATA chunk.
    stream_id: 'int' = UInt16Field()
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, code: 'Enum_CauseCode', length: 'int', stream_id: 'int') -> 'None': ...


@schema_final
class MissingMandatoryParameterCause(ErrorCause, code=Enum_CauseCode.Missing_Mandatory_Parameter):
    """Header schema for SCTP missing mandatory parameter error cause."""

    #: Number of missing parameters.
    num: 'int' = UInt32Field()
    #: Missing parameter types.
    types: 'list[Enum_Parameter]' = ListField(
        length=bounded(lambda pkt: min(max(pkt['num'], 0) * 2, max(pkt['length'] - 8, 0))),
        item_type=EnumField(length=2, namespace=Enum_Parameter),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, code: 'Enum_CauseCode', length: 'int', num: 'int',
                     types: 'list[Enum_Parameter]') -> 'None': ...


@schema_final
class StaleCookieCause(ErrorCause, code=Enum_CauseCode.Stale_Cookie):
    """Header schema for SCTP stale cookie error cause."""

    #: Measure of staleness, in microseconds.
    staleness: 'int' = UInt32Field()
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, code: 'Enum_CauseCode', length: 'int', staleness: 'int') -> 'None': ...


@schema_final
class OutOfResourceCause(ErrorCause, code=Enum_CauseCode.Out_of_Resource):
    """Header schema for SCTP out of resource error cause."""

    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, code: 'Enum_CauseCode', length: 'int') -> 'None': ...


@schema_final
class UnresolvableAddressCause(ErrorCause, code=Enum_CauseCode.Unresolvable_Address):
    """Header schema for SCTP unresolvable address error cause."""

    #: The offending address parameter, complete with its type and length.
    value: 'bytes' = BytesField(length=lambda pkt: max(pkt['length'] - 4, 0))
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, code: 'Enum_CauseCode', length: 'int', value: 'bytes') -> 'None': ...


@schema_final
class UnrecognizedChunkTypeCause(ErrorCause, code=Enum_CauseCode.Unrecognized_Chunk_Type):
    """Header schema for SCTP unrecognized chunk type error cause."""

    #: The unrecognized chunk, complete with its type, flags and length.
    value: 'bytes' = BytesField(length=lambda pkt: max(pkt['length'] - 4, 0))
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, code: 'Enum_CauseCode', length: 'int', value: 'bytes') -> 'None': ...


@schema_final
class InvalidMandatoryParameterCause(ErrorCause, code=Enum_CauseCode.Invalid_Mandatory_Parameter):
    """Header schema for SCTP invalid mandatory parameter error cause."""

    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, code: 'Enum_CauseCode', length: 'int') -> 'None': ...


@schema_final
class UnrecognizedParametersCause(ErrorCause, code=Enum_CauseCode.Unrecognized_Parameters):
    """Header schema for SCTP unrecognized parameters error cause."""

    #: The unrecognized parameters, complete with their types and lengths.
    value: 'bytes' = BytesField(length=lambda pkt: max(pkt['length'] - 4, 0))
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, code: 'Enum_CauseCode', length: 'int', value: 'bytes') -> 'None': ...


@schema_final
class NoUserDataCause(ErrorCause, code=Enum_CauseCode.No_User_Data):
    """Header schema for SCTP no user data error cause."""

    #: TSN of the offending DATA chunk.
    tsn: 'int' = UInt32Field()
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, code: 'Enum_CauseCode', length: 'int', tsn: 'int') -> 'None': ...


@schema_final
class CookieReceivedWhileShuttingDownCause(ErrorCause, code=Enum_CauseCode.Cookie_Received_While_Shutting_Down):  # pylint: disable=line-too-long
    """Header schema for SCTP cookie received while shutting down error cause."""

    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, code: 'Enum_CauseCode', length: 'int') -> 'None': ...


@schema_final
class RestartOfAnAssociationWithNewAddressesCause(ErrorCause, code=Enum_CauseCode.Restart_of_an_Association_with_New_Addresses):  # pylint: disable=line-too-long
    """Header schema for SCTP restart of an association with new addresses error cause."""

    #: The new address parameters, complete with their types and lengths.
    value: 'bytes' = BytesField(length=lambda pkt: max(pkt['length'] - 4, 0))
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, code: 'Enum_CauseCode', length: 'int', value: 'bytes') -> 'None': ...


@schema_final
class UserInitiatedAbortCause(ErrorCause, code=Enum_CauseCode.User_Initiated_Abort):
    """Header schema for SCTP user-initiated abort error cause."""

    #: Upper layer abort reason.
    info: 'bytes' = BytesField(length=lambda pkt: max(pkt['length'] - 4, 0))
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, code: 'Enum_CauseCode', length: 'int', info: 'bytes') -> 'None': ...


@schema_final
class ProtocolViolationCause(ErrorCause, code=Enum_CauseCode.Protocol_Violation):
    """Header schema for SCTP protocol violation error cause."""

    #: Additional information.
    info: 'bytes' = BytesField(length=lambda pkt: max(pkt['length'] - 4, 0))
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, code: 'Enum_CauseCode', length: 'int', info: 'bytes') -> 'None': ...


class Parameter(EnumSchema[Enum_Parameter]):
    """Header schema for SCTP chunk parameters."""

    __default__ = lambda: UnknownParameter

    #: Parameter type.
    type: 'Enum_Parameter' = EnumField(length=2, namespace=Enum_Parameter)
    #: Parameter length.
    length: 'int' = UInt16Field()


@schema_final
class UnknownParameter(Parameter):
    """Header schema for SCTP chunk parameters with unknown types."""

    #: Parameter value.
    value: 'bytes' = BytesField(length=lambda pkt: max(pkt['length'] - 4, 0))
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', length: 'int', value: 'bytes') -> 'None': ...


@schema_final
class HeartbeatInfoParameter(Parameter, code=Enum_Parameter.Heartbeat_Info):
    """Header schema for SCTP heartbeat info parameter."""

    #: Sender-specific heartbeat info.
    info: 'bytes' = BytesField(length=lambda pkt: max(pkt['length'] - 4, 0))
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', length: 'int', info: 'bytes') -> 'None': ...


@schema_final
class IPv4AddressParameter(Parameter, code=Enum_Parameter.IPv4_Address):
    """Header schema for SCTP IPv4 address parameter."""

    #: IPv4 address of the sending endpoint.
    address: 'IPv4Address' = IPv4AddressField()
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', length: 'int',
                     address: 'IPv4Address | int | str | bytes') -> 'None': ...


@schema_final
class IPv6AddressParameter(Parameter, code=Enum_Parameter.IPv6_Address):
    """Header schema for SCTP IPv6 address parameter."""

    #: IPv6 address of the sending endpoint.
    address: 'IPv6Address' = IPv6AddressField()
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', length: 'int',
                     address: 'IPv6Address | int | str | bytes') -> 'None': ...


@schema_final
class StateCookieParameter(Parameter, code=Enum_Parameter.State_Cookie):
    """Header schema for SCTP state cookie parameter."""

    #: State cookie.
    cookie: 'bytes' = BytesField(length=lambda pkt: max(pkt['length'] - 4, 0))
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', length: 'int', cookie: 'bytes') -> 'None': ...


@schema_final
class UnrecognizedParameter(Parameter, code=Enum_Parameter.Unrecognized_Parameter):
    """Header schema for SCTP unrecognized parameter parameter."""

    #: The unrecognized parameter, complete with its type and length.
    value: 'bytes' = BytesField(length=lambda pkt: max(pkt['length'] - 4, 0))
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', length: 'int', value: 'bytes') -> 'None': ...


@schema_final
class CookiePreservativeParameter(Parameter, code=Enum_Parameter.Cookie_Preservative):
    """Header schema for SCTP cookie preservative parameter."""

    #: Suggested cookie life-span increment, in milliseconds.
    increment: 'int' = UInt32Field()
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', length: 'int', increment: 'int') -> 'None': ...


@schema_final
class HostNameAddressParameter(Parameter, code=Enum_Parameter.Host_Name_Address):
    """Header schema for SCTP host name address parameter."""

    #: Host name, including at least one null terminator.
    name: 'bytes' = BytesField(length=lambda pkt: max(pkt['length'] - 4, 0))
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', length: 'int', name: 'bytes') -> 'None': ...


@schema_final
class SupportedAddressTypesParameter(Parameter, code=Enum_Parameter.Supported_Address_Types):
    """Header schema for SCTP supported address types parameter."""

    #: Supported address types, given as address parameter types.
    types: 'list[Enum_Parameter]' = ListField(
        length=bounded(lambda pkt: max(pkt['length'] - 4, 0)),
        item_type=EnumField(length=2, namespace=Enum_Parameter),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', length: 'int',
                     types: 'list[Enum_Parameter]') -> 'None': ...


@schema_final
class GapAckBlock(Schema):
    """Header schema for SCTP SACK chunk gap ack blocks."""

    #: Start offset TSN of the gap ack block.
    start: 'int' = UInt16Field()
    #: End offset TSN of the gap ack block.
    end: 'int' = UInt16Field()

    if TYPE_CHECKING:
        def __init__(self, start: 'int', end: 'int') -> 'None': ...


class Chunk(EnumSchema[Enum_Chunk]):
    """Header schema for SCTP chunks."""

    __default__ = lambda: UnknownChunk

    #: Chunk type.
    type: 'Enum_Chunk' = EnumField(length=1, namespace=Enum_Chunk)
    #: Chunk flags, whose meaning depends on the chunk type.
    flags: 'bytes' = BytesField(length=1)
    #: Chunk length, excluding any trailing padding.
    length: 'int' = UInt16Field()


@schema_final
class UnknownChunk(Chunk):
    """Header schema for SCTP chunks with unknown types."""

    #: Chunk value.
    value: 'bytes' = BytesField(length=lambda pkt: max(pkt['length'] - 4, 0))
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Chunk', flags: 'bytes', length: 'int',
                     value: 'bytes') -> 'None': ...


@schema_final
class DATAChunk(Chunk, code=Enum_Chunk.Payload_Data):
    """Header schema for SCTP DATA chunks."""

    #: Chunk flags.
    flags: 'DATAChunkFlags' = BitField(length=1, namespace={
        'I': (4, 1),
        'U': (5, 1),
        'B': (6, 1),
        'E': (7, 1),
    })
    #: Transmission sequence number.
    tsn: 'int' = UInt32Field()
    #: Stream identifier.
    stream_id: 'int' = UInt16Field()
    #: Stream sequence number.
    stream_seq: 'int' = UInt16Field()
    #: Payload protocol identifier.
    ppid: 'Enum_PayloadProtocolIdentifier' = EnumField(
        length=4, namespace=Enum_PayloadProtocolIdentifier)
    #: User data.
    data: 'bytes' = BytesField(length=lambda pkt: max(pkt['length'] - 16, 0))
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Chunk', flags: 'DATAChunkFlags', length: 'int', tsn: 'int',
                     stream_id: 'int', stream_seq: 'int',
                     ppid: 'Enum_PayloadProtocolIdentifier | int', data: 'bytes') -> 'None': ...


@schema_final
class INITChunk(Chunk, code=Enum_Chunk.Initiation):
    """Header schema for SCTP INIT chunks."""

    #: Initiate tag.
    init_tag: 'int' = UInt32Field()
    #: Advertised receiver window credit.
    a_rwnd: 'int' = UInt32Field()
    #: Number of outbound streams.
    outbound_streams: 'int' = UInt16Field()
    #: Number of inbound streams.
    inbound_streams: 'int' = UInt16Field()
    #: Initial transmission sequence number.
    init_tsn: 'int' = UInt32Field()
    #: Optional and variable-length parameters, including the chunk's own
    #: trailing padding; see :func:`nested_length`.
    parameters: 'list[Parameter]' = OptionField(
        length=nested_length(20),
        base_schema=Parameter,
        type_name='type',
        registry=Parameter.registry,
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Chunk', flags: 'bytes', length: 'int', init_tag: 'int',
                     a_rwnd: 'int', outbound_streams: 'int', inbound_streams: 'int',
                     init_tsn: 'int',
                     parameters: 'list[Parameter | bytes] | bytes') -> 'None': ...


@schema_final
class INITACKChunk(Chunk, code=Enum_Chunk.Initiation_Acknowledgement):
    """Header schema for SCTP INIT ACK chunks."""

    #: Initiate tag.
    init_tag: 'int' = UInt32Field()
    #: Advertised receiver window credit.
    a_rwnd: 'int' = UInt32Field()
    #: Number of outbound streams.
    outbound_streams: 'int' = UInt16Field()
    #: Number of inbound streams.
    inbound_streams: 'int' = UInt16Field()
    #: Initial transmission sequence number.
    init_tsn: 'int' = UInt32Field()
    #: Optional and variable-length parameters, including the chunk's own
    #: trailing padding; see :func:`nested_length`.
    parameters: 'list[Parameter]' = OptionField(
        length=nested_length(20),
        base_schema=Parameter,
        type_name='type',
        registry=Parameter.registry,
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Chunk', flags: 'bytes', length: 'int', init_tag: 'int',
                     a_rwnd: 'int', outbound_streams: 'int', inbound_streams: 'int',
                     init_tsn: 'int',
                     parameters: 'list[Parameter | bytes] | bytes') -> 'None': ...


@schema_final
class SACKChunk(Chunk, code=Enum_Chunk.Selective_Acknowledgement):
    """Header schema for SCTP SACK chunks."""

    #: Cumulative TSN ack.
    cum_tsn_ack: 'int' = UInt32Field()
    #: Advertised receiver window credit.
    a_rwnd: 'int' = UInt32Field()
    #: Number of gap ack blocks.
    num_gap_blocks: 'int' = UInt16Field()
    #: Number of duplicate TSNs.
    num_dup_tsn: 'int' = UInt16Field()
    #: Gap ack blocks.
    gap_blocks: 'list[GapAckBlock]' = ListField(
        length=bounded(
            lambda pkt: min(max(pkt['num_gap_blocks'], 0) * 4, max(pkt['length'] - 16, 0))),
        item_type=SchemaField(length=4, schema=GapAckBlock),
    )
    #: Duplicate TSNs.
    dup_tsn: 'list[int]' = ListField(
        length=bounded(
            lambda pkt: min(max(pkt['num_dup_tsn'], 0) * 4,
                            max(pkt['length'] - 16 - max(pkt['num_gap_blocks'], 0) * 4, 0))),
        item_type=UInt32Field(),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Chunk', flags: 'bytes', length: 'int', cum_tsn_ack: 'int',
                     a_rwnd: 'int', num_gap_blocks: 'int', num_dup_tsn: 'int',
                     gap_blocks: 'list[GapAckBlock] | bytes',
                     dup_tsn: 'list[int] | bytes') -> 'None': ...


@schema_final
class HeartbeatChunk(Chunk, code=Enum_Chunk.Heartbeat_Request):
    """Header schema for SCTP HEARTBEAT chunks."""

    #: Heartbeat information parameters, including the chunk's own trailing
    #: padding; see :func:`nested_length`.
    parameters: 'list[Parameter]' = OptionField(
        length=nested_length(4),
        base_schema=Parameter,
        type_name='type',
        registry=Parameter.registry,
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Chunk', flags: 'bytes', length: 'int',
                     parameters: 'list[Parameter | bytes] | bytes') -> 'None': ...


@schema_final
class HeartbeatACKChunk(Chunk, code=Enum_Chunk.Heartbeat_Acknowledgement):
    """Header schema for SCTP HEARTBEAT ACK chunks."""

    #: Heartbeat information parameters, including the chunk's own trailing
    #: padding; see :func:`nested_length`.
    parameters: 'list[Parameter]' = OptionField(
        length=nested_length(4),
        base_schema=Parameter,
        type_name='type',
        registry=Parameter.registry,
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Chunk', flags: 'bytes', length: 'int',
                     parameters: 'list[Parameter | bytes] | bytes') -> 'None': ...


@schema_final
class AbortChunk(Chunk, code=Enum_Chunk.Abort):
    """Header schema for SCTP ABORT chunks."""

    #: Chunk flags.
    flags: 'TBitFlags' = BitField(length=1, namespace={
        'T': (7, 1),
    })
    #: Zero or more error causes, including the chunk's own trailing padding;
    #: see :func:`nested_length`.
    error: 'list[ErrorCause]' = OptionField(
        length=nested_length(4),
        base_schema=ErrorCause,
        type_name='code',
        registry=ErrorCause.registry,
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Chunk', flags: 'TBitFlags', length: 'int',
                     error: 'list[ErrorCause | bytes] | bytes') -> 'None': ...


@schema_final
class ShutdownChunk(Chunk, code=Enum_Chunk.Shutdown):
    """Header schema for SCTP SHUTDOWN chunks."""

    #: Cumulative TSN ack.
    cum_tsn_ack: 'int' = UInt32Field()
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Chunk', flags: 'bytes', length: 'int',
                     cum_tsn_ack: 'int') -> 'None': ...


@schema_final
class ShutdownACKChunk(Chunk, code=Enum_Chunk.Shutdown_Acknowledgement):
    """Header schema for SCTP SHUTDOWN ACK chunks."""

    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Chunk', flags: 'bytes', length: 'int') -> 'None': ...


@schema_final
class ErrorChunk(Chunk, code=Enum_Chunk.Operation_Error):
    """Header schema for SCTP ERROR chunks."""

    #: One or more error causes, including the chunk's own trailing padding;
    #: see :func:`nested_length`.
    error: 'list[ErrorCause]' = OptionField(
        length=nested_length(4),
        base_schema=ErrorCause,
        type_name='code',
        registry=ErrorCause.registry,
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Chunk', flags: 'bytes', length: 'int',
                     error: 'list[ErrorCause | bytes] | bytes') -> 'None': ...


@schema_final
class CookieEchoChunk(Chunk, code=Enum_Chunk.State_Cookie):
    """Header schema for SCTP COOKIE ECHO chunks."""

    #: State cookie, as received in the INIT ACK chunk's state cookie parameter.
    cookie: 'bytes' = BytesField(length=lambda pkt: max(pkt['length'] - 4, 0))
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Chunk', flags: 'bytes', length: 'int',
                     cookie: 'bytes') -> 'None': ...


@schema_final
class CookieACKChunk(Chunk, code=Enum_Chunk.Cookie_Acknowledgement):
    """Header schema for SCTP COOKIE ACK chunks."""

    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Chunk', flags: 'bytes', length: 'int') -> 'None': ...


@schema_final
class ShutdownCompleteChunk(Chunk, code=Enum_Chunk.Shutdown_Complete):
    """Header schema for SCTP SHUTDOWN COMPLETE chunks."""

    #: Chunk flags.
    flags: 'TBitFlags' = BitField(length=1, namespace={
        'T': (7, 1),
    })
    #: Padding.
    padding: 'bytes' = PaddingField(length=padding_length)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Chunk', flags: 'TBitFlags', length: 'int') -> 'None': ...


@schema_final
class SCTP(Schema):
    """Header schema for SCTP packets.

    Note:
        Unlike :class:`~pcapkit.protocols.schema.transport.tcp.TCP` and
        :class:`~pcapkit.protocols.schema.transport.udp.UDP`, there is **no**
        payload field, since SCTP carries its user data inside DATA chunks
        rather than after the common header. See
        :meth:`SCTP._get_payload <pcapkit.protocols.transport.sctp.SCTP._get_payload>`
        for how the next layer is located.

    """

    #: Source port.
    srcport: 'Enum_AppType' = PortEnumField(length=2, namespace=Enum_AppType)
    #: Destination port.
    dstport: 'Enum_AppType' = PortEnumField(length=2, namespace=Enum_AppType)
    #: Verification tag.
    vtag: 'int' = UInt32Field()
    #: Checksum, as a CRC32c over the whole packet with this field zeroed.
    chksum: 'bytes' = BytesField(length=4)
    #: Chunks.
    chunks: 'list[Chunk]' = OptionField(
        length=lambda pkt: max(pkt['__length__'], 0),
        base_schema=Chunk,
        type_name='type',
        registry=Chunk.registry,
    )

    if TYPE_CHECKING:
        def __init__(self, srcport: 'Enum_AppType | int', dstport: 'Enum_AppType | int',
                     vtag: 'int', chksum: 'bytes',
                     chunks: 'list[Chunk | bytes] | bytes') -> 'None': ...
