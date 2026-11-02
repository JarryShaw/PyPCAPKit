# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for datagram congestion control protocol"""

from typing import TYPE_CHECKING

from pcapkit.const.dccp.feature import Feature as Enum_Feature
from pcapkit.const.dccp.option import Option as Enum_Option
from pcapkit.const.dccp.packet_type import PacketType as Enum_PacketType
from pcapkit.const.dccp.reset_code import ResetCode as Enum_ResetCode
from pcapkit.const.reg.apptype import AppType as Enum_AppType
from pcapkit.const.reg.apptype import TransportProtocol as Enum_TransportProtocol
from pcapkit.corekit.fields.collections import OptionField
from pcapkit.corekit.fields.misc import ConditionalField, PayloadField
from pcapkit.corekit.fields.numbers import (EnumField, NumberField, PortEnumField, UInt8Field,
                                            UInt32Field)
from pcapkit.corekit.fields.strings import BitField, BytesField
from pcapkit.protocols.schema.schema import EnumSchema, Schema, schema_final
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING

__all__ = [
    'DCCP',

    'Option',
    'UnassignedOption', 'Padding', 'Mandatory', 'SlowReceiver', 'Change', 'Confirm',
    'InitCookie', 'NDPCount', 'AckVector', 'DataDropped', 'Timestamp', 'TimestampEcho',
    'ElapsedTime', 'DataChecksum',
]

if TYPE_CHECKING:
    from typing import Any, Optional

    from pcapkit.protocols.protocol import ProtocolBase

#: Length of the generic header with 24-bit sequence numbers (``X`` clear), the
#: shortest a DCCP header can be, :rfc:`4340#section-5.1`. The one home of this
#: value (:issue:`1739`); it is fixed by the RFC, so it is never configurable.
DCCP_MIN_HEADER_LEN = 12

#: Option types up to this one are single octets, without a length,
#: :rfc:`4340#section-5.8`.
DCCP_SINGLE_OCTET_OPTION_MAX = 31

#: Packet types carrying an Acknowledgement Number Subheader: every one
#: :rfc:`4340#section-5` defines but DCCP-Request and DCCP-Data. DCCP-Listen
#: (:rfc:`5596#section-2.2.1`) carries none either.
ACK_TYPES = frozenset({
    Enum_PacketType.DCCP_Response, Enum_PacketType.DCCP_Ack, Enum_PacketType.DCCP_DataAck,
    Enum_PacketType.DCCP_CloseReq, Enum_PacketType.DCCP_Close, Enum_PacketType.DCCP_Reset,
    Enum_PacketType.DCCP_Sync, Enum_PacketType.DCCP_SyncAck,
})

#: Packet types carrying a Service Code: DCCP-Request, DCCP-Response and
#: DCCP-Listen (:rfc:`4340#section-5.2`, :rfc:`5596#section-2.2.1`).
SERVICE_TYPES = frozenset({
    Enum_PacketType.DCCP_Request, Enum_PacketType.DCCP_Response, Enum_PacketType.DCCP_Listen,
})

#: Packet type of DCCP-Reset, which carries a Reset Code and three Data octets,
#: :rfc:`4340#section-5.6`.
RESET_TYPE = Enum_PacketType.DCCP_Reset

if SPHINX_TYPE_CHECKING:  # pragma: no cover
    from typing_extensions import TypedDict

    class Coverage(TypedDict):
        """DCCP ``CCVal`` and checksum coverage field."""

        #: Value used by the HC-Sender CCID.
        ccval: int
        #: Checksum coverage.
        cscov: int

    class TypeField(TypedDict):
        """DCCP reserved bits, packet type and extended sequence numbers flag."""

        #: Reserved bits (``Res``).
        reserved: int
        #: Packet type.
        type: int
        #: Extended sequence numbers (``X``).
        x: int


def header_length(field: 'TypeField') -> 'int':
    """Length of the generic header and the fields its packet type adds.

    Args:
        field: The packet type and extended sequence numbers flag.

    Returns:
        The octets ahead of the options, :rfc:`4340#section-5`.

    """
    extended = field['x']
    code = field['type']

    length = DCCP_MIN_HEADER_LEN + (4 if extended else 0)
    if code in ACK_TYPES:
        length += 8 if extended else 4
    if code in SERVICE_TYPES:
        length += 4
    if code == RESET_TYPE:
        length += 4
    return length


class Option(EnumSchema[Enum_Option]):
    """Header schema for DCCP options."""

    __default__ = lambda: UnassignedOption

    #: Option type.
    type: 'Enum_Option' = EnumField(length=1, namespace=Enum_Option)
    #: Option length, absent from a single-octet option.
    length: 'int' = ConditionalField(
        UInt8Field(),
        lambda pkt: pkt['type'] > DCCP_SINGLE_OCTET_OPTION_MAX,
    )

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        if self.type <= DCCP_SINGLE_OCTET_OPTION_MAX:
            self.length = 1
        return self


@schema_final
class UnassignedOption(Option):
    """Header schema for DCCP unassigned options."""

    #: Option data, absent from a single-octet option.
    data: 'bytes' = ConditionalField(
        BytesField(length=lambda pkt: pkt['length'] - 2),
        lambda pkt: pkt['type'] > DCCP_SINGLE_OCTET_OPTION_MAX,
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', data: 'Optional[bytes]' = None) -> 'None': ...


@schema_final
class Padding(Option, code=Enum_Option.Padding):
    """Header schema for DCCP padding option."""

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int') -> 'None': ...


@schema_final
class Mandatory(Option, code=Enum_Option.Mandatory):
    """Header schema for DCCP mandatory option."""

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int') -> 'None': ...


@schema_final
class SlowReceiver(Option, code=Enum_Option.Slow_Receiver):
    """Header schema for DCCP slow receiver option."""

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int') -> 'None': ...


@schema_final
class Change(Option, code=[Enum_Option.Change_L, Enum_Option.Change_R]):
    """Header schema for DCCP Change L and Change R options."""

    #: Feature number, absent from a 2-octet option.
    feature: 'Enum_Feature' = ConditionalField(
        EnumField(length=1, namespace=Enum_Feature),
        lambda pkt: pkt['length'] > 2,
    )
    #: Preference list or value; a length under 2 is refused, as in every
    #: option that has a length (:rfc:`4340#section-5.8`).
    value: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - (3 if pkt['length'] > 2 else 2))

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', value: 'bytes',
                     feature: 'Optional[Enum_Feature | int]' = None) -> 'None': ...


@schema_final
class Confirm(Option, code=[Enum_Option.Confirm_L, Enum_Option.Confirm_R]):
    """Header schema for DCCP Confirm L and Confirm R options."""

    #: Feature number, absent from a 2-octet option.
    feature: 'Enum_Feature' = ConditionalField(
        EnumField(length=1, namespace=Enum_Feature),
        lambda pkt: pkt['length'] > 2,
    )
    #: Value, then the preference list for a server-priority feature; a length
    #: under 2 is refused, as in every option that has a length
    #: (:rfc:`4340#section-5.8`).
    value: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - (3 if pkt['length'] > 2 else 2))

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', value: 'bytes',
                     feature: 'Optional[Enum_Feature | int]' = None) -> 'None': ...


@schema_final
class InitCookie(Option, code=Enum_Option.Init_Cookie):
    """Header schema for DCCP init cookie option."""

    #: Cookie.
    cookie: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 2)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', cookie: 'bytes') -> 'None': ...


@schema_final
class NDPCount(Option, code=Enum_Option.NDP_Count):
    """Header schema for DCCP NDP count option."""

    #: NDP count, ``length - 2`` octets, read and rebuilt at that width;
    #: :rfc:`4340#section-7.7` allows one to six.
    count: 'int' = NumberField(length=lambda pkt: pkt['length'] - 2, signed=False)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', count: 'int') -> 'None': ...


@schema_final
class AckVector(Option, code=[Enum_Option.Ack_Vector_Nonce_0, Enum_Option.Ack_Vector_Nonce_1]):
    """Header schema for DCCP Ack Vector options."""

    #: Vector, one state and run length per octet.
    vector: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 2)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', vector: 'bytes') -> 'None': ...


@schema_final
class DataDropped(Option, code=Enum_Option.Data_Dropped):
    """Header schema for DCCP data dropped option."""

    #: Vector, one normal or drop block per octet.
    vector: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 2)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', vector: 'bytes') -> 'None': ...


@schema_final
class Timestamp(Option, code=Enum_Option.Timestamp):
    """Header schema for DCCP timestamp option."""

    #: Timestamp value.
    timestamp: 'int' = NumberField(length=lambda pkt: pkt['length'] - 2, signed=False)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', timestamp: 'int') -> 'None': ...


@schema_final
class TimestampEcho(Option, code=Enum_Option.Timestamp_Echo):
    """Header schema for DCCP timestamp echo option."""

    #: Timestamp echo.
    timestamp: 'int' = NumberField(length=lambda pkt: min(pkt['length'] - 2, 4), signed=False)
    #: Elapsed time, absent from a 6-octet option.
    elapsed: 'int' = ConditionalField(
        NumberField(length=lambda pkt: pkt['length'] - 6, signed=False),
        lambda pkt: pkt['length'] > 6,
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', timestamp: 'int',
                     elapsed: 'Optional[int]' = None) -> 'None': ...


@schema_final
class ElapsedTime(Option, code=Enum_Option.Elapsed_Time):
    """Header schema for DCCP elapsed time option."""

    #: Elapsed time, two or four octets.
    elapsed: 'int' = NumberField(length=lambda pkt: pkt['length'] - 2, signed=False)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', elapsed: 'int') -> 'None': ...


@schema_final
class DataChecksum(Option, code=Enum_Option.Data_Checksum):
    """Header schema for DCCP data checksum option."""

    #: CRC-32c of the application data.
    checksum: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 2)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', checksum: 'bytes') -> 'None': ...


@schema_final
class DCCP(Schema):
    """Header schema for DCCP packet."""

    #: Source port.
    srcport: 'Enum_AppType' = PortEnumField(length=2, namespace=Enum_AppType,
                                            proto=Enum_TransportProtocol.dccp)
    #: Destination port.
    dstport: 'Enum_AppType' = PortEnumField(length=2, namespace=Enum_AppType,
                                            proto=Enum_TransportProtocol.dccp)
    #: Data offset, in 32-bit words.
    offset: 'int' = UInt8Field()
    #: ``CCVal`` and checksum coverage.
    cscov: 'Coverage' = BitField(length=1, namespace={
        'ccval': (0, 4),
        'cscov': (4, 4),
    })
    #: Checksum.
    checksum: 'bytes' = BytesField(length=2)
    #: Reserved bits, packet type and extended sequence numbers flag.
    type: 'TypeField' = BitField(length=1, namespace={
        'reserved': (0, 3),
        'type': (3, 4),
        'x': (7, 1),
    })
    #: Reserved octet ahead of a 48-bit sequence number.
    seq_reserved: 'int' = ConditionalField(
        UInt8Field(),
        lambda pkt: pkt['type']['x'] == 1,
    )
    #: Sequence number, 48 or 24 bits.
    seq: 'int' = NumberField(length=lambda pkt: 6 if pkt['type']['x'] else 3, signed=False)
    #: Reserved bits of the acknowledgement number subheader.
    ack_reserved: 'int' = ConditionalField(
        NumberField(length=lambda pkt: 2 if pkt['type']['x'] else 1, signed=False),
        lambda pkt: pkt['type']['type'] in ACK_TYPES,
    )
    #: Acknowledgement number, 48 or 24 bits.
    ack: 'int' = ConditionalField(
        NumberField(length=lambda pkt: 6 if pkt['type']['x'] else 3, signed=False),
        lambda pkt: pkt['type']['type'] in ACK_TYPES,
    )
    #: Service code.
    service_code: 'int' = ConditionalField(
        UInt32Field(),
        lambda pkt: pkt['type']['type'] in SERVICE_TYPES,
    )
    #: Reset code.
    reset_code: 'Enum_ResetCode' = ConditionalField(
        EnumField(length=1, namespace=Enum_ResetCode),
        lambda pkt: pkt['type']['type'] == RESET_TYPE,
    )
    #: Data 1, 2 and 3 of a reset.
    reset_data: 'bytes' = ConditionalField(
        BytesField(length=3),
        lambda pkt: pkt['type']['type'] == RESET_TYPE,
    )
    #: Options, cut short where the data is; :meth:`DCCP.read
    #: <pcapkit.protocols.transport.dccp.DCCP.read>` refuses such a header.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: max(min(pkt['offset'] * 4 - header_length(pkt['type']), pkt['__length__']), 0),
        base_schema=Option,
        type_name='type',
        registry=Option.registry,
    )
    #: Payload, i.e. the application data area.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, srcport: 'Enum_AppType | int', dstport: 'Enum_AppType | int', offset: 'int',
                     cscov: 'Coverage', checksum: 'bytes', type: 'TypeField', seq: 'int',
                     options: 'list[Option | bytes] | bytes', payload: 'bytes | ProtocolBase | Schema',
                     seq_reserved: 'Optional[int]' = None, ack_reserved: 'Optional[int]' = None,
                     ack: 'Optional[int]' = None, service_code: 'Optional[int]' = None,
                     reset_code: 'Optional[Enum_ResetCode | int]' = None,
                     reset_data: 'Optional[bytes]' = None) -> 'None': ...
