# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for internet protocol version 4"""

from typing import TYPE_CHECKING

from pcapkit.const.ipv4.classification_level import ClassificationLevel as Enum_ClassificationLevel
from pcapkit.const.ipv4.option_number import OptionNumber as Enum_OptionNumber
from pcapkit.const.ipv4.router_alert import RouterAlert as Enum_RouterAlert
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.ipaddress import IPv4Field
from pcapkit.corekit.fields.misc import ConditionalField, ListField, PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt16Field, UInt32Field
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField
from pcapkit.protocols.schema.schema import Schema

__all__ = [
    'IPv4',

    'ToSField', 'Flags',
    'OptionType',

    'UnassignedOption', 'EOOLOption', 'NOPOption',
    'SECOption', 'LSROption', 'TSOption',
    'ESECOption', 'RROption', 'SIDOption',
    'SSROption', 'MTUPOption', 'MTUROption',
    'TROption', 'RTRALTOption', 'QSOption',
    'QuickStartRequestOption', 'QuickStartReportOption',
]

if TYPE_CHECKING:
    from ipaddress import IPv4Address
    from typing import Optional

    from typing_extensions import TypedDict

    from pcapkit.corekit.multidict import OrderedMultiDict
    from pcapkit.protocols.protocol import Protocol

    class VerIHLField(TypedDict):
        """Version and header length field."""

        #: IP version.
        version: int
        #: Internet header length.
        ihl: int

    #: Type of service field.
    ToSField = TypedDict('ToSField', {
        'pre': int,
        'del': int,
        'thr': int,
        'rel': int,
        'ecn': int,
    })

    class Flags(TypedDict):
        """Flags and fragment offset field."""

        #: Don't fragment flag.
        df: int
        #: More fragments flag.
        mf: int
        #: Fragment offset.
        offset: int

    class TSFlags(TypedDict):
        """Timestamp flags field."""

        #: Timestamp overflow flag.
        oflw: int
        #: Timestamp type flag.
        flag: int

    class QuickStartFlags(TypedDict):
        """Quick-Start flags."""

        #: QS function.
        func: int
        #: Rate request/report.
        rate: int


class IPv4(Schema):
    """Header schema for IPv4 packet."""

    #: Version and header length.
    vihl: 'VerIHLField' = BitField(length=1, namespace={
        'version': (0, 4),
        'ihl': (4, 8),
    })
    #: Type of service.
    tos: 'ToSField' = BitField(length=1, namespace={
        'pre': (0, 3),
        'del': (3, 1),
        'thr': (4, 1),
        'rel': (5, 1),
        'ecn': (6, 2),
    })
    #: Total length.
    length: 'int' = UInt16Field()
    #: Identification.
    id: 'int' = UInt16Field()
    #: Flags and fragment offset.
    flags: 'Flags' = BitField(length=2, namespace={
        'df': (1, 1),
        'mf': (2, 1),
        'offset': (3, 13),
    })
    #: Time to live.
    ttl: 'int' = UInt8Field()
    #: Protocol.
    proto: 'Enum_TransType' = EnumField(length=1, namespace=Enum_TransType)
    #: Header checksum.
    chksum: 'bytes' = BytesField(length=2)
    #: Source address.
    src: 'IPv4Address' = IPv4Field()
    #: Destination address.
    dst: 'IPv4Address' = IPv4Field()
    #: Options.
    options: 'list[Option]' = ListField(length=lambda pkt: pkt['vihl']['ihl'] * 4 - 20)
    #: Payload.
    payload: 'bytes' = PayloadField(length=lambda pkt: pkt['length'] - pkt['vihl']['ihl'] * 4)

    if TYPE_CHECKING:
        def __init__(self, vihl: 'VerIHLField', tos: 'ToSField', length: 'int', id: 'int',
                     flags: 'Flags', ttl: 'int', proto: 'Enum_TransType', chksum: 'bytes',
                     src: 'IPv4Address | str | bytes | int', dst: 'IPv4Address | str | bytes | int',
                     options: 'list[Option | bytes] | bytes', payload: 'bytes | Protocol | Schema') -> 'None': ...


class Option(Schema):
    """Header schema for IPv4 options."""

    #: Option type.
    type: 'Enum_OptionNumber' = EnumField(length=1, namespace=Enum_OptionNumber)
    #: Option length.
    length: 'int' = ConditionalField(
        UInt8Field(),
        lambda pkt: pkt['type'] not in (Enum_OptionNumber.EOOL, Enum_OptionNumber.NOP),
    )


class UnassignedOption(Option):
    """Header schema for IPv4 unassigned options."""

    #: Option data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 2)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', data: 'bytes') -> 'None': ...


class EOOLOption(Option):
    """Header schema for IPv4 end of option list (``EOOL``) option."""

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int') -> 'None': ...


class NOPOption(Option):
    """Header schema for IPv4 no operation (``NOP``) option."""

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int') -> 'None': ...


class SECOption(Option):
    """Header schema for IPv4 security (``SEC``) option."""

    #: Classification level.
    level: 'Enum_ClassificationLevel' = EnumField(length=1, namespace=Enum_ClassificationLevel)
    #: Protection authority flags.
    data: 'bytes' = ConditionalField(
        BytesField(length=lambda pkt: pkt['length'] - 3),
        lambda pkt: pkt['length'] > 3,
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', level: 'int', data: 'Optional[bytes]') -> 'None': ...


class LSROption(Option):
    """Header schema for IPv4 loose source route (``LSR``) option."""

    #: Pointer.
    pointer: 'int' = UInt8Field()
    #: Route.
    route: 'list[IPv4Address]' = ListField(
        length=lambda pkt: pkt['pointer'] - 4,
        item_type=IPv4Field(),
    )
    #: Remaining data buffer0.
    remainder: 'bytes' = PaddingField(
        length=lambda pkt: pkt['length'] - pkt['pointer'] + 1,
        default=bytes(36),  # a reasonable default
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', pointer: 'int', route: 'list[IPv4Address | str | bytes | int]') -> 'None': ...


class TSOption(Option):
    """Header schema for IPv4 timestamp (``TS``) option."""

    #: Pointer.
    pointer: 'int' = UInt8Field()
    #: Overflow and flags.
    flags: 'TSFlags' = BitField(length=1, namespace={
        'oflw': (0, 4),
        'flag': (4, 4),
    })
    #: Timestamps and internet addresses.
    data: 'list[int] | OrderedMultiDict[IPv4Address, int]' = ListField(
        length=lambda pkt: pkt['pointer'] - 5 if pkt['flags']['flag'] != 3 else pkt['length'] - 4,
        item_type=UInt32Field(),
    )
    #: Remaining data buffer.
    remainder: 'bytes' = PaddingField(
        length=lambda pkt: pkt['length'] - pkt['pointer'] + 1 if pkt['flags']['flag'] != 3 else 0,
        default=bytes(36),  # 36 is the maximum length of the option data field for timestamps
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', pointer: 'int', flags: 'TSFlags', data: 'list[int]') -> 'None': ...


class ESECOption(Option):
    """Header schema for IPv4 extended security (``ESEC``) option."""

    #: Additional security information format code.
    format: 'int' = UInt8Field()
    #: Additional security information.
    info: 'bytes' = ConditionalField(
        BytesField(length=lambda pkt: pkt['length'] - 3),
        lambda pkt: pkt['length'] > 3,
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', format: 'int', info: 'Optional[bytes]') -> 'None': ...


class RROption(Option):
    """Header schema for IPv4 record route (``RR``) option."""

    #: Pointer.
    pointer: 'int' = UInt8Field()
    #: Route.
    route: 'list[IPv4Address]' = ListField(
        length=lambda pkt: pkt['pointer'] - 4,
        item_type=IPv4Field(),
    )
    #: Remaining data buffer0.
    remainder: 'bytes' = PaddingField(
        length=lambda pkt: pkt['length'] - pkt['pointer'] + 1,
        default=bytes(36),  # a reasonable default
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', pointer: 'int', route: 'list[IPv4Address | str | bytes | int]') -> 'None': ...


class SIDOption(Option):
    """Header schema for IPv4 stream identifier (``SID``) option."""

    #: Stream identifier.
    sid: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', sid: 'int') -> 'None': ...


class SSROption(Option):
    """Header schema for IPv4 strict source route (``SSR``) option."""

    #: Pointer.
    pointer: 'int' = UInt8Field()
    #: Route.
    route: 'list[IPv4Address]' = ListField(
        length=lambda pkt: pkt['pointer'] - 4,
        item_type=IPv4Field(),
    )
    #: Remaining data buffer0.
    remainder: 'bytes' = PaddingField(
        length=lambda pkt: pkt['length'] - pkt['pointer'] + 1,
        default=bytes(36),  # a reasonable default
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', pointer: 'int', route: 'list[IPv4Address | str | bytes | int]') -> 'None': ...


class MTUPOption(Option):
    """Header schema for IPv4 MTU probe (``MTUP``) option."""

    #: MTU.
    mtu: 'int' = UInt16Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', mtu: 'int') -> 'None': ...


class MTUROption(Option):
    """Header schema for IPv4 MTU reply (``MTUR``) option."""

    #: MTU.
    mtu: 'int' = UInt16Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', mtu: 'int') -> 'None': ...


class TROption(Option):
    """Header schema for IPv4 traceroute (``TR``) option."""

    #: ID number.
    id: 'int' = UInt16Field()
    #: Outbound hop count.
    out: 'int' = UInt16Field()
    #: Return hop count.
    ret: 'int' = UInt16Field()
    #: Originator IP address.
    origin: 'IPv4Address' = IPv4Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', id: 'int', out: 'int', ret: 'int', origin: 'IPv4Address | str | bytes | int') -> 'None': ...


class RTRALTOption(Option):
    """Header schema for IPv4 router alert (``RTRALT``) option."""

    #: Router alert value.
    alert: 'Enum_RouterAlert' = EnumField(length=2, namespace=Enum_RouterAlert)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', alert: 'Enum_RouterAlert') -> 'None': ...


class QSOption(Option):
    """Header schema for IPV4 quick start (``QS``) options."""

    #: Flags.
    flags: 'QuickStartFlags' = BitField(length=1, namespace={
        'func': (0, 4),
        'rate': (4, 4),
    })


class QuickStartRequestOption(QSOption):
    """Header schema for IPV4 quick start request options."""

    #: QS time-to-live (TTL).
    ttl: 'int' = UInt8Field()
    #: QS nonce.
    nonce: 'bytes' = BytesField(length=4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', flags: 'QuickStartFlags',
                     ttl: 'int', nonce: 'bytes') -> 'None': ...


class QuickStartReportOption(QSOption):
    """Header schema for IPV4 quick start report of approved rate options."""

    #: QS nonce.
    nonce: 'bytes' = BytesField(length=4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', flags: 'QuickStartFlags',
                     nonce: 'bytes') -> 'None': ...
