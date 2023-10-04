# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for internet protocol version 4"""

import collections
import datetime
import ipaddress
from typing import TYPE_CHECKING, cast

from pcapkit.const.ipv4.classification_level import ClassificationLevel as Enum_ClassificationLevel
from pcapkit.const.ipv4.option_number import OptionNumber as Enum_OptionNumber
from pcapkit.const.ipv4.qs_function import QSFunction as Enum_QSFunction
from pcapkit.const.ipv4.router_alert import RouterAlert as Enum_RouterAlert
from pcapkit.const.ipv4.ts_flag import TSFlag as Enum_TSFlag
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.collections import ListField, OptionField
from pcapkit.corekit.fields.ipaddress import IPv4AddressField
from pcapkit.corekit.fields.misc import (ConditionalField, ForwardMatchField, PayloadField,
                                         SchemaField, SwitchField)
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt16Field, UInt32Field
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField
from pcapkit.protocols.schema.schema import EnumSchema, Schema, schema_final
from pcapkit.utilities.exceptions import FieldValueError
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING
from pcapkit.utilities.warnings import ProtocolWarning, warn

__all__ = [
    'IPv4',

    'Option',
    'UnassignedOption', 'EOOLOption', 'NOPOption',
    'SECOption', 'LSROption', 'TSOption',
    'ESECOption', 'RROption', 'SIDOption',
    'SSROption', 'MTUPOption', 'MTUROption',
    'TROption', 'RTRALTOption', 'QSOption',
    'QuickStartRequestOption', 'QuickStartReportOption',
]

if TYPE_CHECKING:
    from datetime import timedelta
    from ipaddress import IPv4Address
    from typing import Any, DefaultDict, Optional, Type

    from pcapkit.corekit.fields.field import FieldBase as Field
    from pcapkit.corekit.multidict import OrderedMultiDict
    from pcapkit.protocols.protocol import ProtocolBase as Protocol

if SPHINX_TYPE_CHECKING:
    from typing_extensions import TypedDict

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

    class QSTestFlags(TypedDict):
        """Quick start test flag."""

        #: QS function.
        func: int

    class QSNonce(TypedDict):
        """Quick start nonce field."""

        #: Nonce.
        nonce: int


def quick_start_data_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`_QSOption.data` field.

    Args:
        pkt: Packet data.

    Returns:
        * If ``func`` is ``0``, returns a :class:`~pcapkit.corekit.fields.misc.SchemaField`
          wrapped :class:`~pcapkit.protocols.schema.internet.ipv4.QuickStartRequestOption`
          instance.
        * If ``func`` is ``8``, returns a :class:`~pcapkit.corekit.fields.misc.SchemaField`
          wrapped :class:`~pcapkit.protocols.schema.internet.ipv4.QuickStartReportOption`
          instance.

    """
    func = Enum_QSFunction.get(pkt['flags']['func'])
    pkt['flags']['func'] = func

    schema = QSOption.registry[func]
    if schema is None:
        raise FieldValueError(f'IPv4: invalid QS function: {func}')
    return SchemaField(length=5, schema=schema)


class Option(EnumSchema[Enum_OptionNumber]):
    """Header schema for IPv4 options."""

    __default__ = lambda: UnassignedOption

    #: Option type.
    type: 'Enum_OptionNumber' = EnumField(length=1, namespace=Enum_OptionNumber)
    #: Option length.
    length: 'int' = ConditionalField(
        UInt8Field(),
        lambda pkt: pkt['type'] not in (Enum_OptionNumber.EOOL, Enum_OptionNumber.NOP),
    )

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        # for EOOL/NOP option, length is always 1
        if self.type in (Enum_OptionNumber.EOOL, Enum_OptionNumber.NOP):
            self.length = 1
        return self


@schema_final
class UnassignedOption(Option):
    """Header schema for IPv4 unassigned options."""

    #: Option data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 2)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', data: 'bytes') -> 'None': ...


@schema_final
class EOOLOption(Option, code=Enum_OptionNumber.EOOL):
    """Header schema for IPv4 end of option list (``EOOL``) option."""

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int') -> 'None': ...


@schema_final
class NOPOption(Option, code=Enum_OptionNumber.NOP):
    """Header schema for IPv4 no operation (``NOP``) option."""

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int') -> 'None': ...


@schema_final
class SECOption(Option, code=Enum_OptionNumber.SEC):
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


@schema_final
class LSROption(Option, code=Enum_OptionNumber.LSR):
    """Header schema for IPv4 loose source route (``LSR``) option."""

    #: Pointer.
    pointer: 'int' = UInt8Field()
    #: Route.
    route: 'list[IPv4Address]' = ListField(
        length=lambda pkt: pkt['pointer'] - 4,
        item_type=IPv4AddressField(),
    )
    #: Remaining data buffer0.
    remainder: 'bytes' = PaddingField(
        length=lambda pkt: pkt['length'] - pkt['pointer'] + 1,
        default=bytes(36),  # a reasonable default
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', pointer: 'int', route: 'list[IPv4Address | str | bytes | int]') -> 'None': ...


@schema_final
class TSOption(Option, code=Enum_OptionNumber.TS):
    """Header schema for IPv4 timestamp (``TS``) option."""

    #: Pointer.
    pointer: 'int' = UInt8Field()
    #: Overflow and flags.
    flags: 'TSFlags' = BitField(length=1, namespace={
        'oflw': (0, 4),
        'flag': (4, 4),
    })
    #: Timestamps and internet addresses.
    ts_data: 'list[int]' = ListField(
        length=lambda pkt: pkt['pointer'] - 5 if pkt['flags']['flag'] != 3 else pkt['length'] - 4,
        item_type=UInt32Field(),
    )
    #: Remaining data buffer.
    remainder: 'bytes' = PaddingField(
        length=lambda pkt: pkt['length'] - pkt['pointer'] + 1 if pkt['flags']['flag'] != 3 else 0,
        default=bytes(36),  # 36 is the maximum length of the option data field for timestamps
    )

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        ts_flag = Enum_TSFlag.get(self.flags['flag'])
        if ts_flag == Enum_TSFlag.Timestamp_Only:
            ts_data = self.ts_data
            self.data = []
            ts_list = []  # type: list[int | timedelta]

            for ts in ts_data:
                self.data.append(ts)

                if ts >> 31:
                    warn(f'IPv4: [OptNo {self.type}] invalid format: timestamp error: {ts_val}', ProtocolWarning)
                    ts_val = ts & 0x7FFFFFFF  # type: int | timedelta
                else:
                    ts_val = datetime.timedelta(milliseconds=ts)
                ts_list.append(ts_val)
            timestamp = tuple(ts_list)  # type: tuple[int | timedelta, ...] | OrderedMultiDict[IPv4Address, int | timedelta]
        elif ts_flag == Enum_TSFlag.IP_with_Timestamp:
            ts_data = self.ts_data
            self.data = OrderedMultiDict()
            timestamp = OrderedMultiDict()

            for ip, ts in zip(ts_data[::2], ts_data[1::2]):
                ip_val = cast('IPv4Address', ipaddress.ip_address(ip))
                self.data.add(ip_val, ts)

                if ts >> 31:
                    warn(f'IPv4: [OptNo {self.type}] invalid format: timestamp error: {ts_val}', ProtocolWarning)
                    ts_val = ts & 0x7FFFFFFF
                else:
                    ts_val = datetime.timedelta(milliseconds=ts)
                timestamp.add(ip_val, ts_val)
        elif ts_flag == Enum_TSFlag.Prespecified_IP_with_Timestamp:
            ts_data = self.ts_data
            self.data = OrderedMultiDict()
            timestamp = OrderedMultiDict()

            for ip, ts in zip(ts_data[::2], ts_data[1::2]):
                ip_val = cast('IPv4Address', ipaddress.ip_address(ip))
                self.data.add(ip_val, ts)

                if ts >> 31:
                    warn(f'IPv4: [OptNo {self.type}] invalid format: timestamp error: {ts_val}', ProtocolWarning)
                    ts_val = ts & 0x7FFFFFFF
                else:
                    ts_val = datetime.timedelta(milliseconds=ts)
                timestamp.add(ip_val, ts_val)

            # extract also the prespecified IP addresses
            # but set the timestamp to 0
            pad = self.remainder
            for index in range(0, len(pad), 8):
                buf_ip = pad[index:index + 4]
                self.data.add(ipaddress.ip_address(buf_ip), 0)  # type: ignore[arg-type]
        else:
            warn(f'IPv4: [OptNo {self.type}] invalid format: unknown timestmap flag: {ts_flag}', ProtocolWarning)
            self.data = self.ts_data
            timestamp = tuple(self.ts_data)

        self.ts_flag = ts_flag
        self.timestamp = timestamp
        return self

    if TYPE_CHECKING:
        ts_flag: 'Enum_TSFlag'
        data: 'list[int] | OrderedMultiDict[IPv4Address, int]'
        timestamp: 'tuple[int | timedelta] | OrderedMultiDict[IPv4Address, int | timedelta]'

        def __init__(self, type: 'Enum_OptionNumber', length: 'int', pointer: 'int', flags: 'TSFlags', data: 'list[int]') -> 'None': ...


@schema_final
class ESECOption(Option, code=Enum_OptionNumber.E_SEC):
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


@schema_final
class RROption(Option, code=Enum_OptionNumber.RR):
    """Header schema for IPv4 record route (``RR``) option."""

    #: Pointer.
    pointer: 'int' = UInt8Field()
    #: Route.
    route: 'list[IPv4Address]' = ListField(
        length=lambda pkt: pkt['pointer'] - 4,
        item_type=IPv4AddressField(),
    )
    #: Remaining data buffer0.
    remainder: 'bytes' = PaddingField(
        length=lambda pkt: pkt['length'] - pkt['pointer'] + 1,
        default=bytes(36),  # a reasonable default
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', pointer: 'int', route: 'list[IPv4Address | str | bytes | int]') -> 'None': ...


@schema_final
class SIDOption(Option, code=Enum_OptionNumber.SID):
    """Header schema for IPv4 stream identifier (``SID``) option."""

    #: Stream identifier.
    sid: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', sid: 'int') -> 'None': ...


@schema_final
class SSROption(Option, code=Enum_OptionNumber.SSR):
    """Header schema for IPv4 strict source route (``SSR``) option."""

    #: Pointer.
    pointer: 'int' = UInt8Field()
    #: Route.
    route: 'list[IPv4Address]' = ListField(
        length=lambda pkt: pkt['pointer'] - 4,
        item_type=IPv4AddressField(),
    )
    #: Remaining data buffer0.
    remainder: 'bytes' = PaddingField(
        length=lambda pkt: pkt['length'] - pkt['pointer'] + 1,
        default=bytes(36),  # a reasonable default
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', pointer: 'int', route: 'list[IPv4Address | str | bytes | int]') -> 'None': ...


@schema_final
class MTUPOption(Option, code=Enum_OptionNumber.MTUP):
    """Header schema for IPv4 MTU probe (``MTUP``) option."""

    #: MTU.
    mtu: 'int' = UInt16Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', mtu: 'int') -> 'None': ...


@schema_final
class MTUROption(Option, code=Enum_OptionNumber.MTUR):
    """Header schema for IPv4 MTU reply (``MTUR``) option."""

    #: MTU.
    mtu: 'int' = UInt16Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', mtu: 'int') -> 'None': ...


@schema_final
class TROption(Option, code=Enum_OptionNumber.TR):
    """Header schema for IPv4 traceroute (``TR``) option."""

    #: ID number.
    id: 'int' = UInt16Field()
    #: Outbound hop count.
    out: 'int' = UInt16Field()
    #: Return hop count.
    ret: 'int' = UInt16Field()
    #: Originator IP address.
    origin: 'IPv4Address' = IPv4AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', id: 'int', out: 'int', ret: 'int', origin: 'IPv4Address | str | bytes | int') -> 'None': ...


@schema_final
class RTRALTOption(Option, code=Enum_OptionNumber.RTRALT):
    """Header schema for IPv4 router alert (``RTRALT``) option."""

    #: Router alert value.
    alert: 'Enum_RouterAlert' = EnumField(length=2, namespace=Enum_RouterAlert)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', alert: 'Enum_RouterAlert') -> 'None': ...


@schema_final
class _QSOption(Schema):
    """Header schema for IPv4 quick start (``QS``) options in generic representation."""

    #: Flags.
    flags: 'QSTestFlags' = ForwardMatchField(BitField(length=3, namespace={
        'func': (16, 4),
    }))
    #: QS data.
    data: 'QuickStartRequestOption | QuickStartReportOption' = SwitchField(
        selector=quick_start_data_selector,
    )

    def post_process(self, packet: 'dict[str, Any]') -> 'QSOption':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        ret = self.data
        ret.func = Enum_QSFunction.get(self.flags['func'])
        return ret


# register ``_QSOption`` as ``QS`` option
Option.register(Enum_OptionNumber.QS, _QSOption)


class QSOption(Option, EnumSchema[Enum_QSFunction]):
    """Header schema for IPV4 quick start (``QS``) options."""

    __enum__: 'DefaultDict[Enum_QSFunction, Type[QSOption]]' = collections.defaultdict(lambda: None)  # type: ignore[return-value,arg-type]

    #: Flags.
    flags: 'QuickStartFlags' = BitField(length=1, namespace={
        'func': (0, 4),
        'rate': (4, 4),
    })

    if TYPE_CHECKING:
        func: 'Enum_QSFunction'


@schema_final
class QuickStartRequestOption(QSOption, code=Enum_QSFunction.Quick_Start_Request):
    """Header schema for IPV4 quick start request options."""

    #: QS time-to-live (TTL).
    ttl: 'int' = UInt8Field()
    #: QS nonce.
    nonce: 'QSNonce' = BitField(length=4, namespace={
        'nonce': (0, 30),
    })

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', flags: 'QuickStartFlags',
                     ttl: 'int', nonce: 'QSNonce') -> 'None': ...


@schema_final
class QuickStartReportOption(QSOption, code=Enum_QSFunction.Report_of_Approved_Rate):
    """Header schema for IPV4 quick start report of approved rate options."""

    #: QS nonce.
    nonce: 'QSNonce' = BitField(length=4, namespace={
        'nonce': (0, 30),
    })

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', flags: 'QuickStartFlags',
                     nonce: 'QSNonce') -> 'None': ...


@schema_final
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
    src: 'IPv4Address' = IPv4AddressField()
    #: Destination address.
    dst: 'IPv4Address' = IPv4AddressField()
    #: Options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['vihl']['ihl'] * 4 - 20,
        base_schema=Option,
        type_name='type',
        registry=Option.registry,
        eool=Enum_OptionNumber.EOOL,
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: pkt.get('__option_padding__', 0))
    #: Payload.
    payload: 'bytes' = PayloadField(length=lambda pkt: pkt['length'] - pkt['vihl']['ihl'] * 4)

    if TYPE_CHECKING:
        def __init__(self, vihl: 'VerIHLField', tos: 'ToSField', length: 'int', id: 'int',
                     flags: 'Flags', ttl: 'int', proto: 'Enum_TransType', chksum: 'bytes',
                     src: 'IPv4Address | str | bytes | int', dst: 'IPv4Address | str | bytes | int',
                     options: 'list[Option | bytes] | bytes', payload: 'bytes | Protocol | Schema') -> 'None': ...
