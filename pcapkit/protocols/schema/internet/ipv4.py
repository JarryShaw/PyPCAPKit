# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for internet protocol version 4"""

import collections
import datetime
from typing import TYPE_CHECKING, cast

from pcapkit.const.ipv4.classification_level import ClassificationLevel as Enum_ClassificationLevel
from pcapkit.const.ipv4.option_number import OptionNumber as Enum_OptionNumber
from pcapkit.const.ipv4.qs_function import QSFunction as Enum_QSFunction
from pcapkit.const.ipv4.router_alert import RouterAlert as Enum_RouterAlert
from pcapkit.const.ipv4.ts_flag import TSFlag as Enum_TSFlag
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.collections import ListField, OptionField
from pcapkit.corekit.fields.ipaddress import IPv4AddressField, parse_ip_address
from pcapkit.corekit.fields.misc import (ConditionalField, ForwardMatchField, PayloadField,
                                         SchemaField, SwitchField)
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt16Field, UInt32Field
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField
from pcapkit.corekit.multidict import OrderedMultiDict
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
    from pcapkit.protocols.protocol import ProtocolBase as Protocol

if SPHINX_TYPE_CHECKING:  # pragma: no cover
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


def quick_start_option_length(schema: 'Type[QSOption]') -> 'int':
    """On-the-wire length, in octets, of a resolved Quick-Start (``QS``) suboption.

    The Quick-Start suboption schemas re-declare the option's own ``type`` and
    ``length`` octets -- they inherit them from :class:`Option` -- so what
    :func:`quick_start_data_selector` has to hand the nested
    :class:`~pcapkit.corekit.fields.misc.SchemaField` is the length of the
    *whole* option, not of the data after its header. Per
    :rfc:`4782#section-3.1` -- figure 3 for a Quick-Start Request and figure 4
    for a Report of Approved Rate -- that is eight octets for both functions,
    which differ in what the fourth octet holds rather than in how many there
    are: *"The second byte contains the length field, indicating an option
    length of eight bytes"*, and *"For a Report of Approved Rate, the fourth
    byte of the Quick-Start Option is not used"*. And
    :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_qs` rejects any other
    value in the ``length`` field outright.

    It is summed from the resolved schema's own fields rather than written as
    that literal, for two reasons. The registry is open --
    :class:`QSOption` is an :class:`~pcapkit.protocols.schema.schema.EnumSchema`,
    so a caller may register a further function code with a schema of its own
    width -- and a number written here has to be kept in step by hand with every
    field the suboptions declare, which is precisely how #552 arose: the length
    was ``5``, the width of a Quick-Start Request's ``ttl`` and ``nonce`` alone,
    with the ``type``, ``length`` and ``flags`` octets in front of them
    unaccounted for.

    Args:
        schema: Quick-Start suboption schema, as resolved from the ``func``
            sub-field by :func:`quick_start_data_selector`.

    Returns:
        Length, in octets, that ``schema`` occupies on the wire.

    Raises:
        FieldValueError: If ``schema`` declares a field whose width is not
            fixed. Every field of a Quick-Start suboption is fixed-width,
            because the option is, and a variable-width one cannot be summed
            here without a packet to size it against -- which is the one thing
            a selector does not have for the schema it is about to return. It
            fails rather than guessing, since guessing is the defect being
            fixed.

    """
    length = 0
    for name, field in schema.__fields__.items():
        # NOTE: A forward match consumes nothing and contributes no octets to
        # ``bytes(schema)`` either, c.f. the ``ForwardMatchField`` branches of
        # :meth:`Schema.pack <pcapkit.protocols.schema.schema.Schema.pack>` and
        # :meth:`Schema.unpack <pcapkit.protocols.schema.schema.Schema.unpack>`
        # and the double-count #441/#446 fixed.
        if isinstance(field, ForwardMatchField):
            continue

        # NOTE: The only conditional field a Quick-Start suboption has is the
        # ``length`` octet it inherits from :class:`Option`, whose test is false
        # only for ``EOOL`` and ``NOP`` -- neither of which is a Quick-Start
        # function -- so it is always on the wire and always counted.
        inner = field.field if isinstance(field, ConditionalField) else field

        # NOTE: ``_length_callback`` rather than a ``length < 0`` test, because a
        # dynamically sized field does not report a negative width: it reports
        # whatever its template says, and the templates fall back to a
        # "reasonable default" of ``1024s`` -- measured on ``LSROption.remainder``,
        # a ``PaddingField`` with a length callback, which reports 1024. So the
        # callback's presence is the only reliable signal, and reaching for it is
        # worth one private access. A :class:`~pcapkit.corekit.fields.misc.SwitchField`
        # is named separately because it is the one field whose width is dynamic
        # *without* a length callback: it carries a
        # :class:`~pcapkit.corekit.fields.misc.NoValueField` until its own selector
        # resolves it, and so reports a width of zero rather than refusing to
        # answer. That is exactly what :class:`_QSOption` -- the outer wrapper,
        # which is not itself a suboption -- would hand back here.
        if (isinstance(inner, SwitchField)
                or getattr(inner, '_length_callback', None) is not None):  # pylint: disable=protected-access
            raise FieldValueError(
                f'IPv4: [OptNo {Enum_OptionNumber.QS}] {schema.__name__}: '
                f'{name!r} is not of a fixed width'
            )
        length += field.length
    return length


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

    Notes:
        The length handed to the :class:`~pcapkit.corekit.fields.misc.SchemaField`
        comes from :func:`quick_start_option_length`, i.e. from the suboption that
        was just resolved. It used to be the literal ``5`` for both, which is not
        the width of either: a well-formed eight-octet Quick-Start Request
        ``1908002adeadbee0`` parsed with ``SchemaWarning: packet length < 0: -3``
        and decoded its ``nonce`` as **55** instead of 933982136, then left three
        octets to be read as a further, fabricated option -- which made the
        enclosing datagram fail with ``ProtocolError: IPv4: invalid format``. That
        is silent corruption on the way to a misleading failure, and it was logged
        in review twice before #552 filed it.

    """
    func = Enum_QSFunction.get(pkt['flags']['func'])
    pkt['flags']['func'] = func

    schema = QSOption.registry[func]
    if schema is None:
        raise FieldValueError(f'IPv4: invalid QS function: {func}')
    return SchemaField(length=quick_start_option_length(schema), schema=schema)


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

        Raises:
            FieldValueError: If an entry of :attr:`ts_data` that the timestamp
                flag makes an address is a :obj:`bool`, is not a valid IP
                address, or is not IPv4 -- c.f.
                :func:`~pcapkit.corekit.fields.ipaddress.parse_ip_address`.

        Notes:
            This runs on the **packing** path as well as the unpacking one --
            :meth:`Schema.pack <pcapkit.protocols.schema.schema.Schema.pack>`
            calls it once the buffer is filled -- so the ``ts_data`` entries it
            converts below are whatever the caller passed to the constructor,
            not octets read off the wire. That is why those conversions go
            through :func:`~pcapkit.corekit.fields.ipaddress.parse_ip_address`
            rather than :func:`ipaddress.ip_address`: this schema is reachable
            from public :meth:`IPv4.make
            <pcapkit.protocols.internet.ipv4.IPv4.make>`, which accepts a
            caller-built option schema and packs it, and
            :attr:`ts_data`'s :class:`~pcapkit.corekit.fields.numbers.UInt32Field`
            item type takes a :obj:`bool` as the :class:`int` it is a subclass
            of, so nothing downstream can question it. Measured before this
            fix: ``ts_data=[True, 5]`` packed as ``0000000100000005`` and
            reported ``IPv4Address('0.0.0.1')`` with no exception and no
            warning. This was the fifth site of that defect -- #481, #500,
            #539 and #540 are the first four -- and the reason it is the fifth
            is that each of those fixed the sites it could see. See #552.

        """
        ts_flag = Enum_TSFlag.get(self.flags['flag'])
        if ts_flag == Enum_TSFlag.Timestamp_Only:
            ts_data = self.ts_data
            self.data = []
            ts_list = []  # type: list[int | timedelta]

            for ts in ts_data:
                self.data.append(ts)

                if ts >> 31:
                    warn(f'IPv4: [OptNo {self.type}] invalid format: timestamp error: {ts}', ProtocolWarning)
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
                ip_val = cast('IPv4Address', parse_ip_address(
                    ip, f'IPv4: [OptNo {self.type}] invalid timestamp address', version=4))
                self.data.add(ip_val, ts)

                if ts >> 31:
                    warn(f'IPv4: [OptNo {self.type}] invalid format: timestamp error: {ts}', ProtocolWarning)
                    ts_val = ts & 0x7FFFFFFF
                else:
                    ts_val = datetime.timedelta(milliseconds=ts)
                timestamp.add(ip_val, ts_val)
        elif ts_flag == Enum_TSFlag.Prespecified_IP_with_Timestamp:
            ts_data = self.ts_data
            self.data = OrderedMultiDict()
            timestamp = OrderedMultiDict()

            for ip, ts in zip(ts_data[::2], ts_data[1::2]):
                ip_val = cast('IPv4Address', parse_ip_address(
                    ip, f'IPv4: [OptNo {self.type}] invalid timestamp address', version=4))
                self.data.add(ip_val, ts)

                if ts >> 31:
                    warn(f'IPv4: [OptNo {self.type}] invalid format: timestamp error: {ts}', ProtocolWarning)
                    ts_val = ts & 0x7FFFFFFF
                else:
                    ts_val = datetime.timedelta(milliseconds=ts)
                timestamp.add(ip_val, ts_val)

            # extract also the prespecified IP addresses
            # but set the timestamp to 0
            #
            # NOTE: Through ``parse_ip_address`` like the two conversions above,
            # even though #540 and #552 both judged this site unable to launder a
            # :obj:`bool` -- ``remainder`` is a
            # :class:`~pcapkit.corekit.fields.strings.PaddingField`, so what it
            # holds is octets rather than anything the caller named. It is routed
            # through anyway because a bare :func:`ipaddress.ip_address` here
            # still raises a plain :exc:`ValueError` for a tail that is not a
            # whole number of 8-octet pairs, which no ``except BaseError`` can
            # catch, and because leaving one of this method's three conversions
            # unguarded is exactly how #552 came to be the fifth site of #481.
            pad = self.remainder
            for index in range(0, len(pad), 8):
                buf_ip = pad[index:index + 4]
                self.data.add(parse_ip_address(  # type: ignore[arg-type]
                    buf_ip, f'IPv4: [OptNo {self.type}] invalid prespecified address',
                    version=4), 0)
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

        # NOTE: The keyword is ``ts_data``, the name of the field above, not the
        # ``data`` this signature used to advertise. ``data`` is the *derived*
        # attribute :meth:`post_process` writes and is declared three lines up;
        # naming it here as a constructor argument too is what
        # :meth:`~pcapkit.protocols.internet.ipv4.IPv4._make_opt_ts` was written
        # against, and because :meth:`Schema.__update__
        # <pcapkit.protocols.schema.schema.Schema.__update__>` answers an unknown
        # field name with an
        # :class:`~pcapkit.utilities.warnings.UnknownFieldWarning` rather than an
        # error, the timestamps were dropped in silence. See #552.
        def __init__(self, type: 'Enum_OptionNumber', length: 'int', pointer: 'int', flags: 'TSFlags', ts_data: 'list[int]') -> 'None': ...


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

    #: Stream identifier. Two octets, per :rfc:`791` section 3.1, which gives the
    #: option as four octets in total: one of type, one of length, and a 16-bit
    #: stream identifier. This was a :class:`~pcapkit.corekit.fields.numbers.UInt32Field`,
    #: which over-read a well-formed option by two octets on the way in -- the
    #: ``packet length < 0: -2`` the library warned about -- and re-emitted it two
    #: octets too wide on the way out, against the ``length=4`` that
    #: :meth:`~pcapkit.protocols.internet.ipv4.IPv4._make_opt_sid` had always
    #: written. See #534.
    sid: 'int' = UInt16Field()

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

    #: Not used. One octet, holding the place a Quick-Start Request fills with
    #: ``QS TTL``: :rfc:`4782#section-3.1` says in as many words that *"for a
    #: Report of Approved Rate, the fourth byte of the Quick-Start Option is not
    #: used"*, and that *"bytes 5-8 contain a 30-bit QS Nonce and a 2-bit
    #: Reserved field"* -- so the nonce begins at the fifth octet for both
    #: functions, and figure 4 gives this option as ``Length=8`` like figure 3
    #: gives its sibling. The field was missing, so the schema was seven octets
    #: wide against the eight
    #: :meth:`~pcapkit.protocols.internet.ipv4.IPv4._make_opt_qs` writes into
    #: ``length`` and the eight
    #: :meth:`~pcapkit.protocols.internet.ipv4.IPv4._read_opt_qs` demands of it,
    #: which meant a spec-correct Report of Approved Rate read off the wire
    #: decoded its ``nonce`` one octet early -- measured, with the selector
    #: length fixed and this field still absent: ``19088100deadbee0`` warned
    #: ``packet length < 0: -1`` and then died with a bare ``struct.error: bad
    #: char in struct format``, the unconsumed octet having been read as another
    #: option. Declared as padding rather than as data because :rfc:`4782` gives
    #: it no meaning and no caller should be setting it. See #552.
    reserved: 'bytes' = PaddingField(length=1)
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
        'ihl': (4, 4),
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
