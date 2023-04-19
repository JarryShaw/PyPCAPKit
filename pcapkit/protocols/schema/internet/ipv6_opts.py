# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for IPv6 destination options"""

import collections
from typing import TYPE_CHECKING, cast

from pcapkit.const.ipv6.option import Option as Enum_Option
from pcapkit.const.ipv6.qs_function import QSFunction as Enum_QSFunction
from pcapkit.const.ipv6.router_alert import RouterAlert as Enum_RouterAlert
from pcapkit.const.ipv6.seed_id import SeedID as Enum_SeedID
from pcapkit.const.ipv6.smf_dpd_mode import SMFDPDMode as Enum_SMFDPDMode
from pcapkit.const.ipv6.tagger_id import TaggerID as Enum_TaggerID
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.collections import OptionField
from pcapkit.corekit.fields.field import NoValue
from pcapkit.corekit.fields.ipaddress import IPv4Field, IPv6Field
from pcapkit.corekit.fields.misc import (ConditionalField, ForwardMatchField, NoValueField,
                                         PayloadField, SchemaField, SwitchField)
from pcapkit.corekit.fields.numbers import (EnumField, NumberField, UInt8Field, UInt16Field,
                                            UInt32Field)
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField
from pcapkit.protocols.schema.schema import Schema
from pcapkit.utilities.exceptions import FieldValueError
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING

__all__ = [
    'IPv6_Opts',

    'SMFDPDOption', 'QuickStartOption',
    'UnassignedOption', 'PadOption', 'TunnelEncapsulationLimitOption',
    'RouterAlertOption', 'CALIPSOOption', 'SMFIdentificationBasedDPDOption',
    'SMFHashBasedDPDOption', 'PDMOption', 'QuickStartRequestOption',
    'QuickStartReportOption', 'RPLOption', 'MPLOption', 'ILNPOption',
    'LineIdentificationOption', 'JumboPayloadOption', 'HomeAddressOption',
    'IPDFFOption',
]

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import IO, Any, Optional

    from pcapkit.corekit.fields.field import _Field as Field
    from pcapkit.protocols.protocol import Protocol

if SPHINX_TYPE_CHECKING:
    from typing_extensions import TypedDict

    class TaggerIDInfo(TypedDict):
        """TaggerID information."""

        #: SMF mode.
        mode: int
        #: TaggerID type.
        type: int
        #: TaggerID length.
        len: int

    class QuickStartFlags(TypedDict):
        """Quick-Start flags."""

        #: QS function.
        func: int
        #: Rate request/report.
        rate: int

    class RPLFlags(TypedDict):
        """RPL flags."""

        #: Down flag.
        down: int
        #: Rank error flag.
        rank_err: int
        #: Forwarding error flag.
        fwd_err: int

    class MPLFlags(TypedDict):
        """MPL flags."""

        #: Seed-ID type. Identifies the length of the
        #: Seed-ID.
        type: int
        #: Max flag. ``1`` indicates that the value in the
        #: sequence field is known to be the largest sequence
        #: number that was received from the MPL Seed.
        max: int
        #: Verification flag. ``0`` indicates that the MPL Option
        #: conforms to this specification.
        drop: int

    class DFFFlags(TypedDict):
        """``IP_DFF`` flags."""

        #: Version.
        ver: int
        #: Duplicate flag.
        dup: int
        #: Retune flag.
        ret: int

    class SMFDPDTestFlag(TypedDict):
        """``SMF_DPD`` test flag."""

        #: Length.
        len: int
        #: DPD mode.
        mode: int

    class QSTestFlags(TypedDict):
        """Quick start test flag."""

        #: QS function.
        func: int

    class QSNonce(TypedDict):
        """Quick start nonce."""

        #: Nonce.
        nonce: int


def mpl_opt_seed_id_len(pkt: 'dict[str, Any]') -> 'int':
    """Return MPL Seed-ID length.

    Args:
        pkt: MPL option unpacked schema.

    Returns:
        MPL Seed-ID length.

    """
    s_type = pkt['flags']['type']
    if s_type == 0:
        return 0
    if s_type == 1:
        return 2
    if s_type == 2:
        return 8
    if s_type == 3:
        return 16
    raise FieldValueError(f'IPv6-Opts: invalid MPL Seed-ID type: {s_type}')


def smf_dpd_data_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`_SMFDPDOption.data` field.

    Args:
        pkt: Packet data.

    Returns:
        * If ``mode`` is ``0``, returns a :class:`~pcapkit.corekit.fields.misc.SchemaField`
          wrapped :class:`~pcapkit.protocols.schema.internet.hopopt.SMFIdentificationBasedDPDOption`
          instance.
        * If ``mode`` is ``1``, returns a :class:`~pcapkit.corekit.fields.misc.SchemaField`
          wrapped :class:`~pcapkit.protocols.schema.internet.hopopt.SMFHashBasedDPDOption`
          instance.

    """
    mode = Enum_SMFDPDMode.get(pkt['test']['mode'])
    if mode == Enum_SMFDPDMode.I_DPD:
        return SchemaField(schema=SMFIdentificationBasedDPDOption)
    if mode == Enum_SMFDPDMode.H_DPD:
        return SchemaField(schema=SMFHashBasedDPDOption)
    raise FieldValueError(f'IPv6-Opts: invalid SMF DPD mode: {mode}')


def smf_i_dpd_tid_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`SMFIdentificationBasedDPDOption.tid` field.

    Args:
        pkt: Packet data.

    Returns:
        * If ``tid_type`` is ``0``, returns a :class:`~pcapkit.corekit.fields.misc.NoValueField`
          instance.
        * If ``tid_type`` is ``1``, returns a :class:`~pcapkit.corekit.fields.ipaddress.IPv4Field`
          instance.
        * If ``tid_type`` is ``2``, returns a :class:`~pcapkit.corekit.fields.ipaddress.IPv6Field`
          instance.
        * Otherwise, returns a :class:`~pcapkit.corekit.fields.strings.BytesField` instance.

    """
    tid_type = Enum_TaggerID.get(pkt['info']['type'])
    tid_len = pkt['info']['len']

    # update type
    pkt['info']['type'] = tid_type

    if tid_type == Enum_TaggerID.NULL:
        if tid_len != 0:
            raise FieldValueError(f'IPv6-Opts: invalid TaggerID length: {tid_len}')
        return NoValueField()
    if tid_type == Enum_TaggerID.IPv4:
        if tid_len != 3:
            raise FieldValueError(f'IPv6-Opts: invalid TaggerID length: {tid_len}')
        return IPv4Field()
    if tid_type == Enum_TaggerID.IPv6:
        if tid_len != 15:
            raise FieldValueError(f'IPv6-Opts: invalid TaggerID length: {tid_len}')
        return IPv6Field()
    return BytesField(length=tid_len + 1)


def quick_start_data_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`_QuickStartOption.data` field.

    Args:
        pkt: Packet data.

    Returns:
        * If ``func`` is ``0``, returns a :class:`~pcapkit.corekit.fields.misc.SchemaField`
          wrapped :class:`~pcapkit.protocols.schema.internet.hopopt.QuickStartRequestOption`
          instance.
        * If ``func`` is ``8``, returns a :class:`~pcapkit.corekit.fields.misc.SchemaField`
          wrapped :class:`~pcapkit.protocols.schema.internet.hopopt.QuickStartReportOption`
          instance.

    """
    func = Enum_QSFunction.get(pkt['flags']['func'])
    pkt['flags']['func'] = func

    if func == Enum_QSFunction.Quick_Start_Request:
        return SchemaField(schema=QuickStartRequestOption)
    if func == Enum_QSFunction.Report_of_Approved_Rate:
        return SchemaField(schema=QuickStartReportOption)
    raise FieldValueError(f'IPv6-Opts: invalid QS function: {func}')


class Option(Schema):
    """Header schema for IPv6-Opts options."""

    #: Option type.
    type: 'Enum_Option' = EnumField(length=1, namespace=Enum_Option)
    #: Option length (conditional in case of ``Pad1`` option).
    len: 'int' = ConditionalField(
        UInt8Field(default=0),
        lambda pkt: pkt['type'] != Enum_Option.Pad1,
    )

    @classmethod
    def post_process(cls, schema: 'Schema', data: 'IO[bytes]',
                     length: 'int', packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            schema: parsed schema
            data: Packed data.
            length: Length of data.
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        if TYPE_CHECKING:
            schema = cast('Option', schema)

        # for Pad1 option, length is always 0
        if schema.type == Enum_Option.Pad1:
            schema.len = 0
        return schema


class UnassignedOption(Option):
    """Header schema for IPv6-Opts unassigned options."""

    #: Option data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['len'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', data: 'bytes') -> 'None': ...


class PadOption(Option):
    """Header schema for IPv6-Opts padding options."""

    #: Padding.
    pad: 'bytes' = PaddingField(length=lambda pkt: pkt['len'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int') -> 'None': ...


class TunnelEncapsulationLimitOption(Option):
    """Header schema for IPv6-Opts tunnel encapsulation limit options."""

    #: Tunnel encapsulation limit.
    limit: 'int' = UInt8Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', limit: 'int') -> 'None': ...


class RouterAlertOption(Option):
    """Header schema for IPv6-Opts router alert options."""

    #: Router alert.
    alert: 'Enum_RouterAlert' = EnumField(length=2, namespace=Enum_RouterAlert)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', alert: 'Enum_RouterAlert') -> 'None': ...


class CALIPSOOption(Option):
    """Header schema for IPv6-Opts common architecture label IPv6 security options."""

    #: CALIPSO domain of interpretation.
    domain: 'int' = UInt32Field()
    #: Compartment length.
    cmpt_len: 'int' = UInt8Field()
    #: Sens level.
    level: 'int' = UInt8Field()
    #: Checksum (CRC-16).
    checksum: 'bytes' = BytesField(length=2)
    #: Compartment bitmap.
    bitmap: 'bytes' = ConditionalField(
        BytesField(length=lambda pkt: pkt['cmpt_len'] * 4),
        lambda pkt: pkt['cmpt_len'] > 0,
    )
    #: Padding.
    pad: 'bytes' = PaddingField(length=lambda pkt: pkt['len'] - 8 - pkt['cmpt_len'] * 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', domain: 'int', cmpt_len: 'int',
                     level: 'int', checksum: 'bytes', bitmap: 'Optional[bytes]') -> 'None': ...


class _SMFDPDOption(Schema):
    """Header schema for IPv6-Opts SMF DPD options with generic representation."""

    #: SMF DPD mode.
    test: 'SMFDPDTestFlag' = ForwardMatchField(BitField(length=3, namespace={
        'len': (1, 8),
        'mode': (16, 1),
    }))
    #: SMF DPD data.
    data: 'SMFIdentificationBasedDPDOption | SMFHashBasedDPDOption' = SwitchField(
        length=lambda pkt: pkt['test']['len'],
        selector=smf_dpd_data_selector,
    )

    @classmethod
    def post_process(cls, schema: 'Schema', data: 'IO[bytes]',
                     length: 'int', packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            schema: parsed schema
            data: Packed data.
            length: Length of data.
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        if TYPE_CHECKING:
            schema = cast('_SMFDPDOption', schema)

        ret = schema.data
        ret.mode = Enum_SMFDPDMode.get(schema.test['mode'])
        return ret


class SMFDPDOption(Option):
    """Header schema for IPv6-Opts simplified multicast forwarding duplicate packet
    detection (``SMF_DPD``) options."""

    if TYPE_CHECKING:
        mode: 'Enum_SMFDPDMode'


class SMFIdentificationBasedDPDOption(SMFDPDOption):
    """Header schema for IPv6-Opts SMF identification-based DPD options."""

    test: 'SMFDPDTestFlag' = ForwardMatchField(BitField(length=1, namespace={
        'mode': (0, 1),
    }))
    #: TaggerID information.
    info: 'TaggerIDInfo' = BitField(length=1, namespace={
        'mode': (0, 1),
        'type': (1, 3),
        'len': (4, 4),
    })
    #: TaggerID.
    tid: 'bytes | IPv4Address | IPv6Address' = ConditionalField(
        SwitchField(length=lambda pkt: pkt['info']['len'] + 1,
                    selector=smf_i_dpd_tid_selector),
        lambda pkt: pkt['info']['type'] != 0,
    )
    #: Identifier.
    id: 'bytes' = BytesField(length=lambda pkt: pkt['len'] - (
        1 if pkt['info']['type'] == 0 else (pkt['info']['len'] + 2)
    ))

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', info: 'TaggerIDInfo',
                     tid: 'Optional[bytes]', id: 'bytes') -> 'None': ...


class SMFHashBasedDPDOption(SMFDPDOption):
    """Header schema for IPv6-Opts SMF hash-based DPD options."""

    #: Hash assist value (HAV).
    hav: 'bytes' = BytesField(length=lambda pkt: pkt['len'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', hav: 'bytes') -> 'None': ...


class PDMOption(Option):
    """Header schema for IPv6-Opts performance and diagnostic metrics (PDM) options."""

    #: Scale delta time last received (DTLR).
    scaledtlr: 'int' = UInt8Field()
    #: Scale delta time last sent (DTLS).
    scaledtls: 'int' = UInt8Field()
    #: Packet sequence number (PSN) this packet.
    psntp: 'int' = UInt16Field()
    #: Packet sequence number (PSN) last received.
    psnlr: 'int' = UInt16Field()
    #: Delta time last received (DTLR).
    deltatlr: 'int' = UInt16Field()
    #: Delta time last sent (DTLS).
    deltatls: 'int' = UInt16Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', scaledtlr: 'int', scaledtls: 'int',
                     psntp: 'int', psnlr: 'int', deltatlr: 'int', deltatls: 'int') -> 'None': ...


class _QuickStartOption(Schema):
    """Header schema for IPv6-Opts quick start options in generic representation."""

    #: Flags.
    flags: 'QSTestFlags' = ForwardMatchField(BitField(length=3, namespace={
        'func': (16, 4),
    }))
    #: QS data.
    data: 'QuickStartRequestOption | QuickStartReportOption' = SwitchField(
        length=5,
        selector=quick_start_data_selector,
    )

    @classmethod
    def post_process(cls, schema: 'Schema', data: 'IO[bytes]',
                     length: 'int', packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            schema: parsed schema
            data: Packed data.
            length: Length of data.
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        if TYPE_CHECKING:
            schema = cast('_QuickStartOption', schema)

        ret = schema.data
        ret.func = Enum_QSFunction.get(packet['flags']['func'])
        return ret


class QuickStartOption(Option):
    """Header schema for IPv6-Opts quick start options."""

    #: Flags.
    flags: 'QuickStartFlags' = BitField(length=1, namespace={
        'func': (0, 4),
        'rate': (4, 4),
    })

    if TYPE_CHECKING:
        func: 'Enum_QSFunction'


class QuickStartRequestOption(QuickStartOption):
    """Header schema for IPv6-Opts quick start request options."""

    #: QS time-to-live (TTL).
    ttl: 'int' = UInt8Field()
    #: QS nonce.
    nonce: 'QSNonce' = BitField(length=4, namespace={
        'nonce': (0, 30),
    })

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', flags: 'QuickStartFlags',
                     ttl: 'int', nonce: 'QSNonce') -> 'None': ...


class QuickStartReportOption(QuickStartOption):
    """Header schema for IPv6-Opts quick start report of approved rate options."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: QS nonce.
    nonce: 'QSNonce' = BitField(length=4, namespace={
        'nonce': (0, 30),
    })

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', flags: 'QuickStartFlags',
                     nonce: 'QSNonce') -> 'None': ...


class RPLOption(Option):
    """Header schema for IPv6-Opts routing protocol for low-power and lossy networks (RPL) options."""

    #: Flags.
    flags: 'RPLFlags' = BitField(length=1, namespace={
        'down': (0, 1),
        'rank_err': (1, 1),
        'fwd_err': (2, 1),
    })
    #: RPL instance ID.
    id: 'int' = UInt8Field()
    #: Sender rank.
    rank: 'int' = UInt16Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', flags: 'RPLFlags', id: 'int',
                     rank: 'int') -> 'None': ...


class MPLOption(Option):
    """Header schema for IPv6-Opts multicast protocol for low-power and lossy networks (MPL) options."""

    #: Flags.
    flags: 'MPLFlags' = BitField(length=1, namespace={
        'type': (0, 2),
        'max': (2, 1),
        'drop': (3, 1),
    })
    #: MPL sequence number.
    seq: 'int' = UInt8Field()
    #: MPL Seed-ID.
    seed: 'int' = ConditionalField(
        NumberField(length=mpl_opt_seed_id_len, signed=False),
        lambda pkt: pkt['flags']['type'] != Enum_SeedID.IPV6_SOURCE_ADDRESS,
    )
    #: Reserved data (padding).
    pad: 'bytes' = PaddingField(length=lambda pkt: pkt['len'] - 2 - (
        0 if pkt['flags']['type'] == 0 else mpl_opt_seed_id_len(pkt)
    ))

    @classmethod
    def post_process(cls, schema: 'Schema', data: 'IO[bytes]',
                     length: 'int', packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            schema: parsed schema
            data: Packed data.
            length: Length of data.
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        if TYPE_CHECKING:
            schema = cast('MPLOption', schema)

        if schema.flags['type'] == Enum_SeedID.IPV6_SOURCE_ADDRESS:
            schema.seed = packet.get('src', NoValue)
        return schema

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', flags: 'MPLFlags', seq: 'int',
                     seed: 'Optional[int]') -> 'None': ...


class ILNPOption(Option):
    """Header schema for IPv6-Opts identifier-locator network protocol (ILNP) options."""

    #: Nonce value.
    nonce: 'int' = NumberField(length=lambda pkt: pkt['len'], signed=False)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', nonce: 'int') -> 'None': ...


class LineIdentificationOption(Option):
    """Header schema for IPv6-Opts line-identification options."""

    #: Line ID length.
    id_len: 'int' = UInt8Field()
    #: Line ID.
    id: 'bytes' = BytesField(length=lambda pkt: pkt['id_len'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', id_len: 'int', id: 'bytes') -> 'None': ...


class JumboPayloadOption(Option):
    """Header schema for IPv6-Opts jumbo payload options."""

    #: Jumbo payload length.
    jumbo_len: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', jumbo_len: 'int') -> 'None': ...


class HomeAddressOption(Option):
    """Header schema for IPv6-Opts home address options."""

    #: Home address.
    addr: 'IPv6Address' = IPv6Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', addr: 'IPv6Address | int | str | bytes') -> 'None': ...


class IPDFFOption(Option):
    """Header schema for IPv6-Opts depth-first forwarding (``IP_DFF``) options."""

    #: Flags.
    flags: 'DFFFlags' = BitField(length=1, namespace={
        'ver': (0, 2),
        'dup': (2, 1),
        'ret': (3, 1),
    })
    #: Sequence number.
    seq: 'int' = UInt16Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', flags: 'DFFFlags', seq: 'int') -> 'None': ...


class IPv6_Opts(Schema):
    """Header schema for IPv6-Opts packet."""

    #: Next header.
    next: 'Enum_TransType' = EnumField(length=1, namespace=Enum_TransType)
    #: Header length.
    len: 'int' = UInt8Field()
    #: Options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['len'] * 8 + 6,
        base_schema=Option,
        type_name='type',
        registry=collections.defaultdict(lambda: UnassignedOption, {
            Enum_Option.Pad1: PadOption,
            Enum_Option.PadN: PadOption,
            Enum_Option.Tunnel_Encapsulation_Limit: TunnelEncapsulationLimitOption,
            Enum_Option.Router_Alert: RouterAlertOption,
            Enum_Option.CALIPSO: CALIPSOOption,
            Enum_Option.SMF_DPD: _SMFDPDOption,
            Enum_Option.PDM: PDMOption,
            Enum_Option.Quick_Start: _QuickStartOption,
            Enum_Option.RPL_Option_0x63: RPLOption,
            Enum_Option.MPL_Option: MPLOption,
            Enum_Option.ILNP_Nonce: ILNPOption,
            Enum_Option.Line_Identification_Option: LineIdentificationOption,
            Enum_Option.Jumbo_Payload: JumboPayloadOption,
            Enum_Option.Home_Address: HomeAddressOption,
            Enum_Option.IP_DFF: IPDFFOption,
        })
    )
    #: Payload.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, next: 'Enum_TransType', len: 'int',
                     options: 'bytes | list[bytes | Option]',
                     payload: 'bytes | Protocol | Schema') -> 'None': ...
