# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for hop-by-hop options"""

import collections
from typing import TYPE_CHECKING

from pcapkit.const.ipv6.option import Option as Enum_Option
from pcapkit.const.ipv6.qs_function import QSFunction as Enum_QSFunction
from pcapkit.const.ipv6.router_alert import RouterAlert as Enum_RouterAlert
from pcapkit.const.ipv6.seed_id import SeedID as Enum_SeedID
from pcapkit.const.ipv6.smf_dpd_mode import SMFDPDMode as Enum_SMFDPDMode
from pcapkit.const.ipv6.tagger_id import TaggerID as Enum_TaggerID
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.collections import OptionField
from pcapkit.corekit.fields.field import NoValue
from pcapkit.corekit.fields.ipaddress import IPv4AddressField, IPv6AddressField
from pcapkit.corekit.fields.misc import (ConditionalField, ForwardMatchField, NoValueField,
                                         PayloadField, SchemaField, SwitchField)
from pcapkit.corekit.fields.numbers import (EnumField, NumberField, UInt8Field, UInt16Field,
                                            UInt32Field)
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField
from pcapkit.protocols.schema.schema import EnumSchema, Schema, schema_final
from pcapkit.utilities.exceptions import FieldValueError
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING

__all__ = [
    'HOPOPT',

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
    from typing import Any, DefaultDict, Optional, Type

    from pcapkit.corekit.fields.field import FieldBase as Field
    from pcapkit.protocols.protocol import ProtocolBase as Protocol

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
    raise FieldValueError(f'HOPOPT: invalid MPL Seed-ID type: {s_type}')


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
    schema = SMFDPDOption.registry[mode]
    if schema is None:
        raise FieldValueError(f'HOPOPT: invalid SMF DPD mode: {mode}')
    return SchemaField(length=pkt['test']['len'], schema=schema)


def smf_i_dpd_tid_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`SMFIdentificationBasedDPDOption.tid` field.

    Args:
        pkt: Packet data.

    Returns:
        * If ``tid_type`` is ``0``, returns a :class:`~pcapkit.corekit.fields.misc.NoValueField`
          instance.
        * If ``tid_type`` is ``1``, returns a :class:`~pcapkit.corekit.fields.ipaddress.IPv4AddressField`
          instance.
        * If ``tid_type`` is ``2``, returns a :class:`~pcapkit.corekit.fields.ipaddress.IPv6AddressField`
          instance.
        * Otherwise, returns a :class:`~pcapkit.corekit.fields.strings.BytesField` instance.

    """
    tid_type = Enum_TaggerID.get(pkt['info']['type'])
    tid_len = pkt['info']['len']

    # update type
    pkt['info']['type'] = tid_type

    if tid_type == Enum_TaggerID.NULL:
        if tid_len != 0:
            raise FieldValueError(f'HOPOPT: invalid TaggerID length: {tid_len}')
        return NoValueField()
    if tid_type == Enum_TaggerID.IPv4:
        if tid_len != 3:
            raise FieldValueError(f'HOPOPT: invalid TaggerID length: {tid_len}')
        return IPv4AddressField()
    if tid_type == Enum_TaggerID.IPv6:
        if tid_len != 15:
            raise FieldValueError(f'HOPOPT: invalid TaggerID length: {tid_len}')
        return IPv6AddressField()
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

    schema = QuickStartOption.registry[func]
    if schema is None:
        raise FieldValueError(f'HOPOPT: invalid QS function: {func}')
    return SchemaField(length=5, schema=schema)


class Option(EnumSchema[Enum_Option]):
    """Header schema for HOPOPT options."""

    __default__ = lambda: UnassignedOption

    #: Option type.
    type: 'Enum_Option' = EnumField(length=1, namespace=Enum_Option)
    #: Option length (conditional in case of ``Pad1`` option).
    len: 'int' = ConditionalField(
        UInt8Field(default=0),
        lambda pkt: pkt['type'] != Enum_Option.Pad1,
    )

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        # for Pad1 option, length is always 0
        if self.type == Enum_Option.Pad1:
            self.len = 0
        return self


@schema_final
class UnassignedOption(Option):
    """Header schema for HOPOPT unassigned options."""

    #: Option data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['len'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', data: 'bytes') -> 'None': ...


@schema_final
class PadOption(Option, code=[Enum_Option.Pad1,
                              Enum_Option.PadN]):
    """Header schema for HOPOPT padding options."""

    #: Padding.
    pad: 'bytes' = PaddingField(length=lambda pkt: pkt.get('len', 0))

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int') -> 'None': ...


@schema_final
class TunnelEncapsulationLimitOption(Option, code=Enum_Option.Tunnel_Encapsulation_Limit):
    """Header schema for HOPOPT tunnel encapsulation limit options."""

    #: Tunnel encapsulation limit.
    limit: 'int' = UInt8Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', limit: 'int') -> 'None': ...


@schema_final
class RouterAlertOption(Option, code=Enum_Option.Router_Alert):
    """Header schema for HOPOPT router alert options."""

    #: Router alert.
    alert: 'Enum_RouterAlert' = EnumField(length=2, namespace=Enum_RouterAlert)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', alert: 'Enum_RouterAlert') -> 'None': ...


@schema_final
class CALIPSOOption(Option, code=Enum_Option.CALIPSO):
    """Header schema for HOPOPT common architecture label IPv6 security options."""

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


@schema_final
class _SMFDPDOption(Schema):
    """Header schema for HOPOPT SMF DPD options with generic representation."""

    #: SMF DPD mode.
    test: 'SMFDPDTestFlag' = ForwardMatchField(BitField(length=3, namespace={
        'len': (1, 8),
        'mode': (16, 1),
    }))
    #: SMF DPD data.
    data: 'SMFIdentificationBasedDPDOption | SMFHashBasedDPDOption' = SwitchField(
        selector=smf_dpd_data_selector,
    )

    def post_process(self, packet: 'dict[str, Any]') -> 'SMFDPDOption':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        ret = self.data
        return ret


# register ``_SMFDPDOption`` as ``SMF_DPD`` option
Option.register(Enum_Option.SMF_DPD, _SMFDPDOption)


class SMFDPDOption(Option, EnumSchema[Enum_SMFDPDMode]):
    """Header schema for HOPOPT simplified multicast forwarding duplicate packet
    detection (``SMF_DPD``) options."""

    __enum__: 'DefaultDict[Enum_SMFDPDMode, Type[SMFDPDOption]]' = collections.defaultdict(lambda: None)  # type: ignore[arg-type,return-value]

    if TYPE_CHECKING:
        mode: 'Enum_SMFDPDMode'


@schema_final
class SMFIdentificationBasedDPDOption(SMFDPDOption, code=Enum_SMFDPDMode.I_DPD):
    """Header schema for HOPOPT SMF identification-based DPD options."""

    #: TaggerID information.
    info: 'TaggerIDInfo' = BitField(length=1, namespace={
        'mode': (0, 1),
        'type': (1, 3),
        'len': (4, 4),
    })
    #: TaggerID.
    tid: 'bytes | IPv4Address | IPv6Address' = ConditionalField(
        SwitchField(selector=smf_i_dpd_tid_selector),
        lambda pkt: pkt['info']['type'] != 0,
    )
    #: Identifier.
    id: 'bytes' = BytesField(length=lambda pkt: pkt['len'] - (
        1 if pkt['info']['type'] == 0 else (pkt['info']['len'] + 2)
    ))

    def post_process(self, packet: 'dict[str, Any]') -> 'SMFIdentificationBasedDPDOption':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        ret = super().post_process(packet)  # type: SMFIdentificationBasedDPDOption
        ret.mode = Enum_SMFDPDMode.I_DPD
        return ret

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', info: 'TaggerIDInfo',
                     tid: 'Optional[bytes]', id: 'bytes') -> 'None': ...


@schema_final
class SMFHashBasedDPDOption(SMFDPDOption, code=Enum_SMFDPDMode.H_DPD):
    """Header schema for HOPOPT SMF hash-based DPD options."""

    #: Hash assist value (HAV).
    hav: 'bytes' = BytesField(length=lambda pkt: pkt['len'])

    def post_process(self, packet: 'dict[str, Any]') -> 'SMFIdentificationBasedDPDOption':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        ret = super().post_process(packet)  # type: SMFIdentificationBasedDPDOption
        ret.mode = Enum_SMFDPDMode.H_DPD
        return ret

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', hav: 'bytes') -> 'None': ...


@schema_final
class PDMOption(Option, code=Enum_Option.PDM):
    """Header schema for HOPOPT performance and diagnostic metrics (PDM) options."""

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


@schema_final
class _QuickStartOption(Schema):
    """Header schema for HOPOPT quick start options in generic representation."""

    #: Flags.
    flags: 'QSTestFlags' = ForwardMatchField(BitField(length=3, namespace={
        'func': (16, 4),
    }))
    #: QS data.
    data: 'QuickStartRequestOption | QuickStartReportOption' = SwitchField(
        selector=quick_start_data_selector,
    )

    def post_process(self, packet: 'dict[str, Any]') -> 'QuickStartOption':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        ret = self.data
        ret.func = Enum_QSFunction.get(self.flags['func'])
        return ret


# register ``_QuickStartOption`` as ``Quick_Start`` option
Option.register(Enum_Option.Quick_Start, _QuickStartOption)


class QuickStartOption(Option, EnumSchema[Enum_QSFunction]):
    """Header schema for HOPOPT quick start options."""

    __enum__: 'DefaultDict[Enum_QSFunction, Type[QuickStartOption]]' = collections.defaultdict(lambda: None)  # type: ignore[arg-type,return-value]

    #: Flags.
    flags: 'QuickStartFlags' = BitField(length=1, namespace={
        'func': (0, 4),
        'rate': (4, 4),
    })

    if TYPE_CHECKING:
        func: 'Enum_QSFunction'


@schema_final
class QuickStartRequestOption(QuickStartOption, code=Enum_QSFunction.Quick_Start_Request):
    """Header schema for HOPOPT quick start request options."""

    #: QS time-to-live (TTL).
    ttl: 'int' = UInt8Field()
    #: QS nonce.
    nonce: 'QSNonce' = BitField(length=4, namespace={
        'nonce': (0, 30),
    })

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', flags: 'QuickStartFlags',
                     ttl: 'int', nonce: 'QSNonce') -> 'None': ...


@schema_final
class QuickStartReportOption(QuickStartOption, code=Enum_QSFunction.Report_of_Approved_Rate):
    """Header schema for HOPOPT quick start report of approved rate options."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: QS nonce.
    nonce: 'QSNonce' = BitField(length=4, namespace={
        'nonce': (0, 30),
    })

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', flags: 'QuickStartFlags',
                     nonce: 'QSNonce') -> 'None': ...


@schema_final
class RPLOption(Option, code=[Enum_Option.RPL_Option_0x23,
                              Enum_Option.RPL_Option_0x63]):
    """Header schema for HOPOPT routing protocol for low-power and lossy networks (RPL) options."""

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


@schema_final
class MPLOption(Option, code=Enum_Option.MPL_Option):
    """Header schema for HOPOPT multicast protocol for low-power and lossy networks (MPL) options."""

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

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        if self.flags['type'] == Enum_SeedID.IPV6_SOURCE_ADDRESS:
            self.seed = packet.get('src', NoValue)
        return self

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', flags: 'MPLFlags', seq: 'int',
                     seed: 'Optional[int]') -> 'None': ...


@schema_final
class ILNPOption(Option, code=Enum_Option.ILNP_Nonce):
    """Header schema for HOPOPT identifier-locator network protocol (ILNP) options."""

    #: Nonce value.
    nonce: 'int' = NumberField(length=lambda pkt: pkt['len'], signed=False)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', nonce: 'int') -> 'None': ...


@schema_final
class LineIdentificationOption(Option, code=Enum_Option.Line_Identification_Option):
    """Header schema for HOPOPT line-identification options."""

    #: Line ID length.
    id_len: 'int' = UInt8Field()
    #: Line ID.
    id: 'bytes' = BytesField(length=lambda pkt: pkt['id_len'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', id_len: 'int', id: 'bytes') -> 'None': ...


@schema_final
class JumboPayloadOption(Option, code=Enum_Option.Jumbo_Payload):
    """Header schema for HOPOPT jumbo payload options."""

    #: Jumbo payload length.
    jumbo_len: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', jumbo_len: 'int') -> 'None': ...


@schema_final
class HomeAddressOption(Option, code=Enum_Option.Home_Address):
    """Header schema for HOPOPT home address options."""

    #: Home address.
    addr: 'IPv6Address' = IPv6AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', addr: 'IPv6Address | int | str | bytes') -> 'None': ...


@schema_final
class IPDFFOption(Option, code=Enum_Option.IP_DFF):
    """Header schema for HOPOPT depth-first forwarding (``IP_DFF``) options."""

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


@schema_final
class HOPOPT(Schema):
    """Header schema for HOPOPT packet."""

    #: Next header.
    next: 'Enum_TransType' = EnumField(length=1, namespace=Enum_TransType)
    #: Header length.
    len: 'int' = UInt8Field()
    #: Options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['len'] * 8 + 6,
        base_schema=Option,
        type_name='type',
        registry=Option.registry,
    )
    #: Payload.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, next: 'Enum_TransType', len: 'int',
                     options: 'bytes | list[bytes | Option]',
                     payload: 'bytes | Protocol | Schema') -> 'None': ...
