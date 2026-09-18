# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for IPv6 destination options"""

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
    from typing import Any, DefaultDict, Optional, Type

    from pcapkit.corekit.fields.field import FieldBase as Field
    from pcapkit.protocols.protocol import ProtocolBase as Protocol

if SPHINX_TYPE_CHECKING:  # pragma: no cover
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


def smf_i_dpd_id_len(pkt: 'dict[str, Any]') -> 'int':
    """Return SMF I-DPD identifier length.

    Args:
        pkt: SMF identification-based DPD option unpacked schema.

    Returns:
        SMF I-DPD identifier length.

    Raises:
        FieldValueError: If ``Opt Data Len`` on the wire is too short to hold
            the TaggerID it declares, which would otherwise underflow the
            identifier length below zero.

    """
    length = pkt['len'] - (1 if pkt['info']['type'] == 0 else (pkt['info']['len'] + 2))
    if length < 0:
        raise FieldValueError(f'IPv6-Opts: invalid SMF I-DPD option length: {pkt["len"]}')
    return length


def smf_dpd_data_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`_SMFDPDOption.data` field.

    Args:
        pkt: Packet data.

    Returns:
        * If ``mode`` is ``0``, returns a :class:`~pcapkit.corekit.fields.misc.SchemaField`
          wrapped :class:`~pcapkit.protocols.schema.internet.ipv6_opts.SMFIdentificationBasedDPDOption`
          instance.
        * If ``mode`` is ``1``, returns a :class:`~pcapkit.corekit.fields.misc.SchemaField`
          wrapped :class:`~pcapkit.protocols.schema.internet.ipv6_opts.SMFHashBasedDPDOption`
          instance.

    Note:
        The field is sized ``Opt Data Len + 2`` rather than ``Opt Data Len``.
        ``Opt Data Len`` counts only what follows the option header
        [:rfc:`8200#section-4.2`], while both schemas this may return inherit
        :attr:`Option.type` and :attr:`Option.len` and so parse those two octets
        themselves. Sizing the field at ``Opt Data Len`` handed them an area two
        octets short of the option they read, which
        :class:`~pcapkit.corekit.fields.collections.OptionField` then mis-counted
        against the option area -- c.f. #431.

    """
    mode = Enum_SMFDPDMode.get(pkt['test']['mode'])
    schema = SMFDPDOption.registry[mode]
    if schema is None:
        raise FieldValueError(f'IPv6-Opts: invalid SMF DPD mode: {mode}')
    return SchemaField(length=pkt['test']['len'] + 2, schema=schema)


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
            raise FieldValueError(f'IPv6-Opts: invalid TaggerID length: {tid_len}')
        return NoValueField()
    if tid_type == Enum_TaggerID.IPv4:
        if tid_len != 3:
            raise FieldValueError(f'IPv6-Opts: invalid TaggerID length: {tid_len}')
        return IPv4AddressField()
    if tid_type == Enum_TaggerID.IPv6:
        if tid_len != 15:
            raise FieldValueError(f'IPv6-Opts: invalid TaggerID length: {tid_len}')
        return IPv6AddressField()
    return BytesField(length=tid_len + 1)


def quick_start_data_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`_QuickStartOption.data` field.

    Args:
        pkt: Packet data.

    Returns:
        * If ``func`` is ``0``, returns a :class:`~pcapkit.corekit.fields.misc.SchemaField`
          wrapped :class:`~pcapkit.protocols.schema.internet.ipv6_opts.QuickStartRequestOption`
          instance.
        * If ``func`` is ``8``, returns a :class:`~pcapkit.corekit.fields.misc.SchemaField`
          wrapped :class:`~pcapkit.protocols.schema.internet.ipv6_opts.QuickStartReportOption`
          instance.

    """
    func = Enum_QSFunction.get(pkt['flags']['func'])
    pkt['flags']['func'] = func

    schema = QuickStartOption.registry[func]
    if schema is None:
        raise FieldValueError(f'IPv6-Opts: invalid QS function: {func}')
    return SchemaField(length=5, schema=schema)


def pad_opt_data_len(pkt: 'dict[str, Any]') -> 'int':
    """Return the length of the padding data of a padding option.

    Args:
        pkt: Padding option unpacked schema.

    Returns:
        Number of padding octets carried after the option header, i.e. the
        value of the ``Opt Data Len`` field of a ``PadN`` option, and zero for
        a ``Pad1`` option, which carries no such field.

    Note:
        A ``Pad1`` option is a single octet with neither an ``Opt Data Len``
        field nor any option data (c.f. :rfc:`8200#section-4.2`), which is why
        :attr:`Option.len` is declared as a
        :class:`~pcapkit.corekit.fields.misc.ConditionalField` and is skipped
        for it. A skipped conditional field is *recorded* in the packet data as
        :data:`~pcapkit.corekit.fields.field.NoValue`, rather than being left
        out of it, so the test below has to be on the **value** and not on the
        presence of the key: ``pkt.get('len', 0)`` on its own hands that
        :obj:`~pcapkit.corekit.fields.field.NoValueType` straight to
        :class:`~pcapkit.corekit.fields.strings.PaddingField`, where it becomes
        an unusable :mod:`struct` template and surfaces much later as an opaque
        :exc:`struct.error` -- which is exactly how a ``Pad1`` option used to
        fail to parse.

    """
    length = pkt.get('len', 0)
    if not isinstance(length, int):  # ``NoValue`` (skipped) or :obj:`None` (unset)
        return 0
    return length


def calipso_pad_len(pkt: 'dict[str, Any]') -> 'int':
    """Return CALIPSO option padding length.

    Args:
        pkt: CALIPSO option unpacked schema.

    Returns:
        CALIPSO option padding length.

    Raises:
        FieldValueError: If ``Opt Data Len`` on the wire is too short to hold
            the fixed header and the compartment bitmap declared by
            ``cmpt_len``, which would otherwise underflow the padding length
            below zero.

    """
    length = pkt['len'] - 8 - pkt['cmpt_len'] * 4
    if length < 0:
        raise FieldValueError(f'IPv6-Opts: invalid CALIPSO option length: {pkt["len"]}')
    return length


def mpl_opt_pad_len(pkt: 'dict[str, Any]') -> 'int':
    """Return MPL option padding length.

    Args:
        pkt: MPL option unpacked schema.

    Returns:
        MPL option padding length.

    Raises:
        FieldValueError: If ``Opt Data Len`` on the wire is too short to hold
            the fixed header and the Seed-ID declared by ``flags.type``, which
            would otherwise underflow the padding length below zero.

    """
    length = pkt['len'] - 2 - (0 if pkt['flags']['type'] == 0 else mpl_opt_seed_id_len(pkt))
    if length < 0:
        raise FieldValueError(f'IPv6-Opts: invalid MPL option length: {pkt["len"]}')
    return length


class Option(EnumSchema[Enum_Option]):
    """Header schema for IPv6-Opts options."""

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
    """Header schema for IPv6-Opts unassigned options."""

    #: Option data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['len'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', data: 'bytes') -> 'None': ...


@schema_final
class PadOption(Option, code=[Enum_Option.Pad1,
                              Enum_Option.PadN]):
    """Header schema for IPv6-Opts padding options.

    The two padding options do **not** share a wire shape: a ``Pad1`` option is
    a lone type octet, whereas a ``PadN`` option is a type octet, an
    ``Opt Data Len`` octet, and that many padding octets [:rfc:`8200#section-4.2`].
    Both the ``Opt Data Len`` octet (:attr:`Option.len`) and the padding data
    (:attr:`self.pad <PadOption.pad>`) are therefore sized from the option type,
    so that a ``Pad1`` option consumes exactly one octet.

    """

    #: Padding.
    pad: 'bytes' = PaddingField(length=pad_opt_data_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int') -> 'None': ...


@schema_final
class TunnelEncapsulationLimitOption(Option, code=Enum_Option.Tunnel_Encapsulation_Limit):
    """Header schema for IPv6-Opts tunnel encapsulation limit options."""

    #: Tunnel encapsulation limit.
    limit: 'int' = UInt8Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', limit: 'int') -> 'None': ...


@schema_final
class RouterAlertOption(Option, code=Enum_Option.Router_Alert):
    """Header schema for IPv6-Opts router alert options."""

    #: Router alert.
    alert: 'Enum_RouterAlert' = EnumField(length=2, namespace=Enum_RouterAlert)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', alert: 'Enum_RouterAlert') -> 'None': ...


@schema_final
class CALIPSOOption(Option, code=Enum_Option.CALIPSO):
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
    pad: 'bytes' = PaddingField(length=calipso_pad_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', domain: 'int', cmpt_len: 'int',
                     level: 'int', checksum: 'bytes', bitmap: 'Optional[bytes]') -> 'None': ...


@schema_final
class _SMFDPDOption(Schema):
    """Header schema for IPv6-Opts SMF DPD options with generic representation.

    The ``test`` field forward-matches the first three octets of the option --
    ``Option Type``, ``Opt Data Len`` and the octet carrying the DPD mode bit --
    without consuming them, so that :func:`smf_dpd_data_selector` can size and
    choose the schema which then reads the option properly. Its ``namespace``
    offsets are therefore bit offsets into the *option*, not into any one field
    of it: ``Opt Data Len`` is octet 1, i.e. bits 8 to 15, and the mode bit is
    the first bit of octet 2 [:rfc:`6621#section-8.1`].

    """

    #: SMF DPD mode.
    test: 'SMFDPDTestFlag' = ForwardMatchField(BitField(length=3, namespace={
        'len': (8, 8),
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
    """Header schema for IPv6-Opts simplified multicast forwarding duplicate packet
    detection (``SMF_DPD``) options."""

    __enum__: 'DefaultDict[Enum_SMFDPDMode, Type[SMFDPDOption]]' = collections.defaultdict(lambda: None)  # type: ignore[arg-type,return-value]

    if TYPE_CHECKING:
        mode: 'Enum_SMFDPDMode'


@schema_final
class SMFIdentificationBasedDPDOption(SMFDPDOption, code=Enum_SMFDPDMode.I_DPD):
    """Header schema for IPv6-Opts SMF identification-based DPD options."""

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
    id: 'bytes' = BytesField(length=smf_i_dpd_id_len)

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
    """Header schema for IPv6-Opts SMF hash-based DPD options."""

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


@schema_final
class _QuickStartOption(Schema):
    """Header schema for IPv6-Opts quick start options in generic representation."""

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
    """Header schema for IPv6-Opts quick start options."""

    # NOTE: This declaration scopes the QS-function registry to this class. Without
    # it the subclasses below register into the *parent* ``Option`` registry, whose
    # keys are IPv6-Opts option *types* -- and since ``Quick_Start_Request`` is 0
    # and ``Report_of_Approved_Rate`` is 8, they would clobber option types 0
    # (``Pad1``) and 8 (``SMF_DPD``). ``hopopt.py`` carries the same declaration.
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


@schema_final
class QuickStartReportOption(QuickStartOption, code=Enum_QSFunction.Report_of_Approved_Rate):
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


@schema_final
class RPLOption(Option, code=[Enum_Option.RPL_Option_0x23,
                              Enum_Option.RPL_Option_0x63]):
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


@schema_final
class MPLOption(Option, code=Enum_Option.MPL_Option):
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
    pad: 'bytes' = PaddingField(length=mpl_opt_pad_len)

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
    """Header schema for IPv6-Opts identifier-locator network protocol (ILNP) options."""

    #: Nonce value.
    nonce: 'int' = NumberField(length=lambda pkt: pkt['len'], signed=False)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', nonce: 'int') -> 'None': ...


@schema_final
class LineIdentificationOption(Option, code=Enum_Option.Line_Identification_Option):
    """Header schema for IPv6-Opts line-identification options."""

    #: Line ID length.
    id_len: 'int' = UInt8Field()
    #: Line ID.
    id: 'bytes' = BytesField(length=lambda pkt: pkt['id_len'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', id_len: 'int', id: 'bytes') -> 'None': ...


@schema_final
class JumboPayloadOption(Option, code=Enum_Option.Jumbo_Payload):
    """Header schema for IPv6-Opts jumbo payload options."""

    #: Jumbo payload length.
    jumbo_len: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', jumbo_len: 'int') -> 'None': ...


@schema_final
class HomeAddressOption(Option, code=Enum_Option.Home_Address):
    """Header schema for IPv6-Opts home address options."""

    #: Home address.
    addr: 'IPv6Address' = IPv6AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', len: 'int', addr: 'IPv6Address | int | str | bytes') -> 'None': ...


@schema_final
class IPDFFOption(Option, code=Enum_Option.IP_DFF):
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


@schema_final
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
        registry=Option.registry,
    )
    #: Payload.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, next: 'Enum_TransType', len: 'int',
                     options: 'bytes | list[bytes | Option]',
                     payload: 'bytes | Protocol | Schema') -> 'None': ...
