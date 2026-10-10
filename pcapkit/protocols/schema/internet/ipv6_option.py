# -*- coding: utf-8 -*-
"""helpers shared by the IPv6 option schemas

:mod:`pcapkit.protocols.schema.internet.ipv6_option` holds the field callbacks
that size and select the IPv6 options [:rfc:`8200#section-4.2`] carried by
both the Hop-by-Hop Options header
(:mod:`~pcapkit.protocols.schema.internet.hopopt`) and the Destination Options
header (:mod:`~pcapkit.protocols.schema.internet.ipv6_opts`).

Each of those two modules declares its own option schemas, so the helpers take
what differs between them as parameters: ``prefix`` is the name of the header,
which leads each error message (``HOPOPT`` or ``IPv6-Opts``), and the selectors
take the option schemas they choose from. Each module binds the parameters in
a function of the same name, which is what its fields use.

"""

from typing import TYPE_CHECKING

from pcapkit.const.ipv6.qs_function import QSFunction as Enum_QSFunction
from pcapkit.const.ipv6.smf_dpd_mode import SMFDPDMode as Enum_SMFDPDMode
from pcapkit.const.ipv6.tagger_id import TaggerID as Enum_TaggerID
from pcapkit.corekit.fields.ipaddress import IPv4AddressField, IPv6AddressField
from pcapkit.corekit.fields.misc import NoValueField, SchemaField
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.utilities.exceptions import FieldValueError

__all__ = [
    'rpl_opt_sub_tlv_len', 'mpl_opt_seed_id_len', 'smf_i_dpd_id_len',
    'smf_dpd_data_selector', 'smf_i_dpd_tid_selector', 'quick_start_data_selector',
    'pad_opt_data_len', 'calipso_pad_len', 'mpl_opt_pad_len',
]

if TYPE_CHECKING:
    from typing import Any, Optional, Type

    from pcapkit.corekit.fields.field import FieldBase as Field
    from pcapkit.protocols.schema.schema import EnumMeta, Schema


def rpl_opt_sub_tlv_len(pkt: 'dict[str, Any]') -> 'int':
    """Return RPL option sub-TLV length.

    Args:
        pkt: RPL option unpacked schema.

    Returns:
        RPL option sub-TLV length, i.e. ``Opt Data Len`` less the four octets
        of the fixed fields. An ``Opt Data Len`` below ``4`` gives ``0``, and
        the reader then rejects the option.

    """
    return max(pkt['len'] - 4, 0)


def mpl_opt_seed_id_len(pkt: 'dict[str, Any]', *, prefix: 'str') -> 'int':
    """Return MPL Seed-ID length.

    Args:
        pkt: MPL option unpacked schema.
        prefix: Name of the extension header, leading the error message.

    Returns:
        MPL Seed-ID length.

    Raises:
        FieldValueError: If ``flags.type`` is not a defined Seed-ID type.

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
    raise FieldValueError(f'{prefix}: invalid MPL Seed-ID type: {s_type}')


def smf_i_dpd_id_len(pkt: 'dict[str, Any]', *, prefix: 'str') -> 'int':
    """Return SMF I-DPD identifier length.

    Args:
        pkt: SMF identification-based DPD option unpacked schema.
        prefix: Name of the extension header, leading the error message.

    Returns:
        SMF I-DPD identifier length.

    Raises:
        FieldValueError: If ``Opt Data Len`` on the wire is too short to hold
            the TaggerID it declares, which would otherwise underflow the
            identifier length below zero.

    """
    length = pkt['len'] - (1 if pkt['info']['type'] == 0 else (pkt['info']['len'] + 2))
    if length < 0:
        raise FieldValueError(f'{prefix}: invalid SMF I-DPD option length: {pkt["len"]}')
    return length


def smf_dpd_data_selector(pkt: 'dict[str, Any]', *, prefix: 'str',
                          base: 'EnumMeta') -> 'Field':
    """Selector function for the ``data`` field of an ``SMF_DPD`` option.

    Args:
        pkt: Packet data.
        prefix: Name of the extension header, leading the error message.
        base: The header's ``SMFDPDOption`` schema, whose registry maps the
            DPD mode to the schema that reads the option.

    Returns:
        * If ``mode`` is ``0``, returns a :class:`~pcapkit.corekit.fields.misc.SchemaField`
          wrapped ``SMFIdentificationBasedDPDOption`` instance.
        * If ``mode`` is ``1``, returns a :class:`~pcapkit.corekit.fields.misc.SchemaField`
          wrapped ``SMFHashBasedDPDOption`` instance.

    Raises:
        FieldValueError: If ``Opt Data Len`` is ``0``, or if no schema is
            registered for the DPD mode.

    Note:
        The field is sized ``Opt Data Len + 2`` rather than ``Opt Data Len``.
        ``Opt Data Len`` counts only what follows the option header
        [:rfc:`8200#section-4.2`], while both schemas this may return inherit
        the option's ``type`` and ``len`` fields and so parse those two octets
        themselves. Sizing the field at ``Opt Data Len`` would hand them an area two
        octets short of the option they read, which
        :class:`~pcapkit.corekit.fields.collections.OptionField` would then
        mis-count against the option area.

    """
    # NOTE: With ``Opt Data Len`` 0 the option has no data octet, so the mode
    # bit forward-matched above belongs to whatever follows the option.
    if pkt['test']['len'] == 0:
        raise FieldValueError(f'{prefix}: invalid SMF DPD option length: 0')

    mode = Enum_SMFDPDMode.get(pkt['test']['mode'])
    schema: 'Optional[Type[Schema]]' = base.registry[mode]
    if schema is None:
        raise FieldValueError(f'{prefix}: invalid SMF DPD mode: {mode}')
    return SchemaField(length=pkt['test']['len'] + 2, schema=schema)


def smf_i_dpd_tid_selector(pkt: 'dict[str, Any]', *, prefix: 'str') -> 'Field':
    """Selector function for the ``tid`` field of an SMF I-DPD option.

    Args:
        pkt: Packet data.
        prefix: Name of the extension header, leading the error message.

    Returns:
        * If ``tid_type`` is ``0`` (``NULL``), returns a
          :class:`~pcapkit.corekit.fields.misc.NoValueField` instance.
        * If ``tid_type`` is ``2`` (``IPv4``), returns a
          :class:`~pcapkit.corekit.fields.ipaddress.IPv4AddressField` instance.
        * If ``tid_type`` is ``3`` (``IPv6``), returns a
          :class:`~pcapkit.corekit.fields.ipaddress.IPv6AddressField` instance.
        * Otherwise, returns a :class:`~pcapkit.corekit.fields.strings.BytesField` instance.

    Raises:
        FieldValueError: If ``tid_len`` does not match the length of the
            ``NULL``, ``IPv4`` or ``IPv6`` TaggerID type.

    """
    tid_type = Enum_TaggerID.get(pkt['info']['type'])
    tid_len = pkt['info']['len']

    # update type
    pkt['info']['type'] = tid_type

    if tid_type == Enum_TaggerID.NULL:
        if tid_len != 0:
            raise FieldValueError(f'{prefix}: invalid TaggerID length: {tid_len}')
        return NoValueField()
    if tid_type == Enum_TaggerID.IPv4:
        if tid_len != 3:
            raise FieldValueError(f'{prefix}: invalid TaggerID length: {tid_len}')
        return IPv4AddressField()
    if tid_type == Enum_TaggerID.IPv6:
        if tid_len != 15:
            raise FieldValueError(f'{prefix}: invalid TaggerID length: {tid_len}')
        return IPv6AddressField()
    return BytesField(length=tid_len + 1)


def quick_start_data_selector(pkt: 'dict[str, Any]', *, base: 'EnumMeta',
                              unassigned: 'Type[Schema]') -> 'Field':
    """Selector function for the ``data`` field of a ``Quick_Start`` option.

    Args:
        pkt: Packet data.
        base: The header's ``QuickStartOption`` schema, whose registry maps
            the QS function to the schema that reads the option.
        unassigned: The header's ``UnassignedOption`` schema.

    Returns:
        * If ``func`` is ``0``, returns a :class:`~pcapkit.corekit.fields.misc.SchemaField`
          wrapped ``QuickStartRequestOption`` instance.
        * If ``func`` is ``8``, returns a :class:`~pcapkit.corekit.fields.misc.SchemaField`
          wrapped ``QuickStartReportOption`` instance.
        * Otherwise, returns a :class:`~pcapkit.corekit.fields.misc.SchemaField`
          wrapped ``unassigned`` instance, sized by the option's own
          ``Opt Data Len``.

    """
    func = Enum_QSFunction.get(pkt['flags']['func'])
    pkt['flags']['func'] = func

    schema: 'Optional[Type[Schema]]' = base.registry[func]
    if schema is None:
        # An unassigned function has no defined layout, so the option is kept
        # as raw data, sized by its own ``Opt Data Len``.
        return SchemaField(length=pkt['flags']['len'] + 2, schema=unassigned)

    # NOTE: The suboption schemas carry the option's own ``type`` and ``len``
    # octets, so this is the width of the whole option: the two header octets
    # plus the six data octets :rfc:`4782#section-3.2` gives both functions.
    return SchemaField(length=8, schema=schema)


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
        the option's ``len`` field is declared as a
        :class:`~pcapkit.corekit.fields.misc.ConditionalField` and is skipped
        for it. A skipped conditional field is *recorded* in the packet data as
        :data:`~pcapkit.corekit.fields.field.NO_VALUE`, rather than being left
        out of it, so the test below has to be on the **value** and not on the
        presence of the key: ``pkt.get('len', 0)`` on its own hands that
        :obj:`~pcapkit.corekit.fields.field.NoValueType` straight to
        :class:`~pcapkit.corekit.fields.strings.PaddingField`, where it becomes
        an unusable :mod:`struct` template and surfaces much later as an opaque
        :exc:`struct.error`, which is how a ``Pad1`` option would fail to parse.

    """
    length = pkt.get('len', 0)
    if not isinstance(length, int):  # ``NO_VALUE`` (skipped) or :obj:`None` (unset)
        return 0
    return length


def calipso_pad_len(pkt: 'dict[str, Any]', *, prefix: 'str') -> 'int':
    """Return CALIPSO option padding length.

    Args:
        pkt: CALIPSO option unpacked schema.
        prefix: Name of the extension header, leading the error message.

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
        raise FieldValueError(f'{prefix}: invalid CALIPSO option length: {pkt["len"]}')
    return length


def mpl_opt_pad_len(pkt: 'dict[str, Any]', *, prefix: 'str') -> 'int':
    """Return MPL option padding length.

    Args:
        pkt: MPL option unpacked schema.
        prefix: Name of the extension header, leading the error message.

    Returns:
        MPL option padding length.

    Raises:
        FieldValueError: If ``Opt Data Len`` on the wire is too short to hold
            the fixed header and the Seed-ID declared by ``flags.type``, which
            would otherwise underflow the padding length below zero.

    """
    length = pkt['len'] - 2 - (0 if pkt['flags']['type'] == 0
                               else mpl_opt_seed_id_len(pkt, prefix=prefix))
    if length < 0:
        raise FieldValueError(f'{prefix}: invalid MPL option length: {pkt["len"]}')
    return length
