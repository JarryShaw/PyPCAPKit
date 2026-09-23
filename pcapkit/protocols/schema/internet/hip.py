# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for Host Identity Protocol"""

from typing import TYPE_CHECKING, cast

from pcapkit.const.hip.certificate import Certificate as Enum_Certificate
from pcapkit.const.hip.cipher import Cipher as Enum_Cipher
from pcapkit.const.hip.di import DITypes as Enum_DITypes
from pcapkit.const.hip.ecdsa_curve import ECDSACurve as Enum_ECDSACurve
from pcapkit.const.hip.ecdsa_low_curve import ECDSALowCurve as Enum_ECDSALowCurve
from pcapkit.const.hip.eddsa_curve import EdDSACurve as Enum_EdDSACurve
from pcapkit.const.hip.esp_transform_suite import ESPTransformSuite as Enum_ESPTransformSuite
from pcapkit.const.hip.group import Group as Enum_Group
from pcapkit.const.hip.hi_algorithm import HIAlgorithm as Enum_HIAlgorithm
from pcapkit.const.hip.hit_suite import HITSuite as Enum_HITSuite
from pcapkit.const.hip.nat_traversal import NATTraversal as Enum_NATTraversal
from pcapkit.const.hip.notify_message import NotifyMessage as Enum_NotifyMessage
from pcapkit.const.hip.parameter import Parameter as Enum_Parameter
from pcapkit.const.hip.registration import Registration as Enum_Registration
from pcapkit.const.hip.registration_failure import RegistrationFailure as Enum_RegistrationFailure
from pcapkit.const.hip.suite import Suite as Enum_Suite
from pcapkit.const.hip.transport import Transport as Enum_Transport
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.collections import ListField, OptionField
from pcapkit.corekit.fields.ipaddress import IPv6AddressField
from pcapkit.corekit.fields.misc import ConditionalField, PayloadField, SchemaField, SwitchField
from pcapkit.corekit.fields.numbers import (EnumField, NumberField, UInt8Field, UInt16Field,
                                            UInt32Field, UInt64Field)
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField
from pcapkit.protocols.schema.schema import EnumSchema, Schema, schema_final
from pcapkit.utilities.exceptions import FieldValueError
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING
from pcapkit.utilities.warnings import ProtocolWarning, warn

__all__ = [
    'HIP',

    'LocatorData', 'Locator', 'HostIdentity',
    'ECDSACurveHostIdentity', 'ECDSALowCurveHostIdentity', 'EdDSACurveHostIdentity',

    'UnassignedParameter', 'ESPInfoParameter', 'R1CounterParameter',
    'LocatorSetParameter', 'PuzzleParameter', 'SolutionParameter',
    'SEQParameter', 'ACKParameter', 'DHGroupListParameter',
    'DiffieHellmanParameter', 'HIPTransformParameter', 'HIPCipherParameter',
    'NATTraversalModeParameter', 'TransactionPacingParameter', 'EncryptedParameter',
    'HostIDParameter', 'HITSuiteListParameter', 'CertParameter',
    'NotificationParameter', 'EchoRequestSignedParameter', 'RegInfoParameter',
    'RegRequestParameter', 'RegResponseParameter', 'RegFailedParameter',
    'RegFromParameter', 'EchoResponseSignedParameter', 'TransportFormatListParameter',
    'ESPTransformParameter', 'SeqDataParameter', 'AckDataParameter',
    'PayloadMICParameter', 'TransactionIDParameter', 'OverlayIDParameter',
    'RouteDstParameter', 'HIPTransportModeParameter', 'HIPMACParameter',
    'HIPMAC2Parameter', 'HIPSignature2Parameter', 'HIPSignatureParameter',
    'EchoRequestUnsignedParameter', 'EchoResponseUnsignedParameter', 'RelayFromParameter',
    'RelayToParameter', 'RouteViaParameter', 'FromParameter',
    'RVSHMACParameter', 'RelayHMACParameter',
]

if TYPE_CHECKING:
    from ipaddress import IPv6Address
    from typing import Any, Optional

    from pcapkit.corekit.fields.field import FieldBase as Field
    from pcapkit.protocols.data.internet.hip import EncryptedParameter as Data_EncryptedParameter
    from pcapkit.protocols.data.internet.hip import HIPCipherParameter as Data_HIPCipherParameter
    from pcapkit.protocols.protocol import ProtocolBase as Protocol

if SPHINX_TYPE_CHECKING:  # pragma: no cover
    from typing_extensions import Literal, TypedDict

    class PacketType(TypedDict):
        """Packet type."""

        #: Reversed bit.
        bit_0: Literal[0]
        #: Packet type.
        type: int

    class VersionType(TypedDict):
        """Version type."""

        #: Version.
        version: int
        #: Reversed bit.
        bit_1: Literal[1]

    class ControlsType(TypedDict):
        """Controls type."""

        #: Anonymous.
        anonymous: bool

    class LocatorFlags(TypedDict):
        """Locator flags."""

        #: Preferred flag.
        preferred: bool

    class DIData(TypedDict):
        """DI type data."""

        #: DI type.
        type: Enum_DITypes
        #: DI length.
        len: int

    class RouteFlags(TypedDict):
        """Route destination flags."""

        #: Symmetric flag.
        symmetric: int
        #: Must-follow flag.
        must_follow: int


def locator_value_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`Locator.value` field.

    Args:
        pkt: Packet data.

    Returns:
        * If ``kind`` is ``0`` and ``size`` is ``16``,
          returns an :class:`~pcapkit.corekit.fields.ipaddress.IPv6AddressField` instance.
        * If ``kind`` is ``1`` and ``size`` is ``20``,
          returns a :class:`~pcapkit.corekit.fields.misc.SchemaField` wrapped
          :class:`~pcapkit.protocols.schema.internet.hip.LocatorData` instance.

    """
    if pkt['type'] == 0 and pkt['len'] == 4:
        return IPv6AddressField()
    if pkt['type'] == 1 and pkt['len'] == 5:
        return SchemaField(
            length=20,
            schema=LocatorData,
        )
    raise FieldValueError('invalid locator type or length')


def host_id_hi_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`HostIDParameter.hi` field.

    Args:
        pkt: Packet data.

    Returns:
        * If ``algorithm`` is ``7`` (ECDSA), returns a
          :class:`~pcapkit.corekit.fields.misc.SchemaField` wrapped
          :class:`~pcapkit.protocols.schema.internet.hip.ECDSACurveHostIdentity` instance.
        * If ``algorithm`` is ``9`` (ECDSA_LOW), returns a
          :class:`~pcapkit.corekit.fields.misc.SchemaField` wrapped
          :class:`~pcapkit.protocols.schema.internet.hip.ECDSALowCurveHostIdentity` instance.
        * If ``algorithm`` is ``13`` (EdDSA), returns a
          :class:`~pcapkit.corekit.fields.misc.SchemaField` wrapped
          :class:`~pcapkit.protocols.schema.internet.hip.EdDSACurveHostIdentity` instance.

    """
    algo = pkt['algorithm']
    schema = HostIdentity.registry[algo]
    if schema is None:
        return BytesField(length=pkt['hi_len'])
    return SchemaField(length=pkt['hi_len'], schema=schema)


def registration_type_list_len(pkt: 'dict[str, Any]') -> 'int':
    """Return registration type list length.

    Used by the ``reg_request``, ``reg_response`` and ``reg_failed`` fields of
    :class:`RegRequestParameter`, :class:`RegResponseParameter` and
    :class:`RegFailedParameter` respectively, each of which follows a single
    ``lifetime`` octet with a list of registration type octets sized by the
    remainder of the parameter.

    Args:
        pkt: Parameter unpacked schema.

    Returns:
        Registration type list length.

    Raises:
        FieldValueError: If the parameter's ``Length`` on the wire is too
            short to hold the ``lifetime`` octet already read, which would
            otherwise underflow the list length below zero.

    """
    length = pkt['len'] - 1
    if length < 0:
        raise FieldValueError(f'HIP: invalid parameter length: {pkt["len"]}')
    return length


def reg_info_list_len(pkt: 'dict[str, Any]') -> 'int':
    """Return ``REG_INFO`` registration type list length.

    Used by the ``reg_info`` field of :class:`RegInfoParameter`, which follows
    a pair of ``min_lifetime`` and ``max_lifetime`` octets with a list of
    registration type octets sized by the remainder of the parameter.

    Args:
        pkt: Parameter unpacked schema.

    Returns:
        Registration type list length.

    Raises:
        FieldValueError: If the parameter's ``Length`` on the wire is too
            short to hold the ``min_lifetime`` and ``max_lifetime`` octets
            already read, which would otherwise underflow the list length
            below zero.

    """
    length = pkt['len'] - 2
    if length < 0:
        raise FieldValueError(f'HIP: invalid parameter length: {pkt["len"]}')
    return length


def two_octet_prefix_list_len(pkt: 'dict[str, Any]') -> 'int':
    """Return list length for a parameter with a two-octet prefix.

    Used by the ``modes``, ``suites`` and ``mode`` fields of
    :class:`NATTraversalModeParameter`, :class:`ESPTransformParameter` and
    :class:`HIPTransportModeParameter` respectively, each of which follows a
    two-octet ``reserved`` or ``port`` field with a list of items sized by
    the remainder of the parameter.

    :class:`TransportFormatListParameter` looked like a fourth call site --
    same ``pkt['len'] - 2`` expression -- but is not: see
    :func:`transport_format_list_len` for why it has no such prefix to
    subtract.

    Args:
        pkt: Parameter unpacked schema.

    Returns:
        List length.

    Raises:
        FieldValueError: If the parameter's ``Length`` on the wire is too
            short to hold the two octets already read, which would otherwise
            underflow the list length below zero.

    """
    length = pkt['len'] - 2
    if length < 0:
        raise FieldValueError(f'HIP: invalid parameter length: {pkt["len"]}')
    return length


def transport_format_list_len(pkt: 'dict[str, Any]') -> 'int':
    """Return ``TRANSPORT_FORMAT_LIST`` transport format list length.

    Used by the ``formats`` field of :class:`TransportFormatListParameter`.
    Unlike :func:`two_octet_prefix_list_len`'s three call sites, this
    parameter has no ``reserved`` or ``port`` field between ``Length`` and
    the list: :rfc:`7401` Section 5.2.11 defines ``Length`` as literally
    "2x number of TF types" and places the list directly after it --

    ::

        |             Type              |             Length            |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |          TF type #1           |           TF type #2          /

    -- so the list's byte length *is* ``Length``, with nothing to subtract.
    Subtracting 2 anyway (as a since-corrected revision of this module once
    did, mirroring the three genuine two-octet-prefix sites) silently
    dropped the trailing two octets of *every* non-empty list on parse, and
    rejected the parameter's own legitimate empty-list encoding
    (``Length = 0``, ``formats = []``) as malformed.

    "2x number of TF types" also fixes each ``TF type`` entry's own width at
    two octets -- the same width the base :class:`Parameter` class uses for
    its own ``type`` field, since a TF type *is* a HIP parameter type number
    -- which is why ``formats``' ``item_type`` is
    ``EnumField(length=2, ...)``, matching :class:`HIPTransportModeParameter`'s
    ``mode`` rather than the one-octet items of :func:`two_octet_prefix_list_len`'s
    other two call sites. This function only answers how many *bytes* the
    list occupies; getting that number right and the item width wrong (as a
    still-earlier revision did, at one octet) still corrupts every non-empty
    list, just by reading twice as many entries as the wire holds instead of
    dropping octets.

    Args:
        pkt: Parameter unpacked schema.

    Returns:
        Transport format list length.

    Raises:
        FieldValueError: If the parameter's ``Length`` on the wire is
            negative. This cannot happen from real wire bytes -- ``len`` is
            an unsigned 16-bit field -- but a caller constructing the schema
            directly, bypassing
            :meth:`~pcapkit.protocols.internet.hip.HIP._make_param_transport_format_list`,
            could still pass one; this keeps that path to the same
            floor-and-raise discipline as :func:`two_octet_prefix_list_len`.

    """
    length = pkt['len']
    if length < 0:
        raise FieldValueError(f'HIP: invalid parameter length: {pkt["len"]}')
    return length


def encrypted_data_len(pkt: 'dict[str, Any]') -> 'int':
    """Return ``ENCRYPTED`` encrypted-data length.

    Used by the ``data`` field of :class:`EncryptedParameter`, which follows a
    four-octet ``reserved`` field and a conditional sixteen-octet ``iv`` with
    the ciphertext, sized by the remainder of the parameter. :rfc:`7401`
    Section 5.2.18 puts all three inside ``Length`` --

    ::

        |             Type              |             Length            |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                           Reserved                            |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                              IV                               |
        /                                                               /
        /                       Encrypted data                          /

    -- so both have to come off ``Length`` to leave the data, and
    :meth:`~pcapkit.protocols.internet.hip.HIP._make_param_encrypted` writes
    ``len=4 + len(iv) + len(data)`` to match.

    This subtracted the ``iv`` but not the ``reserved``, so the field claimed
    four octets more than the parameter holds: on unpack it read four octets
    of the *next* parameter into ``data``, and on pack it zero-extended the
    ciphertext by four. That was recorded as the second half of
    ``hip-parameter/ENCRYPTED`` in the round-trip suite's expected-failure
    table, and left alone -- because while the padding rule was also four
    octets out (#651), the two errors cancelled at some residues of ``Length``
    and not others. Measured by packing through the public maker at every
    residue, the old record total agreed with :rfc:`7401` Section 5.2.1 at
    ``Length % 8`` in ``{0, 5, 6, 7}`` and was eight octets over at
    ``{1, 2, 3, 4}`` -- so ``Length = 8``, which the unit suite happened to
    use, is one of the four where the module emitted RFC-conformant
    ``ENCRYPTED`` octets while getting both halves wrong.

    Fixing the padding without fixing this would therefore have *regressed*
    ``ENCRYPTED``, from right-by-accident at four of the eight residues to four
    octets too long at all eight: with only the padding corrected the total
    becomes ``8 + Length + pad`` against a correct ``4 + Length + pad``, which
    is a uniform four-octet surplus with no residue left where it cancels. So
    the two go together.

    Args:
        pkt: Parameter unpacked schema.

    Returns:
        Encrypted data length.

    Raises:
        FieldValueError: If the parameter's ``Length`` on the wire is too short
            to hold the ``reserved`` octets, and the ``iv`` octets where a
            cipher that carries one was resolved -- which would otherwise
            underflow the data length below zero.

    """
    length = pkt['len'] - 4 - (16 if pkt.get('iv') else 0)
    if length < 0:
        raise FieldValueError(f'HIP: invalid parameter length: {pkt["len"]}')
    return length


def parameter_total_len(length: 'int') -> 'int':
    """Return the total on-wire length of a HIP parameter.

    :rfc:`7401` Section 5.2.1 states the arithmetic outright, so there is
    nothing here to infer from the diagram --

    ::

        All of the encoded TLV parameters have a length (that includes the
        Type and Length fields), which is a multiple of 8 bytes.  When
        needed, padding MUST be added to the end of the parameter so that the
        total length is a multiple of 8 bytes.

        Total Length = 11 + Length - (Length + 3) % 8;

    -- and this function is that formula, spelled the way the RFC spells it.

    The distinction that matters is *which* quantity gets aligned. ``Length``
    is "Length of the Contents, in bytes, excluding Type, Length, and
    Padding", and it is the **total** -- contents plus the four octets of
    ``Type`` and ``Length`` plus padding -- that must land on a multiple of
    eight. Aligning the contents alone instead, as every padding site in this
    module and in :mod:`pcapkit.protocols.internet.hip` did before #651, puts
    every parameter at ``4 (mod 8)`` for every possible ``Length``: never a
    multiple of eight and never the length the RFC gives. It is not even a
    consistent offset, because the two formulas disagree in both directions --
    at ``Length = 4`` (a whole ``SEQ``) the contents are already 8-aligned
    with the header, so the RFC requires no padding at all and aligning the
    contents appends four octets that must not be there; at ``Length = 8`` the
    contents are 8-aligned on their own, so aligning them appends nothing and
    the record is left four octets short.

    Args:
        length: The parameter's ``Length`` field, i.e. its contents length in
            octets, excluding ``Type``, ``Length`` and ``Padding``.

    Returns:
        Total length of the parameter in octets, including ``Type``,
        ``Length``, ``Contents`` and ``Padding``. Always a multiple of eight.

    Raises:
        FieldValueError: If ``length`` is negative. This cannot happen from
            real wire bytes -- ``len`` is an unsigned 16-bit field -- but a
            caller constructing a schema directly could still pass one, and
            the RFC formula is meaningless there: it would answer 8 for
            ``Length = -1``, a "total" smaller than the four-octet header
            alone. Raising keeps this to the same floor-and-raise discipline
            as :func:`two_octet_prefix_list_len`.

    """
    if length < 0:
        raise FieldValueError(f'HIP: invalid parameter length: {length}')
    return 11 + length - (length + 3) % 8


def parameter_padding_len(pkt: 'dict[str, Any]') -> 'int':
    """Return the number of padding octets a HIP parameter needs.

    Used by the ``padding`` field of every parameter schema in this module.
    The count is whatever :func:`parameter_total_len` leaves over once the
    four-octet ``Type`` and ``Length`` header and the ``Length`` octets of
    contents are accounted for, which :rfc:`7401` Section 5.2.1 bounds at
    "0-7 bytes".

    This is one function shared by every parameter rather than a lambda
    repeated per class because it was previously the latter -- 46 copies of
    the same wrong expression here and 49 of its counterpart in
    :mod:`pcapkit.protocols.internet.hip`, which is 95 places for the
    arithmetic to be wrong in and one place too few to state the RFC's reason
    for it.

    Args:
        pkt: Parameter unpacked schema.

    Returns:
        Padding length in octets, between 0 and 7 inclusive.

    Raises:
        FieldValueError: If the parameter's ``Length`` on the wire is
            negative; see :func:`parameter_total_len`.

    """
    length = pkt['len']
    return parameter_total_len(length) - 4 - length


#: Packet-context key under which :class:`LocatorSetParameter` keeps its own
#: ``Length`` for the benefit of :func:`locator_set_padding_len`.
#:
#: It exists because ``LOCATOR_SET`` is the one parameter in this module whose
#: contents are a :class:`~pcapkit.corekit.fields.collections.ListField` of
#: nested schemas, and a nested schema packed through one **shares the
#: enclosing packet context**: :meth:`Schema.pack
#: <pcapkit.protocols.schema.schema.Schema.pack>` opens with
#: ``packet.update(self.__dict__)``, and :class:`Locator` declares a ``len`` of
#: its own. So by the time ``padding`` is evaluated -- after the list, since
#: fields are packed in declaration order -- ``pkt['len']`` is the *last
#: locator's* ``len``, not the parameter's. That is 4 for any IPv6 locator
#: whatever the locator count, which is how the pre-#679 padding expression came
#: to append exactly four octets to every ``LOCATOR_SET`` regardless of size.
#:
#: The shadowing is specific to the packing path. :meth:`Schema.unpack
#: <pcapkit.protocols.schema.schema.Schema.unpack>` hands each field
#: ``packet.copy()``, so nested writes do not propagate back and ``pkt['len']``
#: stays the parameter's there. Snapshotting under a key no nested schema
#: declares is what makes one callback correct on both paths rather than
#: accidentally correct on one.
LOCATOR_SET_LEN = '__locator_set_len__'


def locator_set_len_callback(field: 'ListField',  # pylint: disable=unused-argument
                             pkt: 'dict[str, Any]') -> 'None':
    """Snapshot ``LOCATOR_SET``'s own ``Length`` before its locators shadow it.

    Installed as the ``callback`` of :attr:`LocatorSetParameter.locators`, which
    :meth:`ListField.__call__
    <pcapkit.corekit.fields.collections.ListField.__call__>` runs when the field
    is resolved against the packet -- i.e. before any nested :class:`Locator` has
    been packed into it. See :data:`LOCATOR_SET_LEN` for why the snapshot is
    needed at all.

    Args:
        field: The field being resolved. Unused; the signature is
            :class:`~pcapkit.corekit.fields.collections.ListField`'s.
        pkt: Parameter unpacked schema, modified in place.

    """
    pkt[LOCATOR_SET_LEN] = pkt['len']


def locator_set_padding_len(pkt: 'dict[str, Any]') -> 'int':
    """Return the number of padding octets a ``LOCATOR_SET`` parameter needs.

    The same arithmetic as :func:`parameter_padding_len` -- it defers to it
    rather than repeating it -- but read off the snapshot
    :func:`locator_set_len_callback` took, for the reason :data:`LOCATOR_SET_LEN`
    gives.

    Args:
        pkt: Parameter unpacked schema.

    Returns:
        Padding length in octets, between 0 and 7 inclusive.

    Raises:
        FieldValueError: If the parameter's ``Length`` on the wire is
            negative; see :func:`parameter_total_len`.

    """
    return parameter_padding_len({'len': pkt[LOCATOR_SET_LEN]})


class Parameter(EnumSchema[Enum_Parameter]):
    """Base schema for HIP parameters."""

    __default__ = lambda: UnassignedParameter

    #: Parameter type.
    type: 'Enum_Parameter' = EnumField(length=2, namespace=Enum_Parameter)
    #: Parameter length.
    len: 'int' = UInt16Field()


@schema_final
class UnassignedParameter(Parameter):
    """Header schema for HIP unsigned parameters."""

    #: Parameter value.
    value: 'bytes' = BytesField(length=lambda pkt: pkt['len'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', value: 'bytes') -> 'None': ...


@schema_final
class ESPInfoParameter(Parameter, code=Enum_Parameter.ESP_INFO):
    """Header schema for HIP ``ESP_INFO`` parameters."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: Key management index.
    index: 'int' = UInt16Field()
    #: Old SPI.
    old_spi: 'int' = UInt32Field()
    #: New SPI.
    new_spi: 'int' = UInt32Field()
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', index: 'int',
                     old_spi: 'int', new_spi: 'int') -> 'None': ...


@schema_final
class R1CounterParameter(Parameter, code=[Enum_Parameter.R1_Counter,
                                          Enum_Parameter.R1_COUNTER]):
    """Header schema for HIP ``R1_COUNTER`` parameters.

    Registered under both codes, not 129 alone. :rfc:`5201#section-5.2.3`
    (HIPv1) and :rfc:`7401#section-5.2.3` (HIPv2) give the identical 4 + 8
    layout to code 128 (``R1_Counter``) and code 129 (``R1_COUNTER``) --
    one parameter under two numbers, the difference being HIP's own C-bit
    rather than an unrelated code -- and the field list below is that layout
    exactly, since #696 widened :attr:`counter` to eight octets.
    :attr:`~pcapkit.protocols.internet.hip.HIP.__parameter__` already carries
    two hand-written entries -- not a name-normalisation rule; ``R1_Counter``
    and ``R1_COUNTER`` differ only in case, and each needed its own line --
    mapping both codes to the same ``_read_param_r1_counter``, and
    ``_make_param_r1_counter`` already built this class for 128; it was only
    the schema lookup this class's own ``code=`` feeds -- consulted on the
    parse path by :class:`~pcapkit.corekit.fields.collections.OptionField`
    -- that fell back to :class:`UnassignedParameter` for 128, since a
    single-code ``code=`` registered 129 alone and left 128 unclaimed.
    See #690.

    """

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=4)
    #: R1 counter.
    #:
    #: Eight octets, not four. :rfc:`7401#section-5.2.3` labels the field "R1
    #: generation counter, 8 bytes" in its diagram and then says outright that
    #: the parameter "contains a 64-bit unsigned integer in network byte
    #: order", so the width is stated twice and inferred from neither.
    #: :rfc:`5201#section-5.2.3` gives the same 4 + 8 layout, so there is no
    #: version under which four octets is right, and both codes that reach this
    #: class -- ``R1_Counter`` (128, HIPv1) and ``R1_COUNTER`` (129) -- are
    #: affected. It was a :class:`~pcapkit.corekit.fields.numbers.UInt32Field`
    #: until #672: the parameter declared the correct ``len=12`` and packed 12
    #: octets in total where :rfc:`7401` Section 5.2.1's arithmetic makes the
    #: record 16, leaving it four short at ``4 (mod 8)``. Measured before the
    #: fix, at ``counter=1``: ``00 80 00 0c 00 00 00 00 00 00 00 01`` for code
    #: 128 and the same twelve octets under ``00 81`` for code 129.
    counter: 'int' = UInt64Field()
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', counter: 'int') -> 'None': ...


@schema_final
class Locator(Schema):
    """Header schema for HIP locators."""

    #: Traffic type.
    traffic: 'int' = UInt8Field()
    #: Locator type.
    type: 'int' = UInt8Field()
    #: Locator length.
    len: 'int' = UInt8Field()
    #: Reserved and flags.
    flags: 'LocatorFlags' = BitField(
        length=1,
        namespace={
            'preferred': (7, 1),
        },
    )
    lifetime: 'int' = UInt32Field()
    #: Locator value.
    value: 'IPv6Address | LocatorData' = SwitchField(
        selector=locator_value_selector,
    )

    if TYPE_CHECKING:
        def __init__(self, traffic: 'int', type: 'int', len: 'int', flags: 'LocatorFlags',
                     lifetime: 'int', value: 'bytes | LocatorData') -> 'None': ...


@schema_final
class LocatorSetParameter(Parameter, code=Enum_Parameter.LOCATOR_SET):
    """Header schema for HIP ``LOCATOR_SET`` parameters."""

    #: List of locators.
    #:
    #: The ``length`` callback is the parameter's own ``Length``, and that is
    #: correct on the unpacking path for the reason :data:`LOCATOR_SET_LEN`
    #: gives -- nothing has shadowed ``len`` yet when this field is resolved,
    #: since ``type`` and ``len`` are the only fields ahead of it. What was
    #: wrong until #679 is the *quantity* it was being handed:
    #: :meth:`~pcapkit.protocols.internet.hip.HIP._make_param_locator_set` wrote
    #: ``Length`` as ``sum(Locator.len)``, in the 4-octet units
    #: :rfc:`8046#section-4` gives ``Locator Length``, where :rfc:`7401`
    #: Section 5.2.1's ``Length`` is a byte count. :meth:`Schema.unpack
    #: <pcapkit.protocols.schema.schema.Schema.unpack>` reads exactly
    #: ``field.length`` octets off the stream and hands only those to
    #: :meth:`ListField.unpack
    #: <pcapkit.corekit.fields.collections.ListField.unpack>`, so a set of *n*
    #: plain IPv6 locators offered ``4n`` octets of a ``24n``-octet contents:
    #: measured on ``f0999858e``, n = 2 and n = 5 both parsed **one** truncated
    #: locator and left the rest of the record unconsumed, with
    #: :exc:`~pcapkit.utilities.warnings.SchemaWarning` for the negative
    #: remainder and a repack that did not match the octets read. With
    #: ``Length`` a byte count the budget is the contents, each locator bills
    #: the 8 + ``Locator Length`` * 4 octets it actually consumed, and the
    #: count comes out exact.
    locators: 'list[Locator]' = ListField(
        length=lambda pkt: pkt['len'],
        item_type=SchemaField(schema=Locator),
        callback=locator_set_len_callback,
    )
    #: Padding.
    #:
    #: Not :func:`parameter_padding_len`, which every other parameter in this
    #: module uses, but :func:`locator_set_padding_len` -- the same arithmetic
    #: read off a snapshot of this parameter's ``Length`` rather than off
    #: ``pkt['len']`` directly. :data:`LOCATOR_SET_LEN` documents why the direct
    #: read does not work here: the nested :class:`Locator` schemas share this
    #: parameter's packet context while they pack, and their own ``len``
    #: overwrites it before ``padding`` is reached.
    #:
    #: This is the site #651 deliberately left alone and #664 documented as an
    #: exclusion, because two defects in this parameter cancelled at the shape
    #: its tests sampled and correcting either alone made the wire output worse.
    #: The shadowed ``len`` is 4 for any IPv6 locator, so the old expression
    #: appended exactly four octets whatever the locator count; and the wrong
    #: ``Length`` unit above made the declared ``Length`` ``4n`` where the
    #: contents were ``24n``. ``4 + 24n + 4`` is ``24n + 8``, and since ``24n``
    #: is a multiple of eight the RFC total for a byte-count ``Length`` of
    #: ``24n`` is ``11 + 24n - 3``, the same ``24n + 8``. Hence 32, 56 and 128
    #: octets at n = 1, 2, 5 -- conformant, by two wrongs.
    #:
    #: That cancellation was never general, which is why the pair had to move
    #: together rather than one at a time. It needs every locator to be 24
    #: octets and there to be at least one, and measured on ``f0999858e`` the
    #: shapes that break it were non-conformant before this fix: an empty set
    #: packed 4 octets where :rfc:`7401` Section 5.2.1 wants 8, one SPI-bearing
    #: locator packed 35, two packed 63, and a mixed plain-and-SPI pair packed
    #: 59 or 60 depending on order. Afterwards all seven shapes are the RFC's
    #: own total: 8, 32, 56, 128, 32, 64, 56 and 56 respectively, with the three
    #: plain figures unchanged.
    padding: 'bytes' = PaddingField(length=locator_set_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', locators: 'list[Locator]') -> 'None': ...


@schema_final
class LocatorData(Schema):
    """Header schema for HIP locator data."""

    #: SPI.
    spi: 'int' = UInt32Field()
    #: Locator.
    ip: 'IPv6Address' = IPv6AddressField()

    if TYPE_CHECKING:
        def __init__(self, spi: 'int', ip: 'IPv6Address | int | bytes | str') -> 'None': ...


@schema_final
class PuzzleParameter(Parameter, code=Enum_Parameter.PUZZLE):
    """Header schema for HIP ``PUZZLE`` parameters."""

    #: Numeric index.
    index: 'int' = UInt8Field()
    #: Lifetime.
    lifetime: 'int' = UInt8Field()
    #: Opaque data.
    opaque: 'bytes' = BytesField(length=2)
    #: Random data.
    random: 'int' = NumberField(length=lambda pkt: pkt['len'] - 4, signed=False)
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', index: 'int', lifetime: 'int',
                     opaque: 'bytes', random: 'int') -> 'None': ...


@schema_final
class SolutionParameter(Parameter, code=Enum_Parameter.SOLUTION):
    """Header schema for HIP ``SOLUTION`` parameters."""

    #: Numeric index.
    index: 'int' = UInt8Field()
    #: Reserved octet -- "zero when sent, ignored when received"
    #: (:rfc:`7401#section-5.2.5`, and :rfc:`5201#section-5.2.5` identically).
    #: This octet is *not* a lifetime: only ``PUZZLE`` carries one, at the same
    #: offset, and only :rfc:`7401#section-5.2.4` defines the ``2^(value - 32)``
    #: seconds encoding that goes in it. See #654.
    reserved: 'int' = UInt8Field()
    #: Opaque data.
    opaque: 'bytes' = BytesField(length=2)
    #: Random data.
    random: 'int' = NumberField(length=lambda pkt: (pkt['len'] - 4) // 2, signed=False)
    #: Solution.
    solution: 'int' = NumberField(length=lambda pkt: (pkt['len'] - 4) // 2, signed=False)
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', index: 'int', reserved: 'int',
                     opaque: 'bytes', random: 'int', solution: 'int') -> 'None': ...


@schema_final
class SEQParameter(Parameter, code=Enum_Parameter.SEQ):
    """Header schema for HIP ``SEQ`` parameters."""

    #: Update ID.
    update_id: 'int' = UInt32Field()
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', update_id: 'int') -> 'None': ...


@schema_final
class ACKParameter(Parameter, code=Enum_Parameter.ACK):
    """Header schema for HIP ``ACK`` parameters."""

    #: Update ID.
    update_id: 'list[int]' = ListField(
        length=lambda pkt: pkt['len'],
        item_type=UInt32Field(),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', update_id: 'bytes | list[int]') -> 'None': ...


@schema_final
class DHGroupListParameter(Parameter, code=Enum_Parameter.DH_GROUP_LIST):
    """Header schema for HIP ``DH_GROUP_LIST`` parameters."""

    #: List of DH groups.
    groups: 'list[Enum_Group]' = ListField(
        length=lambda pkt: pkt['len'],
        item_type=EnumField(length=1, namespace=Enum_Group),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', groups: 'list[Enum_Group]') -> 'None': ...


@schema_final
class DiffieHellmanParameter(Parameter, code=Enum_Parameter.DIFFIE_HELLMAN):
    """Header schema for HIP ``DIFFIE_HELLMAN`` parameters."""

    #: Diffie-Hellman group.
    group: 'Enum_Group' = EnumField(length=1, namespace=Enum_Group)
    #: Public value length.
    pub_len: 'int' = UInt16Field()
    #: Diffie-Hellman value.
    pub_val: 'int' = NumberField(length=lambda pkt: pkt['pub_len'], signed=False)
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', group: 'Enum_Group', pub_len: 'int',
                     pub_val: 'int') -> 'None': ...


@schema_final
class HIPTransformParameter(Parameter, code=Enum_Parameter.HIP_TRANSFORM):
    """Header schema for HIP ``TRANSFORM`` parameters."""

    #: Suite IDs.
    suites: 'list[Enum_Suite]' = ListField(
        length=lambda pkt: pkt['len'],
        item_type=EnumField(length=2, namespace=Enum_Suite),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', suites: 'list[Enum_Suite]') -> 'None': ...


@schema_final
class HIPCipherParameter(Parameter, code=Enum_Parameter.HIP_CIPHER):
    """Header schema for HIP ``CIPHER`` parameters."""

    #: Cipher IDs.
    ciphers: 'list[Enum_Cipher]' = ListField(
        length=lambda pkt: pkt['len'],
        item_type=EnumField(length=2, namespace=Enum_Cipher),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', ciphers: 'list[Enum_Cipher]') -> 'None': ...


@schema_final
class NATTraversalModeParameter(Parameter, code=Enum_Parameter.NAT_TRAVERSAL_MODE):
    """Header schema for HIP ``NAT_TRAVERSAL_MODE`` parameters."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: NAT traversal modes.
    modes: 'list[Enum_NATTraversal]' = ListField(
        length=two_octet_prefix_list_len,
        item_type=EnumField(length=2, namespace=Enum_NATTraversal),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', modes: 'list[Enum_NATTraversal]') -> 'None': ...


@schema_final
class TransactionPacingParameter(Parameter, code=Enum_Parameter.TRANSACTION_PACING):
    """Header schema for HIP ``TRANSACTION_PACING`` parameters."""

    #: Transaction pacing.
    min_ta: 'int' = UInt32Field()
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', min_ta: 'int') -> 'None': ...


@schema_final
class EncryptedParameter(Parameter, code=Enum_Parameter.ENCRYPTED):
    """Header schema for HIP ``ENCRYPTED`` parameters."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=4)
    #: Initialization vector.
    iv: 'bytes' = ConditionalField(
        BytesField(length=16),
        lambda pkt: pkt['__cipher__'] in (Enum_Cipher.AES_128_CBC, Enum_Cipher.AES_256_CBC),
    )
    #: Data.
    data: 'bytes' = BytesField(length=encrypted_data_len)
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    @classmethod
    def pre_unpack(cls, packet: 'dict[str, Any]') -> 'None':
        """Prepare ``packet`` data for unpacking process.

        Args:
            packet: packet data

        Notes:
            When ``packet`` already carries a resolved ``cipher`` -- as it
            does when this schema was built via
            :meth:`HIP._make_param_encrypted
            <pcapkit.protocols.internet.hip.HIP._make_param_encrypted>`, which
            sets it as a plain attribute so ``pack()``'s own
            ``packet.update(self.__dict__)`` carries it in here -- that value
            is trusted over the ``HIP_CIPHER`` sibling lookup below, which a
            parameter packed on its own has no ``options`` list for. See
            #556.

        """
        if 'cipher' in packet:
            packet['__cipher__'] = packet.pop('cipher')
            return

        if 'options' in packet:
            cipher_list = cast('list[Data_HIPCipherParameter]',
                            packet['options'].getlist(Enum_Parameter.HIP_CIPHER))
            if not cipher_list:
                warn(f'HIP: [ParamNo {Enum_Parameter.ENCRYPTED}] '
                    'missing HIP_CIPHER parameter', ProtocolWarning)
                # raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

                cipher_id = Enum_Cipher(0xffff)
            else:
                cipher_ids = []  # type: list[Enum_Cipher]
                for cipher in cipher_list:
                    cipher_ids.extend(cipher.cipher_id)

                encrypted_list = cast('list[Data_EncryptedParameter]',
                                    packet['options'].getlist(Enum_Parameter.ENCRYPTED))
                encrypted_index = len(encrypted_list)

                if encrypted_index >= len(cipher_ids):
                    warn(f'HIP: [ParamNo {Enum_Parameter.ENCRYPTED}] '
                        'too many ENCRYPTED parameters', ProtocolWarning)
                    # raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

                    cipher_id = Enum_Cipher(0xfffe)
                else:
                    cipher_id = cipher_ids[encrypted_index]
        else:
            warn(f'HIP: [ParamNo {Enum_Parameter.ENCRYPTED}] '
                 'missing HIP_CIPHER parameter', ProtocolWarning)
            cipher_id = Enum_Cipher(0xffff)

        packet['__cipher__'] = cipher_id

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        self.cipher = packet['__cipher__']
        return self

    if TYPE_CHECKING:
        #: Cipher ID. Not a schema field -- set as a plain attribute, either
        #: by :meth:`post_process` after unpacking, or by
        #: :meth:`HIP._make_param_encrypted
        #: <pcapkit.protocols.internet.hip.HIP._make_param_encrypted>` before
        #: packing -- so it is documented here rather than accepted by
        #: ``__init__``. See #556.
        cipher: 'Enum_Cipher'

        def __init__(self, type: 'Enum_Parameter', len: 'int',
                     iv: 'Optional[bytes]', data: 'bytes') -> 'None': ...


@schema_final
class HostIDParameter(Parameter, code=Enum_Parameter.HOST_ID):
    """Header schema for HIP ``HOST_ID`` parameters."""

    #: Host ID length.
    hi_len: 'int' = UInt16Field()
    #: Domain ID type and length.
    di_data: 'DIData' = BitField(
        length=4,
        namespace={
            'type': (0, 4),
            'len': (4, 12),
        },
    )
    #: Algorithm type.
    algorithm: 'Enum_HIAlgorithm' = EnumField(length=2, namespace=Enum_HIAlgorithm)
    #: Host ID.
    hi: 'bytes | HostIdentity' = SwitchField(selector=host_id_hi_selector)
    #: Domain ID.
    di: 'bytes' = BytesField(length=lambda pkt: pkt['di_data']['len'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', hi_len: 'int', di_data: 'DIData',
                     algorithm: 'Enum_HIAlgorithm', hi: 'bytes | HostIdentity',
                     di: 'bytes') -> 'None': ...


class HostIdentity(EnumSchema[Enum_HIAlgorithm]):
    """Host identity schema."""


@schema_final
class ECDSACurveHostIdentity(HostIdentity, code=Enum_HIAlgorithm.ECDSA):
    """Host identity schema with ECDSA curve."""

    #: Algorithm curve type.
    curve: 'Enum_ECDSACurve' = EnumField(length=2, namespace=Enum_ECDSACurve)
    #: Public key.
    pub_key: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, curve: 'Enum_ECDSACurve', pub_key: 'bytes') -> 'None': ...


@schema_final
class ECDSALowCurveHostIdentity(HostIdentity, code=Enum_HIAlgorithm.ECDSA_LOW):
    """Host identity schema with ECDSA_LOW curve."""

    #: Algorithm curve type.
    curve: 'Enum_ECDSALowCurve' = EnumField(length=2, namespace=Enum_ECDSALowCurve)
    #: Public key.
    pub_key: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, curve: 'Enum_ECDSALowCurve', pub_key: 'bytes') -> 'None': ...


@schema_final
class EdDSACurveHostIdentity(HostIdentity, code=Enum_HIAlgorithm.EdDSA):
    """Host identity schema with EdDSA curve."""

    #: Algorithm curve type.
    curve: 'Enum_EdDSACurve' = EnumField(length=2, namespace=Enum_EdDSACurve)
    #: Public key.
    pub_key: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, curve: 'Enum_EdDSACurve', pub_key: 'bytes') -> 'None': ...


@schema_final
class HITSuiteListParameter(Parameter, code=Enum_Parameter.HIT_SUITE_LIST):
    """Header schema for HIP ``HIT_SUITE_LIST`` parameters."""

    #: HIT suite IDs.
    suites: 'list[Enum_HITSuite]' = ListField(
        length=lambda pkt: pkt['len'],
        item_type=EnumField(length=1, namespace=Enum_HITSuite),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', suites: 'list[Enum_HITSuite]') -> 'None': ...


@schema_final
class CertParameter(Parameter, code=Enum_Parameter.CERT):
    """Header schema for HIP ``CERT`` parameters."""

    #: Certificate group.
    cert_group: 'Enum_Group' = EnumField(length=1, namespace=Enum_Group)
    #: Certificate count.
    cert_count: 'int' = UInt8Field()
    #: Certificate ID.
    cert_id: 'int' = UInt8Field()
    #: Certificate type.
    cert_type: 'Enum_Certificate' = EnumField(length=1, namespace=Enum_Certificate)
    #: Certificate data.
    cert: 'bytes' = BytesField(length=lambda pkt: pkt['len'] - 4)
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', cert_group: 'Enum_Group', cert_count: 'int',
                     cert_id: 'int', cert_type: 'Enum_Certificate', cert: 'bytes') -> 'None': ...


@schema_final
class NotificationParameter(Parameter, code=Enum_Parameter.NOTIFICATION):
    """Header schema for HIP ``NOTIFICATION`` parameters."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: Notify message type.
    msg_type: 'Enum_NotifyMessage' = EnumField(length=2, namespace=Enum_NotifyMessage)
    #: Notification data.
    msg: 'bytes' = BytesField(length=lambda pkt: pkt['len'] - 4)
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', msg_type: 'Enum_NotifyMessage', msg: 'bytes') -> 'None': ...


@schema_final
class EchoRequestSignedParameter(Parameter, code=Enum_Parameter.ECHO_REQUEST_SIGNED):
    """Header schema for HIP ``ECHO_REQUEST_SIGNED`` parameters."""

    #: Opaque data.
    opaque: 'bytes' = BytesField(length=lambda pkt: pkt['len'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', opaque: 'bytes') -> 'None': ...


@schema_final
class RegInfoParameter(Parameter, code=Enum_Parameter.REG_INFO):
    """Header schema for HIP ``REG_INFO`` parameters."""

    #: Minimum lifetime.
    min_lifetime: 'int' = UInt8Field()
    #: Maximum lifetime.
    max_lifetime: 'int' = UInt8Field()
    #: Registration types.
    reg_info: 'list[Enum_Registration]' = ListField(
        length=reg_info_list_len,
        item_type=EnumField(length=1, namespace=Enum_Registration),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', min_lifetime: 'int', max_lifetime: 'int',
                     reg_info: 'list[Enum_Registration]') -> 'None': ...


@schema_final
class RegRequestParameter(Parameter, code=Enum_Parameter.REG_REQUEST):
    """Header schema for HIP ``REG_REQUEST`` parameters."""

    #: Lifetime.
    lifetime: 'int' = UInt8Field()
    #: Registration types.
    reg_request: 'list[Enum_Registration]' = ListField(
        length=registration_type_list_len,
        item_type=EnumField(length=1, namespace=Enum_Registration),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', lifetime: 'int', reg_request: 'list[Enum_Registration]') -> 'None': ...


@schema_final
class RegResponseParameter(Parameter, code=Enum_Parameter.REG_RESPONSE):
    """Header schema for HIP ``REG_RESPONSE`` parameters."""

    #: Lifetime.
    lifetime: 'int' = UInt8Field()
    #: Registration types.
    reg_response: 'list[Enum_Registration]' = ListField(
        length=registration_type_list_len,
        item_type=EnumField(length=1, namespace=Enum_Registration),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', lifetime: 'int', reg_response: 'list[Enum_Registration]') -> 'None': ...


@schema_final
class RegFailedParameter(Parameter, code=Enum_Parameter.REG_FAILED):
    """Header schema for HIP ``REG_FAILED`` parameters."""

    #: Lifetime.
    lifetime: 'int' = UInt8Field()
    #: Registration types.
    reg_failed: 'list[Enum_RegistrationFailure]' = ListField(
        length=registration_type_list_len,
        item_type=EnumField(length=1, namespace=Enum_RegistrationFailure),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', lifetime: 'int', reg_failed: 'list[Enum_RegistrationFailure]') -> 'None': ...


@schema_final
class RegFromParameter(Parameter, code=Enum_Parameter.REG_FROM):
    """Header schema for HIP ``REG_FROM`` parameters."""

    #: Port.
    port: 'int' = UInt16Field()
    #: Protocol.
    protocol: 'Enum_TransType' = EnumField(length=1, namespace=Enum_TransType)
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Address.
    address: 'IPv6Address' = IPv6AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', port: 'int', protocol: 'Enum_TransType', address: 'IPv6Address | bytes | int | str') -> 'None': ...


@schema_final
class EchoResponseSignedParameter(Parameter, code=Enum_Parameter.ECHO_RESPONSE_SIGNED):
    """Header schema for HIP ``ECHO_RESPONSE_SIGNED`` parameters."""

    #: Opaque data.
    opaque: 'bytes' = BytesField(length=lambda pkt: pkt['len'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', opaque: 'bytes') -> 'None': ...


@schema_final
class TransportFormatListParameter(Parameter, code=Enum_Parameter.TRANSPORT_FORMAT_LIST):
    """Header schema for HIP ``TRANSPORT_FORMAT_LIST`` parameters."""

    #: Transport formats.
    formats: 'list[Enum_Parameter]' = ListField(
        length=transport_format_list_len,
        item_type=EnumField(length=2, namespace=Enum_Parameter),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', formats: 'list[Enum_Parameter]') -> 'None': ...


@schema_final
class ESPTransformParameter(Parameter, code=Enum_Parameter.ESP_TRANSFORM):
    """Header schema for HIP ``ESP_TRANSFORM`` parameters."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: Suite IDs.
    suites: 'list[Enum_ESPTransformSuite]' = ListField(
        length=two_octet_prefix_list_len,
        item_type=EnumField(length=2, namespace=Enum_ESPTransformSuite),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', suites: 'list[Enum_ESPTransformSuite]') -> 'None': ...


@schema_final
class SeqDataParameter(Parameter, code=Enum_Parameter.SEQ_DATA):
    """Header schema for HIP ``SEQ_DATA`` parameters."""

    #: Sequence number.
    seq: 'int' = UInt32Field()
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', seq: 'int') -> 'None': ...


@schema_final
class AckDataParameter(Parameter, code=Enum_Parameter.ACK_DATA):
    """Header schema for HIP ``ACK_DATA`` parameters."""

    #: Acked sequence number.
    ack: 'list[int]' = ListField(
        length=lambda pkt: pkt['len'],
        item_type=UInt32Field(),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', ack: 'list[int]') -> 'None': ...


@schema_final
class PayloadMICParameter(Parameter, code=Enum_Parameter.PAYLOAD_MIC):
    """Header schema for HIP ``PAYLOAD_MIC`` parameters."""

    #: Next header.
    next: 'Enum_TransType' = EnumField(length=1, namespace=Enum_TransType)
    #: Reversed.
    reserved: 'bytes' = PaddingField(length=3)
    #: Payload data.
    payload: 'bytes' = BytesField(length=4)
    #: MIC value.
    mic: 'bytes' = BytesField(length=lambda pkt: pkt['len'] - 8)
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', next: 'Enum_TransType', payload: 'bytes', mic: 'bytes') -> 'None': ...


@schema_final
class TransactionIDParameter(Parameter, code=Enum_Parameter.TRANSACTION_ID):
    """Header schema for HIP ``TRANSACTION_ID`` parameters."""

    #: Transaction ID.
    id: 'int' = NumberField(length=lambda pkt: pkt['len'], signed=False)
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', id: 'int') -> 'None': ...


@schema_final
class OverlayIDParameter(Parameter, code=Enum_Parameter.OVERLAY_ID):
    """Header schema for HIP ``OVERLAY_ID`` parameters."""

    #: Overlay ID.
    id: 'int' = NumberField(length=lambda pkt: pkt['len'], signed=False)
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', id: 'int') -> 'None': ...


@schema_final
class RouteDstParameter(Parameter, code=Enum_Parameter.ROUTE_DST):
    """Header schema for HIP ``ROUTE_DST`` parameters."""

    #: Flags.
    flags: 'RouteFlags' = BitField(length=2, namespace={
            'symmetric': (0, 1),
            'must_follow': (1, 1),
    })
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: HIT addresses.
    hit: 'list[IPv6Address]' = ListField(
        length=lambda pkt: pkt['len'] - 4,
        item_type=IPv6AddressField(),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', flags: 'RouteFlags', hit: 'list[str | int | bytes | IPv6Address]') -> 'None': ...


@schema_final
class HIPTransportModeParameter(Parameter, code=Enum_Parameter.HIP_TRANSPORT_MODE):
    """Header schema for HIP ``HIP_TRANSPORT_MODE`` parameters."""

    #: Port.
    port: 'int' = UInt16Field()
    #: Mode IDs.
    mode: 'list[Enum_Transport]' = ListField(
        length=two_octet_prefix_list_len,
        item_type=EnumField(length=2, namespace=Enum_Transport),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', port: 'int', mode: 'list[Enum_Transport]') -> 'None': ...


@schema_final
class HIPMACParameter(Parameter, code=Enum_Parameter.HIP_MAC):
    """Header schema for HIP ``HIP_MAC`` parameters."""

    #: HMAC value.
    hmac: 'bytes' = BytesField(length=lambda pkt: pkt['len'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', hmac: 'bytes') -> 'None': ...


@schema_final
class HIPMAC2Parameter(Parameter, code=Enum_Parameter.HIP_MAC_2):
    """Header schema for HIP ``HIP_MAC_2`` parameters."""

    #: HMAC value.
    hmac: 'bytes' = BytesField(length=lambda pkt: pkt['len'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', hmac: 'bytes') -> 'None': ...


@schema_final
class HIPSignature2Parameter(Parameter, code=Enum_Parameter.HIP_SIGNATURE_2):
    """Header schema for HIP ``HIP_SIGNATURE_2`` parameters."""

    #: Signature algorithm.
    algorithm: 'Enum_HIAlgorithm' = EnumField(length=2, namespace=Enum_HIAlgorithm)
    #: Signature value.
    signature: 'bytes' = BytesField(length=lambda pkt: pkt['len'] - 2)
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', algorithm: 'Enum_HIAlgorithm', signature: 'bytes') -> 'None': ...


@schema_final
class HIPSignatureParameter(Parameter, code=Enum_Parameter.HIP_SIGNATURE):
    """Header schema for HIP ``HIP_SIGNATURE`` parameters."""

    #: Signature algorithm.
    algorithm: 'Enum_HIAlgorithm' = EnumField(length=2, namespace=Enum_HIAlgorithm)
    #: Signature value.
    signature: 'bytes' = BytesField(length=lambda pkt: pkt['len'] - 2)
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', algorithm: 'Enum_HIAlgorithm', signature: 'bytes') -> 'None': ...


@schema_final
class EchoRequestUnsignedParameter(Parameter, code=Enum_Parameter.ECHO_REQUEST_UNSIGNED):
    """Header schema for HIP ``ECHO_REQUEST_UNSIGNED`` parameters."""

    #: Opaque data.
    opaque: 'bytes' = BytesField(length=lambda pkt: pkt['len'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', opaque: 'bytes') -> 'None': ...


@schema_final
class EchoResponseUnsignedParameter(Parameter, code=Enum_Parameter.ECHO_RESPONSE_UNSIGNED):
    """Header schema for HIP ``ECHO_RESPONSE_UNSIGNED`` parameters."""

    #: Opaque data.
    opaque: 'bytes' = BytesField(length=lambda pkt: pkt['len'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', opaque: 'bytes') -> 'None': ...


@schema_final
class RelayFromParameter(Parameter, code=Enum_Parameter.RELAY_FROM):
    """Header schema for HIP ``RELAY_FROM`` parameters."""

    #: Port.
    port: 'int' = UInt16Field()
    #: Protocol.
    protocol: 'Enum_TransType' = EnumField(length=1, namespace=Enum_TransType)
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Address.
    address: 'IPv6Address' = IPv6AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', port: 'int', protocol: 'Enum_TransType', address: 'str | bytes | int | IPv6Address') -> 'None': ...


@schema_final
class RelayToParameter(Parameter, code=Enum_Parameter.RELAY_TO):
    """Header schema for HIP ``RELAY_TO`` parameters."""

    #: Port.
    port: 'int' = UInt16Field()
    #: Protocol.
    protocol: 'Enum_TransType' = EnumField(length=1, namespace=Enum_TransType)
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Address.
    address: 'IPv6Address' = IPv6AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', port: 'int', protocol: 'Enum_TransType', address: 'str | bytes | int | IPv6Address') -> 'None': ...


@schema_final
class OverlayTTLParameter(Parameter, code=Enum_Parameter.OVERLAY_TTL):
    """Header schema for HIP ``OVERLAY_TTL`` parameters."""

    #: TTL value.
    ttl: 'int' = UInt16Field()
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', ttl: 'int') -> 'None': ...


@schema_final
class RouteViaParameter(Parameter, code=Enum_Parameter.ROUTE_VIA):
    """Header schema for HIP ``ROUTE_VIA`` parameters."""

    #: Flags.
    flags: 'RouteFlags' = BitField(length=2, namespace={
        'symmetric': (0, 1),
        'must_follow': (1, 1),
    })
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: HIT addresses.
    hit: 'list[IPv6Address]' = ListField(
        length=lambda pkt: pkt['len'] - 4,
        item_type=IPv6AddressField(),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', flags: 'RouteFlags', hit: 'list[str | bytes | int | IPv6Address]') -> 'None': ...


@schema_final
class FromParameter(Parameter, code=Enum_Parameter.FROM):
    """Header schema for HIP ``FROM`` parameters."""

    #: Address.
    address: 'IPv6Address' = IPv6AddressField()
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', address: 'str | bytes | int | IPv6Address') -> 'None': ...


@schema_final
class RVSHMACParameter(Parameter, code=Enum_Parameter.RVS_HMAC):
    """Header schema for HIP ``RVS_HMAC`` parameters."""

    #: HMAC value.
    hmac: 'bytes' = BytesField(length=lambda pkt: pkt['len'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', hmac: 'bytes') -> 'None': ...


@schema_final
class ViaRVSParameter(Parameter, code=Enum_Parameter.VIA_RVS):
    """Header schema for HIP ``VIA_RVS`` parameters."""

    #: Address.
    address: 'list[IPv6Address]' = ListField(
        length=lambda pkt: pkt['len'],
        item_type=IPv6AddressField(),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', address: 'list[str | bytes | int | IPv6Address]') -> 'None': ...


@schema_final
class RelayHMACParameter(Parameter, code=Enum_Parameter.RELAY_HMAC):
    """Header schema for HIP ``RELAY_HMAC`` parameters."""

    #: HMAC value.
    hmac: 'bytes' = BytesField(length=lambda pkt: pkt['len'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=parameter_padding_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Parameter', len: 'int', hmac: 'bytes') -> 'None': ...


@schema_final
class HIP(Schema):
    """Header schema for HIP packet."""

    #: Next header.
    next: 'Enum_TransType' = EnumField(length=1, namespace=Enum_TransType)
    #: Header length.
    len: 'int' = UInt8Field()
    #: Packet type.
    pkt: 'PacketType' = BitField(
        length=1,
        namespace={
            'bit_0': (0, 1),
            'type': (1, 7),
        },
    )
    #: HIP version.
    ver: 'VersionType' = BitField(
        length=1,
        namespace={
            'version': (0, 4),
            'bit_1': (7, 1),
        },
    )
    #: Checksum.
    checksum: 'bytes' = BytesField(length=2)
    #: HIP controls.
    control: 'ControlsType' = BitField(
        length=2,
        namespace={
            'anonymous': (15, 1),
        },
    )
    #: Sender's host identity tag.
    shit: 'int' = NumberField(length=16, signed=False)
    #: Receiver's host identity tag.
    rhit: 'int' = NumberField(length=16, signed=False)
    #: HIP parameters.
    param: 'list[Parameter]' = OptionField(
        length=lambda pkt: (pkt['len'] - 4) * 8,
        base_schema=Parameter,
        type_name='type',
        registry=Parameter.registry,
    )
    #: Payload.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, next: 'Enum_TransType', len: 'int', pkt: 'PacketType',
                     ver: 'VersionType', checksum: 'bytes', control: 'ControlsType',
                     shit: 'int', rhit: 'int', param: 'bytes | list[bytes | Parameter]',
                     payload: 'bytes | Protocol | Schema') -> 'None': ...
