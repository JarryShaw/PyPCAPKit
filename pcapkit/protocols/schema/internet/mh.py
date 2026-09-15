# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for mobility header"""

import datetime
import math
from typing import TYPE_CHECKING

from pcapkit.const.mh.access_type import AccessType as Enum_AccessType
from pcapkit.const.mh.ack_status_code import ACKStatusCode as Enum_ACKStatusCode
from pcapkit.const.mh.ani_suboption import ANISuboption as Enum_ANISuboption
from pcapkit.const.mh.auth_subtype import AuthSubtype as Enum_AuthSubtype
from pcapkit.const.mh.binding_ack_flag import BindingACKFlag as Enum_BindingACKFlag
from pcapkit.const.mh.binding_error import BindingError as Enum_BindingError
from pcapkit.const.mh.binding_revocation import BindingRevocation as Enum_BindingRevocation
from pcapkit.const.mh.binding_update_flag import BindingUpdateFlag as Enum_BindingUpdateFlag
from pcapkit.const.mh.cga_extension import CGAExtension as Enum_CGAExtension
from pcapkit.const.mh.cga_type import CGAType as Enum_CGAType
from pcapkit.const.mh.dhcp_support_mode import DHCPSupportMode as Enum_DHCPSupportMode
from pcapkit.const.mh.dns_status_code import DNSStatusCode as Enum_DNSStatusCode
from pcapkit.const.mh.dsmip6_tls_packet import DSMIP6TLSPacket as Enum_DSMIP6TLSPacket
from pcapkit.const.mh.dsmipv6_home_address import DSMIPv6HomeAddress as Enum_DSMIPv6HomeAddress
from pcapkit.const.mh.enumerating_algorithm import EnumeratingAlgorithm as Enum_EnumeratingAlgorithm
from pcapkit.const.mh.fb_ack_status import FlowBindingACKStatus as Enum_FlowBindingACKStatus
from pcapkit.const.mh.fb_action import FlowBindingAction as Enum_FlowBindingAction
from pcapkit.const.mh.fb_indication_trigger import \
    FlowBindingIndicationTrigger as Enum_FlowBindingIndicationTrigger
from pcapkit.const.mh.fb_type import FlowBindingType as Enum_FlowBindingType
from pcapkit.const.mh.flow_id_status import FlowIDStatus as Enum_FlowIDStatus
from pcapkit.const.mh.flow_id_suboption import FlowIDSuboption as Enum_FlowIDSuboption
from pcapkit.const.mh.handoff_type import HandoffType as Enum_HandoffType
from pcapkit.const.mh.handover_ack_flag import HandoverACKFlag as Enum_HandoverACKFlag
from pcapkit.const.mh.handover_ack_status import HandoverACKStatus as Enum_HandoverACKStatus
from pcapkit.const.mh.handover_initiate_flag import \
    HandoverInitiateFlag as Enum_HandoverInitiateFlag
from pcapkit.const.mh.handover_initiate_status import \
    HandoverInitiateStatus as Enum_HandoverInitiateStatus
from pcapkit.const.mh.home_address_reply import HomeAddressReply as Enum_HomeAddressReply
from pcapkit.const.mh.lla_code import LLACode as Enum_LLACode
from pcapkit.const.mh.lma_mag_suboption import \
    LMAControlledMAGSuboption as Enum_LMAControlledMAGSuboption
from pcapkit.const.mh.mn_group_id import MNGroupID as Enum_MNGroupID
from pcapkit.const.mh.mn_id_subtype import MNIDSubtype as Enum_MNIDSubtype
from pcapkit.const.mh.operator_id import OperatorID as Enum_OperatorID
from pcapkit.const.mh.option import Option as Enum_Option
from pcapkit.const.mh.packet import Packet as Enum_Packet
from pcapkit.const.mh.qos_attribute import QoSAttribute as Enum_QoSAttribute
from pcapkit.const.mh.revocation_status_code import \
    RevocationStatusCode as Enum_RevocationStatusCode
from pcapkit.const.mh.revocation_trigger import RevocationTrigger as Enum_RevocationTrigger
from pcapkit.const.mh.status_code import StatusCode as Enum_StatusCode
from pcapkit.const.mh.traffic_selector import TrafficSelector as Enum_TrafficSelector
from pcapkit.const.mh.upa_status import \
    UpdateNotificationACKStatus as Enum_UpdateNotificationACKStatus
from pcapkit.const.mh.upn_reason import UpdateNotificationReason as Enum_UpdateNotificationReason
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.collections import ListField, OptionField
from pcapkit.corekit.fields.ipaddress import IPv6AddressField
from pcapkit.corekit.fields.misc import (ConditionalField, ForwardMatchField, PayloadField,
                                         SchemaField, SwitchField)
from pcapkit.corekit.fields.numbers import (EnumField, UInt8Field, UInt16Field, UInt32Field,
                                            UInt64Field)
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField, StringField
from pcapkit.protocols.schema.schema import EnumSchema, Schema, schema_final
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING

__all__ = [
    'MH',

    'Packet',
    'UnknownMessage', 'BindingRefreshRequestMessage', 'HomeTestInitMessage', 'CareofTestInitMessage',
    'HomeTestMessage', 'CareofTestMessage', 'BindingUpdateMessage', 'BindingAcknowledgementMessage',
    'BindingErrorMessage', 'FastBindingUpdateMessage', 'FastBindingAcknowledgmentMessage',
    'FastNeighborAdvertisementMessage', 'ExperimentalMessage', 'HandoverInitiateMessage',
    'HandoverAcknowledgeMessage',

    'Option',
    'UnassignedOption', 'PadOption', 'BindingRefreshAdviceOption', 'AlternateCareofAddressOption',
    'NonceIndicesOption', 'AuthorizationDataOption', 'MobileNetworkPrefixOption',
    'LinkLayerAddressOption', 'MNIDOption', 'AuthOption', 'MesgIDOption', 'CGAParametersRequestOption',
    'CGAParametersOption', 'SignatureOption', 'PermanentHomeKeygenTokenOption', 'CareofTestInitOption',
    'CareofTestOption', 'ExperimentalMobilityOption', 'BADFOption', 'IPv6AddressPrefixOption',

    'CGAParameter',

    'CGAExtension',
    'UnknownExtension', 'MultiPrefixExtension',
]

if TYPE_CHECKING:
    from datetime import datetime as dt_type
    from ipaddress import IPv6Address
    from typing import Any

    from pcapkit.corekit.fields.field import FieldBase as Field
    from pcapkit.protocols.protocol import ProtocolBase as Protocol

if SPHINX_TYPE_CHECKING:  # pragma: no cover
    from typing_extensions import TypedDict

    class ANSIKeyLengthTest(TypedDict):
        """Length test for ANSI.1 encoded data, c.f.,
        :attr:`CGAParameter.public_key_test`."""

        len: int

    class MultiPrefixExtensionFlags(TypedDict):
        """Flags for :attr:`MultiPrefixExtension.flags`."""

        P: int

    class BindingUpdateMessageFlags(TypedDict):
        """Flags for :attr:`BindingUpdateMessage.flags`."""

        A: 'int'
        H: 'int'
        L: 'int'
        K: 'int'

    class BindingAcknowledgementMessageFlags(TypedDict):
        """Flags for :attr:`BindingAcknowledgementMessage.flags`."""

        K: 'int'

    class FastBindingUpdateMessageFlags(TypedDict):
        """Flags for :attr:`FastBindingUpdateMessage.flags`."""

        A: 'int'
        H: 'int'
        L: 'int'
        K: 'int'

    class FastBindingAcknowledgmentMessageFlags(TypedDict):
        """Flags for :attr:`FastBindingAcknowledgmentMessage.flags`."""

        K: 'int'

    class HandoverInitiateMessageFlags(TypedDict):
        """Flags for :attr:`HandoverInitiateMessage.flags`."""

        S: 'int'
        U: 'int'
        P: 'int'
        F: 'int'

    class HandoverAcknowledgeMessageFlags(TypedDict):
        """Flags for :attr:`HandoverAcknowledgeMessage.flags`."""

        U: 'int'
        P: 'int'
        F: 'int'


def mh_data_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`MH.data` field.

    Args:
        pkt: Packet data.

    Returns:
        Returns a :class:`~pcapkit.corekit.fields.misc.SchemaField`
        wrapped :class:`~pcapkit.protocols.schema.internet.mh.Packet`
        subclass instance.

    """
    type = pkt['type']  # type: Enum_Packet
    length = pkt['length'] * 8 + 2
    schema = Packet.registry[type]
    return SchemaField(length=length, schema=schema)


def mn_id_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`MNIDOption.identifier` field.

    Args:
        pkt: Packet data.

    Returns:
        Returns a :class:`~pcapkit.corekit.fields.field.Field` instance
        corresponding to the subtype.

    """
    subtype = pkt['subtype']  # type: Enum_MNIDSubtype
    if subtype == Enum_MNIDSubtype.NAI:
        return StringField(length=pkt['length'] - 1)
    if subtype == Enum_MNIDSubtype.IPv6_Address:
        return IPv6AddressField()
    return BytesField(length=pkt['length'] - 1)


def pad_opt_data_len(pkt: 'dict[str, Any]') -> 'int':
    """Return the length of the padding data of a padding option.

    Args:
        pkt: Padding option unpacked schema.

    Returns:
        Number of padding octets carried after the option header, i.e. the
        value of the ``Option Length`` field of a ``PadN`` option, and zero for
        a ``Pad1`` option, which carries no such field.

    Note:
        A ``Pad1`` option is a single octet with neither an ``Option Length``
        field nor any option data (c.f. :rfc:`6275#section-6.2.5`), which is why
        :attr:`Option.length` is declared as a
        :class:`~pcapkit.corekit.fields.misc.ConditionalField` and is skipped
        for it. A skipped conditional field is *recorded* in the packet data as
        :data:`~pcapkit.corekit.fields.field.NoValue`, rather than being left
        out of it, so the test below has to be on the **value** and not on the
        presence of the key: ``pkt.get('length', 0)`` on its own hands that
        :class:`~pcapkit.corekit.fields.field.NoValueType` straight to
        :class:`~pcapkit.corekit.fields.strings.PaddingField`, where it becomes
        an unusable :mod:`struct` template and surfaces much later as an opaque
        :exc:`struct.error` -- which is exactly how a ``Pad1`` option used to
        fail to parse.

    """
    length = pkt.get('length', 0)
    if not isinstance(length, int):  # ``NoValue`` (skipped) or :obj:`None` (unset)
        return 0
    return length


@schema_final
class MH(Schema):
    """Header schema for MH packets."""

    #: Next header.
    next: 'Enum_TransType' = EnumField(length=1, namespace=Enum_TransType)
    #: Header length.
    length: 'int' = UInt8Field()
    #: MH type.
    type: 'Enum_Packet' = EnumField(length=1, namespace=Enum_Packet)
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Checksum.
    chksum: 'bytes' = BytesField(length=2)
    #: Message data.
    data: 'Packet' = SwitchField(selector=mh_data_selector)
    #: Payload.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, next: 'Enum_TransType | int', length: 'int', type: 'Enum_Packet | int',
                     chksum: 'bytes', data: 'Packet | bytes', payload: 'bytes | Protocol | Schema') -> 'None': ...


class Option(EnumSchema[Enum_Option]):
    """Header schema for MH options."""

    __default__ = lambda: UnassignedOption

    #: Option type.
    type: 'Enum_Option' = EnumField(length=1, namespace=Enum_Option)
    #: Option length (excl. type and length fields), conditional in case of
    #: ``Pad1`` option.
    length: 'int' = ConditionalField(
        UInt8Field(default=0),
        lambda pkt: pkt['type'] != Enum_Option.Pad1,
    )

    def post_process(self, packet: 'dict[str, Any]') -> 'Option':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        # for Pad1 option, length is always 1
        if self.type == Enum_Option.Pad1:
            self.length = 0
        return self


@schema_final
class UnassignedOption(Option):
    """Header schema for unassigned MH options."""

    #: Option data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', data: 'bytes') -> 'None': ...


@schema_final
class PadOption(Option, code=[Enum_Option.Pad1,
                              Enum_Option.PadN]):
    """Header schema for MH padding options.

    The two padding options do **not** share a wire shape: a ``Pad1`` option is
    a lone type octet, whereas a ``PadN`` option is a type octet, an
    ``Option Length`` octet, and that many padding octets
    [:rfc:`6275#section-6.2.5`]. Both the ``Option Length`` octet
    (:attr:`Option.length`) and the padding data
    (:attr:`self.data <PadOption.data>`) are therefore sized from the option
    type, so that a ``Pad1`` option consumes exactly one octet.

    """

    #: Option data.
    data: 'bytes' = PaddingField(length=pad_opt_data_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int') -> 'None': ...


@schema_final
class BindingRefreshAdviceOption(Option, code=Enum_Option.Binding_Refresh_Advice):
    """Header schema for MH binding refresh advice options."""

    #: Refresh interval.
    interval: 'int' = UInt16Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', interval: 'int') -> 'None': ...


@schema_final
class AlternateCareofAddressOption(Option, code=Enum_Option.Alternate_Care_of_Address):
    """Header schema for MH alternate care-of address options."""

    #: Alternate care-of address.
    address: 'IPv6Address' = IPv6AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', address: 'IPv6Address | str | bytes | int') -> 'None': ...


@schema_final
class NonceIndicesOption(Option, code=Enum_Option.Nonce_Indices):
    """Header schema for MH nonce indices options."""

    #: Home nonce index.
    home: 'int' = UInt16Field()
    #: Care-of nonce index.
    careof: 'int' = UInt16Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', home: 'int', careof: 'int') -> 'None': ...


@schema_final
class AuthorizationDataOption(Option, code=Enum_Option.Authorization_Data):
    """Header schema for MH binding authorization data options."""

    #: Authenticator.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', data: 'bytes') -> 'None': ...


@schema_final
class MobileNetworkPrefixOption(Option, code=Enum_Option.Mobile_Network_Prefix_Option):
    """Header schema for MH mobile network prefix options."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Prefix length.
    prefix_length: 'int' = UInt8Field()
    #: Mobile network prefix.
    prefix: 'IPv6Address' = IPv6AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', prefix_length: 'int', prefix: 'IPv6Address | int | bytes | str') -> 'None': ...


@schema_final
class LinkLayerAddressOption(Option, code=Enum_Option.Mobility_Header_Link_Layer_Address_option):
    """Header schema for MH link-layer address (MH-LLA) options."""

    #: Option code.
    code: 'Enum_LLACode' = EnumField(length=1, namespace=Enum_LLACode)
    #: Link-layer address (LAA).
    lla: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 1)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', code: 'Enum_LLACode', lla: 'bytes') -> 'None': ...


@schema_final
class MNIDOption(Option, code=Enum_Option.MN_ID_OPTION_TYPE):
    """Header schema for MH mobile node identifier (MNID) options."""

    #: Subtype.
    subtype: 'Enum_MNIDSubtype' = EnumField(length=1, namespace=Enum_MNIDSubtype)
    #: Identifier.
    identifier: 'bytes | str | IPv6Address' = SwitchField(selector=mn_id_selector)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', subtype: 'Enum_MNIDSubtype', identifier: 'bytes | str | IPv6Address | int') -> 'None': ...


@schema_final
class AuthOption(Option, code=Enum_Option.AUTH_OPTION_TYPE):
    """Header schema for Mobility Message Authentication options."""

    #: Subtype.
    subtype: 'Enum_AuthSubtype' = EnumField(length=1, namespace=Enum_AuthSubtype)
    #: Mobility SPI.
    spi: 'int' = UInt32Field()
    #: Authentication data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 5)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', subtype: 'Enum_AuthSubtype', spi: 'int', data: 'bytes') -> 'None': ...


@schema_final
class MesgIDOption(Option, code=Enum_Option.MESG_ID_OPTION_TYPE):
    """Header schema for Mobility Message Replay Protection options."""

    #: Timestamp (seconds since January 1st, 1970, c.f., :rfc:`1305`).
    seconds: 'int' = UInt32Field()
    #: Timestamp fractions (1/2**32 seconds per unit, c.f., :rfc:`1305`).
    fraction: 'int' = UInt32Field()

    def post_process(self, packet: 'dict[str, Any]') -> 'MesgIDOption':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        self = super().post_process(packet)

        # convert timestamp to datetime
        # c.f., http://tickelton.gitlab.io/articles/ntp-timestamps/
        ts_sec = self.seconds - 2_208_988_800  # 70 years
        ts_usec = math.floor(self.fraction / 2**32)

        self.timestamp = datetime.datetime.fromtimestamp(ts_sec + ts_usec, tz=datetime.timezone.utc)

        return self

    if TYPE_CHECKING:
        #: Timestamp interval (since UNIX-epoch).
        timestamp: 'dt_type'

        def __init__(self, type: 'Enum_Option', length: 'int', seconds: 'int', fraction: 'int') -> 'None': ...


@schema_final
class CGAParametersRequestOption(Option, code=Enum_Option.CGA_Parameters_Request):
    """Header schema for CGA Parameters Request options."""

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int') -> 'None': ...


class CGAExtension(EnumSchema[Enum_CGAExtension]):
    """Header schema for CGA extensions."""

    __default__ = lambda: UnknownExtension

    #: Extension type.
    type: 'Enum_CGAExtension' = EnumField(length=2, namespace=Enum_CGAExtension)
    #: Extension data length.
    length: 'int' = UInt16Field()


@schema_final
class UnknownExtension(CGAExtension):
    """Header schema for unknown CGA extensions."""

    #: Extension data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_CGAExtension', length: 'int', data: 'bytes') -> 'None': ...


@schema_final
class MultiPrefixExtension(CGAExtension, code=Enum_CGAExtension.Multi_Prefix):
    """Header schema for Multi-Prefix CGA extensions."""

    #: Flags.
    flags: 'MultiPrefixExtensionFlags' = BitField(length=4, namespace={
        'P': (0, 1),
    })
    #: Prefixes.
    prefixes: 'list[int]' = ListField(
        length=lambda pkt: pkt['length'] - 4,
        item_type=UInt64Field(),
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_CGAExtension', length: 'int', flags: 'MultiPrefixExtensionFlags', prefixes: 'list[int]') -> 'None': ...


@schema_final
class CGAParameter(Schema):
    """Header schema for CGA Parameters."""

    #: Modifier.
    modifier: 'Enum_CGAType' = EnumField(length=16, namespace=Enum_CGAType)
    #: Subnet prefix.
    prefix: 'int' = UInt64Field()
    #: Collision count.
    collision_count: 'int' = UInt8Field()
    #: Public key length test.
    public_key_test: 'ANSIKeyLengthTest' = ForwardMatchField(BitField(length=2, namespace={
        'len': (8, 8),
    }))
    #: Public key (ASN.1 encoded).
    public_key: 'bytes' = BytesField(length=lambda pkt: pkt['public_key_test']['len'] + 2)  # 2 bytes for type & length
    #: Extension fields.
    extensions: 'list[CGAExtension]' = OptionField(
        length=lambda pkt: pkt['length'] - 25 - len(pkt['public_key']),
        base_schema=CGAExtension,
        type_name='type',
        registry=CGAExtension.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, modifier: 'Enum_CGAType', prefix: 'int', collision_count: 'int', public_key: 'bytes',
                     extensions: 'list[CGAExtension | bytes]') -> 'None': ...


@schema_final
class CGAParametersOption(Option, code=Enum_Option.CGA_Parameters):
    """Header schema for CGA Parameters options."""

    #: CGA parameters, c.f., :rfc:`3972`.
    parameters: 'list[CGAParameter]' = ListField(
        length=lambda pkt: pkt['length'],
        item_type=SchemaField(schema=CGAParameter),
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', parameters: 'list[CGAParameter | bytes]') -> 'None': ...


@schema_final
class SignatureOption(Option, code=Enum_Option.Signature):
    """Header schema for MH Signature options."""

    #: Signature.
    signature: 'bytes' = BytesField(length=lambda pkt: pkt['length'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', signature: 'bytes') -> 'None': ...


@schema_final
class PermanentHomeKeygenTokenOption(Option, code=Enum_Option.Permanent_Home_Keygen_Token):
    """Header schema for Permanent Home Keygen Token options."""

    #: Permanent home keygen token.
    token: 'bytes' = BytesField(length=lambda pkt: pkt['length'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', token: 'bytes') -> 'None': ...


@schema_final
class CareofTestInitOption(Option, code=Enum_Option.Care_of_Test_Init):
    """Header schema for MH Care-of Test Init options."""

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int') -> 'None': ...


@schema_final
class CareofTestOption(Option, code=Enum_Option.Care_of_Test):
    """Header schema for MH Care-of Test options."""

    #: Care-of keygen token.
    token: 'bytes' = BytesField(length=8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', token: 'bytes') -> 'None': ...


@schema_final
class ExperimentalMobilityOption(Option, code=Enum_Option.Experimental_Mobility_Option):
    """Header schema for MH Experimental Mobility options."""

    #: Experimental data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', data: 'bytes') -> 'None': ...


@schema_final
class BADFOption(Option, code=Enum_Option.Binding_Authorization_Data_for_FMIPv6):
    """Header schema for MH Binding Authorization Data for FMIPv6 (BADF) options.

    Note:
        Per :rfc:`5568#section-6.4.5`, the ``length`` field of this option counts
        the :attr:`data` (authenticator) bytes **only** -- it excludes the 4-byte
        :attr:`spi` field, unlike every other mobility option, whose length covers
        all option data. The option is therefore 6 bytes longer than its declared
        length, which is why :rfc:`5568` also requires it to be the **last**
        mobility option present.

    """

    #: Security parameter index. ``0`` is reserved for authenticators computed
    #: using SEND-based handover keys.
    spi: 'int' = UInt32Field()
    #: Authenticator.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', spi: 'int', data: 'bytes') -> 'None': ...


@schema_final
class IPv6AddressPrefixOption(Option, code=Enum_Option.Mobility_Header_IPv6_Address_Prefix):
    """Header schema for MH Mobility Header IPv6 Address/Prefix options.

    Note:
        The option codes of :rfc:`5568#section-6.4.2` are defined inline by the
        RFC with no IANA registry behind them, so their enumeration lives in
        :class:`pcapkit.protocols.internet.mh.IPv6AddressPrefixCode` rather than
        in :mod:`pcapkit.const.mh`. Being module-local, it cannot be imported
        here without a circular import, so :attr:`code` carries the raw wire
        integer and the enumeration is applied when
        :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_ipv6_ap` builds the
        data model -- the same split as
        :class:`pcapkit.protocols.misc.pcapng.PacketDirection` and the
        ``epb_flags`` option schema.

    """

    #: Option code, c.f.,
    #: :class:`pcapkit.protocols.internet.mh.IPv6AddressPrefixCode`.
    code: 'int' = UInt8Field()
    #: Prefix length.
    prefix_length: 'int' = UInt8Field()
    #: IPv6 address/prefix.
    address: 'IPv6Address' = IPv6AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', code: 'int', prefix_length: 'int',
                     address: 'IPv6Address | int | bytes | str') -> 'None': ...


# TODO: Implement other options.


class Packet(EnumSchema[Enum_Packet]):
    """Header schema for MH packet data."""

    __default__ = lambda: UnknownMessage


@schema_final
class UnknownMessage(Packet):
    """Header schema for MH unknown message type."""

    #: Message data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, data: 'bytes') -> 'None': ...


@schema_final
class BindingRefreshRequestMessage(Packet, code=Enum_Packet.Binding_Refresh_Request):
    """Header schema for MH Binding Refresh Request (BRR) message."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: Mobility options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['__length__'],
        base_schema=Option,
        type_name='type',
        registry=Option.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, options: 'list[Option | bytes]') -> 'None': ...


@schema_final
class HomeTestInitMessage(Packet, code=Enum_Packet.Home_Test_Init):
    """Header schema for MH Home Test Init (HoTI) message."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: Home init cookie.
    cookie: 'bytes' = BytesField(length=8)
    #: Mobility options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['__length__'],
        base_schema=Option,
        type_name='type',
        registry=Option.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, cookie: 'bytes', options: 'list[Option | bytes]') -> 'None': ...


@schema_final
class CareofTestInitMessage(Packet, code=Enum_Packet.Care_of_Test_Init):
    """Header schema for MH Care-of Test Init (CoTI) messages."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: Care-of init cookie.
    cookie: 'bytes' = BytesField(length=8)
    #: Mobility options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['__length__'],
        base_schema=Option,
        type_name='type',
        registry=Option.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, cookie: 'bytes', options: 'list[Option | bytes]') -> 'None': ...


@schema_final
class HomeTestMessage(Packet, code=Enum_Packet.Home_Test):
    """Header schema for MH Home Test (HoT) message."""

    #: Home nonce index.
    nonce_index: 'int' = UInt16Field()
    #: Home init cookie.
    cookie: 'bytes' = BytesField(length=8)
    #: Home keygen token.
    token: 'bytes' = BytesField(length=8)
    #: Mobility options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['__length__'],
        base_schema=Option,
        type_name='type',
        registry=Option.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, nonce_index: 'int', cookie: 'bytes', token: 'bytes',
                     options: 'list[Option | bytes]') -> 'None': ...


@schema_final
class CareofTestMessage(Packet, code=Enum_Packet.Care_of_Test):
    """Header schema for MH Care-of Test (CoT) message."""

    #: Care-of nonce index.
    nonce_index: 'int' = UInt16Field()
    #: Care-of init cookie.
    cookie: 'bytes' = BytesField(length=8)
    #: Care-of keygen token.
    token: 'bytes' = BytesField(length=8)
    #: Mobility options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['__length__'],
        base_schema=Option,
        type_name='type',
        registry=Option.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, nonce_index: 'int', cookie: 'bytes', token: 'bytes',
                     options: 'list[Option | bytes]') -> 'None': ...


@schema_final
class BindingUpdateMessage(Packet, code=Enum_Packet.Binding_Update):
    """Header schema for MH Binding Update (BU) messages."""

    #: Sequence number.
    seq: 'int' = UInt16Field()
    #: Flags.
    flags: 'BindingUpdateMessageFlags' = BitField(length=2, namespace={
        'A': (0, 1),
        'H': (1, 1),
        'L': (2, 1),
        'K': (3, 1),
    })
    #: Lifetime. One time unit is 4 seconds.
    lifetime: 'int' = UInt16Field()
    #: Mobility options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['__length__'],
        base_schema=Option,
        type_name='type',
        registry=Option.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, seq: 'int', flags: 'BindingUpdateMessageFlags',
                     lifetime: 'int', options: 'list[Option | bytes]') -> 'None': ...


@schema_final
class BindingAcknowledgementMessage(Packet, code=Enum_Packet.Binding_Acknowledgement):
    """Header schema for MH Binding Acknowledgement (BA) messages."""

    #: Status.
    status: 'Enum_StatusCode' = EnumField(length=1, namespace=Enum_StatusCode)
    #: Flags.
    flags: 'BindingAcknowledgementMessageFlags' = BitField(length=1, namespace={
        'K': (0, 1),
    })
    #: Sequence number.
    seq: 'int' = UInt16Field()
    #: Lifetime. One time unit is 4 seconds.
    lifetime: 'int' = UInt16Field()
    #: Mobility options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['__length__'],
        base_schema=Option,
        type_name='type',
        registry=Option.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, status: 'Enum_StatusCode', flags: 'BindingAcknowledgementMessageFlags',
                     seq: 'int', lifetime: 'int', options: 'list[Option | bytes]') -> 'None': ...


@schema_final
class BindingErrorMessage(Packet, code=Enum_Packet.Binding_Error):
    """Header schema for MH Binding Error (BE) messages."""

    #: Status.
    status: 'Enum_BindingError' = EnumField(length=1, namespace=Enum_BindingError)
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Home address.
    home: 'IPv6Address' = IPv6AddressField()
    #: Mobility options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['__length__'],
        base_schema=Option,
        type_name='type',
        registry=Option.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, status: 'Enum_BindingError', home: 'IPv6Address | str | int | bytes',
                     options: 'list[Option | bytes]') -> 'None': ...


@schema_final
class FastBindingUpdateMessage(Packet, code=Enum_Packet.Fast_Binding_Update):
    """Header schema for MH Fast Binding Update (FBU) messages."""

    #: Sequence number.
    seq: 'int' = UInt16Field()
    #: Flags.
    flags: 'FastBindingUpdateMessageFlags' = BitField(length=2, namespace={
        'A': (0, 1),
        'H': (1, 1),
        'L': (2, 1),
        'K': (3, 1),
    })
    #: Lifetime. One time unit is 4 seconds.
    lifetime: 'int' = UInt16Field()
    #: Mobility options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['__length__'],
        base_schema=Option,
        type_name='type',
        registry=Option.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, seq: 'int', flags: 'FastBindingUpdateMessageFlags',
                     lifetime: 'int', options: 'list[Option | bytes]') -> 'None': ...


@schema_final
class FastBindingAcknowledgmentMessage(Packet, code=Enum_Packet.Fast_Binding_Acknowledgment):
    """Header schema for MH Fast Binding Acknowledgment (FBack) messages.

    Note:
        The status values of :rfc:`5568#section-6.2.3` are defined inline by the
        RFC and are absent from the IANA *Status Codes* registry, so their
        enumeration lives in
        :class:`pcapkit.protocols.internet.mh.FastBindingAcknowledgmentStatus`
        rather than in :mod:`pcapkit.const.mh`. Being module-local, it cannot be
        imported here without a circular import, so :attr:`status` carries the
        raw wire integer and the enumeration is applied when
        :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_fback` builds the data
        model.

    """

    #: Status, c.f.,
    #: :class:`pcapkit.protocols.internet.mh.FastBindingAcknowledgmentStatus`.
    status: 'int' = UInt8Field()
    #: Flags.
    flags: 'FastBindingAcknowledgmentMessageFlags' = BitField(length=1, namespace={
        'K': (0, 1),
    })
    #: Sequence number.
    seq: 'int' = UInt16Field()
    #: Lifetime. One time unit is 4 seconds.
    lifetime: 'int' = UInt16Field()
    #: Mobility options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['__length__'],
        base_schema=Option,
        type_name='type',
        registry=Option.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, status: 'int', flags: 'FastBindingAcknowledgmentMessageFlags',
                     seq: 'int', lifetime: 'int', options: 'list[Option | bytes]') -> 'None': ...


@schema_final
class FastNeighborAdvertisementMessage(Packet, code=Enum_Packet.Fast_Neighbor_Advertisement):
    """Header schema for MH Fast Neighbor Advertisement (FNA) messages."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: Mobility options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['__length__'],
        base_schema=Option,
        type_name='type',
        registry=Option.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, options: 'list[Option | bytes]') -> 'None': ...


@schema_final
class ExperimentalMessage(Packet, code=Enum_Packet.Experimental_Mobility_Header):
    """Header schema for MH Experimental Mobility Header messages."""

    #: Experimental message data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, data: 'bytes') -> 'None': ...


@schema_final
class HandoverInitiateMessage(Packet, code=Enum_Packet.Handover_Initiate_Message):
    """Header schema for MH Handover Initiate (HI) messages."""

    #: Sequence number.
    seq: 'int' = UInt16Field()
    #: Flags.
    flags: 'HandoverInitiateMessageFlags' = BitField(length=1, namespace={
        'S': (0, 1),
        'U': (1, 1),
        'P': (2, 1),
        'F': (3, 1),
    })
    #: Code.
    code: 'Enum_HandoverInitiateStatus' = EnumField(length=1, namespace=Enum_HandoverInitiateStatus)
    #: Mobility options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['__length__'],
        base_schema=Option,
        type_name='type',
        registry=Option.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, seq: 'int', flags: 'HandoverInitiateMessageFlags',
                     code: 'Enum_HandoverInitiateStatus', options: 'list[Option | bytes]') -> 'None': ...


@schema_final
class HandoverAcknowledgeMessage(Packet, code=Enum_Packet.Handover_Acknowledge_Message):
    """Header schema for MH Handover Acknowledge (HAck) messages."""

    #: Sequence number.
    seq: 'int' = UInt16Field()
    #: Flags.
    flags: 'HandoverAcknowledgeMessageFlags' = BitField(length=1, namespace={
        'U': (0, 1),
        'P': (1, 1),
        'F': (2, 1),
    })
    #: Code.
    code: 'Enum_HandoverACKStatus' = EnumField(length=1, namespace=Enum_HandoverACKStatus)
    #: Mobility options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['__length__'],
        base_schema=Option,
        type_name='type',
        registry=Option.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, seq: 'int', flags: 'HandoverAcknowledgeMessageFlags',
                     code: 'Enum_HandoverACKStatus', options: 'list[Option | bytes]') -> 'None': ...


# TODO: Implement other message types.
