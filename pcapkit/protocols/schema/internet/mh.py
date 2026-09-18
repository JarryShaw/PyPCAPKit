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
from pcapkit.corekit.fields.ipaddress import IPv4AddressField, IPv6AddressField
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
    'HandoverAcknowledgeMessage', 'HeartbeatMessage', 'HomeAgentSwitchMessage',
    'BindingRevocationMessage', 'LocalizedRoutingInitiationMessage',
    'LocalizedRoutingAcknowledgmentMessage', 'UpdateNotificationMessage',
    'UpdateNotificationAcknowledgementMessage', 'FlowBindingMessage',
    'SubscriptionQueryMessage', 'SubscriptionResponseMessage',

    'Option',
    'UnassignedOption', 'PadOption', 'BindingRefreshAdviceOption', 'AlternateCareofAddressOption',
    'NonceIndicesOption', 'AuthorizationDataOption', 'MobileNetworkPrefixOption',
    'LinkLayerAddressOption', 'MNIDOption', 'AuthOption', 'MesgIDOption', 'CGAParametersRequestOption',
    'CGAParametersOption', 'SignatureOption', 'PermanentHomeKeygenTokenOption', 'CareofTestInitOption',
    'CareofTestOption', 'ExperimentalMobilityOption', 'BADFOption', 'IPv6AddressPrefixOption',
    'HomeNetworkPrefixOption', 'HandoffIndicatorOption', 'AccessTechnologyTypeOption',
    'MNLLIdentifierOption', 'LinkLocalAddressOption', 'TimestampOption', 'RestartCounterOption',
    'DNSUpdateOption', 'VendorSpecificOption', 'ServiceSelectionOption',
    'IPv4HomeAddressOption', 'IPv4AddressAcknowledgementOption', 'NATDetectionOption',
    'IPv4CareofAddressOption', 'GREKeyOption', 'BindingIdentifierOption',
    'IPv4HomeAddressRequestOption', 'IPv4HomeAddressReplyOption',
    'IPv4DefaultRouterAddressOption', 'IPv4DHCPSupportModeOption', 'ContextRequestOption',
    'LMAAddressOption', 'MNLLAIIDOption', 'TransientBindingOption', 'FlowSummaryOption',
    'FlowIdentificationOption', 'RedirectCapabilityOption', 'RedirectOption',
    'LoadInformationOption', 'AlternateIPv4CareofAddressOption', 'MNGroupIdentifierOption',
    'MAGIPv6AddressOption', 'AccessNetworkIdentifierOption', 'IPv4TrafficOffloadSelectorOption',
    'DynamicIPMulticastSelectorOption', 'DelegatedMNPOption',
    'ActiveMulticastSubscriptionIPv4Option', 'ActiveMulticastSubscriptionIPv6Option',
    'QualityOfServiceOption', 'LMAUserPlaneAddressOption', 'MulticastMobilityOption',
    'MulticastAcknowledgementOption', 'LMAControlledMAGParametersOption',
    'MAGMultipathBindingOption', 'MAGIdentifierOption', 'AnchoredPrefixOption',
    'LocalPrefixOption', 'PreviousMAAROption', 'ServingMAAROption',
    'DLIFLinkLocalAddressOption', 'DLIFLinkLayerAddressOption',

    'FlowIdentificationSuboption',
    'UnassignedFlowIdentificationSuboption', 'PadFlowIdentificationSuboption',
    'BIDReferenceSuboption', 'TrafficSelectorSuboption', 'FlowBindingActionSuboption',
    'TargetCareofAddressSuboption',

    'ANISuboption',
    'UnassignedANISuboption', 'ANINetworkIdentifierSuboption', 'ANIGeoLocationSuboption',
    'ANIOperatorIdentifierSuboption', 'ANICivicLocationSuboption',
    'ANIMAGGroupIdentifierSuboption', 'ANIUpdateTimerSuboption',

    'QoSAttribute',
    'UnassignedQoSAttribute', 'BitRateAttribute', 'PerSessionBitRateAttribute',
    'AllocationRetentionPriorityAttribute', 'QoSTrafficSelectorAttribute',
    'QoSVendorSpecificAttribute',

    'LMAControlledMAGSuboption',
    'UnassignedLMAControlledMAGSuboption', 'BindingReregistrationControlSuboption',
    'HeartbeatControlSuboption',

    'CGAParameter',

    'CGAExtension',
    'UnknownExtension', 'MultiPrefixExtension', 'ExperimentalExtension',
]

if TYPE_CHECKING:
    from datetime import datetime as dt_type
    from ipaddress import IPv4Address, IPv6Address
    from typing import Any, Optional

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

    class HeartbeatMessageFlags(TypedDict):
        """Flags for :attr:`HeartbeatMessage.flags`."""

        U: 'int'
        R: 'int'

    class FixedPointTimestamp(TypedDict):
        """Fixed-point timestamp of :attr:`TimestampOption.timestamp`."""

        seconds: 'int'
        fraction: 'int'

    class BindingRevocationMessageFlags(TypedDict):
        """Flags for :attr:`BindingRevocationMessage.flags`."""

        P: 'int'
        V: 'int'
        G: 'int'

    class LocalizedRoutingAcknowledgmentMessageFlags(TypedDict):
        """Flags for :attr:`LocalizedRoutingAcknowledgmentMessage.flags`."""

        U: 'int'

    class FlowBindingMessageFlags(TypedDict):
        """Flags for :attr:`FlowBindingMessage.flags`."""

        A: 'int'

    class UpdateNotificationMessageFlags(TypedDict):
        """Flags for :attr:`UpdateNotificationMessage.flags`."""

        A: 'int'
        D: 'int'

    class SubscriptionResponseMessageFlags(TypedDict):
        """Flags for :attr:`SubscriptionResponseMessage.flags`."""

        I: 'int'

    class DNSUpdateOptionFlags(TypedDict):
        """Flags for :attr:`DNSUpdateOption.flags`."""

        R: 'int'

    class IPv4HomeAddressOptionFlags(TypedDict):
        """Prefix length and flags of :attr:`IPv4HomeAddressOption.flags`."""

        prefix_length: 'int'
        P: 'int'

    class PrefixLengthOnly(TypedDict):
        """Prefix length packed alone in its own word, as in
        :attr:`IPv4AddressAcknowledgementOption.flags`,
        :attr:`IPv4HomeAddressRequestOption.flags` and
        :attr:`IPv4HomeAddressReplyOption.flags`."""

        prefix_length: 'int'

    class NATDetectionOptionFlags(TypedDict):
        """Flags for :attr:`NATDetectionOption.flags`."""

        F: 'int'

    class IPv4DHCPSupportModeOptionFlags(TypedDict):
        """Flags for :attr:`IPv4DHCPSupportModeOption.flags`."""

        S: 'int'

    class RedirectOptionFlags(TypedDict):
        """Flags for :attr:`RedirectOption.flags`."""

        K: 'int'
        N: 'int'

    class BindingIdentifierOptionFlags(TypedDict):
        """Flag and priority of :attr:`BindingIdentifierOption.flags`."""

        H: 'int'
        BID_PRI: 'int'

    class TransientBindingOptionFlags(TypedDict):
        """Flags for :attr:`TransientBindingOption.flags`."""

        L: 'int'

    class ModeFlagOnly(TypedDict):
        """A lone ``M`` mode flag, as in
        :attr:`DynamicIPMulticastSelectorOption.flags` and
        :attr:`IPv4TrafficOffloadSelectorOption.flags`."""

        M: 'int'

    class DelegatedMNPOptionFlags(TypedDict):
        """Flags for :attr:`DelegatedMNPOption.flags`."""

        V: 'int'

    class MAGMultipathBindingOptionFlags(TypedDict):
        """Flags for :attr:`MAGMultipathBindingOption.flags`."""

        B: 'int'
        O: 'int'

    class ANINetworkIdentifierFlags(TypedDict):
        """Flags for :attr:`ANINetworkIdentifierSuboption.flags`."""

        E: 'int'

    class GeoLocationDegrees(TypedDict):
        """Latitude and longitude of :attr:`ANIGeoLocationSuboption.location`."""

        latitude: 'int'
        longitude: 'int'

    class SessionBitRateFlags(TypedDict):
        """Flags for :attr:`PerSessionBitRateAttribute.flags`."""

        S: 'int'
        E: 'int'

    class AllocationRetentionPriorityFields(TypedDict):
        """Priority fields of :attr:`AllocationRetentionPriorityAttribute.priority`."""

        PL: 'int'
        PC: 'int'
        PV: 'int'


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


def pad_subopt_data_len(pkt: 'dict[str, Any]') -> 'int':
    """Return the length of the padding data of a flow identification padding
    sub-option.

    Args:
        pkt: Padding sub-option unpacked schema.

    Returns:
        Number of padding octets carried after the sub-option header, i.e. the
        value of the ``Sub-Opt Length`` field of a ``PadN`` sub-option, and zero
        for the one-octet ``Pad`` sub-option, which carries no such field.

    See Also:
        :func:`pad_opt_data_len`, which does the same job for the mobility
        options themselves and documents why the test has to be on the field
        *value* rather than on the presence of its key.

    """
    length = pkt.get('length', 0)
    if not isinstance(length, int):  # ``NoValue`` (skipped) or :obj:`None` (unset)
        return 0
    return length


def bid_address_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`BindingIdentifierOption.address` field.

    Args:
        pkt: Packet data.

    Returns:
        Returns a :class:`~pcapkit.corekit.fields.field.FieldBase` instance
        sized from the option length, which is the only thing on the wire that
        says whether the care-of address is an IPv4 or an IPv6 one
        [:rfc:`5648#section-4.3`].

    """
    length = pkt['length']
    if length == 8:
        return IPv4AddressField()
    if length == 20:
        return IPv6AddressField()
    return BytesField(length=max(length - 4, 0))


def lma_address_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`LMAAddressOption.address` field.

    Args:
        pkt: Packet data.

    Returns:
        Returns a :class:`~pcapkit.corekit.fields.field.FieldBase` instance
        sized from the option length -- 6 for an IPv4 address and 18 for an IPv6
        one [:rfc:`5949#section-6.2.2`].

    """
    length = pkt['length']
    if length == 6:
        return IPv4AddressField()
    if length == 18:
        return IPv6AddressField()
    return BytesField(length=max(length - 2, 0))


def target_coa_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`TargetCareofAddressSuboption.address` field.

    Args:
        pkt: Packet data.

    Returns:
        Returns a :class:`~pcapkit.corekit.fields.field.FieldBase` instance
        sized from the sub-option length -- 6 for an IPv4 address and 18 for an
        IPv6 one [:rfc:`7109#section-6.2.2`].

    """
    length = pkt['length']
    if length == 6:
        return IPv4AddressField()
    if length == 18:
        return IPv6AddressField()
    return BytesField(length=max(length - 2, 0))


def dmnp_prefix_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`DelegatedMNPOption.prefix` field.

    Args:
        pkt: Packet data.

    Returns:
        Returns a :class:`~pcapkit.corekit.fields.field.FieldBase` instance
        selected by the ``V`` flag, which :rfc:`7148#section-4.1` makes
        authoritative for the address family -- unlike the options that carry no
        such flag and have to be sized from their length.

    """
    if pkt['flags']['V']:
        return IPv4AddressField()
    return IPv6AddressField()


def lma_user_plane_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`LMAUserPlaneAddressOption.address` field.

    Args:
        pkt: Packet data.

    Returns:
        Returns a :class:`~pcapkit.corekit.fields.field.FieldBase` instance
        sized from the option length. :rfc:`7389#section-4` lets the address be
        absent as well as IPv4 or IPv6 -- a mobile access gateway sends the
        option with no address at all, or with an all-zero one, purely to say
        which transport it wants.

    """
    length = pkt['length']
    if length == 6:
        return IPv4AddressField()
    if length == 18:
        return IPv6AddressField()
    return BytesField(length=max(length - 2, 0))


def br_code_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`BindingRevocationMessage.code` field.

    Args:
        pkt: Packet data.

    Returns:
        Returns an :class:`~pcapkit.corekit.fields.numbers.EnumField` over the
        registry the octet draws from, which depends on which of the two forms
        of the message this is: a revocation trigger in a Binding Revocation
        Indication and a status code in a Binding Revocation Acknowledgement
        [:rfc:`5846#section-5.1`, :rfc:`5846#section-5.2`].

    """
    if pkt['br_type'] == Enum_BindingRevocation.Binding_Revocation_Acknowledgement:
        return EnumField(length=1, namespace=Enum_RevocationStatusCode)
    return EnumField(length=1, namespace=Enum_RevocationTrigger)


def fb_code_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`FlowBindingMessage.code` field.

    Args:
        pkt: Packet data.

    Returns:
        Returns an :class:`~pcapkit.corekit.fields.numbers.EnumField` over the
        registry the octet draws from, which depends on which of the two forms of
        the message this is: an indication trigger in a Flow Binding Indication
        and a status code in a Flow Binding Acknowledgement
        [:rfc:`7109#section-6.1.1`, :rfc:`7109#section-6.1.2`].

    """
    if pkt['fb_type'] == Enum_FlowBindingType.Acknowledgement:
        return EnumField(length=1, namespace=Enum_FlowBindingACKStatus)
    return EnumField(length=1, namespace=Enum_FlowBindingIndicationTrigger)


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
        # NOTE: No ``int`` here, and deliberately so even though
        # :meth:`MH._make_opt_mn_id <pcapkit.protocols.internet.mh.MH._make_opt_mn_id>`
        # *does* accept one. The two annotations describe different boundaries:
        # the maker's is what a **caller** may pass, while this one is what the
        # schema can **hold**, and the maker converts between them before ever
        # constructing this class -- an ``int`` becomes :obj:`bytes` via
        # :meth:`int.to_bytes` for the octet subtypes and an
        # :class:`~ipaddress.IPv6Address` for ``IPv6_Address``. Measured through
        # the maker: ``identifier=0x1234`` arrives here as ``b'\\x124'`` for
        # ``IMSI``/``DUID`` and as ``IPv6Address('::1234')`` for
        # ``IPv6_Address``, never as an ``int``. Widening this stub to admit one
        # would therefore document a value the schema can never hold, and would
        # positively mislead: ``mn_id_selector`` resolves every subtype but
        # ``IPv6_Address`` to a
        # :class:`~pcapkit.corekit.fields.strings.StringField` or
        # :class:`~pcapkit.corekit.fields.strings.BytesField`, and handing either
        # a raw ``int`` is precisely the #467 defect -- ``struct.pack()`` cannot
        # consume it (c.f. #467, #468).
        def __init__(self, type: 'Enum_Option', length: 'int', subtype: 'Enum_MNIDSubtype', identifier: 'bytes | str | IPv6Address') -> 'None': ...


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
class ExperimentalExtension(CGAExtension, code=[Enum_CGAExtension.Exp_FFFD,
                                                Enum_CGAExtension.Exp_FFFE,
                                                Enum_CGAExtension.Exp_FFFF]):
    """Header schema for experimental CGA extensions.

    :rfc:`4581#section-3` assigns extension types ``0xFFFD``, ``0xFFFE`` and
    ``0xFFFF`` for experimental use as :rfc:`3692` recommends, and defines **no**
    structure for their extension data -- neither it nor :rfc:`5535` gives those
    three a layout, and the IANA registry records only their names. So the data
    is genuinely opaque rather than merely undecoded here, and a parser cannot do
    better than the extension header and a byte string.

    The three share one schema because they share one shape; they are told apart
    by :attr:`CGAExtension.type`.

    """

    #: Extension data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_CGAExtension', length: 'int', data: 'bytes') -> 'None': ...


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


@schema_final
class DNSUpdateOption(Option, code=Enum_Option.DNS_UPDATE_TYPE):
    """Header schema for MH DNS-UPDATE-TYPE options."""

    #: Status.
    status: 'Enum_DNSStatusCode' = EnumField(length=1, namespace=Enum_DNSStatusCode)
    #: Flags.
    flags: 'DNSUpdateOptionFlags' = BitField(length=1, namespace={
        'R': (0, 1),
    })
    #: Mobile node identity, in FQDN form.
    identity: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 2)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', status: 'Enum_DNSStatusCode',
                     flags: 'DNSUpdateOptionFlags', identity: 'bytes') -> 'None': ...


@schema_final
class VendorSpecificOption(Option, code=Enum_Option.Vendor_Specific_Mobility_Option):
    """Header schema for MH Vendor Specific mobility options."""

    #: Vendor ID, an SMI Network Management Private Enterprise Number.
    vendor: 'int' = UInt32Field()
    #: Vendor-administered sub-type.
    subtype: 'int' = UInt8Field()
    #: Vendor-specific data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 5)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', vendor: 'int', subtype: 'int',
                     data: 'bytes') -> 'None': ...


@schema_final
class ServiceSelectionOption(Option, code=Enum_Option.Service_Selection_Mobility_Option):
    """Header schema for MH Service Selection mobility options."""

    #: Service identifier.
    identifier: 'str' = StringField(length=lambda pkt: pkt['length'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', identifier: 'str | bytes') -> 'None': ...


@schema_final
class HomeNetworkPrefixOption(Option, code=Enum_Option.Home_Network_Prefix_Option):
    """Header schema for MH Home Network Prefix options."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Prefix length.
    prefix_length: 'int' = UInt8Field()
    #: Home network prefix.
    prefix: 'IPv6Address' = IPv6AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', prefix_length: 'int',
                     prefix: 'IPv6Address | int | bytes | str') -> 'None': ...


@schema_final
class HandoffIndicatorOption(Option, code=Enum_Option.Handoff_Indicator_Option):
    """Header schema for MH Handoff Indicator options."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Handoff indicator.
    hi: 'Enum_HandoffType' = EnumField(length=1, namespace=Enum_HandoffType)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', hi: 'Enum_HandoffType') -> 'None': ...


@schema_final
class AccessTechnologyTypeOption(Option, code=Enum_Option.Access_Technology_Type_Option):
    """Header schema for MH Access Technology Type options."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Access technology type.
    att: 'Enum_AccessType' = EnumField(length=1, namespace=Enum_AccessType)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', att: 'Enum_AccessType') -> 'None': ...


@schema_final
class MNLLIdentifierOption(Option, code=Enum_Option.Mobile_Node_Link_layer_Identifier_Option):
    """Header schema for MH Mobile Node Link-layer Identifier options."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: Link-layer identifier.
    lli: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 2)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', lli: 'bytes') -> 'None': ...


@schema_final
class LinkLocalAddressOption(Option, code=Enum_Option.Link_local_Address_Option):
    """Header schema for MH Link-local Address options."""

    #: Link-local address.
    address: 'IPv6Address' = IPv6AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int',
                     address: 'IPv6Address | int | bytes | str') -> 'None': ...


@schema_final
class TimestampOption(Option, code=Enum_Option.Timestamp_Option):
    """Header schema for MH Timestamp options.

    Note:
        The 64-bit timestamp of :rfc:`5213#section-8.8` is **not** an
        :rfc:`1305` NTP timestamp, which is why it is not shared with
        :class:`MesgIDOption`. It counts seconds since 1 January 1970 00:00 UTC
        -- the UNIX epoch, not NTP's 1900 one -- in a fixed-point format whose
        integer part occupies the leading **48** bits and whose fractional part
        occupies the trailing **16**, each unit of the latter being 1/65536 of a
        second. NTP splits its 64 bits 32/32 from a different epoch, so reusing
        :class:`~pcapkit.protocols.internet.mh.NTPTimestamp` here would misread
        both halves.

    """

    #: Timestamp, as the 48-bit second count and 16-bit fraction of
    #: :rfc:`5213#section-8.8`.
    timestamp: 'FixedPointTimestamp' = BitField(length=8, namespace={
        'seconds': (0, 48),
        'fraction': (48, 16),
    })

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int',
                     timestamp: 'FixedPointTimestamp') -> 'None': ...


@schema_final
class RestartCounterOption(Option, code=Enum_Option.Restart_Counter):
    """Header schema for MH Restart Counter options."""

    #: Restart counter.
    counter: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', counter: 'int') -> 'None': ...


@schema_final
class IPv4HomeAddressOption(Option, code=Enum_Option.IPv4_Home_Address):
    """Header schema for MH IPv4 Home Address options."""

    #: Prefix length and flags. :rfc:`5555#section-3.1.1` packs the 6-bit
    #: ``Prefix-len``, the ``P`` flag and 9 reserved bits into one 16-bit word.
    flags: 'IPv4HomeAddressOptionFlags' = BitField(length=2, namespace={
        'prefix_length': (0, 6),
        'P': (6, 1),
    })
    #: IPv4 home address.
    address: 'IPv4Address' = IPv4AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', flags: 'IPv4HomeAddressOptionFlags',
                     address: 'IPv4Address | int | bytes | str') -> 'None': ...


@schema_final
class IPv4AddressAcknowledgementOption(Option, code=Enum_Option.IPv4_Address_Acknowledgement):
    """Header schema for MH IPv4 Address Acknowledgement options."""

    #: Status.
    status: 'Enum_DSMIPv6HomeAddress' = EnumField(length=1, namespace=Enum_DSMIPv6HomeAddress)
    #: Prefix length, with 2 reserved bits below it.
    flags: 'PrefixLengthOnly' = BitField(length=1, namespace={
        'prefix_length': (0, 6),
    })
    #: IPv4 home address.
    address: 'IPv4Address' = IPv4AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', status: 'Enum_DSMIPv6HomeAddress',
                     flags: 'PrefixLengthOnly',
                     address: 'IPv4Address | int | bytes | str') -> 'None': ...


@schema_final
class NATDetectionOption(Option, code=Enum_Option.NAT_Detection):
    """Header schema for MH NAT Detection options."""

    #: Flags.
    flags: 'NATDetectionOptionFlags' = BitField(length=2, namespace={
        'F': (0, 1),
    })
    #: Suggested NAT binding refresh time, in seconds.
    refresh: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', flags: 'NATDetectionOptionFlags',
                     refresh: 'int') -> 'None': ...


@schema_final
class IPv4CareofAddressOption(Option, code=Enum_Option.IPv4_Care_of_Address):
    """Header schema for MH IPv4 Care-of Address options."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: IPv4 care-of address.
    address: 'IPv4Address' = IPv4AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int',
                     address: 'IPv4Address | int | bytes | str') -> 'None': ...


@schema_final
class GREKeyOption(Option, code=Enum_Option.GRE_Key_Option):
    """Header schema for MH GRE Key options.

    Note:
        The ``GRE Key Identifier`` field is **absent** when
        :attr:`Option.length` is ``2`` and present when it is ``6``
        [:rfc:`5845#section-6.1`]. There is no flag saying so, so
        :attr:`key` is sized from the option length alone.

    """

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: GRE key identifier, carried only when the option length is 6.
    key: 'Optional[int]' = ConditionalField(
        UInt32Field(default=0),
        lambda pkt: pkt['length'] >= 6,
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int',
                     key: 'Optional[int]') -> 'None': ...


@schema_final
class BindingIdentifierOption(Option, code=Enum_Option.Binding_Identifier):
    """Header schema for MH Binding Identifier (BID) options.

    Note:
        The care-of address is absent when :attr:`Option.length` is ``4``, an
        IPv4 address when it is ``8``, and an IPv6 address when it is ``20``
        [:rfc:`5648#section-4.3`]. The option carries **no** address-family
        flag, so :attr:`address` is selected from the option length alone.

        :rfc:`6089#section-4.1` renames the 7 bits below the ``H`` flag from
        ``Reserved`` to ``BID-PRI``, a binding priority in which ``0`` means the
        sender predates :rfc:`6089`. The field is parsed under the newer name.

    """

    #: Binding identifier.
    bid: 'int' = UInt16Field()
    #: Status, overriding the message status for this binding alone.
    status: 'Enum_StatusCode' = EnumField(length=1, namespace=Enum_StatusCode)
    #: Simultaneous home and foreign binding flag, and binding priority.
    flags: 'BindingIdentifierOptionFlags' = BitField(length=1, namespace={
        'H': (0, 1),
        'BID_PRI': (1, 7),
    })
    #: Care-of address, absent for an option length of 4.
    address: 'Optional[IPv4Address | IPv6Address | bytes]' = ConditionalField(
        SwitchField(selector=bid_address_selector),
        lambda pkt: pkt['length'] > 4,
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', bid: 'int',
                     status: 'Enum_StatusCode', flags: 'BindingIdentifierOptionFlags',
                     address: 'Optional[IPv4Address | IPv6Address | bytes | int | str]') -> 'None': ...


@schema_final
class IPv4HomeAddressRequestOption(Option, code=Enum_Option.IPv4_Home_Address_Request):
    """Header schema for MH IPv4 Home Address Request options."""

    #: Prefix length, with 10 reserved bits below it.
    flags: 'PrefixLengthOnly' = BitField(length=2, namespace={
        'prefix_length': (0, 6),
    })
    #: Requested IPv4 home address.
    address: 'IPv4Address' = IPv4AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', flags: 'PrefixLengthOnly',
                     address: 'IPv4Address | int | bytes | str') -> 'None': ...


@schema_final
class IPv4HomeAddressReplyOption(Option, code=Enum_Option.IPv4_Home_Address_Reply):
    """Header schema for MH IPv4 Home Address Reply options."""

    #: Status.
    status: 'Enum_HomeAddressReply' = EnumField(length=1, namespace=Enum_HomeAddressReply)
    #: Prefix length, with 2 reserved bits below it.
    flags: 'PrefixLengthOnly' = BitField(length=1, namespace={
        'prefix_length': (0, 6),
    })
    #: Assigned IPv4 home address.
    address: 'IPv4Address' = IPv4AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', status: 'Enum_HomeAddressReply',
                     flags: 'PrefixLengthOnly',
                     address: 'IPv4Address | int | bytes | str') -> 'None': ...


@schema_final
class IPv4DefaultRouterAddressOption(Option, code=Enum_Option.IPv4_Default_Router_Address):
    """Header schema for MH IPv4 Default-Router Address options."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: IPv4 default-router address.
    address: 'IPv4Address' = IPv4AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int',
                     address: 'IPv4Address | int | bytes | str') -> 'None': ...


@schema_final
class IPv4DHCPSupportModeOption(Option, code=Enum_Option.IPv4_DHCP_Support_Mode):
    """Header schema for MH IPv4 DHCP Support Mode options."""

    #: Flags. The ``S`` bit is the **last** bit of the option, not the first
    #: [:rfc:`5844#section-3.3.4`].
    flags: 'IPv4DHCPSupportModeOptionFlags' = BitField(length=2, namespace={
        'S': (15, 1),
    })

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int',
                     flags: 'IPv4DHCPSupportModeOptionFlags') -> 'None': ...


@schema_final
class ContextRequestOption(Option, code=Enum_Option.Context_Request_Option):
    """Header schema for MH Context Request options.

    Note:
        The request entries are carried as one opaque run here and walked by
        :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_cr`, rather than as a
        :class:`~pcapkit.corekit.fields.collections.ListField` of a nested schema.
        Each entry is self-describing -- a type octet, a length octet and that many
        octets of value [:rfc:`5949#section-6.2.1`] -- so a nested schema would need
        a :class:`~pcapkit.corekit.fields.misc.SchemaField` with no fixed length,
        and such a field is handed ``-1`` as its length and hands that on as the
        nested schema's ``__length__``. Every field then decrements a budget that
        started negative, and parsing a perfectly valid option emits a
        :class:`~pcapkit.utilities.warnings.SchemaWarning` per field saying
        ``packet length < 0``. Decoding the run directly costs a few lines and
        keeps a valid packet quiet.

    """

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: Requested contexts, as a run of type/length/value entries.
    requests: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 2)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int',
                     requests: 'bytes') -> 'None': ...


@schema_final
class LMAAddressOption(Option, code=Enum_Option.Local_Mobility_Anchor_Address_Option):
    """Header schema for MH Local Mobility Anchor Address options.

    Note:
        :attr:`code` says whether an IPv6 (``1``) or an IPv4 (``2``) address
        follows [:rfc:`5949#section-6.2.2`]. Those codes are defined inline by
        the RFC with no IANA registry behind them, so their enumeration lives in
        :class:`pcapkit.protocols.internet.mh.LMAAddressCode` rather than in
        :mod:`pcapkit.const.mh`, and :attr:`code` carries the raw wire integer.
        The address field is nonetheless sized from :attr:`Option.length`, which
        is the authoritative width on the wire.

    """

    #: Option code, c.f.,
    #: :class:`pcapkit.protocols.internet.mh.LMAAddressCode`.
    code: 'int' = UInt8Field()
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Local mobility anchor address.
    address: 'IPv4Address | IPv6Address | bytes' = SwitchField(selector=lma_address_selector)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', code: 'int',
                     address: 'IPv4Address | IPv6Address | bytes | int | str') -> 'None': ...


@schema_final
class MNLLAIIDOption(Option,
                     code=Enum_Option.Mobile_Node_Link_local_Address_Interface_Identifier_Option):
    """Header schema for MH Mobile Node Link-local Address Interface Identifier options."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: Interface identifier.
    iid: 'bytes' = BytesField(length=8)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', iid: 'bytes') -> 'None': ...


@schema_final
class TransientBindingOption(Option, code=Enum_Option.Transient_Binding):
    """Header schema for MH Transient Binding options."""

    #: Flags.
    flags: 'TransientBindingOptionFlags' = BitField(length=1, namespace={
        'L': (7, 1),
    })
    #: Maximum lifetime of the transient state, in units of 100 milliseconds.
    lifetime: 'int' = UInt8Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int',
                     flags: 'TransientBindingOptionFlags', lifetime: 'int') -> 'None': ...


@schema_final
class FlowSummaryOption(Option, code=Enum_Option.Flow_Summary_Mobility_Option):
    """Header schema for MH Flow Summary mobility options."""

    #: Flow identifiers being refreshed.
    fid: 'list[int]' = ListField(
        length=lambda pkt: pkt['length'],
        item_type=UInt16Field(),
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', fid: 'list[int]') -> 'None': ...


class FlowIdentificationSuboption(EnumSchema[Enum_FlowIDSuboption]):
    """Header schema for MH Flow Identification sub-options."""

    __default__ = lambda: UnassignedFlowIdentificationSuboption

    #: Sub-option type.
    type: 'Enum_FlowIDSuboption' = EnumField(length=1, namespace=Enum_FlowIDSuboption)
    #: Sub-option length, conditional in case of the one-octet ``Pad`` sub-option.
    length: 'int' = ConditionalField(
        UInt8Field(default=0),
        lambda pkt: pkt['type'] != Enum_FlowIDSuboption.Pad,
    )

    def post_process(self, packet: 'dict[str, Any]') -> 'FlowIdentificationSuboption':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        # the one-octet ``Pad`` sub-option carries no length field at all
        if self.type == Enum_FlowIDSuboption.Pad:
            self.length = 0
        return self


@schema_final
class UnassignedFlowIdentificationSuboption(FlowIdentificationSuboption):
    """Header schema for unassigned MH Flow Identification sub-options."""

    #: Sub-option data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_FlowIDSuboption', length: 'int', data: 'bytes') -> 'None': ...


@schema_final
class PadFlowIdentificationSuboption(FlowIdentificationSuboption,
                                     code=[Enum_FlowIDSuboption.Pad,
                                           Enum_FlowIDSuboption.PadN]):
    """Header schema for MH Flow Identification padding sub-options.

    As with the mobility options themselves, the one-octet ``Pad`` sub-option
    carries neither a length field nor any data, whereas ``PadN`` carries both
    [:rfc:`6089#section-4.2.1.1`, :rfc:`6089#section-4.2.1.2`].

    """

    #: Sub-option data.
    data: 'bytes' = PaddingField(length=pad_subopt_data_len)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_FlowIDSuboption', length: 'int') -> 'None': ...


@schema_final
class BIDReferenceSuboption(FlowIdentificationSuboption,
                            code=Enum_FlowIDSuboption.BID_Reference):
    """Header schema for MH Flow Identification BID Reference sub-options."""

    #: Referenced binding identifiers.
    bid: 'list[int]' = ListField(
        length=lambda pkt: pkt['length'],
        item_type=UInt16Field(),
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_FlowIDSuboption', length: 'int',
                     bid: 'list[int]') -> 'None': ...


@schema_final
class TrafficSelectorSuboption(FlowIdentificationSuboption,
                               code=Enum_FlowIDSuboption.Traffic_Selector):
    """Header schema for MH Flow Identification Traffic Selector sub-options.

    Note:
        The interior of :attr:`selector` is defined by :rfc:`6088` -- a flag
        word followed by whichever of its sixteen range bounds the flags select
        -- and belongs to the separate *Traffic Selector Format* registry rather
        than to this sub-option. It is therefore carried opaquely here, and
        :attr:`ts_format` says which format it is in.

    """

    #: Traffic selector format.
    ts_format: 'Enum_TrafficSelector' = EnumField(length=1, namespace=Enum_TrafficSelector)
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Traffic selector, in the format named by :attr:`ts_format`.
    selector: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 2)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_FlowIDSuboption', length: 'int',
                     ts_format: 'Enum_TrafficSelector', selector: 'bytes') -> 'None': ...


@schema_final
class FlowBindingActionSuboption(FlowIdentificationSuboption,
                                 code=Enum_FlowIDSuboption.Flow_Binding_Action):
    """Header schema for MH Flow Identification Flow Binding Action sub-options."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Flow binding action.
    action: 'Enum_FlowBindingAction' = EnumField(length=1, namespace=Enum_FlowBindingAction)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_FlowIDSuboption', length: 'int',
                     action: 'Enum_FlowBindingAction') -> 'None': ...


@schema_final
class TargetCareofAddressSuboption(FlowIdentificationSuboption,
                                   code=Enum_FlowIDSuboption.Target_Care_of_Address):
    """Header schema for MH Flow Identification Target Care-of Address sub-options.

    Note:
        As with the Binding Identifier option, the sub-option carries no
        address-family flag, so the address is an IPv4 one when the sub-option
        length is 6 and an IPv6 one when it is 18
        [:rfc:`7109#section-6.2.2`].

    """

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: Target care-of address.
    address: 'IPv4Address | IPv6Address | bytes' = SwitchField(selector=target_coa_selector)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_FlowIDSuboption', length: 'int',
                     address: 'IPv4Address | IPv6Address | bytes | int | str') -> 'None': ...


@schema_final
class FlowIdentificationOption(Option, code=Enum_Option.Flow_Identification_Mobility_Option):
    """Header schema for MH Flow Identification mobility options."""

    #: Flow identifier.
    fid: 'int' = UInt16Field()
    #: Flow priority.
    fid_pri: 'int' = UInt16Field()
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Status.
    status: 'Enum_FlowIDStatus' = EnumField(length=1, namespace=Enum_FlowIDStatus)
    #: Sub-options.
    suboptions: 'list[FlowIdentificationSuboption]' = OptionField(
        length=lambda pkt: pkt['length'] - 6,
        base_schema=FlowIdentificationSuboption,
        type_name='type',
        registry=FlowIdentificationSuboption.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', fid: 'int', fid_pri: 'int',
                     status: 'Enum_FlowIDStatus',
                     suboptions: 'list[FlowIdentificationSuboption | bytes]') -> 'None': ...


@schema_final
class RedirectCapabilityOption(Option, code=Enum_Option.Redirect_Capability_Mobility_Option):
    """Header schema for MH Redirect-Capability mobility options."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int') -> 'None': ...


@schema_final
class RedirectOption(Option, code=Enum_Option.Redirect_Mobility_Option):
    """Header schema for MH Redirect mobility options.

    Note:
        Exactly one of the ``K`` and ``N`` flags is set -- :rfc:`6463#section-4.2`
        forbids both being set and both being clear -- so exactly one of
        :attr:`ipv6` and :attr:`ipv4` is present, and the option length is
        correspondingly 18 or 6.

    """

    #: Flags.
    flags: 'RedirectOptionFlags' = BitField(length=2, namespace={
        'K': (0, 1),
        'N': (1, 1),
    })
    #: IPv6 address of the redirected-to LMA, present when ``K`` is set.
    ipv6: 'Optional[IPv6Address]' = ConditionalField(
        IPv6AddressField(),
        lambda pkt: bool(pkt['flags']['K']),
    )
    #: IPv4 address of the redirected-to LMA, present when ``N`` is set.
    ipv4: 'Optional[IPv4Address]' = ConditionalField(
        IPv4AddressField(),
        lambda pkt: bool(pkt['flags']['N']),
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', flags: 'RedirectOptionFlags',
                     ipv6: 'Optional[IPv6Address | int | bytes | str]',
                     ipv4: 'Optional[IPv4Address | int | bytes | str]') -> 'None': ...


@schema_final
class LoadInformationOption(Option, code=Enum_Option.Load_Information_Mobility_Option):
    """Header schema for MH Load Information mobility options."""

    #: Priority; a lower value is a higher priority.
    priority: 'int' = UInt16Field()
    #: Mobility sessions currently in use.
    sessions_in_use: 'int' = UInt32Field()
    #: Maximum number of mobility sessions accepted.
    max_sessions: 'int' = UInt32Field()
    #: Used capacity, in kilobytes per second.
    used_capacity: 'int' = UInt32Field()
    #: Maximum capacity, in kilobytes per second.
    max_capacity: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', priority: 'int',
                     sessions_in_use: 'int', max_sessions: 'int', used_capacity: 'int',
                     max_capacity: 'int') -> 'None': ...


@schema_final
class AlternateIPv4CareofAddressOption(Option, code=Enum_Option.Alternate_IPv4_Care_of_Address):
    """Header schema for MH Alternate IPv4 Care-of Address options."""

    #: Alternate IPv4 care-of address.
    address: 'IPv4Address' = IPv4AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int',
                     address: 'IPv4Address | int | bytes | str') -> 'None': ...


@schema_final
class MNGroupIdentifierOption(Option, code=Enum_Option.Mobile_Node_Group_Identifier):
    """Header schema for MH Mobile Node Group Identifier options."""

    #: Sub-type.
    subtype: 'Enum_MNGroupID' = EnumField(length=1, namespace=Enum_MNGroupID)
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Mobile node group identifier.
    group_id: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', subtype: 'Enum_MNGroupID',
                     group_id: 'int') -> 'None': ...


@schema_final
class MAGIPv6AddressOption(Option, code=Enum_Option.MAG_IPv6_Address):
    """Header schema for MH MAG IPv6 Address options."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Address length, in bits; always 128.
    address_length: 'int' = UInt8Field()
    #: MAG IPv6 address.
    address: 'IPv6Address' = IPv6AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', address_length: 'int',
                     address: 'IPv6Address | int | bytes | str') -> 'None': ...


class ANISuboption(EnumSchema[Enum_ANISuboption]):
    """Header schema for MH Access Network Identifier sub-options."""

    __default__ = lambda: UnassignedANISuboption

    #: Sub-option type.
    type: 'Enum_ANISuboption' = EnumField(length=1, namespace=Enum_ANISuboption)
    #: Sub-option length.
    length: 'int' = UInt8Field()


@schema_final
class UnassignedANISuboption(ANISuboption):
    """Header schema for unassigned MH Access Network Identifier sub-options."""

    #: Sub-option data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_ANISuboption', length: 'int', data: 'bytes') -> 'None': ...


@schema_final
class ANINetworkIdentifierSuboption(ANISuboption, code=Enum_ANISuboption.Network_Identifier):
    """Header schema for MH Network-Identifier ANI sub-options."""

    #: Flags.
    flags: 'ANINetworkIdentifierFlags' = BitField(length=1, namespace={
        'E': (0, 1),
    })
    #: Network name length.
    net_name_len: 'int' = UInt8Field()
    #: Network name, e.g. an SSID or a PLMN identifier.
    net_name: 'bytes' = BytesField(length=lambda pkt: pkt['net_name_len'])
    #: Access-point name length.
    ap_name_len: 'int' = UInt8Field()
    #: Access-point name.
    ap_name: 'bytes' = BytesField(length=lambda pkt: pkt['ap_name_len'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_ANISuboption', length: 'int',
                     flags: 'ANINetworkIdentifierFlags', net_name_len: 'int', net_name: 'bytes',
                     ap_name_len: 'int', ap_name: 'bytes') -> 'None': ...


@schema_final
class ANIGeoLocationSuboption(ANISuboption, code=Enum_ANISuboption.Geo_Location):
    """Header schema for MH Geo-Location ANI sub-options.

    Note:
        Both degree fields are 24-bit **two's-complement** fixed-point values
        with 9 integer bits [:rfc:`6757#section-3.1.2`]. A
        :class:`~pcapkit.corekit.fields.strings.BitField` reads them unsigned,
        so the sign is applied when
        :meth:`~pcapkit.protocols.internet.mh.MH._read_ani_geo` builds the data
        model.

    """

    #: Latitude and longitude, in the fixed-point format of
    #: :rfc:`6757#section-3.1.2`.
    location: 'GeoLocationDegrees' = BitField(length=6, namespace={
        'latitude': (0, 24),
        'longitude': (24, 24),
    })

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_ANISuboption', length: 'int',
                     location: 'GeoLocationDegrees') -> 'None': ...


@schema_final
class ANIOperatorIdentifierSuboption(ANISuboption, code=Enum_ANISuboption.Operator_Identifier):
    """Header schema for MH Operator-Identifier ANI sub-options."""

    #: Operator identifier type.
    op_id_type: 'Enum_OperatorID' = EnumField(length=1, namespace=Enum_OperatorID)
    #: Operator identifier.
    identifier: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 1)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_ANISuboption', length: 'int',
                     op_id_type: 'Enum_OperatorID', identifier: 'bytes') -> 'None': ...


@schema_final
class ANICivicLocationSuboption(ANISuboption, code=Enum_ANISuboption.Civic_Location):
    """Header schema for MH Civic-Location ANI sub-options
    [:rfc:`7563#section-3.1`]."""

    #: Encoding format; only ``0``, the binary encoding of :rfc:`4776#section-3.1`,
    #: is defined.
    format: 'int' = UInt8Field()
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Civic location.
    location: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 2)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_ANISuboption', length: 'int', format: 'int',
                     location: 'bytes') -> 'None': ...


@schema_final
class ANIMAGGroupIdentifierSuboption(ANISuboption, code=Enum_ANISuboption.MAG_Group_Identifier):
    """Header schema for MH MAG-Group-Identifier ANI sub-options.

    Note:
        :rfc:`7563#section-3.2` contradicts itself about this field's width: the
        diagram places ``group identifier`` in bits 16 to 31 of the word, and the
        prose fixes ``ANI Length`` at ``2``, but the field description then calls
        it "a 3-octet unsigned integer value". Two of the three statements agree
        on **two** octets and are the ones that constrain the wire, so that is
        what is parsed here. No erratum has been filed against the RFC.

    """

    #: MAG group identifier.
    group_id: 'int' = UInt16Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_ANISuboption', length: 'int',
                     group_id: 'int') -> 'None': ...


@schema_final
class ANIUpdateTimerSuboption(ANISuboption, code=Enum_ANISuboption.ANI_Update_Timer):
    """Header schema for MH ANI Update-Timer sub-options
    [:rfc:`7563#section-3.3`]."""

    #: Update timer. One time unit is 4 seconds; ``0`` asks for an immediate
    #: update.
    timer: 'int' = UInt16Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_ANISuboption', length: 'int',
                     timer: 'int') -> 'None': ...


@schema_final
class AccessNetworkIdentifierOption(Option, code=Enum_Option.Access_Network_Identifier):
    """Header schema for MH Access Network Identifier options.

    Note:
        Unlike most options that carry sub-options, this one has **no** reserved
        octet between its own length and the first sub-option
        [:rfc:`6757#section-3`].

    """

    #: Sub-options.
    suboptions: 'list[ANISuboption]' = OptionField(
        length=lambda pkt: pkt['length'],
        base_schema=ANISuboption,
        type_name='type',
        registry=ANISuboption.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int',
                     suboptions: 'list[ANISuboption | bytes]') -> 'None': ...


@schema_final
class IPv4TrafficOffloadSelectorOption(Option, code=Enum_Option.IPv4_Traffic_Offload_Selector):
    """Header schema for MH IPv4 Traffic Offload Selector options."""

    #: Flags.
    flags: 'ModeFlagOnly' = BitField(length=4, namespace={
        'M': (0, 1),
    })
    #: Traffic selector, carried as the traffic selector sub-option of
    #: :rfc:`6089#section-4.2.1.4`. Optional in a proxy binding update and
    #: mandatory in a proxy binding acknowledgement, hence a list.
    selector: 'list[FlowIdentificationSuboption]' = OptionField(
        length=lambda pkt: pkt['length'] - 4,
        base_schema=FlowIdentificationSuboption,
        type_name='type',
        registry=FlowIdentificationSuboption.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', flags: 'ModeFlagOnly',
                     selector: 'list[FlowIdentificationSuboption | bytes]') -> 'None': ...


@schema_final
class DynamicIPMulticastSelectorOption(Option, code=Enum_Option.Dynamic_IP_Multicast_Selector):
    """Header schema for MH Dynamic IP Multicast Selector options.

    Note:
        The multicast address records are :rfc:`3810#section-5.2` MLD or
        :rfc:`3376#section-4.2` IGMP structures, which belong to those protocols
        rather than to the Mobility Header, so they are carried opaquely here.
        :attr:`protocol` says which of the two they are in -- ``143`` for MLDv2
        and ``131`` for MLDv1.

    """

    #: MLD or IGMP protocol number identifying the record format.
    protocol: 'int' = UInt8Field()
    #: Flags.
    flags: 'ModeFlagOnly' = BitField(length=1, namespace={
        'M': (0, 1),
    })
    #: Number of multicast address records.
    records: 'int' = UInt16Field()
    #: Multicast address records.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', protocol: 'int',
                     flags: 'ModeFlagOnly', records: 'int', data: 'bytes') -> 'None': ...


@schema_final
class DelegatedMNPOption(Option, code=Enum_Option.Delegated_Mobile_Network_Prefix):
    """Header schema for MH Delegated Mobile Network Prefix options."""

    #: Flags.
    flags: 'DelegatedMNPOptionFlags' = BitField(length=1, namespace={
        'V': (0, 1),
    })
    #: Prefix length.
    prefix_length: 'int' = UInt8Field()
    #: Delegated mobile network prefix, an IPv4 one when ``V`` is set.
    prefix: 'IPv4Address | IPv6Address' = SwitchField(selector=dmnp_prefix_selector)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int',
                     flags: 'DelegatedMNPOptionFlags', prefix_length: 'int',
                     prefix: 'IPv4Address | IPv6Address | int | bytes | str') -> 'None': ...


@schema_final
class ActiveMulticastSubscriptionIPv4Option(
        Option, code=Enum_Option.Active_Multicast_Subscription_IPv4):
    """Header schema for MH Active Multicast Subscription IPv4 options.

    Note:
        The membership context is an IGMP group address or group record
        [:rfc:`1112`, :rfc:`2236`, :rfc:`3376#section-4.2`], which belongs to
        IGMP rather than to the Mobility Header, so it is carried opaquely here.

    """

    #: IGMP message type identifying the context format: ``0x12`` for IGMPv1,
    #: ``0x16`` for IGMPv2 and ``0x22`` for IGMPv3.
    igmp_type: 'int' = UInt8Field()
    #: Multicast membership context.
    context: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 1)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', igmp_type: 'int',
                     context: 'bytes') -> 'None': ...


@schema_final
class ActiveMulticastSubscriptionIPv6Option(
        Option, code=Enum_Option.Active_Multicast_Subscription_IPv6):
    """Header schema for MH Active Multicast Subscription IPv6 options.

    Note:
        The membership context is an :rfc:`3810#section-5.2` multicast address
        record for MLDv2, or a reserved word followed by a multicast address for
        MLDv1 [:rfc:`2710`]. Both belong to MLD rather than to the Mobility
        Header, so the context is carried opaquely here.

    """

    #: MLD message type identifying the context format: ``143`` for MLDv2 and
    #: ``131`` for MLDv1.
    mld_type: 'int' = UInt8Field()
    #: Multicast membership context.
    context: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 1)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', mld_type: 'int',
                     context: 'bytes') -> 'None': ...


class QoSAttribute(EnumSchema[Enum_QoSAttribute]):
    """Header schema for MH Quality-of-Service attributes."""

    __default__ = lambda: UnassignedQoSAttribute

    #: Attribute type.
    type: 'Enum_QoSAttribute' = EnumField(length=1, namespace=Enum_QoSAttribute)
    #: Attribute length.
    length: 'int' = UInt8Field()


@schema_final
class UnassignedQoSAttribute(QoSAttribute):
    """Header schema for unassigned MH Quality-of-Service attributes."""

    #: Attribute value.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_QoSAttribute', length: 'int', data: 'bytes') -> 'None': ...


@schema_final
class BitRateAttribute(QoSAttribute, code=[Enum_QoSAttribute.Per_MN_Agg_Max_DL_Bit_Rate,
                                           Enum_QoSAttribute.Per_MN_Agg_Max_UL_Bit_Rate,
                                           Enum_QoSAttribute.Aggregate_Max_DL_Bit_Rate,
                                           Enum_QoSAttribute.Aggregate_Max_UL_Bit_Rate,
                                           Enum_QoSAttribute.Guaranteed_DL_Bit_Rate,
                                           Enum_QoSAttribute.Guaranteed_UL_Bit_Rate]):
    """Header schema for the MH Quality-of-Service attributes that carry a bare
    bit rate.

    Six of the eleven registered attributes share this shape -- two reserved
    octets and a 32-bit rate [:rfc:`7222#section-4.2.1`,
    :rfc:`7222#section-4.2.2`, :rfc:`7222#section-4.2.6` to
    :rfc:`7222#section-4.2.9`] -- so one schema is registered against all six.

    Note:
        The rate is in **bits** per second, not kilobits
        [:rfc:`7222#section-4.2.1`].

    """

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: Bit rate, in bits per second.
    rate: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_QoSAttribute', length: 'int', rate: 'int') -> 'None': ...


@schema_final
class PerSessionBitRateAttribute(
        QoSAttribute, code=[Enum_QoSAttribute.Per_Session_Agg_Max_DL_Bit_Rate,
                            Enum_QoSAttribute.Per_Session_Agg_Max_UL_Bit_Rate]):
    """Header schema for the MH per-session aggregate maximum bit-rate
    Quality-of-Service attributes [:rfc:`7222#section-4.2.3`,
    :rfc:`7222#section-4.2.4`]."""

    #: Flags.
    flags: 'SessionBitRateFlags' = BitField(length=2, namespace={
        'S': (0, 1),
        'E': (1, 1),
    })
    #: Bit rate, in bits per second.
    rate: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_QoSAttribute', length: 'int',
                     flags: 'SessionBitRateFlags', rate: 'int') -> 'None': ...


@schema_final
class AllocationRetentionPriorityAttribute(
        QoSAttribute, code=Enum_QoSAttribute.Allocation_Retention_Priority):
    """Header schema for the MH Allocation-Retention-Priority Quality-of-Service
    attribute [:rfc:`7222#section-4.2.5`]."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Priority level, pre-emption capability and pre-emption vulnerability.
    priority: 'AllocationRetentionPriorityFields' = BitField(length=1, namespace={
        'PL': (0, 4),
        'PC': (4, 2),
        'PV': (6, 2),
    })

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_QoSAttribute', length: 'int',
                     priority: 'AllocationRetentionPriorityFields') -> 'None': ...


@schema_final
class QoSTrafficSelectorAttribute(QoSAttribute, code=Enum_QoSAttribute.QoS_Traffic_Selector):
    """Header schema for the MH QoS-Traffic-Selector Quality-of-Service attribute.

    Note:
        The reserved octet comes **before** the traffic selector format here,
        which is the other way round from the traffic selector sub-option of
        :rfc:`6089#section-4.2.1.4` [:rfc:`7222#section-4.2.10`]. The two are
        otherwise the same shape, which makes them easy to confuse.

    """

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Traffic selector format.
    ts_format: 'Enum_TrafficSelector' = EnumField(length=1, namespace=Enum_TrafficSelector)
    #: Traffic selector, in the format named by :attr:`ts_format`.
    selector: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 2)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_QoSAttribute', length: 'int',
                     ts_format: 'Enum_TrafficSelector', selector: 'bytes') -> 'None': ...


@schema_final
class QoSVendorSpecificAttribute(
        QoSAttribute, code=Enum_QoSAttribute.QoS_Vendor_Specific_Attribute):
    """Header schema for the MH QoS-Vendor-Specific Quality-of-Service attribute
    [:rfc:`7222#section-4.2.11`]."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: Vendor ID, an SMI Network Management Private Enterprise Number.
    vendor: 'int' = UInt32Field()
    #: Vendor-administered sub-type.
    subtype: 'int' = UInt8Field()
    #: Vendor-specific data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 7)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_QoSAttribute', length: 'int', vendor: 'int',
                     subtype: 'int', data: 'bytes') -> 'None': ...


@schema_final
class QualityOfServiceOption(Option, code=Enum_Option.Quality_of_Service):
    """Header schema for MH Quality-of-Service options."""

    #: Service request identifier.
    sr_id: 'int' = UInt8Field()
    #: Traffic class, holding a 6-bit DSCP and 2 reserved bits.
    tc: 'int' = UInt8Field()
    #: Operational code.
    oc: 'int' = UInt8Field()
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=3)
    #: Quality-of-service attributes.
    attributes: 'list[QoSAttribute]' = OptionField(
        length=lambda pkt: pkt['length'] - 6,
        base_schema=QoSAttribute,
        type_name='type',
        registry=QoSAttribute.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', sr_id: 'int', tc: 'int',
                     oc: 'int', attributes: 'list[QoSAttribute | bytes]') -> 'None': ...


@schema_final
class LMAUserPlaneAddressOption(Option, code=Enum_Option.LMA_User_Plane_Address):
    """Header schema for MH LMA User-Plane Address options."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: LMA user-plane address, absent in a proxy binding update.
    address: 'IPv4Address | IPv6Address | bytes' = SwitchField(selector=lma_user_plane_selector)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int',
                     address: 'IPv4Address | IPv6Address | bytes | int | str') -> 'None': ...


@schema_final
class MulticastMobilityOption(Option, code=Enum_Option.Multicast_Mobility_Option):
    """Header schema for MH Multicast Mobility options.

    Note:
        This option's length field is **not** the usual octet count.
        :rfc:`7411#section-5.3` measures it in 32-bit *words* and excludes the
        option code and reserved octets as well as the type and length ones, so
        the whole option occupies ``4 + length * 4`` octets. The report payload
        itself is an MLD or IGMP structure belonging to those protocols, so it is
        carried opaquely.

    """

    #: Option code: ``1`` for IGMPv3, ``2`` for MLDv2, ``3`` for IGMPv3 in
    #: IGMPv2 compatibility mode and ``4`` for MLDv2 in MLDv1 compatibility mode.
    code: 'int' = UInt8Field()
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: MLD or IGMP report payload.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'] * 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', code: 'int',
                     data: 'bytes') -> 'None': ...


@schema_final
class MulticastAcknowledgementOption(Option, code=Enum_Option.Multicast_Acknowledgement_Option):
    """Header schema for MH Multicast Acknowledgement options.

    Note:
        As with :class:`MulticastMobilityOption`, the length field counts 32-bit
        words rather than octets and excludes the option code and status octets
        [:rfc:`7411#section-5.4`].

    """

    #: Option code; always ``0``.
    code: 'int' = UInt8Field()
    #: Status: ``1`` report payload type unsupported, ``2`` requested group
    #: service unsupported, ``3`` requested group service administratively
    #: prohibited.
    status: 'int' = UInt8Field()
    #: MLD or IGMP unsupported report payload.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'] * 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', code: 'int', status: 'int',
                     data: 'bytes') -> 'None': ...


class LMAControlledMAGSuboption(EnumSchema[Enum_LMAControlledMAGSuboption]):
    """Header schema for MH LMA-Controlled MAG Parameters sub-options."""

    __default__ = lambda: UnassignedLMAControlledMAGSuboption

    #: Sub-option type.
    type: 'Enum_LMAControlledMAGSuboption' = EnumField(
        length=1, namespace=Enum_LMAControlledMAGSuboption)
    #: Sub-option length.
    length: 'int' = UInt8Field()


@schema_final
class UnassignedLMAControlledMAGSuboption(LMAControlledMAGSuboption):
    """Header schema for unassigned MH LMA-Controlled MAG Parameters sub-options."""

    #: Sub-option data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_LMAControlledMAGSuboption', length: 'int',
                     data: 'bytes') -> 'None': ...


@schema_final
class BindingReregistrationControlSuboption(
        LMAControlledMAGSuboption,
        code=Enum_LMAControlledMAGSuboption.Binding_Re_registration_Control):
    """Header schema for MH Binding Re-registration Control sub-options
    [:rfc:`8127#section-3.1.1`]."""

    #: Time before binding expiry at which to re-register. One time unit is
    #: 4 seconds.
    start_time: 'int' = UInt16Field()
    #: Minimum delay before the first retransmission, in seconds.
    initial_retransmission: 'int' = UInt16Field()
    #: Maximum delay before the last retransmission, in seconds.
    max_retransmission: 'int' = UInt16Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_LMAControlledMAGSuboption', length: 'int',
                     start_time: 'int', initial_retransmission: 'int',
                     max_retransmission: 'int') -> 'None': ...


@schema_final
class HeartbeatControlSuboption(LMAControlledMAGSuboption,
                                code=Enum_LMAControlledMAGSuboption.Heartbeat_Control):
    """Header schema for MH Heartbeat Control sub-options [:rfc:`8127#section-3.1.2`]."""

    #: Delay after a successful heartbeat exchange, in seconds.
    interval: 'int' = UInt16Field()
    #: Minimum delay before a heartbeat retransmission, in seconds.
    retransmission_delay: 'int' = UInt16Field()
    #: Maximum number of heartbeat retransmissions.
    max_retransmissions: 'int' = UInt16Field()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_LMAControlledMAGSuboption', length: 'int',
                     interval: 'int', retransmission_delay: 'int',
                     max_retransmissions: 'int') -> 'None': ...


@schema_final
class LMAControlledMAGParametersOption(Option, code=Enum_Option.LMA_Controlled_MAG_Parameters):
    """Header schema for MH LMA-Controlled MAG Parameters options.

    Note:
        The option is registered to :rfc:`8127`, not to :rfc:`7864` -- the latter
        defines the flow-mobility options and the ``FLOW-MOBILITY`` update
        notification reason instead.

    """

    #: Sub-options.
    suboptions: 'list[LMAControlledMAGSuboption]' = OptionField(
        length=lambda pkt: pkt['length'],
        base_schema=LMAControlledMAGSuboption,
        type_name='type',
        registry=LMAControlledMAGSuboption.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int',
                     suboptions: 'list[LMAControlledMAGSuboption | bytes]') -> 'None': ...


@schema_final
class MAGMultipathBindingOption(Option, code=Enum_Option.MAG_Multipath_Binding):
    """Header schema for MH MAG Multipath Binding options."""

    #: Interface access-technology type.
    att: 'Enum_AccessType' = EnumField(length=1, namespace=Enum_AccessType)
    #: Interface label.
    label: 'int' = UInt8Field()
    #: Binding identifier; ``0`` and ``255`` are reserved.
    bid: 'int' = UInt8Field()
    #: Flags.
    flags: 'MAGMultipathBindingOptionFlags' = BitField(length=3, namespace={
        'B': (0, 1),
        'O': (1, 1),
    })

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', att: 'Enum_AccessType',
                     label: 'int', bid: 'int',
                     flags: 'MAGMultipathBindingOptionFlags') -> 'None': ...


@schema_final
class MAGIdentifierOption(Option, code=Enum_Option.MAG_Identifier):
    """Header schema for MH MAG Identifier options."""

    #: Sub-type, drawn from the mobile node identifier subtype registry.
    subtype: 'Enum_MNIDSubtype' = EnumField(length=1, namespace=Enum_MNIDSubtype)
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Identifier, in the form named by :attr:`subtype`.
    identifier: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 2)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', subtype: 'Enum_MNIDSubtype',
                     identifier: 'bytes') -> 'None': ...


@schema_final
class AnchoredPrefixOption(Option, code=Enum_Option.Anchored_Prefix):
    """Header schema for MH Anchored Prefix options [:rfc:`8885#section-4.3`]."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Prefix length.
    prefix_length: 'int' = UInt8Field()
    #: Anchored prefix.
    prefix: 'IPv6Address' = IPv6AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', prefix_length: 'int',
                     prefix: 'IPv6Address | int | bytes | str') -> 'None': ...


@schema_final
class LocalPrefixOption(Option, code=Enum_Option.Local_Prefix):
    """Header schema for MH Local Prefix options [:rfc:`8885#section-4.4`]."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Prefix length.
    prefix_length: 'int' = UInt8Field()
    #: Local prefix.
    prefix: 'IPv6Address' = IPv6AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', prefix_length: 'int',
                     prefix: 'IPv6Address | int | bytes | str') -> 'None': ...


@schema_final
class PreviousMAAROption(Option, code=Enum_Option.Previous_MAAR):
    """Header schema for MH Previous MAAR options [:rfc:`8885#section-4.5`]."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Prefix length of :attr:`prefix`.
    prefix_length: 'int' = UInt8Field()
    #: Previous MAAR's global address.
    maar: 'IPv6Address' = IPv6AddressField()
    #: Mobile node's home network prefix.
    prefix: 'IPv6Address' = IPv6AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', prefix_length: 'int',
                     maar: 'IPv6Address | int | bytes | str',
                     prefix: 'IPv6Address | int | bytes | str') -> 'None': ...


@schema_final
class ServingMAAROption(Option, code=Enum_Option.Serving_MAAR):
    """Header schema for MH Serving MAAR options [:rfc:`8885#section-4.6`]."""

    #: Serving MAAR's global address.
    address: 'IPv6Address' = IPv6AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int',
                     address: 'IPv6Address | int | bytes | str') -> 'None': ...


@schema_final
class DLIFLinkLocalAddressOption(Option, code=Enum_Option.DLIF_Link_Local_Address):
    """Header schema for MH DLIF Link-Local Address options [:rfc:`8885#section-4.7`]."""

    #: Distributed logical interface's link-local address.
    address: 'IPv6Address' = IPv6AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int',
                     address: 'IPv6Address | int | bytes | str') -> 'None': ...


@schema_final
class DLIFLinkLayerAddressOption(Option, code=Enum_Option.DLIF_Link_Layer_Address):
    """Header schema for MH DLIF Link-Layer Address options [:rfc:`8885#section-4.8`]."""

    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: Distributed logical interface's link-layer address, encoded as in
    #: :rfc:`4861#section-4.6.2` and therefore link-type dependent in width.
    lla: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 2)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', lla: 'bytes') -> 'None': ...


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


@schema_final
class HeartbeatMessage(Packet, code=Enum_Packet.Heartbeat_Message):
    """Header schema for MH Heartbeat messages."""

    #: Flags.
    flags: 'HeartbeatMessageFlags' = BitField(length=2, namespace={
        'U': (14, 1),
        'R': (15, 1),
    })
    #: Sequence number.
    seq: 'int' = UInt32Field()
    #: Mobility options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['__length__'],
        base_schema=Option,
        type_name='type',
        registry=Option.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, flags: 'HeartbeatMessageFlags', seq: 'int',
                     options: 'list[Option | bytes]') -> 'None': ...


@schema_final
class HomeAgentSwitchMessage(Packet, code=Enum_Packet.Home_Agent_Switch_Message):
    """Header schema for MH Home Agent Switch messages."""

    #: Number of home agent addresses that follow.
    count: 'int' = UInt8Field()
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Home agent addresses.
    addresses: 'list[IPv6Address]' = ListField(
        length=lambda pkt: pkt['count'] * 16,
        item_type=IPv6AddressField(),
    )
    #: Mobility options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['__length__'],
        base_schema=Option,
        type_name='type',
        registry=Option.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, count: 'int', addresses: 'list[IPv6Address | int | bytes | str]',
                     options: 'list[Option | bytes]') -> 'None': ...


@schema_final
class BindingRevocationMessage(Packet, code=Enum_Packet.Binding_Revocation_Message):
    """Header schema for MH Binding Revocation messages.

    The one message type carries two forms, told apart by :attr:`br_type` rather
    than by the Mobility Header type: a Binding Revocation Indication
    [:rfc:`5846#section-5.1`] and a Binding Revocation Acknowledgement
    [:rfc:`5846#section-5.2`]. Both have the same geometry, and the only field
    that differs is the octet after :attr:`br_type` -- a revocation trigger in
    the former and a status code in the latter -- so :attr:`code` selects its
    enumeration from :attr:`br_type`.

    """

    #: Binding revocation type, saying which form this is.
    br_type: 'Enum_BindingRevocation' = EnumField(length=1, namespace=Enum_BindingRevocation)
    #: Revocation trigger, or acknowledgement status.
    code: 'Enum_RevocationTrigger | Enum_RevocationStatusCode' = SwitchField(
        selector=br_code_selector)
    #: Sequence number.
    seq: 'int' = UInt16Field()
    #: Flags.
    flags: 'BindingRevocationMessageFlags' = BitField(length=2, namespace={
        'P': (0, 1),
        'V': (1, 1),
        'G': (2, 1),
    })
    #: Mobility options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['__length__'],
        base_schema=Option,
        type_name='type',
        registry=Option.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, br_type: 'Enum_BindingRevocation',
                     code: 'Enum_RevocationTrigger | Enum_RevocationStatusCode | int',
                     seq: 'int', flags: 'BindingRevocationMessageFlags',
                     options: 'list[Option | bytes]') -> 'None': ...


@schema_final
class LocalizedRoutingInitiationMessage(Packet, code=Enum_Packet.Localized_Routing_Initiation):
    """Header schema for MH Localized Routing Initiation messages."""

    #: Sequence number.
    seq: 'int' = UInt16Field()
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: Lifetime, **in seconds** rather than in the units of 4 seconds that the
    #: binding messages use. ``0xFFFF`` is an infinite lifetime and ``0`` asks
    #: for localized routing to stop [:rfc:`6705#section-10.1`].
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
        def __init__(self, seq: 'int', lifetime: 'int',
                     options: 'list[Option | bytes]') -> 'None': ...


@schema_final
class LocalizedRoutingAcknowledgmentMessage(
        Packet, code=Enum_Packet.Localized_Routing_Acknowledgment):
    """Header schema for MH Localized Routing Acknowledgment messages.

    Note:
        :rfc:`6705#section-10.2` defines this message's three status values
        inline and IANA keeps no registry for them -- they are neither in the
        general *Status Codes* registry nor in one of their own -- so their
        enumeration lives in
        :class:`pcapkit.protocols.internet.mh.LocalizedRoutingStatus` rather than
        in :mod:`pcapkit.const.mh`. Being module-local, it cannot be imported
        here without a circular import, so :attr:`status` carries the raw wire
        integer.

    """

    #: Sequence number.
    seq: 'int' = UInt16Field()
    #: Flags.
    flags: 'LocalizedRoutingAcknowledgmentMessageFlags' = BitField(length=1, namespace={
        'U': (0, 1),
    })
    #: Status, c.f.,
    #: :class:`pcapkit.protocols.internet.mh.LocalizedRoutingStatus`.
    status: 'int' = UInt8Field()
    #: Lifetime, in seconds.
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
        def __init__(self, seq: 'int', flags: 'LocalizedRoutingAcknowledgmentMessageFlags',
                     status: 'int', lifetime: 'int',
                     options: 'list[Option | bytes]') -> 'None': ...


@schema_final
class UpdateNotificationMessage(Packet, code=Enum_Packet.Update_Notification):
    """Header schema for MH Update Notification messages."""

    #: Sequence number.
    seq: 'int' = UInt16Field()
    #: Notification reason.
    reason: 'Enum_UpdateNotificationReason' = EnumField(
        length=2, namespace=Enum_UpdateNotificationReason)
    #: Flags.
    flags: 'UpdateNotificationMessageFlags' = BitField(length=2, namespace={
        'A': (0, 1),
        'D': (1, 1),
    })
    #: Mobility options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['__length__'],
        base_schema=Option,
        type_name='type',
        registry=Option.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, seq: 'int', reason: 'Enum_UpdateNotificationReason',
                     flags: 'UpdateNotificationMessageFlags',
                     options: 'list[Option | bytes]') -> 'None': ...


@schema_final
class UpdateNotificationAcknowledgementMessage(
        Packet, code=Enum_Packet.Update_Notification_Acknowledgement):
    """Header schema for MH Update Notification Acknowledgement messages."""

    #: Sequence number.
    seq: 'int' = UInt16Field()
    #: Status.
    status: 'Enum_UpdateNotificationACKStatus' = EnumField(
        length=1, namespace=Enum_UpdateNotificationACKStatus)
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=3)
    #: Mobility options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['__length__'],
        base_schema=Option,
        type_name='type',
        registry=Option.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, seq: 'int', status: 'Enum_UpdateNotificationACKStatus',
                     options: 'list[Option | bytes]') -> 'None': ...


@schema_final
class FlowBindingMessage(Packet, code=Enum_Packet.Flow_Binding_Message):
    """Header schema for MH Flow Binding messages.

    As with :class:`BindingRevocationMessage`, the one message type carries two
    forms told apart by a field inside the message rather than by the Mobility
    Header type: a Flow Binding Indication [:rfc:`7109#section-6.1.1`] and a Flow
    Binding Acknowledgement [:rfc:`7109#section-6.1.2`], selected by
    :attr:`fb_type`.

    Note:
        The octet after :attr:`code` holds the ``A`` flag in an indication and is
        wholly reserved in an acknowledgement, so :attr:`flags` reads as all-zero
        for a well-formed acknowledgement.

    """

    #: Flow binding type, saying which form this is.
    fb_type: 'Enum_FlowBindingType' = EnumField(length=2, namespace=Enum_FlowBindingType)
    #: Sequence number.
    seq: 'int' = UInt16Field()
    #: Indication trigger, or acknowledgement status.
    code: 'Enum_FlowBindingIndicationTrigger | Enum_FlowBindingACKStatus' = SwitchField(
        selector=fb_code_selector)
    #: Flags.
    flags: 'FlowBindingMessageFlags' = BitField(length=1, namespace={
        'A': (0, 1),
    })
    #: Mobility options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['__length__'],
        base_schema=Option,
        type_name='type',
        registry=Option.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, fb_type: 'Enum_FlowBindingType', seq: 'int',
                     code: 'Enum_FlowBindingIndicationTrigger | Enum_FlowBindingACKStatus | int',
                     flags: 'FlowBindingMessageFlags',
                     options: 'list[Option | bytes]') -> 'None': ...


@schema_final
class SubscriptionQueryMessage(Packet, code=Enum_Packet.Subscription_Query):
    """Header schema for MH Subscription Query messages.

    Note:
        The sequence number is a single octet here, unlike the two-octet one of
        most other mobility messages [:rfc:`7161#section-4.3.1.2`].

    """

    #: Sequence number, counted modulo 256.
    seq: 'int' = UInt8Field()
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Mobility options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['__length__'],
        base_schema=Option,
        type_name='type',
        registry=Option.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, seq: 'int', options: 'list[Option | bytes]') -> 'None': ...


@schema_final
class SubscriptionResponseMessage(Packet, code=Enum_Packet.Subscription_Response):
    """Header schema for MH Subscription Response messages."""

    #: Sequence number, echoed from the query.
    seq: 'int' = UInt8Field()
    #: Flags.
    flags: 'SubscriptionResponseMessageFlags' = BitField(length=1, namespace={
        'I': (0, 1),
    })
    #: Mobility options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['__length__'],
        base_schema=Option,
        type_name='type',
        registry=Option.registry,
        eool=None,
    )

    if TYPE_CHECKING:
        def __init__(self, seq: 'int', flags: 'SubscriptionResponseMessageFlags',
                     options: 'list[Option | bytes]') -> 'None': ...


# TODO: Implement other message types.
