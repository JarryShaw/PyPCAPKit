# -*- coding: utf-8 -*-
"""data model for MH protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from datetime import datetime as dt_type
    from datetime import timedelta
    from ipaddress import IPv4Address, IPv6Address, IPv6Network
    from typing import Optional

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
    from pcapkit.const.mh.enumerating_algorithm import \
        EnumeratingAlgorithm as Enum_EnumeratingAlgorithm
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
    from pcapkit.const.mh.packet import Packet
    from pcapkit.const.mh.packet import Packet as Enum_Packet
    from pcapkit.const.mh.qos_attribute import QoSAttribute as Enum_QoSAttribute
    from pcapkit.const.mh.revocation_status_code import \
        RevocationStatusCode as Enum_RevocationStatusCode
    from pcapkit.const.mh.revocation_trigger import RevocationTrigger as Enum_RevocationTrigger
    from pcapkit.const.mh.status_code import StatusCode as Enum_StatusCode
    from pcapkit.const.mh.traffic_selector import TrafficSelector as Enum_TrafficSelector
    from pcapkit.const.mh.upa_status import \
        UpdateNotificationACKStatus as Enum_UpdateNotificationACKStatus
    from pcapkit.const.mh.upn_reason import \
        UpdateNotificationReason as Enum_UpdateNotificationReason
    from pcapkit.const.reg.transtype import TransType
    from pcapkit.corekit.multidict import OrderedMultiDict
    from pcapkit.protocols.internet.mh import (FastBindingAcknowledgmentStatus,
                                               IPv6AddressPrefixCode, LMAAddressCode,
                                               LocalizedRoutingStatus, NTPTimestamp,
                                               PMIPv6Timestamp)

__all__ = [
    'MH',
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

    'ContextRequest',

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


class MH(Protocol):
    """Data model for MH protocol."""

    #: Next header.
    next: 'TransType'
    #: Header length.
    length: 'int'
    #: Mobility header type.
    type: 'Packet'
    #: Checksum.
    chksum: 'bytes'


@info_final
class UnknownMessage(MH):
    """Data model for MH unknown message type."""

    #: Message data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes', data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin,line-too-long


@info_final
class BindingRefreshRequestMessage(MH):
    """Data model for MH Binding Refresh Request (BRR) message type."""

    #: Mobility options.
    options: 'OrderedMultiDict[Enum_Option, Option]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes',
                     options: 'OrderedMultiDict[Enum_Option, Option]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin,line-too-long


@info_final
class HomeTestInitMessage(MH):
    """Data modelf for MH Home Test Init (HoTI) message type."""

    #: Home init cookie.
    cookie: 'bytes'
    #: Mobility options.
    options: 'OrderedMultiDict[Enum_Option, Option]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes',
                     cookie: 'bytes', options: 'OrderedMultiDict[Enum_Option, Option]') -> 'None': ...


@info_final
class CareofTestInitMessage(MH):
    """Data model for MH Care-of Test Init (CoTI) message type."""

    #: Care-of init cookie.
    cookie: 'bytes'
    #: Mobility options.
    options: 'OrderedMultiDict[Enum_Option, Option]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes',
                     cookie: 'bytes', options: 'OrderedMultiDict[Enum_Option, Option]') -> 'None': ...


@info_final
class HomeTestMessage(MH):
    """Data model for MH Home Test (HoT) message type."""

    #: Home nonce index.
    nonce_index: 'int'
    #: Home init cookie.
    cookie: 'bytes'
    #: Home keygen token.
    token: 'bytes'
    #: Mobility options.
    options: 'OrderedMultiDict[Enum_Option, Option]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes',
                     nonce_index: 'int', cookie: 'bytes', token: 'bytes',
                     options: 'OrderedMultiDict[Enum_Option, Option]') -> 'None': ...


@info_final
class CareofTestMessage(MH):
    """Data model for MH Care-of Test (CoT) message type."""

    #: Care-of nonce index.
    nonce_index: 'int'
    #: Care-of init cookie.
    cookie: 'bytes'
    #: Care-of keygen token.
    token: 'bytes'
    #: Mobility options.
    options: 'OrderedMultiDict[Enum_Option, Option]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes',
                     nonce_index: 'int', cookie: 'bytes', token: 'bytes',
                     options: 'OrderedMultiDict[Enum_Option, Option]') -> 'None': ...


@info_final
class BindingUpdateMessage(MH):
    """Data model for MH Binding Update message type."""

    #: Sequence number.
    seq: 'int'
    #: Acknowledge flag.
    ack: 'bool'
    #: home registration flag.
    home: 'bool'
    #: Link-local address compability flag.
    lla_compat: 'bool'
    #: Key management mobility capability flag.
    key_mngt: 'bool'
    #: Lifetime.
    lifetime: 'timedelta'
    #: Mobility options.
    options: 'OrderedMultiDict[Enum_Option, Option]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes',
                     seq: 'int', ack: 'bool', home: 'bool', lla_compat: 'bool', key_mngt: 'bool',
                     lifetime: 'timedelta', options: 'OrderedMultiDict[Enum_Option, Option]') -> 'None': ...


@info_final
class BindingAcknowledgementMessage(MH):
    """Data model for MH Binding Acknowledge (BA) message type."""

    #: Status.
    status: 'Enum_StatusCode'
    #: Key management mobility capability flag.
    key_mngt: 'bool'
    #: Sequence number.
    seq: 'int'
    #: Lifetime.
    lifetime: 'timedelta'
    #: Mobility options.
    options: 'OrderedMultiDict[Enum_Option, Option]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes',
                     status: 'Enum_StatusCode', key_mngt: 'bool', seq: 'int', lifetime: 'timedelta',
                     options: 'OrderedMultiDict[Enum_Option, Option]') -> 'None': ...


@info_final
class BindingErrorMessage(MH):
    """Data model for MH Binding Error (BE) message type."""

    #: Status.
    status: 'Enum_BindingError'
    #: Home address.
    home: 'IPv6Address'
    #: Mobility options.
    options: 'OrderedMultiDict[Enum_Option, Option]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes',
                     status: 'Enum_BindingError', home: 'IPv6Address',
                     options: 'OrderedMultiDict[Enum_Option, Option]') -> 'None': ...


@info_final
class FastBindingUpdateMessage(MH):
    """Data model for MH Fast Binding Update (FBU) message type."""

    #: Sequence number.
    seq: 'int'
    #: Acknowledge flag.
    ack: 'bool'
    #: Home registration flag.
    home: 'bool'
    #: Link-local address compatibility flag.
    lla_compat: 'bool'
    #: Key management mobility capability flag.
    key_mngt: 'bool'
    #: Lifetime.
    lifetime: 'timedelta'
    #: Mobility options.
    options: 'OrderedMultiDict[Enum_Option, Option]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes',
                     seq: 'int', ack: 'bool', home: 'bool', lla_compat: 'bool', key_mngt: 'bool',
                     lifetime: 'timedelta', options: 'OrderedMultiDict[Enum_Option, Option]') -> 'None': ...


@info_final
class FastBindingAcknowledgmentMessage(MH):
    """Data model for MH Fast Binding Acknowledgment (FBack) message type."""

    #: Status. :rfc:`5568#section-6.2.3` defines the FBack status values inline
    #: rather than drawing them from the IANA *Status Codes* registry, so this
    #: field carries the module-local
    #: :class:`~pcapkit.protocols.internet.mh.FastBindingAcknowledgmentStatus`
    #: instead of :class:`~pcapkit.const.mh.status_code.StatusCode`.
    status: 'FastBindingAcknowledgmentStatus'
    #: Key management mobility capability flag.
    key_mngt: 'bool'
    #: Sequence number.
    seq: 'int'
    #: Lifetime.
    lifetime: 'timedelta'
    #: Mobility options.
    options: 'OrderedMultiDict[Enum_Option, Option]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes',
                     status: 'FastBindingAcknowledgmentStatus', key_mngt: 'bool', seq: 'int',
                     lifetime: 'timedelta',
                     options: 'OrderedMultiDict[Enum_Option, Option]') -> 'None': ...


@info_final
class FastNeighborAdvertisementMessage(MH):
    """Data model for MH Fast Neighbor Advertisement (FNA) message type."""

    #: Mobility options.
    options: 'OrderedMultiDict[Enum_Option, Option]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes',
                     options: 'OrderedMultiDict[Enum_Option, Option]') -> 'None': ...


@info_final
class ExperimentalMessage(MH):
    """Data model for MH Experimental Mobility Header message type."""

    #: Experimental message data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes',
                     data: 'bytes') -> 'None': ...


@info_final
class HandoverInitiateMessage(MH):
    """Data model for MH Handover Initiate (HI) message type."""

    #: Sequence number.
    seq: 'int'
    #: Assigned address configuration flag.
    assign: 'bool'
    #: Buffer flag.
    buffer: 'bool'
    #: Proxy flag.
    proxy: 'bool'
    #: Forwarding flag.
    forward: 'bool'
    #: Code.
    code: 'Enum_HandoverInitiateStatus'
    #: Mobility options.
    options: 'OrderedMultiDict[Enum_Option, Option]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes',
                     seq: 'int', assign: 'bool', buffer: 'bool', proxy: 'bool', forward: 'bool',
                     code: 'Enum_HandoverInitiateStatus',
                     options: 'OrderedMultiDict[Enum_Option, Option]') -> 'None': ...


@info_final
class HandoverAcknowledgeMessage(MH):
    """Data model for MH Handover Acknowledge (HAck) message type."""

    #: Sequence number.
    seq: 'int'
    #: Buffer flag.
    buffer: 'bool'
    #: Proxy flag.
    proxy: 'bool'
    #: Forwarding flag.
    forward: 'bool'
    #: Code.
    code: 'Enum_HandoverACKStatus'
    #: Mobility options.
    options: 'OrderedMultiDict[Enum_Option, Option]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes',
                     seq: 'int', buffer: 'bool', proxy: 'bool', forward: 'bool',
                     code: 'Enum_HandoverACKStatus',
                     options: 'OrderedMultiDict[Enum_Option, Option]') -> 'None': ...


@info_final
class HeartbeatMessage(MH):
    """Data model for MH Heartbeat message type."""

    #: Unsolicited flag. Set in an unsolicited Heartbeat response, in which case
    #: :attr:`seq` is ignored and no response is expected.
    unsolicited: 'bool'
    #: Response flag. Unset for a Heartbeat request, set for a response.
    response: 'bool'
    #: Sequence number.
    seq: 'int'
    #: Mobility options.
    options: 'OrderedMultiDict[Enum_Option, Option]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes',
                     unsolicited: 'bool', response: 'bool', seq: 'int',
                     options: 'OrderedMultiDict[Enum_Option, Option]') -> 'None': ...


@info_final
class HomeAgentSwitchMessage(MH):
    """Data model for MH Home Agent Switch message type."""

    #: Alternate home agent addresses. An empty tuple asks the mobile node to
    #: run home agent discovery instead.
    addresses: 'tuple[IPv6Address, ...]'
    #: Mobility options.
    options: 'OrderedMultiDict[Enum_Option, Option]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes',
                     addresses: 'tuple[IPv6Address, ...]',
                     options: 'OrderedMultiDict[Enum_Option, Option]') -> 'None': ...


@info_final
class BindingRevocationMessage(MH):
    """Data model for MH Binding Revocation message type.

    Both forms of the message -- the Binding Revocation Indication and the
    Binding Revocation Acknowledgement -- share this model, since they share a
    Mobility Header type and differ only in :attr:`br_type` and in what
    :attr:`code` means.
    """

    #: Binding revocation type, saying which form of the message this is.
    br_type: 'Enum_BindingRevocation'
    #: Revocation trigger in an indication, acknowledgement status in an
    #: acknowledgement. The two draw from different registries, which is why the
    #: field is not split in two.
    code: 'Enum_RevocationTrigger | Enum_RevocationStatusCode'
    #: Sequence number.
    seq: 'int'
    #: Proxy binding flag.
    proxy: 'bool'
    #: IPv4 home address binding only flag.
    ipv4_hoa: 'bool'
    #: Global revocation flag.
    global_revocation: 'bool'
    #: Mobility options.
    options: 'OrderedMultiDict[Enum_Option, Option]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes',
                     br_type: 'Enum_BindingRevocation',
                     code: 'Enum_RevocationTrigger | Enum_RevocationStatusCode', seq: 'int',
                     proxy: 'bool', ipv4_hoa: 'bool', global_revocation: 'bool',
                     options: 'OrderedMultiDict[Enum_Option, Option]') -> 'None': ...


@info_final
class LocalizedRoutingInitiationMessage(MH):
    """Data model for MH Localized Routing Initiation message type."""

    #: Sequence number.
    seq: 'int'
    #: Lifetime. :rfc:`6705#section-10.1` counts this in seconds rather than in
    #: the units of 4 seconds the binding messages use.
    lifetime: 'timedelta'
    #: Mobility options.
    options: 'OrderedMultiDict[Enum_Option, Option]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes',
                     seq: 'int', lifetime: 'timedelta',
                     options: 'OrderedMultiDict[Enum_Option, Option]') -> 'None': ...


@info_final
class LocalizedRoutingAcknowledgmentMessage(MH):
    """Data model for MH Localized Routing Acknowledgment message type."""

    #: Sequence number.
    seq: 'int'
    #: Unsolicited flag.
    unsolicited: 'bool'
    #: Status. :rfc:`6705#section-10.2` defines its values inline with no IANA
    #: registry behind them, so this field carries the module-local
    #: :class:`~pcapkit.protocols.internet.mh.LocalizedRoutingStatus` rather than
    #: :class:`~pcapkit.const.mh.status_code.StatusCode`.
    status: 'LocalizedRoutingStatus'
    #: Lifetime, in seconds.
    lifetime: 'timedelta'
    #: Mobility options.
    options: 'OrderedMultiDict[Enum_Option, Option]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes',
                     seq: 'int', unsolicited: 'bool', status: 'LocalizedRoutingStatus',
                     lifetime: 'timedelta',
                     options: 'OrderedMultiDict[Enum_Option, Option]') -> 'None': ...


@info_final
class UpdateNotificationMessage(MH):
    """Data model for MH Update Notification message type."""

    #: Sequence number.
    seq: 'int'
    #: Notification reason.
    reason: 'Enum_UpdateNotificationReason'
    #: Acknowledgement requested flag.
    ack: 'bool'
    #: Retransmission flag.
    retransmit: 'bool'
    #: Mobility options.
    options: 'OrderedMultiDict[Enum_Option, Option]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes',
                     seq: 'int', reason: 'Enum_UpdateNotificationReason', ack: 'bool',
                     retransmit: 'bool',
                     options: 'OrderedMultiDict[Enum_Option, Option]') -> 'None': ...


@info_final
class UpdateNotificationAcknowledgementMessage(MH):
    """Data model for MH Update Notification Acknowledgement message type."""

    #: Sequence number.
    seq: 'int'
    #: Status.
    status: 'Enum_UpdateNotificationACKStatus'
    #: Mobility options.
    options: 'OrderedMultiDict[Enum_Option, Option]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes',
                     seq: 'int', status: 'Enum_UpdateNotificationACKStatus',
                     options: 'OrderedMultiDict[Enum_Option, Option]') -> 'None': ...


@info_final
class FlowBindingMessage(MH):
    """Data model for MH Flow Binding message type.

    Both forms of the message -- the Flow Binding Indication and the Flow Binding
    Acknowledgement -- share this model, since they share a Mobility Header type
    and differ only in :attr:`fb_type` and in what :attr:`code` means.
    """

    #: Flow binding type, saying which form of the message this is.
    fb_type: 'Enum_FlowBindingType'
    #: Sequence number.
    seq: 'int'
    #: Indication trigger in an indication, acknowledgement status in an
    #: acknowledgement.
    code: 'Enum_FlowBindingIndicationTrigger | Enum_FlowBindingACKStatus'
    #: Acknowledgement requested flag. Only meaningful in an indication; an
    #: acknowledgement reserves the whole octet this bit is taken from.
    ack: 'bool'
    #: Mobility options.
    options: 'OrderedMultiDict[Enum_Option, Option]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes',
                     fb_type: 'Enum_FlowBindingType', seq: 'int',
                     code: 'Enum_FlowBindingIndicationTrigger | Enum_FlowBindingACKStatus',
                     ack: 'bool',
                     options: 'OrderedMultiDict[Enum_Option, Option]') -> 'None': ...


@info_final
class SubscriptionQueryMessage(MH):
    """Data model for MH Subscription Query message type."""

    #: Sequence number, counted modulo 256.
    seq: 'int'
    #: Mobility options.
    options: 'OrderedMultiDict[Enum_Option, Option]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes',
                     seq: 'int',
                     options: 'OrderedMultiDict[Enum_Option, Option]') -> 'None': ...


@info_final
class SubscriptionResponseMessage(MH):
    """Data model for MH Subscription Response message type."""

    #: Sequence number, echoed from the query.
    seq: 'int'
    #: Multicast information flag, set when the response carries active
    #: multicast subscription options.
    info: 'bool'
    #: Mobility options.
    options: 'OrderedMultiDict[Enum_Option, Option]'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes',
                     seq: 'int', info: 'bool',
                     options: 'OrderedMultiDict[Enum_Option, Option]') -> 'None': ...


# TODO: Implement other message types.


class Option(Data):
    """Data model for MH options."""

    #: Option type.
    type: 'Enum_Option'
    #: Option length (incl. type and length fields).
    length: 'int'


@info_final
class UnassignedOption(Option):
    """Data model for unassigned MH options."""

    #: Option data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', data: 'bytes') -> 'None': ...


@info_final
class PadOption(Option):
    """Data model for Pad option."""

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int') -> 'None': ...


@info_final
class BindingRefreshAdviceOption(Option):
    """Data model for Binding Refresh Advice option."""

    #: Refresh interval.
    interval: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', interval: 'int') -> 'None': ...


@info_final
class AlternateCareofAddressOption(Option):
    """Data model for Alternate Care-of Address option."""

    #: Alternate care-of address.
    address: 'IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', address: 'IPv6Address') -> 'None': ...


@info_final
class NonceIndicesOption(Option):
    """Data model for Nonce Indices option."""

    #: Home nonce index.
    home: 'int'
    #: Care-of nonce index.
    careof: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', home: 'int', careof: 'int') -> 'None': ...


@info_final
class AuthorizationDataOption(Option):
    """Data model for Binding Authorization Data option."""

    #: Authenticator.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', data: 'bytes') -> 'None': ...


@info_final
class MobileNetworkPrefixOption(Option):
    """Data model for Mobile Network Prefix option."""

    #: Mobile Network Prefix.
    prefix: 'IPv6Network'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', prefix: 'IPv6Network') -> 'None': ...


@info_final
class LinkLayerAddressOption(Option):
    """Data model for MH Link-Layer Address (MH-LLA) option."""

    #: Option code.
    code: 'Enum_LLACode'
    #: Link-layer address (LLA).
    lla: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', code: 'Enum_LLACode', lla: 'bytes') -> 'None': ...


@info_final
class MNIDOption(Option):
    """Data model for MN-ID option."""

    #: Subtype.
    subtype: 'Enum_MNIDSubtype'
    #: Identifier.
    identifier: 'bytes | str | IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', subtype: 'Enum_MNIDSubtype', identifier: 'bytes | str | IPv6Address') -> 'None': ...


@info_final
class AuthOption(Option):
    """Data model for Mobility Message Authentication option."""

    #: Subtype.
    subtype: 'Enum_AuthSubtype'
    #: Mobility SPI.
    spi: 'int'
    #: Authentication data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', subtype: 'Enum_AuthSubtype', spi: 'int', data: 'bytes') -> 'None': ...


@info_final
class MesgIDOption(Option):
    """Data model for Mobility Message Replay Protection option."""

    #: Timestamp.
    timestamp: 'dt_type'
    #: NTP timestamp, c.f., :rfc:`1305`.
    ntp_timestamp: 'NTPTimestamp'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', timestamp: 'dt_type', ntp_timestamp: 'NTPTimestamp') -> 'None': ...


@info_final
class CGAParametersRequestOption(Option):
    """Data model for CGA Parameters Request option."""

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int') -> 'None': ...


class CGAExtension(Data):
    """Data model for CGA extension."""

    #: Extension type.
    type: 'Enum_CGAExtension'
    #: Extension length.
    length: 'int'


@info_final
class UnknownExtension(CGAExtension):
    """Data model for unknown CGA extensions."""

    #: Extension data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_CGAExtension', length: 'int', data: 'bytes') -> 'None': ...


@info_final
class ExperimentalExtension(CGAExtension):
    """Data model for experimental CGA extensions.

    :rfc:`4581#section-3` assigns the three experimental extension types but
    gives their extension data no structure at all, so :attr:`data` is opaque by
    specification rather than merely undecoded.
    """

    #: Extension data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_CGAExtension', length: 'int', data: 'bytes') -> 'None': ...


@info_final
class MultiPrefixExtension(CGAExtension):
    """Data model for Multi-Prefix CGA extension."""

    #: P flag. Set if a public key is included in the Public Key field of
    #: the CGA Parameter Data Structure, reset otherwise.
    flag: 'bool'
    #: Prefixes.
    prefixes: 'tuple[int, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_CGAExtension', length: 'int', flag: 'bool', prefixes: 'tuple[int, ...]') -> 'None': ...


@info_final
class CGAParameter(Data):
    """Data model for CGA parameter."""

    #: Modifier.
    modifier: 'Enum_CGAType'
    #: Subnet prefix.
    prefix: 'int'
    #: Collision count.
    collision_count: 'int'
    #: Publick key (ASN.1 encoded).
    public_key: 'bytes'
    #: Extension fields.
    extensions: 'OrderedMultiDict[Enum_CGAExtension, CGAExtension]'

    if TYPE_CHECKING:
        def __init__(self, modifier: 'Enum_CGAType', prefix: 'int', collision_count: 'int', public_key: 'bytes',
                     extensions: 'OrderedMultiDict[Enum_CGAExtension, CGAExtension]') -> 'None': ...


@info_final
class CGAParametersOption(Option):
    """Data model for CGA Parameters option."""

    #: CGA parameters, c.f., :rfc:`3972`.
    parameters: 'tuple[CGAParameter, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', parameters: 'tuple[CGAParameter, ...]') -> 'None': ...


@info_final
class SignatureOption(Option):
    """Data model for MH Signature option."""

    #: Signature.
    signature: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', signature: 'bytes') -> 'None': ...


@info_final
class PermanentHomeKeygenTokenOption(Option):
    """Data model for Permanent Home Keygen Token option."""

    #: Permanent home keygen token.
    token: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', token: 'bytes') -> 'None': ...


@info_final
class CareofTestInitOption(Option):
    """Header schema for MH Care-of Test Init options."""

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int') -> 'None': ...


@info_final
class CareofTestOption(Option):
    """Header schema for MH Care-of Test options."""

    #: Care-of keygen token.
    token: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', token: 'bytes') -> 'None': ...


@info_final
class ExperimentalMobilityOption(Option):
    """Data model for MH Experimental Mobility option."""

    #: Experimental data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', data: 'bytes') -> 'None': ...


@info_final
class BADFOption(Option):
    """Data model for MH Binding Authorization Data for FMIPv6 (BADF) option."""

    #: Security parameter index.
    spi: 'int'
    #: Authenticator.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', spi: 'int', data: 'bytes') -> 'None': ...


@info_final
class IPv6AddressPrefixOption(Option):
    """Data model for MH Mobility Header IPv6 Address/Prefix option."""

    #: Option code, c.f., :rfc:`5568#section-6.4.2`. The codes are defined inline
    #: by the RFC with no IANA registry behind them, so this field carries the
    #: module-local
    #: :class:`~pcapkit.protocols.internet.mh.IPv6AddressPrefixCode`.
    code: 'IPv6AddressPrefixCode'
    #: Prefix length.
    prefix_length: 'int'
    #: IPv6 address/prefix. Kept separate from :attr:`prefix_length` since option
    #: codes ``1`` through ``3`` carry a full address whose host bits are
    #: significant, so the pair cannot always be fused into a network.
    address: 'IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', code: 'IPv6AddressPrefixCode',
                     prefix_length: 'int', address: 'IPv6Address') -> 'None': ...


@info_final
class HomeNetworkPrefixOption(Option):
    """Data model for MH Home Network Prefix option."""

    #: Prefix length.
    prefix_length: 'int'
    #: Home network prefix. Kept apart from :attr:`prefix_length` rather than
    #: fused into an :class:`~ipaddress.IPv6Network`, so that a prefix whose bits
    #: past :attr:`prefix_length` are non-zero survives a round trip -- masking
    #: them off, which is what building a network does, would not reproduce the
    #: octets that were parsed. Same reasoning as
    #: :class:`IPv6AddressPrefixOption`.
    prefix: 'IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', prefix_length: 'int',
                     prefix: 'IPv6Address') -> 'None': ...


@info_final
class HandoffIndicatorOption(Option):
    """Data model for MH Handoff Indicator option."""

    #: Handoff indicator.
    hi: 'Enum_HandoffType'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', hi: 'Enum_HandoffType') -> 'None': ...


@info_final
class AccessTechnologyTypeOption(Option):
    """Data model for MH Access Technology Type option."""

    #: Access technology type.
    att: 'Enum_AccessType'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', att: 'Enum_AccessType') -> 'None': ...


@info_final
class MNLLIdentifierOption(Option):
    """Data model for MH Mobile Node Link-layer Identifier option."""

    #: Link-layer identifier.
    lli: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', lli: 'bytes') -> 'None': ...


@info_final
class LinkLocalAddressOption(Option):
    """Data model for MH Link-local Address option."""

    #: Link-local address.
    address: 'IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', address: 'IPv6Address') -> 'None': ...


@info_final
class TimestampOption(Option):
    """Data model for MH Timestamp option."""

    #: Timestamp.
    timestamp: 'dt_type'
    #: Timestamp in the fixed-point format of :rfc:`5213#section-8.8`, kept
    #: alongside :attr:`timestamp` so that the 1/65536-second resolution of the
    #: wire format survives a round trip.
    pmip_timestamp: 'PMIPv6Timestamp'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', timestamp: 'dt_type',
                     pmip_timestamp: 'PMIPv6Timestamp') -> 'None': ...


@info_final
class RestartCounterOption(Option):
    """Data model for MH Restart Counter option."""

    #: Restart counter.
    counter: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', counter: 'int') -> 'None': ...


@info_final
class DNSUpdateOption(Option):
    """Data model for MH DNS-UPDATE-TYPE option."""

    #: Status. :rfc:`5026#section-8.1` draws this from a registry of its own
    #: rather than from the general mobility status codes.
    status: 'Enum_DNSStatusCode'
    #: Remove flag. Set when the mobile node asks the home agent to remove the
    #: DNS entry rather than to create or update it.
    remove: 'bool'
    #: Mobile node identity, in FQDN form. Kept as :obj:`bytes` because the RFC
    #: does not say which of the two FQDN encodings is meant.
    identity: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', status: 'Enum_DNSStatusCode',
                     remove: 'bool', identity: 'bytes') -> 'None': ...


@info_final
class VendorSpecificOption(Option):
    """Data model for MH Vendor Specific mobility option."""

    #: Vendor ID, an SMI Network Management Private Enterprise Number.
    vendor: 'int'
    #: Vendor-administered sub-type.
    subtype: 'int'
    #: Vendor-specific data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', vendor: 'int', subtype: 'int',
                     data: 'bytes') -> 'None': ...


@info_final
class ServiceSelectionOption(Option):
    """Data model for MH Service Selection mobility option."""

    #: Service identifier.
    identifier: 'str'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', identifier: 'str') -> 'None': ...


@info_final
class IPv4HomeAddressOption(Option):
    """Data model for MH IPv4 Home Address option."""

    #: Prefix length. ``32`` means the option carries a single address rather
    #: than a prefix; ``0`` is invalid.
    prefix_length: 'int'
    #: IPv4 home address. ``0.0.0.0`` asks the home agent to allocate one
    #: dynamically. Kept apart from :attr:`prefix_length` so that the host bits,
    #: which are significant here, survive a round trip.
    address: 'IPv4Address'
    #: Mobile network prefix request flag.
    request_prefix: 'bool'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', prefix_length: 'int',
                     address: 'IPv4Address', request_prefix: 'bool') -> 'None': ...


@info_final
class IPv4AddressAcknowledgementOption(Option):
    """Data model for MH IPv4 Address Acknowledgement option."""

    #: Status. :rfc:`5555#section-3.2.1` draws this from the DSMIPv6 IPv4 home
    #: address registry, which is **not** the one the IPv4 Home Address Reply
    #: option of :rfc:`5844` uses -- that one lacks value 133.
    status: 'Enum_DSMIPv6HomeAddress'
    #: Allocated prefix length. Meaningful only on success, and required to be
    #: zero on failure.
    prefix_length: 'int'
    #: Assigned IPv4 home address.
    address: 'IPv4Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int',
                     status: 'Enum_DSMIPv6HomeAddress', prefix_length: 'int',
                     address: 'IPv4Address') -> 'None': ...


@info_final
class NATDetectionOption(Option):
    """Data model for MH NAT Detection option."""

    #: Force UDP encapsulation flag.
    force: 'bool'
    #: Suggested NAT binding refresh interval, in seconds. ``0`` means the value
    #: is to be ignored, and all ones that no keep-alives are needed.
    refresh: 'timedelta'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', force: 'bool',
                     refresh: 'timedelta') -> 'None': ...


@info_final
class IPv4CareofAddressOption(Option):
    """Data model for MH IPv4 Care-of Address option."""

    #: IPv4 care-of address.
    address: 'IPv4Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', address: 'IPv4Address') -> 'None': ...


@info_final
class GREKeyOption(Option):
    """Data model for MH GRE Key option."""

    #: GRE key identifier, or :obj:`None` when the option carries none -- which
    #: :rfc:`5845#section-6.1` signals by an option length of 2 rather than 6.
    key: 'Optional[int]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int',
                     key: 'Optional[int]') -> 'None': ...


@info_final
class BindingIdentifierOption(Option):
    """Data model for MH Binding Identifier (BID) option."""

    #: Binding identifier.
    bid: 'int'
    #: Status, overriding the message status for this binding alone.
    status: 'Enum_StatusCode'
    #: Simultaneous home and foreign binding flag.
    simultaneous: 'bool'
    #: Binding priority. :rfc:`6089#section-4.1` renames the bits :rfc:`5648`
    #: reserved; ``0`` means the sender predates :rfc:`6089`.
    bid_pri: 'int'
    #: Care-of address, or :obj:`None` when the option carries none.
    address: 'Optional[IPv4Address | IPv6Address]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', bid: 'int',
                     status: 'Enum_StatusCode', simultaneous: 'bool', bid_pri: 'int',
                     address: 'Optional[IPv4Address | IPv6Address]') -> 'None': ...


@info_final
class IPv4HomeAddressRequestOption(Option):
    """Data model for MH IPv4 Home Address Request option."""

    #: Prefix length of the requested home network.
    prefix_length: 'int'
    #: Requested IPv4 home address. ``0.0.0.0`` asks the local mobility anchor to
    #: allocate one.
    address: 'IPv4Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', prefix_length: 'int',
                     address: 'IPv4Address') -> 'None': ...


@info_final
class IPv4HomeAddressReplyOption(Option):
    """Data model for MH IPv4 Home Address Reply option."""

    #: Status. :rfc:`5844#section-3.3.2` draws this from a registry of its own,
    #: which unlike the DSMIPv6 one of :rfc:`5555` has no value 133.
    status: 'Enum_HomeAddressReply'
    #: Prefix length of the assigned home network.
    prefix_length: 'int'
    #: Assigned IPv4 home address.
    address: 'IPv4Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', status: 'Enum_HomeAddressReply',
                     prefix_length: 'int', address: 'IPv4Address') -> 'None': ...


@info_final
class IPv4DefaultRouterAddressOption(Option):
    """Data model for MH IPv4 Default-Router Address option."""

    #: IPv4 default-router address.
    address: 'IPv4Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', address: 'IPv4Address') -> 'None': ...


@info_final
class IPv4DHCPSupportModeOption(Option):
    """Data model for MH IPv4 DHCP Support Mode option."""

    #: DHCP support mode. Unset means the mobile access gateway acts as a DHCP
    #: relay, set that it acts as a DHCP server.
    mode: 'Enum_DHCPSupportMode'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int',
                     mode: 'Enum_DHCPSupportMode') -> 'None': ...


@info_final
class ContextRequest(Data):
    """Data model for one entry of an MH Context Request option."""

    #: Requested mobility option type.
    type: 'Enum_Option'
    #: Length of :attr:`value`.
    length: 'int'
    #: Extra data identifying the requested context.
    value: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', value: 'bytes') -> 'None': ...


@info_final
class ContextRequestOption(Option):
    """Data model for MH Context Request option."""

    #: Requested contexts.
    requests: 'tuple[ContextRequest, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int',
                     requests: 'tuple[ContextRequest, ...]') -> 'None': ...


@info_final
class LMAAddressOption(Option):
    """Data model for MH Local Mobility Anchor Address option."""

    #: Option code, c.f., :rfc:`5949#section-6.2.2`. The codes are defined inline
    #: by the RFC with no IANA registry behind them, so this field carries the
    #: module-local :class:`~pcapkit.protocols.internet.mh.LMAAddressCode`.
    code: 'LMAAddressCode'
    #: Local mobility anchor address.
    address: 'IPv4Address | IPv6Address | bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', code: 'LMAAddressCode',
                     address: 'IPv4Address | IPv6Address | bytes') -> 'None': ...


@info_final
class MNLLAIIDOption(Option):
    """Data model for MH Mobile Node Link-local Address Interface Identifier option."""

    #: Interface identifier.
    iid: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', iid: 'bytes') -> 'None': ...


@info_final
class TransientBindingOption(Option):
    """Data model for MH Transient Binding option."""

    #: Late path switch flag.
    late: 'bool'
    #: Maximum lifetime of the transient state. Counted on the wire in units of
    #: 100 milliseconds.
    lifetime: 'timedelta'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', late: 'bool',
                     lifetime: 'timedelta') -> 'None': ...


@info_final
class FlowSummaryOption(Option):
    """Data model for MH Flow Summary mobility option."""

    #: Flow identifiers being refreshed.
    fid: 'tuple[int, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int',
                     fid: 'tuple[int, ...]') -> 'None': ...


class FlowIdentificationSuboption(Data):
    """Data model for MH Flow Identification sub-options."""

    #: Sub-option type.
    type: 'Enum_FlowIDSuboption'
    #: Sub-option length (incl. type and length fields).
    length: 'int'


@info_final
class UnassignedFlowIdentificationSuboption(FlowIdentificationSuboption):
    """Data model for unassigned MH Flow Identification sub-options."""

    #: Sub-option data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_FlowIDSuboption', length: 'int',
                     data: 'bytes') -> 'None': ...


@info_final
class PadFlowIdentificationSuboption(FlowIdentificationSuboption):
    """Data model for MH Flow Identification padding sub-options."""

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_FlowIDSuboption', length: 'int') -> 'None': ...


@info_final
class BIDReferenceSuboption(FlowIdentificationSuboption):
    """Data model for MH Flow Identification BID Reference sub-option."""

    #: Referenced binding identifiers.
    bid: 'tuple[int, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_FlowIDSuboption', length: 'int',
                     bid: 'tuple[int, ...]') -> 'None': ...


@info_final
class TrafficSelectorSuboption(FlowIdentificationSuboption):
    """Data model for MH Flow Identification Traffic Selector sub-option."""

    #: Traffic selector format.
    ts_format: 'Enum_TrafficSelector'
    #: Traffic selector. Its interior is :rfc:`6088` territory and belongs to the
    #: separate traffic selector format registry, so it is kept opaque.
    selector: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_FlowIDSuboption', length: 'int',
                     ts_format: 'Enum_TrafficSelector', selector: 'bytes') -> 'None': ...


@info_final
class FlowBindingActionSuboption(FlowIdentificationSuboption):
    """Data model for MH Flow Identification Flow Binding Action sub-option."""

    #: Flow binding action.
    action: 'Enum_FlowBindingAction'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_FlowIDSuboption', length: 'int',
                     action: 'Enum_FlowBindingAction') -> 'None': ...


@info_final
class TargetCareofAddressSuboption(FlowIdentificationSuboption):
    """Data model for MH Flow Identification Target Care-of Address sub-option."""

    #: Target care-of address.
    address: 'IPv4Address | IPv6Address | bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_FlowIDSuboption', length: 'int',
                     address: 'IPv4Address | IPv6Address | bytes') -> 'None': ...


@info_final
class FlowIdentificationOption(Option):
    """Data model for MH Flow Identification mobility option."""

    #: Flow identifier.
    fid: 'int'
    #: Flow priority.
    fid_pri: 'int'
    #: Status.
    status: 'Enum_FlowIDStatus'
    #: Sub-options.
    suboptions: 'OrderedMultiDict[Enum_FlowIDSuboption, FlowIdentificationSuboption]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', fid: 'int', fid_pri: 'int',
                     status: 'Enum_FlowIDStatus',
                     suboptions: 'OrderedMultiDict[Enum_FlowIDSuboption, FlowIdentificationSuboption]') -> 'None': ...


@info_final
class RedirectCapabilityOption(Option):
    """Data model for MH Redirect-Capability mobility option."""

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int') -> 'None': ...


@info_final
class RedirectOption(Option):
    """Data model for MH Redirect mobility option."""

    #: IPv6 address of the redirected-to local mobility anchor, if carried.
    ipv6: 'Optional[IPv6Address]'
    #: IPv4 address of the redirected-to local mobility anchor, if carried.
    ipv4: 'Optional[IPv4Address]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', ipv6: 'Optional[IPv6Address]',
                     ipv4: 'Optional[IPv4Address]') -> 'None': ...


@info_final
class LoadInformationOption(Option):
    """Data model for MH Load Information mobility option."""

    #: Priority; a lower value is a higher priority.
    priority: 'int'
    #: Mobility sessions currently in use.
    sessions_in_use: 'int'
    #: Maximum number of mobility sessions accepted.
    max_sessions: 'int'
    #: Used capacity, in kilobytes per second.
    used_capacity: 'int'
    #: Maximum capacity, in kilobytes per second.
    max_capacity: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', priority: 'int',
                     sessions_in_use: 'int', max_sessions: 'int', used_capacity: 'int',
                     max_capacity: 'int') -> 'None': ...


@info_final
class AlternateIPv4CareofAddressOption(Option):
    """Data model for MH Alternate IPv4 Care-of Address option."""

    #: Alternate IPv4 care-of address.
    address: 'IPv4Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', address: 'IPv4Address') -> 'None': ...


@info_final
class MNGroupIdentifierOption(Option):
    """Data model for MH Mobile Node Group Identifier option."""

    #: Sub-type.
    subtype: 'Enum_MNGroupID'
    #: Mobile node group identifier. ``1`` is the default "all sessions" group.
    group_id: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', subtype: 'Enum_MNGroupID',
                     group_id: 'int') -> 'None': ...


@info_final
class MAGIPv6AddressOption(Option):
    """Data model for MH MAG IPv6 Address option."""

    #: Address length, in bits; always 128.
    address_length: 'int'
    #: MAG IPv6 address.
    address: 'IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', address_length: 'int',
                     address: 'IPv6Address') -> 'None': ...


class ANISuboption(Data):
    """Data model for MH Access Network Identifier sub-options."""

    #: Sub-option type.
    type: 'Enum_ANISuboption'
    #: Sub-option length (incl. type and length fields).
    length: 'int'


@info_final
class UnassignedANISuboption(ANISuboption):
    """Data model for unassigned MH Access Network Identifier sub-options."""

    #: Sub-option data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_ANISuboption', length: 'int', data: 'bytes') -> 'None': ...


@info_final
class ANINetworkIdentifierSuboption(ANISuboption):
    """Data model for MH Network-Identifier ANI sub-option."""

    #: UTF-8 encoding flag for :attr:`net_name`.
    utf8: 'bool'
    #: Network name, e.g. an SSID or a PLMN identifier.
    net_name: 'bytes'
    #: Access-point name.
    ap_name: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_ANISuboption', length: 'int', utf8: 'bool',
                     net_name: 'bytes', ap_name: 'bytes') -> 'None': ...


@info_final
class ANIGeoLocationSuboption(ANISuboption):
    """Data model for MH Geo-Location ANI sub-option."""

    #: Latitude, in degrees.
    latitude: 'float'
    #: Longitude, in degrees.
    longitude: 'float'
    #: Latitude as the signed 24-bit fixed-point integer on the wire, kept so
    #: that the exact value survives a round trip.
    raw_latitude: 'int'
    #: Longitude as the signed 24-bit fixed-point integer on the wire.
    raw_longitude: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_ANISuboption', length: 'int', latitude: 'float',
                     longitude: 'float', raw_latitude: 'int',
                     raw_longitude: 'int') -> 'None': ...


@info_final
class ANIOperatorIdentifierSuboption(ANISuboption):
    """Data model for MH Operator-Identifier ANI sub-option."""

    #: Operator identifier type.
    op_id_type: 'Enum_OperatorID'
    #: Operator identifier.
    identifier: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_ANISuboption', length: 'int',
                     op_id_type: 'Enum_OperatorID', identifier: 'bytes') -> 'None': ...


@info_final
class ANICivicLocationSuboption(ANISuboption):
    """Data model for MH Civic-Location ANI sub-option."""

    #: Encoding format; only ``0``, the binary encoding of
    #: :rfc:`4776#section-3.1`, is defined.
    format: 'int'
    #: Civic location.
    location: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_ANISuboption', length: 'int', format: 'int',
                     location: 'bytes') -> 'None': ...


@info_final
class ANIMAGGroupIdentifierSuboption(ANISuboption):
    """Data model for MH MAG-Group-Identifier ANI sub-option."""

    #: MAG group identifier.
    group_id: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_ANISuboption', length: 'int',
                     group_id: 'int') -> 'None': ...


@info_final
class ANIUpdateTimerSuboption(ANISuboption):
    """Data model for MH ANI Update-Timer sub-option."""

    #: Update timer. Counted on the wire in units of 4 seconds; zero asks for an
    #: immediate update.
    timer: 'timedelta'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_ANISuboption', length: 'int',
                     timer: 'timedelta') -> 'None': ...


@info_final
class AccessNetworkIdentifierOption(Option):
    """Data model for MH Access Network Identifier option."""

    #: Sub-options.
    suboptions: 'OrderedMultiDict[Enum_ANISuboption, ANISuboption]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int',
                     suboptions: 'OrderedMultiDict[Enum_ANISuboption, ANISuboption]') -> 'None': ...


@info_final
class IPv4TrafficOffloadSelectorOption(Option):
    """Data model for MH IPv4 Traffic Offload Selector option."""

    #: Offload mode flag. Unset offloads the flows matching the selector; set
    #: offloads everything except them.
    mode: 'bool'
    #: Traffic selector sub-options.
    selector: 'OrderedMultiDict[Enum_FlowIDSuboption, FlowIdentificationSuboption]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', mode: 'bool',
                     selector: 'OrderedMultiDict[Enum_FlowIDSuboption, FlowIdentificationSuboption]') -> 'None': ...


@info_final
class DynamicIPMulticastSelectorOption(Option):
    """Data model for MH Dynamic IP Multicast Selector option."""

    #: MLD or IGMP protocol number identifying the record format.
    protocol: 'int'
    #: Selector mode flag. Set routes the group locally, unset via the home
    #: network.
    mode: 'bool'
    #: Number of multicast address records carried in :attr:`data`.
    records: 'int'
    #: Multicast address records. These are MLD or IGMP structures belonging to
    #: those protocols rather than to the Mobility Header, so they are kept
    #: opaque.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', protocol: 'int', mode: 'bool',
                     records: 'int', data: 'bytes') -> 'None': ...


@info_final
class DelegatedMNPOption(Option):
    """Data model for MH Delegated Mobile Network Prefix option."""

    #: IPv4 prefix flag, saying which family :attr:`prefix` is in.
    ipv4: 'bool'
    #: Prefix length.
    prefix_length: 'int'
    #: Delegated mobile network prefix, IPv4 or IPv6 as :attr:`ipv4` says.
    prefix: 'IPv4Address | IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', ipv4: 'bool',
                     prefix_length: 'int',
                     prefix: 'IPv4Address | IPv6Address') -> 'None': ...


@info_final
class ActiveMulticastSubscriptionIPv4Option(Option):
    """Data model for MH Active Multicast Subscription IPv4 option."""

    #: IGMP message type identifying the context format.
    igmp_type: 'int'
    #: Multicast membership context, an IGMP structure kept opaque.
    context: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', igmp_type: 'int',
                     context: 'bytes') -> 'None': ...


@info_final
class ActiveMulticastSubscriptionIPv6Option(Option):
    """Data model for MH Active Multicast Subscription IPv6 option."""

    #: MLD message type identifying the context format.
    mld_type: 'int'
    #: Multicast membership context, an MLD structure kept opaque.
    context: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', mld_type: 'int',
                     context: 'bytes') -> 'None': ...


class QoSAttribute(Data):
    """Data model for MH Quality-of-Service attributes."""

    #: Attribute type.
    type: 'Enum_QoSAttribute'
    #: Attribute length (incl. type and length fields).
    length: 'int'


@info_final
class UnassignedQoSAttribute(QoSAttribute):
    """Data model for unassigned MH Quality-of-Service attributes."""

    #: Attribute value.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_QoSAttribute', length: 'int', data: 'bytes') -> 'None': ...


@info_final
class BitRateAttribute(QoSAttribute):
    """Data model for the MH Quality-of-Service attributes carrying a bare bit rate."""

    #: Bit rate, in **bits** per second.
    rate: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_QoSAttribute', length: 'int', rate: 'int') -> 'None': ...


@info_final
class PerSessionBitRateAttribute(QoSAttribute):
    """Data model for the MH per-session aggregate maximum bit-rate attributes."""

    #: Service-identifier aggregation flag.
    service: 'bool'
    #: Guaranteed-bit-rate exclusion flag.
    exclude: 'bool'
    #: Bit rate, in **bits** per second.
    rate: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_QoSAttribute', length: 'int', service: 'bool',
                     exclude: 'bool', rate: 'int') -> 'None': ...


@info_final
class AllocationRetentionPriorityAttribute(QoSAttribute):
    """Data model for the MH Allocation-Retention-Priority attribute."""

    #: Priority level, 1 through 15, where 1 is the highest.
    priority_level: 'int'
    #: Pre-emption capability; ``0`` enabled, ``1`` disabled.
    preemption_capability: 'int'
    #: Pre-emption vulnerability; ``0`` enabled, ``1`` disabled.
    preemption_vulnerability: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_QoSAttribute', length: 'int', priority_level: 'int',
                     preemption_capability: 'int',
                     preemption_vulnerability: 'int') -> 'None': ...


@info_final
class QoSTrafficSelectorAttribute(QoSAttribute):
    """Data model for the MH QoS-Traffic-Selector attribute."""

    #: Traffic selector format.
    ts_format: 'Enum_TrafficSelector'
    #: Traffic selector, kept opaque as for
    #: :class:`TrafficSelectorSuboption`.
    selector: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_QoSAttribute', length: 'int',
                     ts_format: 'Enum_TrafficSelector', selector: 'bytes') -> 'None': ...


@info_final
class QoSVendorSpecificAttribute(QoSAttribute):
    """Data model for the MH QoS-Vendor-Specific attribute."""

    #: Vendor ID, an SMI Network Management Private Enterprise Number.
    vendor: 'int'
    #: Vendor-administered sub-type.
    subtype: 'int'
    #: Vendor-specific data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_QoSAttribute', length: 'int', vendor: 'int',
                     subtype: 'int', data: 'bytes') -> 'None': ...


@info_final
class QualityOfServiceOption(Option):
    """Data model for MH Quality-of-Service option."""

    #: Service request identifier.
    sr_id: 'int'
    #: Differentiated services code point, the significant 6 bits of the traffic
    #: class octet.
    dscp: 'int'
    #: Operational code: ``0`` response, ``1`` allocate, ``2`` de-allocate,
    #: ``3`` modify, ``4`` query, ``5`` negotiate.
    oc: 'int'
    #: Quality-of-service attributes.
    attributes: 'OrderedMultiDict[Enum_QoSAttribute, QoSAttribute]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', sr_id: 'int', dscp: 'int',
                     oc: 'int',
                     attributes: 'OrderedMultiDict[Enum_QoSAttribute, QoSAttribute]') -> 'None': ...


@info_final
class LMAUserPlaneAddressOption(Option):
    """Data model for MH LMA User-Plane Address option."""

    #: LMA user-plane address, or :obj:`None` when the option carries none --
    #: which is how a mobile access gateway asks for a transport without naming
    #: an address.
    address: 'Optional[IPv4Address | IPv6Address]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int',
                     address: 'Optional[IPv4Address | IPv6Address]') -> 'None': ...


@info_final
class MulticastMobilityOption(Option):
    """Data model for MH Multicast Mobility option."""

    #: Option code: ``1`` IGMPv3, ``2`` MLDv2, ``3`` IGMPv3 in IGMPv2
    #: compatibility mode, ``4`` MLDv2 in MLDv1 compatibility mode.
    code: 'int'
    #: MLD or IGMP report payload, kept opaque.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', code: 'int',
                     data: 'bytes') -> 'None': ...


@info_final
class MulticastAcknowledgementOption(Option):
    """Data model for MH Multicast Acknowledgement option."""

    #: Option code; always ``0``.
    code: 'int'
    #: Status: ``1`` report payload type unsupported, ``2`` requested group
    #: service unsupported, ``3`` administratively prohibited.
    status: 'int'
    #: MLD or IGMP unsupported report payload, kept opaque.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', code: 'int', status: 'int',
                     data: 'bytes') -> 'None': ...


class LMAControlledMAGSuboption(Data):
    """Data model for MH LMA-Controlled MAG Parameters sub-options."""

    #: Sub-option type.
    type: 'Enum_LMAControlledMAGSuboption'
    #: Sub-option length (incl. type and length fields).
    length: 'int'


@info_final
class UnassignedLMAControlledMAGSuboption(LMAControlledMAGSuboption):
    """Data model for unassigned MH LMA-Controlled MAG Parameters sub-options."""

    #: Sub-option data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_LMAControlledMAGSuboption', length: 'int',
                     data: 'bytes') -> 'None': ...


@info_final
class BindingReregistrationControlSuboption(LMAControlledMAGSuboption):
    """Data model for MH Binding Re-registration Control sub-option."""

    #: Time before binding expiry at which to re-register. Counted on the wire in
    #: units of 4 seconds.
    start_time: 'timedelta'
    #: Minimum delay before the first retransmission.
    initial_retransmission: 'timedelta'
    #: Maximum delay before the last retransmission.
    max_retransmission: 'timedelta'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_LMAControlledMAGSuboption', length: 'int',
                     start_time: 'timedelta', initial_retransmission: 'timedelta',
                     max_retransmission: 'timedelta') -> 'None': ...


@info_final
class HeartbeatControlSuboption(LMAControlledMAGSuboption):
    """Data model for MH Heartbeat Control sub-option."""

    #: Delay after a successful heartbeat exchange.
    interval: 'timedelta'
    #: Minimum delay before a heartbeat retransmission.
    retransmission_delay: 'timedelta'
    #: Maximum number of heartbeat retransmissions.
    max_retransmissions: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_LMAControlledMAGSuboption', length: 'int',
                     interval: 'timedelta', retransmission_delay: 'timedelta',
                     max_retransmissions: 'int') -> 'None': ...


@info_final
class LMAControlledMAGParametersOption(Option):
    """Data model for MH LMA-Controlled MAG Parameters option."""

    #: Sub-options.
    suboptions: 'OrderedMultiDict[Enum_LMAControlledMAGSuboption, LMAControlledMAGSuboption]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int',
                     suboptions: 'OrderedMultiDict[Enum_LMAControlledMAGSuboption, LMAControlledMAGSuboption]') -> 'None': ...


@info_final
class MAGMultipathBindingOption(Option):
    """Data model for MH MAG Multipath Binding option."""

    #: Interface access-technology type.
    att: 'Enum_AccessType'
    #: Interface label.
    label: 'int'
    #: Binding identifier; ``0`` and ``255`` are reserved.
    bid: 'int'
    #: Bulk re-registration flag.
    bulk: 'bool'
    #: Registration overwrite flag.
    overwrite: 'bool'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', att: 'Enum_AccessType',
                     label: 'int', bid: 'int', bulk: 'bool',
                     overwrite: 'bool') -> 'None': ...


@info_final
class MAGIdentifierOption(Option):
    """Data model for MH MAG Identifier option."""

    #: Sub-type, drawn from the mobile node identifier subtype registry.
    subtype: 'Enum_MNIDSubtype'
    #: Identifier, in the form named by :attr:`subtype`.
    identifier: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', subtype: 'Enum_MNIDSubtype',
                     identifier: 'bytes') -> 'None': ...


@info_final
class AnchoredPrefixOption(Option):
    """Data model for MH Anchored Prefix option."""

    #: Prefix length.
    prefix_length: 'int'
    #: Anchored prefix. Kept apart from :attr:`prefix_length` so that the bits
    #: past it, which :rfc:`8885#section-4.3` tells a receiver to ignore rather
    #: than requires a sender to zero, survive a round trip.
    prefix: 'IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', prefix_length: 'int',
                     prefix: 'IPv6Address') -> 'None': ...


@info_final
class LocalPrefixOption(Option):
    """Data model for MH Local Prefix option."""

    #: Prefix length.
    prefix_length: 'int'
    #: Local prefix.
    prefix: 'IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', prefix_length: 'int',
                     prefix: 'IPv6Address') -> 'None': ...


@info_final
class PreviousMAAROption(Option):
    """Data model for MH Previous MAAR option."""

    #: Prefix length of :attr:`prefix`.
    prefix_length: 'int'
    #: Previous MAAR's global address. A full address rather than a prefix, so
    #: :attr:`prefix_length` does not apply to it.
    maar: 'IPv6Address'
    #: Mobile node's home network prefix.
    prefix: 'IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', prefix_length: 'int',
                     maar: 'IPv6Address', prefix: 'IPv6Address') -> 'None': ...


@info_final
class ServingMAAROption(Option):
    """Data model for MH Serving MAAR option."""

    #: Serving MAAR's global address.
    address: 'IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', address: 'IPv6Address') -> 'None': ...


@info_final
class DLIFLinkLocalAddressOption(Option):
    """Data model for MH DLIF Link-Local Address option."""

    #: Distributed logical interface's link-local address.
    address: 'IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', address: 'IPv6Address') -> 'None': ...


@info_final
class DLIFLinkLayerAddressOption(Option):
    """Data model for MH DLIF Link-Layer Address option."""

    #: Distributed logical interface's link-layer address.
    lla: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Option', length: 'int', lla: 'bytes') -> 'None': ...


# TODO: Implement other options.
