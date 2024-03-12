# -*- coding: utf-8 -*-
"""data model for MH protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from datetime import datetime as dt_type
    from datetime import timedelta
    from ipaddress import IPv6Address, IPv6Network

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
    from pcapkit.protocols.internet.mh import NTPTimestamp

__all__ = [
    'MH',
    'UnknownMessage', 'BindingRefreshRequestMessage', 'HomeTestInitMessage', 'CareofTestInitMessage',
    'HomeTestMessage', 'CareofTestMessage', 'BindingUpdateMessage', 'BindingAcknowledgementMessage',
    'BindingErrorMessage',

    'Option',
    'UnassignedOption', 'PadOption', 'BindingRefreshAdviceOption', 'AlternateCareofAddressOption',
    'NonceIndicesOption', 'AuthorizationDataOption', 'MobileNetworkPrefixOption',
    'LinkLayerAddressOption', 'MNIDOption', 'AuthOption', 'MesgIDOption', 'CGAParametersRequestOption',
    'CGAParametersOption', 'SignatureOption', 'PermanentHomeKeygenTokenOption', 'CareofTestInitOption',
    'CareofTestOption',

    'CGAParameter',

    'CGAExtension',
    'UnknownExtension', 'MultiPrefixExtension',

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


# TODO: Implement other options.
