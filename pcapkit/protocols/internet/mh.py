# -*- coding: utf-8 -*-
# pylint: disable=fixme
"""mobility header

:mod:`pcapkit.protocols.internet.mh` contains
:class:`~pcapkit.protocols.internet.mh.MH` only,
which implements extractor for Mobility Header
(MH) [*]_, whose structure is described as below:

======= ========= ================== ===============================
Octets      Bits        Name                    Description
======= ========= ================== ===============================
  0           0   ``mh.next``                 Next Header
  1           8   ``mh.length``               Header Length
  2          16   ``mh.type``                 Mobility Header Type
  3          24                               Reserved
  4          32   ``mh.chksum``               Checksum
  6          48   ``mh.data``                 Message Data
======= ========= ================== ===============================

.. [*] https://en.wikipedia.org/wiki/Mobile_IP#Changes_in_IPv6_for_Mobile_IPv6

"""
import collections
import datetime
import ipaddress
import math
from typing import TYPE_CHECKING, cast, overload

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
from pcapkit.protocols.data.internet.mh import MH as Data_MH
from pcapkit.protocols.data.internet.mh import \
    AlternateCareofAddressOption as Data_AlternateCareofAddressOption
from pcapkit.protocols.data.internet.mh import AuthOption as Data_AuthOption
from pcapkit.protocols.data.internet.mh import \
    AuthorizationDataOption as Data_AuthorizationDataOption
from pcapkit.protocols.data.internet.mh import \
    BindingAcknowledgementMessage as Data_BindingAcknowledgementMessage
from pcapkit.protocols.data.internet.mh import BindingErrorMessage as Data_BindingErrorMessage
from pcapkit.protocols.data.internet.mh import \
    BindingRefreshAdviceOption as Data_BindingRefreshAdviceOption
from pcapkit.protocols.data.internet.mh import \
    BindingRefreshRequestMessage as Data_BindingRefreshRequestMessage
from pcapkit.protocols.data.internet.mh import BindingUpdateMessage as Data_BindingUpdateMessage
from pcapkit.protocols.data.internet.mh import CareofTestInitMessage as Data_CareofTestInitMessage
from pcapkit.protocols.data.internet.mh import CareofTestInitOption as Data_CareofTestInitOption
from pcapkit.protocols.data.internet.mh import CareofTestMessage as Data_CareofTestMessage
from pcapkit.protocols.data.internet.mh import CareofTestOption as Data_CareofTestOption
from pcapkit.protocols.data.internet.mh import CGAExtension as Data_CGAExtension
from pcapkit.protocols.data.internet.mh import CGAParameter as Data_CGAParameter
from pcapkit.protocols.data.internet.mh import CGAParametersOption as Data_CGAParametersOption
from pcapkit.protocols.data.internet.mh import \
    CGAParametersRequestOption as Data_CGAParametersRequestOption
from pcapkit.protocols.data.internet.mh import HomeTestInitMessage as Data_HomeTestInitMessage
from pcapkit.protocols.data.internet.mh import HomeTestMessage as Data_HomeTestMessage
from pcapkit.protocols.data.internet.mh import LinkLayerAddressOption as Data_LinkLayerAddressOption
from pcapkit.protocols.data.internet.mh import MesgIDOption as Data_MesgIDOption
from pcapkit.protocols.data.internet.mh import MNIDOption as Data_MNIDOption
from pcapkit.protocols.data.internet.mh import \
    MobileNetworkPrefixOption as Data_MobileNetworkPrefixOption
from pcapkit.protocols.data.internet.mh import MultiPrefixExtension as Data_MultiPrefixExtension
from pcapkit.protocols.data.internet.mh import NonceIndicesOption as Data_NonceIndicesOption
from pcapkit.protocols.data.internet.mh import PadOption as Data_PadOption
from pcapkit.protocols.data.internet.mh import \
    PermanentHomeKeygenTokenOption as Data_PermanentHomeKeygenTokenOption
from pcapkit.protocols.data.internet.mh import SignatureOption as Data_SignatureOption
from pcapkit.protocols.data.internet.mh import UnassignedOption as Data_UnassignedOption
from pcapkit.protocols.data.internet.mh import UnknownExtension as Data_UnknownExtension
from pcapkit.protocols.data.internet.mh import UnknownMessage as Data_UnknownMessage
from pcapkit.protocols.internet.internet import Internet
from pcapkit.protocols.schema.internet.mh import MH as Schema_MH
from pcapkit.protocols.schema.internet.mh import \
    AlternateCareofAddressOption as Schema_AlternateCareofAddressOption
from pcapkit.protocols.schema.internet.mh import AuthOption as Schema_AuthOption
from pcapkit.protocols.schema.internet.mh import \
    AuthorizationDataOption as Schema_AuthorizationDataOption
from pcapkit.protocols.schema.internet.mh import \
    BindingAcknowledgementMessage as Schema_BindingAcknowledgementMessage
from pcapkit.protocols.schema.internet.mh import BindingErrorMessage as Schema_BindingErrorMessage
from pcapkit.protocols.schema.internet.mh import \
    BindingRefreshAdviceOption as Schema_BindingRefreshAdviceOption
from pcapkit.protocols.schema.internet.mh import \
    BindingRefreshRequestMessage as Schema_BindingRefreshRequestMessage
from pcapkit.protocols.schema.internet.mh import BindingUpdateMessage as Schema_BindingUpdateMessage
from pcapkit.protocols.schema.internet.mh import \
    CareofTestInitMessage as Schema_CareofTestInitMessage
from pcapkit.protocols.schema.internet.mh import CareofTestInitOption as Schema_CareofTestInitOption
from pcapkit.protocols.schema.internet.mh import CareofTestMessage as Schema_CareofTestMessage
from pcapkit.protocols.schema.internet.mh import CareofTestOption as Schema_CareofTestOption
from pcapkit.protocols.schema.internet.mh import CGAExtension as Schema_CGAExtension
from pcapkit.protocols.schema.internet.mh import CGAParameter as Schema_CGAParameter
from pcapkit.protocols.schema.internet.mh import CGAParametersOption as Schema_CGAParametersOption
from pcapkit.protocols.schema.internet.mh import \
    CGAParametersRequestOption as Schema_CGAParametersRequestOption
from pcapkit.protocols.schema.internet.mh import HomeTestInitMessage as Schema_HomeTestInitMessage
from pcapkit.protocols.schema.internet.mh import HomeTestMessage as Schema_HomeTestMessage
from pcapkit.protocols.schema.internet.mh import \
    LinkLayerAddressOption as Schema_LinkLayerAddressOption
from pcapkit.protocols.schema.internet.mh import MesgIDOption as Schema_MesgIDOption
from pcapkit.protocols.schema.internet.mh import MNIDOption as Schema_MNIDOption
from pcapkit.protocols.schema.internet.mh import \
    MobileNetworkPrefixOption as Schema_MobileNetworkPrefixOption
from pcapkit.protocols.schema.internet.mh import MultiPrefixExtension as Schema_MultiPrefixExtension
from pcapkit.protocols.schema.internet.mh import NonceIndicesOption as Schema_NonceIndicesOption
from pcapkit.protocols.schema.internet.mh import PadOption as Schema_PadOption
from pcapkit.protocols.schema.internet.mh import \
    PermanentHomeKeygenTokenOption as Schema_PermanentHomeKeygenTokenOption
from pcapkit.protocols.schema.internet.mh import SignatureOption as Schema_SignatureOption
from pcapkit.protocols.schema.internet.mh import UnassignedOption as Schema_UnassignedOption
from pcapkit.protocols.schema.internet.mh import UnknownExtension as Schema_UnknownExtension
from pcapkit.protocols.schema.internet.mh import UnknownMessage as Schema_UnknownMessage
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall
from pcapkit.utilities.warnings import ProtocolWarning, RegistryWarning, warn

if TYPE_CHECKING:
    from datetime import datetime as dt_type
    from datetime import timedelta
    from enum import IntEnum as StdlibEnum
    from ipaddress import IPv6Address, IPv6Network
    from typing import IO, Any, Callable, DefaultDict, NoReturn, Optional, Type

    from aenum import IntEnum as AenumEnum
    from mypy_extensions import DefaultArg, KwArg, NamedArg
    from typing_extensions import Literal

    from pcapkit.corekit.multidict import OrderedMultiDict
    from pcapkit.corekit.protochain import ProtoChain
    from pcapkit.protocols.data.internet.mh import Option as Data_Option
    from pcapkit.protocols.protocol import ProtocolBase as Protocol
    from pcapkit.protocols.schema.internet.mh import Option as Schema_Option
    from pcapkit.protocols.schema.internet.mh import Packet as Schema_Packet
    from pcapkit.protocols.schema.schema import Schema

    Option = OrderedMultiDict[Enum_Option, Data_Option]
    Extension = OrderedMultiDict[Enum_CGAExtension, Data_CGAExtension]

    PacketParser = Callable[[Schema_Packet, NamedArg(Schema_MH, 'header')], Data_MH]
    PacketConstructor = Callable[[DefaultArg(Optional[Data_MH]),
                                 KwArg(Any)], Schema_Packet]

    OptionParser = Callable[[Schema_Option, NamedArg(Option, 'options')], Data_Option]
    OptionConstructor = Callable[[Enum_Option, DefaultArg(Optional[Data_Option]),
                                  KwArg(Any)], Schema_Option]

    ExtensionParser = Callable[[Schema_CGAExtension, NamedArg(Extension, 'extensions')], Data_CGAExtension]
    ExtensionConstructor = Callable[[Enum_CGAExtension, DefaultArg(Optional[Data_CGAExtension]),
                                     KwArg(Any)], Schema_CGAExtension]

__all__ = ['MH']


class NTPTimestamp(collections.namedtuple('NTPTimestamp', 'seconds fraction')):
    """NTP timestamp format, c.f., :rfc:`1305`."""

    __slots__ = ()

    #: Seconds since 1 January 1900.
    seconds: int
    #: Fraction of a second.
    fraction: int


class MH(Internet[Data_MH, Schema_MH],
         schema=Schema_MH, data=Data_MH):
    """This class implements Mobility Header.

    This class currently supports parsing og the following MH message types,
    which are resgitered in the :attr:`self.__message__ <pcapkit.protocols.internet.mh.MH.__message__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Message Type
         - Message Parser
         - Message Constructor
       * - :attr:`~pcapkit.const.mh.packet.Packet.Binding_Refresh_Request`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_brr`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_brr`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Home_Test_Init`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_hoti`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_hoti`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Care_of_Test_Init`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_coti`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_coti`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Home_Test`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_hot`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_hot`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Care_of_Test`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_cot`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_cot`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Binding_Update`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_bu`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_bu`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Binding_Acknowledgement`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_ba`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_ba`
       * - :attr:`~pcapkit.const.mh.packet.Packet.Binding_Error`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_msg_be`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_msg_be`

    This class currently supports parsing the following MH options, which are
    registered in the :attr:`self.__option__ <pcapkit.protocols.internet.mh.MH.__option__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Option Code
         - Option Parser
         - Option Constructor

       * - :attr:`~pcapkit.const.mh.option.Option.Pad1`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_pad`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_pad`
       * - :attr:`~pcapkit.const.mh.option.Option.PadN`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_pad`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_pad`
       * - :attr:`~pcapkit.const.mh.option.Option.Binding_Refresh_Advice`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_bra`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_bra`
       * - :attr:`~pcapkit.const.mh.option.Option.Alternate_Care_of_Address`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_aca`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_aca`
       * - :attr:`~pcapkit.const.mh.option.Option.Nonce_Indices`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_ni`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_ni`
       * - :attr:`~pcapkit.const.mh.option.Option.Authorization_Data`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_bad`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_bad`
       * - :attr:`~pcapkit.const.mh.option.Option.Mobile_Network_Prefix_Option`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_mnp`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_mnp`
       * - :attr:`~pcapkit.const.mh.option.Option.Mobility_Header_Link_Layer_Address_option`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_lla`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_lla`
       * - :attr:`~pcapkit.const.mh.option.Option.MN_ID_OPTION_TYPE`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_mn_id`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_mn_id`
       * - :attr:`~pcapkit.const.mh.option.Option.AUTH_OPTION_TYPE`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_auth`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_auth`
       * - :attr:`~pcapkit.const.mh.option.Option.MESG_ID_OPTION_TYPE`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_mesg_id`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_mesg_id`
       * - :attr:`~pcapkit.const.mh.option.Option.CGA_Parameters_Request`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_cga_pr`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_cga_pr`
       * - :attr:`~pcapkit.const.mh.option.Option.CGA_Parameters`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_cga_param`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_cga_param`
       * - :attr:`~pcapkit.const.mh.option.Option.Signature`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_signature`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_signature`
       * - :attr:`~pcapkit.const.mh.option.Option.Permanent_Home_Keygen_Token`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_phkt`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_phkt`
       * - :attr:`~pcapkit.const.mh.option.Option.Care_of_Test_Init`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_ct_init`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_ct_init`
       * - :attr:`~pcapkit.const.mh.option.Option.Care_of_Test`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_opt_ct`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_opt_ct`

    This class currently supports parsing of the following MH CGA extensions,
    which are registered in the :attr:`self.__extension__ <pcapkit.protocols.internet.mh.MH.__extension__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - CGA Extension Code
         - CGA Extension Parser
         - CGA Extension Constructor
       * - :attr:`~pcapkit.const.mh.extension.cga_extension.CGAExtension.Multi_Prefix`
         - :meth:`~pcapkit.protocols.internet.mh.MH._read_ext_multiprefix`
         - :meth:`~pcapkit.protocols.internet.mh.MH._make_ext_multiprefix`

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: DefaultDict[Enum_Packet, str | tuple[PacketParser, PacketConstructor]]:
    #: Message type to method mapping. Method names are expected to be referred
    #: to the class by ``_read_msg_${name}`` and/or ``_make_msg_${name}``,
    #: and if such name not found, the value should then be a method that can
    #: parse the message type by itself.
    __message__ = collections.defaultdict(
        lambda: 'unknown',
        {
            Enum_Packet.Binding_Refresh_Request: 'brr',
            Enum_Packet.Home_Test_Init: 'hoti',
            Enum_Packet.Care_of_Test_Init: 'coti',
            Enum_Packet.Home_Test: 'hot',
            Enum_Packet.Care_of_Test: 'cot',
            Enum_Packet.Binding_Update: 'bu',
            Enum_Packet.Binding_Acknowledgement: 'ba',
            Enum_Packet.Binding_Error: 'be',
        },
    )  # type: DefaultDict[Enum_Packet | int, str | tuple[PacketParser, PacketConstructor]]

    #: DefaultDict[Enum_Option, str | tuple[OptionParser, OptionConstructor]]:
    #: Option type to method mapping. Method names are expected to be referred
    #: to the class by ``_read_option_${name}`` and/or ``_make_opt_${name}``,
    #: and if such name not found, the value should then be a method that can
    #: parse the option by itself.
    __option__ = collections.defaultdict(
        lambda: 'none',
        {
            Enum_Option.Pad1: 'pad',
            Enum_Option.PadN: 'pad',
            Enum_Option.Binding_Refresh_Advice: 'bra',
            Enum_Option.Alternate_Care_of_Address: 'aca',
            Enum_Option.Nonce_Indices: 'ni',
            Enum_Option.Authorization_Data: 'bad',
            Enum_Option.Mobile_Network_Prefix_Option: 'mnp',
            Enum_Option.Mobility_Header_Link_Layer_Address_option: 'lla',
            Enum_Option.MN_ID_OPTION_TYPE: 'mn_id',
            Enum_Option.AUTH_OPTION_TYPE: 'auth',
            Enum_Option.MESG_ID_OPTION_TYPE: 'mesg_id',
            Enum_Option.CGA_Parameters_Request: 'cga_pr',
            Enum_Option.CGA_Parameters: 'cga_param',
            Enum_Option.Signature: 'signature',
            Enum_Option.Permanent_Home_Keygen_Token: 'phkt',
            Enum_Option.Care_of_Test_Init: 'ct_init',
            Enum_Option.Care_of_Test: 'ct',
        },
    )  # type: DefaultDict[Enum_Option | int, str | tuple[OptionParser, OptionConstructor]]

    #: DefaultDict[Enum_CGAExtension, str | tuple[ExtensionParser, ExtensionConstructor]]:
    #: CGA extension type to method mapping. Method names are expected to be referred
    #: to the class by ``_read_extension_${name}`` and/or ``_make_ext_${name}``,
    #: and if such name not found, the value should then be a method that can
    #: parse the CGA extension by itself.
    __extension__ = collections.defaultdict(
        lambda: 'none',
        {
            Enum_CGAExtension.Multi_Prefix: 'multiprefix',
        },
    )  # type: DefaultDict[Enum_CGAExtension | int, str | tuple[ExtensionParser, ExtensionConstructor]]

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Mobility Header"]':
        """Name of current protocol."""
        return 'Mobility Header'

    @property
    def length(self) -> 'int':
        """Header length of current protocol."""
        return self._info.length

    @property
    def payload(self) -> 'Protocol | NoReturn':
        """Payload of current instance.

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'payload'")
        return super().payload

    @property
    def protocol(self) -> 'Optional[str] | NoReturn':
        """Name of next layer protocol (if any).

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'protocol'")
        return super().protocol

    @property
    def protochain(self) -> 'ProtoChain | NoReturn':
        """Protocol chain of current instance.

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'protochain'")
        return super().protochain

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, *, version: 'Literal[4, 6]' = 4,  # pylint: disable=arguments-differ,unused-argument
             extension: bool = False, **kwargs: 'Any') -> 'Data_MH':  # pylint: disable=unused-argument
        """Read Mobility Header.

        Structure of MH header [:rfc:`6275`]:

        .. code-block:: text

           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Payload Proto |  Header Len   |   MH Type     |   Reserved    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |           Checksum            |                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
           |                                                               |
           .                                                               .
           .                       Message Data                            .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            version: IP protocol version.
            extension: If the protocol is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        name = self.__message__[schema.type]
        if isinstance(name, str):
            meth_name = f'_read_msg_{name}'
            meth = cast('PacketParser',
                        getattr(self, meth_name, self._read_msg_unknown))
        else:
            meth = name[0]
        mh = meth(schema.data, header=schema)

        if extension:
            return mh
        return self._decode_next_layer(mh, schema.next, length - mh.length)

    def make(self,
             next: 'Enum_TransType | StdlibEnum | AenumEnum | str | int' = Enum_TransType.UDP,
             next_default: 'Optional[int]' = None,
             next_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             next_reversed: 'bool' = False,
             type: 'Enum_Packet | StdlibEnum | AenumEnum | str | int' = Enum_Packet.Binding_Refresh_Request,
             type_default: 'Optional[int]' = None,
             type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             type_reversed: 'bool' = False,
             chksum: 'bytes' = b'',
             data: 'bytes | Data_MH | Schema_Packet | dict[str, Any]' = b'\x00\x00',  # minimum length
             payload: 'Protocol | Schema | bytes' = b'',
             **kwargs: 'Any') -> 'Schema_MH':
        """Make (construct) packet data.

        Args:
            next: Next header type.
            next_default: Default value for next header type field.
            next_namespace: Namespace of next header type field.
            next_reversed: Whether the bits of next header type field is reversed.
            type: Mobility Header type.
            type_default: Default value for Mobility Header type field.
            type_namespace: Namespace of Mobility Header type field.
            type_reversed: Whether the bits of Mobility Header type field is reversed.
            chksum: Checksum.
            data: Message data.
            payload: Payload of next layer protocol.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        next_val = self._make_index(next, next_default, namespace=next_namespace,
                                    reversed=next_reversed, pack=False)
        type_val = self._make_index(type, type_default, namespace=type_namespace,
                                    reversed=type_reversed, pack=False)

        if isinstance(data, bytes):
            data_val = data  # type: bytes | Schema_Packet
        elif isinstance(data, (dict, Data_MH)):
            name = self.__message__[type_val]
            if isinstance(name, str):
                meth_name = f'_make_msg_{name}'
                meth = cast('PacketConstructor',
                            getattr(self, meth_name, self._make_msg_unknown))
            else:
                meth = name[1]

            if isinstance(data, dict):
                data_val = meth(**data)
            else:
                data_val = meth(data)
        elif isinstance(data, Schema_Packet):
            data_val = data
        else:
            raise ProtocolError(f'MH: [Type {type_val}] invalid format')

        return Schema_MH(
            next=next_val,
            length=math.ceil((len(data_val) + 6) / 8) - 1,
            type=type_val,
            chksum=chksum,
            data=data_val,
            payload=payload,
        )

    @classmethod
    def register_message(cls, code: 'Enum_Packet', meth: 'str | tuple[PacketParser, PacketConstructor]') -> 'None':
        """Register a message parser.

        Args:
            code: MH message type code.
            meth: Method name or callable to parse and/or construct the message.

        """
        if code in cls.__message__:
            warn(f'message type {code} already registered, overwriting', RegistryWarning)
        cls.__message__[code] = meth

    @classmethod
    def register_option(cls, code: 'Enum_Option', meth: 'str | tuple[OptionParser, OptionConstructor]') -> 'None':
        """Register an option parser.

        Args:
            code: MH option code.
            meth: Method name or callable to parse and/or construct the option.

        """
        if code in cls.__option__:
            warn(f'option {code} already registered, overwriting', RegistryWarning)
        cls.__option__[code] = meth

    @classmethod
    def register_extension(cls, code: 'Enum_CGAExtension', meth: 'str | tuple[ExtensionParser, ExtensionConstructor]') -> 'None':
        """Register a CGA extension parser.

        Args:
            code: CGA extension code.
            meth: Method name or callable to parse and/or construct the extension.

        """
        if code in cls.__extension__:
            warn(f'extension {code} already registered, overwriting', RegistryWarning)
        cls.__extension__[code] = meth

    ##########################################################################
    # Data models.
    ##########################################################################

    @overload
    def __post_init__(self, file: 'IO[bytes] | bytes', length: 'Optional[int]' = ..., *,  # pylint: disable=arguments-differ
                      extension: 'bool' = ..., **kwargs: 'Any') -> 'None': ...

    @overload
    def __post_init__(self, **kwargs: 'Any') -> 'None': ...  # pylint: disable=arguments-differ

    def __post_init__(self, file: 'Optional[IO[bytes] | bytes]' = None, length: 'Optional[int]' = None, *,  # pylint: disable=arguments-differ
                      extension: 'bool' = False, **kwargs: 'Any') -> 'None':
        """Post initialisation hook.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            extension: If the protocol is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For construction argument, please refer to :meth:`self.make <MH.make>`.

        """
        #: bool: If the protocol is used as an IPv6 extension header.
        self._extf = extension

        # call super __post_init__
        super().__post_init__(file, length, extension=extension, **kwargs)  # type: ignore[arg-type]

    def __length_hint__(self) -> 'Literal[6]':
        """Return an estimated length for the object."""
        return 6

    @classmethod
    def __index__(cls) -> 'Enum_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return Enum_TransType.Mobility_Header  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_MH') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'next': data.next,
            'type': data.type,
            'chksum': data.chksum,
            'data': data,
            'payload': cls._make_payload(data),
        }

    def _read_msg_unknown(self, schema: 'Schema_UnknownMessage', *,
                          header: 'Schema_MH') -> 'Data_UnknownMessage':
        """Read unknown MH message type.

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_UnknownMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            data=schema.data,
        )
        return data

    def _read_msg_brr(self, schema: 'Schema_BindingRefreshRequestMessage', *,
                      header: 'Schema_MH') -> 'Data_BindingRefreshRequestMessage':
        """Read MH binding refresh request (BRR) message type.

        Structure of MH Binding Refresh Request Message [:rfc:`6275`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |          Reserved             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Mobility Options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_BindingRefreshRequestMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            options=self._read_mh_options(schema.options)
        )
        return data

    def _read_msg_hoti(self, schema: 'Schema_HomeTestInitMessage', *,
                       header: 'Schema_MH') -> 'Data_HomeTestInitMessage':
        """Read MH home test initiation (HoTI) message type.

        Structure of MH Home Test Initiation Message [:rfc:`6275`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |           Reserved            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                       Home Init Cookie                        +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                       Mobility Options                        .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_HomeTestInitMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            cookie=schema.cookie,
            options=self._read_mh_options(schema.options)
        )
        return data

    def _read_msg_coti(self, schema: 'Schema_CareofTestInitMessage', *,
                       header: 'Schema_MH') -> 'Data_CareofTestInitMessage':
        """Read MH care-of test initiation (CoTI) message type.

        Structure of MH Care-of Test Initiation Message [:rfc:`6275`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |           Reserved            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                      Care-of Init Cookie                      +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Mobility Options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_CareofTestInitMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            cookie=schema.cookie,
            options=self._read_mh_options(schema.options)
        )
        return data

    def _read_msg_hot(self, schema: 'Schema_HomeTestMessage', *,
                      header: 'Schema_MH') -> 'Data_HomeTestMessage':
        """Read MH home test (HoT) message type.

        Structure of MH Home Test Message [:rfc:`6275`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |       Home Nonce Index        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                        Home Init Cookie                       +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                       Home Keygen Token                       +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Mobility Options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_HomeTestMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            nonce_index=schema.nonce_index,
            cookie=schema.cookie,
            token=schema.token,
            options=self._read_mh_options(schema.options),
        )
        return data

    def _read_msg_cot(self, schema: 'Schema_CareofTestMessage', *,
                      header: 'Schema_MH') -> 'Data_CareofTestMessage':
        """Read MH care-of test (CoT) message type.

        Structure of MH Care-of Test Message [:rfc:`6275`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |      Care-of Nonce Index      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                      Care-of Init Cookie                      +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                     Care-of Keygen Token                      +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Mobility Options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_CareofTestMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            nonce_index=schema.nonce_index,
            cookie=schema.cookie,
            token=schema.token,
            options=self._read_mh_options(schema.options),
        )
        return data

    def _read_msg_bu(self, schema: 'Schema_BindingUpdateMessage', *,
                     header: 'Schema_MH') -> 'Data_BindingUpdateMessage':
        """Read MH binding update (BU) message type.

        Structure of MH Binding Update Message [:rfc:`6275`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |          Sequence #           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |A|H|L|K|        Reserved       |           Lifetime            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Mobility Options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_BindingUpdateMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            seq=schema.seq,
            ack=bool(schema.flags['A']),
            home=bool(schema.flags['H']),
            lla_compat=bool(schema.flags['L']),
            key_mngt=bool(schema.flags['K']),
            lifetime=datetime.timedelta(seconds=schema.lifetime * 4),
            options=self._read_mh_options(schema.options),
        )
        return data

    def _read_msg_ba(self, schema: 'Schema_BindingAcknowledgementMessage', *,
                     header: 'Schema_MH') -> 'Data_BindingAcknowledgementMessage':
        """Read MH binding acknowledgement (BA) message type.

        Structure of MH Binding Acknowledgement Message [:rfc:`6275`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |    Status     |K|  Reserved   |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |           Sequence #          |           Lifetime            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Mobility Options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_BindingAcknowledgementMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            status=schema.status,
            key_mngt=bool(schema.flags['K']),
            seq=schema.seq,
            lifetime=datetime.timedelta(seconds=schema.lifetime * 4),
            options=self._read_mh_options(schema.options),
        )
        return data

    def _read_msg_be(self, schema: 'Schema_BindingErrorMessage', *,
                     header: 'Schema_MH') -> 'Data_BindingErrorMessage':
        """Read MH binding error (BE) message type.

        Structure of MH Binding Error Message [:rfc:`6275`]:

        .. code-block:: text

                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |     Status    |   Reserved    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                          Home Address                         +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           .                                                               .
           .                        Mobility Options                       .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed message type schema.
            header: Parsed MH header schema.

        Returns:
            Parsed message type data.

        """
        data = Data_BindingErrorMessage(
            next=header.next,
            length=(header.length + 1) * 8,
            type=header.type,
            chksum=header.chksum,
            status=schema.status,
            home=schema.home,
            options=self._read_mh_options(schema.options),
        )
        return data

    # TODO: Implement other message types.

    def _read_mh_options(self, options_schema: 'list[Schema_Option]') -> 'Option':
        """Read MH options.

        Structure of MH option [:rfc:`6275`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Option Type  | Option Length |   Option Data...
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            options_schema: Parsed MH options.

        Returns:
            Parsed MH options data.

        """
        options = OrderedMultiDict()  # type: Option

        for schema in options_schema:
            type = schema.type
            name = self.__option__[type]

            if isinstance(name, str):
                meth_name = f'_read_opt_{name}'
                meth = cast('OptionParser',
                            getattr(self, meth_name, self._read_opt_none))
            else:
                meth = name[0]
            data = meth(schema, options=options)

            # record option data
            options.add(type, data)

        return options

    def _read_opt_none(self, schema: 'Schema_UnassignedOption', *
                             options: 'Option') -> 'Data_UnassignedOption':
        """Read MH unassigned option.

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        data = Data_UnassignedOption(
            type=schema.type,
            length=schema.length + 2,
            data=schema.data,
        )
        return data

    def _read_opt_pad(self, schema: 'Schema_PadOption', *,
                      options: 'Option') -> 'Data_PadOption':
        """Read MH padding option.

        Structure of MH padding option [:rfc:`6275`]:

        * ``Pad1`` option:

          .. code-block:: text

              0
              0 1 2 3 4 5 6 7
             +-+-+-+-+-+-+-+-+
             |   Type = 0    |
             +-+-+-+-+-+-+-+-+

        * ``PadN`` option:

          .. code-block:: text

              0                   1
              0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -
             |   Type = 1    | Option Length | Option Data
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        code, clen = schema.type, schema.length

        if code not in (Enum_Option.Pad1, Enum_Option.PadN):
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        if code == Enum_Option.Pad1 and clen != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        if code == Enum_Option.PadN and clen == 0:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')

        if code == Enum_Option.Pad1:
            size = 1
        else:
            size = clen + 2

        data = Data_PadOption(
            type=schema.type,
            length=size,
        )
        return data

    def _read_opt_bra(self, schema: 'Schema_BindingRefreshAdviceOption', *,
                      options: 'Option') -> 'Data_BindingRefreshAdviceOption':
        """Read MH binding refresh advice option.

        Structure of MH Binding Refresh Advice option [:rfc:`6275`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |   Type = 2    |   Length = 2  |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |       Refresh Interval        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 2:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_BindingRefreshAdviceOption(
            type=schema.type,
            length=schema.length + 2,
            interval=schema.interval,
        )
        return data

    def _read_opt_aca(self, schema: 'Schema_AlternateCareofAddressOption', *,
                      options: 'Option') -> 'Data_AlternateCareofAddressOption':
        """Read MH alternate care-of address option.

        Structure of MH Alternate Care-of Address option [:rfc:`6275`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |   Type = 3    |  Length = 16  |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                   Alternate Care-of Address                   +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 16:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_AlternateCareofAddressOption(
            type=schema.type,
            length=schema.length + 2,
            address=schema.address,
        )
        return data

    def _read_opt_ni(self, schema: 'Schema_NonceIndicesOption', *,
                     options: 'Option') -> 'Data_NonceIndicesOption':
        """Read MH nonce indices option.

        Structure of MH Nonce Indices option [:rfc:`6275`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |   Type = 4    |   Length = 4  |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |         Home Nonce Index      |     Care-of Nonce Index       |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 4:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_NonceIndicesOption(
            type=schema.type,
            length=schema.length + 2,
            home=schema.home,
            careof=schema.careof,
        )
        return data

    def _read_opt_bad(self, schema: 'Schema_AuthorizationDataOption', *,
                      options: 'Option') -> 'Data_AuthorizationDataOption':
        """Read MH binding authorization data option.

        Structure of MH Binding Authorization Data option [:rfc:`6275`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |   Type = 5    | Option Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                         Authenticator                         |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length % 8 != 0:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_AuthorizationDataOption(
            type=schema.type,
            length=schema.length + 2,
            data=schema.data,
        )
        return data

    def _read_opt_mnp(self, schema: 'Schema_MobileNetworkPrefixOption', *,
                      options: 'Option') -> 'Data_MobileNetworkPrefixOption':
        """Read MH mobile network prefix option.

        Structure of MH Mobile Network Prefix option [:rfc:`3963`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Type     |   Length      |   Reserved    | Prefix Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                   Mobile Network Prefix                       +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 18:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        prefix = cast('IPv6Network',
                      ipaddress.ip_network((schema.prefix, schema.prefix_length)))

        data = Data_MobileNetworkPrefixOption(
            type=schema.type,
            length=schema.length + 2,
            prefix=prefix,
        )
        return data

    def _read_opt_lla(self, schema: 'Schema_LinkLayerAddressOption', *,
                      options: 'Option') -> 'Data_LinkLayerAddressOption':
        """Read MH link-layer address (MH-LLA) option.

        Structure of MH Link-Layer Address option [:rfc:`5568`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                         |     Type      |     Length    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Option-Code   |                  LLA                     ....
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.code != Enum_LLACode.MH:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_LinkLayerAddressOption(
            type=schema.type,
            length=schema.length + 2,
            code=schema.code,
            lla=schema.lla,
        )
        return data

    def _read_opt_mn_id(self, schema: 'Schema_MNIDOption', *,
                       options: 'Option') -> 'Data_MNIDOption':
        """Read MH mobile node identifier option.

        Structure of MH Mobile Node Identifier option [:rfc:`4283`]:

        .. code-block:: text

           0                   1                   2                   3
           0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Option Type  | Option Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Subtype      |          Identifier ...
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        data = Data_MNIDOption(
            type=schema.type,
            length=schema.length + 2,
            subtype=schema.subtype,
            identifier=schema.identifier,
        )
        return data

    def _read_opt_auth(self, schema: 'Schema_AuthOption', *,
                       options: 'Option') -> 'Data_AuthOption':
        """Read MH mobility message authentication option.

        Structure of MH Mobility Message Authentication option [:rfc:`4285`]:

        .. code-block:: text

           0                   1                   2                   3
           0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                           |  Option Type  | Option Length |  Subtype      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                  Mobility SPI                                 |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                  Authentication Data ....
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if (schema.length + 1) % 4 != 0:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_AuthOption(
            type=schema.type,
            length=schema.length + 2,
            subtype=schema.subtype,
            spi=schema.spi,
            data=schema.data,
        )
        return data

    def _read_opt_mesg_id(self, schema: 'Schema_MesgIDOption', *,
                          options: 'Option') -> 'Data_MesgIDOption':
        """Read MH mobility message replay protection option.

        Structure of MH Mobility Message Replay Protection option [:rfc:`4285`]:

        .. code-block:: text

           0                   1                   2                   3
           0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                       |      Option Type  | Option Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                  Timestamp ...                                |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                  Timestamp                                    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if (schema.length) % 8 != 0:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_MesgIDOption(
            type=schema.type,
            length=schema.length + 2,
            timestamp=schema.timestamp,
            ntp_timestamp=NTPTimestamp(schema.seconds, schema.fraction),
        )
        return data

    def _read_opt_cga_pr(self, schema: 'Schema_CGAParametersRequestOption', *,
                         options: 'Option') -> 'Data_CGAParametersRequestOption':
        """Read MH CGA parameters request option.

        Structure of MH CGA Parameters Request option [:rfc:`4866`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Option Type  | Option Length |
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 0:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_CGAParametersRequestOption(
            type=schema.type,
            length=schema.length + 2,
        )
        return data

    def _read_opt_cga_param(self, schema: 'Schema_CGAParametersOption', *,
                            options: 'Option') -> 'Data_CGAParametersOption':
        """Read MH CGA parameters option.

        Structure of MH CGA Parameters option [:rfc:`4866`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Option Type  | Option Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           :                                                               :
           :                          CGA Parameters                       :
           :                                                               :
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        for param in schema.parameters:
            if param.collision_count not in (0, 1, 2):
                raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_CGAParametersOption(
            type=schema.type,
            length=schema.length + 2,
            parameters=tuple(Data_CGAParameter(
                modifier=param.modifier,
                prefix=param.prefix,
                collision_count=param.collision_count,
                public_key=param.public_key,
                extensions=self._read_cga_extensions(param.extensions),
            ) for param in schema.parameters),
        )
        return data

    def _read_opt_signature(self, schema: 'Schema_SignatureOption', *,
                            options: 'Option') -> 'Data_SignatureOption':
        """Read MH signature option.

        Structure of MH Signature option [:rfc:`4866`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Option Type  | Option Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           :                                                               :
           :                            Signature                          :
           :                                                               :
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        data = Data_SignatureOption(
            type=schema.type,
            length=schema.length + 2,
            signature=schema.signature,
        )
        return data

    def _read_opt_phkt(self, schema: 'Schema_PermanentHomeKeygenTokenOption', *,
                       options: 'Option') -> 'Data_PermanentHomeKeygenTokenOption':
        """Read MH permanent home keygen token option.

        Structure of MH Permanent Home Keygen Token option [:rfc:`4866`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Option Type  | Option Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           :                                                               :
           :                  Permanent Home Keygen Token                  :
           :                                                               :
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        data = Data_PermanentHomeKeygenTokenOption(
            type=schema.type,
            length=schema.length + 2,
            token=schema.token,
        )
        return data

    def _read_opt_ct_init(self, schema: 'Schema_CareofTestInitOption', *,
                          options: 'Option') -> 'Data_CareofTestInitOption':
        """Read MH Care-of Test Init option.

        Structure of MH Care-of Test Init option [:rfc:`4866`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Option Type  | Option Length |
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 0:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_CareofTestInitOption(
            type=schema.type,
            length=schema.length + 2,
        )
        return data

    def _read_opt_ct(self, schema: 'Schema_CareofTestOption', *,
                     options: 'Option') -> 'Data_CareofTestOption':
        """Read MH Care-of Test option.

        Structure of MH Care-of Test option [:rfc:`4866`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                           |  Option Type  | Option Length |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                     Care-of Keygen Token                      +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed option schema.
            options: Parsed MH options.

        Returns:
            Constructed option data.

        """
        if schema.length != 8:
            raise ProtocolError(f'{self.alias}: [Opt {schema.type}] invalid format')

        data = Data_CareofTestOption(
            type=schema.type,
            length=schema.length + 2,
            token=schema.token,
        )
        return data

    # TODO: Implement other options.

    def _read_cga_extensions(self, extensions_schema: 'list[Schema_CGAExtension]') -> 'Extension':
        """Read CGA extensions.

        Structure of CGA extensions [:rfc:`4581`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |         Extension Type        |   Extension Data Length       |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           ~                       Extension Data                          ~
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            extensions_schema: Parsed CGA extensions.

        Returns:
            Parsed CGA extensions data.

        """
        extensions = OrderedMultiDict()  # type: Extension

        for schema in extensions_schema:
            type = schema.type
            name = self.__extension__[type]

            if isinstance(name, str):
                meth_name = f'_read_ext_{name}'
                meth = cast('ExtensionParser',
                            getattr(self, meth_name, self._read_ext_none))
            else:
                meth = name[0]
            data = meth(schema, extensions=extensions)

            # record extension data
            extensions.add(type, data)

        return extensions

    def _read_ext_none(self, schema: 'Schema_UnknownExtension', *,
                       extensions: 'Extension') -> 'Data_UnknownExtension':
        """Read unknown CGA extension.

        Args:
            schema: Parsed extension schema.
            extensions: Parsed MH CGA extensions.

        Returns:
            Constructed extension data.

        """
        data = Data_UnknownExtension(
            type=schema.type,
            length=schema.length + 2,
            data=schema.data,
        )
        return data

    def _read_ext_multiprefix(self, schema: 'Schema_MultiPrefixExtension', *,
                                extensions: 'Extension') -> 'Data_MultiPrefixExtension':
        """Read multi-prefix CGA extension.

        Structure of Multi-Prefix CGA extension [:rfc:`5535`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |         Extension Type        |   Extension Data Length       |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |P|                         Reserved                            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                           Prefix[1]                           +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                           Prefix[2]                           +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           .                               .                               .
           .                               .                               .
           .                               .                               .
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                           Prefix[n]                           +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: Parsed extension schema.
            extensions: Parsed MH CGA extensions.

        Returns:
            Constructed extension data.

        """
        data = Data_MultiPrefixExtension(
            type=schema.type,
            length=schema.length + 2,
            flag=bool(schema.flags['P']),
            prefixes=tuple(schema.prefixes),
        )
        return data

    # TODO: Implement other CGA extensions.

    def _make_msg_unknown(self, message: 'Optional[Data_UnknownMessage]', *,
                          data: 'bytes' = b'',
                          **kwargs: 'Any') -> 'Schema_UnknownMessage':
        """Make MH unknown message type.

        Args:
            message: Message data model.
            data: Raw message data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            data = message.data

        return Schema_UnknownMessage(
            data=data,
        )

    def _make_msg_brr(self, message: 'Optional[Data_BindingRefreshRequestMessage]', *,
                      options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                      **kwargs: 'Any') -> 'Schema_BindingRefreshRequestMessage':
        """Make MH binding refresh request (BRR) message type.

        Args:
            message: Message data model.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            options = message.options
        else:
            options = options or []

        return Schema_BindingRefreshRequestMessage(
            options=self._make_mh_options(options),
        )

    def _make_msg_hoti(self, message: 'Optional[Data_HomeTestInitMessage]', *,
                       cookie: 'bytes' = b'\x00\x00\x00\x00\x00\x00\x00\x00',
                       options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                       **kwargs: 'Any') -> 'Schema_HomeTestInitMessage':
        """Make MH home test init (HoTI) message type.

        Args:
            message: Message data model.
            cookie: Home test cookie.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            cookie = message.cookie
            options = message.options
        else:
            options = options or []

        return Schema_HomeTestInitMessage(
            cookie=cookie,
            options=self._make_mh_options(options),
        )

    def _make_msg_coti(self, message: 'Optional[Data_CareofTestInitMessage]', *,
                       cookie: 'bytes' = b'\x00\x00\x00\x00\x00\x00\x00\x00',
                       options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                       **kwargs: 'Any') -> 'Schema_CareofTestInitMessage':
        """Make MH care-of test init (CoTI) message type.

        Args:
            message: Message data model.
            cookie: Care-of test cookie.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            cookie = message.cookie
            options = message.options
        else:
            options = options or []

        return Schema_CareofTestInitMessage(
            cookie=cookie,
            options=self._make_mh_options(options),
        )

    def _make_msg_hot(self, message: 'Optional[Data_HomeTestMessage]', *,
                      nonce_index: 'int' = 0,
                      cookie: 'bytes' = b'\x00\x00\x00\x00\x00\x00\x00\x00',
                      token: 'bytes' = b'\x00\x00\x00\x00\x00\x00\x00\x00',
                      options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                      **kwargs: 'Any') -> 'Schema_HomeTestMessage':
        """Make MH home test (HoT) message type.

        Args:
            message: Message data model.
            nonce_index: Home nonce index.
            cookie: Home test cookie.
            token: Home test token.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            nonce_index = message.nonce_index
            cookie = message.cookie
            token = message.token
            options = message.options
        else:
            options = options or []

        return Schema_HomeTestMessage(
            nonce_index=nonce_index,
            cookie=cookie,
            token=token,
            options=self._make_mh_options(options),
        )

    def _make_msg_cot(self, message: 'Optional[Data_CareofTestMessage]', *,
                      nonce_index: 'int' = 0,
                      cookie: 'bytes' = b'\x00\x00\x00\x00\x00\x00\x00\x00',
                      token: 'bytes' = b'\x00\x00\x00\x00\x00\x00\x00\x00',
                      options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                      **kwargs: 'Any') -> 'Schema_CareofTestMessage':
        """Make MH care-of test (CoT) message type.

        Args:
            message: Message data model.
            nonce_index: Care-of nonce index.
            cookie: Care-of test cookie.
            token: Care-of test token.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            nonce_index = message.nonce_index
            cookie = message.cookie
            token = message.token
            options = message.options
        else:
            options = options or []

        return Schema_CareofTestMessage(
            nonce_index=nonce_index,
            cookie=cookie,
            token=token,
            options=self._make_mh_options(options),
        )

    def _make_msg_bu(self, message: 'Optional[Data_BindingUpdateMessage]', *,
                     seq: 'int' = 0,
                     ack: 'bool' = False,
                     home: 'bool' = False,
                     lla_compat: 'bool' = False,
                     key_mngt: 'bool' = False,
                     lifetime: 'int | timedelta' = 4,  # reasonable default value
                     options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                     **kwargs: 'Any') -> 'Schema_BindingUpdateMessage':
        """Make MH binding update (BU) message type.

        Args:
            message: Message data model.
            seq: Sequence number.
            ack: Acknowledgement flag.
            home: Home registration flag.
            lla_compat: LLA compatibility flag.
            key_mngt: Key management mobility option flag.
            lifetime: Lifetime in seconds or timedelta.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            seq = message.seq
            ack = message.ack
            home = message.home
            lla_compat = message.lla_compat
            key_mngt = message.key_mngt
            lifetime_val = math.ceil(message.lifetime.total_seconds())
            options = message.options
        else:
            lifetime_val = lifetime if isinstance(lifetime, int) else math.ceil(lifetime.total_seconds())
            options = options or []

        return Schema_BindingUpdateMessage(
            seq=seq,
            flags={
                'A': ack,
                'H': home,
                'L': lla_compat,
                'K': key_mngt,
            },
            lifetime=math.ceil(lifetime_val / 4),
            options=self._make_mh_options(options),
        )

    def _make_msg_ba(self, message: 'Optional[Data_BindingAcknowledgementMessage]', *,
                     status: 'Enum_StatusCode | StdlibEnum | AenumEnum | str | int' = Enum_StatusCode.Binding_Update_accepted_Proxy_Binding_Update_accepted,
                     status_default: 'Optional[int]' = None,
                     status_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                     status_reversed: 'bool' = False,
                     key_mngt: 'bool' = False,
                     seq: 'int' = 0,
                     lifetime: 'int | timedelta' = 4,  # reasonable default value
                     options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                     **kwargs: 'Any') -> 'Schema_BindingAcknowledgementMessage':
        """Make MH binding acknowledge (BA) message type.

        Args:
            message: Message data model.
            status: Status code.
            status_default: Default status code.
            status_namespace: Status code namespace.
            status_reversed: Reverse status code namespace.
            key_mngt: Key management mobility option flag.
            seq: Sequence number.
            lifetime: Lifetime in seconds or timedelta.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            status_val = message.status
            key_mngt = message.key_mngt
            seq = message.seq
            lifetime_val = math.ceil(message.lifetime.total_seconds())
            options = message.options
        else:
            status_val = self._make_index(status, status_default, namespace=status_namespace,  # type: ignore[assignment]
                                          reversed=status_reversed, pack=False)
            lifetime_val = lifetime if isinstance(lifetime, int) else math.ceil(lifetime.total_seconds())
            options = options or []

        return Schema_BindingAcknowledgementMessage(
            status=status_val,
            flags={
                'K': key_mngt,
            },
            seq=seq,
            lifetime=math.ceil(lifetime_val / 4),
            options=self._make_mh_options(options),
        )

    def _make_msg_be(self, message: 'Optional[Data_BindingErrorMessage]', *,
                     status: 'Enum_StatusCode | StdlibEnum | AenumEnum | str | int' = Enum_StatusCode.Binding_Update_accepted_Proxy_Binding_Update_accepted,
                     status_default: 'Optional[int]' = None,
                     status_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                     status_reversed: 'bool' = False,
                     home: 'IPv6Address | int | str | bytes' = '::',
                     options: 'Optional[Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]]' = None,
                     **kwargs: 'Any') -> 'Schema_BindingErrorMessage':
        """Make MH binding error (BE) message type.

        Args:
            message: Message data model.
            status: Status code.
            status_default: Default status code.
            status_namespace: Status code namespace.
            status_reversed: Reverse status code namespace.
            home: Home address.
            options: Mobility options.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed message type.

        """
        if message is not None:
            status_val = message.status
            home = message.home
            options = message.options
        else:
            status_val = self._make_index(status, status_default, namespace=status_namespace,  # type: ignore[assignment]
                                          reversed=status_reversed, pack=False)
            options = options or []

        return Schema_BindingErrorMessage(
            status=status_val,
            home=home,
            options=self._make_mh_options(options),
        )

    # TODO: Implement other message types.

    def _make_mh_options(self, options: 'Option | list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes]') -> 'list[Schema_Option | bytes]':
        """Make options for MH.

        Args:
            options: MH options.

        Returns:
            Mobility options list.

        """
        if isinstance(options, list):
            options_list = []  # type: list[Schema_Option | bytes]
            for schema in options:
                if isinstance(schema, bytes):
                    code = Enum_Option.get(int.from_bytes(schema[0:1], 'big', signed=False))

                    data = schema  # type: Schema_Option | bytes
                elif isinstance(schema, Schema):
                    data = schema
                else:
                    code, args = cast('tuple[Enum_Option, dict[str, Any]]', schema)
                    name = self.__option__[code]
                    if isinstance(name, str):
                        meth_name = f'_make_opt_{name}'
                        meth = cast('OptionConstructor',
                                    getattr(self, meth_name, self._make_opt_none))
                    else:
                        meth = name[1]
                    data = meth(code, **args)

                options_list.append(data)
            return options_list

        options_list = []
        for code, option in options.items(multi=True):
            name = self.__option__[code]
            if isinstance(name, str):
                meth_name = f'_make_opt_{name}'
                meth = cast('OptionConstructor',
                            getattr(self, meth_name, self._make_opt_none))
            else:
                meth = name[1]

            data = meth(code, option)
            options_list.append(data)
        return options_list

    def _make_opt_none(self, type: 'Enum_Option', option: 'Optional[Data_UnassignedOption]' = None, *,
                             data: 'bytes' = b'',
                             **kwargs: 'Any') -> 'Schema_UnassignedOption':
        """Make MH unassigned option.

        Args:
            type: Option type.
            option: Option data model.
            data: Option data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            data = option.data

        return Schema_UnassignedOption(
            type=type,
            length=len(data),
            data=data,
        )

    def _make_opt_pad(self, type: 'Enum_Option', option: 'Optional[Data_PadOption]' = None, *,
                      length: 'int' = 0,
                      **kwargs: 'Any') -> 'Schema_PadOption':
        """Make MH pad option.

        Args:
            type: Option type.
            option: Option data model.
            length: Padding length.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if  option is not None:
            length = option.length

        if type == Enum_Option.Pad1 and length != 0:
            # raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid format')
            warn(f'{self.alias}: [OptNo {type}] invalid format', ProtocolWarning)
            type = Enum_Option.PadN  # type: ignore[assignment]
        if type == Enum_Option.PadN and length == 0:
            # raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid format')
            warn(f'{self.alias}: [OptNo {type}] invalid format', ProtocolWarning)
            type = Enum_Option.Pad1  # type: ignore[assignment]

        return Schema_PadOption(
            type=type,
            length=length,
        )

    def _make_opt_bra(self, type: 'Enum_Option', option: 'Optional[Data_BindingRefreshAdviceOption]' = None, *,
                      interval: 'int' = 0,
                      **kwargs: 'Any') -> 'Schema_BindingRefreshAdviceOption':
        """Make MH binding refresh advice option.

        Args:
            type: Option type.
            option: Option data model.
            interval: Refresh interval.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            interval = option.interval

        return Schema_BindingRefreshAdviceOption(
            type=type,
            length=2,
            interval=interval,
        )

    def _make_opt_aca(self, type: 'Enum_Option', option: 'Optional[Data_AlternateCareofAddressOption]' = None, *,
                      address: 'bytes | str | int | IPv6Address' = '::',
                      **kwargs: 'Any') -> 'Schema_AlternateCareofAddressOption':
        """Make MH alternate care-of address option.

        Args:
            type: Option type.
            option: Option data model.
            address: Alternate care-of address.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            address = option.address

        return Schema_AlternateCareofAddressOption(
            type=type,
            length=16,
            address=address,
        )

    def _make_opt_ni(self, type: 'Enum_Option', option: 'Optional[Data_NonceIndicesOption]' = None, *,
                     home: 'int' = 0,
                     careof: 'int' = 0,
                     **kwargs: 'Any') -> 'Schema_NonceIndicesOption':
        """Make MH nonce indices option.

        Args:
            type: Option type.
            option: Option data model.
            home: Home nonce index.
            careof: Care-of nonce index.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            home = option.home
            careof = option.careof

        return Schema_NonceIndicesOption(
            type=type,
            length=4,
            home=home,
            careof=careof,
        )

    def _make_opt_bad(self, type: 'Enum_Option', option: 'Optional[Data_AuthorizationDataOption]' = None, *,
                      data: 'bytes' = b'',
                      **kwargs: 'Any') -> 'Schema_AuthorizationDataOption':
        """Make MH binding authorization data option.

        Args:
            type: Option type.
            option: Option data model.
            data: Authenticator.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            data = option.data

        if len(data) % 8 != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid format')

        return Schema_AuthorizationDataOption(
            type=type,
            length=len(data),
            data=data,
        )

    def _make_opt_mnp(self, type: 'Enum_Option', option: 'Optional[Data_MobileNetworkPrefixOption]' = None, *,
                      prefix: 'bytes | str | IPv6Network' = '::/0',
                      **kwargs: 'Any') -> 'Schema_MobileNetworkPrefixOption':
        """Make MH mobile network prefix option.

        Args:
            type: Option type.
            option: Option data model.
            prefix: Mobile network prefix.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            prefix = option.prefix

        prefix_val = ipaddress.ip_network(prefix)
        if prefix_val.version != 6:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid movile network prefix: {prefix!r}')
        prefix_length = prefix_val.prefixlen
        prefix_addr = prefix_val.network_address

        return Schema_MobileNetworkPrefixOption(
            type=type,
            length=18,
            prefix_length=prefix_length,
            prefix=prefix_addr,
        )

    def _make_opt_lla(self, type: 'Enum_Option', option: 'Optional[Data_LinkLayerAddressOption]' = None, *,
                      address: 'bytes' = b'',
                      **kwargs: 'Any') -> 'Schema_LinkLayerAddressOption':
        """Make MH link-layer address option.

        Args:
            type: Option type.
            option: Option data model.
            address: Link-layer address.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            address = option.lla

        return Schema_LinkLayerAddressOption(
            type=type,
            length=len(address) + 1,
            code=Enum_LLACode.MH,  # type: ignore[arg-type]
            lla=address,
        )

    def _make_opt_mn_id(self, type: 'Enum_Option', option: 'Optional[Data_MNIDOption]' = None, *,
                       subtype: 'Enum_MNIDSubtype | StdlibEnum | AenumEnum | str | int' = Enum_MNIDSubtype.IPv6_Address,
                       subtype_default: 'Optional[int]' = None,
                       subtype_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                       subtype_reversed: 'bool' = False,
                       identifier: 'bytes | str | IPv6Address | int' = '::',
                       **kwargs: 'Any') -> 'Schema_MNIDOption':
        """Make MH mobile node identifier option.

        Args:
            type: Option type.
            option: Option data model.
            subtype: MN-ID subtype.
            subtype_default: MN-ID subtype default value.
            subtype_namespace: MN-ID subtype namespace.
            subtype_reversed: MN-ID subtype reversed flag.
            identifier: Identifier.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            subtype_val = option.subtype
            identifier = option.identifier
        else:
            subtype_val = self._make_index(subtype, subtype_default, namespace=subtype_namespace,  # type: ignore[assignment]
                                           reversed=subtype_reversed, pack=False)

        if isinstance(identifier, ipaddress.IPv6Address):
            id_len = 16
        elif isinstance(identifier, int):
            id_len = math.ceil(identifier.bit_length() / 8)
        else:
            id_len = len(identifier)

        return Schema_MNIDOption(
            type=type,
            length=1 + id_len,
            subtype=subtype_val,
            identifier=identifier,
        )

    def _make_opt_auth(self, type: 'Enum_Option', option: 'Optional[Data_AuthOption]' = None, *,
                       subtype: 'Enum_AuthSubtype | StdlibEnum | AenumEnum | str | int' = Enum_AuthSubtype.MN_HA,
                       subtype_default: 'Optional[int]' = None,
                       subtype_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                       subtype_reversed: 'bool' = False,
                       spi: 'int' = 0,
                       data: 'bytes' = b'',
                       **kwargs: 'Any') -> 'Schema_AuthOption':
        """Make MH authentication option.

        Args:
            type: Option type.
            option: Option data model.
            subtype: Authentication subtype.
            subtype_default: Authentication subtype default value.
            subtype_namespace: Authentication subtype namespace.
            subtype_reversed: Authentication subtype reversed flag.
            spi: Security parameter index.
            data: Authentication data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            subtype_val = option.subtype
            spi = option.spi
            data = option.data
        else:
            subtype_val = self._make_index(subtype, subtype_default, namespace=subtype_namespace,  # type: ignore[assignment]
                                           reversed=subtype_reversed, pack=False)

        if (len(data) + 6) % 4 != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {type}] invalid format')

        return Schema_AuthOption(
            type=type,
            length=5 + len(data),
            subtype=subtype_val,
            spi=spi,
            data=data,
        )

    def _make_opt_mesg_id(self, type: 'Enum_Option', option: 'Optional[Data_MesgIDOption]' = None, *,
                          timestamp: 'Optional[NTPTimestamp]' = None,
                          interval: 'Optional[dt_type]' = None,
                          **kwargs: 'Any') -> 'Schema_MesgIDOption':
        """Make MH mobility message replay protection option.

        Args:
            type: Option type.
            option: Option data model.
            timestamp: NTP timestamp, c.f., :rfc:`1305`.
            interval: Timestamp interval (since UNIX-epoch).
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            timestamp = option.ntp_timestamp

        if timestamp is None:
            interval = interval or datetime.datetime.now(datetime.timezone.utc)

            int_ts = interval.timestamp()
            ts_sec = math.floor(int_ts)
            ts_frc = math.ceil(((int_ts - ts_sec) * 1_000_000)) * 2**32

            timestamp = NTPTimestamp(seconds=ts_sec + 2_208_988_800,  # 70 years
                                     fraction=ts_frc)

        return Schema_MesgIDOption(
            type=type,
            length=8,
            seconds=timestamp.seconds,
            fraction=timestamp.fraction,
        )

    def _make_opt_cga_pr(self, type: 'Enum_Option', option: 'Optional[Data_CGAParametersRequestOption]' = None,
                         **kwargs: 'Any') -> 'Schema_CGAParametersRequestOption':
        """Make MH CGA parameters request option.

        Args:
            type: Option type.
            option: Option data model.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        return Schema_CGAParametersRequestOption(
            type=type,
            length=0,
        )

    def _make_opt_cga_param(self, type: 'Enum_Option', option: 'Optional[Data_CGAParametersOption]' = None, *,
                            parameters: 'Optional[list[Schema_CGAParameter | Data_CGAParameter | dict[str, Any] | bytes]]' = None,
                            **kwargs: 'Any') -> 'Schema_CGAParametersOption':
        """Make MH CGA paramters option.

        Args:
            type: Option type.
            option: Option data model.
            parameters: CGA parameters.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            parameters = cast('list[Data_CGAParameter]', option.parameters)  # type: ignore[assignment]

        if parameters is None:
            parameters = []

        param = []  # type: list[Schema_CGAParameter | bytes]
        length = 0
        for data in parameters:
            if isinstance(data, bytes):
                length += len(data)
                param.append(data)
            elif isinstance(data, Schema_CGAParameter):
                length += len(data)
                param.append(data)
            elif isinstance(data, Data_CGAParameter):
                ext, _ = self._make_cga_extensions(data.extensions)
                schema = Schema_CGAParameter(
                    modifier=data.modifier,
                    prefix=data.prefix,
                    collision_count=data.collision_count,
                    public_key=data.public_key,
                    extensions=ext,
                )

                length += len(schema)
                param.append(schema)
            else:
                raise ProtocolError(f'{self.alias}: [OptNo {type}] unknown CGA parameter format: {data}')

        return Schema_CGAParametersOption(
            type=type,
            length=length,
            parameters=param,
        )

    def _make_opt_signature(self, type: 'Enum_Option', option: 'Optional[Data_SignatureOption]' = None, *,
                            signature: 'bytes' = b'',
                            **kwargs: 'Any') -> 'Schema_SignatureOption':
        """Make MH signature option.

        Args:
            type: Option type.
            option: Option data model.
            signature: Signature data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            signature = option.signature

        return Schema_SignatureOption(
            type=type,
            length=len(signature),
            signature=signature,
        )

    def _make_opt_phkt(self, type: 'Enum_Option', option: 'Optional[Data_PermanentHomeKeygenTokenOption]' = None, *,
                       token: 'bytes' = b'',
                       **kwargs: 'Any') -> 'Schema_PermanentHomeKeygenTokenOption':
        """Make MH permanent home keygen token option.

        Args:
            type: Option type.
            option: Option data model.
            token: Token data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            token = option.token

        return Schema_PermanentHomeKeygenTokenOption(
            type=type,
            length=len(token),
            token=token,
        )

    def _make_opt_ct_init(self, type: 'Enum_Option', option: 'Optional[Data_CareofTestInitOption]' = None,
                          **kwargs: 'Any') -> 'Schema_CareofTestInitOption':
        """Make MH Care-of Test Init option.

        Args:
            type: Option type.
            option: Option data model.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        return Schema_CareofTestInitOption(
            type=type,
            length=0,
        )

    def _make_opt_ct(self, type: 'Enum_Option', option: 'Optional[Data_CareofTestOption]' = None,
                     token: 'bytes' = b'\x00\x00\x00\x00\x00\x00\x00\x00',
                     **kwargs: 'Any') -> 'Schema_CareofTestOption':
        """Make MH Care-of Test option.

        Args:
            type: Option type.
            option: Option data model.
            token: Care-of keygen token.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed option schema.

        """
        if option is not None:
            token = option.token

        return Schema_CareofTestOption(
            type=type,
            length=8,
            token=token,
        )

    # TODO: Implement other options.

    def _make_cga_extensions(self, extensions: 'Extension | list[Schema_CGAExtension | tuple[Enum_CGAExtension, dict[str, Any]] | bytes]') -> 'tuple[list[Schema_CGAExtension | bytes], int]':
        """Make CGA extensions for MH.

        Args:
            extensions: CGA extensions.

        Returns:
            Tuple of extensions and total length of extensions.

        """
        total_length = 0
        if isinstance(extensions, list):
            extensions_list = []  # type: list[Schema_CGAExtension | bytes]
            for schema in extensions:
                if isinstance(schema, bytes):
                    code = Enum_CGAExtension.get(int.from_bytes(schema[0:2], 'big', signed=False))

                    data = schema  # type: Schema_CGAExtension | bytes
                    data_len = len(data)
                elif isinstance(schema, Schema):
                    data = schema
                    data_len = len(schema.pack())
                else:
                    code, args = cast('tuple[Enum_CGAExtension, dict[str, Any]]', schema)
                    name = self.__extension__[code]
                    if isinstance(name, str):
                        meth_name = f'_make_ext_{name}'
                        meth = cast('ExtensionConstructor',
                                    getattr(self, meth_name, self._make_ext_none))
                    else:
                        meth = name[1]

                    data = meth(code, **args)
                    data_len = len(data.pack())

                extensions_list.append(data)
                total_length += data_len
            return extensions_list, total_length

        extensions_list = []
        for code, extension in extensions.items(multi=True):
            name = self.__extension__[code]
            if isinstance(name, str):
                meth_name = f'_make_ext_{name}'
                meth = cast('ExtensionConstructor',
                            getattr(self, meth_name, self._make_ext_none))
            else:
                meth = name[1]

            data = meth(code, extension)
            data_len = len(data.pack())

            extensions_list.append(data)
            total_length += data_len
        return extensions_list, total_length

    def _make_ext_none(self, type: 'Enum_CGAExtension', option: 'Optional[Data_UnknownExtension]' = None, *,
                       data: 'bytes' = b'',
                       **kwargs: 'Any') -> 'Schema_UnknownExtension':
        """Make CGA extension.

        Args:
            type: Extension type.
            option: Extension data model.
            data: Extension data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed extension schema.

        """
        if option is not None:
            data = option.data

        return Schema_UnknownExtension(
            type=type,
            length=len(data),
            data=data,
        )

    def _make_ext_multiprefix(self, type: 'Enum_CGAExtension', option: 'Optional[Data_MultiPrefixExtension]' = None, *,
                              flag: 'bool' = False,
                              prefixes: 'Optional[list[int]]' = None,
                              **kwargs: 'Any') -> 'Schema_MultiPrefixExtension':
        """Make CGA multi-prefix extension.

        Args:
            type: Extension type.
            option: Extension data model.
            flag: Public key flag.
            prefixes: Prefixes.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed extension schema.

        """
        if option is not None:
            flag = option.flag
            prefixes = cast('list[int]', option.prefixes)
        else:
            prefixes = prefixes or []

        return Schema_MultiPrefixExtension(
            type=type,
            length=1 + len(prefixes) * 16,
            flags={
                'P': int(flag),
            },
            prefixes=prefixes,
        )

    # TODO: Implement other CGA extensions.
