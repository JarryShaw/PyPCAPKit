# -*- coding: utf-8 -*-
"""HIP - Host Identity Protocol
==================================

:mod:`pcapkit.protocols.internet.hip` contains
:class:`~pcapkit.protocols.internet.hip.HIP` only,
which implements extractor for Host Identity
Protocol (HIP) [*]_, whose structure is described
as below:

======= ========= ====================== ==================================
Octets      Bits        Name                    Description
======= ========= ====================== ==================================
  0           0   ``hip.next``              Next Header
  1           8   ``hip.length``            Header Length
  2          16                             Reserved (``\\x00``)
  2          17   ``hip.type``              Packet Type
  3          24   ``hip.version``           Version
  3          28                             Reserved
  3          31                             Reserved (``\\x01``)
  4          32   ``hip.chksum``            Checksum
  6          48   ``hip.control``           Controls
  8          64   ``hip.shit``              Sender's Host Identity Tag
  24        192   ``hip.rhit``              Receiver's Host Identity Tag
  40        320   ``hip.parameters``        HIP Parameters
======= ========= ====================== ==================================

.. [*] https://en.wikipedia.org/wiki/Host_Identity_Protocol

"""
import datetime
import ipaddress
import math
import struct
from typing import TYPE_CHECKING, cast, overload

from pcapkit.const.hip.certificate import Certificate as Enum_Certificate
from pcapkit.const.hip.cipher import Cipher as Enum_Cipher
from pcapkit.const.hip.di import DITypes as Enum_DITypes
from pcapkit.const.hip.ecdsa_curve import ECDSACurve as Enum_ECDSACurve
from pcapkit.const.hip.ecdsa_low_curve import ECDSALowCurve as Enum_ECDSALowCurve
from pcapkit.const.hip.esp_transform_suite import ESPTransformSuite as Enum_ESPTransformSuite
from pcapkit.const.hip.group import Group as Enum_Group
from pcapkit.const.hip.hi_algorithm import HIAlgorithm as Enum_HIAlgorithm
from pcapkit.const.hip.hit_suite import HITSuite as Enum_HITSuite
from pcapkit.const.hip.nat_traversal import NATTraversal as Enum_NATTraversal
from pcapkit.const.hip.notify_message import NotifyMessage as Enum_NotifyMessage
from pcapkit.const.hip.packet import Packet as Enum_Packet
from pcapkit.const.hip.parameter import Parameter as Enum_Parameter
from pcapkit.const.hip.registration import Registration as Enum_Registration
from pcapkit.const.hip.registration_failure import RegistrationFailure as Enum_RegistrationFailure
from pcapkit.const.hip.suite import Suite as Enum_Suite
from pcapkit.const.hip.transport import Transport as Enum_Transport
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.protocols.data.internet.hip import HIP as Data_HIP
from pcapkit.protocols.data.internet.hip import AckDataParameter as Data_AckDataParameter
from pcapkit.protocols.data.internet.hip import ACKParameter as Data_ACKParameter
from pcapkit.protocols.data.internet.hip import CertParameter as Data_CertParameter
from pcapkit.protocols.data.internet.hip import Control as Data_Control
from pcapkit.protocols.data.internet.hip import DHGroupListParameter as Data_DHGroupListParameter
from pcapkit.protocols.data.internet.hip import \
    DiffieHellmanParameter as Data_DiffieHellmanParameter
from pcapkit.protocols.data.internet.hip import \
    EchoRequestSignedParameter as Data_EchoRequestSignedParameter
from pcapkit.protocols.data.internet.hip import \
    EchoRequestUnsignedParameter as Data_EchoRequestUnsignedParameter
from pcapkit.protocols.data.internet.hip import \
    EchoResponseSignedParameter as Data_EchoResponseSignedParameter
from pcapkit.protocols.data.internet.hip import \
    EchoResponseUnsignedParameter as Data_EchoResponseUnsignedParameter
from pcapkit.protocols.data.internet.hip import EncryptedParameter as Data_EncryptedParameter
from pcapkit.protocols.data.internet.hip import ESPInfoParameter as Data_ESPInfoParameter
from pcapkit.protocols.data.internet.hip import ESPTransformParameter as Data_ESPTransformParameter
from pcapkit.protocols.data.internet.hip import Flags as Data_Flags
from pcapkit.protocols.data.internet.hip import FromParameter as Data_FromParameter
from pcapkit.protocols.data.internet.hip import HIPCipherParameter as Data_HIPCipherParameter
from pcapkit.protocols.data.internet.hip import HIPMAC2Parameter as Data_HIPMAC2Parameter
from pcapkit.protocols.data.internet.hip import HIPMACParameter as Data_HIPMACParameter
from pcapkit.protocols.data.internet.hip import \
    HIPSignature2Parameter as Data_HIPSignature2Parameter
from pcapkit.protocols.data.internet.hip import HIPSignatureParameter as Data_HIPSignatureParameter
from pcapkit.protocols.data.internet.hip import HIPTransformParameter as Data_HIPTransformParameter
from pcapkit.protocols.data.internet.hip import \
    HIPTransportModeParameter as Data_HIPTransportModeParameter
from pcapkit.protocols.data.internet.hip import HITSuiteListParameter as Data_HITSuiteParameter
from pcapkit.protocols.data.internet.hip import HostIdentity as Data_HostIdentity
from pcapkit.protocols.data.internet.hip import HostIDParameter as Data_HostIDParameter
from pcapkit.protocols.data.internet.hip import Lifetime as Data_Lifetime
from pcapkit.protocols.data.internet.hip import Locator as Data_Locator
from pcapkit.protocols.data.internet.hip import LocatorData as Data_LocatorData
from pcapkit.protocols.data.internet.hip import LocatorSetParameter as Data_LocatorSetParameter
from pcapkit.protocols.data.internet.hip import \
    NATTraversalModeParameter as Data_NATTraversalModeParameter
from pcapkit.protocols.data.internet.hip import NotificationParameter as Data_NotificationParameter
from pcapkit.protocols.data.internet.hip import OverlayIDParameter as Data_OverlayIDParameter
from pcapkit.protocols.data.internet.hip import OverlayTTLParameter as Data_OverlayTTLParameter
from pcapkit.protocols.data.internet.hip import PayloadMICParameter as Data_PayloadMICParameter
from pcapkit.protocols.data.internet.hip import PuzzleParameter as Data_PuzzleParameter
from pcapkit.protocols.data.internet.hip import R1CounterParameter as Data_R1CounterParameter
from pcapkit.protocols.data.internet.hip import RegFailedParameter as Data_RegFailedParameter
from pcapkit.protocols.data.internet.hip import RegFromParameter as Data_RegFromParameter
from pcapkit.protocols.data.internet.hip import RegInfoParameter as Data_RegInfoParameter
from pcapkit.protocols.data.internet.hip import RegRequestParameter as Data_RegRequestParameter
from pcapkit.protocols.data.internet.hip import RegResponseParameter as Data_RegResponseParameter
from pcapkit.protocols.data.internet.hip import RelayFromParameter as Data_RelayFromParameter
from pcapkit.protocols.data.internet.hip import RelayHMACParameter as Data_RelayHMACParameter
from pcapkit.protocols.data.internet.hip import RelayToParameter as Data_RelayToParameter
from pcapkit.protocols.data.internet.hip import RouteDstParameter as Data_RouteDstParameter
from pcapkit.protocols.data.internet.hip import RouteViaParameter as Data_RouteViaParameter
from pcapkit.protocols.data.internet.hip import RVSHMACParameter as Data_RVSHMACParameter
from pcapkit.protocols.data.internet.hip import SeqDataParameter as Data_SeqDataParameter
from pcapkit.protocols.data.internet.hip import SEQParameter as Data_SEQParameter
from pcapkit.protocols.data.internet.hip import SolutionParameter as Data_SolutionParameter
from pcapkit.protocols.data.internet.hip import \
    TransactionIDParameter as Data_TransactionIDParameter
from pcapkit.protocols.data.internet.hip import \
    TransactionPacingParameter as Data_TransactionPacingParameter
from pcapkit.protocols.data.internet.hip import \
    TransportFormatListParameter as Data_TransportFormatListParameter
from pcapkit.protocols.data.internet.hip import UnassignedParameter as Data_UnassignedParameter
from pcapkit.protocols.data.internet.hip import ViaRVSParameter as Data_ViaRVSParameter
from pcapkit.protocols.internet.internet import Internet
from pcapkit.protocols.schema.internet.hip import HIP as Schema_HIP
from pcapkit.protocols.schema.internet.hip import AckDataParameter as Schema_AckDataParameter
from pcapkit.protocols.schema.internet.hip import ACKParameter as Schema_ACKParameter
from pcapkit.protocols.schema.internet.hip import CertParameter as Schema_CertParameter
from pcapkit.protocols.schema.internet.hip import Control as Schema_Control
from pcapkit.protocols.schema.internet.hip import \
    DHGroupListParameter as Schema_DHGroupListParameter
from pcapkit.protocols.schema.internet.hip import \
    DiffieHellmanParameter as Schema_DiffieHellmanParameter
from pcapkit.protocols.schema.internet.hip import \
    ECDSACurveHostIdentity as Schema_ECDSACurveHostIdentity
from pcapkit.protocols.schema.internet.hip import \
    ECDSALowCurveHostIdentity as Schema_ECDSALowCurveHostIdentity
from pcapkit.protocols.schema.internet.hip import \
    EchoRequestSignedParameter as Schema_EchoRequestSignedParameter
from pcapkit.protocols.schema.internet.hip import \
    EchoRequestUnsignedParameter as Schema_EchoRequestUnsignedParameter
from pcapkit.protocols.schema.internet.hip import \
    EchoResponseSignedParameter as Schema_EchoResponseSignedParameter
from pcapkit.protocols.schema.internet.hip import \
    EchoResponseUnsignedParameter as Schema_EchoResponseUnsignedParameter
from pcapkit.protocols.schema.internet.hip import EncryptedParameter as Schema_EncryptedParameter
from pcapkit.protocols.schema.internet.hip import ESPInfoParameter as Schema_ESPInfoParameter
from pcapkit.protocols.schema.internet.hip import \
    ESPTransformParameter as Schema_ESPTransformParameter
from pcapkit.protocols.schema.internet.hip import Flags as Schema_Flags
from pcapkit.protocols.schema.internet.hip import FromParameter as Schema_FromParameter
from pcapkit.protocols.schema.internet.hip import HIPCipherParameter as Schema_HIPCipherParameter
from pcapkit.protocols.schema.internet.hip import HIPMAC2Parameter as Schema_HIPMAC2Parameter
from pcapkit.protocols.schema.internet.hip import HIPMACParameter as Schema_HIPMACParameter
from pcapkit.protocols.schema.internet.hip import \
    HIPSignature2Parameter as Schema_HIPSignature2Parameter
from pcapkit.protocols.schema.internet.hip import \
    HIPSignatureParameter as Schema_HIPSignatureParameter
from pcapkit.protocols.schema.internet.hip import \
    HIPTransformParameter as Schema_HIPTransformParameter
from pcapkit.protocols.schema.internet.hip import \
    HIPTransportModeParameter as Schema_HIPTransportModeParameter
from pcapkit.protocols.schema.internet.hip import HITSuiteListParameter as Schema_HITSuiteParameter
from pcapkit.protocols.schema.internet.hip import HostIDParameter as Schema_HostIDParameter
from pcapkit.protocols.schema.internet.hip import Lifetime as Schema_Lifetime
from pcapkit.protocols.schema.internet.hip import Locator as Schema_Locator
from pcapkit.protocols.schema.internet.hip import LocatorData as Schema_LocatorData
from pcapkit.protocols.schema.internet.hip import LocatorSetParameter as Schema_LocatorSetParameter
from pcapkit.protocols.schema.internet.hip import \
    NATTraversalModeParameter as Schema_NATTraversalModeParameter
from pcapkit.protocols.schema.internet.hip import \
    NotificationParameter as Schema_NotificationParameter
from pcapkit.protocols.schema.internet.hip import OverlayIDParameter as Schema_OverlayIDParameter
from pcapkit.protocols.schema.internet.hip import OverlayTTLParameter as Schema_OverlayTTLParameter
from pcapkit.protocols.schema.internet.hip import PayloadMICParameter as Schema_PayloadMICParameter
from pcapkit.protocols.schema.internet.hip import PuzzleParameter as Schema_PuzzleParameter
from pcapkit.protocols.schema.internet.hip import R1CounterParameter as Schema_R1CounterParameter
from pcapkit.protocols.schema.internet.hip import RegFailedParameter as Schema_RegFailedParameter
from pcapkit.protocols.schema.internet.hip import RegFromParameter as Schema_RegFromParameter
from pcapkit.protocols.schema.internet.hip import RegInfoParameter as Schema_RegInfoParameter
from pcapkit.protocols.schema.internet.hip import RegRequestParameter as Schema_RegRequestParameter
from pcapkit.protocols.schema.internet.hip import \
    RegResponseParameter as Schema_RegResponseParameter
from pcapkit.protocols.schema.internet.hip import RelayFromParameter as Schema_RelayFromParameter
from pcapkit.protocols.schema.internet.hip import RelayHMACParameter as Schema_RelayHMACParameter
from pcapkit.protocols.schema.internet.hip import RelayToParameter as Schema_RelayToParameter
from pcapkit.protocols.schema.internet.hip import RouteDstParameter as Schema_RouteDstParameter
from pcapkit.protocols.schema.internet.hip import RouteViaParameter as Schema_RouteViaParameter
from pcapkit.protocols.schema.internet.hip import RVSHMACParameter as Schema_RVSHMACParameter
from pcapkit.protocols.schema.internet.hip import SeqDataParameter as Schema_SeqDataParameter
from pcapkit.protocols.schema.internet.hip import SEQParameter as Schema_SEQParameter
from pcapkit.protocols.schema.internet.hip import SolutionParameter as Schema_SolutionParameter
from pcapkit.protocols.schema.internet.hip import \
    TransactionIDParameter as Schema_TransactionIDParameter
from pcapkit.protocols.schema.internet.hip import \
    TransactionPacingParameter as Schema_TransactionPacingParameter
from pcapkit.protocols.schema.internet.hip import \
    TransportFormatListParameter as Schema_TransportFormatListParameter
from pcapkit.protocols.schema.internet.hip import UnassignedParameter as Schema_UnassignedParameter
from pcapkit.protocols.schema.internet.hip import ViaRVSParameter as Schema_ViaRVSParameter
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall
from pcapkit.utilities.warnings import ProtocolWarning, warn

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from ipaddress import IPv4Address, IPv6Address
    from typing import IO, Any, Callable, NoReturn, Optional, Type

    from aenum import IntEnum as AenumEnum
    from mypy_extensions import NamedArg
    from typing_extensions import Literal

    from pcapkit.corekit.protochain import ProtoChain
    from pcapkit.protocols.data.internet.hip import Parameter as Data_Parameter
    from pcapkit.protocols.protocol import Protocol
    from pcapkit.protocols.schema.internet.hip import Parameter as Schema_Parameter
    from pcapkit.protocols.schema.schema import Schema

    Parameter = OrderedMultiDict[Enum_Parameter, Data_Parameter]
    ParameterParser = Callable[[Enum_Parameter, bool, int, NamedArg(bytes, 'data'),
                                NamedArg(int, 'length'), NamedArg(int, 'version'),
                                NamedArg(Parameter, 'options')], Data_Parameter]
    ParameterConstructor = Callable[['HIP', Enum_Parameter, Data_Parameter,
                                     NamedArg(int, 'version')], Schema_Parameter]

__all__ = ['HIP']


class HIP(Internet[Data_HIP, Schema_HIP]):
    """This class implements Host Identity Protocol.

    This class currently supports parsing of the following HIP parameters,
    which are directly mapped to the :class:`pcapkit.const.hip.parameter.Parameter`
    enumeration:

    .. list-table::
       :header-rows: 1

       * - Parameter Code
         - Parameter Parser
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.ESP_INFO`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_esp_info`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.R1_COUNTER`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_r1_counter`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.LOCATOR_SET`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_locator_set`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.PUZZLE`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_puzzle`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.SOLUTION`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_solution`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.SEQ`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_seq`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.ACK`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_ack`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.DH_GROUP_LIST`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_dh_group_list`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.DIFFIE_HELLMAN`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_diffie_hellman`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.HIP_TRANSFORM`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_hip_transform`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.HIP_CIPHER`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_hip_cipher`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.NAT_TRAVERSAL_MODE`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_nat_traversal_mode`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.TRANSACTION_PACING`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_transaction_pacing`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.ENCRYPTED`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_encrypted`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.HOST_ID`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_host_id`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.HIT_SUITE_LIST`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_hit_suite_list`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.CERT`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_cert`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.NOTIFICATION`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_notification`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.ECHO_REQUEST_SIGNED`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_echo_request_signed`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.REG_INFO`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_reg_info`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.REG_REQUEST`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_reg_request`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.REG_RESPONSE`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_reg_response`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.REG_FAILED`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_reg_failed`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.REG_FROM`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_reg_from`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.ECHO_RESPONSE_SIGNEED`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_echo_response_signed`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.TRANSPORT_FORMAT_LIST`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_transport_format_list`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.ESP_TRANSFORM`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_esp_transform`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.SEQ_DATA`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_seq_data`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.ACK_DATA`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_ack_data`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.PAYLOAD_MIC`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_payload_mic`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.TRANSACTION_ID`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_transaction_id`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.OVERLAY_ID`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_overlay_id`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.ROUTE_DST`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_route_dst`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.HIP_TRANSPORT_MODE`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_hip_transport_mode`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.HIP_MAC`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_hip_mac`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.HIP_MAC_2`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_hip_mac_2`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.HIP_SIGNATURE_2`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_hip_signature_2`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.HIP_SIGNATURE`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_hip_signature`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.ECHO_REQUEST_UNSIGNED`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_echo_request_unsigned`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.ECHO_RESPONSE_UNSIGNED`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_echo_response_unsigned`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.RELAY_FROM`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_relay_from`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.RELAY_TO`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_relay_to`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.OVERLAY_TTL`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_overlay_ttl`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.ROUTE_VIA`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_route_via`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.FROM`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_from`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.RVS_HMAC`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_rvs_hmac`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.VIA_RVS`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_via_rvs`
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.RELAY_HMAC`
         - :meth:`~pcapkit.protocols.internet.hip.HIP._read_param_relay_hmac`

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Host Identity Protocol"]':
        """Name of current protocol."""
        return 'Host Identity Protocol'

    @property
    def alias(self) -> 'str':
        """Acronym of corresponding protocol."""
        return f'HIPv{self._info.version}'

    @property
    def length(self) -> 'int':
        """Header length of current protocol."""
        return self._info.length

    @property
    def payload(self) -> 'Protocol | NoReturn':
        """Payload of current instance.

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        :rtype: pcapkit.protocols.protocol.Protocol
        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'payload'")
        return self._next

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

    def read(self, length: 'Optional[int]' = None, *, extension: bool = False, **kwargs: 'Any') -> 'Data_HIP':  # pylint: disable=arguments-differ,unused-argument
        """Read Host Identity Protocol.

        Structure of HIP header [:rfc:`5201`][:rfc:`7401`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | Next Header   | Header Length |0| Packet Type |Version| RES.|1|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Checksum             |           Controls            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                Sender's Host Identity Tag (HIT)               |
            |                                                               |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |               Receiver's Host Identity Tag (HIT)              |
            |                                                               |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            /                        HIP Parameters                         /
            /                                                               /
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            extension: If the packet is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        if schema.pkt['bit_0'] != 0:
            raise ProtocolError('HIP: invalid format')
        if schema.ver['bit_1'] != 1:
            raise ProtocolError('HIP: invalid format')

        hip = Data_HIP(
            next=schema.next,
            length=schema.len * 8 + 8,
            type=Enum_Packet(schema.pkt['type']),
            version=schema.ver['version'],
            chksum=schema.checksum,
            control=Data_Control(
                anonymous=bool(schema.control['anonymous']),
            ),
            shit=schema.shit,
            rhit=schema.rhit,
        )

        _prml = (schema.len - 4) * 8
        if _prml:
            hip.__update__([
                ('parameters', self._read_hip_param(_prml, version=hip.version)),
            ])

        if extension:
            return hip
        return self._decode_next_layer(hip, schema.next, length - hip.length)

    def make(self,
             next: 'Enum_TransType | StdlibEnum | AenumEnum | str | int' = Enum_TransType.UDP,
             next_default: 'Optional[int]' = None,
             next_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             next_reversed: 'bool' = False,
             packet: 'Enum_Packet | StdlibEnum | AenumEnum | str | int' = Enum_Packet.HIP_DATA,
             packet_default: 'Optional[int]' = None,
             packet_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             packet_reversed: 'bool' = False,
             version: 'int' = 2,
             checksum: 'bytes' = b'\x00\x00',
             controls_anonymous: 'bool' = False,
             shit: 'int' = 0,
             rhit: 'int' = 0,
             parameters: 'Optional[list[Schema_Parameter | bytes] | Parameter]' = None,  # pylint: disable=line-too-long
             payload: 'bytes | Protocol | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_HIP':
        """Make (construct) packet data.

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        next_value = self._make_index(next, next_default, namespace=next_namespace,  # type: ignore[call-overload]
                                      reversed=next_reversed, pack=False)
        packet_value = self._make_index(packet, packet_default, namespace=packet_namespace,  # type: ignore[call-overload]
                                        reversed=packet_reversed, pack=False)

        if parameters is not None:
            parameters_value, total_length = self._make_hip_param(parameters, version=version)
            length = total_length // 8 + 4
        else:
            parameters_value, total_length = [], 0

        return Schema_HIP(
            next=next_value,
            len=length,
            pkt = {
                'bit_0': 0,
                'type': packet_value,
            },
            ver = {
                'bit_1': 1,
                'version': version,
            },
            checksum=checksum,
            control = {
                'anonymous': controls_anonymous,
            },
            shit=shit,
            rhit=rhit,
            param=parameters_value,
            payload=payload,
        )

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
            For construction argument, please refer to :meth:`make`.

        """
        #: bool: If the protocol is used as an IPv6 extension header.
        self._extf = extension

        # call super __post_init__
        super().__post_init__(file, length, extension=extension, **kwargs)  # type: ignore[arg-type]

    def __length_hint__(self) -> 'Literal[40]':
        """Return an estimated length for the object."""
        return 40

    @classmethod
    def __index__(cls) -> 'Enum_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return Enum_TransType.HIP  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_hip_param(self, length: 'int', *, version: 'int') -> 'Parameter':  # pylint: disable=line-too-long
        """Read HIP parameters.

        Arguments:
            length: length of parameters
            version: HIP version

        Returns:
            Extracted HIP parameters.

        Raises:
            ProtocolError: if packet length threshold check failed

        """
        payload = cast('bytes', self.__header__.param)
        self.__header__.param = []

        counter = 0                   # length of read parameters
        options = OrderedMultiDict()  # type: Parameter

        while counter < length:
            cbuf = payload[counter:counter + 2]
            if not cbuf:  # break when eol triggered
                break

            # get parameter type & C-bit
            code = int(cbuf, base=2)
            cbit = bool(code & 0b1)

            # get parameter length
            cdat = payload[counter + 2:counter + 4]
            clen = struct.unpack('!H', cdat)[0]   # Length of the Contents, in bytes, excluding Type, Length, and Padding
            plen = 4 + clen + (8 - clen % 8) % 8  # Total Length = 4 [Type + Length] + Contents + Padding

            # extract parameter
            dscp = Enum_Parameter.get(code)
            meth_name = f'_read_param_{dscp.name.lower()}'
            meth = getattr(self, meth_name, self._read_param_unassigned)  # type: ParameterParser
            data = meth(self, code, cbit, clen, data=payload[counter:counter + plen],  # type: ignore[arg-type]
                        length=plen, version=version, options=options)  # type: ignore[misc]

            # record parameter data
            counter += plen
            options.add(dscp, data)

        # check threshold
        if counter != length:
            raise ProtocolError(f'HIPv{version}: invalid format')

        return options

    def _read_param_unassigned(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                               data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                               options: 'Parameter') -> 'Data_UnassignedParameter':  # pylint: disable=unused-argument
        """Read HIP unassigned parameters.

        Structure of HIP unassigned parameters [:rfc:`5201`][:rfc:`7401`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type            |C|             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            /                          Contents                             /
            /                                               +-+-+-+-+-+-+-+-+
            |                                               |    Padding    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        schema = Schema_UnassignedParameter.unpack(data, length)  # type: Schema_UnassignedParameter
        self.__header__.param.append(schema)

        unassigned = Data_UnassignedParameter(
            type=code,
            critical=cbit,
            length=length,
            contents=schema.value,
        )
        return unassigned

    def _read_param_esp_info(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,
                             data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                             options: 'Parameter') -> 'Data_ESPInfoParameter':  # pylint: disable=unused-argument
        """Read HIP ``ESP_INFO`` parameter.

        Structure of HIP ``ESP_INFO`` parameter [:rfc:`7402`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |           Reserved            |         KEYMAT Index          |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                            OLD SPI                            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                            NEW SPI                            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``clen`` is **NOT** ``12``.

        """
        if clen != 12:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        schema = Schema_ESPInfoParameter.unpack(data, length)  # type: Schema_ESPInfoParameter
        self.__header__.param.append(schema)

        esp_info = Data_ESPInfoParameter(
            type=code,
            critical=cbit,
            length=length,
            index=schema.index,
            old_spi=schema.old_spi,
            new_spi=schema.new_spi,
        )
        return esp_info

    def _read_param_r1_counter(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,
                               data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                               options: 'Parameter') -> 'Data_R1CounterParameter':  # pylint: disable=unused-argument
        """Read HIP ``R1_COUNTER`` parameter.

        Structure of HIP ``R1_COUNTER`` parameter [:rfc:`5201`][:rfc:`7401`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                       Reserved, 4 bytes                       |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                R1 generation counter, 8 bytes                 |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``clen`` is **NOT** ``12`` or the parameter is **NOT** used in HIPv1.

        """
        if clen != 12:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')
        if code == 128 and version != 1:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid parameter')

        schema = Schema_R1CounterParameter.unpack(data, length)  # type: Schema_R1CounterParameter
        self.__header__.param.append(schema)

        r1_counter = Data_R1CounterParameter(
            type=code,
            critical=cbit,
            length=length,
            counter=schema.counter,
        )
        return r1_counter

    def _read_param_locator_set(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,
                                data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                                options: 'Parameter') -> 'Data_LocatorSetParameter':  # pylint: disable=unused-argument
        """Read HIP ``LOCATOR_SET`` parameter.

        Structure of HIP ``LOCATOR_SET`` parameter [:rfc:`8046`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |            Length             |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | Traffic Type   | Locator Type | Locator Length | Reserved   |P|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                       Locator Lifetime                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                            Locator                            |
            |                                                               |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            .                                                               .
            .                                                               .
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | Traffic Type   | Locator Type | Locator Length | Reserved   |P|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                       Locator Lifetime                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                            Locator                            |
            |                                                               |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If locator data is malformed.

        """
        def _read_locator(locator: 'Schema_Locator') -> 'Data_LocatorData | IPv6Address':
            """Parse locator data.

            Args:
                locator: locator data

            Returns:
                * If ``kind`` is ``0`` and ``size`` is ``16``,
                  returns an :class:`~ipaddress.IPv4Address` object.
                * If ``kind`` is ``1`` and ``size`` is ``20``,
                  returns a :class:`~pcapkit.protocols.data.internet.hip.Locator` object.

            Raises:
                ProtocolError: in other cases

            """
            kind = locator.type
            size = 8 + locator.len * 4
            data = cast('bytes', locator.value)

            if kind == 0 and locator.len == 4:
                value = cast('IPv6Address', ipaddress.ip_address(data))
                locator.value = value
                return value
            if kind == 1 and locator.len == 5:
                locator.value = Schema_LocatorData.unpack(data, size)
                return Data_LocatorData(
                    spi=locator.value.spi,
                    ip=ipaddress.ip_address(locator.value.ip),  # type: ignore[arg-type]
                )
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        schema = Schema_LocatorSetParameter.unpack(data, length)  # type: Schema_LocatorSetParameter
        self.__header__.param.append(schema)

        locators = cast('bytes', schema.locators)
        schema.locators = []

        # length of read locators
        _size = 0
        # list of locators
        _locs = []  # type: list[Data_Locator]

        while _size < clen:
            locator = Schema_Locator.unpack(locators[_size:])  # type: Schema_Locator
            schema.locators.append(locator)

            _traf = locator.traffic
            _loct = locator.type
            _locl = locator.len * 4
            _resp = locator.flags
            _life = locator.lifetime
            _lobj = _read_locator(locator)

            _locs.append(Data_Locator(
                traffic=_traf,
                type=_loct,
                length=_locl,
                preferred=bool(_resp['preferred']),
                lifetime=datetime.timedelta(seconds=_life),
                locator=_lobj,
            ))

        locator_set = Data_LocatorSetParameter(
            type=code,
            critical=cbit,
            length=length,
            locator_set=tuple(_locs),
        )

        return locator_set

    def _read_param_puzzle(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,
                           data: 'bytes', length: 'int', version: 'int',
                           options: 'Parameter') -> 'Data_PuzzleParameter':  # pylint: disable=unused-argument
        """Read HIP ``PUZZLE`` parameter.

        Structure of HIP ``PUZZLE`` parameter [:rfc:`5201`][:rfc:`7401`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |  #K, 1 byte   |    Lifetime   |        Opaque, 2 bytes        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                      Random #I, RHASH_len / 8 bytes           |
            /                                                               /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: The parameter is **ONLY** supported in HIPv1.

        """
        if version == 1 and clen != 12:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        schema = Schema_PuzzleParameter.unpack(data, length)  # type: Schema_PuzzleParameter
        self.__header__.param.append(schema)

        _numk = schema.index
        _time = schema.lifetime
        _opak = schema.opaque
        _rand = schema.random  # Length (clen) = 4 + RHASH_len / 8

        puzzle = Data_PuzzleParameter(
            type=code,
            critical=cbit,
            length=length,
            index=_numk,
            lifetime=datetime.timedelta(seconds=2 ** (_time - 32)),
            opaque=_opak,
            random=_rand,
        )
        return puzzle

    def _read_param_solution(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,
                             data: 'bytes', length: 'int', version: 'int',
                             options: 'Parameter') -> 'Data_SolutionParameter':  # pylint: disable=unused-argument
        """Read HIP ``SOLUTION`` parameter.

        Structure of HIP ``SOLUTION`` parameter [:rfc:`5201`][:rfc:`7401`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |  #K, 1 byte   |    Lifetime   |        Opaque, 2 bytes        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                      Random #I, n bytes                       |
            /                                                               /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |            Puzzle solution #J, RHASH_len / 8 bytes            |
            /                                                               /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: The parameter is **ONLY** supported in HIPv1.

        """
        if version == 1 and clen != 20:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')
        if (clen - 4) % 2 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        schema = Schema_SolutionParameter.unpack(data, length)  # type: Schema_SolutionParameter
        self.__header__.param.append(schema)

        _numk = schema.index
        _time = schema.lifetime
        _opak = schema.opaque
        _rand = schema.random
        _solt = schema.solution  # Length (clen) = 4 + RHASH_len / 4

        solution = Data_SolutionParameter(
            type=code,
            critical=cbit,
            length=length,
            index=_numk,
            lifetime=datetime.timedelta(seconds=2 ** (_time - 32)),
            opaque=_opak,
            random=_rand,
            solution=_solt,
        )
        return solution

    def _read_param_seq(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,
                        data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                        options: 'Parameter') -> 'Data_SEQParameter':  # pylint: disable=unused-argument
        """Read HIP ``SEQ`` parameter.

        Structure of HIP ``SEQ`` parameter [:rfc:`7401`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                            Update ID                          |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``clen`` is **NOT** ``4``.

        """
        if clen != 4:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        schema = Schema_SEQParameter.unpack(data, length)  # type: Schema_SEQParameter
        self.__header__.param.append(schema)

        _upid = schema.update_id

        seq = Data_SEQParameter(
            type=code,
            critical=cbit,
            length=length,
            id=_upid,
        )
        return seq

    def _read_param_ack(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,
                        data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                        options: 'Parameter') -> 'Data_ACKParameter':  # pylint: disable=unused-argument
        """Read HIP ``ACK`` parameter.

        Structure of HIP ``ACK`` parameter [:rfc:`7401`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                       peer Update ID 1                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            /                       peer Update ID n                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``clen`` is **NOT** ``4`` modulo.

        """
        if clen % 4 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        schema = Schema_ACKParameter.unpack(data, length)  # type: Schema_ACKParameter
        self.__header__.param.append(schema)

        ack = Data_ACKParameter(
            type=code,
            critical=cbit,
            length=length,
            update_id=tuple(schema.update_id),
        )
        return ack

    def _read_param_dh_group_list(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                  data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                                  options: 'Parameter') -> 'Data_DHGroupListParameter':  # pylint: disable=unused-argument
        """Read HIP ``DH_GROUP_LIST`` parameter.

        Structure of HIP ``DH_GROUP_LIST`` parameter [:rfc:`7401`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | DH GROUP ID #1| DH GROUP ID #2| DH GROUP ID #3| DH GROUP ID #4|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | DH GROUP ID #n|                Padding                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        schema = Schema_DHGroupListParameter.unpack(data, length)  # type: Schema_DHGroupListParameter
        self.__header__.param.append(schema)

        dh_group_list = Data_DHGroupListParameter(
            type=code,
            critical=cbit,
            length=length,
            group_id=tuple(schema.groups),
        )
        return dh_group_list

    def _read_param_diffie_hellman(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                   data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                                   options: 'Parameter') -> 'Data_DiffieHellmanParameter':  # pylint: disable=unused-argument
        """Read HIP ``DIFFIE_HELLMAN`` parameter.

        Structure of HIP ``DIFFIE_HELLMAN`` parameter [:rfc:`7401`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |   Group ID    |      Public Value Length      | Public Value  /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            /                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            /                               |            Padding            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        schema = Schema_DiffieHellmanParameter.unpack(data, length)  # type: Schema_DiffieHellmanParameter
        self.__header__.param.append(schema)

        diffie_hellman = Data_DiffieHellmanParameter(
            type=code,
            critical=cbit,
            length=length,
            group_id=schema.group,
            pub_len=schema.pub_len,
            pub_val=schema.pub_val,
        )
        return diffie_hellman

    def _read_param_hip_transform(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,
                                  data: 'bytes', length: 'int', version: 'int',
                                  options: 'Parameter') -> 'Data_HIPTransformParameter':  # pylint: disable=unused-argument
        """Read HIP ``HIP_TRANSFORM`` parameter.

        Structure of HIP ``HIP_TRANSFORM`` parameter [:rfc:`5201`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |            Suite ID #1        |          Suite ID #2          |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |            Suite ID #n        |             Padding           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: The parameter is **ONLY** supported in HIPv1.

        """
        if version != 1:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid parameter')
        if clen % 2 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        schema = Schema_HIPTransformParameter.unpack(data, length)  # type: Schema_HIPTransformParameter
        self.__header__.param.append(schema)

        hip_transform = Data_HIPTransformParameter(
            type=code,
            critical=cbit,
            length=length,
            suite_id=tuple(schema.suites),
        )
        return hip_transform

    def _read_param_hip_cipher(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                               data: 'bytes', length: 'int', version: 'int',
                               options: 'Parameter') -> 'Data_HIPCipherParameter':  # pylint: disable=unused-argument
        """Read HIP ``HIP_CIPHER`` parameter.

        Structure of HIP ``HIP_CIPHER`` parameter [:rfc:`7401`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Cipher ID #1         |          Cipher ID #2         |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Cipher ID #n         |             Padding           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``clen`` is **NOT** a ``2`` modulo.

        """
        if clen % 2 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        schema = Schema_HIPCipherParameter.unpack(data, length)  # type: Schema_HIPCipherParameter
        self.__header__.param.append(schema)

        # NOTE: The sender of a HIP_CIPHER parameter MUST make sure that there are no
        # more than six (6) Cipher IDs in one HIP_CIPHER parameter. [:rfc:`7401#section-5.2.8`]
        if len(schema.ciphers) > 5:
            warn(f'HIPv{version}: [ParamNo {code}] invalid format', ProtocolWarning)
            # raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        hip_cipher = Data_HIPCipherParameter(
            type=code,
            critical=cbit,
            length=length,
            cipher_id=tuple(schema.ciphers),
        )
        return hip_cipher

    def _read_param_nat_traversal_mode(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                       data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                                       options: 'Parameter') -> 'Data_NATTraversalModeParameter':  # pylint: disable=unused-argument,line-too-long
        """Read HIP ``NAT_TRAVERSAL_MODE`` parameter.

        Structure of HIP ``NAT_TRAVERSAL_MODE`` parameter [:rfc:`5770`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |           Reserved            |            Mode ID #1         |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |           Mode ID #2          |            Mode ID #3         |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |           Mode ID #n          |             Padding           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``clen`` is **NOT** a ``2`` modulo.

        """
        if clen % 2 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        schema = Schema_NATTraversalModeParameter.unpack(data, length)  # type: Schema_NATTraversalModeParameter
        self.__header__.param.append(schema)

        nat_traversal_mode = Data_NATTraversalModeParameter(
            type=code,
            critical=cbit,
            length=length,
            mode_id=tuple(schema.modes),
        )
        return nat_traversal_mode

    def _read_param_transaction_pacing(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,
                                       data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                                       options: 'Parameter') -> 'Data_TransactionPacingParameter':  # pylint: disable=unused-argument,line-too-long
        """Read HIP ``TRANSACTION_PACING`` parameter.

        Structure of HIP ``TRANSACTION_PACING`` parameter [:rfc:`5770`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                            Min Ta                             |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``clen`` is **NOT** ``4``.

        """
        if clen != 4:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        schema = Schema_TransactionPacingParameter.unpack(data, length)  # type: Schema_TransactionPacingParameter
        self.__header__.param.append(schema)

        transaction_pacing = Data_TransactionPacingParameter(
            type=code,
            critical=cbit,
            length=length,
            min_ta=schema.min_ta,
        )
        return transaction_pacing

    def _read_param_encrypted(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                              data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                              options: 'Parameter') -> 'Data_EncryptedParameter':  # pylint: disable=unused-argument
        """Read HIP ``ENCRYPTED`` parameter.

        Structure of HIP ``ENCRYPTED`` parameter [:rfc:`7401`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                           Reserved                            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                              IV                               /
            /                                                               /
            /                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
            /                        Encrypted data                         /
            /                                                               /
            /                               +-------------------------------+
            /                               |            Padding            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        cipher_list = cast('list[Data_HIPCipherParameter]',
                           options.getlist(Enum_Parameter.HIP_CIPHER))  # type: ignore[arg-type]
        if cipher_list:
            warn(f'HIPv{version}: [ParamNo {code}] missing HIP_CIPHER parameter', ProtocolWarning)
            # raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

            cipher_id = Enum_Cipher(0xffff)
        else:
            cipher_ids = []  # type: list[Enum_Cipher]
            for cipher in cipher_list:
                cipher_ids.extend(cipher.cipher_id)

            encrypted_list = cast('list[Data_EncryptedParameter]',
                                options.getlist(Enum_Parameter.ENCRYPTED))  # type: ignore[arg-type]
            encrypted_index = len(encrypted_list)

            if encrypted_index >= len(cipher_ids):
                warn(f'HIPv{version}: [ParamNo {code}] too many ENCRYPTED parameters', ProtocolWarning)
                #raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

                cipher_id = Enum_Cipher(0xfffe)
            else:
                cipher_id = cipher_ids[encrypted_index]

        schema = Schema_EncryptedParameter.unpack(data, length, packet={
            '__cipher__': cipher_id,
        })  # type: Schema_EncryptedParameter
        schema.cipher = cipher_id
        self.__header__.param.append(schema)

        encrypted = Data_EncryptedParameter(
            type=code,
            critical=cbit,
            length=length,
            cipher=cipher_id,
            iv=schema.iv,
            data=schema.data,
        )
        return encrypted

    def _read_param_host_id(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                            data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                            options: 'Parameter') -> 'Data_HostIDParameter':  # pylint: disable=unused-argument
        """Read HIP ``HOST_ID`` parameter.

        Structure of HIP ``HOST_ID`` parameter [:rfc:`7401`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          HI Length            |DI-Type|      DI Length        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Algorithm            |         Host Identity         /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            /                               |       Domain Identifier       /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            /                                               |    Padding    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        schema = Schema_HostIDParameter.unpack(data, length)  # type: Schema_HostIDParameter
        self.__header__.param.append(schema)

        if schema.algorithm == Enum_HIAlgorithm.ECDSA:
            schema.hi = Schema_ECDSACurveHostIdentity.unpack(
                cast('bytes', schema.hi), schema.hi_len,
            )
            hi = Data_HostIdentity(
                curve=schema.hi.curve,
                pubkey=schema.hi.pub_key,
            )
        elif schema.algorithm == Enum_HIAlgorithm.ECDSA_LOW:
            schema.hi = Schema_ECDSALowCurveHostIdentity.unpack(
                cast('bytes', schema.hi), schema.hi_len,
            )
            hi = Data_HostIdentity(
                curve=schema.hi.curve,
                pubkey=schema.hi.pub_key,
            )
        else:
            hi = cast('bytes', schema.hi)  # type: ignore[assignment]

        host_id = Data_HostIDParameter(
            type=code,
            critical=cbit,
            length=length,
            hi_len=schema.hi_len,
            di_type=schema.di_data['type'],
            di_len=schema.di_data['len'],
            algorithm=schema.algorithm,
            hi=hi,
            di=schema.di,
        )
        return host_id

    def _read_param_hit_suite_list(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                   data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                                   options: 'Parameter') -> 'Data_HITSuiteParameter':  # pylint: disable=unused-argument
        """Read HIP ``HIT_SUITE_LIST`` parameter.

        Structure of HIP ``HIT_SUITE_LIST`` parameter [:rfc:`7401`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |     ID #1     |     ID #2     |     ID #3     |     ID #4     |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |     ID #n     |                Padding                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _hsid = []  # type: list[Enum_HITSuite]
        for _ in range(clen):
            _hsid.append(Enum_HITSuite.get(self._read_unpack(1)))

        hit_suite_list = Data_HITSuiteParameter(
            type=code,
            critical=cbit,
            length=length,
            suite_id=tuple(_hsid),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return hit_suite_list

    def _read_param_cert(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                         data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                         options: 'Parameter') -> 'Data_CertParameter':  # pylint: disable=unused-argument
        """Read HIP ``CERT`` parameter.

        Structure of HIP ``CERT`` parameter [:rfc:`7401`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |  CERT group   |  CERT count   |    CERT ID    |   CERT type   |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                          Certificate                          /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            /                               |   Padding (variable length)   |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _ctgp = self._read_unpack(1)
        _ctct = self._read_unpack(1)
        _ctid = self._read_unpack(1)
        _cttp = self._read_unpack(1)
        _ctdt = self._read_fileng(clen-4)

        cert = Data_CertParameter(
            type=code,
            critical=cbit,
            length=length,
            cert_group=Enum_Group.get(_ctgp),
            cert_count=_ctct,
            cert_id=_ctid,
            cert_type=Enum_Certificate.get(_cttp),
            cert=_ctdt,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return cert

    def _read_param_notification(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                 data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                                 options: 'Parameter') -> 'Data_NotificationParameter':  # pylint: disable=unused-argument
        """Read HIP ``NOTIFICATION`` parameter.

        Structure of HIP ``NOTIFICATION`` parameter [:rfc:`7401`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Reserved             |      Notify Message Type      |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               /
            /                   Notification Data                           /
            /                                               +---------------+
            /                                               |     Padding   |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _resv = self._read_fileng(2)
        _code = self._read_unpack(2)
        _data = self._read_fileng(clen - 4)

        _type = Enum_NotifyMessage.get(_code)

        notification = Data_NotificationParameter(
            type=code,
            critical=cbit,
            length=length,
            msg_type=_type,
            msg=_data,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return notification

    def _read_param_echo_request_signed(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                        data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                                        options: 'Parameter') -> 'Data_EchoRequestSignedParameter':  # pylint: disable=unused-argument
        """Read HIP ``ECHO_REQUEST_SIGNED`` parameter.

        Structure of HIP ``ECHO_REQUEST_SIGNED`` parameter [:rfc:`7401`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                 Opaque data (variable length)                 |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _data = self._read_fileng(clen)

        echo_request_signed = Data_EchoRequestSignedParameter(
            type=code,
            critical=cbit,
            length=length,
            opaque=_data,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return echo_request_signed

    def _read_param_reg_info(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                             data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                             options: 'Parameter') -> 'Data_RegInfoParameter':  # pylint: disable=unused-argument
        """Read HIP ``REG_INFO`` parameter.

        Structure of HIP ``REG_INFO`` parameter [:rfc:`8003`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | Min Lifetime  | Max Lifetime  |  Reg Type #1  |  Reg Type #2  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |      ...      |     ...       |  Reg Type #n  |               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    Padding    +
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If the registration type is invalid.

        """
        _mint = self._read_unpack(1)
        _maxt = self._read_unpack(1)

        _type = []  # type: list[Enum_Registration]
        for _ in range(clen-2):
            _code = self._read_unpack(1)
            _kind = Enum_Registration.get(_code)
            _type.append(_kind)

        reg_info = Data_RegInfoParameter(
            type=code,
            critical=cbit,
            length=length,
            lifetime=Data_Lifetime(
                min=datetime.timedelta(seconds=_mint),
                max=datetime.timedelta(seconds=_maxt),
            ),
            reg_type=tuple(_type),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return reg_info

    def _read_param_reg_request(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                                options: 'Parameter') -> 'Data_RegRequestParameter':  # pylint: disable=unused-argument
        """Read HIP ``REG_REQUEST`` parameter.

        Structure of HIP ``REG_REQUEST`` parameter [:rfc:`8003`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |   Lifetime    |  Reg Type #1  |  Reg Type #2  |  Reg Type #3  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |      ...      |     ...       |  Reg Type #n  |               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    Padding    +
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If the registration type is invalid.

        """
        _mint = self._read_unpack(1)
        _maxt = self._read_unpack(1)

        _type = []  # type: list[Enum_Registration]
        for _ in range(clen-2):
            _code = self._read_unpack(1)
            _kind = Enum_Registration.get(_code)
            _type.append(_kind)

        reg_request = Data_RegRequestParameter(
            type=code,
            critical=cbit,
            length=length,
            lifetime=Data_Lifetime(
                min=datetime.timedelta(seconds=_mint),
                max=datetime.timedelta(seconds=_maxt),
            ),
            reg_type=tuple(_type),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return reg_request

    def _read_param_reg_response(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                 data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                                 options: 'Parameter') -> 'Data_RegResponseParameter':  # pylint: disable=unused-argument
        """Read HIP ``REG_RESPONSE`` parameter.

        Structure of HIP ``REG_RESPONSE`` parameter [:rfc:`8003`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |   Lifetime    |  Reg Type #1  |  Reg Type #2  |  Reg Type #3  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |      ...      |     ...       |  Reg Type #n  |               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    Padding    +
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If the registration type is invalid.

        """
        _mint = self._read_unpack(1)
        _maxt = self._read_unpack(1)

        _type = []  # type: list[Enum_Registration]
        for _ in range(clen-2):
            _code = self._read_unpack(1)
            _kind = Enum_Registration.get(_code)
            _type.append(_kind)

        reg_response = Data_RegResponseParameter(
            type=code,
            critical=cbit,
            length=length,
            lifetime=Data_Lifetime(
                min=datetime.timedelta(seconds=_mint),
                max=datetime.timedelta(seconds=_maxt),
            ),
            reg_type=tuple(_type),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return reg_response

    def _read_param_reg_failed(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                               data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                               options: 'Parameter') -> 'Data_RegFailedParameter':  # pylint: disable=unused-argument
        """Read HIP ``REG_FAILED`` parameter.

        Structure of HIP ``REG_FAILED`` parameter [:rfc:`8003`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |   Lifetime    |  Reg Type #1  |  Reg Type #2  |  Reg Type #3  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |      ...      |     ...       |  Reg Type #n  |               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    Padding    +
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If the registration type is invalid.

        """
        _mint = self._read_unpack(1)
        _maxt = self._read_unpack(1)

        _type = []  # type: list[Enum_RegistrationFailure]
        for _ in range(clen-2):
            _code = self._read_unpack(1)
            _kind = Enum_RegistrationFailure.get(_code)
            _type.append(_kind)

        reg_failed = Data_RegFailedParameter(
            type=code,
            critical=cbit,
            length=length,
            lifetime=Data_Lifetime(
                min=datetime.timedelta(seconds=_mint),
                max=datetime.timedelta(seconds=_maxt),
            ),
            reg_type=tuple(_type),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return reg_failed

    def _read_param_reg_from(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                             data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                             options: 'Parameter') -> 'Data_RegFromParameter':  # pylint: disable=unused-argument
        """Read HIP ``REG_FROM`` parameter.

        Structure of HIP ``REG_FROM`` parameter [:rfc:`5770`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Port              |    Protocol   |     Reserved  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                            Address                            |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``clen`` is **NOT** ``20``.

        """
        if clen != 20:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _port = self._read_unpack(2)
        _ptcl = self._read_protos(1)
        _resv = self._read_fileng(1)
        _addr = self._read_fileng(16)

        reg_from = Data_RegFromParameter(
            type=code,
            critical=cbit,
            length=length,
            port=_port,
            protocol=_ptcl,
            address=ipaddress.ip_address(_addr),  # type: ignore[arg-type]
        )

        return reg_from

    def _read_param_echo_response_signed(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                         data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                                         options: 'Parameter') -> 'Data_EchoResponseSignedParameter':  # pylint: disable=unused-argument
        """Read HIP ``ECHO_RESPONSE_SIGNED`` parameter.

        Structure of HIP ``ECHO_RESPONSE_SIGNED`` parameter [:rfc:`7401`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                 Opaque data (variable length)                 |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _data = self._read_fileng(clen)

        echo_response_signed = Data_EchoResponseSignedParameter(
            type=code,
            critical=cbit,
            length=length,
            opaque=_data,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return echo_response_signed

    def _read_param_transport_format_list(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                          data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                                          options: 'Parameter') -> 'Data_TransportFormatListParameter':  # pylint: disable=unused-argument
        """Read HIP ``TRANSPORT_FORMAT_LIST`` parameter.

        Structure of HIP ``TRANSPORT_FORMAT_LIST`` parameter [:rfc:`7401`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          TF type #1           |           TF type #2          /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            /          TF type #n           |             Padding           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``clen`` is **NOT** ``2`` modulo.

        """
        if clen % 2 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _tfid = []  # type: list[int]
        for _ in range(clen // 2):
            _tfid.append(self._read_unpack(2))

        transport_format_list = Data_TransportFormatListParameter(
            type=code,
            critical=cbit,
            length=length,
            tf_type=tuple(_tfid),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return transport_format_list

    def _read_param_esp_transform(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                  data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                                  options: 'Parameter') -> 'Data_ESPTransformParameter':  # pylint: disable=unused-argument
        """Read HIP ``ESP_TRANSFORM`` parameter.

        Structure of HIP ``ESP_TRANSFORM`` parameter [:rfc:`7402`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Reserved             |           Suite ID #1         |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Suite ID #2          |           Suite ID #3         |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Suite ID #n          |             Padding           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``clen`` is **NOT** ``2`` modulo.

        """
        if clen % 2 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _resv = self._read_fileng(2)
        _stid = []  # type: list[Enum_ESPTransformSuite]
        for _ in range((clen - 2) // 2):
            _code = self._read_unpack(2)
            _stid.append(Enum_ESPTransformSuite.get(_code))

        esp_transform = Data_ESPTransformParameter(
            type=code,
            critical=cbit,
            length=length,
            suite_id=tuple(_stid),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return esp_transform

    def _read_param_seq_data(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                             data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                             options: 'Parameter') -> 'Data_SeqDataParameter':  # pylint: disable=unused-argument
        """Read HIP ``SEQ_DATA`` parameter.

        Structure of HIP ``SEQ_DATA`` parameter [:rfc:`6078`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                        Sequence number                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``clen`` is **NOT** ``4``.

        """
        if clen != 4:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _seqn = self._read_unpack(4)

        seq_data = Data_SeqDataParameter(
            type=code,
            critical=cbit,
            length=length,
            seq=_seqn,
        )

        return seq_data

    def _read_param_ack_data(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                             data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                             options: 'Parameter') -> 'Data_AckDataParameter':  # pylint: disable=unused-argument
        """Read HIP ``ACK_DATA`` parameter.

        Structure of HIP ``ACK_DATA`` parameter [:rfc:`6078`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                     Acked Sequence number                     /
            /                                                               /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``clen`` is **NOT** ``4`` modulo.

        """
        if clen % 4 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _ackn = []  # type: list[int]
        for _ in range(clen // 4):
            _ackn.append(self._read_unpack(4))

        ack_data = Data_AckDataParameter(
            type=code,
            critical=cbit,
            length=length,
            ack=tuple(_ackn),
        )

        return ack_data

    def _read_param_payload_mic(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                                options: 'Parameter') -> 'Data_PayloadMICParameter':  # pylint: disable=unused-argument
        """Read HIP ``PAYLOAD_MIC`` parameter.

        Structure of HIP ``PAYLOAD_MIC`` parameter [:rfc:`6078`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |  Next Header  |                   Reserved                    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                         Payload Data                          |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            /                         MIC Value                             /
            /                                               +-+-+-+-+-+-+-+-+
            |                                               |    Padding    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _next = self._read_protos(1)
        _resv = self._read_fileng(3)
        _data = self._read_fileng(4)
        _micv = self._read_fileng(clen-8)

        payload_mic = Data_PayloadMICParameter(
            type=code,
            critical=cbit,
            length=length,
            next=_next,
            payload=_data,
            mic=_micv,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return payload_mic

    def _read_param_transaction_id(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                   data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                                   options: 'Parameter') -> 'Data_TransactionIDParameter':  # pylint: disable=unused-argument
        """Read HIP ``TRANSACTION_ID`` parameter.

        Structure of HIP ``TRANSACTION_ID`` parameter [:rfc:`6078`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                           Identifier                          /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            /                                               |    Padding    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _tsid = self._read_unpack(clen)

        transaction_id = Data_TransactionIDParameter(
            type=code,
            critical=cbit,
            length=length,
            id=_tsid,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return transaction_id

    def _read_param_overlay_id(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                               data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                               options: 'Parameter') -> 'Data_OverlayIDParameter':  # pylint: disable=unused-argument
        """Read HIP ``OVERLAY_ID`` parameter.

        Structure of HIP ``OVERLAY_ID`` parameter [:rfc:`6079`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                           Identifier                          /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            /                                               |    Padding    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _olid = self._read_unpack(clen)

        overlay_id = Data_OverlayIDParameter(
            type=code,
            critical=cbit,
            length=length,
            id=_olid,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return overlay_id

    def _read_param_route_dst(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                              data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                              options: 'Parameter') -> 'Data_RouteDstParameter':  # pylint: disable=unused-argument
        """Read HIP ``ROUTE_DST`` parameter.

        Structure of HIP ``ROUTE_DST`` parameter [:rfc:`6028`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Flags             |            Reserved           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                            HIT #1                             |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            .                               .                               .
            .                               .                               .
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                            HIT #n                             |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If the parameter is malformed.

        """
        if (clen - 4) % 16 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _flag = self._read_binary(2)
        _resv = self._read_fileng(2)

        _addr = []  # type: list[IPv6Address]
        for _ in range((clen - 4) // 16):
            _addr.append(ipaddress.ip_address(self._read_fileng(16)))  # type: ignore[arg-type]

        route_dst = Data_RouteDstParameter(
            type=code,
            critical=cbit,
            length=length,
            flags=Data_Flags(
                symmetric=bool(int(_flag[0], base=2)),
                must_follow=bool(int(_flag[1], base=2)),
            ),
            hit=tuple(_addr),
        )

        return route_dst

    def _read_param_hip_transport_mode(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                       data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                                       options: 'Parameter') -> 'Data_HIPTransportModeParameter':  # pylint: disable=unused-argument
        """Read HIP ``HIP_TRANSPORT_MODE`` parameter.

        Structure of HIP ``HIP_TRANSPORT_MODE`` parameter [:rfc:`6261`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Port              |           Mode ID #1          |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Mode ID #2           |           Mode ID #3          |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Mode ID #n           |             Padding           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``clen`` is **NOT** ``2`` modulo.

        """
        if clen % 2 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _port = self._read_unpack(2)

        _mdid = []  # type: list[Enum_Transport]
        for _ in range((clen - 2) // 2):
            _code = self._read_unpack(2)
            _mdid.append(Enum_Transport.get(_code))

        hip_transport_mode = Data_HIPTransportModeParameter(
            type=code,
            critical=cbit,
            length=length,
            port=_port,
            mode_id=tuple(_mdid),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return hip_transport_mode

    def _read_param_hip_mac(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                            data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                            options: 'Parameter') -> 'Data_HIPMACParameter':  # pylint: disable=unused-argument
        """Read HIP ``HIP_MAC`` parameter.

        Structure of HIP ``HIP_MAC`` parameter [:rfc:`7401`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                             HMAC                              |
            /                                                               /
            /                               +-------------------------------+
            |                               |            Padding            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _hmac = self._read_fileng(clen)

        hip_mac = Data_HIPMACParameter(
            type=code,
            critical=cbit,
            length=length,
            hmac=_hmac,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return hip_mac

    def _read_param_hip_mac_2(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                              data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                              options: 'Parameter') -> 'Data_HIPMAC2Parameter':  # pylint: disable=unused-argument
        """Read HIP ``HIP_MAC_2`` parameter.

        Structure of HIP ``HIP_MAC_2`` parameter [:rfc:`7401`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                             HMAC                              |
            /                                                               /
            /                               +-------------------------------+
            |                               |            Padding            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _hmac = self._read_fileng(clen)

        hip_mac_2 = Data_HIPMAC2Parameter(
            type=code,
            critical=cbit,
            length=length,
            hmac=_hmac,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return hip_mac_2

    def _read_param_hip_signature_2(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                    data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                                    options: 'Parameter') -> 'Data_HIPSignature2Parameter':  # pylint: disable=unused-argument
        """Read HIP ``HIP_SIGNATURE_2`` parameter.

        Structure of HIP ``HIP_SIGNATURE_2`` parameter [:rfc:`7401`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |    SIG alg                    |            Signature          /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            /                               |             Padding           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _algo = self._read_unpack(2)
        _sign = self._read_fileng(clen-2)

        hip_signature_2 = Data_HIPSignature2Parameter(
            type=code,
            critical=cbit,
            length=length,
            algorithm=Enum_HIAlgorithm.get(_algo),
            signature=_sign,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return hip_signature_2

    def _read_param_hip_signature(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                  data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                                  options: 'Parameter') -> 'Data_HIPSignatureParameter':  # pylint: disable=unused-argument
        """Read HIP ``HIP_SIGNATURE`` parameter.

        Structure of HIP ``HIP_SIGNATURE`` parameter [:rfc:`7401`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |    SIG alg                    |            Signature          /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            /                               |             Padding           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _algo = self._read_unpack(2)
        _sign = self._read_fileng(clen-2)

        hip_signature = Data_HIPSignatureParameter(
            type=code,
            critical=cbit,
            length=length,
            algorithm=Enum_HIAlgorithm.get(_algo),
            signature=_sign,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return hip_signature

    def _read_param_echo_request_unsigned(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                          data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                                          options: 'Parameter') -> 'Data_EchoRequestUnsignedParameter':  # pylint: disable=unused-argument
        """Read HIP ``ECHO_REQUEST_UNSIGNED`` parameter.

        Structure of HIP ``ECHO_REQUEST_UNSIGNED`` parameter [:rfc:`7401`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                 Opaque data (variable length)                 |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _data = self._read_fileng(clen)

        echo_request_unsigned = Data_EchoRequestUnsignedParameter(
            type=code,
            critical=cbit,
            length=length,
            opaque=_data,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return echo_request_unsigned

    def _read_param_echo_response_unsigned(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                           data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                                           options: 'Parameter') -> 'Data_EchoResponseUnsignedParameter':  # pylint: disable=unused-argument
        """Read HIP ``ECHO_RESPONSE_UNSIGNED`` parameter.

        Structure of HIP ``ECHO_RESPONSE_UNSIGNED`` parameter [:rfc:`7401`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                 Opaque data (variable length)                 |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _data = self._read_fileng(clen)

        echo_response_unsigned = Data_EchoResponseUnsignedParameter(
            type=code,
            critical=cbit,
            length=length,
            opaque=_data,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return echo_response_unsigned

    def _read_param_relay_from(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                               data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                               options: 'Parameter') -> 'Data_RelayFromParameter':  # pylint: disable=unused-argument
        """Read HIP ``RELAY_FROM`` parameter.

        Structure of HIP ``RELAY_FROM`` parameter [:rfc:`5770`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Port              |    Protocol   |     Reserved  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                            Address                            |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``clen`` is **NOT** ``20``.

        """
        if clen != 20:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _port = self._read_unpack(2)
        _ptcl = self._read_protos(1)
        _resv = self._read_fileng(1)
        _addr = self._read_fileng(16)

        relay_from = Data_RelayFromParameter(
            type=code,
            critical=cbit,
            length=length,
            port=_port,
            protocol=_ptcl,
            address=ipaddress.ip_address(_addr),  # type: ignore[arg-type]
        )

        return relay_from

    def _read_param_relay_to(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                             data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                             options: 'Parameter') -> 'Data_RelayToParameter':  # pylint: disable=unused-argument
        """Read HIP ``RELAY_TO`` parameter.

        Structure of HIP ``RELAY_TO`` parameter [:rfc:`5770`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Port              |    Protocol   |     Reserved  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                            Address                            |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``clen`` is **NOT** ``20``.

        """
        if clen != 20:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _port = self._read_unpack(2)
        _ptcl = self._read_protos(1)
        _resv = self._read_fileng(1)
        _addr = self._read_fileng(16)

        relay_to = Data_RelayToParameter(
            type=code,
            critical=cbit,
            length=length,
            port=_port,
            protocol=_ptcl,
            address=ipaddress.ip_address(_addr),  # type: ignore[arg-type]
        )

        return relay_to

    def _read_param_overlay_ttl(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                                options: 'Parameter') -> 'Data_OverlayTTLParameter':  # pylint: disable=unused-argument
        """Read HIP ``OVERLAY_TTL`` parameter.

        Structure of HIP ``OVERLAY_TTL`` parameter [:rfc:`6078`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             TTL               |            Reserved           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``clen`` is **NOT** ``4``.

        """
        if clen != 4:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _ttln = self._read_unpack(2)

        overlay_ttl = Data_OverlayTTLParameter(
            type=code,
            critical=cbit,
            length=length,
            ttl=datetime.timedelta(seconds=_ttln),
        )

        return overlay_ttl

    def _read_param_route_via(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                              data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                              options: 'Parameter') -> 'Data_RouteViaParameter':  # pylint: disable=unused-argument
        """Read HIP ``ROUTE_VIA`` parameter.

        Structure of HIP ``ROUTE_VIA`` parameter [:rfc:`6028`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Flags             |            Reserved           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                            HIT #1                             |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            .                               .                               .
            .                               .                               .
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                            HIT #n                             |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If the parameter is malformed.

        """
        if (clen - 4) % 16 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _flag = self._read_binary(2)
        _resv = self._read_fileng(2)

        _addr = []  # type: list[IPv6Address]
        for _ in range((clen - 4) // 16):
            _addr.append(ipaddress.ip_address(self._read_fileng(16)))  # type: ignore[arg-type]

        route_via = Data_RouteViaParameter(
            type=code,
            critical=cbit,
            length=length,
            flags=Data_Flags(
                symmetric=bool(int(_flag[0], base=2)),
                must_follow=bool(int(_flag[1], base=2)),
            ),
            hit=tuple(_addr),
        )

        return route_via

    def _read_param_from(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                         data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                         options: 'Parameter') -> 'Data_FromParameter':  # pylint: disable=unused-argument
        """Read HIP ``FROM`` parameter.

        Structure of HIP ``FROM`` parameter [:rfc:`8004`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                             Address                           |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``clen`` is **NOT** ``16``.

        """
        if clen != 16:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _addr = self._read_fileng(16)

        from_ = Data_FromParameter(
            type=code,
            critical=cbit,
            length=length,
            address=ipaddress.ip_address(_addr),  # type: ignore[arg-type]
        )

        return from_

    def _read_param_rvs_hmac(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                             data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                             options: 'Parameter') -> 'Data_RVSHMACParameter':  # pylint: disable=unused-argument
        """Read HIP ``RVS_HMAC`` parameter.

        Structure of HIP ``RVS_HMAC`` parameter [:rfc:`8004`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                             HMAC                              |
            /                                                               /
            /                               +-------------------------------+
            |                               |            Padding            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _hmac = self._read_fileng(clen)

        rvs_hmac = Data_RVSHMACParameter(
            type=code,
            critical=cbit,
            length=length,
            hmac=_hmac,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return rvs_hmac

    def _read_param_via_rvs(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                            data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                            options: 'Parameter') -> 'Data_ViaRVSParameter':  # pylint: disable=unused-argument
        """Read HIP ``VIA_RVS`` parameter.

        Structure of HIP ``VIA_RVS`` parameter [:rfc:`6028`]:

        .. code-block:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                            Address                            |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            .                               .                               .
            .                               .                               .
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                            Address                            |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``clen`` is **NOT** ``16`` modulo.

        """
        if clen % 16 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _addr = []  # type: list[IPv6Address]
        for _ in range(clen // 16):
            _addr.append(ipaddress.ip_address(self._read_fileng(16)))  # type: ignore[arg-type]

        via_rvs = Data_ViaRVSParameter(
            type=code,
            critical=cbit,
            length=length,
            address=tuple(_addr),
        )

        return via_rvs

    def _read_param_relay_hmac(self, code: 'Enum_Parameter', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                               data: 'bytes', length: 'int', version: 'int',  # pylint: disable=unused-argument
                               options: 'Parameter') -> 'Data_RelayHMACParameter':  # pylint: disable=unused-argument
        """Read HIP ``RELAY_HMAC`` parameter.

        Structure of HIP ``RELAY_HMAC`` parameter [:rfc:`5770`]:

        .. code-block::

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                             HMAC                              |
            /                                                               /
            /                               +-------------------------------+
            |                               |            Padding            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code: parameter code
            cbit: critical bit
            clen: length of contents
            data: parameter payload data (incl. type, length, content and padding, if any)
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _hmac = self._read_fileng(clen)

        relay_hmac = Data_RelayHMACParameter(
            type=code,
            critical=cbit,
            length=length,
            hmac=_hmac,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return relay_hmac

    def _make_hip_param(self, parameters: 'list[Schema_Parameter | bytes] | Parameter', *,
                        version: 'int') -> 'tuple[list[Schema_Parameter | bytes], int]':
        """Make HIP parameter.

        Args:
            parameters: HIP parameters
            version: HIP protocol version

        Returns:
            HIP parameters.

        """
        total_length = 0
        if isinstance(parameters, list):
            for schema in parameters:
                if isinstance(schema, bytes):
                    total_length += len(schema)
                else:
                    total_length += len(schema.pack())
            return parameters, total_length

        parameters_list = []  # type: list[Schema_Parameter]
        for code, param in parameters.items(multi=True):
            meth_name = f'_make_param_{code.name.lower()}'
            meth = cast('ParameterConstructor',
                        getattr(self, meth_name, self._make_param_unassigned))
            data = meth(self, code, param, version=version)  # type: Schema_Parameter

            parameters_list.append(data)
            total_length += len(data.pack())
        return parameters_list, total_length  # type: ignore[return-value]

    def _make_param_unassigned(self, code: 'Enum_Parameter', param: 'Data_UnassignedParameter', *,  # pylint: disable=unused-argument
                               version: 'int') -> 'Schema_UnassignedParameter':
        """Make HIP unassigned parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version

        Returns:
            HIP parameter schema.

        """
        return Schema_UnassignedParameter(
            type=code,
            len=len(param.contents),
            value=param.contents,
        )

    def _make_param_esp_info(self, code: 'Enum_Parameter', param: 'Data_ESPInfoParameter', *,  # pylint: disable=unused-argument
                             version: 'int') -> 'Schema_ESPInfoParameter':
        """Make HIP ``ESP_INFO`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version

        Returns:
            HIP parameter schema.

        """
        return Schema_ESPInfoParameter(
            type=code,
            len=12,
            index=param.index,
            old_spi=param.old_spi,
            new_spi=param.new_spi,
        )

    def _make_param_r1_counter(self, code: 'Enum_Parameter', param: 'Data_R1CounterParameter', *, # pylint: disable=unused-argument
                               version: 'int') -> 'Schema_R1CounterParameter':
        """Make HIP ``R1_COUNTER`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version

        Returns:
            HIP parameter schema.

        """
        if code == Enum_Parameter.R1_Counter and version != 1:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid parameter')

        return Schema_R1CounterParameter(
            type=code,
            len=12,
            counter=param.counter,
        )

    def _make_param_locator_set(self, code: 'Enum_Parameter', param: 'Data_LocatorSetParameter', *,  # pylint: disable=unused-argument
                                version: 'int') -> 'Schema_LocatorSetParameter':
        """Make HIP ``LOCATOR_SET`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version

        Returns:
            HIP parameter schema.

        """
        def _make_locator(locator: 'Data_Locator') -> 'Schema_Locator':
            """Make locator data.

            Args:
                locator: locator data

            Returns:
                HIP locator schema.

            """
            value = locator.locator
            if isinstance(value, ipaddress.IPv6Address):
                data = value.packed  # type: bytes | Schema_LocatorData
            elif isinstance(value, Data_LocatorData):
                data = Schema_LocatorData(
                    spi=value.spi,
                    ip=value.ip.packed,
                )
            else:
                raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

            return Schema_Locator(
                traffic=locator.traffic,
                type=locator.type,
                len=locator.length // 4,
                flags={
                    'preferred': locator.preferred,
                },
                lifetime=int(locator.lifetime.total_seconds()),
                value=data,
            )

        return Schema_LocatorSetParameter(
            type=code,
            len=sum(locator.length for locator in param.locator_set),
            locators=[_make_locator(locator) for locator in param.locator_set],
        )

    def _make_param_puzzle(self, code: 'Enum_Parameter', param: 'Data_PuzzleParameter', *,  # pylint: disable=unused-argument
                           version: 'int') -> 'Schema_PuzzleParameter':
        """Make HIP ``PUZZLE`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version

        Returns:
            HIP parameter schema.

        """
        return Schema_PuzzleParameter(
            type=code,
            len=4 + math.ceil(param.random.bit_length() / 8),
            index=param.index,
            lifetime=math.floor(math.log2(param.lifetime.total_seconds()) + 32),
            opaque=param.opaque,
            random=param.random,
        )

    def _make_param_solution(self, code: 'Enum_Parameter', param: 'Data_SolutionParameter', *,  # pylint: disable=unused-argument
                             version: 'int') -> 'Schema_SolutionParameter':
        """Make HIP ``SOLUTION`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version

        Returns:
            HIP parameter schema.

        """
        return Schema_SolutionParameter(
            type=code,
            len=4 + math.ceil(max(param.random.bit_length(), param.solution.bit_length()) / 4),
            index=param.index,
            lifetime=math.floor(math.log2(param.lifetime.total_seconds()) + 32),
            opaque=param.opaque,
            random=param.random,
            solution=param.solution,
        )

    def _make_param_seq(self, code: 'Enum_Parameter', param: 'Data_SEQParameter', *,  # pylint: disable=unused-argument
                        version: 'int') -> 'Schema_SEQParameter':
        """Make HIP ``SEQ`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version

        Returns:
            HIP parameter schema.

        """
        return Schema_SEQParameter(
            type=code,
            len=4,
            update_id=param.id,
        )

    def _make_param_ack(self, code: 'Enum_Parameter', param: 'Data_ACKParameter', *,  # pylint: disable=unused-argument
                        version: 'int') -> 'Schema_ACKParameter':
        """Make HIP ``ACK`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version

        Returns:
            HIP parameter schema.

        """
        return Schema_ACKParameter(
            type=code,
            len=4 * len(param.update_id),
            update_id=cast('list[int]', param.update_id),
        )

    def _make_param_dh_group_list(self, code: 'Enum_Parameter', param: 'Data_DHGroupListParameter', *,  # pylint: disable=unused-argument
                                  version: 'int') -> 'Schema_DHGroupListParameter':
        """Make HIP ``DH_GROUP_LIST`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version

        Returns:
            HIP parameter schema.

        """
        return Schema_DHGroupListParameter(
            type=code,
            len=len(param.group_id),
            groups=cast('list[Enum_Group]', param.group_id),
        )

    def _make_param_diffie_hellman(self, code: 'Enum_Parameter', param: 'Data_DiffieHellmanParameter', *,  # pylint: disable=unused-argument
                                   version: 'int') -> 'Schema_DiffieHellmanParameter':
        """Make HIP ``DIFFIE_HELLMAN`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version

        Returns:
            HIP parameter schema.

        """
        return Schema_DiffieHellmanParameter(
            type=code,
            len=3 + param.pub_len,
            group=param.group_id,
            pub_len=param.pub_len,
            pub_val=param.pub_val,
        )

    def _make_param_hip_transform(self, code: 'Enum_Parameter', param: 'Data_HIPTransformParameter', *,  # pylint: disable=unused-argument
                                  version: 'int') -> 'Schema_HIPTransformParameter':
        """Make HIP ``HIP_TRANSFORM`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version

        Returns:
            HIP parameter schema.

        """
        return Schema_HIPTransformParameter(
            type=code,
            len=2 * len(param.suite_id),
            suites=cast('list[Enum_Suite]', param.suite_id),
        )

    def _make_param_hip_cipher(self, code: 'Enum_Parameter', param: 'Data_HIPCipherParameter', *,  # pylint: disable=unused-argument
                               version: 'int') -> 'Schema_HIPCipherParameter':
        """Make HIP ``HIP_CIPHER`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version

        Returns:
            HIP parameter schema.

        """
        return Schema_HIPCipherParameter(
            type=code,
            len=2 * len(param.cipher_id),
            ciphers=cast('list[Enum_Cipher]', param.cipher_id),
        )

    def _make_param_nat_traversal_mode(self, code: 'Enum_Parameter', param: 'Data_NATTraversalModeParameter', *,  # pylint: disable=unused-argument
                                       version: 'int') -> 'Schema_NATTraversalModeParameter':
        """Make HIP ``NAT_TRAVERSAL_MODE`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version

        Returns:
            HIP parameter schema.

        """
        return Schema_NATTraversalModeParameter(
            type=code,
            len=2 + 2 * len(param.mode_id),
            modes=cast('list[Enum_NATTraversal]', param.mode_id),
        )

    def _make_param_encrypted(self, code: 'Enum_Parameter', param: 'Data_EncryptedParameter', *,  # pylint: disable=unused-argument
                              version: 'int') -> 'Schema_EncryptedParameter':
        """Make HIP ``ENCRYPTED`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version

        Returns:
            HIP parameter schema.

        """
        return Schema_EncryptedParameter(
            type=code,
            len=4 + len(param.iv or b'') + len(param.data),
            cipher=param.cipher,
            iv=param.iv,
            data=param.data,
        )

    def _make_param_host_id(self, code: 'Enum_Parameter', param: 'Data_HostIDParameter', *,  # pylint: disable=unused-argument
                            version: 'int') -> 'Schema_HostIDParameter':
        """Make HIP ``HOST_ID`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version

        Returns:
            HIP parameter schema.

        """
        if isinstance(param.hi, Data_HostIdentity):
            if isinstance(param.hi.curve, Enum_ECDSACurve):
                hi = Schema_ECDSACurveHostIdentity(
                    curve=param.hi.curve,
                    pub_key=param.hi.pubkey,
                )  # type: Schema_ECDSACurveHostIdentity | Schema_ECDSALowCurveHostIdentity | bytes
            elif isinstance(param.hi.curve, Enum_ECDSALowCurve):
                hi = Schema_ECDSALowCurveHostIdentity(
                    curve=param.hi.curve,
                    pub_key=param.hi.pubkey,
                )
            else:
                raise ProtocolError(f'[HIPv{version}] invalid ECDSA curve: {param.hi.curve!r}')
        else:
            hi = param.hi

        return Schema_HostIDParameter(
            type=code,
            len=6 + param.hi_len + param.di_len,
            hi_len=param.hi_len,
            di_data={
                'type': param.di_type,
                'len': param.di_len,
            },
            algorithm=param.algorithm,
            hi=hi,
            di=param.di,
        )
