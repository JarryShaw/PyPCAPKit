# -*- coding: utf-8 -*-
"""HIP - Host Identity Protocol
==================================

.. module:: pcapkit.protocols.internet.hip

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
from typing import TYPE_CHECKING, cast, overload

from pcapkit.const.hip.certificate import Certificate as Enum_Certificate
from pcapkit.const.hip.cipher import Cipher as Enum_Cipher
from pcapkit.const.hip.di import DITypes as Enum_DITypes
from pcapkit.const.hip.ecdsa_curve import ECDSACurve as Enum_ECDSACurve
from pcapkit.const.hip.ecdsa_low_curve import ECDSALowCurve as Enum_ECDSALowCurve
from pcapkit.const.hip.eddsa_curve import EdDSACurve as Enum_EdDSACurve
from pcapkit.const.hip.group import Group as Enum_Group
from pcapkit.const.hip.hi_algorithm import HIAlgorithm as Enum_HIAlgorithm
from pcapkit.const.hip.hit_suite import HITSuite as Enum_HITSuite
from pcapkit.const.hip.notify_message import NotifyMessage as Enum_NotifyMessage
from pcapkit.const.hip.packet import Packet as Enum_Packet
from pcapkit.const.hip.parameter import Parameter as Enum_Parameter
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
from pcapkit.protocols.data.internet.hip import HITSuiteListParameter as Data_HITSuiteListParameter
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
from pcapkit.protocols.schema.internet.hip import \
    EdDSACurveHostIdentity as Schema_EdDSACurveHostIdentity
from pcapkit.protocols.schema.internet.hip import EncryptedParameter as Schema_EncryptedParameter
from pcapkit.protocols.schema.internet.hip import ESPInfoParameter as Schema_ESPInfoParameter
from pcapkit.protocols.schema.internet.hip import \
    ESPTransformParameter as Schema_ESPTransformParameter
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
from pcapkit.protocols.schema.internet.hip import \
    HITSuiteListParameter as Schema_HITSuiteListParameter
from pcapkit.protocols.schema.internet.hip import HostIdentity as Schema_HostIdentity
from pcapkit.protocols.schema.internet.hip import HostIDParameter as Schema_HostIDParameter
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
from pcapkit.protocols.schema.schema import Schema
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING
from pcapkit.utilities.warnings import ProtocolWarning, RegistryWarning, warn

if TYPE_CHECKING:
    from datetime import timedelta
    from enum import IntEnum as StdlibEnum
    from ipaddress import IPv6Address
    from typing import IO, Any, Callable, NoReturn, Optional, Type

    from aenum import IntEnum as AenumEnum
    from mypy_extensions import DefaultArg, KwArg, NamedArg
    from typing_extensions import Literal, NotRequired

    from pcapkit.const.hip.esp_transform_suite import ESPTransformSuite as Enum_ESPTransformSuite
    from pcapkit.const.hip.nat_traversal import NATTraversal as Enum_NATTraversal
    from pcapkit.const.hip.registration import Registration as Enum_Registration
    from pcapkit.const.hip.registration_failure import \
        RegistrationFailure as Enum_RegistrationFailure
    from pcapkit.const.hip.suite import Suite as Enum_Suite
    from pcapkit.const.hip.transport import Transport as Enum_Transport
    from pcapkit.corekit.protochain import ProtoChain
    from pcapkit.protocols.data.internet.hip import Parameter as Data_Parameter
    from pcapkit.protocols.protocol import ProtocolBase as Protocol
    from pcapkit.protocols.schema.internet.hip import Parameter as Schema_Parameter

    Parameter = OrderedMultiDict[Enum_Parameter, Data_Parameter]
    ParameterParser = Callable[[Schema_Parameter, NamedArg(int, 'version'),
                                NamedArg(Parameter, 'options')], Data_Parameter]
    ParameterConstructor = Callable[[Enum_Parameter, DefaultArg(Optional[Data_Parameter]),
                                     NamedArg(int, 'version'), KwArg(Any)], Schema_Parameter]

__all__ = ['HIP']


if SPHINX_TYPE_CHECKING:
    from typing_extensions import TypedDict

    class Locator(TypedDict):
        """Locator dictionary type."""

        #: Traffic type.
        traffic: 'int'
        #: Locator type.
        type: 'int'
        #: Preferred flag.
        preferred: 'bool'
        #: Lifetime.
        lifetime: 'timedelta | int'
        #: IP address.
        ip: 'IPv6Address | bytes | int | str'
        #: SPI.
        spi: 'NotRequired[int]'


class HIP(Internet[Data_HIP, Schema_HIP],
          schema=Schema_HIP, data=Data_HIP):
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
       * - :attr:`~pcapkit.const.hip.parameter.Parameter.ECHO_RESPONSE_SIGNED`
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
             parameters: 'Optional[list[Schema_Parameter | tuple[Enum_Parameter, dict[str, Any]] | bytes] | Parameter]' = None,  # pylint: disable=line-too-long
             payload: 'bytes | Protocol | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_HIP':
        """Make (construct) packet data.

        Args:
            next: Next header type.
            next_default: Default value for next header type.
            next_namespace: Namespace for next header type.
            next_reversed: If the next header type is reversed.
            packet: HIP packet type.
            packet_default: Default value for HIP packet type.
            packet_namespace: Namespace for HIP packet type.
            packet_reversed: If the HIP packet type is reversed.
            version: HIP version.
            checksum: Checksum.
            controls_anonymous: If the sender is anonymous.
            shit: Sender's host identity tag (HIT).
            rhit: Receiver's host identity tag (HIT).
            parameters: HIP parameters.
            payload: Payload.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        next_value = self._make_index(next, next_default, namespace=next_namespace,
                                      reversed=next_reversed, pack=False)
        packet_value = self._make_index(packet, packet_default, namespace=packet_namespace,
                                        reversed=packet_reversed, pack=False)

        if parameters is not None:
            parameters_value, total_length = self._make_hip_param(parameters, version=version)
            length = total_length // 8 + 4
        else:
            parameters_value, length = [], 0

        return Schema_HIP(
            next=next_value,  # type: ignore[arg-type]
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

    @classmethod
    def register_parameter(cls, code: 'Enum_Parameter', meth: 'str | tuple[ParameterParser, ParameterConstructor]') -> 'None':
        """Register a parameter parser.

        Args:
            code: IPv4 option code.
            meth: Method name or callable to parse and/or construct the option.

        """
        name = code.name.lower()
        if hasattr(cls, f'_read_param_{name}'):
            warn(f'parameter {code} already registered, overwriting', RegistryWarning)

        if isinstance(meth, str):
            meth = (getattr(cls, f'_read_param_{meth}', cls._read_param_unassigned),  # type: ignore[arg-type]
                    getattr(cls, f'_make_param_{meth}', cls._make_param_unassigned))  # type: ignore[arg-type]

        setattr(cls, f'_read_param_{name}', meth[0])
        setattr(cls, f'_make_param_{name}', meth[1])

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
            For construction argument, please refer to :meth:`self.make <HIP.make>`.

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

    @classmethod
    def _make_data(cls, data: 'Data_HIP') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'next': data.next,
            'packet': data.type,
            'version': data.version,
            'checksum': data.chksum,
            'controls_anonymous': data.control.anonymous,
            'shit': data.shit,
            'rhit': data.rhit,
            'parameters': data.parameters,
            'payload': cls._make_payload(data),
        }

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
        counter = 0                   # length of read parameters
        options = OrderedMultiDict()  # type: Parameter

        for schema in self.__header__.param:
            dscp = schema.type

            meth_name = f'_read_param_{dscp.name.lower()}'
            meth = cast('ParameterParser',
                        getattr(self, meth_name, self._read_param_unassigned))
            data = meth(schema, version=version, options=options)

            # record parameter data
            options.add(dscp, data)
            counter += len(schema)

        # check threshold
        if counter != length:
            raise ProtocolError(f'HIPv{version}: invalid format')
        return options

    def _read_param_unassigned(self, schema: 'Schema_UnassignedParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        unassigned = Data_UnassignedParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            contents=schema.value,
        )
        return unassigned

    def _read_param_esp_info(self, schema: 'Schema_ESPInfoParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``schema.len`` is **NOT** ``12``.

        """
        if schema.len != 12:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

        esp_info = Data_ESPInfoParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            index=schema.index,
            old_spi=schema.old_spi,
            new_spi=schema.new_spi,
        )
        return esp_info

    def _read_param_r1_counter(self, schema: 'Schema_R1CounterParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``schema.len`` is **NOT** ``12`` or the parameter is **NOT** used in HIPv1.

        """
        if schema.len != 12:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')
        if schema.type == 128 and version != 1:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid parameter')

        r1_counter = Data_R1CounterParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            counter=schema.counter,
        )
        return r1_counter

    def _read_param_locator_set(self, schema: 'Schema_LocatorSetParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
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

            if kind == 0 and locator.len == 4:
                return cast('IPv6Address', locator.value)
            if kind == 1 and locator.len == 5:
                loc_val = cast('Schema_LocatorData', locator.value)
                return Data_LocatorData(
                    spi=loc_val.spi,
                    ip=ipaddress.ip_address(loc_val.ip),  # type: ignore[arg-type]
                )
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

        # length of read locators
        _size = 0
        # list of locators
        _locs = []  # type: list[Data_Locator]

        for locator in schema.locators:
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
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            locator_set=tuple(_locs),
        )

        return locator_set

    def _read_param_puzzle(self, schema: 'Schema_PuzzleParameter', *, version: 'int',
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: The parameter is **ONLY** supported in HIPv1.

        """
        if version == 1 and schema.len != 12:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

        _numk = schema.index
        _time = schema.lifetime
        _opak = schema.opaque
        _rand = schema.random  # Length (schema.len) = 4 + RHASH_len / 8

        puzzle = Data_PuzzleParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            index=_numk,
            lifetime=datetime.timedelta(seconds=2 ** (_time - 32)),
            opaque=_opak,
            random=_rand,
        )
        return puzzle

    def _read_param_solution(self, schema: 'Schema_SolutionParameter', *, version: 'int',
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: The parameter is **ONLY** supported in HIPv1.

        """
        if version == 1 and schema.len != 20:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')
        if (schema.len - 4) % 2 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

        _numk = schema.index
        _time = schema.lifetime
        _opak = schema.opaque
        _rand = schema.random
        _solt = schema.solution  # Length (schema.len) = 4 + RHASH_len / 4

        solution = Data_SolutionParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            index=_numk,
            lifetime=datetime.timedelta(seconds=2 ** (_time - 32)),
            opaque=_opak,
            random=_rand,
            solution=_solt,
        )
        return solution

    def _read_param_seq(self, schema: 'Schema_SEQParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``schema.len`` is **NOT** ``4``.

        """
        if schema.len != 4:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

        _upid = schema.update_id

        seq = Data_SEQParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            id=_upid,
        )
        return seq

    def _read_param_ack(self, schema: 'Schema_ACKParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``schema.len`` is **NOT** ``4`` modulo.

        """
        if schema.len % 4 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

        ack = Data_ACKParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            update_id=tuple(schema.update_id),
        )
        return ack

    def _read_param_dh_group_list(self, schema: 'Schema_DHGroupListParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        dh_group_list = Data_DHGroupListParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            group_id=tuple(schema.groups),
        )
        return dh_group_list

    def _read_param_diffie_hellman(self, schema: 'Schema_DiffieHellmanParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        diffie_hellman = Data_DiffieHellmanParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            group_id=schema.group,
            pub_len=schema.pub_len,
            pub_val=schema.pub_val,
        )
        return diffie_hellman

    def _read_param_hip_transform(self, schema: 'Schema_HIPTransformParameter', *, version: 'int',
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: The parameter is **ONLY** supported in HIPv1.

        """
        if version != 1:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid parameter')
        if schema.len % 2 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

        hip_transform = Data_HIPTransformParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            suite_id=tuple(schema.suites),
        )
        return hip_transform

    def _read_param_hip_cipher(self, schema: 'Schema_HIPCipherParameter', *, version: 'int',
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``schema.len`` is **NOT** a ``2`` modulo.

        """
        if schema.len % 2 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

        # NOTE: The sender of a HIP_CIPHER parameter MUST make sure that there are no
        # more than six (6) Cipher IDs in one HIP_CIPHER parameter. [:rfc:`7401#section-5.2.8`]
        if len(schema.ciphers) > 5:
            warn(f'HIPv{version}: [ParamNo {schema.type}] invalid format', ProtocolWarning)
            # raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

        hip_cipher = Data_HIPCipherParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            cipher_id=tuple(schema.ciphers),
        )
        return hip_cipher

    def _read_param_nat_traversal_mode(self, schema: 'Schema_NATTraversalModeParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``schema.len`` is **NOT** a ``2`` modulo.

        """
        if schema.len % 2 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

        nat_traversal_mode = Data_NATTraversalModeParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            mode_id=tuple(schema.modes),
        )
        return nat_traversal_mode

    def _read_param_transaction_pacing(self, schema: 'Schema_TransactionPacingParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``schema.len`` is **NOT** ``4``.

        """
        if schema.len != 4:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

        transaction_pacing = Data_TransactionPacingParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            min_ta=schema.min_ta,
        )
        return transaction_pacing

    def _read_param_encrypted(self, schema: 'Schema_EncryptedParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        encrypted = Data_EncryptedParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            cipher=schema.cipher,
            iv=getattr(schema, 'iv', None),
            data=schema.data,
        )
        return encrypted

    def _read_param_host_id(self, schema: 'Schema_HostIDParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        if schema.algorithm == Enum_HIAlgorithm.ECDSA:
            schema_hi = cast('Schema_ECDSACurveHostIdentity', schema.hi)
            hi = Data_HostIdentity(
                curve=schema_hi.curve,
                pubkey=schema_hi.pub_key,
            )
        elif schema.algorithm == Enum_HIAlgorithm.ECDSA_LOW:
            schema_hi = cast('Schema_ECDSALowCurveHostIdentity', schema.hi)  # type: ignore[assignment]
            hi = Data_HostIdentity(
                curve=schema_hi.curve,
                pubkey=schema_hi.pub_key,
            )
        elif schema.algorithm == Enum_HIAlgorithm.EdDSA:
            schema_hi = cast('Schema_EdDSACurveHostIdentity', schema.hi)  # type: ignore[assignment]
            hi = Data_HostIdentity(
                curve=schema_hi.curve,
                pubkey=schema_hi.pub_key,
            )
        else:
            hi = cast('bytes', schema.hi)  # type: ignore[assignment]

        host_id = Data_HostIDParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            hi_len=schema.hi_len,
            di_type=schema.di_data['type'],
            di_len=schema.di_data['len'],
            algorithm=schema.algorithm,
            hi=hi,
            di=schema.di,
        )
        return host_id

    def _read_param_hit_suite_list(self, schema: 'Schema_HITSuiteListParameter', *, version: 'int',  # pylint: disable=unused-argument
                                   options: 'Parameter') -> 'Data_HITSuiteListParameter':  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        hit_suite_list = Data_HITSuiteListParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            suite_id=tuple(schema.suites),
        )
        return hit_suite_list

    def _read_param_cert(self, schema: 'Schema_CertParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        cert = Data_CertParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            cert_group=schema.cert_group,
            cert_count=schema.cert_count,
            cert_id=schema.cert_id,
            cert_type=schema.cert_type,
            cert=schema.cert,
        )
        return cert

    def _read_param_notification(self, schema: 'Schema_NotificationParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        notification = Data_NotificationParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            msg_type=schema.msg_type,
            msg=schema.msg,
        )
        return notification

    def _read_param_echo_request_signed(self, schema: 'Schema_EchoRequestSignedParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        echo_request_signed = Data_EchoRequestSignedParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            opaque=schema.opaque,
        )
        return echo_request_signed

    def _read_param_reg_info(self, schema: 'Schema_RegInfoParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        reg_info = Data_RegInfoParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            lifetime=Data_Lifetime(
                min=datetime.timedelta(seconds=schema.min_lifetime),
                max=datetime.timedelta(seconds=schema.max_lifetime),
            ),
            reg_type=tuple(schema.reg_info),
        )
        return reg_info

    def _read_param_reg_request(self, schema: 'Schema_RegRequestParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        reg_request = Data_RegRequestParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            lifetime=datetime.timedelta(seconds=schema.lifetime),
            reg_type=tuple(schema.reg_request),
        )
        return reg_request

    def _read_param_reg_response(self, schema: 'Schema_RegResponseParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        reg_response = Data_RegResponseParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            lifetime=datetime.timedelta(seconds=schema.lifetime),
            reg_type=tuple(schema.reg_response),
        )
        return reg_response

    def _read_param_reg_failed(self, schema: 'Schema_RegFailedParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        reg_failed = Data_RegFailedParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            lifetime=datetime.timedelta(seconds=schema.lifetime),
            reg_type=tuple(schema.reg_failed),
        )
        return reg_failed

    def _read_param_reg_from(self, schema: 'Schema_RegFromParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``schema.len`` is **NOT** ``20``.

        """
        if schema.len != 20:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

        reg_from = Data_RegFromParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            port=schema.port,
            protocol=schema.protocol,
            address=schema.address,
        )
        return reg_from

    def _read_param_echo_response_signed(self, schema: 'Schema_EchoResponseSignedParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        echo_response_signed = Data_EchoResponseSignedParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            opaque=schema.opaque,
        )
        return echo_response_signed

    def _read_param_transport_format_list(self, schema: 'Schema_TransportFormatListParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``schema.len`` is **NOT** ``2`` modulo.

        """
        if schema.len % 2 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

        transport_format_list = Data_TransportFormatListParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            tf_type=tuple(schema.formats),
        )
        return transport_format_list

    def _read_param_esp_transform(self, schema: 'Schema_ESPTransformParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``schema.len`` is **NOT** ``2`` modulo.

        """
        if schema.len % 2 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

        esp_transform = Data_ESPTransformParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            suite_id=tuple(schema.suites),
        )
        return esp_transform

    def _read_param_seq_data(self, schema: 'Schema_SeqDataParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``schema.len`` is **NOT** ``4``.

        """
        if schema.len != 4:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

        seq_data = Data_SeqDataParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            seq=schema.seq,
        )
        return seq_data

    def _read_param_ack_data(self, schema: 'Schema_AckDataParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``schema.len`` is **NOT** ``4`` modulo.

        """
        if schema.len % 4 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

        ack_data = Data_AckDataParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            ack=tuple(schema.ack),
        )
        return ack_data

    def _read_param_payload_mic(self, schema: 'Schema_PayloadMICParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        payload_mic = Data_PayloadMICParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            next=schema.next,
            payload=schema.payload,
            mic=schema.mic,
        )
        return payload_mic

    def _read_param_transaction_id(self, schema: 'Schema_TransactionIDParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        transaction_id = Data_TransactionIDParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            id=schema.id,
        )
        return transaction_id

    def _read_param_overlay_id(self, schema: 'Schema_OverlayIDParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        overlay_id = Data_OverlayIDParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            id=schema.id,
        )
        return overlay_id

    def _read_param_route_dst(self, schema: 'Schema_RouteDstParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If the parameter is malformed.

        """
        if (schema.len - 4) % 16 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

        route_dst = Data_RouteDstParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            flags=Data_Flags(
                symmetric=bool(schema.flags['symmetric']),
                must_follow=bool(schema.flags['must_follow']),
            ),
            hit=tuple(schema.hit),
        )
        return route_dst

    def _read_param_hip_transport_mode(self, schema: 'Schema_HIPTransportModeParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``schema.len`` is **NOT** ``2`` modulo.

        """
        if schema.len % 2 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

        hip_transport_mode = Data_HIPTransportModeParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            port=schema.port,
            mode_id=tuple(schema.mode),
        )
        return hip_transport_mode

    def _read_param_hip_mac(self, schema: 'Schema_HIPMACParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        hip_mac = Data_HIPMACParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            hmac=schema.hmac,
        )
        return hip_mac

    def _read_param_hip_mac_2(self, schema: 'Schema_HIPMAC2Parameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        hip_mac_2 = Data_HIPMAC2Parameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            hmac=schema.hmac,
        )
        return hip_mac_2

    def _read_param_hip_signature_2(self, schema: 'Schema_HIPSignature2Parameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        hip_signature_2 = Data_HIPSignature2Parameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            algorithm=schema.algorithm,
            signature=schema.signature,
        )
        return hip_signature_2

    def _read_param_hip_signature(self, schema: 'Schema_HIPSignatureParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        hip_signature = Data_HIPSignatureParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            algorithm=schema.algorithm,
            signature=schema.signature,
        )
        return hip_signature

    def _read_param_echo_request_unsigned(self, schema: 'Schema_EchoRequestUnsignedParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        echo_request_unsigned = Data_EchoRequestUnsignedParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            opaque=schema.opaque,
        )
        return echo_request_unsigned

    def _read_param_echo_response_unsigned(self, schema: 'Schema_EchoResponseUnsignedParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        echo_response_unsigned = Data_EchoResponseUnsignedParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            opaque=schema.opaque,
        )
        return echo_response_unsigned

    def _read_param_relay_from(self, schema: 'Schema_RelayFromParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``schema.len`` is **NOT** ``20``.

        """
        if schema.len != 20:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

        address = ipaddress.ip_address(schema.address)
        schema.address = address  # type: ignore[assignment]

        relay_from = Data_RelayFromParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            port=schema.port,
            protocol=schema.protocol,
            address=address,  # type: ignore[arg-type]
        )
        return relay_from

    def _read_param_relay_to(self, schema: 'Schema_RelayToParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``schema.len`` is **NOT** ``20``.

        """
        if schema.len != 20:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

        address = ipaddress.ip_address(schema.address)
        schema.address = address  # type: ignore[assignment]

        relay_to = Data_RelayToParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            port=schema.port,
            protocol=schema.protocol,
            address=address,  # type: ignore[arg-type]
        )
        return relay_to

    def _read_param_overlay_ttl(self, schema: 'Schema_OverlayTTLParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``schema.len`` is **NOT** ``4``.

        """
        if schema.len != 4:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

        overlay_ttl = Data_OverlayTTLParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            ttl=datetime.timedelta(seconds=schema.ttl),
        )
        return overlay_ttl

    def _read_param_route_via(self, schema: 'Schema_RouteViaParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If the parameter is malformed.

        """
        if (schema.len - 4) % 16 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

        route_via = Data_RouteViaParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            flags=Data_Flags(
                symmetric=bool(schema.flags['symmetric']),
                must_follow=bool(schema.flags['must_follow']),
            ),
            hit=tuple(schema.hit),
        )
        return route_via

    def _read_param_from(self, schema: 'Schema_FromParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``schema.len`` is **NOT** ``16``.

        """
        if schema.len != 16:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

        from_ = Data_FromParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            address=schema.address,
        )
        return from_

    def _read_param_rvs_hmac(self, schema: 'Schema_RVSHMACParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        rvs_hmac = Data_RVSHMACParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            hmac=schema.hmac,
        )
        return rvs_hmac

    def _read_param_via_rvs(self, schema: 'Schema_ViaRVSParameter', *, version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``schema.len`` is **NOT** ``16`` modulo.

        """
        if schema.len % 16 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {schema.type}] invalid format')

        via_rvs = Data_ViaRVSParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            address=tuple(schema.address),
        )
        return via_rvs

    def _read_param_relay_hmac(self, schema: 'Schema_RelayHMACParameter', version: 'int',  # pylint: disable=unused-argument
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
            schema: parsed parameter schama
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        relay_hmac = Data_RelayHMACParameter(
            type=schema.type,
            critical=bool(schema.type & 0b1),
            length=4 + schema.len + (8 - schema.len % 8) % 8,
            hmac=schema.hmac,
        )
        return relay_hmac

    def _make_hip_param(self, parameters: 'list[Schema_Parameter | tuple[Enum_Parameter, dict[str, Any]] | bytes] | Parameter', *,
                        version: 'int') -> 'tuple[list[Schema_Parameter | bytes], int]':
        """Make HIP parameter.

        Args:
            parameters: HIP parameters
            version: HIP protocol version

        Returns:
            HIP parameters and total length.

        """
        total_length = 0
        if isinstance(parameters, list):
            parameters_list = []  # type: list[Schema_Parameter | bytes]
            for schema in parameters:
                if isinstance(schema, bytes):
                    parameters_list.append(schema)
                    total_length += len(schema)
                elif isinstance(schema, Schema):
                    schema_packed = schema.pack()

                    parameters_list.append(schema_packed)
                    total_length += len(schema_packed)
                else:
                    code, args = cast('tuple[Enum_Parameter, dict[str, Any]]', schema)
                    meth_name = f'_make_param_{code.name.lower()}'
                    meth = cast('ParameterConstructor',
                                getattr(self, meth_name, self._make_param_unassigned))

                    data = meth(code, version=version, **args)  # type: Schema_Parameter
                    data_packed = data.pack()

                    parameters_list.append(data)
                    total_length += len(data_packed)
            return parameters_list, total_length

        parameters_list = []
        for code, param in parameters.items(multi=True):
            meth_name = f'_make_param_{code.name.lower()}'
            meth = cast('ParameterConstructor',
                        getattr(self, meth_name, self._make_param_unassigned))

            data = meth(code, param, version=version)
            data_packed = data.pack()

            parameters_list.append(data)
            total_length += len(data_packed)
        return parameters_list, total_length

    def _make_param_unassigned(self, code: 'Enum_Parameter', param: 'Optional[Data_UnassignedParameter]' = None, *,  # pylint: disable=unused-argument
                               version: 'int',
                               contents: 'bytes' = b'',
                               **kwargs: 'Any') -> 'Schema_UnassignedParameter':
        """Make HIP unassigned parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            contents: parameter contents
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            contents = param.contents

        return Schema_UnassignedParameter(
            type=code,
            len=len(contents),
            value=contents,
        )

    def _make_param_esp_info(self, code: 'Enum_Parameter', param: 'Optional[Data_ESPInfoParameter]' = None, *,  # pylint: disable=unused-argument
                             version: 'int',
                             index: 'int' = 0,
                             old_spi: 'int' = 0,
                             new_spi: 'int' = 0,
                             **kwargs: 'Any') -> 'Schema_ESPInfoParameter':
        """Make HIP ``ESP_INFO`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            index: KEYMAT index
            old_spi: old SPI
            new_spi: new SPI
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            index = param.index
            old_spi = param.old_spi
            new_spi = param.new_spi

        return Schema_ESPInfoParameter(
            type=code,
            len=12,
            index=index,
            old_spi=old_spi,
            new_spi=new_spi,
        )

    def _make_param_r1_counter(self, code: 'Enum_Parameter', param: 'Optional[Data_R1CounterParameter]' = None, *, # pylint: disable=unused-argument
                               version: 'int',
                               counter: 'int' = 0,
                               **kwargs: 'Any') -> 'Schema_R1CounterParameter':
        """Make HIP ``R1_COUNTER`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            counter: R1 generation counter
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if code == Enum_Parameter.R1_Counter and version != 1:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid parameter')

        if param is not None:
            counter = param.counter

        return Schema_R1CounterParameter(
            type=code,
            len=12,
            counter=counter,
        )

    def _make_param_locator_set(self, code: 'Enum_Parameter', param: 'Optional[Data_LocatorSetParameter]' = None, *,  # pylint: disable=unused-argument
                                version: 'int',
                                locator_set: 'Optional[list[Data_Locator | Locator]]' = None,
                                **kwargs: 'Any') -> 'Schema_LocatorSetParameter':
        """Make HIP ``LOCATOR_SET`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            locator_set: locators data
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        def _make_locator(locator: 'Optional[Data_Locator]' = None, *,
                          traffic: 'int' = 0,
                          type: 'int' = 0,
                          preferred: 'bool' = False,
                          lifetime: 'timedelta | int' = 0,
                          ip: 'IPv6Address | bytes | int | str' = '::',
                          spi: 'Optional[int]' = None,
                          **kwargs: 'Any') -> 'Schema_Locator':
            """Make locator data.

            Args:
                locator: locator data
                traffic: traffic type
                type: locator type
                preferred: preferred flag
                lifetime: lifetime
                ip: IP address
                spi: SPI
                **kwargs: arbitrary keyword arguments

            Returns:
                HIP locator schema.

            """
            if locator is not None:
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

                traffic = locator.traffic
                type = locator.type
                length = locator.length // 4
                preferred = locator.preferred
                lifetime = math.floor(locator.lifetime.total_seconds())
            else:
                if spi is None:
                    length = 4
                    data = ipaddress.IPv6Address(ip).packed
                else:
                    length = 5
                    data = Schema_LocatorData(
                        spi=spi,
                        ip=ipaddress.IPv6Address(ip).packed,
                    )

                if isinstance(lifetime, timedelta):
                    lifetime = math.floor(lifetime.total_seconds())

            return Schema_Locator(
                traffic=traffic,
                type=type,
                len=length,
                flags={
                    'preferred': preferred,
                },
                lifetime=lifetime,
                value=data,
            )

        if param is not None:
            locators = [_make_locator(locator) for locator in param.locator_set]
        else:
            if locator_set is None:
                locator_set = []
            locators = [_make_locator(**locator) for locator in locator_set]

        return Schema_LocatorSetParameter(
            type=code,
            len=sum(locator['len'] for locator in locators),
            locators=locators,
        )

    def _make_param_puzzle(self, code: 'Enum_Parameter', param: 'Optional[Data_PuzzleParameter]' = None, *,  # pylint: disable=unused-argument
                           version: 'int',
                           index: 'int' = 0,
                           lifetime: 'timedelta | int' = 0,
                           opaque: 'bytes' = b'',
                           random: 'int' = 0,
                           **kwargs: 'Any') -> 'Schema_PuzzleParameter':
        """Make HIP ``PUZZLE`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            index: #K index
            lifetime: lifetime
            opaque: opaque data
            random: random #I value
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            index = param.index
            lifetime = math.floor(math.log2(param.lifetime.total_seconds()) + 32)
            opaque = param.opaque
            random = param.random
        else:
            lifetime = math.floor(math.log2(
                lifetime if isinstance(lifetime, int) else lifetime.total_seconds()
            ) + 32)

        return Schema_PuzzleParameter(
            type=code,
            len=4 + math.ceil(random.bit_length() / 8),
            index=index,
            lifetime=lifetime,
            opaque=opaque,
            random=random,
        )

    def _make_param_solution(self, code: 'Enum_Parameter', param: 'Optional[Data_SolutionParameter]' = None, *,  # pylint: disable=unused-argument
                             version: 'int',
                             index: 'int' = 0,
                             lifetime: 'timedelta | int' = 0,
                             opaque: 'bytes' = b'',
                             random: 'int' = 0,
                             solution: 'int' = 0,
                             **kwargs: 'Any') -> 'Schema_SolutionParameter':
        """Make HIP ``SOLUTION`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            index: #K index
            lifetime: lifetime
            opaque: opaque data
            random: random #I value
            solution: solution #J value

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            index = param.index
            lifetime = math.floor(math.log2(param.lifetime.total_seconds()) + 32)
            opaque = param.opaque
            random = param.random
            solution = param.solution
        else:
            lifetime = math.floor(math.log2(
                lifetime if isinstance(lifetime, int) else lifetime.total_seconds()
            ) + 32)

        return Schema_SolutionParameter(
            type=code,
            len=4 + math.ceil(max(random.bit_length(), solution.bit_length()) / 4),
            index=index,
            lifetime=lifetime,
            opaque=opaque,
            random=random,
            solution=solution,
        )

    def _make_param_seq(self, code: 'Enum_Parameter', param: 'Optional[Data_SEQParameter]' = None, *,  # pylint: disable=unused-argument
                        version: 'int',
                        update_id: 'int' = 0,
                        **kwargs: 'Any') -> 'Schema_SEQParameter':
        """Make HIP ``SEQ`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            update_id: update ID

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            update_id = param.id

        return Schema_SEQParameter(
            type=code,
            len=4,
            update_id=update_id,
        )

    def _make_param_ack(self, code: 'Enum_Parameter', param: 'Optional[Data_ACKParameter]' = None, *,  # pylint: disable=unused-argument
                        version: 'int',
                        update_id: 'Optional[list[int]]' = None,
                        **kwargs: 'Any') -> 'Schema_ACKParameter':
        """Make HIP ``ACK`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            update_id: list of update ID

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            id_list = cast('list[int]', param.update_id)
        else:
            if update_id is None:
                update_id = []
            id_list = update_id

        return Schema_ACKParameter(
            type=code,
            len=4 * len(id_list),
            update_id=id_list,
        )

    def _make_param_dh_group_list(self, code: 'Enum_Parameter', param: 'Optional[Data_DHGroupListParameter]' = None, *,  # pylint: disable=unused-argument
                                  version: 'int',
                                  groups: 'Optional[list[Enum_Group | StdlibEnum | AenumEnum | str | int]]' = None,
                                  group_default: 'Optional[int]' = None,
                                  group_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                                  group_reversed: 'bool' = False,
                                  **kwargs: 'Any') -> 'Schema_DHGroupListParameter':
        """Make HIP ``DH_GROUP_LIST`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            groups: list of group ID
            group_default: default group ID
            group_namespace: group ID namespace
            group_reversed: reverse group ID namespace
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            group_id = cast('list[Enum_Group]', param.group_id)
        else:
            if groups is None:
                groups = []

            group_id = []
            for group in groups:
                group_id.append(self._make_index(group, group_default, namespace=group_namespace,  # type: ignore[arg-type]
                                                 reversed=group_reversed, pack=False))

        return Schema_DHGroupListParameter(
            type=code,
            len=len(group_id),
            groups=group_id,
        )

    def _make_param_diffie_hellman(self, code: 'Enum_Parameter', param: 'Optional[Data_DiffieHellmanParameter]' = None, *,  # pylint: disable=unused-argument
                                   version: 'int',
                                   group: 'Enum_Group | StdlibEnum | AenumEnum | str | int' = Enum_Group.NIST_P_256,
                                   group_default: 'Optional[int]' = None,
                                   group_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                                   group_reversed: 'bool' = False,
                                   pub_val: 'int' = 0,
                                   **kwargs: 'Any') -> 'Schema_DiffieHellmanParameter':
        """Make HIP ``DIFFIE_HELLMAN`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            group: group ID
            group_default: default group ID
            group_namespace: group ID namespace
            group_reversed: reverse group ID namespace
            pub_val: public value
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            group_id = param.group_id
            pub_len = param.pub_len
            pub_val = param.pub_val
        else:
            group_id = self._make_index(group, group_default, namespace=group_namespace,  # type: ignore[assignment]
                                     reversed=group_reversed, pack=False)
            pub_len = math.ceil(pub_val.bit_length() / 8)

        return Schema_DiffieHellmanParameter(
            type=code,
            len=3 + pub_len,
            group=group_id,
            pub_len=pub_len,
            pub_val=pub_val,
        )

    def _make_param_hip_transform(self, code: 'Enum_Parameter', param: 'Optional[Data_HIPTransformParameter]' = None, *,  # pylint: disable=unused-argument
                                  version: 'int',
                                  suites: 'Optional[list[Enum_Suite | StdlibEnum | AenumEnum | str | int]]' = None,
                                  suite_default: 'Optional[int]' = None,
                                  suite_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                                  suite_reversed: 'bool' = False,
                                  **kwargs: 'Any') -> 'Schema_HIPTransformParameter':
        """Make HIP ``HIP_TRANSFORM`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            suites: list of suite ID
            suite_default: default suite ID
            suite_namespace: suite ID namespace
            suite_reversed: reverse suite ID namespace
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            suite_id = cast('list[Enum_Suite]', param.suite_id)
        else:
            if suites is None:
                suites = []

            suite_id = []
            for suite in suites:
                suite_id.append(self._make_index(suite, suite_default, namespace=suite_namespace,  # type: ignore[arg-type]
                                                 reversed=suite_reversed, pack=False))

        return Schema_HIPTransformParameter(
            type=code,
            len=2 * len(suite_id),
            suites=suite_id,
        )

    def _make_param_hip_cipher(self, code: 'Enum_Parameter', param: 'Optional[Data_HIPCipherParameter]' = None, *,  # pylint: disable=unused-argument
                               version: 'int',
                               ciphers: 'Optional[list[Enum_Cipher | StdlibEnum | AenumEnum | str | int]]' = None,
                               cipher_default: 'Optional[int]' = None,
                               cipher_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                               cipher_reversed: 'bool' = False,
                               **kwargs: 'Any') -> 'Schema_HIPCipherParameter':
        """Make HIP ``HIP_CIPHER`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            ciphers: list of cipher ID
            cipher_default: default cipher ID
            cipher_namespace: cipher ID namespace
            cipher_reversed: reverse cipher ID namespace
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            cipher_id = cast('list[Enum_Cipher]', param.cipher_id)
        else:
            if ciphers is None:
                ciphers = []

            cipher_id = []
            for cipher in ciphers:
                cipher_id.append(self._make_index(cipher, cipher_default, namespace=cipher_namespace,  # type: ignore[arg-type]
                                                  reversed=cipher_reversed, pack=False))

        return Schema_HIPCipherParameter(
            type=code,
            len=2 * len(cipher_id),
            ciphers=cipher_id,
        )

    def _make_param_nat_traversal_mode(self, code: 'Enum_Parameter', param: 'Optional[Data_NATTraversalModeParameter]' = None, *,  # pylint: disable=unused-argument
                                       version: 'int',
                                       modes: 'Optional[list[Enum_NATTraversal | StdlibEnum | AenumEnum | str | int]]' = None,
                                       mode_default: 'Optional[int]' = None,
                                       mode_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                                       mode_reversed: 'bool' = False,
                                       **kwargs: 'Any') -> 'Schema_NATTraversalModeParameter':
        """Make HIP ``NAT_TRAVERSAL_MODE`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            modes: list of mode ID
            mode_default: default mode ID
            mode_namespace: mode ID namespace
            mode_reversed: reverse mode ID namespace
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            mode_id = cast('list[Enum_NATTraversal]', param.mode_id)
        else:
            if modes is None:
                modes = []

            mode_id = []
            for mode in modes:
                mode_id.append(self._make_index(mode, mode_default, namespace=mode_namespace,  # type: ignore[arg-type]
                                                reversed=mode_reversed, pack=False))

        return Schema_NATTraversalModeParameter(
            type=code,
            len=2 + 2 * len(mode_id),
            modes=mode_id,
        )

    def _make_param_transaction_pacing(self, code: 'Enum_Parameter', param: 'Optional[Data_TransactionPacingParameter]' = None, *,  # pylint: disable=unused-argument
                                       version: 'int',
                                       min_ta: 'int' = 0,
                                       **kwargs: 'Any') -> 'Schema_TransactionPacingParameter':
        """Make HIP ``TRANSACTION_PACING`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            min_ta: minimum time between transactions
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            min_ta = param.min_ta

        return Schema_TransactionPacingParameter(
            type=code,
            len=4,
            min_ta=min_ta,
        )

    def _make_param_encrypted(self, code: 'Enum_Parameter', param: 'Optional[Data_EncryptedParameter]' = None, *,  # pylint: disable=unused-argument
                              version: 'int',
                              cipher: 'Enum_Cipher | StdlibEnum | AenumEnum | str | int' = Enum_Cipher.NULL_ENCRYPT,
                              cipher_default: 'Optional[int]' = None,
                              cipher_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                              cipher_reversed: 'bool' = False,
                              iv: 'Optional[bytes]' = None,
                              data: 'bytes' = b'',
                              **kwargs: 'Any') -> 'Schema_EncryptedParameter':
        """Make HIP ``ENCRYPTED`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            cipher: cipher ID
            cipher_default: default cipher ID
            cipher_namespace: cipher ID namespace
            cipher_reversed: reverse cipher ID namespace
            iv: initialization vector (optional depending on cipher ID)
            data: encrypted data

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            cipher_id = param.cipher
            iv = param.iv
            data = param.data
        else:
            cipher_id = self._make_index(cipher, cipher_default, namespace=cipher_namespace,  # type: ignore[assignment]
                                         reversed=cipher_reversed, pack=False)

        if cipher_id in (Enum_Cipher.AES_128_CBC, Enum_Cipher.AES_256_CBC):
            if iv is None:
                raise ProtocolError(f'HIPv{version}: [ParamNo {code}] IV is required for AES cipher')
            if len(iv) != 16:
                raise ProtocolError(f'HIPv{version}: [ParamNo {code}] IV length must be 16 bytes for AES cipher')

        return Schema_EncryptedParameter(
            type=code,
            len=4 + len(iv or b'') + len(data),
            cipher=cipher_id,
            iv=iv,
            data=data,
        )

    def _make_param_host_id(self, code: 'Enum_Parameter', param: 'Optional[Data_HostIDParameter]' = None, *,  # pylint: disable=unused-argument
                            version: 'int',
                            hi: 'Optional[Data_HostIdentity | bytes | Schema_HostIdentity]' = None,
                            hi_curve: 'Optional[Enum_ECDSACurve | Enum_ECDSALowCurve | Enum_EdDSACurve]' = None,  # pylint: disable=line-too-long
                            hi_pub_key: 'bytes' = b'',
                            hi_algorithm: 'Enum_HIAlgorithm | StdlibEnum | AenumEnum | str | int' = Enum_HIAlgorithm.NULL_ENCRYPT,
                            hi_algorithm_default: 'Optional[int]' = None,
                            hi_algorithm_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                            hi_algorithm_reversed: 'bool' = False,
                            di: 'bytes' = b'',
                            di_type: 'Enum_DITypes | StdlibEnum | AenumEnum | str | int' = Enum_DITypes.none_included,
                            di_type_default: 'Optional[int]' = None,
                            di_type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                            di_type_reversed: 'bool' = False,
                            **kwargs: 'Any') -> 'Schema_HostIDParameter':
        """Make HIP ``HOST_ID`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            hi: host identity
            hi_curve: host identity curve
            hi_pub_key: host identity public key
            hi_algorithm: host identity algorithm
            hi_algorithm_default: default host identity algorithm
            hi_algorithm_namespace: host identity algorithm namespace
            hi_algorithm_reversed: reverse host identity algorithm namespace
            di: domain identifier
            di_type: domain identifier type
            di_type_default: default domain identifier type
            di_type_namespace: domain identifier type namespace
            di_type_reversed: reverse domain identifier type namespace
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            hi = param.hi
            di = param.di
            hi_len = param.hi_len
            di_len = param.di_len
            di_enum = param.di_type
            algorithm = param.algorithm  # type: int | Enum_HIAlgorithm
        else:
            di_len = len(di)
            di_enum = self._make_index(di_type, di_type_default, namespace=di_type_namespace,  # type: ignore[assignment]
                                       reversed=di_type_reversed, pack=False)
            algorithm = self._make_index(hi_algorithm, hi_algorithm_default, namespace=hi_algorithm_namespace,
                                         reversed=hi_algorithm_reversed, pack=False)

        if hi is None:
            hi_len = 2 + len(hi_pub_key)

            if isinstance(hi_curve, Enum_ECDSACurve):
                hi_data = Schema_ECDSACurveHostIdentity(
                    curve=hi_curve,
                    pub_key=hi_pub_key,
                )  # type: Schema_HostIdentity | bytes
                algorithm = Enum_HIAlgorithm.ECDSA
            elif isinstance(hi_curve, Enum_ECDSALowCurve):
                hi_data = Schema_ECDSALowCurveHostIdentity(
                    curve=hi_curve,
                    pub_key=hi_pub_key,
                )
                algorithm = Enum_HIAlgorithm.ECDSA_LOW
            elif isinstance(hi_curve, Enum_EdDSACurve):
                hi_data = Schema_EdDSACurveHostIdentity(
                    curve=hi_curve,
                    pub_key=hi_pub_key,
                )
                algorithm = Enum_HIAlgorithm.EdDSA
            else:
                raise ProtocolError(f'[HIPv{version}] invalid curve: {hi_curve!r}')
        else:
            if isinstance(hi, Data_HostIdentity):
                hi_len = 2 + len(hi.pubkey)
                if isinstance(hi.curve, Enum_ECDSACurve):
                    hi_data = Schema_ECDSACurveHostIdentity(
                        curve=hi.curve,
                        pub_key=hi.pubkey,
                    )
                    algorithm = Enum_HIAlgorithm.ECDSA
                elif isinstance(hi.curve, Enum_ECDSALowCurve):
                    hi_data = Schema_ECDSALowCurveHostIdentity(
                        curve=hi.curve,
                        pub_key=hi.pubkey,
                    )
                    algorithm = Enum_HIAlgorithm.ECDSA_LOW
                elif isinstance(hi.curve, Enum_EdDSACurve):
                    hi_data = Schema_EdDSACurveHostIdentity(
                        curve=hi.curve,
                        pub_key=hi.pubkey,
                    )
                    algorithm = Enum_HIAlgorithm.EdDSA
                else:
                    raise ProtocolError(f'[HIPv{version}] invalid curve: {hi.curve!r}')
            elif isinstance(hi, Schema_HostIdentity):
                hi_len = 2 + len(hi.pub_key)
                hi_data = hi
            else:
                hi_len = len(hi)
                hi_data = hi

        return Schema_HostIDParameter(
            type=code,
            len=6 + hi_len + di_len,
            hi_len=hi_len,
            di_data={
                'type': di_enum,
                'len': di_len,
            },
            algorithm=algorithm,  # type: ignore[arg-type]
            hi=hi_data,
            di=di,
        )

    def _make_param_hit_suite_list(self, code: 'Enum_Parameter', param: 'Optional[Data_HITSuiteListParameter]' = None, *,  # pylint: disable=unused-argument
                                   version: 'int',
                                   suites: 'Optional[list[Enum_HITSuite | StdlibEnum | AenumEnum | str | int]]' = None,
                                   suite_default: 'Optional[int]' = None,
                                   suite_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                                   suite_reversed: 'bool' = False,
                                   **kwargs: 'Any') -> 'Schema_HITSuiteListParameter':
        """Make HIP ``HIT_SUITE_LIST`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            suites: list of suites
            suite_default: default suite
            suite_namespace: suite namespace
            suite_reversed: reverse suite namespace

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            suite_id = cast('list[Enum_HITSuite]', param.suite_id)
        else:
            if suites is None:
                suites = []

            suite_id = []
            for suite in suites:
                suite_id.append(self._make_index(suite, suite_default, namespace=suite_namespace,  # type: ignore[arg-type]
                                                 reversed=suite_reversed, pack=False))

        return Schema_HITSuiteListParameter(
            type=code,
            len=len(suite_id),
            suites=suite_id,
        )

    def _make_param_cert(self, code: 'Enum_Parameter', param: 'Optional[Data_CertParameter]' = None, *,  # pylint: disable=unused-argument
                         version: 'int',
                         cert_group: 'Enum_Group | StdlibEnum | AenumEnum | str | int' = Enum_Group.NIST_P_256,
                         cert_group_default: 'Optional[int]' = None,
                         cert_group_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                         cert_group_reversed: 'bool' = False,
                         cert_count: 'int' = 0,
                         cert_id: 'int' = 0,
                         cert_type: 'Enum_Certificate | StdlibEnum | AenumEnum | str | int' = Enum_Certificate.X_509_v3,
                         cert_type_default: 'Optional[int]' = None,
                         cert_type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                         cert_type_reversed: 'bool' = False,
                         cert: 'bytes' = b'',
                         **kwargs: 'Any') -> 'Schema_CertParameter':
        """Make HIP ``CERT`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            cert_group: certificate group
            cert_group_default: default certificate group
            cert_group_namespace: certificate group namespace
            cert_group_reversed: reverse certificate group namespace
            cert_count: certificate count
            cert_id: certificate ID
            cert_type: certificate type
            cert_type_default: default certificate type
            cert_type_namespace: certificate type namespace
            cert_type_reversed: reverse certificate type namespace
            cert: certificate data
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            group = param.cert_group
            count = param.cert_count
            id = param.cert_id
            type = param.cert_type
            cert = param.cert
        else:
            group = self._make_index(cert_group, cert_group_default, namespace=cert_group_namespace,  # type: ignore[assignment]
                                     reversed=cert_group_reversed, pack=False)
            count = cert_count
            id = cert_id
            type = self._make_index(cert_type, cert_type_default, namespace=cert_type_namespace,  # type: ignore[assignment]
                                    reversed=cert_type_reversed, pack=False)

        return Schema_CertParameter(
            type=code,
            len=4 + len(cert),
            cert_group=group,
            cert_count=count,
            cert_id=id,
            cert_type=type,
            cert=cert,
        )

    def _make_param_notification(self, code: 'Enum_Parameter', param: 'Optional[Data_NotificationParameter]' = None, *,  # pylint: disable=unused-argument
                                 version: 'int',
                                 msg_type: 'Enum_NotifyMessage | StdlibEnum | AenumEnum | str | int' = Enum_NotifyMessage.I2_ACKNOWLEDGEMENT,
                                 msg_type_default: 'Optional[int]' = None,
                                 msg_type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                                 msg_type_reversed: 'bool' = False,
                                 msg: 'bytes' = b'',
                                 **kwargs: 'Any') -> 'Schema_NotificationParameter':
        """Make HIP ``NOTIFICATION`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            msg_type: notification message type
            msg_type_default: default notification message type
            msg_type_namespace: notification message type namespace
            msg_type_reversed: reverse notification message type namespace
            msg: notification message
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            type = param.msg_type
            msg = param.msg
        else:
            type = self._make_index(msg_type, msg_type_default, namespace=msg_type_namespace,  # type: ignore[assignment]
                                    reversed=msg_type_reversed, pack=False)

        return Schema_NotificationParameter(
            type=code,
            len=4 + len(msg),
            msg_type=type,
            msg=msg,
        )

    def _make_param_echo_request_signed(self, code: 'Enum_Parameter', param: 'Optional[Data_EchoRequestSignedParameter]' = None, *,  # pylint: disable=unused-argument
                                        version: 'int',
                                        opaque: 'bytes' = b'',
                                        **kwargs: 'Any') -> 'Schema_EchoRequestSignedParameter':
        """Make HIP ``ECHO_REQUEST_SIGNED`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            opaque: opaque data
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            opaque = param.opaque

        return Schema_EchoRequestSignedParameter(
            type=code,
            len=len(opaque),
            opaque=opaque,
        )

    def _make_param_reg_info(self, code: 'Enum_Parameter', param: 'Optional[Data_RegInfoParameter]' = None, *,  # pylint: disable=unused-argument
                             version: 'int',
                             min_lifetime: 'int | timedelta' = 0,
                             max_lifetime: 'int | timedelta' = 0xf,
                             reg_info: 'Optional[list[Enum_Registration | StdlibEnum | AenumEnum | str | int]]' = None,
                             reg_info_default: 'Optional[int]' = None,
                             reg_info_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                             reg_info_reversed: 'bool' = False,
                             **kwargs: 'Any') -> 'Schema_RegInfoParameter':
        """Make HIP ``REG_INFO`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            min_lifetime: minimum lifetime
            max_lifetime: maximum lifetime
            reg_info: registration information list
            reg_info_default: default registration information
            reg_info_namespace: registration information namespace
            reg_info_reversed: reverse registration information namespace
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            reg_type = cast('list[Enum_Registration]', param.reg_type)
            min_lt = math.floor(param.lifetime.min.total_seconds())
            max_lt = math.floor(param.lifetime.max.total_seconds())
        else:
            if reg_info is None:
                reg_info = []

            reg_type = []
            for reg in reg_info:
                reg_type.append(self._make_index(reg, reg_info_default, namespace=reg_info_namespace,  # type: ignore[arg-type]
                                                 reversed=reg_info_reversed, pack=False))

            min_lt = min_lifetime if isinstance(min_lifetime, int) else math.floor(min_lifetime.total_seconds())
            max_lt = max_lifetime if isinstance(max_lifetime, int) else math.floor(max_lifetime.total_seconds())

        return Schema_RegInfoParameter(
            type=code,
            len=2 + len(reg_type),
            min_lifetime=min_lt,
            max_lifetime=max_lt,
            reg_info=reg_type,
        )

    def _make_param_reg_request(self, code: 'Enum_Parameter', param: 'Optional[Data_RegRequestParameter]' = None, *,  # pylint: disable=unused-argument
                                version: 'int',
                                lifetime: 'int | timedelta' = 0,
                                reg_request: 'Optional[list[Enum_Registration | StdlibEnum | AenumEnum | str | int]]' = None,
                                reg_request_default: 'Optional[int]' = None,
                                reg_request_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                                reg_request_reversed: 'bool' = False,
                                **kwargs: 'Any') -> 'Schema_RegRequestParameter':
        """Make HIP ``REG_REQUEST`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            lifetime: lifetime
            reg_request: registration request list
            reg_request_default: default registration request
            reg_request_namespace: registration request namespace
            reg_request_reversed: reverse registration request namespace
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            reg_type = cast('list[Enum_Registration]', param.reg_type)
            lt = math.floor(param.lifetime.total_seconds())
        else:
            if reg_request is None:
                reg_request = []

            reg_type = []
            for reg in reg_request:
                reg_type.append(self._make_index(reg, reg_request_default, namespace=reg_request_namespace,  # type: ignore[arg-type]
                                                 reversed=reg_request_reversed, pack=False))

            lt = lifetime if isinstance(lifetime, int) else math.floor(lifetime.total_seconds())

        return Schema_RegRequestParameter(
            type=code,
            len=1 + len(reg_type),
            lifetime=lt,
            reg_request=reg_type,
        )

    def _make_param_reg_response(self, code: 'Enum_Parameter', param: 'Optional[Data_RegResponseParameter]' = None, *,  # pylint: disable=unused-argument
                                 version: 'int',
                                 lifetime: 'int | timedelta' = 0,
                                 reg_response: 'Optional[list[Enum_Registration | StdlibEnum | AenumEnum | str | int]]' = None,
                                 reg_response_default: 'Optional[int]' = None,
                                 reg_response_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                                 reg_response_reversed: 'bool' = False,
                                 **kwargs: 'Any') -> 'Schema_RegResponseParameter':
        """Make HIP ``REG_RESPONSE`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            reg_type = cast('list[Enum_Registration]', param.reg_type)
            lt = math.floor(param.lifetime.total_seconds())
        else:
            if reg_response is None:
                reg_response = []

            reg_type = []
            for reg in reg_response:
                reg_type.append(self._make_index(reg, reg_response_default, namespace=reg_response_namespace,  # type: ignore[arg-type]
                                                 reversed=reg_response_reversed, pack=False))

            lt = lifetime if isinstance(lifetime, int) else math.floor(lifetime.total_seconds())

        return Schema_RegResponseParameter(
            type=code,
            len=1 + len(reg_type),
            lifetime=lt,
            reg_response=reg_type,
        )

    def _make_param_reg_failed(self, code: 'Enum_Parameter', param: 'Optional[Data_RegFailedParameter]' = None, *,  # pylint: disable=unused-argument
                               version: 'int',
                               lifetime: 'int | timedelta' = 0,
                               reg_failed: 'Optional[list[Enum_RegistrationFailure | StdlibEnum | AenumEnum | str | int]]' = None,
                               reg_failed_default: 'Optional[int]' = None,
                               reg_failed_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                               reg_failed_reversed: 'bool' = False,
                               **kwargs: 'Any') -> 'Schema_RegFailedParameter':
        """Make HIP ``REG_FAILED`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            lifetime: lifetime
            reg_failed: registration failure list
            reg_failed_default: default registration failure
            reg_failed_namespace: registration failure namespace
            reg_failed_reversed: reverse registration failure namespace

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            reg_type = cast('list[Enum_RegistrationFailure]', param.reg_type)
            lt = math.floor(param.lifetime.total_seconds())
        else:
            if reg_failed is None:
                reg_failed = []

            reg_type = []
            for reg in reg_failed:
                reg_type.append(self._make_index(reg, reg_failed_default, namespace=reg_failed_namespace,  # type: ignore[arg-type]
                                                 reversed=reg_failed_reversed, pack=False))

            lt = lifetime if isinstance(lifetime, int) else math.floor(lifetime.total_seconds())

        return Schema_RegFailedParameter(
            type=code,
            len=1 + len(reg_type),
            lifetime=lt,
            reg_failed=reg_type,
        )

    def _make_param_reg_from(self, code: 'Enum_Parameter', param: 'Optional[Data_RegFromParameter]' = None, *,  # pylint: disable=unused-argument
                             version: 'int',
                             port: 'int' = 0,
                             protocol: 'Enum_TransType | StdlibEnum | AenumEnum | str | int' = Enum_TransType.UDP,
                             protocol_default: 'Optional[int]' = None,
                             protocol_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                             protocol_reversed: 'bool' = False,
                             address: 'IPv6Address | str | int | bytes' = '::',
                             **kwargs: 'Any') -> 'Schema_RegFromParameter':
        """Make HIP ``REG_FROM`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            port: port number
            protocol: transport protocol
            protocol_default: default transport protocol
            protocol_namespace: transport protocol namespace
            protocol_reversed: reverse transport protocol namespace
            address: IPv6 address
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            port = param.port
            proto = param.protocol
            address = param.address
        else:
            proto = self._make_index(protocol, protocol_default, namespace=protocol_namespace,  # type: ignore[assignment]
                                     reversed=protocol_reversed, pack=False)

        return Schema_RegFromParameter(
            type=code,
            len=20,
            port=port,
            protocol=proto,
            address=address,
        )

    def _make_param_echo_response_signed(self, code: 'Enum_Parameter', param: 'Optional[Data_EchoResponseSignedParameter]' = None, *,  # pylint: disable=unused-argument
                                         version: 'int',
                                         opaque: 'bytes' = b'',
                                         **kwargs: 'Any') -> 'Schema_EchoResponseSignedParameter':
        """Make HIP ``ECHO_RESPONSE_SIGNED`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            opaque: opaque data
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            opaque = param.opaque

        return Schema_EchoResponseSignedParameter(
            type=code,
            len=len(opaque),
            opaque=opaque,
        )

    def _make_param_transport_format_list(self, code: 'Enum_Parameter', param: 'Optional[Data_TransportFormatListParameter]' = None, *,  # pylint: disable=unused-argument
                                          version: 'int',
                                          formats: 'Optional[list[Enum_Parameter | StdlibEnum | AenumEnum | str | int]]' = None,
                                          format_default: 'Optional[int]' = None,
                                          format_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                                          format_reversed: 'bool' = False,
                                          **kwargs: 'Any') -> 'Schema_TransportFormatListParameter':
        """Make HIP ``TRANSPORT_FORMAT_LIST`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            formats: transport format list
            format_default: default transport format
            format_namespace: transport format namespace
            format_reversed: reverse transport format namespace
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            tf_type = cast('list[Enum_Parameter]', param.tf_type)
        else:
            if formats is None:
                formats = []

            tf_type = []
            for tf in formats:
                tf_type.append(self._make_index(tf, format_default, namespace=format_namespace,  # type: ignore[arg-type]
                                                reversed=format_reversed, pack=False))

        return Schema_TransportFormatListParameter(
            type=code,
            len=2 * len(tf_type),
            formats=tf_type,
        )

    def _make_param_esp_transform(self, code: 'Enum_Parameter', param: 'Optional[Data_ESPTransformParameter]' = None, *,  # pylint: disable=unused-argument
                                  version: 'int',
                                  suites: 'Optional[list[Enum_ESPTransformSuite | StdlibEnum | AenumEnum | str | int]]' = None,
                                  suite_default: 'Optional[int]' = None,
                                  suite_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                                  suite_reversed: 'bool' = False,
                                  **kwargs: 'Any') -> 'Schema_ESPTransformParameter':
        """Make HIP ``ESP_TRANSFORM`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            suites: ESP transform suite list
            suite_default: default ESP transform suite
            suite_namespace: ESP transform suite namespace
            suite_reversed: reverse ESP transform suite namespace
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            suite_id = cast('list[Enum_ESPTransformSuite]', param.suite_id)
        else:
            if suites is None:
                suites = []

            suite_id = []
            for suite in suites:
                suite_id.append(self._make_index(suite, suite_default, namespace=suite_namespace,  # type: ignore[arg-type]
                                                 reversed=suite_reversed, pack=False))

        return Schema_ESPTransformParameter(
            type=code,
            len=2 + 2 * len(suite_id),
            suites=suite_id,
        )

    def _make_param_seq_data(self, code: 'Enum_Parameter', param: 'Optional[Data_SeqDataParameter]' = None, *,  # pylint: disable=unused-argument
                             version: 'int',
                             seq: 'int' = 0,
                             **kwargs: 'Any') -> 'Schema_SeqDataParameter':
        """Make HIP ``SEQ_DATA`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            seq: sequence number
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            seq = param.seq

        return Schema_SeqDataParameter(
            type=code,
            len=4,
            seq=seq,
        )

    def _make_param_ack_data(self, code: 'Enum_Parameter', param: 'Optional[Data_AckDataParameter]' = None, *,  # pylint: disable=unused-argument
                             version: 'int',
                             ack: 'Optional[list[int]]' = None,
                             **kwargs: 'Any') -> 'Schema_AckDataParameter':
        """Make HIP ``ACK_DATA`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            ack: ACK list

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            ack = cast('list[int]', param.ack)
        else:
            ack = [] if ack is None else ack

        return Schema_AckDataParameter(
            type=code,
            len=4 * len(ack),
            ack=ack,
        )

    def _make_param_payload_mic(self, code: 'Enum_Parameter', param: 'Optional[Data_PayloadMICParameter]' = None, *,  # pylint: disable=unused-argument
                                version: 'int',
                                next: 'Enum_TransType | StdlibEnum | AenumEnum | str | int' = Enum_TransType.UDP,
                                next_default: 'Optional[int]' = None,
                                next_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                                next_reversed: 'bool' = False,
                                payload: 'bytes' = b'',
                                mic: 'bytes' = b'',
                                **kwargs: 'Any') -> 'Schema_PayloadMICParameter':
        """Make HIP ``PAYLOAD_MIC`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            next: next protocol
            next_default: default next protocol
            next_namespace: next protocol namespace
            next_reversed: reverse next protocol namespace
            payload: payload data
            mic: message integrity code
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            protocol = param.next
            payload = param.payload
            mic = param.mic
        else:
            protocol = self._make_index(next, next_default, namespace=next_namespace,  # type: ignore[assignment]
                                        reversed=next_reversed, pack=False)

        return Schema_PayloadMICParameter(
            type=code,
            len=8 + len(mic),
            next=protocol,
            payload=payload,
            mic=mic,
        )

    def _make_param_transaction_id(self, code: 'Enum_Parameter', param: 'Optional[Data_TransactionIDParameter]' = None, *,  # pylint: disable=unused-argument
                                   version: 'int',
                                   id: 'int' = 0,
                                   **kwargs: 'Any') -> 'Schema_TransactionIDParameter':
        """Make HIP ``TRANSACTION_ID`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            id: transaction ID
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            id = param.id

        return Schema_TransactionIDParameter(
            type=code,
            len=math.ceil(id.bit_length() / 8),
            id=id,
        )

    def _make_param_overlay_id(self, code: 'Enum_Parameter', param: 'Optional[Data_OverlayIDParameter]' = None, *,  # pylint: disable=unused-argument
                               version: 'int',
                               id: 'int' = 0,
                               **kwargs: 'Any') -> 'Schema_OverlayIDParameter':
        """Make HIP ``OVERLAY_ID`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            id: overlay ID
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            id = param.id

        return Schema_OverlayIDParameter(
            type=code,
            len=math.ceil(id.bit_length() / 8),
            id=id,
        )

    def _make_param_route_dst(self, code: 'Enum_Parameter', param: 'Optional[Data_RouteDstParameter]' = None, *,  # pylint: disable=unused-argument
                              version: 'int',
                              symmetric: 'bool' = False,
                              must_follow: 'bool' = False,
                              hit: 'Optional[list[bytes | str | int | IPv6Address]]' = None,
                              **kwargs: 'Any') -> 'Schema_RouteDstParameter':
        """Make HIP ``ROUTE_DST`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            symmetric = param.flags.symmetric
            must_follow = param.flags.must_follow
            hit_list = cast('list[bytes | str | int | IPv6Address]', param.hit)
        else:
            hit_list = hit if hit is not None else []

        return Schema_RouteDstParameter(
            type=code,
            len=4 + 16 * len(hit_list),
            flags={
                'symmetric': int(symmetric),
                'must_follow': int(must_follow),
            },
            hit=hit_list,
        )

    def _make_param_hip_transport_mode(self, code: 'Enum_Parameter', param: 'Optional[Data_HIPTransportModeParameter]' = None, *,  # pylint: disable=unused-argument
                                       version: 'int',
                                       port: 'int' = 0,
                                       modes: 'Optional[list[Enum_Transport | StdlibEnum | AenumEnum | str | int]]' = None,
                                       mode_default: 'Optional[int]' = None,
                                       mode_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                                       mode_reversed: 'bool' = False,
                                       **kwargs: 'Any') -> 'Schema_HIPTransportModeParameter':
        """Make HIP ``HIP_TRANSPORT_MODE`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            port: port number
            modes: transport mode list
            mode_default: default transport mode
            mode_namespace: transport mode namespace
            mode_reversed: reverse transport mode namespace
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            port = param.port
            mode_id = cast('list[Enum_Transport]', param.mode_id)
        else:
            if modes is None:
                modes = []

            mode_id = []
            for mode in modes:
                mode_id.append(self._make_index(mode, mode_default, namespace=mode_namespace,  # type: ignore[arg-type]
                                                reversed=mode_reversed, pack=False))

        return Schema_HIPTransportModeParameter(
            type=code,
            len=2 + 2 * len(mode_id),
            port=port,
            mode=mode_id,
        )

    def _make_param_hip_mac(self, code: 'Enum_Parameter', param: 'Optional[Data_HIPMACParameter]' = None, *,  # pylint: disable=unused-argument
                            version: 'int',
                            hmac: 'bytes' = b'',
                            **kwargs: 'Any') -> 'Schema_HIPMACParameter':
        """Make HIP ``HIP_MAC`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            hmac: HMAC value
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            hmac = param.hmac

        return Schema_HIPMACParameter(
            type=code,
            len=len(hmac),
            hmac=hmac,
        )

    def _make_param_hip_mac_2(self, code: 'Enum_Parameter', param: 'Optional[Data_HIPMAC2Parameter]' = None, *,  # pylint: disable=unused-argument
                              version: 'int',
                              hmac: 'bytes' = b'',
                              **kwargs: 'Any') -> 'Schema_HIPMAC2Parameter':
        """Make HIP ``HIP_MAC_2`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            hmac: HMAC value
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            hmac = param.hmac

        return Schema_HIPMAC2Parameter(
            type=code,
            len=len(hmac),
            hmac=hmac,
        )

    def _make_param_hip_signature_2(self, code: 'Enum_Parameter', param: 'Optional[Data_HIPSignature2Parameter]' = None, *,  # pylint: disable=unused-argument
                                    version: 'int',
                                    algorithm: 'Enum_HIAlgorithm | StdlibEnum | AenumEnum | str | int' = Enum_HIAlgorithm.NULL_ENCRYPT,
                                    algorithm_default: 'Optional[int]' = None,
                                    algorithm_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                                    algorithm_reversed: 'bool' = False,
                                    signature: 'bytes' = b'',
                                    **kwargs: 'Any') -> 'Schema_HIPSignature2Parameter':
        """Make HIP ``HIP_SIGNATURE_2`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            algorithm: signature algorithm
            algorithm_default: default signature algorithm
            algorithm_namespace: signature algorithm namespace
            algorithm_reversed: reverse signature algorithm namespace
            signature: signature value
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            algo = param.algorithm
            signature = param.signature
        else:
            algo = self._make_index(algorithm, algorithm_default, namespace=algorithm_namespace,  # type: ignore[assignment]
                                    reversed=algorithm_reversed, pack=False)

        return Schema_HIPSignature2Parameter(
            type=code,
            len=2 + len(signature),
            algorithm=algo,
            signature=signature,
        )

    def _make_param_hip_signature(self, code: 'Enum_Parameter', param: 'Optional[Data_HIPSignatureParameter]' = None, *,  # pylint: disable=unused-argument
                                  version: 'int',
                                  algorithm: 'Enum_HIAlgorithm | StdlibEnum | AenumEnum | str | int' = Enum_HIAlgorithm.NULL_ENCRYPT,
                                  algorithm_default: 'Optional[int]' = None,
                                  algorithm_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                                  algorithm_reversed: 'bool' = False,
                                  signature: 'bytes' = b'',
                                  **kwargs: 'Any') -> 'Schema_HIPSignatureParameter':
        """Make HIP ``HIP_SIGNATURE`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            algorithm: signature algorithm
            algorithm_default: default signature algorithm
            algorithm_namespace: signature algorithm namespace
            algorithm_reversed: reverse signature algorithm namespace
            signature: signature value
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            algo = param.algorithm
            signature = param.signature
        else:
            algo = self._make_index(algorithm, algorithm_default, namespace=algorithm_namespace,  # type: ignore[assignment]
                                    reversed=algorithm_reversed, pack=False)

        return Schema_HIPSignatureParameter(
            type=code,
            len=2 + len(signature),
            algorithm=algo,
            signature=signature,
        )

    def _make_param_echo_request_unsigned(self, code: 'Enum_Parameter', param: 'Optional[Data_EchoRequestUnsignedParameter]' = None, *,  # pylint: disable=unused-argument
                                          version: 'int',
                                          opaque: 'bytes' = b'',
                                          **kwargs: 'Any') -> 'Schema_EchoRequestUnsignedParameter':
        """Make HIP ``ECHO_REQUEST_UNSIGNED`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            opaque: opaque data
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            opaque = param.opaque

        return Schema_EchoRequestUnsignedParameter(
            type=code,
            len=len(opaque),
            opaque=opaque,
        )

    def _make_param_echo_response_unsigned(self, code: 'Enum_Parameter', param: 'Optional[Data_EchoRequestUnsignedParameter]' = None, *,  # pylint: disable=unused-argument
                                           version: 'int',
                                           opaque: 'bytes' = b'',
                                           **kwargs: 'Any') -> 'Schema_EchoRequestUnsignedParameter':
        """Make HIP ``ECHO_RESPONSE_UNSIGNED`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            opaque = param.opaque

        return Schema_EchoRequestUnsignedParameter(
            type=code,
            len=len(opaque),
            opaque=opaque,
        )

    def _make_param_relay_from(self, code: 'Enum_Parameter', param: 'Optional[Data_RelayFromParameter]' = None, *,  # pylint: disable=unused-argument
                               version: 'int',
                               port: 'int' = 0,
                               protocol: 'Enum_TransType | StdlibEnum | AenumEnum | str | int' = Enum_TransType.UDP,
                               protocol_default: 'Optional[int]' = None,
                               protocol_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                               protocol_reversed: 'bool' = False,
                               address: 'IPv6Address | str | int | bytes' = '::',
                               **kwargs: 'Any') -> 'Schema_RelayFromParameter':
        """Make HIP ``RELAY_FROM`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            port: port number
            protocol: transport protocol
            protocol_default: default transport protocol
            protocol_namespace: transport protocol namespace
            protocol_reversed: reverse transport protocol namespace
            address: relay address

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            port = param.port
            proto = param.protocol
            address = param.address
        else:
            proto = self._make_index(protocol, protocol_default, namespace=protocol_namespace,  # type: ignore[assignment]
                                     reversed=protocol_reversed, pack=False)

        return Schema_RelayFromParameter(
            type=code,
            len=20,
            port=port,
            protocol=proto,
            address=address,
        )

    def _make_param_relay_to(self, code: 'Enum_Parameter', param: 'Optional[Data_RelayToParameter]' = None, *,  # pylint: disable=unused-argument
                             version: 'int',
                             port: 'int' = 0,
                             protocol: 'Enum_TransType | StdlibEnum | AenumEnum | str | int' = Enum_TransType.UDP,
                             protocol_default: 'Optional[int]' = None,
                             protocol_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                             protocol_reversed: 'bool' = False,
                             address: 'IPv6Address | str | int | bytes' = '::',
                             **kwargs: 'Any') -> 'Schema_RelayToParameter':
        """Make HIP ``RELAY_TO`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            port: port number
            protocol: transport protocol
            protocol_default: default transport protocol
            protocol_namespace: transport protocol namespace
            protocol_reversed: reverse transport protocol namespace
            address: relay address
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            port = param.port
            proto = param.protocol
            address = param.address
        else:
            proto = self._make_index(protocol, protocol_default, namespace=protocol_namespace,  # type: ignore[assignment]
                                     reversed=protocol_reversed, pack=False)

        return Schema_RelayToParameter(
            type=code,
            len=20,
            port=port,
            protocol=proto,
            address=address,
        )

    def _make_param_overlay_ttl(self, code: 'Enum_Parameter', param: 'Optional[Data_OverlayTTLParameter]' = None, *,  # pylint: disable=unused-argument
                                version: 'int',
                                ttl: 'int | timedelta' = 0,
                                **kwargs: 'Any') -> 'Schema_OverlayTTLParameter':
        """Make HIP ``OVERLAY_TTL`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            ttl: overlay time-to-live (TTL) value
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            ttl_val = math.floor(param.ttl.total_seconds())
        else:
            ttl_val = ttl if isinstance(ttl, int) else math.floor(ttl.total_seconds())

        return Schema_OverlayTTLParameter(
            type=code,
            len=4,
            ttl=ttl_val,
        )

    def _make_param_route_via(self, code: 'Enum_Parameter', param: 'Optional[Data_RouteViaParameter]' = None, *,  # pylint: disable=unused-argument
                              version: 'int',
                              symmetric: 'bool' = False,
                              must_follow: 'bool' = False,
                              hit: 'Optional[list[IPv6Address | bytes | str | int]]' = None,
                              **kwargs: 'Any') -> 'Schema_RouteViaParameter':
        """Make HIP ``ROUTE_VIA`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            symmetric: symmetric flag
            must_follow: must-follow flag
            hit: list of HITs

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            symmetric = param.flags.symmetric
            must_follow = param.flags.must_follow
            hit_list = cast('list[IPv6Address | bytes | str | int]', param.hit)
        else:
            hit_list = hit if hit is not None else []

        return Schema_RouteViaParameter(
            type=code,
            len=4 + 16 * len(hit_list),
            flags={
                'symmetric': int(symmetric),
                'must_follow': int(must_follow),
            },
            hit=hit_list,
        )

    def _make_param_from(self, code: 'Enum_Parameter', param: 'Optional[Data_FromParameter]' = None, *,  # pylint: disable=unused-argument
                         version: 'int',
                         address: 'IPv6Address | str | int | bytes' = '::',
                         **kwargs: 'Any') -> 'Schema_FromParameter':
        """Make HIP ``FROM`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            address: relay address
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            address = param.address

        return Schema_FromParameter(
            type=code,
            len=16,
            address=address,
        )

    def _make_param_rvs_hmac(self, code: 'Enum_Parameter', param: 'Optional[Data_RVSHMACParameter]' = None, *,  # pylint: disable=unused-argument
                             version: 'int',
                             hmac: 'bytes' = b'',
                             **kwargs: 'Any') -> 'Schema_RVSHMACParameter':
        """Make HIP ``RVS_HMAC`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            hmac: HMAC value
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            hmac = param.hmac

        return Schema_RVSHMACParameter(
            type=code,
            len=len(hmac),
            hmac=hmac,
        )

    def _make_param_via_rvs(self, code: 'Enum_Parameter', param: 'Optional[Data_ViaRVSParameter]' = None, *,  # pylint: disable=unused-argument
                            version: 'int',
                            address: 'Optional[list[IPv6Address | bytes | str | int]]' = None,
                            **kwargs: 'Any') -> 'Schema_ViaRVSParameter':
        """Make HIP ``VIA_RVS`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            address: list of relay addresses
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            addr_list = cast('list[IPv6Address | bytes | str | int]', param.address)
        else:
            addr_list = address if address is not None else []

        return Schema_ViaRVSParameter(
            type=code,
            len=16 * len(addr_list),
            address=addr_list,
        )

    def _make_param_relay_hmac(self, code: 'Enum_Parameter', param: 'Optional[Data_RelayHMACParameter]' = None, *,  # pylint: disable=unused-argument
                               version: 'int',
                               hmac: 'bytes' = b'',
                               **kwargs: 'Any') -> 'Schema_RelayHMACParameter':
        """Make HIP ``RELAY_HMAC`` parameter.

        Args:
            code: parameter code
            param: parameter data
            version: HIP protocol version
            hmac: HMAC value
            **kwargs: arbitrary keyword arguments

        Returns:
            HIP parameter schema.

        """
        if param is not None:
            hmac = param.hmac

        return Schema_RelayHMACParameter(
            type=code,
            len=len(hmac),
            hmac=hmac,
        )
