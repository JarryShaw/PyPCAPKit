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
from typing import TYPE_CHECKING, overload

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
from pcapkit.protocols.data.internet.hip import \
    DeffieHellmanParameter as Data_DeffieHellmanParameter
from pcapkit.protocols.data.internet.hip import DHGroupListParameter as Data_DHGroupListParameter
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
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall
from pcapkit.utilities.warnings import ProtocolWarning, warn

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import IO, Any, Callable, NoReturn, Optional

    from mypy_extensions import NamedArg
    from typing_extensions import Literal

    from pcapkit.corekit.protochain import ProtoChain
    from pcapkit.protocols.data.internet.hip import Parameter as Data_Parameter
    from pcapkit.protocols.protocol import Protocol

    Parameter = OrderedMultiDict[Enum_Parameter, Data_Parameter]
    ParameterParser = Callable[[int, bool, int, NamedArg(Enum_Parameter, 'desc'), NamedArg(int, 'length'), NamedArg(int, 'version'),  # pylint: disable=line-too-long
                                NamedArg(Parameter, 'options')], Data_Parameter]  # pylint: disable=line-too-long

__all__ = ['HIP']


class HIP(Internet[Data_HIP]):
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

        _next = self._read_protos(1)
        _hlen = self._read_unpack(1)
        _type = self._read_binary(1)
        if _type[0] != '0':
            raise ProtocolError('HIP: invalid format')
        _vers = self._read_binary(1)
        if _vers[7] != '1':
            raise ProtocolError('HIP: invalid format')
        _csum = self._read_fileng(2)
        _ctrl = self._read_binary(2)
        _shit = self._read_unpack(16)
        _rhit = self._read_unpack(16)

        hip = Data_HIP(
            next=_next,
            length=(_hlen + 1) * 8,
            type=Enum_Packet.get(int(_type[1:], base=2)),
            version=int(_vers[:4], base=2),
            chksum=_csum,
            control=Data_Control(
                anonymous=bool(int(_ctrl[15], base=2)),
            ),
            shit=_shit,
            rhit=_rhit,
        )

        _prml = _hlen - 38
        if _prml:
            hip.__update__([
                ('parameters', self._read_hip_param(_prml, version=hip.version)),
            ])

        if extension:
            return hip
        return self._decode_next_layer(hip, _next, length - hip.length)

    def make(self, **kwargs: 'Any') -> 'NoReturn':
        """Make (construct) packet data.

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        raise NotImplementedError

    ##########################################################################
    # Data models.
    ##########################################################################

    @overload
    def __post_init__(self, file: 'IO[bytes]', length: 'Optional[int]' = ..., *,  # pylint: disable=arguments-differ
                      extension: 'bool' = ..., **kwargs: 'Any') -> 'None': ...

    @overload
    def __post_init__(self, **kwargs: 'Any') -> 'None': ...  # pylint: disable=arguments-differ

    def __post_init__(self, file: 'Optional[IO[bytes]]' = None, length: 'Optional[int]' = None, *,  # pylint: disable=arguments-differ
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
        counter = 0                   # length of read parameters
        options = OrderedMultiDict()  # type: Parameter

        while counter < length:
            # break when eol triggered
            kind = self._read_binary(2)
            if not kind:
                break

            # get parameter type & C-bit
            code = int(kind, base=2)
            cbit = bool(int(kind[15], base=2))

            # get parameter length
            clen = self._read_unpack(2)        # Length of the Contents, in bytes, excluding Type,Length, and Padding
            plen = 11 + clen - (clen + 3) % 8  # Total Length = 11 + Length - (Length + 3) % 8

            # extract parameter
            dscp = Enum_Parameter.get(code)
            meth_name = f'_read_param_{dscp.name.lower()}'
            meth = getattr(self, meth_name, self._read_param_unassigned)  # type: ParameterParser
            data = meth(self, code, cbit, clen, desc=dscp, length=plen,  # type: ignore[arg-type]
                        version=version, options=options)  # type: ignore[misc]

            # record parameter data
            counter += plen
            options.add(dscp, data)

        # check threshold
        if counter != length:
            raise ProtocolError(f'HIPv{version}: invalid format')

        return options

    def _read_param_unassigned(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                               desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        unassigned = Data_UnassignedParameter(
            type=desc,
            critical=cbit,
            length=clen,
            contents=self._read_fileng(clen),
        )

        plen = length - clen
        if plen:
            self._read_fileng(plen)

        return unassigned

    def _read_param_esp_info(self, code: 'int', cbit: 'bool', clen: 'int', *,
                             desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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

        _resv = self._read_fileng(2)
        _kind = self._read_unpack(2)
        _olds = self._read_unpack(2)
        _news = self._read_unpack(2)

        esp_info = Data_ESPInfoParameter(
            type=desc,
            critical=cbit,
            length=clen,
            index=_kind,
            old_spi=_olds,
            new_spi=_news,
        )

        return esp_info

    def _read_param_r1_counter(self, code: 'int', cbit: 'bool', clen: 'int', *,
                               desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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

        _resv = self._read_fileng(4)
        _genc = self._read_unpack(8)

        r1_counter = Data_R1CounterParameter(
            type=desc,
            critical=cbit,
            length=clen,
            counter=_genc,
        )

        return r1_counter

    def _read_param_locator_set(self, code: 'int', cbit: 'bool', clen: 'int', *,
                                desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If locator data is malformed.

        """
        def _read_locator(kind: 'int', size: 'int') -> 'Data_LocatorData | IPv4Address':
            """Parse locator data.

            Args:
                kind: locator type
                size: locator length

            Returns:
                * If ``kind`` is ``0`` and ``size`` is ``16``,
                  returns an :class:`~ipaddress.IPv4Address` object.
                * If ``kind`` is ``1`` and ``size`` is ``20``,
                  returns a :class:`~pcapkit.protocols.data.internet.hip.Locator` object.

            Raises:
                ProtocolError: in other cases

            """
            if kind == 0 and size == 16:
                return ipaddress.ip_address(self._read_fileng(16))  # type: ignore[return-value]
            if kind == 1 and size == 20:
                return Data_LocatorData(
                    spi=self._read_unpack(4),
                    ip=ipaddress.ip_address(self._read_fileng(16)),  # type: ignore[arg-type]
                )
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        # length of read locators
        _size = 0
        # list of locators
        _locs = []  # type: list[Data_Locator]

        while _size < clen:
            _traf = self._read_unpack(1)
            _loct = self._read_unpack(1)
            _locl = self._read_unpack(1) * 4
            _resp = self._read_binary(1)
            _life = self._read_unpack(4)
            _lobj = _read_locator(_loct, _locl)

            _locs.append(Data_Locator(
                traffic=_traf,
                type=_loct,
                length=_locl,
                preferred=bool(int(_resp[7], base=2)),
                lifetime=datetime.timedelta(seconds=_life),
                locator=_lobj,
            ))

        locator_set = Data_LocatorSetParameter(
            type=desc,
            critical=cbit,
            length=clen,
            locator_set=tuple(_locs),
        )

        return locator_set

    def _read_param_puzzle(self, code: 'int', cbit: 'bool', clen: 'int', *,
                           desc: 'Enum_Parameter', length: 'int', version: 'int',
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
            desc: parameter type
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

        _numk = self._read_unpack(1)
        _time = self._read_unpack(1)
        _opak = self._read_fileng(2)
        _rand = self._read_unpack(clen - 4)  # Length (clen) = 4 + RHASH_len / 8

        puzzle = Data_PuzzleParameter(
            type=desc,
            critical=cbit,
            length=clen,
            index=_numk,
            lifetime=datetime.timedelta(seconds=2 ** (_time - 32)),
            opaque=_opak,
            random=_rand,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return puzzle

    def _read_param_solution(self, code: 'int', cbit: 'bool', clen: 'int', *,
                             desc: 'Enum_Parameter', length: 'int', version: 'int',
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
            desc: parameter type
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

        _rlen = (clen - 4) * 4  # Length (clen) = 4 + RHASH_len / 4

        _numk = self._read_unpack(1)
        _time = self._read_unpack(1)
        _opak = self._read_fileng(2)
        _rand = self._read_unpack(_rlen // 8)
        _solv = self._read_unpack(_rlen // 8)

        solution = Data_SolutionParameter(
            type=desc,
            critical=cbit,
            length=clen,
            index=_numk,
            lifetime=datetime.timedelta(seconds=2 ** (_time - 32)),
            opaque=_opak,
            random=_rand,
            solution=_solv,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return solution

    def _read_param_seq(self, code: 'int', cbit: 'bool', clen: 'int', *,
                        desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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

        _upid = self._read_unpack(4)

        seq = Data_SEQParameter(
            type=desc,
            critical=cbit,
            length=clen,
            id=_upid,
        )

        return seq

    def _read_param_ack(self, code: 'int', cbit: 'bool', clen: 'int', *,
                        desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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

        _upid = []  # type: list[int]
        for _ in range(clen // 4):
            _upid.append(self._read_unpack(4))

        ack = Data_ACKParameter(
            type=desc,
            critical=cbit,
            length=clen,
            update_id=tuple(_upid),
        )

        return ack

    def _read_param_dh_group_list(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                  desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _dhid = []  # type: list[Enum_Group]
        for _ in range(clen):
            _dhid.append(Enum_Group.get(self._read_unpack(1)))

        dh_group_list = Data_DHGroupListParameter(
            type=desc,
            critical=cbit,
            length=clen,
            group_id=tuple(_dhid),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return dh_group_list

    def _read_param_diffie_hellman(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                   desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
                                   options: 'Parameter') -> 'Data_DeffieHellmanParameter':  # pylint: disable=unused-argument
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
            desc: parameter type
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _gpid = self._read_unpack(1)
        _vlen = self._read_unpack(2)
        _pval = self._read_fileng(_vlen)

        diffie_hellman = Data_DeffieHellmanParameter(
            type=desc,
            critical=cbit,
            length=clen,
            group_id=Enum_Group.get(_gpid),
            pub_len=_vlen,
            pub_val=_pval,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return diffie_hellman

    def _read_param_hip_transform(self, code: 'int', cbit: 'bool', clen: 'int', *,
                                  desc: 'Enum_Parameter', length: 'int', version: 'int',
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
            desc: parameter type
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

        _stid = []  # type: list[Enum_Suite]
        for _ in range(clen // 2):
            _stid.append(Enum_Suite.get(self._read_unpack(2)))

        hip_transform = Data_HIPTransformParameter(
            type=desc,
            critical=cbit,
            length=clen,
            suite_id=tuple(_stid),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return hip_transform

    def _read_param_hip_cipher(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                               desc: 'Enum_Parameter', length: 'int', version: 'int',
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
            desc: parameter type
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

        _cpid = []  # type: list[Enum_Cipher]
        for index, _ in enumerate(range(clen // 2)):
            # NOTE: The sender of a HIP_CIPHER parameter MUST make sure that there are no
            # more than six (6) Cipher IDs in one HIP_CIPHER parameter. [:rfc:`7401#section-5.2.8`]
            if index > 5:
                warn(f'HIPv{version}: [ParamNo {code}] invalid format', ProtocolWarning)
                # raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')
            _cpid.append(Enum_Cipher.get(self._read_unpack(2)))

        hip_cipher = Data_HIPCipherParameter(
            type=desc,
            critical=cbit,
            length=clen,
            cipher_id=tuple(_cpid),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return hip_cipher

    def _read_param_nat_traversal_mode(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                       desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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

        _resv = self._read_fileng(2)
        _mdid = []  # type: list[Enum_NATTraversal]
        for _ in range((clen - 2) // 2):
            _mdid.append(Enum_NATTraversal.get(self._read_unpack(2)))

        nat_traversal_mode = Data_NATTraversalModeParameter(
            type=desc,
            critical=cbit,
            length=clen,
            mode_id=tuple(_mdid),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return nat_traversal_mode

    def _read_param_transaction_pacing(self, code: 'int', cbit: 'bool', clen: 'int', *,
                                       desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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

        _data = self._read_unpack(4)

        transaction_pacing = Data_TransactionPacingParameter(
            type=desc,
            critical=cbit,
            length=clen,
            min_ta=_data,
        )

        return transaction_pacing

    def _read_param_encrypted(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                              desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _resv = self._read_fileng(4)
        _data = self._read_fileng(clen-4)

        encrypted = Data_EncryptedParameter(
            type=desc,
            critical=cbit,
            length=clen,
            raw=_data,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return encrypted

    def _read_param_host_id(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                            desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        def _read_host_identity(length: 'int', code: 'int') -> 'tuple[Enum_HIAlgorithm, Data_HostIdentity | bytes]':  # pylint: disable=line-too-long
            """Read host identity.

            Args:
                length: length of host identity
                code: host identity type

            Returns:
                Parsed host identity data.

            """
            if TYPE_CHECKING:
                host_id: 'Data_HostIdentity | bytes'

            algorithm = Enum_HIAlgorithm.get(code)
            if algorithm == Enum_HIAlgorithm.ECDSA:
                host_id = Data_HostIdentity(
                    curve=Enum_ECDSACurve.get(self._read_unpack(2)),
                    pubkey=self._read_fileng(length-2),
                )
            elif algorithm == Enum_HIAlgorithm.ECDSA_LOW:
                host_id = Data_HostIdentity(
                    curve=Enum_ECDSALowCurve.get(self._read_unpack(2)),
                    pubkey=self._read_fileng(length-2),
                )
            else:
                host_id = self._read_fileng(length)
            return algorithm, host_id

        def _read_domain_identifier(di_data: 'str') -> 'tuple[Enum_DITypes, int, bytes]':
            """Read domain identifier.

            Args:
                di_data: bit string of DI information byte

            Returns:
                A :data:`tuple` of DI type enumeration, DI content length and DI data.

            """
            di_type = Enum_DITypes.get(int(di_data[:4], base=2))
            di_len = int(di_data[4:], base=2)
            domain_id = self._read_fileng(di_len)
            return di_type, di_len, domain_id

        _hlen = self._read_unpack(2)
        _didt = self._read_binary(2)
        _algo = self._read_unpack(2)
        _hidf = _read_host_identity(_hlen, _algo)
        _didf = _read_domain_identifier(_didt)

        host_id = Data_HostIDParameter(
            type=desc,
            critical=cbit,
            length=clen,
            hi_len=_hlen,
            di_type=_didf[0],
            di_len=_didf[1],
            algorithm=_hidf[0],
            hi=_hidf[1],
            di=_didf[2],
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return host_id

    def _read_param_hit_suite_list(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                   desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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
            type=desc,
            critical=cbit,
            length=clen,
            suite_id=tuple(_hsid),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return hit_suite_list

    def _read_param_cert(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                         desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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
            type=desc,
            critical=cbit,
            length=clen,
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

    def _read_param_notification(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                 desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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
            type=desc,
            critical=cbit,
            length=clen,
            msg_type=_type,
            msg=_data,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return notification

    def _read_param_echo_request_signed(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                        desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _data = self._read_fileng(clen)

        echo_request_signed = Data_EchoRequestSignedParameter(
            type=desc,
            critical=cbit,
            length=clen,
            opaque=_data,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return echo_request_signed

    def _read_param_reg_info(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                             desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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
            type=desc,
            critical=cbit,
            length=clen,
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

    def _read_param_reg_request(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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
            type=desc,
            critical=cbit,
            length=clen,
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

    def _read_param_reg_response(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                 desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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
            type=desc,
            critical=cbit,
            length=clen,
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

    def _read_param_reg_failed(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                               desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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
            type=desc,
            critical=cbit,
            length=clen,
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

    def _read_param_reg_from(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                             desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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
            type=desc,
            critical=cbit,
            length=clen,
            port=_port,
            protocol=_ptcl,
            address=ipaddress.ip_address(_addr),  # type: ignore[arg-type]
        )

        return reg_from

    def _read_param_echo_response_signed(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                         desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _data = self._read_fileng(clen)

        echo_response_signed = Data_EchoResponseSignedParameter(
            type=desc,
            critical=cbit,
            length=clen,
            opaque=_data,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return echo_response_signed

    def _read_param_transport_format_list(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                          desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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
            type=desc,
            critical=cbit,
            length=clen,
            tf_type=tuple(_tfid),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return transport_format_list

    def _read_param_esp_transform(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                  desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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
            type=desc,
            critical=cbit,
            length=clen,
            suite_id=tuple(_stid),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return esp_transform

    def _read_param_seq_data(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                             desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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
            type=desc,
            critical=cbit,
            length=clen,
            seq=_seqn,
        )

        return seq_data

    def _read_param_ack_data(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                             desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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
            type=desc,
            critical=cbit,
            length=clen,
            ack=tuple(_ackn),
        )

        return ack_data

    def _read_param_payload_mic(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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
            type=desc,
            critical=cbit,
            length=clen,
            next=_next,
            payload=_data,
            mic=_micv,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return payload_mic

    def _read_param_transaction_id(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                   desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _tsid = self._read_unpack(clen)

        transaction_id = Data_TransactionIDParameter(
            type=desc,
            critical=cbit,
            length=clen,
            id=_tsid,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return transaction_id

    def _read_param_overlay_id(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                               desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _olid = self._read_unpack(clen)

        overlay_id = Data_OverlayIDParameter(
            type=desc,
            critical=cbit,
            length=clen,
            id=_olid,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return overlay_id

    def _read_param_route_dst(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                              desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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
            type=desc,
            critical=cbit,
            length=clen,
            flags=Data_Flags(
                symmetric=bool(int(_flag[0], base=2)),
                must_follow=bool(int(_flag[1], base=2)),
            ),
            hit=tuple(_addr),
        )

        return route_dst

    def _read_param_hip_transport_mode(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                       desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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
            type=desc,
            critical=cbit,
            length=clen,
            port=_port,
            mode_id=tuple(_mdid),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return hip_transport_mode

    def _read_param_hip_mac(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                            desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _hmac = self._read_fileng(clen)

        hip_mac = Data_HIPMACParameter(
            type=desc,
            critical=cbit,
            length=clen,
            hmac=_hmac,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return hip_mac

    def _read_param_hip_mac_2(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                              desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _hmac = self._read_fileng(clen)

        hip_mac_2 = Data_HIPMAC2Parameter(
            type=desc,
            critical=cbit,
            length=clen,
            hmac=_hmac,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return hip_mac_2

    def _read_param_hip_signature_2(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                    desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _algo = self._read_unpack(2)
        _sign = self._read_fileng(clen-2)

        hip_signature_2 = Data_HIPSignature2Parameter(
            type=desc,
            critical=cbit,
            length=clen,
            algorithm=Enum_HIAlgorithm.get(_algo),
            signature=_sign,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return hip_signature_2

    def _read_param_hip_signature(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                  desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _algo = self._read_unpack(2)
        _sign = self._read_fileng(clen-2)

        hip_signature = Data_HIPSignatureParameter(
            type=desc,
            critical=cbit,
            length=clen,
            algorithm=Enum_HIAlgorithm.get(_algo),
            signature=_sign,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return hip_signature

    def _read_param_echo_request_unsigned(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                          desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _data = self._read_fileng(clen)

        echo_request_unsigned = Data_EchoRequestUnsignedParameter(
            type=desc,
            critical=cbit,
            length=clen,
            opaque=_data,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return echo_request_unsigned

    def _read_param_echo_response_unsigned(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                           desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _data = self._read_fileng(clen)

        echo_response_unsigned = Data_EchoResponseUnsignedParameter(
            type=desc,
            critical=cbit,
            length=clen,
            opaque=_data,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return echo_response_unsigned

    def _read_param_relay_from(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                               desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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
            type=desc,
            critical=cbit,
            length=clen,
            port=_port,
            protocol=_ptcl,
            address=ipaddress.ip_address(_addr),  # type: ignore[arg-type]
        )

        return relay_from

    def _read_param_relay_to(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                             desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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
            type=desc,
            critical=cbit,
            length=clen,
            port=_port,
            protocol=_ptcl,
            address=ipaddress.ip_address(_addr),  # type: ignore[arg-type]
        )

        return relay_to

    def _read_param_overlay_ttl(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                                desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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
            type=desc,
            critical=cbit,
            length=clen,
            ttl=datetime.timedelta(seconds=_ttln),
        )

        return overlay_ttl

    def _read_param_route_via(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                              desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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
            type=desc,
            critical=cbit,
            length=clen,
            flags=Data_Flags(
                symmetric=bool(int(_flag[0], base=2)),
                must_follow=bool(int(_flag[1], base=2)),
            ),
            hit=tuple(_addr),
        )

        return route_via

    def _read_param_from(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                         desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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
            type=desc,
            critical=cbit,
            length=clen,
            address=ipaddress.ip_address(_addr),  # type: ignore[arg-type]
        )

        return from_

    def _read_param_rvs_hmac(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                             desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _hmac = self._read_fileng(clen)

        rvs_hmac = Data_RVSHMACParameter(
            type=desc,
            critical=cbit,
            length=clen,
            hmac=_hmac,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return rvs_hmac

    def _read_param_via_rvs(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                            desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
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
            type=desc,
            critical=cbit,
            length=clen,
            address=tuple(_addr),
        )

        return via_rvs

    def _read_param_relay_hmac(self, code: 'int', cbit: 'bool', clen: 'int', *,  # pylint: disable=unused-argument
                               desc: 'Enum_Parameter', length: 'int', version: 'int',  # pylint: disable=unused-argument
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
            desc: parameter type
            length: remaining packet length
            version: HIP protocol version
            options: parsed HIP parameters

        Returns:
            Parsed parameter data.

        """
        _hmac = self._read_fileng(clen)

        relay_hmac = Data_RelayHMACParameter(
            type=desc,
            critical=cbit,
            length=clen,
            hmac=_hmac,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return relay_hmac
