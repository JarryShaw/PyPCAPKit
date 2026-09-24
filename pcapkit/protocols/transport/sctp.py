# -*- coding: utf-8 -*-
# mypy: disable-error-code=dict-item
"""SCTP - Stream Control Transmission Protocol
================================================

.. module:: pcapkit.protocols.transport.sctp

:mod:`pcapkit.protocols.transport.sctp` contains
:class:`~pcapkit.protocols.transport.sctp.SCTP` only,
which implements extractor for Stream Control
Transmission Protocol (SCTP) [*]_, whose structure is
described as below:

======= ========= ========================= =======================================
Octets      Bits        Name                    Description
======= ========= ========================= =======================================
  0           0   ``sctp.srcport``          Source Port
  2          16   ``sctp.dstport``          Destination Port
  4          32   ``sctp.vtag``             Verification Tag
  8          64   ``sctp.chksum``           Checksum (CRC32c)
  12         96   ``sctp.chunks``           Chunks
======= ========= ========================= =======================================

.. [*] https://en.wikipedia.org/wiki/Stream_Control_Transmission_Protocol

"""
import collections
import struct
from typing import TYPE_CHECKING, cast

from pcapkit.const.reg.apptype import TransportProtocol as Enum_TransportProtocol
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.const.sctp.cause_code import CauseCode as Enum_CauseCode
from pcapkit.const.sctp.chunk import Chunk as Enum_Chunk
from pcapkit.const.sctp.parameter import Parameter as Enum_Parameter
from pcapkit.const.sctp.payload_protocol_identifier import \
    PayloadProtocolIdentifier as Enum_PayloadProtocolIdentifier
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.protocols.data.transport.sctp import SCTP as Data_SCTP
from pcapkit.protocols.data.transport.sctp import AbortChunk as Data_AbortChunk
from pcapkit.protocols.data.transport.sctp import CookieACKChunk as Data_CookieACKChunk
from pcapkit.protocols.data.transport.sctp import CookieEchoChunk as Data_CookieEchoChunk
from pcapkit.protocols.data.transport.sctp import \
    CookiePreservativeParameter as Data_CookiePreservativeParameter
from pcapkit.protocols.data.transport.sctp import \
    CookieReceivedWhileShuttingDownCause as Data_CookieReceivedWhileShuttingDownCause
from pcapkit.protocols.data.transport.sctp import DATAChunk as Data_DATAChunk
from pcapkit.protocols.data.transport.sctp import DATAChunkFlags as Data_DATAChunkFlags
from pcapkit.protocols.data.transport.sctp import ErrorChunk as Data_ErrorChunk
from pcapkit.protocols.data.transport.sctp import GapAckBlock as Data_GapAckBlock
from pcapkit.protocols.data.transport.sctp import HeartbeatACKChunk as Data_HeartbeatACKChunk
from pcapkit.protocols.data.transport.sctp import HeartbeatChunk as Data_HeartbeatChunk
from pcapkit.protocols.data.transport.sctp import \
    HeartbeatInfoParameter as Data_HeartbeatInfoParameter
from pcapkit.protocols.data.transport.sctp import \
    HostNameAddressParameter as Data_HostNameAddressParameter
from pcapkit.protocols.data.transport.sctp import INITACKChunk as Data_INITACKChunk
from pcapkit.protocols.data.transport.sctp import INITChunk as Data_INITChunk
from pcapkit.protocols.data.transport.sctp import \
    InvalidMandatoryParameterCause as Data_InvalidMandatoryParameterCause
from pcapkit.protocols.data.transport.sctp import \
    InvalidStreamIdentifierCause as Data_InvalidStreamIdentifierCause
from pcapkit.protocols.data.transport.sctp import IPv4AddressParameter as Data_IPv4AddressParameter
from pcapkit.protocols.data.transport.sctp import IPv6AddressParameter as Data_IPv6AddressParameter
from pcapkit.protocols.data.transport.sctp import \
    MissingMandatoryParameterCause as Data_MissingMandatoryParameterCause
from pcapkit.protocols.data.transport.sctp import NoUserDataCause as Data_NoUserDataCause
from pcapkit.protocols.data.transport.sctp import OutOfResourceCause as Data_OutOfResourceCause
from pcapkit.protocols.data.transport.sctp import \
    ProtocolViolationCause as Data_ProtocolViolationCause
from pcapkit.protocols.data.transport.sctp import \
    RestartOfAnAssociationWithNewAddressesCause as Data_RestartOfAnAssociationWithNewAddressesCause
from pcapkit.protocols.data.transport.sctp import SACKChunk as Data_SACKChunk
from pcapkit.protocols.data.transport.sctp import ShutdownACKChunk as Data_ShutdownACKChunk
from pcapkit.protocols.data.transport.sctp import ShutdownChunk as Data_ShutdownChunk
from pcapkit.protocols.data.transport.sctp import \
    ShutdownCompleteChunk as Data_ShutdownCompleteChunk
from pcapkit.protocols.data.transport.sctp import StaleCookieCause as Data_StaleCookieCause
from pcapkit.protocols.data.transport.sctp import StateCookieParameter as Data_StateCookieParameter
from pcapkit.protocols.data.transport.sctp import \
    SupportedAddressTypesParameter as Data_SupportedAddressTypesParameter
from pcapkit.protocols.data.transport.sctp import TBitFlags as Data_TBitFlags
from pcapkit.protocols.data.transport.sctp import UnknownCause as Data_UnknownCause
from pcapkit.protocols.data.transport.sctp import UnknownChunk as Data_UnknownChunk
from pcapkit.protocols.data.transport.sctp import UnknownParameter as Data_UnknownParameter
from pcapkit.protocols.data.transport.sctp import \
    UnrecognizedChunkTypeCause as Data_UnrecognizedChunkTypeCause
from pcapkit.protocols.data.transport.sctp import \
    UnrecognizedParameter as Data_UnrecognizedParameter
from pcapkit.protocols.data.transport.sctp import \
    UnrecognizedParametersCause as Data_UnrecognizedParametersCause
from pcapkit.protocols.data.transport.sctp import \
    UnresolvableAddressCause as Data_UnresolvableAddressCause
from pcapkit.protocols.data.transport.sctp import \
    UserInitiatedAbortCause as Data_UserInitiatedAbortCause
from pcapkit.protocols.protocol import ProtocolBase
from pcapkit.protocols.schema.schema import Schema
from pcapkit.protocols.schema.transport.sctp import SCTP as Schema_SCTP
from pcapkit.protocols.schema.transport.sctp import AbortChunk as Schema_AbortChunk
from pcapkit.protocols.schema.transport.sctp import CookieACKChunk as Schema_CookieACKChunk
from pcapkit.protocols.schema.transport.sctp import CookieEchoChunk as Schema_CookieEchoChunk
from pcapkit.protocols.schema.transport.sctp import \
    CookiePreservativeParameter as Schema_CookiePreservativeParameter
from pcapkit.protocols.schema.transport.sctp import \
    CookieReceivedWhileShuttingDownCause as Schema_CookieReceivedWhileShuttingDownCause
from pcapkit.protocols.schema.transport.sctp import DATAChunk as Schema_DATAChunk
from pcapkit.protocols.schema.transport.sctp import ErrorChunk as Schema_ErrorChunk
from pcapkit.protocols.schema.transport.sctp import GapAckBlock as Schema_GapAckBlock
from pcapkit.protocols.schema.transport.sctp import HeartbeatACKChunk as Schema_HeartbeatACKChunk
from pcapkit.protocols.schema.transport.sctp import HeartbeatChunk as Schema_HeartbeatChunk
from pcapkit.protocols.schema.transport.sctp import \
    HeartbeatInfoParameter as Schema_HeartbeatInfoParameter
from pcapkit.protocols.schema.transport.sctp import \
    HostNameAddressParameter as Schema_HostNameAddressParameter
from pcapkit.protocols.schema.transport.sctp import INITACKChunk as Schema_INITACKChunk
from pcapkit.protocols.schema.transport.sctp import INITChunk as Schema_INITChunk
from pcapkit.protocols.schema.transport.sctp import \
    InvalidMandatoryParameterCause as Schema_InvalidMandatoryParameterCause
from pcapkit.protocols.schema.transport.sctp import \
    InvalidStreamIdentifierCause as Schema_InvalidStreamIdentifierCause
from pcapkit.protocols.schema.transport.sctp import \
    IPv4AddressParameter as Schema_IPv4AddressParameter
from pcapkit.protocols.schema.transport.sctp import \
    IPv6AddressParameter as Schema_IPv6AddressParameter
from pcapkit.protocols.schema.transport.sctp import \
    MissingMandatoryParameterCause as Schema_MissingMandatoryParameterCause
from pcapkit.protocols.schema.transport.sctp import NoUserDataCause as Schema_NoUserDataCause
from pcapkit.protocols.schema.transport.sctp import OutOfResourceCause as Schema_OutOfResourceCause
from pcapkit.protocols.schema.transport.sctp import \
    ProtocolViolationCause as Schema_ProtocolViolationCause
from pcapkit.protocols.schema.transport.sctp import \
    RestartOfAnAssociationWithNewAddressesCause as \
    Schema_RestartOfAnAssociationWithNewAddressesCause
from pcapkit.protocols.schema.transport.sctp import SACKChunk as Schema_SACKChunk
from pcapkit.protocols.schema.transport.sctp import ShutdownACKChunk as Schema_ShutdownACKChunk
from pcapkit.protocols.schema.transport.sctp import ShutdownChunk as Schema_ShutdownChunk
from pcapkit.protocols.schema.transport.sctp import \
    ShutdownCompleteChunk as Schema_ShutdownCompleteChunk
from pcapkit.protocols.schema.transport.sctp import StaleCookieCause as Schema_StaleCookieCause
from pcapkit.protocols.schema.transport.sctp import \
    StateCookieParameter as Schema_StateCookieParameter
from pcapkit.protocols.schema.transport.sctp import \
    SupportedAddressTypesParameter as Schema_SupportedAddressTypesParameter
from pcapkit.protocols.schema.transport.sctp import UnknownCause as Schema_UnknownCause
from pcapkit.protocols.schema.transport.sctp import UnknownChunk as Schema_UnknownChunk
from pcapkit.protocols.schema.transport.sctp import UnknownParameter as Schema_UnknownParameter
from pcapkit.protocols.schema.transport.sctp import \
    UnrecognizedChunkTypeCause as Schema_UnrecognizedChunkTypeCause
from pcapkit.protocols.schema.transport.sctp import \
    UnrecognizedParameter as Schema_UnrecognizedParameter
from pcapkit.protocols.schema.transport.sctp import \
    UnrecognizedParametersCause as Schema_UnrecognizedParametersCause
from pcapkit.protocols.schema.transport.sctp import \
    UnresolvableAddressCause as Schema_UnresolvableAddressCause
from pcapkit.protocols.schema.transport.sctp import \
    UserInitiatedAbortCause as Schema_UserInitiatedAbortCause
from pcapkit.protocols.transport.transport import Transport
from pcapkit.utilities.exceptions import ProtocolError, RegistryError
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Any, Callable, DefaultDict, Optional, Type

    from mypy_extensions import DefaultArg, KwArg, NamedArg
    from typing_extensions import Literal

    from pcapkit.const.reg.apptype import AppType as Enum_AppType
    from pcapkit.protocols.data.transport.sctp import Chunk as Data_Chunk
    from pcapkit.protocols.data.transport.sctp import ErrorCause as Data_ErrorCause
    from pcapkit.protocols.data.transport.sctp import Parameter as Data_Parameter
    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema.transport.sctp import Chunk as Schema_Chunk
    from pcapkit.protocols.schema.transport.sctp import ErrorCause as Schema_ErrorCause
    from pcapkit.protocols.schema.transport.sctp import Parameter as Schema_Parameter

    Chunks = OrderedMultiDict[Enum_Chunk, Data_Chunk]
    Parameters = OrderedMultiDict[Enum_Parameter, Data_Parameter]
    Causes = OrderedMultiDict[Enum_CauseCode, Data_ErrorCause]

    ChunkParser = Callable[[Schema_Chunk, NamedArg(Chunks, 'chunks')], Data_Chunk]
    ChunkConstructor = Callable[[Enum_Chunk, DefaultArg(Optional[Data_Chunk]),
                                 KwArg(Any)], Schema_Chunk]

    ParameterParser = Callable[[Schema_Parameter,
                                NamedArg(Parameters, 'parameters')], Data_Parameter]
    ParameterConstructor = Callable[[Enum_Parameter, DefaultArg(Optional[Data_Parameter]),
                                    KwArg(Any)], Schema_Parameter]

    CauseParser = Callable[[Schema_ErrorCause, NamedArg(Causes, 'causes')], Data_ErrorCause]
    CauseConstructor = Callable[[Enum_CauseCode, DefaultArg(Optional[Data_ErrorCause]),
                                KwArg(Any)], Schema_ErrorCause]

__all__ = ['SCTP']

#: Reflected CRC32c (Castagnoli) lookup table, as generated by the sample code
#: of :rfc:`9260#appendix-A` with ``TB_POLY=0x1EDC6F41`` and ``TB_REVER=TRUE``.
CRC32C_TABLE = []  # type: list[int]
for _index in range(256):
    _crc = _index
    for _ in range(8):
        _crc = (_crc >> 1) ^ (0x82F63B78 if _crc & 1 else 0)
    CRC32C_TABLE.append(_crc)
del _index, _crc


class SCTP(Transport[Data_SCTP, Schema_SCTP],
           schema=Schema_SCTP, data=Data_SCTP):
    """This class implements Stream Control Transmission Protocol.

    Unlike :class:`~pcapkit.protocols.transport.tcp.TCP` and
    :class:`~pcapkit.protocols.transport.udp.UDP`, SCTP does **not** dispatch
    the next layer on port numbers: user data travels inside DATA chunks, and
    each DATA chunk names its upper layer through its *payload protocol
    identifier* (PPID). The :attr:`self.__proto__ <SCTP.__proto__>` registry is
    therefore keyed by PPID rather than by port number, and is populated through
    :meth:`SCTP.register`::

       >>> SCTP.register(Enum_PayloadProtocolIdentifier.PayloadProtocolIdentifier_3GPP_NG_Application_Protocol, NGAP)
       >>> SCTP.register(60, NGAP)  # equivalent, PPID given as a plain integer

    Two PPIDs are registered by default, both to
    :class:`~pcapkit.protocols.application.ngap.NGAP`: 60
    (``NG_Application_Protocol``) and 66 (``NGAP_over_DTLS_over_SCTP``). Every
    other PPID resolves to :class:`~pcapkit.protocols.misc.raw.Raw`.

    Only PPID 60 actually decodes, though. A PPID 66 payload is an NGAP PDU
    wrapped in a DTLS record, and :mod:`pcapkit` has no DTLS implementation, so
    those bytes are not aligned PER and the parse degrades to
    :class:`~pcapkit.protocols.misc.raw.Raw` -- every time, not only when
    ``pycrate`` is absent. It is registered so that the PPID is *named* in the
    protochain rather than reported as an unassigned number, which is strictly
    more than leaving it out would give.

    This class currently supports parsing of the following SCTP chunks, which
    are directly mapped to the :class:`pcapkit.const.sctp.chunk.Chunk`
    enumeration:

    .. list-table::
       :header-rows: 1

       * - Chunk Type
         - Chunk Parser
         - Chunk Constructor
       * - :attr:`~pcapkit.const.sctp.chunk.Chunk.Payload_Data`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._read_chunk_data`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._make_chunk_data`
       * - :attr:`~pcapkit.const.sctp.chunk.Chunk.Initiation`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._read_chunk_init`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._make_chunk_init`
       * - :attr:`~pcapkit.const.sctp.chunk.Chunk.Initiation_Acknowledgement`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._read_chunk_init_ack`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._make_chunk_init_ack`
       * - :attr:`~pcapkit.const.sctp.chunk.Chunk.Selective_Acknowledgement`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._read_chunk_sack`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._make_chunk_sack`
       * - :attr:`~pcapkit.const.sctp.chunk.Chunk.Heartbeat_Request`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._read_chunk_heartbeat`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._make_chunk_heartbeat`
       * - :attr:`~pcapkit.const.sctp.chunk.Chunk.Heartbeat_Acknowledgement`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._read_chunk_heartbeat_ack`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._make_chunk_heartbeat_ack`
       * - :attr:`~pcapkit.const.sctp.chunk.Chunk.Abort`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._read_chunk_abort`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._make_chunk_abort`
       * - :attr:`~pcapkit.const.sctp.chunk.Chunk.Shutdown`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._read_chunk_shutdown`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._make_chunk_shutdown`
       * - :attr:`~pcapkit.const.sctp.chunk.Chunk.Shutdown_Acknowledgement`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._read_chunk_shutdown_ack`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._make_chunk_shutdown_ack`
       * - :attr:`~pcapkit.const.sctp.chunk.Chunk.Operation_Error`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._read_chunk_error`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._make_chunk_error`
       * - :attr:`~pcapkit.const.sctp.chunk.Chunk.State_Cookie`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._read_chunk_cookie_echo`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._make_chunk_cookie_echo`
       * - :attr:`~pcapkit.const.sctp.chunk.Chunk.Cookie_Acknowledgement`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._read_chunk_cookie_ack`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._make_chunk_cookie_ack`
       * - :attr:`~pcapkit.const.sctp.chunk.Chunk.Shutdown_Complete`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._read_chunk_shutdown_complete`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._make_chunk_shutdown_complete`

    Any other chunk type -- unassigned, reserved, or defined by an SCTP
    extension that :mod:`pcapkit` does not implement -- falls through to
    :meth:`~pcapkit.protocols.transport.sctp.SCTP._read_chunk_donone`, which
    records the chunk's raw flags and value verbatim rather than raising.

    This class currently supports parsing of the following chunk parameters,
    which are directly mapped to the
    :class:`pcapkit.const.sctp.parameter.Parameter` enumeration:

    .. list-table::
       :header-rows: 1

       * - Parameter Type
         - Parameter Parser
         - Parameter Constructor
       * - :attr:`~pcapkit.const.sctp.parameter.Parameter.Heartbeat_Info`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._read_param_hbinfo`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._make_param_hbinfo`
       * - :attr:`~pcapkit.const.sctp.parameter.Parameter.IPv4_Address`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._read_param_ipv4`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._make_param_ipv4`
       * - :attr:`~pcapkit.const.sctp.parameter.Parameter.IPv6_Address`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._read_param_ipv6`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._make_param_ipv6`
       * - :attr:`~pcapkit.const.sctp.parameter.Parameter.State_Cookie`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._read_param_cookie`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._make_param_cookie`
       * - :attr:`~pcapkit.const.sctp.parameter.Parameter.Unrecognized_Parameter`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._read_param_unrecognized`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._make_param_unrecognized`
       * - :attr:`~pcapkit.const.sctp.parameter.Parameter.Cookie_Preservative`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._read_param_preservative`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._make_param_preservative`
       * - :attr:`~pcapkit.const.sctp.parameter.Parameter.Host_Name_Address`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._read_param_hostname`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._make_param_hostname`
       * - :attr:`~pcapkit.const.sctp.parameter.Parameter.Supported_Address_Types`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._read_param_addrtypes`
         - :meth:`~pcapkit.protocols.transport.sctp.SCTP._make_param_addrtypes`

    This class currently supports parsing of all thirteen error causes defined
    by :rfc:`9260#section-3.3.10`, which are directly mapped to the
    :class:`pcapkit.const.sctp.cause_code.CauseCode` enumeration; see
    :attr:`self.__cause__ <SCTP.__cause__>` for the mapping. Unknown cause
    codes fall through to
    :meth:`~pcapkit.protocols.transport.sctp.SCTP._read_cause_donone`.

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Payload of the packet, i.e. the user data of the first DATA chunk found
    #: in the packet, as located by :meth:`self.read <SCTP.read>`.
    _payload = b''  # type: bytes

    #: Payload protocol identifier of the first DATA chunk found in the packet.
    _ppid = None  # type: Optional[Enum_PayloadProtocolIdentifier]

    #: DefaultDict[int, ModuleDescriptor[ProtocolBase] | ~typing.Type[ProtocolBase]]: Protocol
    #: index mapping for decoding next layer, c.f.
    #: :meth:`self._decode_next_layer <pcapkit.protocols.transport.sctp.SCTP._decode_next_layer>`
    #: & :meth:`self._import_next_layer <pcapkit.protocols.protocol.Protocol._import_next_layer>`.
    #:
    #: Important:
    #:    Keyed by the DATA chunk's *payload protocol identifier* (PPID), **not**
    #:    by port number as in :class:`~pcapkit.protocols.transport.tcp.TCP` and
    #:    :class:`~pcapkit.protocols.transport.udp.UDP`.
    __proto__ = collections.defaultdict(
        lambda: ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'),
        {
            # PPID 66 is NGAP wrapped in a DTLS record rather than a bare
            # NGAP-PDU, and pcapkit implements no DTLS. It is registered anyway
            # so that the PPID is *named*: the payload then fails in NGAP's own
            # decoder and `beholder` degrades it to Raw, which is where an
            # unregistered PPID would have left it regardless.
            Enum_PayloadProtocolIdentifier.PayloadProtocolIdentifier_3GPP_NG_Application_Protocol: ModuleDescriptor('pcapkit.protocols.application.ngap', 'NGAP'),  # NGAP
            Enum_PayloadProtocolIdentifier.PayloadProtocolIdentifier_3GPP_NGAP_over_DTLS_over_SCTP: ModuleDescriptor('pcapkit.protocols.application.ngap', 'NGAP'),  # NGAP over DTLS
        },
    )  # type: DefaultDict[int, ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]]

    #: DefaultDict[Enum_Chunk, str | tuple[ChunkParser, ChunkConstructor]]: Chunk
    #: type to method mapping, c.f. :meth:`_read_sctp_chunks` and
    #: :meth:`_make_sctp_chunks`. Method names are expected to be referred to
    #: the class by ``_read_chunk_${name}`` and ``_make_chunk_${name}``, and if
    #: such name not found, the value should then be a method that can parse the
    #: chunk by itself.
    __chunk__ = collections.defaultdict(
        lambda: 'donone',
        {
            Enum_Chunk.Payload_Data: 'data',                          # [RFC 9260] DATA
            Enum_Chunk.Initiation: 'init',                            # [RFC 9260] INIT
            Enum_Chunk.Initiation_Acknowledgement: 'init_ack',        # [RFC 9260] INIT ACK
            Enum_Chunk.Selective_Acknowledgement: 'sack',             # [RFC 9260] SACK
            Enum_Chunk.Heartbeat_Request: 'heartbeat',                # [RFC 9260] HEARTBEAT
            Enum_Chunk.Heartbeat_Acknowledgement: 'heartbeat_ack',    # [RFC 9260] HEARTBEAT ACK
            Enum_Chunk.Abort: 'abort',                                # [RFC 9260] ABORT
            Enum_Chunk.Shutdown: 'shutdown',                          # [RFC 9260] SHUTDOWN
            Enum_Chunk.Shutdown_Acknowledgement: 'shutdown_ack',      # [RFC 9260] SHUTDOWN ACK
            Enum_Chunk.Operation_Error: 'error',                      # [RFC 9260] ERROR
            Enum_Chunk.State_Cookie: 'cookie_echo',                   # [RFC 9260] COOKIE ECHO
            Enum_Chunk.Cookie_Acknowledgement: 'cookie_ack',          # [RFC 9260] COOKIE ACK
            Enum_Chunk.Shutdown_Complete: 'shutdown_complete',        # [RFC 9260] SHUTDOWN COMPLETE
        },
    )  # type: DefaultDict[int, str | tuple[ChunkParser, ChunkConstructor]]

    #: DefaultDict[Enum_Parameter, str | tuple[ParameterParser, ParameterConstructor]]:
    #: Chunk parameter type to method mapping, c.f. :meth:`_read_sctp_parameters`
    #: and :meth:`_make_sctp_parameters`. Method names are expected to be
    #: referred to the class by ``_read_param_${name}`` and
    #: ``_make_param_${name}``, and if such name not found, the value should then
    #: be a method that can parse the parameter by itself.
    __parameter__ = collections.defaultdict(
        lambda: 'donone',
        {
            Enum_Parameter.Heartbeat_Info: 'hbinfo',                  # [RFC 9260] Heartbeat Info
            Enum_Parameter.IPv4_Address: 'ipv4',                      # [RFC 9260] IPv4 Address
            Enum_Parameter.IPv6_Address: 'ipv6',                      # [RFC 9260] IPv6 Address
            Enum_Parameter.State_Cookie: 'cookie',                    # [RFC 9260] State Cookie
            Enum_Parameter.Unrecognized_Parameter: 'unrecognized',    # [RFC 9260] Unrecognized
            Enum_Parameter.Cookie_Preservative: 'preservative',       # [RFC 9260] Cookie Preservative
            Enum_Parameter.Host_Name_Address: 'hostname',             # [RFC 9260] Host Name Address
            Enum_Parameter.Supported_Address_Types: 'addrtypes',      # [RFC 9260] Supported Addr Types
        },
    )  # type: DefaultDict[int, str | tuple[ParameterParser, ParameterConstructor]]

    #: DefaultDict[Enum_CauseCode, str | tuple[CauseParser, CauseConstructor]]: Error
    #: cause code to method mapping, c.f. :meth:`_read_sctp_causes` and
    #: :meth:`_make_sctp_causes`. Method names are expected to be referred to the
    #: class by ``_read_cause_${name}`` and ``_make_cause_${name}``, and if such
    #: name not found, the value should then be a method that can parse the error
    #: cause by itself.
    __cause__ = collections.defaultdict(
        lambda: 'donone',
        {
            Enum_CauseCode.Invalid_Stream_Identifier: 'invalid_stream',
            Enum_CauseCode.Missing_Mandatory_Parameter: 'missing_param',
            Enum_CauseCode.Stale_Cookie: 'stale_cookie',
            Enum_CauseCode.Out_of_Resource: 'out_of_resource',
            Enum_CauseCode.Unresolvable_Address: 'unresolvable_addr',
            Enum_CauseCode.Unrecognized_Chunk_Type: 'unrecognized_chunk',
            Enum_CauseCode.Invalid_Mandatory_Parameter: 'invalid_param',
            Enum_CauseCode.Unrecognized_Parameters: 'unrecognized_params',
            Enum_CauseCode.No_User_Data: 'no_user_data',
            Enum_CauseCode.Cookie_Received_While_Shutting_Down: 'cookie_shutdown',
            Enum_CauseCode.Restart_of_an_Association_with_New_Addresses: 'restart_addr',
            Enum_CauseCode.User_Initiated_Abort: 'user_abort',
            Enum_CauseCode.Protocol_Violation: 'protocol_violation',
        },
    )  # type: DefaultDict[int, str | tuple[CauseParser, CauseConstructor]]

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Stream Control Transmission Protocol"]':
        """Name of current protocol."""
        return 'Stream Control Transmission Protocol'

    @property
    def length(self) -> 'Literal[12]':
        """Header length of current protocol, i.e. the SCTP common header."""
        return 12

    @property
    def src(self) -> 'Enum_AppType':
        """Source port."""
        return self._info.srcport

    @property
    def dst(self) -> 'Enum_AppType':
        """Destination port."""
        return self._info.dstport

    @property
    def ppid(self) -> 'Optional[Enum_PayloadProtocolIdentifier]':
        """Payload protocol identifier of the first DATA chunk of the packet.

        Returns:
            The PPID used to dispatch the next layer, or :obj:`None` if the
            packet carries no DATA chunk.

        """
        return self._ppid

    @property
    def checksum_valid(self) -> 'bool':
        """Whether the recorded CRC32c checksum matches the packet.

        The SCTP checksum covers the common header and every chunk with the
        checksum field itself zeroed, and -- unlike the TCP and UDP checksums --
        involves no IP pseudo-header, so it can be verified from the SCTP packet
        alone. See :rfc:`9260#section-6.8`.

        """
        return self.validate_checksum(bytes(self.__header__))

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_SCTP':  # pylint: disable=unused-argument
        """Read Stream Control Transmission Protocol (SCTP).

        Structure of SCTP common header [:rfc:`9260`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Source Port Number       |    Destination Port Number    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                       Verification Tag                        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                           Checksum                            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                           Chunk #1                            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                              ...                              |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                           Chunk #n                            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        sctp = Data_SCTP(
            srcport=schema.srcport,
            dstport=schema.dstport,
            vtag=schema.vtag,
            chksum=schema.chksum,
            chunks=self._read_sctp_chunks(),
        )

        # NOTE: The next layer is named by the DATA chunk's payload protocol
        # identifier, not by a port number. A packet may bundle several DATA
        # chunks; we dispatch on the first one, and the rest stay recorded in
        # the chunk list.
        self._ppid = None
        self._payload = b''
        for chunk in schema.chunks:
            if chunk.type == Enum_Chunk.Payload_Data:
                chunk = cast('Schema_DATAChunk', chunk)
                self._ppid = chunk.ppid
                self._payload = chunk.data
                break

        return self._decode_next_layer(sctp, self._ppid, len(self._payload))

    def make(self,
             srcport: 'Enum_AppType | int' = 0,
             dstport: 'Enum_AppType | int' = 0,
             vtag: 'int' = 0,
             chksum: 'Optional[bytes]' = None,
             chunks: 'Optional[list[Schema_Chunk | tuple[Enum_Chunk, dict[str, Any]] | bytes] | Chunks]' = None,  # pylint: disable=line-too-long
             **kwargs: 'Any') -> 'Schema_SCTP':
        """Make (construct) packet data.

        Args:
            srcport: Source port.
            dstport: Destination port.
            vtag: Verification tag.
            chksum: Checksum. If :obj:`None`, the CRC32c checksum of the
                constructed packet is computed and inserted, per
                :rfc:`9260#section-6.8`.
            chunks: SCTP chunks.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Note:
            There is no ``payload`` argument: SCTP carries its user data in the
            ``data`` field of a DATA chunk, so the payload is supplied as part
            of that chunk.

        """
        if chunks is not None:
            chunks_value = self._make_sctp_chunks(chunks)
        else:
            chunks_value = []

        schema = Schema_SCTP(
            srcport=self._make_port(srcport, Enum_TransportProtocol.sctp),
            dstport=self._make_port(dstport, Enum_TransportProtocol.sctp),
            vtag=vtag,
            chksum=b'\x00\x00\x00\x00' if chksum is None else chksum,
            chunks=chunks_value,
        )

        if chksum is None:
            schema.chksum = self.calculate_checksum(schema.pack())
        return schema

    @classmethod
    def register(cls, code: 'Enum_PayloadProtocolIdentifier | int', protocol: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None':  # type: ignore[override] # pylint: disable=line-too-long
        r"""Register a new protocol class for a payload protocol identifier.

        Notes:
            The full qualified class name of the new protocol class
            should be as ``{protocol.module}.{protocol.name}``.

        Arguments:
            code: payload protocol identifier (PPID), as in
                :class:`~pcapkit.const.sctp.payload_protocol_identifier.PayloadProtocolIdentifier`
            protocol: module descriptor or a
                :class:`~pcapkit.protocols.protocol.Protocol` subclass

        Important:
            SCTP overrides :meth:`Transport.register
            <pcapkit.protocols.transport.transport.Transport.register>` because
            its :attr:`self.__proto__ <SCTP.__proto__>` registry is keyed by
            PPID rather than by port number.

        Raises:
            pcapkit.utilities.exceptions.RegistryError: If ``protocol`` is not a
                :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass.

        Warns:
            pcapkit.utilities.warnings.RegistryWarning: If this PPID is already
                registered, naming the displaced entry and its replacement so a
                caller can tell *what* was lost. Fires only when the incumbent
                differs from the replacement, as the port-keyed
                :meth:`Transport.register
                <pcapkit.protocols.transport.transport.Transport.register>` it
                overrides does.

        """
        if isinstance(protocol, ModuleDescriptor):
            protocol = protocol.klass
        if not issubclass(protocol, ProtocolBase):
            raise RegistryError(f'protocol must be a Protocol subclass, not {protocol!r}')
        incumbent = cls.__proto__.get(code)
        if incumbent is not None and incumbent is not protocol:
            warn(f'payload protocol identifier {code} already registered, overwriting '
                 f'{incumbent!r} with {protocol!r}', RegistryWarning)
        cls.__proto__[code] = protocol

    @classmethod
    def register_chunk(cls, code: 'Enum_Chunk', meth: 'str | tuple[ChunkParser, ChunkConstructor]') -> 'None':
        """Register a chunk parser.

        Args:
            code: SCTP chunk type.
            meth: Method name or callable to parse and/or construct the chunk.

        """
        if code in cls.__chunk__:
            warn(f'chunk {code} already registered, overwriting', RegistryWarning)
        cls.__chunk__[code] = meth

    @classmethod
    def register_parameter(cls, code: 'Enum_Parameter', meth: 'str | tuple[ParameterParser, ParameterConstructor]') -> 'None':
        """Register a chunk parameter parser.

        Args:
            code: SCTP chunk parameter type.
            meth: Method name or callable to parse and/or construct the parameter.

        """
        if code in cls.__parameter__:
            warn(f'parameter {code} already registered, overwriting', RegistryWarning)
        cls.__parameter__[code] = meth

    @classmethod
    def register_cause(cls, code: 'Enum_CauseCode', meth: 'str | tuple[CauseParser, CauseConstructor]') -> 'None':
        """Register an error cause parser.

        Args:
            code: SCTP error cause code.
            meth: Method name or callable to parse and/or construct the cause.

        """
        if code in cls.__cause__:
            warn(f'error cause {code} already registered, overwriting', RegistryWarning)
        cls.__cause__[code] = meth

    @staticmethod
    def crc32c(data: 'bytes') -> 'int':
        """Calculate the CRC32c of ``data``.

        SCTP uses the CRC32c (Castagnoli) polynomial rather than the one's
        complement internet checksum used by TCP, UDP and IP. The algorithm is
        the reflected, table-driven one given by :rfc:`9260#appendix-A`, with
        the remainder register initialised to all ones and the result
        complemented.

        Args:
            data: Data to checksum.

        Returns:
            The CRC32c value, in host order.

        """
        crc = 0xFFFFFFFF
        for byte in data:
            crc = (crc >> 8) ^ CRC32C_TABLE[(crc ^ byte) & 0xFF]
        return crc ^ 0xFFFFFFFF

    @classmethod
    def calculate_checksum(cls, packet: 'bytes') -> 'bytes':
        """Calculate the checksum field of an SCTP packet.

        Per :rfc:`9260#section-6.8`, the checksum field is first zeroed, the
        CRC32c of the whole packet is then computed, and the result is written
        back into the checksum field. Per :rfc:`9260#appendix-A` the resulting
        four bytes are the CRC32c value in *little*-endian order.

        Args:
            packet: Whole SCTP packet, i.e. the common header followed by every
                chunk. The current contents of the checksum field are ignored.

        Returns:
            The four bytes to place in the checksum field.

        Raises:
            ProtocolError: If ``packet`` is shorter than the 12-byte SCTP
                common header.

        """
        if len(packet) < 12:
            raise ProtocolError('SCTP: invalid format')

        zeroed = packet[:8] + b'\x00\x00\x00\x00' + packet[12:]
        return struct.pack('<I', cls.crc32c(zeroed))

    @classmethod
    def validate_checksum(cls, packet: 'bytes') -> 'bool':
        """Validate the checksum field of an SCTP packet.

        Args:
            packet: Whole SCTP packet, i.e. the common header followed by every
                chunk.

        Returns:
            Whether the checksum field matches the packet contents.

        Raises:
            ProtocolError: If ``packet`` is shorter than the 12-byte SCTP
                common header.

        """
        return cls.calculate_checksum(packet) == packet[8:12]

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[12]':
        """Return an estimated length for the object."""
        return 12

    @classmethod
    def __index__(cls) -> 'Enum_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return Enum_TransType.SCTP  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_SCTP') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'srcport': data.srcport,
            'dstport': data.dstport,
            'vtag': data.vtag,
            'chksum': data.chksum,
            'chunks': data.chunks,
        }

    def _get_payload(self) -> 'bytes':
        """Get payload of the packet.

        SCTP has no payload field in its header schema -- user data travels
        inside DATA chunks -- so this returns the user data of the *first* DATA
        chunk found by :meth:`self.read <SCTP.read>`, which is also the chunk
        whose payload protocol identifier selects the next layer. Should the
        packet carry no DATA chunk, an empty :obj:`bytes` is returned and the
        next layer resolves to
        :class:`~pcapkit.protocols.misc.null.NoPayload`.

        Returns:
            Payload of the packet as :obj:`bytes`.

        """
        return self._payload

    def _decode_next_layer(self, dict_: 'Data_SCTP', proto: 'Optional[int]' = None,  # type: ignore[override]
                           length: 'Optional[int]' = None, *,
                           packet: 'Optional[dict[str, Any]]' = None) -> 'Data_SCTP':
        r"""Decode next layer protocol.

        Arguments:
            dict\_: info buffer
            proto: payload protocol identifier of the DATA chunk carrying the
                payload, if any
            length: valid (*non-padding*) length
            packet: packet info (passed from :meth:`self.unpack <pcapkit.protocols.protocol.Protocol.unpack>`)

        Returns:
            Current protocol with next layer extracted.

        Important:
            This deliberately bypasses :meth:`Transport._decode_next_layer
            <pcapkit.protocols.transport.transport.Transport._decode_next_layer>`,
            which keys the lookup on port numbers, since SCTP keys it on the
            DATA chunk's payload protocol identifier instead.

            The PPID is passed through **unchanged**, registered or not, so that
            an unregistered payload is still labelled with the identifier it
            arrived with -- as :meth:`Internet._import_next_layer
            <pcapkit.protocols.internet.internet.Internet._import_next_layer>`
            does for an unregistered transport type. Resolving it to
            :class:`~pcapkit.protocols.misc.raw.Raw` is
            :meth:`ProtocolBase._import_next_layer
            <pcapkit.protocols.protocol.Protocol._import_next_layer>`'s job,
            which looks the PPID up through
            :meth:`ProtocolBase._lookup_next_layer
            <pcapkit.protocols.protocol.Protocol._lookup_next_layer>` and so
            leaves :attr:`self.__proto__ <SCTP.__proto__>` untouched.

        """
        return ProtocolBase._decode_next_layer(  # pylint: disable=protected-access
            self, dict_, proto, length, packet=packet)  # type: ignore[arg-type,return-value]

    def _read_sctp_chunks(self) -> 'Chunks':
        """Read SCTP chunk list.

        Returns:
            Extracted SCTP chunks.

        """
        chunks = OrderedMultiDict()  # type: Chunks

        for schema in self.__header__.chunks:
            code = schema.type
            name = self._lookup_registry(self.__chunk__, code)

            if isinstance(name, str):
                meth_name = f'_read_chunk_{name}'
                meth = cast('ChunkParser',
                            getattr(self, meth_name, self._read_chunk_donone))
            else:
                meth = name[0]
            chunks.add(code, meth(schema, chunks=chunks))
        return chunks

    def _make_sctp_chunks(self, chunks: 'list[Schema_Chunk | tuple[Enum_Chunk, dict[str, Any]] | bytes] | Chunks') -> 'list[Schema_Chunk | bytes]':  # pylint: disable=line-too-long
        """Make chunks for SCTP.

        Args:
            chunks: SCTP chunks.

        Returns:
            Constructed chunk schemas.

        Note:
            No alignment fix-up happens here, unlike
            :meth:`TCP._make_tcp_options
            <pcapkit.protocols.transport.tcp.TCP._make_tcp_options>`: every
            chunk schema carries its own trailing
            :class:`~pcapkit.corekit.fields.strings.PaddingField`, computed from
            the chunk's own ``length``, so a chunk pads itself to the four-byte
            boundary required by :rfc:`9260#section-3.2`.

        """
        chunks_list = []  # type: list[Schema_Chunk | bytes]

        if isinstance(chunks, list):
            for schema in chunks:
                if isinstance(schema, bytes):
                    chunks_list.append(schema)
                elif isinstance(schema, Schema):
                    chunks_list.append(schema)
                else:
                    code, args = cast('tuple[Enum_Chunk, dict[str, Any]]', schema)
                    chunks_list.append(self._make_sctp_chunk(code, None, **args))
            return chunks_list

        for code, chunk in chunks.items(multi=True):
            chunks_list.append(self._make_sctp_chunk(code, chunk))
        return chunks_list

    def _make_sctp_chunk(self, code: 'Enum_Chunk', chunk: 'Optional[Data_Chunk]' = None,
                         **kwargs: 'Any') -> 'Schema_Chunk':
        """Dispatch to the chunk constructor registered for ``code``.

        Args:
            code: SCTP chunk type.
            chunk: Chunk data, if constructing from a parsed data model.
            **kwargs: Arbitrary keyword arguments for the constructor.

        Returns:
            Constructed chunk schema.

        """
        name = self._lookup_registry(self.__chunk__, code)
        if isinstance(name, str):
            meth_name = f'_make_chunk_{name}'
            meth = cast('ChunkConstructor',
                        getattr(self, meth_name, self._make_chunk_donone))
        else:
            meth = name[1]
        return meth(code, chunk, **kwargs)

    def _read_sctp_parameters(self, schemas: 'list[Schema_Parameter]') -> 'Parameters':
        """Read SCTP chunk parameter list.

        Args:
            schemas: Parsed parameter schemas.

        Returns:
            Extracted SCTP chunk parameters.

        """
        parameters = OrderedMultiDict()  # type: Parameters

        for schema in schemas:
            code = schema.type
            name = self._lookup_registry(self.__parameter__, code)

            if isinstance(name, str):
                meth_name = f'_read_param_{name}'
                meth = cast('ParameterParser',
                            getattr(self, meth_name, self._read_param_donone))
            else:
                meth = name[0]
            parameters.add(code, meth(schema, parameters=parameters))
        return parameters

    def _make_sctp_parameters(self, parameters: 'list[Schema_Parameter | tuple[Enum_Parameter, dict[str, Any]] | bytes] | Parameters') -> 'list[Schema_Parameter | bytes]':  # pylint: disable=line-too-long
        """Make chunk parameters for SCTP.

        Args:
            parameters: SCTP chunk parameters.

        Returns:
            Constructed parameter schemas.

        """
        parameters_list = []  # type: list[Schema_Parameter | bytes]

        if isinstance(parameters, list):
            for schema in parameters:
                if isinstance(schema, (bytes, Schema)):
                    parameters_list.append(schema)
                else:
                    code, args = cast('tuple[Enum_Parameter, dict[str, Any]]', schema)
                    parameters_list.append(self._make_sctp_parameter(code, None, **args))
            return parameters_list

        for code, parameter in parameters.items(multi=True):
            parameters_list.append(self._make_sctp_parameter(code, parameter))
        return parameters_list

    def _make_sctp_parameter(self, code: 'Enum_Parameter', parameter: 'Optional[Data_Parameter]' = None,
                             **kwargs: 'Any') -> 'Schema_Parameter':
        """Dispatch to the parameter constructor registered for ``code``.

        Args:
            code: SCTP chunk parameter type.
            parameter: Parameter data, if constructing from a parsed data model.
            **kwargs: Arbitrary keyword arguments for the constructor.

        Returns:
            Constructed parameter schema.

        """
        name = self._lookup_registry(self.__parameter__, code)
        if isinstance(name, str):
            meth_name = f'_make_param_{name}'
            meth = cast('ParameterConstructor',
                        getattr(self, meth_name, self._make_param_donone))
        else:
            meth = name[1]
        return meth(code, parameter, **kwargs)

    def _read_sctp_causes(self, schemas: 'list[Schema_ErrorCause]') -> 'Causes':
        """Read SCTP error cause list.

        Args:
            schemas: Parsed error cause schemas.

        Returns:
            Extracted SCTP error causes.

        """
        causes = OrderedMultiDict()  # type: Causes

        for schema in schemas:
            code = schema.code
            name = self._lookup_registry(self.__cause__, code)

            if isinstance(name, str):
                meth_name = f'_read_cause_{name}'
                meth = cast('CauseParser',
                            getattr(self, meth_name, self._read_cause_donone))
            else:
                meth = name[0]
            causes.add(code, meth(schema, causes=causes))
        return causes

    def _make_sctp_causes(self, causes: 'list[Schema_ErrorCause | tuple[Enum_CauseCode, dict[str, Any]] | bytes] | Causes') -> 'list[Schema_ErrorCause | bytes]':  # pylint: disable=line-too-long
        """Make error causes for SCTP.

        Args:
            causes: SCTP error causes.

        Returns:
            Constructed error cause schemas.

        """
        causes_list = []  # type: list[Schema_ErrorCause | bytes]

        if isinstance(causes, list):
            for schema in causes:
                if isinstance(schema, (bytes, Schema)):
                    causes_list.append(schema)
                else:
                    code, args = cast('tuple[Enum_CauseCode, dict[str, Any]]', schema)
                    causes_list.append(self._make_sctp_cause(code, None, **args))
            return causes_list

        for code, cause in causes.items(multi=True):
            causes_list.append(self._make_sctp_cause(code, cause))
        return causes_list

    def _make_sctp_cause(self, code: 'Enum_CauseCode', cause: 'Optional[Data_ErrorCause]' = None,
                         **kwargs: 'Any') -> 'Schema_ErrorCause':
        """Dispatch to the error cause constructor registered for ``code``.

        Args:
            code: SCTP error cause code.
            cause: Cause data, if constructing from a parsed data model.
            **kwargs: Arbitrary keyword arguments for the constructor.

        Returns:
            Constructed error cause schema.

        """
        name = self._lookup_registry(self.__cause__, code)
        if isinstance(name, str):
            meth_name = f'_make_cause_{name}'
            meth = cast('CauseConstructor',
                        getattr(self, meth_name, self._make_cause_donone))
        else:
            meth = name[1]
        return meth(code, cause, **kwargs)

    def _read_chunk_donone(self, schema: 'Schema_UnknownChunk', *, chunks: 'Chunks') -> 'Data_UnknownChunk':  # pylint: disable=unused-argument
        """Read SCTP chunk of an unsupported type.

        This is the fall-through for every chunk type :mod:`pcapkit` does not
        implement -- unassigned, reserved, or defined by an SCTP extension --
        as well as for the SCTP-defined but reserved ECNE and CWR chunks. The
        chunk's raw flags and value are recorded verbatim rather than raising,
        so that a bundle containing an unknown chunk still parses.

        Arguments:
            schema: parsed chunk schema
            chunks: extracted SCTP chunks

        Returns:
            Parsed chunk data.

        """
        return Data_UnknownChunk(
            type=schema.type,
            length=schema.length,
            flags=schema.flags,
            value=schema.value,
        )

    def _read_chunk_data(self, schema: 'Schema_DATAChunk', *, chunks: 'Chunks') -> 'Data_DATAChunk':  # pylint: disable=unused-argument
        """Read SCTP DATA chunk.

        Structure of SCTP DATA chunk [:rfc:`9260#section-3.3.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Type = 0    |  Res  |I|U|B|E|            Length             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                              TSN                              |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Stream Identifier S      |   Stream Sequence Number n     |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                  Payload Protocol Identifier                  |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           \\                                                               \\
           /                 User Data (seq n of Stream S)                 /
           \\                                                               \\
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed chunk schema
            chunks: extracted SCTP chunks

        Returns:
            Parsed chunk data.

        Raises:
            ProtocolError: If ``length`` is **NOT** greater than ``16``, since
                :rfc:`9260#section-3.3.1` requires at least one byte of user
                data.

        """
        if schema.length <= 16:
            raise ProtocolError(f'{self.alias}: [Chunk {schema.type}] invalid format')

        return Data_DATAChunk(
            type=schema.type,
            length=schema.length,
            flags=Data_DATAChunkFlags(
                I=bool(schema.flags['I']),
                U=bool(schema.flags['U']),
                B=bool(schema.flags['B']),
                E=bool(schema.flags['E']),
            ),
            tsn=schema.tsn,
            stream_id=schema.stream_id,
            stream_seq=schema.stream_seq,
            ppid=schema.ppid,
            data=schema.data,
        )

    def _read_chunk_init(self, schema: 'Schema_INITChunk', *, chunks: 'Chunks') -> 'Data_INITChunk':  # pylint: disable=unused-argument
        """Read SCTP INIT chunk.

        Structure of SCTP INIT chunk [:rfc:`9260#section-3.3.2`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Type = 1    |  Chunk Flags  |      Chunk Length             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                         Initiate Tag                          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |          Advertised Receiver Window Credit (a_rwnd)           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Number of Outbound Streams   |   Number of Inbound Streams   |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                          Initial TSN                          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           \\                                                               \\
           /              Optional/Variable-Length Parameters              /
           \\                                                               \\
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed chunk schema
            chunks: extracted SCTP chunks

        Returns:
            Parsed chunk data.

        Raises:
            ProtocolError: If ``length`` is **NOT** at least ``20``.

        Note:
            The chunk flags are reserved by :rfc:`9260#section-3.3.2` and are
            therefore not exposed on the data model.

        """
        if schema.length < 20:
            raise ProtocolError(f'{self.alias}: [Chunk {schema.type}] invalid format')

        return Data_INITChunk(
            type=schema.type,
            length=schema.length,
            init_tag=schema.init_tag,
            a_rwnd=schema.a_rwnd,
            outbound_streams=schema.outbound_streams,
            inbound_streams=schema.inbound_streams,
            init_tsn=schema.init_tsn,
            parameters=self._read_sctp_parameters(schema.parameters),
        )

    def _read_chunk_init_ack(self, schema: 'Schema_INITACKChunk', *, chunks: 'Chunks') -> 'Data_INITACKChunk':  # pylint: disable=unused-argument
        """Read SCTP INIT ACK chunk.

        Structure of SCTP INIT ACK chunk [:rfc:`9260#section-3.3.3`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Type = 2    |  Chunk Flags  |         Chunk Length          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                         Initiate Tag                          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |               Advertised Receiver Window Credit               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Number of Outbound Streams   |   Number of Inbound Streams   |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                          Initial TSN                          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           \\                                                               \\
           /              Optional/Variable-Length Parameters              /
           \\                                                               \\
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed chunk schema
            chunks: extracted SCTP chunks

        Returns:
            Parsed chunk data.

        Raises:
            ProtocolError: If ``length`` is **NOT** at least ``20``.

        """
        if schema.length < 20:
            raise ProtocolError(f'{self.alias}: [Chunk {schema.type}] invalid format')

        return Data_INITACKChunk(
            type=schema.type,
            length=schema.length,
            init_tag=schema.init_tag,
            a_rwnd=schema.a_rwnd,
            outbound_streams=schema.outbound_streams,
            inbound_streams=schema.inbound_streams,
            init_tsn=schema.init_tsn,
            parameters=self._read_sctp_parameters(schema.parameters),
        )

    def _read_chunk_sack(self, schema: 'Schema_SACKChunk', *, chunks: 'Chunks') -> 'Data_SACKChunk':  # pylint: disable=unused-argument
        """Read SCTP SACK chunk.

        Structure of SCTP SACK chunk [:rfc:`9260#section-3.3.4`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Type = 3    |  Chunk Flags  |         Chunk Length          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                      Cumulative TSN Ack                       |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |          Advertised Receiver Window Credit (a_rwnd)           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Number of Gap Ack Blocks = N  |  Number of Duplicate TSNs = M |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |    Gap Ack Block #1 Start     |     Gap Ack Block #1 End      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           /                              ...                              /
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                        Duplicate TSN 1                        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           /                              ...                              /
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed chunk schema
            chunks: extracted SCTP chunks

        Returns:
            Parsed chunk data.

        Raises:
            ProtocolError: If ``length`` does **NOT** match the declared number
                of gap ack blocks and duplicate TSNs.

        """
        if schema.length != 16 + schema.num_gap_blocks * 4 + schema.num_dup_tsn * 4:
            raise ProtocolError(f'{self.alias}: [Chunk {schema.type}] invalid format')

        return Data_SACKChunk(
            type=schema.type,
            length=schema.length,
            cum_tsn_ack=schema.cum_tsn_ack,
            a_rwnd=schema.a_rwnd,
            num_gap_blocks=schema.num_gap_blocks,
            num_dup_tsn=schema.num_dup_tsn,
            gap_blocks=tuple(
                Data_GapAckBlock(
                    start=block.start,
                    end=block.end,
                ) for block in schema.gap_blocks
            ),
            dup_tsn=tuple(schema.dup_tsn),
        )

    def _read_chunk_heartbeat(self, schema: 'Schema_HeartbeatChunk', *, chunks: 'Chunks') -> 'Data_HeartbeatChunk':  # pylint: disable=unused-argument
        """Read SCTP HEARTBEAT chunk.

        Structure of SCTP HEARTBEAT chunk [:rfc:`9260#section-3.3.5`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Type = 4    |  Chunk Flags  |       Heartbeat Length        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           \\                                                               \\
           /          Heartbeat Information TLV (Variable-Length)          /
           \\                                                               \\
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed chunk schema
            chunks: extracted SCTP chunks

        Returns:
            Parsed chunk data.

        Raises:
            ProtocolError: If ``length`` is **NOT** at least ``4``.

        Note:
            :rfc:`9260#section-3.3.5` mandates exactly one Heartbeat Info
            parameter, but the parameters are modelled as a list so that a
            sender emitting more (or none) still parses.

        """
        if schema.length < 4:
            raise ProtocolError(f'{self.alias}: [Chunk {schema.type}] invalid format')

        return Data_HeartbeatChunk(
            type=schema.type,
            length=schema.length,
            parameters=self._read_sctp_parameters(schema.parameters),
        )

    def _read_chunk_heartbeat_ack(self, schema: 'Schema_HeartbeatACKChunk', *, chunks: 'Chunks') -> 'Data_HeartbeatACKChunk':  # pylint: disable=unused-argument
        """Read SCTP HEARTBEAT ACK chunk.

        Structure of SCTP HEARTBEAT ACK chunk [:rfc:`9260#section-3.3.6`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Type = 5    |  Chunk Flags  |     Heartbeat Ack Length      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           \\                                                               \\
           /          Heartbeat Information TLV (Variable-Length)          /
           \\                                                               \\
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed chunk schema
            chunks: extracted SCTP chunks

        Returns:
            Parsed chunk data.

        Raises:
            ProtocolError: If ``length`` is **NOT** at least ``4``.

        """
        if schema.length < 4:
            raise ProtocolError(f'{self.alias}: [Chunk {schema.type}] invalid format')

        return Data_HeartbeatACKChunk(
            type=schema.type,
            length=schema.length,
            parameters=self._read_sctp_parameters(schema.parameters),
        )

    def _read_chunk_abort(self, schema: 'Schema_AbortChunk', *, chunks: 'Chunks') -> 'Data_AbortChunk':  # pylint: disable=unused-argument
        """Read SCTP ABORT chunk.

        Structure of SCTP ABORT chunk [:rfc:`9260#section-3.3.7`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Type = 6    |  Reserved   |T|            Length             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           \\                                                               \\
           /                   zero or more Error Causes                   /
           \\                                                               \\
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed chunk schema
            chunks: extracted SCTP chunks

        Returns:
            Parsed chunk data.

        Raises:
            ProtocolError: If ``length`` is **NOT** at least ``4``.

        """
        if schema.length < 4:
            raise ProtocolError(f'{self.alias}: [Chunk {schema.type}] invalid format')

        return Data_AbortChunk(
            type=schema.type,
            length=schema.length,
            flags=Data_TBitFlags(
                T=bool(schema.flags['T']),
            ),
            error=self._read_sctp_causes(schema.error),
        )

    def _read_chunk_shutdown(self, schema: 'Schema_ShutdownChunk', *, chunks: 'Chunks') -> 'Data_ShutdownChunk':  # pylint: disable=unused-argument
        """Read SCTP SHUTDOWN chunk.

        Structure of SCTP SHUTDOWN chunk [:rfc:`9260#section-3.3.8`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Type = 7    |  Chunk Flags  |          Length = 8           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                      Cumulative TSN Ack                       |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed chunk schema
            chunks: extracted SCTP chunks

        Returns:
            Parsed chunk data.

        Raises:
            ProtocolError: If ``length`` is **NOT** ``8``.

        """
        if schema.length != 8:
            raise ProtocolError(f'{self.alias}: [Chunk {schema.type}] invalid format')

        return Data_ShutdownChunk(
            type=schema.type,
            length=schema.length,
            cum_tsn_ack=schema.cum_tsn_ack,
        )

    def _read_chunk_shutdown_ack(self, schema: 'Schema_ShutdownACKChunk', *, chunks: 'Chunks') -> 'Data_ShutdownACKChunk':  # pylint: disable=unused-argument
        """Read SCTP SHUTDOWN ACK chunk.

        Structure of SCTP SHUTDOWN ACK chunk [:rfc:`9260#section-3.3.9`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Type = 8    |  Chunk Flags  |          Length = 4           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed chunk schema
            chunks: extracted SCTP chunks

        Returns:
            Parsed chunk data.

        Raises:
            ProtocolError: If ``length`` is **NOT** ``4``.

        """
        if schema.length != 4:
            raise ProtocolError(f'{self.alias}: [Chunk {schema.type}] invalid format')

        return Data_ShutdownACKChunk(
            type=schema.type,
            length=schema.length,
        )

    def _read_chunk_error(self, schema: 'Schema_ErrorChunk', *, chunks: 'Chunks') -> 'Data_ErrorChunk':  # pylint: disable=unused-argument
        """Read SCTP ERROR chunk.

        Structure of SCTP ERROR chunk [:rfc:`9260#section-3.3.10`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Type = 9    |  Chunk Flags  |            Length             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           \\                                                               \\
           /                   one or more Error Causes                    /
           \\                                                               \\
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed chunk schema
            chunks: extracted SCTP chunks

        Returns:
            Parsed chunk data.

        Raises:
            ProtocolError: If ``length`` is **NOT** at least ``4``.

        """
        if schema.length < 4:
            raise ProtocolError(f'{self.alias}: [Chunk {schema.type}] invalid format')

        return Data_ErrorChunk(
            type=schema.type,
            length=schema.length,
            error=self._read_sctp_causes(schema.error),
        )

    def _read_chunk_cookie_echo(self, schema: 'Schema_CookieEchoChunk', *, chunks: 'Chunks') -> 'Data_CookieEchoChunk':  # pylint: disable=unused-argument
        """Read SCTP COOKIE ECHO chunk.

        Structure of SCTP COOKIE ECHO chunk [:rfc:`9260#section-3.3.11`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Type = 10   |  Chunk Flags  |            Length             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           /                            Cookie                             /
           \\                                                               \\
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed chunk schema
            chunks: extracted SCTP chunks

        Returns:
            Parsed chunk data.

        Raises:
            ProtocolError: If ``length`` is **NOT** at least ``4``.

        Note:
            A COOKIE ECHO chunk carries the *contents* of the state cookie
            parameter rather than the parameter itself, so the cookie is a plain
            :obj:`bytes` here rather than a
            :class:`~pcapkit.protocols.data.transport.sctp.StateCookieParameter`.

        """
        if schema.length < 4:
            raise ProtocolError(f'{self.alias}: [Chunk {schema.type}] invalid format')

        return Data_CookieEchoChunk(
            type=schema.type,
            length=schema.length,
            cookie=schema.cookie,
        )

    def _read_chunk_cookie_ack(self, schema: 'Schema_CookieACKChunk', *, chunks: 'Chunks') -> 'Data_CookieACKChunk':  # pylint: disable=unused-argument
        """Read SCTP COOKIE ACK chunk.

        Structure of SCTP COOKIE ACK chunk [:rfc:`9260#section-3.3.12`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Type = 11   |  Chunk Flags  |          Length = 4           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed chunk schema
            chunks: extracted SCTP chunks

        Returns:
            Parsed chunk data.

        Raises:
            ProtocolError: If ``length`` is **NOT** ``4``.

        """
        if schema.length != 4:
            raise ProtocolError(f'{self.alias}: [Chunk {schema.type}] invalid format')

        return Data_CookieACKChunk(
            type=schema.type,
            length=schema.length,
        )

    def _read_chunk_shutdown_complete(self, schema: 'Schema_ShutdownCompleteChunk', *, chunks: 'Chunks') -> 'Data_ShutdownCompleteChunk':  # pylint: disable=unused-argument
        """Read SCTP SHUTDOWN COMPLETE chunk.

        Structure of SCTP SHUTDOWN COMPLETE chunk [:rfc:`9260#section-3.3.13`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Type = 14   |  Reserved   |T|          Length = 4           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed chunk schema
            chunks: extracted SCTP chunks

        Returns:
            Parsed chunk data.

        Raises:
            ProtocolError: If ``length`` is **NOT** ``4``.

        """
        if schema.length != 4:
            raise ProtocolError(f'{self.alias}: [Chunk {schema.type}] invalid format')

        return Data_ShutdownCompleteChunk(
            type=schema.type,
            length=schema.length,
            flags=Data_TBitFlags(
                T=bool(schema.flags['T']),
            ),
        )

    def _make_chunk_donone(self, code: 'Enum_Chunk', chunk: 'Optional[Data_UnknownChunk]' = None, *,
                           flags: 'bytes' = b'\x00',
                           value: 'bytes' = b'',
                           **kwargs: 'Any') -> 'Schema_UnknownChunk':
        """Make SCTP chunk of an unsupported type.

        Args:
            code: chunk type
            chunk: chunk data
            flags: raw chunk flags, as a single byte
            value: chunk value in :obj:`bytes`
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed chunk schema.

        Raises:
            ProtocolError: If ``flags`` is **NOT** exactly one byte.

        """
        if chunk is not None:
            flags = chunk.flags
            value = chunk.value

        if len(flags) != 1:
            raise ProtocolError(f'{self.alias}: [Chunk {code}] invalid format')

        return Schema_UnknownChunk(
            type=code,
            flags=flags,
            length=len(value) + 4,
            value=value,
        )

    def _make_chunk_data(self, code: 'Enum_Chunk', chunk: 'Optional[Data_DATAChunk]' = None, *,
                         I: 'bool' = False,  # noqa: E741
                         U: 'bool' = False,
                         B: 'bool' = True,
                         E: 'bool' = True,
                         tsn: 'int' = 0,
                         stream_id: 'int' = 0,
                         stream_seq: 'int' = 0,
                         ppid: 'Enum_PayloadProtocolIdentifier | int' = 0,
                         data: 'bytes' = b'',
                         **kwargs: 'Any') -> 'Schema_DATAChunk':
        """Make SCTP DATA chunk.

        Args:
            code: chunk type
            chunk: chunk data
            I: immediate bit
            U: unordered bit
            B: beginning fragment bit
            E: ending fragment bit
            tsn: transmission sequence number
            stream_id: stream identifier
            stream_seq: stream sequence number
            ppid: payload protocol identifier
            data: user data
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed chunk schema.

        Raises:
            ProtocolError: If ``data`` is empty, since :rfc:`9260#section-3.3.1`
                requires at least one byte of user data.

        """
        if chunk is not None:
            I = chunk.flags.I  # noqa: E741
            U = chunk.flags.U
            B = chunk.flags.B
            E = chunk.flags.E
            tsn = chunk.tsn
            stream_id = chunk.stream_id
            stream_seq = chunk.stream_seq
            ppid = chunk.ppid
            data = chunk.data

        if not data:
            raise ProtocolError(f'{self.alias}: [Chunk {code}] invalid format')

        return Schema_DATAChunk(
            type=code,
            flags={
                'I': int(I),
                'U': int(U),
                'B': int(B),
                'E': int(E),
            },
            length=len(data) + 16,
            tsn=tsn,
            stream_id=stream_id,
            stream_seq=stream_seq,
            ppid=ppid,
            data=data,
        )

    def _make_chunk_init(self, code: 'Enum_Chunk', chunk: 'Optional[Data_INITChunk]' = None, *,
                         init_tag: 'int' = 0,
                         a_rwnd: 'int' = 1500,  # minimum permitted by [RFC 9260]
                         outbound_streams: 'int' = 1,
                         inbound_streams: 'int' = 1,
                         init_tsn: 'int' = 0,
                         parameters: 'Optional[list[Schema_Parameter | tuple[Enum_Parameter, dict[str, Any]] | bytes] | Parameters]' = None,  # pylint: disable=line-too-long
                         **kwargs: 'Any') -> 'Schema_INITChunk':
        """Make SCTP INIT chunk.

        Args:
            code: chunk type
            chunk: chunk data
            init_tag: initiate tag
            a_rwnd: advertised receiver window credit
            outbound_streams: number of outbound streams
            inbound_streams: number of inbound streams
            init_tsn: initial transmission sequence number
            parameters: optional and variable-length parameters
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed chunk schema.

        Note:
            The chunk flags are reserved by :rfc:`9260#section-3.3.2` and are
            always emitted as zero.

        """
        if chunk is not None:
            init_tag = chunk.init_tag
            a_rwnd = chunk.a_rwnd
            outbound_streams = chunk.outbound_streams
            inbound_streams = chunk.inbound_streams
            init_tsn = chunk.init_tsn
            parameters = chunk.parameters

        if parameters is not None:
            parameters_value = self._make_sctp_parameters(parameters)
        else:
            parameters_value = []
        length = 20 + sum(len(param) if isinstance(param, bytes) else len(param.pack())
                          for param in parameters_value)

        return Schema_INITChunk(
            type=code,
            flags=b'\x00',
            length=length,
            init_tag=init_tag,
            a_rwnd=a_rwnd,
            outbound_streams=outbound_streams,
            inbound_streams=inbound_streams,
            init_tsn=init_tsn,
            parameters=parameters_value,
        )

    def _make_chunk_init_ack(self, code: 'Enum_Chunk', chunk: 'Optional[Data_INITACKChunk]' = None, *,
                             init_tag: 'int' = 0,
                             a_rwnd: 'int' = 1500,  # minimum permitted by [RFC 9260]
                             outbound_streams: 'int' = 1,
                             inbound_streams: 'int' = 1,
                             init_tsn: 'int' = 0,
                             parameters: 'Optional[list[Schema_Parameter | tuple[Enum_Parameter, dict[str, Any]] | bytes] | Parameters]' = None,  # pylint: disable=line-too-long
                             **kwargs: 'Any') -> 'Schema_INITACKChunk':
        """Make SCTP INIT ACK chunk.

        Args:
            code: chunk type
            chunk: chunk data
            init_tag: initiate tag
            a_rwnd: advertised receiver window credit
            outbound_streams: number of outbound streams
            inbound_streams: number of inbound streams
            init_tsn: initial transmission sequence number
            parameters: optional and variable-length parameters
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed chunk schema.

        """
        if chunk is not None:
            init_tag = chunk.init_tag
            a_rwnd = chunk.a_rwnd
            outbound_streams = chunk.outbound_streams
            inbound_streams = chunk.inbound_streams
            init_tsn = chunk.init_tsn
            parameters = chunk.parameters

        if parameters is not None:
            parameters_value = self._make_sctp_parameters(parameters)
        else:
            parameters_value = []
        length = 20 + sum(len(param) if isinstance(param, bytes) else len(param.pack())
                          for param in parameters_value)

        return Schema_INITACKChunk(
            type=code,
            flags=b'\x00',
            length=length,
            init_tag=init_tag,
            a_rwnd=a_rwnd,
            outbound_streams=outbound_streams,
            inbound_streams=inbound_streams,
            init_tsn=init_tsn,
            parameters=parameters_value,
        )

    def _make_chunk_sack(self, code: 'Enum_Chunk', chunk: 'Optional[Data_SACKChunk]' = None, *,
                         cum_tsn_ack: 'int' = 0,
                         a_rwnd: 'int' = 1500,  # minimum permitted by [RFC 9260]
                         gap_blocks: 'Optional[list[Schema_GapAckBlock | Data_GapAckBlock | tuple[int, int]]]' = None,  # pylint: disable=line-too-long
                         dup_tsn: 'Optional[list[int]]' = None,
                         **kwargs: 'Any') -> 'Schema_SACKChunk':
        """Make SCTP SACK chunk.

        Args:
            code: chunk type
            chunk: chunk data
            cum_tsn_ack: cumulative TSN ack
            a_rwnd: advertised receiver window credit
            gap_blocks: gap ack blocks, each as a schema, a data model or a
                ``(start, end)`` pair
            dup_tsn: duplicate TSNs
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed chunk schema.

        Note:
            The counts of gap ack blocks and duplicate TSNs are derived from the
            supplied lists rather than taken as arguments, so that they cannot
            disagree with the lists they count.

        """
        if chunk is not None:
            cum_tsn_ack = chunk.cum_tsn_ack
            a_rwnd = chunk.a_rwnd
            gap_blocks = list(chunk.gap_blocks)
            dup_tsn = list(chunk.dup_tsn)

        blocks = []  # type: list[Schema_GapAckBlock]
        for block in gap_blocks or []:
            if isinstance(block, Schema_GapAckBlock):
                blocks.append(block)
            elif isinstance(block, Data_GapAckBlock):
                blocks.append(Schema_GapAckBlock(start=block.start, end=block.end))
            else:
                start, end = cast('tuple[int, int]', block)
                blocks.append(Schema_GapAckBlock(start=start, end=end))
        tsn_list = list(dup_tsn or [])

        return Schema_SACKChunk(
            type=code,
            flags=b'\x00',
            length=16 + len(blocks) * 4 + len(tsn_list) * 4,
            cum_tsn_ack=cum_tsn_ack,
            a_rwnd=a_rwnd,
            num_gap_blocks=len(blocks),
            num_dup_tsn=len(tsn_list),
            gap_blocks=blocks,
            dup_tsn=tsn_list,
        )

    def _make_chunk_heartbeat(self, code: 'Enum_Chunk', chunk: 'Optional[Data_HeartbeatChunk]' = None, *,
                              parameters: 'Optional[list[Schema_Parameter | tuple[Enum_Parameter, dict[str, Any]] | bytes] | Parameters]' = None,  # pylint: disable=line-too-long
                              **kwargs: 'Any') -> 'Schema_HeartbeatChunk':
        """Make SCTP HEARTBEAT chunk.

        Args:
            code: chunk type
            chunk: chunk data
            parameters: heartbeat information parameters
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed chunk schema.

        """
        if chunk is not None:
            parameters = chunk.parameters

        if parameters is not None:
            parameters_value = self._make_sctp_parameters(parameters)
        else:
            parameters_value = []
        length = 4 + sum(len(param) if isinstance(param, bytes) else len(param.pack())
                         for param in parameters_value)

        return Schema_HeartbeatChunk(
            type=code,
            flags=b'\x00',
            length=length,
            parameters=parameters_value,
        )

    def _make_chunk_heartbeat_ack(self, code: 'Enum_Chunk', chunk: 'Optional[Data_HeartbeatACKChunk]' = None, *,
                                  parameters: 'Optional[list[Schema_Parameter | tuple[Enum_Parameter, dict[str, Any]] | bytes] | Parameters]' = None,  # pylint: disable=line-too-long
                                  **kwargs: 'Any') -> 'Schema_HeartbeatACKChunk':
        """Make SCTP HEARTBEAT ACK chunk.

        Args:
            code: chunk type
            chunk: chunk data
            parameters: heartbeat information parameters
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed chunk schema.

        """
        if chunk is not None:
            parameters = chunk.parameters

        if parameters is not None:
            parameters_value = self._make_sctp_parameters(parameters)
        else:
            parameters_value = []
        length = 4 + sum(len(param) if isinstance(param, bytes) else len(param.pack())
                         for param in parameters_value)

        return Schema_HeartbeatACKChunk(
            type=code,
            flags=b'\x00',
            length=length,
            parameters=parameters_value,
        )

    def _make_chunk_abort(self, code: 'Enum_Chunk', chunk: 'Optional[Data_AbortChunk]' = None, *,
                          T: 'bool' = False,
                          error: 'Optional[list[Schema_ErrorCause | tuple[Enum_CauseCode, dict[str, Any]] | bytes] | Causes]' = None,  # pylint: disable=line-too-long
                          **kwargs: 'Any') -> 'Schema_AbortChunk':
        """Make SCTP ABORT chunk.

        Args:
            code: chunk type
            chunk: chunk data
            T: whether the verification tag has been reflected
            error: zero or more error causes
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed chunk schema.

        """
        if chunk is not None:
            T = chunk.flags.T
            error = chunk.error

        if error is not None:
            error_value = self._make_sctp_causes(error)
        else:
            error_value = []
        length = 4 + sum(len(cause) if isinstance(cause, bytes) else len(cause.pack())
                         for cause in error_value)

        return Schema_AbortChunk(
            type=code,
            flags={
                'T': int(T),
            },
            length=length,
            error=error_value,
        )

    def _make_chunk_shutdown(self, code: 'Enum_Chunk', chunk: 'Optional[Data_ShutdownChunk]' = None, *,
                             cum_tsn_ack: 'int' = 0,
                             **kwargs: 'Any') -> 'Schema_ShutdownChunk':
        """Make SCTP SHUTDOWN chunk.

        Args:
            code: chunk type
            chunk: chunk data
            cum_tsn_ack: cumulative TSN ack
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed chunk schema.

        """
        if chunk is not None:
            cum_tsn_ack = chunk.cum_tsn_ack

        return Schema_ShutdownChunk(
            type=code,
            flags=b'\x00',
            length=8,
            cum_tsn_ack=cum_tsn_ack,
        )

    def _make_chunk_shutdown_ack(self, code: 'Enum_Chunk', chunk: 'Optional[Data_ShutdownACKChunk]' = None,
                                 **kwargs: 'Any') -> 'Schema_ShutdownACKChunk':
        """Make SCTP SHUTDOWN ACK chunk.

        Args:
            code: chunk type
            chunk: chunk data
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed chunk schema.

        """
        return Schema_ShutdownACKChunk(
            type=code,
            flags=b'\x00',
            length=4,
        )

    def _make_chunk_error(self, code: 'Enum_Chunk', chunk: 'Optional[Data_ErrorChunk]' = None, *,
                          error: 'Optional[list[Schema_ErrorCause | tuple[Enum_CauseCode, dict[str, Any]] | bytes] | Causes]' = None,  # pylint: disable=line-too-long
                          **kwargs: 'Any') -> 'Schema_ErrorChunk':
        """Make SCTP ERROR chunk.

        Args:
            code: chunk type
            chunk: chunk data
            error: one or more error causes
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed chunk schema.

        """
        if chunk is not None:
            error = chunk.error

        if error is not None:
            error_value = self._make_sctp_causes(error)
        else:
            error_value = []
        length = 4 + sum(len(cause) if isinstance(cause, bytes) else len(cause.pack())
                         for cause in error_value)

        return Schema_ErrorChunk(
            type=code,
            flags=b'\x00',
            length=length,
            error=error_value,
        )

    def _make_chunk_cookie_echo(self, code: 'Enum_Chunk', chunk: 'Optional[Data_CookieEchoChunk]' = None, *,
                                cookie: 'bytes' = b'',
                                **kwargs: 'Any') -> 'Schema_CookieEchoChunk':
        """Make SCTP COOKIE ECHO chunk.

        Args:
            code: chunk type
            chunk: chunk data
            cookie: state cookie, as received in the INIT ACK chunk's state
                cookie parameter
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed chunk schema.

        """
        if chunk is not None:
            cookie = chunk.cookie

        return Schema_CookieEchoChunk(
            type=code,
            flags=b'\x00',
            length=len(cookie) + 4,
            cookie=cookie,
        )

    def _make_chunk_cookie_ack(self, code: 'Enum_Chunk', chunk: 'Optional[Data_CookieACKChunk]' = None,
                               **kwargs: 'Any') -> 'Schema_CookieACKChunk':
        """Make SCTP COOKIE ACK chunk.

        Args:
            code: chunk type
            chunk: chunk data
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed chunk schema.

        """
        return Schema_CookieACKChunk(
            type=code,
            flags=b'\x00',
            length=4,
        )

    def _make_chunk_shutdown_complete(self, code: 'Enum_Chunk', chunk: 'Optional[Data_ShutdownCompleteChunk]' = None, *,
                                      T: 'bool' = False,
                                      **kwargs: 'Any') -> 'Schema_ShutdownCompleteChunk':
        """Make SCTP SHUTDOWN COMPLETE chunk.

        Args:
            code: chunk type
            chunk: chunk data
            T: whether the verification tag has been reflected
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed chunk schema.

        """
        if chunk is not None:
            T = chunk.flags.T

        return Schema_ShutdownCompleteChunk(
            type=code,
            flags={
                'T': int(T),
            },
            length=4,
        )

    def _read_param_donone(self, schema: 'Schema_UnknownParameter', *, parameters: 'Parameters') -> 'Data_UnknownParameter':  # pylint: disable=unused-argument
        """Read SCTP chunk parameter of an unsupported type.

        This is the fall-through for every chunk parameter type :mod:`pcapkit`
        does not implement. The parameter's value is recorded verbatim rather
        than raising, so a chunk carrying an unknown parameter still parses.

        Arguments:
            schema: parsed parameter schema
            parameters: extracted SCTP chunk parameters

        Returns:
            Parsed parameter data.

        """
        return Data_UnknownParameter(
            type=schema.type,
            length=schema.length,
            value=schema.value,
        )

    def _read_param_hbinfo(self, schema: 'Schema_HeartbeatInfoParameter', *, parameters: 'Parameters') -> 'Data_HeartbeatInfoParameter':  # pylint: disable=unused-argument
        """Read SCTP heartbeat info parameter.

        Structure of SCTP heartbeat info parameter [:rfc:`9260#section-3.3.5`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |    Heartbeat Info Type = 1    |        HB Info Length         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           /                Sender-Specific Heartbeat Info                 /
           \\                                                               \\
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed parameter schema
            parameters: extracted SCTP chunk parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``length`` is **NOT** at least ``4``.

        """
        if schema.length < 4:
            raise ProtocolError(f'{self.alias}: [Param {schema.type}] invalid format')

        return Data_HeartbeatInfoParameter(
            type=schema.type,
            length=schema.length,
            info=schema.info,
        )

    def _read_param_ipv4(self, schema: 'Schema_IPv4AddressParameter', *, parameters: 'Parameters') -> 'Data_IPv4AddressParameter':  # pylint: disable=unused-argument
        """Read SCTP IPv4 address parameter.

        Structure of SCTP IPv4 address parameter [:rfc:`9260#section-3.3.2.1.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |           Type = 5            |          Length = 8           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                         IPv4 Address                          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed parameter schema
            parameters: extracted SCTP chunk parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``length`` is **NOT** ``8``.

        """
        if schema.length != 8:
            raise ProtocolError(f'{self.alias}: [Param {schema.type}] invalid format')

        return Data_IPv4AddressParameter(
            type=schema.type,
            length=schema.length,
            address=schema.address,
        )

    def _read_param_ipv6(self, schema: 'Schema_IPv6AddressParameter', *, parameters: 'Parameters') -> 'Data_IPv6AddressParameter':  # pylint: disable=unused-argument
        """Read SCTP IPv6 address parameter.

        Structure of SCTP IPv6 address parameter [:rfc:`9260#section-3.3.2.1.2`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |           Type = 6            |          Length = 20          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           |                         IPv6 Address                          |
           |                                                               |
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed parameter schema
            parameters: extracted SCTP chunk parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``length`` is **NOT** ``20``.

        """
        if schema.length != 20:
            raise ProtocolError(f'{self.alias}: [Param {schema.type}] invalid format')

        return Data_IPv6AddressParameter(
            type=schema.type,
            length=schema.length,
            address=schema.address,
        )

    def _read_param_cookie(self, schema: 'Schema_StateCookieParameter', *, parameters: 'Parameters') -> 'Data_StateCookieParameter':  # pylint: disable=unused-argument
        """Read SCTP state cookie parameter.

        Structure of SCTP state cookie parameter [:rfc:`9260#section-3.3.3.1.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |           Type = 7            |            Length             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           /                            Cookie                             /
           \\                                                               \\
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed parameter schema
            parameters: extracted SCTP chunk parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``length`` is **NOT** at least ``4``.

        """
        if schema.length < 4:
            raise ProtocolError(f'{self.alias}: [Param {schema.type}] invalid format')

        return Data_StateCookieParameter(
            type=schema.type,
            length=schema.length,
            cookie=schema.cookie,
        )

    def _read_param_unrecognized(self, schema: 'Schema_UnrecognizedParameter', *, parameters: 'Parameters') -> 'Data_UnrecognizedParameter':  # pylint: disable=unused-argument
        """Read SCTP unrecognized parameter parameter.

        Structure of SCTP unrecognized parameter [:rfc:`9260#section-3.3.3.1.2`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |           Type = 8            |            Length             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           /                  Unrecognized Parameter                       /
           \\                                                               \\
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed parameter schema
            parameters: extracted SCTP chunk parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``length`` is **NOT** at least ``4``.

        Note:
            The offending parameter is recorded as raw :obj:`bytes`, complete
            with its own type and length, rather than being parsed recursively:
            by definition the sender did not recognise it, so neither
            interpretation nor validation of its contents would be meaningful.

        """
        if schema.length < 4:
            raise ProtocolError(f'{self.alias}: [Param {schema.type}] invalid format')

        return Data_UnrecognizedParameter(
            type=schema.type,
            length=schema.length,
            value=schema.value,
        )

    def _read_param_preservative(self, schema: 'Schema_CookiePreservativeParameter', *, parameters: 'Parameters') -> 'Data_CookiePreservativeParameter':  # pylint: disable=unused-argument
        """Read SCTP cookie preservative parameter.

        Structure of SCTP cookie preservative parameter [:rfc:`9260#section-3.3.2.1.3`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |           Type = 9            |          Length = 8           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |         Suggested Cookie Life-Span Increment (msec.)          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed parameter schema
            parameters: extracted SCTP chunk parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``length`` is **NOT** ``8``.

        """
        if schema.length != 8:
            raise ProtocolError(f'{self.alias}: [Param {schema.type}] invalid format')

        return Data_CookiePreservativeParameter(
            type=schema.type,
            length=schema.length,
            increment=schema.increment,
        )

    def _read_param_hostname(self, schema: 'Schema_HostNameAddressParameter', *, parameters: 'Parameters') -> 'Data_HostNameAddressParameter':  # pylint: disable=unused-argument
        """Read SCTP host name address parameter.

        Structure of SCTP host name address parameter [:rfc:`9260#section-3.3.2.1.4`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |           Type = 11           |            Length             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           /                           Host Name                           /
           \\                                                               \\
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed parameter schema
            parameters: extracted SCTP chunk parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``length`` is **NOT** at least ``4``.

        Note:
            The usage of this parameter is deprecated by
            :rfc:`9260#section-3.3.2.1.4`; it is parsed so that a packet
            carrying one can still be inspected. The host name is kept as raw
            :obj:`bytes`, including its null terminator, since the encoding is
            not specified on the wire.

        """
        if schema.length < 4:
            raise ProtocolError(f'{self.alias}: [Param {schema.type}] invalid format')

        return Data_HostNameAddressParameter(
            type=schema.type,
            length=schema.length,
            name=schema.name,
        )

    def _read_param_addrtypes(self, schema: 'Schema_SupportedAddressTypesParameter', *, parameters: 'Parameters') -> 'Data_SupportedAddressTypesParameter':  # pylint: disable=unused-argument
        """Read SCTP supported address types parameter.

        Structure of SCTP supported address types parameter [:rfc:`9260#section-3.3.2.1.5`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |           Type = 12           |            Length             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |        Address Type #1        |        Address Type #2        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                            ......                             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed parameter schema
            parameters: extracted SCTP chunk parameters

        Returns:
            Parsed parameter data.

        Raises:
            ProtocolError: If ``length`` is **NOT** ``4`` plus a multiple of
                ``2``.

        """
        if schema.length < 4 or (schema.length - 4) % 2:
            raise ProtocolError(f'{self.alias}: [Param {schema.type}] invalid format')

        return Data_SupportedAddressTypesParameter(
            type=schema.type,
            length=schema.length,
            types=tuple(schema.types),
        )

    def _make_param_donone(self, code: 'Enum_Parameter', param: 'Optional[Data_UnknownParameter]' = None, *,
                           value: 'bytes' = b'',
                           **kwargs: 'Any') -> 'Schema_UnknownParameter':
        """Make SCTP chunk parameter of an unsupported type.

        Args:
            code: parameter type
            param: parameter data
            value: parameter value in :obj:`bytes`
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed parameter schema.

        """
        if param is not None:
            value = param.value

        return Schema_UnknownParameter(
            type=code,
            length=len(value) + 4,
            value=value,
        )

    def _make_param_hbinfo(self, code: 'Enum_Parameter', param: 'Optional[Data_HeartbeatInfoParameter]' = None, *,
                           info: 'bytes' = b'',
                           **kwargs: 'Any') -> 'Schema_HeartbeatInfoParameter':
        """Make SCTP heartbeat info parameter.

        Args:
            code: parameter type
            param: parameter data
            info: sender-specific heartbeat info
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed parameter schema.

        """
        if param is not None:
            info = param.info

        return Schema_HeartbeatInfoParameter(
            type=code,
            length=len(info) + 4,
            info=info,
        )

    def _make_param_ipv4(self, code: 'Enum_Parameter', param: 'Optional[Data_IPv4AddressParameter]' = None, *,
                         address: 'IPv4Address | int | str | bytes' = '0.0.0.0',  # nosec: B104
                         **kwargs: 'Any') -> 'Schema_IPv4AddressParameter':
        """Make SCTP IPv4 address parameter.

        Args:
            code: parameter type
            param: parameter data
            address: IPv4 address of the sending endpoint
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed parameter schema.

        """
        if param is not None:
            address = param.address

        return Schema_IPv4AddressParameter(
            type=code,
            length=8,
            address=address,
        )

    def _make_param_ipv6(self, code: 'Enum_Parameter', param: 'Optional[Data_IPv6AddressParameter]' = None, *,
                         address: 'IPv6Address | int | str | bytes' = '::',
                         **kwargs: 'Any') -> 'Schema_IPv6AddressParameter':
        """Make SCTP IPv6 address parameter.

        Args:
            code: parameter type
            param: parameter data
            address: IPv6 address of the sending endpoint
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed parameter schema.

        """
        if param is not None:
            address = param.address

        return Schema_IPv6AddressParameter(
            type=code,
            length=20,
            address=address,
        )

    def _make_param_cookie(self, code: 'Enum_Parameter', param: 'Optional[Data_StateCookieParameter]' = None, *,
                           cookie: 'bytes' = b'',
                           **kwargs: 'Any') -> 'Schema_StateCookieParameter':
        """Make SCTP state cookie parameter.

        Args:
            code: parameter type
            param: parameter data
            cookie: state cookie
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed parameter schema.

        """
        if param is not None:
            cookie = param.cookie

        return Schema_StateCookieParameter(
            type=code,
            length=len(cookie) + 4,
            cookie=cookie,
        )

    def _make_param_unrecognized(self, code: 'Enum_Parameter', param: 'Optional[Data_UnrecognizedParameter]' = None, *,
                                 value: 'bytes' = b'',
                                 **kwargs: 'Any') -> 'Schema_UnrecognizedParameter':
        """Make SCTP unrecognized parameter parameter.

        Args:
            code: parameter type
            param: parameter data
            value: the unrecognized parameter, complete with its type and length
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed parameter schema.

        """
        if param is not None:
            value = param.value

        return Schema_UnrecognizedParameter(
            type=code,
            length=len(value) + 4,
            value=value,
        )

    def _make_param_preservative(self, code: 'Enum_Parameter', param: 'Optional[Data_CookiePreservativeParameter]' = None, *,
                                 increment: 'int' = 0,
                                 **kwargs: 'Any') -> 'Schema_CookiePreservativeParameter':
        """Make SCTP cookie preservative parameter.

        Args:
            code: parameter type
            param: parameter data
            increment: suggested cookie life-span increment, in milliseconds
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed parameter schema.

        """
        if param is not None:
            increment = param.increment

        return Schema_CookiePreservativeParameter(
            type=code,
            length=8,
            increment=increment,
        )

    def _make_param_hostname(self, code: 'Enum_Parameter', param: 'Optional[Data_HostNameAddressParameter]' = None, *,
                             name: 'bytes' = b'\x00',
                             **kwargs: 'Any') -> 'Schema_HostNameAddressParameter':
        """Make SCTP host name address parameter.

        Args:
            code: parameter type
            param: parameter data
            name: host name, including at least one null terminator
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed parameter schema.

        Raises:
            ProtocolError: If ``name`` is not null-terminated, as required by
                :rfc:`9260#section-3.3.2.1.4`.

        """
        if param is not None:
            name = param.name

        if not name.endswith(b'\x00'):
            raise ProtocolError(f'{self.alias}: [Param {code}] invalid format')

        return Schema_HostNameAddressParameter(
            type=code,
            length=len(name) + 4,
            name=name,
        )

    def _make_param_addrtypes(self, code: 'Enum_Parameter', param: 'Optional[Data_SupportedAddressTypesParameter]' = None, *,
                              types: 'Optional[list[Enum_Parameter | int]]' = None,
                              **kwargs: 'Any') -> 'Schema_SupportedAddressTypesParameter':
        """Make SCTP supported address types parameter.

        Args:
            code: parameter type
            param: parameter data
            types: supported address types, given as address parameter types
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed parameter schema.

        """
        if param is not None:
            types = list(param.types)

        types_value = [Enum_Parameter.get(item) if isinstance(item, int) else item
                       for item in types or []]

        return Schema_SupportedAddressTypesParameter(
            type=code,
            length=len(types_value) * 2 + 4,
            types=types_value,
        )

    def _read_cause_donone(self, schema: 'Schema_UnknownCause', *, causes: 'Causes') -> 'Data_UnknownCause':  # pylint: disable=unused-argument
        """Read SCTP error cause of an unsupported cause code.

        This is the fall-through for every error cause code :mod:`pcapkit` does
        not implement, e.g. those registered by SCTP extensions. The
        cause-specific information is recorded verbatim rather than raising.

        Arguments:
            schema: parsed error cause schema
            causes: extracted SCTP error causes

        Returns:
            Parsed error cause data.

        """
        return Data_UnknownCause(
            code=schema.code,
            length=schema.length,
            value=schema.value,
        )

    def _read_cause_invalid_stream(self, schema: 'Schema_InvalidStreamIdentifierCause', *, causes: 'Causes') -> 'Data_InvalidStreamIdentifierCause':  # pylint: disable=unused-argument
        """Read SCTP invalid stream identifier error cause.

        Structure of the cause [:rfc:`9260#section-3.3.10.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |        Cause Code = 1         |       Cause Length = 8        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |       Stream Identifier       |          (Reserved)           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed error cause schema
            causes: extracted SCTP error causes

        Returns:
            Parsed error cause data.

        Raises:
            ProtocolError: If ``length`` is **NOT** ``8``.

        """
        if schema.length != 8:
            raise ProtocolError(f'{self.alias}: [Cause {schema.code}] invalid format')

        return Data_InvalidStreamIdentifierCause(
            code=schema.code,
            length=schema.length,
            stream_id=schema.stream_id,
        )

    def _read_cause_missing_param(self, schema: 'Schema_MissingMandatoryParameterCause', *, causes: 'Causes') -> 'Data_MissingMandatoryParameterCause':  # pylint: disable=unused-argument
        """Read SCTP missing mandatory parameter error cause.

        Structure of the cause [:rfc:`9260#section-3.3.10.2`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |        Cause Code = 2         |   Cause Length = 8 + N * 2    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                 Number of missing params = N                  |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Missing Param Type #1     |     Missing Param Type #2     |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed error cause schema
            causes: extracted SCTP error causes

        Returns:
            Parsed error cause data.

        Raises:
            ProtocolError: If ``length`` does **NOT** match the declared number
                of missing parameters.

        """
        if schema.length != 8 + schema.num * 2:
            raise ProtocolError(f'{self.alias}: [Cause {schema.code}] invalid format')

        return Data_MissingMandatoryParameterCause(
            code=schema.code,
            length=schema.length,
            num=schema.num,
            types=tuple(schema.types),
        )

    def _read_cause_stale_cookie(self, schema: 'Schema_StaleCookieCause', *, causes: 'Causes') -> 'Data_StaleCookieCause':  # pylint: disable=unused-argument
        """Read SCTP stale cookie error cause.

        Structure of the cause [:rfc:`9260#section-3.3.10.3`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |        Cause Code = 3         |       Cause Length = 8        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                 Measure of Staleness (usec.)                  |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed error cause schema
            causes: extracted SCTP error causes

        Returns:
            Parsed error cause data.

        Raises:
            ProtocolError: If ``length`` is **NOT** ``8``.

        """
        if schema.length != 8:
            raise ProtocolError(f'{self.alias}: [Cause {schema.code}] invalid format')

        return Data_StaleCookieCause(
            code=schema.code,
            length=schema.length,
            staleness=schema.staleness,
        )

    def _read_cause_out_of_resource(self, schema: 'Schema_OutOfResourceCause', *, causes: 'Causes') -> 'Data_OutOfResourceCause':  # pylint: disable=unused-argument
        """Read SCTP out of resource error cause.

        Structure of the cause [:rfc:`9260#section-3.3.10.4`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |        Cause Code = 4         |       Cause Length = 4        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed error cause schema
            causes: extracted SCTP error causes

        Returns:
            Parsed error cause data.

        Raises:
            ProtocolError: If ``length`` is **NOT** ``4``.

        """
        if schema.length != 4:
            raise ProtocolError(f'{self.alias}: [Cause {schema.code}] invalid format')

        return Data_OutOfResourceCause(
            code=schema.code,
            length=schema.length,
        )

    def _read_cause_unresolvable_addr(self, schema: 'Schema_UnresolvableAddressCause', *, causes: 'Causes') -> 'Data_UnresolvableAddressCause':  # pylint: disable=unused-argument
        """Read SCTP unresolvable address error cause.

        Structure of the cause [:rfc:`9260#section-3.3.10.5`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |        Cause Code = 5         |         Cause Length          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           /                     Unresolvable Address                      /
           \\                                                               \\
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed error cause schema
            causes: extracted SCTP error causes

        Returns:
            Parsed error cause data.

        Raises:
            ProtocolError: If ``length`` is **NOT** at least ``4``.

        """
        if schema.length < 4:
            raise ProtocolError(f'{self.alias}: [Cause {schema.code}] invalid format')

        return Data_UnresolvableAddressCause(
            code=schema.code,
            length=schema.length,
            value=schema.value,
        )

    def _read_cause_unrecognized_chunk(self, schema: 'Schema_UnrecognizedChunkTypeCause', *, causes: 'Causes') -> 'Data_UnrecognizedChunkTypeCause':  # pylint: disable=unused-argument
        """Read SCTP unrecognized chunk type error cause.

        Structure of the cause [:rfc:`9260#section-3.3.10.6`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |        Cause Code = 6         |         Cause Length          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           /                      Unrecognized Chunk                       /
           \\                                                               \\
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed error cause schema
            causes: extracted SCTP error causes

        Returns:
            Parsed error cause data.

        Raises:
            ProtocolError: If ``length`` is **NOT** at least ``4``.

        """
        if schema.length < 4:
            raise ProtocolError(f'{self.alias}: [Cause {schema.code}] invalid format')

        return Data_UnrecognizedChunkTypeCause(
            code=schema.code,
            length=schema.length,
            value=schema.value,
        )

    def _read_cause_invalid_param(self, schema: 'Schema_InvalidMandatoryParameterCause', *, causes: 'Causes') -> 'Data_InvalidMandatoryParameterCause':  # pylint: disable=unused-argument
        """Read SCTP invalid mandatory parameter error cause.

        Structure of the cause [:rfc:`9260#section-3.3.10.7`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |        Cause Code = 7         |       Cause Length = 4        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed error cause schema
            causes: extracted SCTP error causes

        Returns:
            Parsed error cause data.

        Raises:
            ProtocolError: If ``length`` is **NOT** ``4``.

        """
        if schema.length != 4:
            raise ProtocolError(f'{self.alias}: [Cause {schema.code}] invalid format')

        return Data_InvalidMandatoryParameterCause(
            code=schema.code,
            length=schema.length,
        )

    def _read_cause_unrecognized_params(self, schema: 'Schema_UnrecognizedParametersCause', *, causes: 'Causes') -> 'Data_UnrecognizedParametersCause':  # pylint: disable=unused-argument
        """Read SCTP unrecognized parameters error cause.

        Structure of the cause [:rfc:`9260#section-3.3.10.8`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |        Cause Code = 8         |         Cause Length          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           /                    Unrecognized Parameters                    /
           \\                                                               \\
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed error cause schema
            causes: extracted SCTP error causes

        Returns:
            Parsed error cause data.

        Raises:
            ProtocolError: If ``length`` is **NOT** at least ``4``.

        """
        if schema.length < 4:
            raise ProtocolError(f'{self.alias}: [Cause {schema.code}] invalid format')

        return Data_UnrecognizedParametersCause(
            code=schema.code,
            length=schema.length,
            value=schema.value,
        )

    def _read_cause_no_user_data(self, schema: 'Schema_NoUserDataCause', *, causes: 'Causes') -> 'Data_NoUserDataCause':  # pylint: disable=unused-argument
        """Read SCTP no user data error cause.

        Structure of the cause [:rfc:`9260#section-3.3.10.9`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |        Cause Code = 9         |       Cause Length = 8        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                              TSN                              |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed error cause schema
            causes: extracted SCTP error causes

        Returns:
            Parsed error cause data.

        Raises:
            ProtocolError: If ``length`` is **NOT** ``8``.

        """
        if schema.length != 8:
            raise ProtocolError(f'{self.alias}: [Cause {schema.code}] invalid format')

        return Data_NoUserDataCause(
            code=schema.code,
            length=schema.length,
            tsn=schema.tsn,
        )

    def _read_cause_cookie_shutdown(self, schema: 'Schema_CookieReceivedWhileShuttingDownCause', *, causes: 'Causes') -> 'Data_CookieReceivedWhileShuttingDownCause':  # pylint: disable=unused-argument
        """Read SCTP cookie received while shutting down error cause.

        Structure of the cause [:rfc:`9260#section-3.3.10.10`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |        Cause Code = 10        |       Cause Length = 4        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed error cause schema
            causes: extracted SCTP error causes

        Returns:
            Parsed error cause data.

        Raises:
            ProtocolError: If ``length`` is **NOT** ``4``.

        """
        if schema.length != 4:
            raise ProtocolError(f'{self.alias}: [Cause {schema.code}] invalid format')

        return Data_CookieReceivedWhileShuttingDownCause(
            code=schema.code,
            length=schema.length,
        )

    def _read_cause_restart_addr(self, schema: 'Schema_RestartOfAnAssociationWithNewAddressesCause', *, causes: 'Causes') -> 'Data_RestartOfAnAssociationWithNewAddressesCause':  # pylint: disable=unused-argument
        """Read SCTP restart of an association with new addresses error cause.

        Structure of the cause [:rfc:`9260#section-3.3.10.11`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |        Cause Code = 11        |         Cause Length          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           /                       New Address TLVs                        /
           \\                                                               \\
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed error cause schema
            causes: extracted SCTP error causes

        Returns:
            Parsed error cause data.

        Raises:
            ProtocolError: If ``length`` is **NOT** at least ``4``.

        """
        if schema.length < 4:
            raise ProtocolError(f'{self.alias}: [Cause {schema.code}] invalid format')

        return Data_RestartOfAnAssociationWithNewAddressesCause(
            code=schema.code,
            length=schema.length,
            value=schema.value,
        )

    def _read_cause_user_abort(self, schema: 'Schema_UserInitiatedAbortCause', *, causes: 'Causes') -> 'Data_UserInitiatedAbortCause':  # pylint: disable=unused-argument
        """Read SCTP user-initiated abort error cause.

        Structure of the cause [:rfc:`9260#section-3.3.10.12`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |        Cause Code = 12        |         Cause Length          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           /                   Upper Layer Abort Reason                    /
           \\                                                               \\
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed error cause schema
            causes: extracted SCTP error causes

        Returns:
            Parsed error cause data.

        Raises:
            ProtocolError: If ``length`` is **NOT** at least ``4``.

        """
        if schema.length < 4:
            raise ProtocolError(f'{self.alias}: [Cause {schema.code}] invalid format')

        return Data_UserInitiatedAbortCause(
            code=schema.code,
            length=schema.length,
            info=schema.info,
        )

    def _read_cause_protocol_violation(self, schema: 'Schema_ProtocolViolationCause', *, causes: 'Causes') -> 'Data_ProtocolViolationCause':  # pylint: disable=unused-argument
        """Read SCTP protocol violation error cause.

        Structure of the cause [:rfc:`9260#section-3.3.10.13`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |        Cause Code = 13        |         Cause Length          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           /                    Additional Information                     /
           \\                                                               \\
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            schema: parsed error cause schema
            causes: extracted SCTP error causes

        Returns:
            Parsed error cause data.

        Raises:
            ProtocolError: If ``length`` is **NOT** at least ``4``.

        """
        if schema.length < 4:
            raise ProtocolError(f'{self.alias}: [Cause {schema.code}] invalid format')

        return Data_ProtocolViolationCause(
            code=schema.code,
            length=schema.length,
            info=schema.info,
        )

    def _make_cause_donone(self, code: 'Enum_CauseCode', cause: 'Optional[Data_UnknownCause]' = None, *,
                           value: 'bytes' = b'',
                           **kwargs: 'Any') -> 'Schema_UnknownCause':
        """Make SCTP error cause of an unsupported cause code.

        Args:
            code: error cause code
            cause: error cause data
            value: cause-specific information in :obj:`bytes`
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed error cause schema.

        """
        if cause is not None:
            value = cause.value

        return Schema_UnknownCause(
            code=code,
            length=len(value) + 4,
            value=value,
        )

    def _make_cause_invalid_stream(self, code: 'Enum_CauseCode', cause: 'Optional[Data_InvalidStreamIdentifierCause]' = None, *,
                                   stream_id: 'int' = 0,
                                   **kwargs: 'Any') -> 'Schema_InvalidStreamIdentifierCause':
        """Make SCTP invalid stream identifier error cause.

        Args:
            code: error cause code
            cause: error cause data
            stream_id: stream identifier of the offending DATA chunk
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed error cause schema.

        """
        if cause is not None:
            stream_id = cause.stream_id

        return Schema_InvalidStreamIdentifierCause(
            code=code,
            length=8,
            stream_id=stream_id,
        )

    def _make_cause_missing_param(self, code: 'Enum_CauseCode', cause: 'Optional[Data_MissingMandatoryParameterCause]' = None, *,
                                  types: 'Optional[list[Enum_Parameter | int]]' = None,
                                  **kwargs: 'Any') -> 'Schema_MissingMandatoryParameterCause':
        """Make SCTP missing mandatory parameter error cause.

        Args:
            code: error cause code
            cause: error cause data
            types: missing parameter types
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed error cause schema.

        Note:
            The count of missing parameters is derived from ``types`` rather
            than taken as an argument, so that it cannot disagree with the list
            it counts.

        """
        if cause is not None:
            types = list(cause.types)

        types_value = [Enum_Parameter.get(item) if isinstance(item, int) else item
                       for item in types or []]

        return Schema_MissingMandatoryParameterCause(
            code=code,
            length=8 + len(types_value) * 2,
            num=len(types_value),
            types=types_value,
        )

    def _make_cause_stale_cookie(self, code: 'Enum_CauseCode', cause: 'Optional[Data_StaleCookieCause]' = None, *,
                                 staleness: 'int' = 0,
                                 **kwargs: 'Any') -> 'Schema_StaleCookieCause':
        """Make SCTP stale cookie error cause.

        Args:
            code: error cause code
            cause: error cause data
            staleness: measure of staleness, in microseconds
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed error cause schema.

        """
        if cause is not None:
            staleness = cause.staleness

        return Schema_StaleCookieCause(
            code=code,
            length=8,
            staleness=staleness,
        )

    def _make_cause_out_of_resource(self, code: 'Enum_CauseCode', cause: 'Optional[Data_OutOfResourceCause]' = None,
                                    **kwargs: 'Any') -> 'Schema_OutOfResourceCause':
        """Make SCTP out of resource error cause.

        Args:
            code: error cause code
            cause: error cause data
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed error cause schema.

        """
        return Schema_OutOfResourceCause(
            code=code,
            length=4,
        )

    def _make_cause_unresolvable_addr(self, code: 'Enum_CauseCode', cause: 'Optional[Data_UnresolvableAddressCause]' = None, *,
                                      value: 'bytes' = b'',
                                      **kwargs: 'Any') -> 'Schema_UnresolvableAddressCause':
        """Make SCTP unresolvable address error cause.

        Args:
            code: error cause code
            cause: error cause data
            value: the offending address parameter, complete with its type and
                length
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed error cause schema.

        """
        if cause is not None:
            value = cause.value

        return Schema_UnresolvableAddressCause(
            code=code,
            length=len(value) + 4,
            value=value,
        )

    def _make_cause_unrecognized_chunk(self, code: 'Enum_CauseCode', cause: 'Optional[Data_UnrecognizedChunkTypeCause]' = None, *,
                                       value: 'bytes' = b'',
                                       **kwargs: 'Any') -> 'Schema_UnrecognizedChunkTypeCause':
        """Make SCTP unrecognized chunk type error cause.

        Args:
            code: error cause code
            cause: error cause data
            value: the unrecognized chunk, complete with its type, flags and
                length
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed error cause schema.

        """
        if cause is not None:
            value = cause.value

        return Schema_UnrecognizedChunkTypeCause(
            code=code,
            length=len(value) + 4,
            value=value,
        )

    def _make_cause_invalid_param(self, code: 'Enum_CauseCode', cause: 'Optional[Data_InvalidMandatoryParameterCause]' = None,
                                  **kwargs: 'Any') -> 'Schema_InvalidMandatoryParameterCause':
        """Make SCTP invalid mandatory parameter error cause.

        Args:
            code: error cause code
            cause: error cause data
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed error cause schema.

        """
        return Schema_InvalidMandatoryParameterCause(
            code=code,
            length=4,
        )

    def _make_cause_unrecognized_params(self, code: 'Enum_CauseCode', cause: 'Optional[Data_UnrecognizedParametersCause]' = None, *,
                                        value: 'bytes' = b'',
                                        **kwargs: 'Any') -> 'Schema_UnrecognizedParametersCause':
        """Make SCTP unrecognized parameters error cause.

        Args:
            code: error cause code
            cause: error cause data
            value: the unrecognized parameters, complete with their types and
                lengths
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed error cause schema.

        """
        if cause is not None:
            value = cause.value

        return Schema_UnrecognizedParametersCause(
            code=code,
            length=len(value) + 4,
            value=value,
        )

    def _make_cause_no_user_data(self, code: 'Enum_CauseCode', cause: 'Optional[Data_NoUserDataCause]' = None, *,
                                 tsn: 'int' = 0,
                                 **kwargs: 'Any') -> 'Schema_NoUserDataCause':
        """Make SCTP no user data error cause.

        Args:
            code: error cause code
            cause: error cause data
            tsn: TSN of the offending DATA chunk
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed error cause schema.

        """
        if cause is not None:
            tsn = cause.tsn

        return Schema_NoUserDataCause(
            code=code,
            length=8,
            tsn=tsn,
        )

    def _make_cause_cookie_shutdown(self, code: 'Enum_CauseCode', cause: 'Optional[Data_CookieReceivedWhileShuttingDownCause]' = None,
                                    **kwargs: 'Any') -> 'Schema_CookieReceivedWhileShuttingDownCause':
        """Make SCTP cookie received while shutting down error cause.

        Args:
            code: error cause code
            cause: error cause data
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed error cause schema.

        """
        return Schema_CookieReceivedWhileShuttingDownCause(
            code=code,
            length=4,
        )

    def _make_cause_restart_addr(self, code: 'Enum_CauseCode', cause: 'Optional[Data_RestartOfAnAssociationWithNewAddressesCause]' = None, *,
                                 value: 'bytes' = b'',
                                 **kwargs: 'Any') -> 'Schema_RestartOfAnAssociationWithNewAddressesCause':
        """Make SCTP restart of an association with new addresses error cause.

        Args:
            code: error cause code
            cause: error cause data
            value: the new address parameters, complete with their types and
                lengths
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed error cause schema.

        """
        if cause is not None:
            value = cause.value

        return Schema_RestartOfAnAssociationWithNewAddressesCause(
            code=code,
            length=len(value) + 4,
            value=value,
        )

    def _make_cause_user_abort(self, code: 'Enum_CauseCode', cause: 'Optional[Data_UserInitiatedAbortCause]' = None, *,
                               info: 'bytes' = b'',
                               **kwargs: 'Any') -> 'Schema_UserInitiatedAbortCause':
        """Make SCTP user-initiated abort error cause.

        Args:
            code: error cause code
            cause: error cause data
            info: upper layer abort reason
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed error cause schema.

        """
        if cause is not None:
            info = cause.info

        return Schema_UserInitiatedAbortCause(
            code=code,
            length=len(info) + 4,
            info=info,
        )

    def _make_cause_protocol_violation(self, code: 'Enum_CauseCode', cause: 'Optional[Data_ProtocolViolationCause]' = None, *,
                                       info: 'bytes' = b'',
                                       **kwargs: 'Any') -> 'Schema_ProtocolViolationCause':
        """Make SCTP protocol violation error cause.

        Args:
            code: error cause code
            cause: error cause data
            info: additional information
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed error cause schema.

        """
        if cause is not None:
            info = cause.info

        return Schema_ProtocolViolationCause(
            code=code,
            length=len(info) + 4,
            info=info,
        )
