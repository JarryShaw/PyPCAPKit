# -*- coding: utf-8 -*-
"""data model for SCTP protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Union

    from pcapkit.const.reg.apptype import AppType
    from pcapkit.const.sctp.cause_code import CauseCode
    from pcapkit.const.sctp.chunk import Chunk as ChunkType
    from pcapkit.const.sctp.parameter import Parameter as ParameterType
    from pcapkit.const.sctp.payload_protocol_identifier import PayloadProtocolIdentifier
    from pcapkit.corekit.multidict import OrderedMultiDict

    IPAddress = Union[IPv4Address, IPv6Address]

__all__ = [
    'SCTP',

    'DATAChunkFlags', 'TBitFlags', 'GapAckBlock',

    'Chunk',
    'UnknownChunk', 'DATAChunk', 'INITChunk', 'INITACKChunk', 'SACKChunk',
    'HeartbeatChunk', 'HeartbeatACKChunk', 'AbortChunk', 'ShutdownChunk',
    'ShutdownACKChunk', 'ErrorChunk', 'CookieEchoChunk', 'CookieACKChunk',
    'ShutdownCompleteChunk',

    'Parameter',
    'UnknownParameter', 'HeartbeatInfoParameter', 'IPv4AddressParameter',
    'IPv6AddressParameter', 'StateCookieParameter', 'UnrecognizedParameter',
    'CookiePreservativeParameter', 'HostNameAddressParameter',
    'SupportedAddressTypesParameter',

    'ErrorCause',
    'UnknownCause', 'InvalidStreamIdentifierCause', 'MissingMandatoryParameterCause',
    'StaleCookieCause', 'OutOfResourceCause', 'UnresolvableAddressCause',
    'UnrecognizedChunkTypeCause', 'InvalidMandatoryParameterCause',
    'UnrecognizedParametersCause', 'NoUserDataCause',
    'CookieReceivedWhileShuttingDownCause',
    'RestartOfAnAssociationWithNewAddressesCause', 'UserInitiatedAbortCause',
    'ProtocolViolationCause',
]


@info_final
class DATAChunkFlags(Data):
    """Data model for SCTP DATA chunk flags."""

    #: (I)mmediate bit, i.e., request a SACK chunk without delay.
    I: 'bool'
    #: (U)nordered bit, i.e., no stream sequence number is assigned.
    U: 'bool'
    #: (B)eginning fragment bit.
    B: 'bool'
    #: (E)nding fragment bit.
    E: 'bool'

    if TYPE_CHECKING:
        def __init__(self, I: 'bool', U: 'bool', B: 'bool', E: 'bool') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class TBitFlags(Data):
    """Data model for SCTP chunk flags carrying only the T bit, i.e., ABORT and
    SHUTDOWN COMPLETE chunks."""

    #: T bit, i.e., the verification tag has been reflected.
    T: 'bool'

    if TYPE_CHECKING:
        def __init__(self, T: 'bool') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class GapAckBlock(Data):
    """Data model for SCTP SACK chunk gap ack blocks."""

    #: Start offset TSN of the gap ack block.
    start: 'int'
    #: End offset TSN of the gap ack block.
    end: 'int'

    if TYPE_CHECKING:
        def __init__(self, start: 'int', end: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class ErrorCause(Data):
    """Data model for SCTP error causes."""

    #: Cause code.
    code: 'CauseCode'
    #: Cause length.
    length: 'int'


@info_final
class UnknownCause(ErrorCause):
    """Data model for SCTP error causes with unknown cause codes."""

    #: Cause-specific information.
    value: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, code: 'CauseCode', length: 'int', value: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class InvalidStreamIdentifierCause(ErrorCause):
    """Data model for SCTP invalid stream identifier error cause."""

    #: Stream identifier of the offending DATA chunk.
    stream_id: 'int'

    if TYPE_CHECKING:
        def __init__(self, code: 'CauseCode', length: 'int', stream_id: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class MissingMandatoryParameterCause(ErrorCause):
    """Data model for SCTP missing mandatory parameter error cause."""

    #: Number of missing parameters.
    num: 'int'
    #: Missing parameter types.
    types: 'tuple[ParameterType, ...]'

    if TYPE_CHECKING:
        def __init__(self, code: 'CauseCode', length: 'int', num: 'int', types: 'tuple[ParameterType, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class StaleCookieCause(ErrorCause):
    """Data model for SCTP stale cookie error cause."""

    #: Measure of staleness, in microseconds.
    staleness: 'int'

    if TYPE_CHECKING:
        def __init__(self, code: 'CauseCode', length: 'int', staleness: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class OutOfResourceCause(ErrorCause):
    """Data model for SCTP out of resource error cause."""

    if TYPE_CHECKING:
        def __init__(self, code: 'CauseCode', length: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class UnresolvableAddressCause(ErrorCause):
    """Data model for SCTP unresolvable address error cause."""

    #: The offending address parameter, complete with its type and length.
    value: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, code: 'CauseCode', length: 'int', value: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class UnrecognizedChunkTypeCause(ErrorCause):
    """Data model for SCTP unrecognized chunk type error cause."""

    #: The unrecognized chunk, complete with its type, flags and length.
    value: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, code: 'CauseCode', length: 'int', value: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class InvalidMandatoryParameterCause(ErrorCause):
    """Data model for SCTP invalid mandatory parameter error cause."""

    if TYPE_CHECKING:
        def __init__(self, code: 'CauseCode', length: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class UnrecognizedParametersCause(ErrorCause):
    """Data model for SCTP unrecognized parameters error cause."""

    #: The unrecognized parameters, complete with their types and lengths.
    value: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, code: 'CauseCode', length: 'int', value: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class NoUserDataCause(ErrorCause):
    """Data model for SCTP no user data error cause."""

    #: TSN of the offending DATA chunk.
    tsn: 'int'

    if TYPE_CHECKING:
        def __init__(self, code: 'CauseCode', length: 'int', tsn: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class CookieReceivedWhileShuttingDownCause(ErrorCause):
    """Data model for SCTP cookie received while shutting down error cause."""

    if TYPE_CHECKING:
        def __init__(self, code: 'CauseCode', length: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class RestartOfAnAssociationWithNewAddressesCause(ErrorCause):
    """Data model for SCTP restart of an association with new addresses error cause."""

    #: The new address parameters, complete with their types and lengths.
    value: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, code: 'CauseCode', length: 'int', value: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class UserInitiatedAbortCause(ErrorCause):
    """Data model for SCTP user-initiated abort error cause."""

    #: Upper layer abort reason.
    info: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, code: 'CauseCode', length: 'int', info: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class ProtocolViolationCause(ErrorCause):
    """Data model for SCTP protocol violation error cause."""

    #: Additional information.
    info: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, code: 'CauseCode', length: 'int', info: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class Parameter(Data):
    """Data model for SCTP chunk parameters."""

    #: Parameter type.
    type: 'ParameterType'
    #: Parameter length.
    length: 'int'


@info_final
class UnknownParameter(Parameter):
    """Data model for SCTP chunk parameters with unknown types."""

    #: Parameter value.
    value: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'ParameterType', length: 'int', value: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class HeartbeatInfoParameter(Parameter):
    """Data model for SCTP heartbeat info parameter."""

    #: Sender-specific heartbeat info.
    info: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'ParameterType', length: 'int', info: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class IPv4AddressParameter(Parameter):
    """Data model for SCTP IPv4 address parameter."""

    #: IPv4 address of the sending endpoint.
    address: 'IPv4Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'ParameterType', length: 'int', address: 'IPv4Address') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class IPv6AddressParameter(Parameter):
    """Data model for SCTP IPv6 address parameter."""

    #: IPv6 address of the sending endpoint.
    address: 'IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, type: 'ParameterType', length: 'int', address: 'IPv6Address') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class StateCookieParameter(Parameter):
    """Data model for SCTP state cookie parameter."""

    #: State cookie.
    cookie: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'ParameterType', length: 'int', cookie: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class UnrecognizedParameter(Parameter):
    """Data model for SCTP unrecognized parameter parameter."""

    #: The unrecognized parameter, complete with its type and length.
    value: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'ParameterType', length: 'int', value: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class CookiePreservativeParameter(Parameter):
    """Data model for SCTP cookie preservative parameter."""

    #: Suggested cookie life-span increment, in milliseconds.
    increment: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'ParameterType', length: 'int', increment: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class HostNameAddressParameter(Parameter):
    """Data model for SCTP host name address parameter."""

    #: Host name, including at least one null terminator.
    name: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'ParameterType', length: 'int', name: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class SupportedAddressTypesParameter(Parameter):
    """Data model for SCTP supported address types parameter."""

    #: Supported address types, given as address parameter types.
    types: 'tuple[ParameterType, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'ParameterType', length: 'int', types: 'tuple[ParameterType, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class Chunk(Data):
    """Data model for SCTP chunks."""

    #: Chunk type.
    type: 'ChunkType'
    #: Chunk length, excluding any trailing padding.
    length: 'int'


@info_final
class UnknownChunk(Chunk):
    """Data model for SCTP chunks with unknown types."""

    #: Raw chunk flags.
    flags: 'bytes'
    #: Chunk value.
    value: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'ChunkType', length: 'int', flags: 'bytes', value: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class DATAChunk(Chunk):
    """Data model for SCTP DATA chunks."""

    #: Chunk flags.
    flags: 'DATAChunkFlags'
    #: Transmission sequence number.
    tsn: 'int'
    #: Stream identifier.
    stream_id: 'int'
    #: Stream sequence number.
    stream_seq: 'int'
    #: Payload protocol identifier.
    ppid: 'PayloadProtocolIdentifier'
    #: User data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'ChunkType', length: 'int', flags: 'DATAChunkFlags', tsn: 'int', stream_id: 'int', stream_seq: 'int', ppid: 'PayloadProtocolIdentifier', data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class INITChunk(Chunk):
    """Data model for SCTP INIT chunks."""

    #: Initiate tag.
    init_tag: 'int'
    #: Advertised receiver window credit.
    a_rwnd: 'int'
    #: Number of outbound streams.
    outbound_streams: 'int'
    #: Number of inbound streams.
    inbound_streams: 'int'
    #: Initial transmission sequence number.
    init_tsn: 'int'
    #: Optional and variable-length parameters.
    parameters: 'OrderedMultiDict[ParameterType, Parameter]'

    if TYPE_CHECKING:
        def __init__(self, type: 'ChunkType', length: 'int', init_tag: 'int', a_rwnd: 'int', outbound_streams: 'int', inbound_streams: 'int', init_tsn: 'int', parameters: 'OrderedMultiDict[ParameterType, Parameter]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class INITACKChunk(Chunk):
    """Data model for SCTP INIT ACK chunks."""

    #: Initiate tag.
    init_tag: 'int'
    #: Advertised receiver window credit.
    a_rwnd: 'int'
    #: Number of outbound streams.
    outbound_streams: 'int'
    #: Number of inbound streams.
    inbound_streams: 'int'
    #: Initial transmission sequence number.
    init_tsn: 'int'
    #: Optional and variable-length parameters.
    parameters: 'OrderedMultiDict[ParameterType, Parameter]'

    if TYPE_CHECKING:
        def __init__(self, type: 'ChunkType', length: 'int', init_tag: 'int', a_rwnd: 'int', outbound_streams: 'int', inbound_streams: 'int', init_tsn: 'int', parameters: 'OrderedMultiDict[ParameterType, Parameter]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class SACKChunk(Chunk):
    """Data model for SCTP SACK chunks."""

    #: Cumulative TSN ack.
    cum_tsn_ack: 'int'
    #: Advertised receiver window credit.
    a_rwnd: 'int'
    #: Number of gap ack blocks.
    num_gap_blocks: 'int'
    #: Number of duplicate TSNs.
    num_dup_tsn: 'int'
    #: Gap ack blocks.
    gap_blocks: 'tuple[GapAckBlock, ...]'
    #: Duplicate TSNs.
    dup_tsn: 'tuple[int, ...]'

    if TYPE_CHECKING:
        def __init__(self, type: 'ChunkType', length: 'int', cum_tsn_ack: 'int', a_rwnd: 'int', num_gap_blocks: 'int', num_dup_tsn: 'int', gap_blocks: 'tuple[GapAckBlock, ...]', dup_tsn: 'tuple[int, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class HeartbeatChunk(Chunk):
    """Data model for SCTP HEARTBEAT chunks."""

    #: Heartbeat information parameters.
    parameters: 'OrderedMultiDict[ParameterType, Parameter]'

    if TYPE_CHECKING:
        def __init__(self, type: 'ChunkType', length: 'int', parameters: 'OrderedMultiDict[ParameterType, Parameter]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class HeartbeatACKChunk(Chunk):
    """Data model for SCTP HEARTBEAT ACK chunks."""

    #: Heartbeat information parameters.
    parameters: 'OrderedMultiDict[ParameterType, Parameter]'

    if TYPE_CHECKING:
        def __init__(self, type: 'ChunkType', length: 'int', parameters: 'OrderedMultiDict[ParameterType, Parameter]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class AbortChunk(Chunk):
    """Data model for SCTP ABORT chunks."""

    #: Chunk flags.
    flags: 'TBitFlags'
    #: Zero or more error causes.
    error: 'OrderedMultiDict[CauseCode, ErrorCause]'

    if TYPE_CHECKING:
        def __init__(self, type: 'ChunkType', length: 'int', flags: 'TBitFlags', error: 'OrderedMultiDict[CauseCode, ErrorCause]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class ShutdownChunk(Chunk):
    """Data model for SCTP SHUTDOWN chunks."""

    #: Cumulative TSN ack.
    cum_tsn_ack: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'ChunkType', length: 'int', cum_tsn_ack: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class ShutdownACKChunk(Chunk):
    """Data model for SCTP SHUTDOWN ACK chunks."""

    if TYPE_CHECKING:
        def __init__(self, type: 'ChunkType', length: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class ErrorChunk(Chunk):
    """Data model for SCTP ERROR chunks."""

    #: One or more error causes.
    error: 'OrderedMultiDict[CauseCode, ErrorCause]'

    if TYPE_CHECKING:
        def __init__(self, type: 'ChunkType', length: 'int', error: 'OrderedMultiDict[CauseCode, ErrorCause]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class CookieEchoChunk(Chunk):
    """Data model for SCTP COOKIE ECHO chunks."""

    #: State cookie, as received in the INIT ACK chunk's state cookie parameter.
    cookie: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'ChunkType', length: 'int', cookie: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class CookieACKChunk(Chunk):
    """Data model for SCTP COOKIE ACK chunks."""

    if TYPE_CHECKING:
        def __init__(self, type: 'ChunkType', length: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class ShutdownCompleteChunk(Chunk):
    """Data model for SCTP SHUTDOWN COMPLETE chunks."""

    #: Chunk flags.
    flags: 'TBitFlags'

    if TYPE_CHECKING:
        def __init__(self, type: 'ChunkType', length: 'int', flags: 'TBitFlags') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class SCTP(Protocol):
    """Data model for SCTP packet."""

    #: Source port.
    srcport: 'AppType'
    #: Destination port.
    dstport: 'AppType'
    #: Verification tag.
    vtag: 'int'
    #: Checksum, as a CRC32c over the whole packet with this field zeroed.
    chksum: 'bytes'
    #: Chunks.
    chunks: 'OrderedMultiDict[ChunkType, Chunk]'

    if TYPE_CHECKING:
        def __init__(self, srcport: 'AppType', dstport: 'AppType', vtag: 'int', chksum: 'bytes', chunks: 'OrderedMultiDict[ChunkType, Chunk]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin
