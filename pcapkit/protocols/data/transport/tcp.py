# -*- coding: utf-8 -*-
"""data model for TCP protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from datetime import timedelta
    from ipaddress import IPv4Address, IPv6Address
    from typing import Optional, Union

    from pcapkit.const.reg.apptype import AppType
    from pcapkit.const.tcp.checksum import Checksum
    from pcapkit.const.tcp.flags import Flags as TCP_Flags
    from pcapkit.const.tcp.mp_tcp_option import MPTCPOption
    from pcapkit.const.tcp.option import Option as OptionNumber
    from pcapkit.corekit.multidict import OrderedMultiDict

    IPAddress = Union[IPv4Address, IPv6Address]

__all__ = [
    'TCP',

    'Flags', 'SACKBlock',

    'Option',
    'UnassignedOption', 'EndOfOptionList', 'NoOperation', 'MaximumSegmentSize', 'WindowScale',
    'SACKPermitted', 'SACK', 'Echo', 'EchoReply', 'Timestamps', 'PartialOrderConnectionPermitted',
    'PartialOrderServiceProfile', 'CC', 'CCNew', 'CCEcho', 'AlternateChecksumRequest',
    'AlternateChecksumData', 'MD5Signature', 'QuickStartResponse', 'UserTimeout',
    'Authentication', 'FastOpenCookie',

    'MPTCPCapableFlag',

    'MPTCP',
    'MPTCPUnknown', 'MPTCPCapable', 'MPTCPDSS', 'MPTCPAddAddress', 'MPTCPRemoveAddress',
    'MPTCPPriority', 'MPTCPFallback', 'MPTCPFastclose',

    'MPTCPJoin',
    'MPTCPJoinSYN', 'MPTCPJoinSYNACK', 'MPTCPJoinACK',
]


@info_final
class Flags(Data):
    """Data model for TCP flags."""

    #: ECN-nonce concealment protection.
    #ns: 'bool'
    #: Congestion window reduced.
    cwr: 'bool'
    #: ECN-Echo.
    ece: 'bool'
    #: Urgent.
    urg: 'bool'
    #: Acknowledgment.
    ack: 'bool'
    #: Push function.
    psh: 'bool'
    #: Reset connection.
    rst: 'bool'
    #: Synchronize sequence numbers.
    syn: 'bool'
    #: Last packet from sender.
    fin: 'bool'

    if TYPE_CHECKING:
        def __init__(self, cwr: 'bool', ece: 'bool', urg: 'bool', ack: 'bool',
                     psh: 'bool', rst: 'bool', syn: 'bool', fin: 'bool') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class TCP(Protocol):
    """Data model for TCP packet."""

    #: Source port.
    srcport: 'AppType'
    #: Destination port.
    dstport: 'AppType'
    #: Sequence number.
    seq: 'int'
    #: Acknowledgment number.
    ack: 'int'
    #: Data offset.
    hdr_len: 'int'
    #: Flags.
    flags: 'Flags'
    #: Window size.
    window_size: 'int'
    #: Checksum.
    checksum: 'bytes'
    #: Urgent pointer.
    urgent_pointer: 'int'

    if TYPE_CHECKING:
        #: TCP options.
        options: 'OrderedMultiDict[OptionNumber, Option]'
        #: Connection control flags.
        connection: 'TCP_Flags'

        def __init__(self, srcport: 'AppType', dstport: 'AppType', seq: 'int', ack: 'int', hdr_len: 'int',
                     flags: 'Flags', window_size: 'int', checksum: 'bytes', urgent_pointer: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class Option(Data):
    """Data model for TCP options."""

    #: Option kind.
    kind: 'OptionNumber'
    #: Option length.
    length: 'int'


@info_final
class UnassignedOption(Option):
    """Data model for unassigned TCP option."""

    #: Option data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class EndOfOptionList(Option):
    """Data model for TCP end of option list option."""

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class NoOperation(Option):
    """Data model for TCP no operation option."""

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class MaximumSegmentSize(Option):
    """Data model for TCP maximum segment size option."""

    #: Maximum segment size.
    mss: 'int'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', mss: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class WindowScale(Option):
    """Data model for TCP window scale option."""

    #: Window scale.
    shift: 'int'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', shift: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class SACKPermitted(Option):
    """Data model for TCP SACK permitted option."""

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class SACKBlock(Data):
    """Data model for TCP SACK block."""

    #: Left edge.
    left: 'int'
    #: Right edge.
    right: 'int'

    if TYPE_CHECKING:
        def __init__(self, left: 'int', right: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class SACK(Option):
    """Data model for TCP SACK option."""

    #: SACK blocks.
    sack: 'tuple[SACKBlock, ...]'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', sack: 'tuple[SACKBlock, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class Echo(Option):
    """Data model for TCP echo option."""

    #: Echo data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class EchoReply(Option):
    """Data model for TCP echo reply option."""

    #: Echo data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class Timestamps(Option):
    """Data model for TCP timestamp option."""

    #: Timestamp .
    timestamp: 'int'
    #: Echo data.
    echo: 'int'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', timestamp: 'int', echo: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class PartialOrderConnectionPermitted(Option):
    """Data model for TCP partial order connection permitted option."""

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class PartialOrderServiceProfile(Option):
    """Data model for TCP partial order connection profile option."""

    #: Start flag.
    start: 'bool'
    #: End flag.
    end: 'bool'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', start: 'bool', end: 'bool') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class CC(Option):
    """Data model for TCP CC option."""

    #: Connection count.
    cc: 'int'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', cc: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class CCNew(Option):
    """Data model for TCP CC.NEW option."""

    #: Connection count.
    cc: 'int'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', cc: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class CCEcho(Option):
    """Data model for TCP CC.ECHO option."""

    #: Connection count.
    cc: 'int'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', cc: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class AlternateChecksumRequest(Option):
    """Data model for TCP alternate checksum request option."""

    #: Checksum algorithm.
    chksum: 'Checksum'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', chksum: 'Checksum') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class AlternateChecksumData(Option):
    """Data model for TCP alternate checksum data option."""

    #: Checksum data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class MD5Signature(Option):
    """Data model for TCP MD5 signature option."""

    #: MD5 signature.
    digest: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', digest: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class QuickStartResponse(Option):
    """Data model for TCP quick start response option."""

    #: Rate request.
    req_rate: 'int'
    #: TTL difference.
    ttl_diff: 'int'
    #: QS nonce.
    nonce: 'int'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', req_rate: 'int', ttl_diff: 'int', nonce: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class UserTimeout(Option):
    """Data model for TCP user timeout option."""

    #: User timeout.
    timeout: 'timedelta'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', timeout: 'timedelta') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class Authentication(Option):
    """Data model for TCP authentication option."""

    #: Key ID.
    key_id: 'int'
    #: Receive next key ID.
    next_key_id: 'int'
    #: MAC.
    mac: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', key_id: 'int', next_key_id: 'int', mac: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class FastOpenCookie(Option):
    """Data model for TCP fast open cookie option."""

    #: Cookie.
    cookie: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', cookie: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class MPTCP(Option):
    """Data model for TCP MPTCP option."""

    #: Subtype.
    subtype: 'MPTCPOption'


@info_final
class MPTCPUnknown(MPTCP):
    """Data model for TCP unknown MPTCP option."""

    #: Data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', subtype: 'MPTCPOption', data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class MPTCPCapableFlag(Data):
    """Data model for TCP MPTCP capable option flags."""

    #: Checksum require flag.
    req: 'bool'
    #: Extensibility flag.
    ext: 'bool'
    #: HMAC-SHA1 flag.
    hsa: 'bool'

    if TYPE_CHECKING:
        def __init__(self, req: 'bool', ext: 'bool', hsa: 'bool') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class MPTCPCapable(MPTCP):
    """Data model for TCP ``MP_CAPABLE`` option."""

    #: Version.
    version: 'int'
    #: Flags.
    flags: 'MPTCPCapableFlag'
    #: Option sender's key.
    skey: 'int'
    #: Option receiver's key.
    rkey: 'Optional[int]'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', subtype: 'MPTCPOption', version: 'int', flags: 'MPTCPCapableFlag', skey: 'int', rkey: 'Optional[int]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class MPTCPJoin(MPTCP):
    """Data model for TCP ``MP_JOIN`` option."""

    #: Connection type.
    connection: 'TCP_Flags'


@info_final
class MPTCPJoinSYN(MPTCPJoin):
    """Data model for TCP ``MP_JOIN-SYN`` option."""

    #: Backup path flag.
    backup: 'bool'
    #: Address ID.
    addr_id: 'int'
    #: Receiver's token.
    token: 'int'
    #: Sendder's random number.
    nonce: 'int'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', subtype: 'MPTCPOption', connection: 'TCP_Flags', backup: 'bool', addr_id: 'int', token: 'int', nonce: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class MPTCPJoinSYNACK(MPTCPJoin):
    """Data model for TCP ``MP_JOIN-SYNACK`` option."""

    #: Backup path flag.
    backup: 'bool'
    #: Address ID.
    addr_id: 'int'
    #: Sender's truncated HMAC.
    hmac: 'bytes'
    #: Sendder's random number.
    nonce: 'int'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', subtype: 'MPTCPOption', connection: 'TCP_Flags', backup: 'bool', addr_id: 'int', hmac: 'bytes', nonce: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class MPTCPJoinACK(MPTCPJoin):
    """Data model for TCP ``MP_JOIN-ACK`` option."""

    #: HMAC value.
    hmac: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', subtype: 'MPTCPOption', connection: 'TCP_Flags', hmac: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class MPTCPDSS(MPTCP):
    """Data model for TCP ``DSS`` option."""

    #: ``DATA_FIN`` flag.
    data_fin: 'bool'
    #: Data ACK.
    ack: 'Optional[int]'
    #: Data sequence number.
    dsn: 'Optional[int]'
    #: Subflow sequence number.
    ssn: 'Optional[int]'
    #: Data-level length.
    dl_len: 'Optional[int]'
    #: Checksum.
    checksum: 'Optional[bytes]'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', subtype: 'MPTCPOption', data_fin: 'bool', ack: 'Optional[int]', dsn: 'Optional[int]', ssn: 'Optional[int]', dl_len: 'Optional[int]', checksum: 'Optional[bytes]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class MPTCPAddAddress(MPTCP):
    """Data model for TCP ``ADD_ADDR`` option."""

    #: IP version.
    version: 'int'
    #: Address ID.
    addr_id: 'int'
    #: Address.
    addr: 'IPAddress'
    #: Port number.
    port: 'Optional[int]'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', subtype: 'MPTCPOption', version: 'int', addr_id: 'int', addr: 'IPAddress', port: 'Optional[int]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class MPTCPRemoveAddress(MPTCP):
    """Data model for TCP ``REMOVE_ADDR`` option."""

    #: Address ID.
    addr_id: 'tuple[int, ...]'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', subtype: 'MPTCPOption', addr_id: 'tuple[int, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class MPTCPPriority(MPTCP):
    """Data model for TCP ``MP_PRIO`` option."""

    #: Backup path flag.
    backup: 'bool'
    #: Address ID.
    addr_id: 'Optional[int]'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', subtype: 'MPTCPOption', backup: 'bool', addr_id: 'Optional[int]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class MPTCPFallback(MPTCP):
    """Data model for TCP ``MP_FAIL`` option."""

    #: Data sequence number.
    dsn: 'int'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', subtype: 'MPTCPOption', dsn: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class MPTCPFastclose(MPTCP):
    """Data model for TCP ``MP_FASTCLOSE`` option."""

    #: Option receiver's key.
    rkey: 'int'

    if TYPE_CHECKING:
        def __init__(self, kind: 'OptionNumber', length: 'int', subtype: 'MPTCPOption', rkey: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin
