# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for transmission control protocol"""

import collections
from typing import TYPE_CHECKING, cast

from pcapkit.const.tcp.checksum import Checksum as Enum_Checksum
from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
from pcapkit.const.tcp.option import Option as Enum_Option
from pcapkit.corekit.fields.collections import ListField, OptionField
from pcapkit.corekit.fields.ipaddress import IPv4Field, IPv6Field
from pcapkit.corekit.fields.misc import (ConditionalField, ForwardMatchField, PayloadField,
                                         SchemaField, SwitchField)
from pcapkit.corekit.fields.numbers import (EnumField, NumberField, UInt8Field, UInt16Field,
                                            UInt32Field, UInt64Field)
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField
from pcapkit.protocols.schema.schema import Schema
from pcapkit.utilities.exceptions import FieldError
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING

__all__ = [
    'TCP',

    'Option',
    'UnassignedOption', 'EndOfOptionList', 'NoOperation', 'MaximumSegmentSize', 'WindowScale',
    'SACKPermitted', 'SACK', 'Echo', 'EchoReply', 'Timestamp', 'PartialOrderConnectionPermitted',
    'PartialOrderConnectionProfile', 'CC', 'CCNew', 'CCEcho', 'AlternateChecksumRequest',
    'AlternateChecksumData', 'MD5Signature', 'QuickStartResponse', 'UserTimeout',
    'Authentication', 'FastOpenCookie',

    'MPTCP',
    'MPTCPUnknown', 'MPTCPCapable', 'MPTCPDSS', 'MPTCPAddAddress', 'MPTCPRemoveAddress',
    'MPTCPPriority', 'MPTCPFallback', 'MPTCPFastclose',

    'MPTCPJoin',
    'MPTCPJoinSYN', 'MPTCPJoinSYNACK', 'MPTCPJoinACK',
]

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import IO, Any, Optional

    from typing_extensions import Literal

    from pcapkit.corekit.fields.field import _Field as Field
    from pcapkit.protocols.protocol import Protocol

if SPHINX_TYPE_CHECKING:
    from typing_extensions import TypedDict

    class OffsetFlag(TypedDict):
        """TCP offset field flag."""

        #: Data offset.
        offset: int
        #: ECN-nonce concealment protection.
        ns: int

    class Flags(TypedDict):
        """TCP flags."""

        #: Congestion window reduced.
        cwr: int
        #: ECN-Echo.
        ece: int
        #: Urgent pointer.
        urg: int
        #: Acknowledgment.
        ack: int
        #: Push function.
        psh: int
        #: Reset connection.
        rst: int
        #: Synchronize sequence numbers.
        syn: int
        #: Last packet from sender.
        fin: int

    class POCProfile(TypedDict):
        """TCP partial order connection service profile."""

        #: Start flag.
        start: int
        #: End flag.
        end: int

    class QuickStartFlags(TypedDict):
        """TCP quick start flags."""

        #: Rate request.
        rate: int

    class QuickStartNonce(TypedDict):
        """TCP quick start nonce."""

        #: Nonce.
        nonce: int

    class TimeoutInfo(TypedDict):
        """User timeout information."""

        #: Granularity.
        granularity: int
        #: Timeout value.
        timeout: int

    class MPTCPSubtypeTest(TypedDict):
        """TCP MPTCP subtype."""

        #: Length.
        length: int
        #: Subtype.
        subtype: int

    class MPTCPSubtypeUnknown(TypedDict):
        """TCP unknown MPTCP subtype field."""

        #: Subtype.
        subtype: int
        #: Data.
        data: int

    class MPTCPSubtypeCapable(TypedDict):
        """MPTCP Capable subtype field."""

        #: Subtype.
        subtype: int
        #: Version.
        version: int

    class MPTCPCapableFlags(TypedDict):
        """MPTCP Capable flags."""

        #: Checksum required.
        req: int
        #: Extensibility flag.
        ext: int
        #: Use of HMAC-SHA1.
        hsa: int

    class MPTCPSubtypeJoin(TypedDict):
        """MPTCP Join subtype field."""

        #: Subtype.
        subtype: int
        #: Backup flag.
        backup: int

    class MPTCPSubtype(TypedDict):
        """MPTCP subtype field."""

        #: Subtype.
        subtype: int

    class MPTCPDSSFlags(TypedDict):
        """MPTCP-DSS flags."""

        #: ``DATA_FIN`` flag.
        F: int
        #: Data sequence number is 8 octets (if not set, DSN is 4 octets).
        m: int
        #: Data Sequence Number (DSN), Subflow Sequence Number (SSN), Data-Level
        #: Length, and Checksum present.
        M: int
        #: Data ACK is 8 octets (if not set, Data ACK is 4 octets).
        a: int
        #: Data ACK present.
        A: int

    class MPTCPSubtypeAddAddress(TypedDict):
        """MPTCP Add Address subtype field."""

        #: Subtype.
        subtype: int
        #: IP version.
        version: int

    class MPTCPSubtypePriority(TypedDict):
        """MPTCP Priority subtype field."""

        #: Subtype.
        subtype: int
        #: Backup flag.
        backup: int


def mptcp_data_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`_MPTCP.data` field.

    Args:
        pkt: Packet data.

    Returns:
        A :class:`~pcapkit.corekit.fields.misc.SchemaField` wrapped
        :class:`~pcapkit.protocols.schema.transport.tcp.MPTCP` subclass
        instance.

    """
    subtype = Enum_MPTCPOption.get(pkt['test']['subtype'])
    pkt['test']['subtype'] = subtype

    if subtype == Enum_MPTCPOption.MP_CAPABLE:
        return SchemaField(schema=MPTCPCapable)
    if subtype == Enum_MPTCPOption.MP_JOIN:
        if pkt['flags']['syn'] == 1 and pkt['flags']['ack'] == 0:
            return SchemaField(schema=MPTCPJoinSYN)
        if pkt['flags']['syn'] == 1 and pkt['flags']['ack'] == 1:
            return SchemaField(schema=MPTCPJoinSYNACK)
        if pkt['flags']['syn'] == 0 and pkt['flags']['ack'] == 1:
            return SchemaField(schema=MPTCPJoinACK)
        raise FieldError(f'TCP: [OptNo {Enum_Option.Multipath_TCP}] {Enum_MPTCPOption.MP_JOIN} invalid flags')
    if subtype == Enum_MPTCPOption.DSS:
        return SchemaField(schema=MPTCPDSS)
    if subtype == Enum_MPTCPOption.ADD_ADDR:
        return SchemaField(schema=MPTCPAddAddress)
    if subtype == Enum_MPTCPOption.REMOVE_ADDR:
        return SchemaField(schema=MPTCPRemoveAddress)
    if subtype == Enum_MPTCPOption.MP_PRIO:
        return SchemaField(schema=MPTCPPriority)
    if subtype == Enum_MPTCPOption.MP_FAIL:
        return SchemaField(schema=MPTCPFallback)
    if subtype == Enum_MPTCPOption.MP_FASTCLOSE:
        return SchemaField(schema=MPTCPFastclose)
    return SchemaField(schema=MPTCPUnknown)


def mptcp_add_address_length(pkt: 'dict[str, Any]') -> 'Literal[4, 16]':
    """Length callback function for :attr:`MPTCPAddAddress.address` field.

    Args:
        pkt: Packet data.

    Returns:
        Length of :attr:`MPTCPAddAddress.address` field.

    """
    if pkt['test']['version'] == 4:
        return 4
    if pkt['test']['version'] == 6:
        return 16
    raise FieldError(f'TCP: [OptNo {Enum_Option.Multipath_TCP}] {Enum_MPTCPOption.ADD_ADDR} invalid IP version')


def mptcp_add_address_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`MPTCPAddAddress.address` field.

    Args:
        pkt: Packet data.

    Returns:
        * If IP version is 4, a :class:`~pcapkit.corekit.fields.ipaddress.IPv4Field`
          instance.
        * If IP version is 6, a :class:`~pcapkit.corekit.fields.ipaddress.IPv6Field`
          instance.

    """
    if pkt['test']['version'] == 4:
        return IPv4Field()
    if pkt['test']['version'] == 6:
        return IPv6Field()
    raise FieldError(f'TCP: [OptNo {Enum_Option.Multipath_TCP}] {Enum_MPTCPOption.ADD_ADDR} invalid IP version')


class Option(Schema):
    """Header schema for TCP options."""

    #: Option kind.
    kind: 'Enum_Option' = EnumField(length=1, namespace=Enum_Option)
    #: Option length.
    length: 'int' = ConditionalField(
        UInt8Field(),
        lambda pkt: pkt['kind'] not in (Enum_Option.End_of_Option_List, Enum_Option.No_Operation),
    )

    @classmethod
    def post_process(cls, schema: 'Schema', data: 'IO[bytes]',
                     length: 'int', packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            schema: parsed schema
            data: Packed data.
            length: Length of data.
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        if TYPE_CHECKING:
            schema = cast('Option', schema)

        # for EOOL/NOP option, length is always 1
        if schema.kind in (Enum_Option.End_of_Option_List, Enum_Option.No_Operation):
            schema.length = 1
        return schema


class UnassignedOption(Option):
    """Header schema for TCP unassigned options."""

    #: Option data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 2)

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', data: 'bytes') -> 'None': ...


class EndOfOptionList(Option):
    """Header schema for TCP end of option list."""

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int') -> 'None': ...


class NoOperation(Option):
    """Header schema for TCP no operation."""

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int') -> 'None': ...


class MaximumSegmentSize(Option):
    """Header schema for TCP max segment size option."""

    #: Maximum segment size.
    mss: 'int' = UInt16Field()

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', mss: 'int') -> 'None': ...


class WindowScale(Option):
    """Header schema for TCP window scale option."""

    #: Window scale (shift count).
    shift: 'int' = UInt8Field()

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', scale: 'int') -> 'None': ...


class SACKPermitted(Option):
    """Header schema for TCP SACK permitted option."""

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int') -> 'None': ...


class SACKBlock(Schema):
    """Header schema for TCP SACK option data."""

    #: Left edge of the block.
    left: 'int' = UInt32Field()
    #: Right edge of the block.
    right: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, left: 'int', right: 'int') -> 'None': ...


class SACK(Option):
    """Header schema for TCP SACK option."""

    #: Selected ACK data.
    sack: 'list[SACKBlock]' = ListField(
        length=lambda pkt: pkt['length'] - 2,
        item_type=SchemaField(length=8, schema=SACKBlock),
    )

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', sack: 'list[SACKBlock]') -> 'None': ...


class Echo(Option):
    """Header schema for TCP echo option."""

    #: Info to be echoed.
    data: 'bytes' = BytesField(length=4)

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', data: 'bytes') -> 'None': ...


class EchoReply(Option):
    """Header schema for TCP echo reply option."""

    #: Echoed info.
    data: 'bytes' = BytesField(length=4)

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', data: 'bytes') -> 'None': ...


class Timestamp(Option):
    """Header schema for TCP timestamps option."""

    #: Timestamp value.
    value: 'int' = UInt32Field()
    #: Timestamp echo reply.
    reply: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', value: 'int', reply: 'int') -> 'None': ...


class PartialOrderConnectionPermitted(Option):
    """Header schema for TCP partial order connection permitted option."""

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int') -> 'None': ...


class PartialOrderConnectionProfile(Option):
    """Header schema for TCP partial order connection service profile option."""

    #: Profile data.
    profile: 'POCProfile' = BitField(length=1, namespace={
        'start': (0, 1),
        'end': (1, 1),
    })

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', profile: 'POCProfile') -> 'None': ...


class CC(Option):
    """Header schema for TCP CC option."""

    #: Connection count.
    count: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', count: 'int') -> 'None': ...


class CCNew(Option):
    """Header schema for TCP connection count (new) option."""

    #: Connection count.
    count: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', count: 'int') -> 'None': ...


class CCEcho(Option):
    """Header schema for TCP connection count (echo) option."""

    #: Connection count.
    count: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', count: 'int') -> 'None': ...


class AlternateChecksumRequest(Option):
    """Header schema for TCP alternate checksum request option."""

    #: Checksum algorithm.
    algorithm: 'Enum_Checksum' = EnumField(length=1, namespace=Enum_Checksum)

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', algorithm: 'Enum_Checksum') -> 'None': ...


class AlternateChecksumData(Option):
    """Header schema for TCP alternate checksum data option."""

    #: Checksum data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 2)

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', data: 'bytes') -> 'None': ...


class MD5Signature(Option):
    """Header schema for TCP MD5 signature option."""

    #: MD5 digest.
    digest: 'bytes' = BytesField(length=16)

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', digest: 'bytes') -> 'None': ...


class QuickStartResponse(Option):
    """Header schema for TCP quick start response option."""

    #: Flags.
    flags: 'QuickStartFlags' = BitField(length=1, namespace={
        'rate': (4, 4),
    })
    #: TTL difference.
    diff: 'int' = UInt8Field()
    #: QS nonce.
    nonce: 'QuickStartNonce' = BitField(length=4, namespace={
        'nonce': (0, 30),
    })

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', flags: 'QuickStartFlags', diff: 'int', nonce: 'QuickStartNonce') -> 'None': ...


class UserTimeout(Option):
    """Header schema for TCP user timeout option."""

    #: Granularity and user timeout.
    info: 'TimeoutInfo' = BitField(length=2, namespace={
        'granularity': (0, 1),
        'timeout': (1, 15),
    })

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', info: 'TimeoutInfo') -> 'None': ...


class Authentication(Option):
    """Header schema for TCP authentication option."""

    #: Key ID.
    key_id: 'int' = UInt8Field()
    #: Next key ID.
    next_key_id: 'int' = UInt8Field()
    #: MAC value.
    mac: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 4)

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', key_id: 'int', next_key_id: 'int', mac: 'bytes') -> 'None': ...


class _MPTCP(Schema):
    """Header schema for Multipath TCP options in a generic representation."""

    #: Subtype and flags.
    test: 'MPTCPSubtypeTest' = ForwardMatchField(BitField(length=3, namespace={
        'length': (1, 8),
        'subtype': (16, 4),
    }))
    #: Subtype-specific data.
    data: 'MPTCP' = SwitchField(
        length=lambda pkt: pkt['test']['length'],
        selector=mptcp_data_selector,
    )

    @classmethod
    def post_process(cls, schema: 'Schema', data: 'IO[bytes]',
                     length: 'int', packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            schema: parsed schema
            data: Packed data.
            length: Length of data.
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        if TYPE_CHECKING:
            schema = cast('_MPTCP', schema)

        ret = schema.data
        ret.subtype = Enum_MPTCPOption.get(packet['test']['subtype'])
        return ret


class MPTCP(Option):
    """Header schema for Multipath TCP options."""

    if TYPE_CHECKING:
        #: MPTCP subtype.
        subtype: 'Enum_MPTCPOption'


class MPTCPUnknown(MPTCP):
    """Header schema for unknown Multipath TCP option."""

    #: Subtype and data.
    test: 'MPTCPSubtypeUnknown' = BitField(length=1, namespace={
        'subtype': (0, 4),
        'data': (4, 4),
    })
    #: Data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 2)

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', test: 'MPTCPSubtypeUnknown', data: 'bytes') -> 'None': ...


class MPTCPCapable(MPTCP):
    """Header schema for Multipath TCP capable option."""

    #: Subtype and version.
    test: 'MPTCPSubtypeCapable' = BitField(length=1, namespace={
        'subtype': (0, 4),
        'version': (4, 4),
    })
    #: Flags.
    flags: 'MPTCPCapableFlags' = BitField(length=1, namespace={
        'req': (0, 1),
        'ext': (1, 1),
        'hsa': (7, 1),
    })
    #: Option sender's key.
    skey: 'int' = UInt64Field()
    #: Option receiver's key.
    rkey: 'int' = ConditionalField(
        UInt64Field(),
        lambda pkt: pkt['length'] != 32,
    )

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', test: 'MPTCPSubtypeCapable', flags: 'MPTCPCapableFlags', skey: 'int', rkey: 'Optional[int]') -> 'None': ...


class MPTCPJoin(MPTCP):
    """Header schema for Multipath TCP join option."""


class MPTCPJoinSYN(MPTCPJoin):
    """Header schema for Multipath TCP join option for ``SYN`` connection."""

    #: Subtype and flags.
    test: 'MPTCPSubtypeJoin' = BitField(length=1, namespace={
        'subtype': (0, 4),
        'backup': (7, 1),
    })
    #: Address ID.
    addr_id: 'int' = UInt8Field()
    #: Receiver's token.
    token: 'int' = UInt32Field()
    #: Sender's random number.
    nonce: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', test: 'MPTCPSubtypeJoin', addr_id: 'int', token: 'int', nonce: 'int') -> 'None': ...


class MPTCPJoinSYNACK(MPTCPJoin):
    """Header schema for Multipath TCP join option for ``SYN/ACK`` connection."""

    #: Subtype and flags.
    test: 'MPTCPSubtypeJoin' = BitField(length=1, namespace={
        'subtype': (0, 4),
        'backup': (7, 1),
    })
    #: Address ID.
    addr_id: 'int' = UInt8Field()
    #: Sender's truncated HMAC
    hmac: 'bytes' = BytesField(length=8)
    #: Sender's random number.
    nonce: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', test: 'MPTCPSubtypeJoin', addr_id: 'int', hmac: 'bytes', nonce: 'int') -> 'None': ...


class MPTCPJoinACK(MPTCPJoin):
    """Header schema for Multipath TCP join option for ``ACK`` connection."""

    #: Subtype.
    test: 'MPTCPSubtype' = BitField(length=1, namespace={
        'subtype': (0, 4),
    })
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=1)
    #: Sender's HMAC.
    hmac: 'bytes' = BytesField(length=20)

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', test: 'MPTCPSubtype', hmac: 'bytes') -> 'None': ...


class MPTCPDSS(MPTCP):
    """Header schema for Multipath TCP DSS option."""

    #: Subtype and flags.
    test: 'MPTCPSubtype' = BitField(length=1, namespace={
        'subtype': (0, 4),
    })
    #: Flags.
    flags: 'MPTCPDSSFlags' = BitField(length=1, namespace={
        'F': (3, 1),
        'm': (4, 1),
        'M': (5, 1),
        'a': (6, 1),
        'A': (7, 1),
    })
    #: Data ACK.
    ack: 'int' = ConditionalField(
        NumberField(length=lambda pkt: 8 if pkt['flags']['a'] else 0, signed=False),
        lambda pkt: pkt['flags']['A'],
    )
    #: Data sequence number.
    dsn: 'int' = ConditionalField(
        NumberField(length=lambda pkt: 8 if pkt['flags']['m'] else 0, signed=False),
        lambda pkt: pkt['flags']['M'],
    )
    #: Subflow sequence number.
    ssn: 'int' = ConditionalField(
        UInt32Field(),
        lambda pkt: pkt['flags']['M'],
    )
    #: Data level length.
    dl_len: 'int' = ConditionalField(
        UInt16Field(),
        lambda pkt: pkt['flags']['M'],
    )
    #: Checksum.
    checksum: 'bytes' = ConditionalField(
        BytesField(length=2),
        lambda pkt: pkt['flags']['M'],
    )

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', test: 'MPTCPSubtype', flags: 'MPTCPDSSFlags', ack: 'Optional[int]', dsn: 'Optional[int]', ssn: 'Optional[int]', dl_len: 'Optional[int]', checksum: 'Optional[bytes]') -> 'None': ...


class MPTCPAddAddress(MPTCP):
    """Header schema for Multipath TCP add address option."""

    #: Subtype and IP version.
    test: 'MPTCPSubtypeAddAddress' = BitField(length=1, namespace={
        'subtype': (0, 4),
        'version': (4, 4),
    })
    #: Address ID.
    addr_id: 'int' = UInt8Field()
    #: Address.
    address: 'IPv4Address | IPv6Address' = SwitchField(
        length=mptcp_add_address_length,
        selector=mptcp_add_address_selector,
    )
    #: Port.
    port: 'int' = ConditionalField(
        UInt16Field(),
        lambda pkt: pkt['length'] in (10, 22),
    )

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', test: 'MPTCPSubtypeAddAddress', addr_id: 'int', address: 'IPv4Address | IPv6Address', port: 'Optional[int]') -> 'None': ...


class MPTCPRemoveAddress(MPTCP):
    """Header schema for Multipath TCP remove address option."""

    #: Subtype.
    test: 'MPTCPSubtype' = BitField(length=1, namespace={
        'subtype': (0, 4),
    })
    #: Address ID.
    addr_id: 'list[int]' = ListField(
        length=lambda pkt: pkt['length'] - 3,
        item_type=UInt8Field(),
    )

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', test: 'MPTCPSubtype', addr_id: 'list[int]') -> 'None': ...


class MPTCPPriority(MPTCP):
    """Header schema for Multipath TCP priority option."""

    #: Subtype.
    test: 'MPTCPSubtypePriority' = BitField(length=1, namespace={
        'subtype': (0, 4),
        'backup': (7, 1),
    })
    #: Address ID.
    addr_id: 'int' = ConditionalField(
        UInt8Field(),
        lambda pkt: pkt['length'] == 4,
    )

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', test: 'MPTCPSubtypePriority', addr_id: 'Optional[int]') -> 'None': ...


class MPTCPFallback(MPTCP):
    """Header schema for Multipath TCP fallback option."""

    #: Subtype.
    test: 'MPTCPSubtype' = BitField(length=1, namespace={
        'subtype': (0, 4),
    })
    #: Data sequence number.
    dsn: 'int' = UInt64Field()

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', test: 'MPTCPSubtype', dsn: 'int') -> 'None': ...


class MPTCPFastclose(MPTCP):
    """Header schema for Multipath TCP fastclose option."""

    #: Subtype.
    test: 'MPTCPSubtype' = BitField(length=1, namespace={
        'subtype': (0, 4),
    })
    #: Option receiver's key.
    key: 'int' = UInt64Field()

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', test: 'MPTCPSubtype', key: 'int') -> 'None': ...


class FastOpenCookie(Option):
    """"Header schema for TCP Fast Open option."""

    #: Cookie.
    cookie: 'bytes' = ConditionalField(
        BytesField(length=lambda pkt: pkt['length'] - 2),
        lambda pkt: pkt['length'] >= 6,
    )

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', cookie: 'Optional[bytes]') -> 'None': ...


class TCP(Schema):
    """Header schema for TCP packet."""

    #: Source port.
    srcport: 'int' = UInt16Field()
    #: Destination port.
    dstport: 'int' = UInt16Field()
    #: Sequence number.
    seq: 'int' = UInt32Field()
    #: Acknowledgement number.
    ack: 'int' = UInt32Field()
    #: Data offset.
    offset: 'OffsetFlag' = BitField(length=1, namespace={
        'offset': (0, 4),
        'ns': (7, 1),
    })
    #: TCP flags.
    flags: 'Flags' = BitField(length=1, namespace={
        'cwr': (0, 1),
        'ece': (1, 1),
        'urg': (2, 1),
        'ack': (3, 1),
        'psh': (4, 1),
        'rst': (5, 1),
        'syn': (6, 1),
        'fin': (7, 1),
    })
    #: Window size.
    window: 'int' = UInt16Field()
    #: Checksum.
    checksum: 'bytes' = BytesField(length=2)
    #: Urgent pointer.
    urgent: 'int' = UInt16Field()
    #: Options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['offset']['offset'] * 4 - 20,
        base_schema=Option,
        type_name='kind',
        eool=Enum_Option.End_of_Option_List,
        registry=collections.defaultdict(lambda: UnassignedOption, {
            Enum_Option.End_of_Option_List: EndOfOptionList,
            Enum_Option.No_Operation: NoOperation,
            Enum_Option.Maximum_Segment_Size: MaximumSegmentSize,
            Enum_Option.Window_Scale: WindowScale,
            Enum_Option.SACK_Permitted: SACKPermitted,
            Enum_Option.SACK: SACK,
            Enum_Option.Echo: Echo,
            Enum_Option.Echo_Reply: EchoReply,
            Enum_Option.Timestamps: Timestamp,
            Enum_Option.Partial_Order_Connection_Permitted: PartialOrderConnectionPermitted,
            Enum_Option.Partial_Order_Service_Profile: PartialOrderConnectionProfile,
            Enum_Option.CC: CC,
            Enum_Option.CC_NEW: CCNew,
            Enum_Option.CC_ECHO: CCEcho,
            Enum_Option.TCP_Alternate_Checksum_Request: AlternateChecksumRequest,
            Enum_Option.TCP_Alternate_Checksum_Data: AlternateChecksumData,
            Enum_Option.MD5_Signature_Option: MD5Signature,
            Enum_Option.Quick_Start_Response: QuickStartResponse,
            Enum_Option.User_Timeout_Option: UserTimeout,
            Enum_Option.TCP_Authentication_Option: Authentication,
            Enum_Option.Multipath_TCP: _MPTCP,
            Enum_Option.TCP_Fast_Open_Cookie: FastOpenCookie,
        }),
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: pkt.get('__option_padding__', 0))
    #: Payload.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, srcport: 'int', dstport: 'int', seq: 'int', ack: 'int',
                     offset: 'OffsetFlag', flags: 'Flags', window: 'int', checksum: 'bytes',
                     urgent: 'int', options: 'list[Option | bytes] | bytes', payload: 'bytes | Protocol | Schema') -> 'None': ...
