# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for transmission control protocol"""

import collections
from typing import TYPE_CHECKING

from pcapkit.const.reg.apptype import AppType as Enum_AppType
from pcapkit.const.reg.apptype import TransportProtocol as Enum_TransportProtocol
from pcapkit.const.tcp.checksum import Checksum as Enum_Checksum
from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
from pcapkit.const.tcp.option import Option as Enum_Option
from pcapkit.corekit.fields.collections import ListField, OptionField
from pcapkit.corekit.fields.ipaddress import IPv4AddressField, IPv6AddressField
from pcapkit.corekit.fields.misc import (ConditionalField, ForwardMatchField, PayloadField,
                                         SchemaField, SwitchField)
from pcapkit.corekit.fields.numbers import (EnumField, NumberField, UInt8Field, UInt16Field,
                                            UInt32Field, UInt64Field)
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField
from pcapkit.protocols.schema.schema import EnumSchema, Schema, schema_final
from pcapkit.utilities.exceptions import FieldError
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING

__all__ = [
    'TCP',

    'Option',
    'UnassignedOption', 'EndOfOptionList', 'NoOperation', 'MaximumSegmentSize', 'WindowScale',
    'SACKPermitted', 'SACK', 'Echo', 'EchoReply', 'Timestamps', 'PartialOrderConnectionPermitted',
    'PartialOrderServiceProfile', 'CC', 'CCNew', 'CCEcho', 'AlternateChecksumRequest',
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
    from typing import Any, DefaultDict, Optional, Type

    from pcapkit.corekit.fields.field import FieldBase as Field
    from pcapkit.protocols.protocol import ProtocolBase as Protocol

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
    schema = MPTCP.registry[subtype]

    if subtype == Enum_MPTCPOption.MP_JOIN and schema is MPTCPJoin:  # placeholder
        if pkt['flags']['syn'] == 1 and pkt['flags']['ack'] == 0:
            schema = MPTCPJoinSYN
        elif pkt['flags']['syn'] == 1 and pkt['flags']['ack'] == 1:
            schema = MPTCPJoinSYNACK
        elif pkt['flags']['syn'] == 0 and pkt['flags']['ack'] == 1:
            schema = MPTCPJoinACK
        else:
            raise FieldError(f'TCP: [OptNo {Enum_Option.Multipath_TCP}] {Enum_MPTCPOption.MP_JOIN} invalid flags')
    return SchemaField(length=pkt['test']['length'], schema=schema)


def mptcp_add_address_selector(pkt: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`MPTCPAddAddress.address` field.

    Args:
        pkt: Packet data.

    Returns:
        * If IP version is 4, a :class:`~pcapkit.corekit.fields.ipaddress.IPv4AddressField`
          instance.
        * If IP version is 6, a :class:`~pcapkit.corekit.fields.ipaddress.IPv6AddressField`
          instance.

    """
    if pkt['test']['version'] == 4:
        return IPv4AddressField()
    if pkt['test']['version'] == 6:
        return IPv6AddressField()
    raise FieldError(f'TCP: [OptNo {Enum_Option.Multipath_TCP}] {Enum_MPTCPOption.ADD_ADDR} invalid IP version')


class PortEnumField(EnumField):
    """Enumerated value for protocol fields.

    Args:
        length: Field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        default: Field default value, if any.
        signed: Whether the field is signed.
        byteorder: Field byte order.
        bit_length: Field bit length.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    Important:
        This class is specifically designed for :class:`~pcapkit.const.reg.apptype.AppType`
        as it is actually a :class:`~enum.StrEnum` class.

    """
    if TYPE_CHECKING:
        _namespace: 'Enum_AppType'

    def pre_process(self, value: 'int | Enum_AppType', packet: 'dict[str, Any]') -> 'int | bytes':
        """Process field value before construction (packing).

        Arguments:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        """
        if isinstance(value, Enum_AppType):
            value = value.port
        return super().pre_process(value, packet)

    def post_process(self, value: 'int | bytes', packet: 'dict[str, Any]') -> 'Enum_AppType':
        """Process field value after parsing (unpacked).

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        """
        value = super(EnumField, self).post_process(value, packet)
        return self._namespace.get(value, proto=Enum_TransportProtocol.tcp)


class Option(EnumSchema[Enum_Option]):
    """Header schema for TCP options."""

    __default__ = lambda: UnassignedOption

    #: Option kind.
    kind: 'Enum_Option' = EnumField(length=1, namespace=Enum_Option)
    #: Option length.
    length: 'int' = ConditionalField(
        UInt8Field(),
        lambda pkt: pkt['kind'] not in (Enum_Option.End_of_Option_List, Enum_Option.No_Operation),
    )

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        # for EOOL/NOP option, length is always 1
        if self.kind in (Enum_Option.End_of_Option_List, Enum_Option.No_Operation):
            self.length = 1
        return self


@schema_final
class UnassignedOption(Option):
    """Header schema for TCP unassigned options."""

    #: Option data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 2)

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', data: 'bytes') -> 'None': ...


@schema_final
class EndOfOptionList(Option, code=Enum_Option.End_of_Option_List):
    """Header schema for TCP end of option list."""

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int') -> 'None': ...


@schema_final
class NoOperation(Option, code=Enum_Option.No_Operation):
    """Header schema for TCP no operation."""

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int') -> 'None': ...


@schema_final
class MaximumSegmentSize(Option, code=Enum_Option.Maximum_Segment_Size):
    """Header schema for TCP max segment size option."""

    #: Maximum segment size.
    mss: 'int' = UInt16Field()

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', mss: 'int') -> 'None': ...


@schema_final
class WindowScale(Option, code=Enum_Option.Window_Scale):
    """Header schema for TCP window scale option."""

    #: Window scale (shift count).
    shift: 'int' = UInt8Field()

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', scale: 'int') -> 'None': ...


@schema_final
class SACKPermitted(Option, code=Enum_Option.SACK_Permitted):
    """Header schema for TCP SACK permitted option."""

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int') -> 'None': ...


@schema_final
class SACKBlock(Schema):
    """Header schema for TCP SACK option data."""

    #: Left edge of the block.
    left: 'int' = UInt32Field()
    #: Right edge of the block.
    right: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, left: 'int', right: 'int') -> 'None': ...


@schema_final
class SACK(Option, code=Enum_Option.SACK):
    """Header schema for TCP SACK option."""

    #: Selected ACK data.
    sack: 'list[SACKBlock]' = ListField(
        length=lambda pkt: pkt['length'] - 2,
        item_type=SchemaField(length=8, schema=SACKBlock),
    )

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', sack: 'list[SACKBlock]') -> 'None': ...


@schema_final
class Echo(Option, code=Enum_Option.Echo):
    """Header schema for TCP echo option."""

    #: Info to be echoed.
    data: 'bytes' = BytesField(length=4)

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', data: 'bytes') -> 'None': ...


@schema_final
class EchoReply(Option, code=Enum_Option.Echo_Reply):
    """Header schema for TCP echo reply option."""

    #: Echoed info.
    data: 'bytes' = BytesField(length=4)

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', data: 'bytes') -> 'None': ...


@schema_final
class Timestamps(Option, code=Enum_Option.Timestamps):
    """Header schema for TCP timestamps option."""

    #: Timestamp value.
    value: 'int' = UInt32Field()
    #: Timestamp echo reply.
    reply: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', value: 'int', reply: 'int') -> 'None': ...


@schema_final
class PartialOrderConnectionPermitted(Option, code=Enum_Option.Partial_Order_Connection_Permitted):
    """Header schema for TCP partial order connection permitted option."""

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int') -> 'None': ...


@schema_final
class PartialOrderServiceProfile(Option, code=Enum_Option.Partial_Order_Service_Profile):
    """Header schema for TCP partial order connection service profile option."""

    #: Profile data.
    profile: 'POCProfile' = BitField(length=1, namespace={
        'start': (0, 1),
        'end': (1, 1),
    })

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', profile: 'POCProfile') -> 'None': ...


@schema_final
class CC(Option, code=Enum_Option.CC):
    """Header schema for TCP CC option."""

    #: Connection count.
    count: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', count: 'int') -> 'None': ...


@schema_final
class CCNew(Option, code=Enum_Option.CC_NEW):
    """Header schema for TCP connection count (new) option."""

    #: Connection count.
    count: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', count: 'int') -> 'None': ...


@schema_final
class CCEcho(Option, code=Enum_Option.CC_ECHO):
    """Header schema for TCP connection count (echo) option."""

    #: Connection count.
    count: 'int' = UInt32Field()

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', count: 'int') -> 'None': ...


@schema_final
class AlternateChecksumRequest(Option, code=Enum_Option.TCP_Alternate_Checksum_Request):
    """Header schema for TCP alternate checksum request option."""

    #: Checksum algorithm.
    algorithm: 'Enum_Checksum' = EnumField(length=1, namespace=Enum_Checksum)

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', algorithm: 'Enum_Checksum') -> 'None': ...


@schema_final
class AlternateChecksumData(Option, code=Enum_Option.TCP_Alternate_Checksum_Data):
    """Header schema for TCP alternate checksum data option."""

    #: Checksum data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 2)

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', data: 'bytes') -> 'None': ...


@schema_final
class MD5Signature(Option, code=Enum_Option.MD5_Signature_Option):
    """Header schema for TCP MD5 signature option."""

    #: MD5 digest.
    digest: 'bytes' = BytesField(length=16)

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', digest: 'bytes') -> 'None': ...


@schema_final
class QuickStartResponse(Option, code=Enum_Option.Quick_Start_Response):
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


@schema_final
class UserTimeout(Option, code=Enum_Option.User_Timeout_Option):
    """Header schema for TCP user timeout option."""

    #: Granularity and user timeout.
    info: 'TimeoutInfo' = BitField(length=2, namespace={
        'granularity': (0, 1),
        'timeout': (1, 15),
    })

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', info: 'TimeoutInfo') -> 'None': ...


@schema_final
class Authentication(Option, code=Enum_Option.TCP_Authentication_Option):
    """Header schema for TCP authentication option."""

    #: Key ID.
    key_id: 'int' = UInt8Field()
    #: Next key ID.
    next_key_id: 'int' = UInt8Field()
    #: MAC value.
    mac: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 4)

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', key_id: 'int', next_key_id: 'int', mac: 'bytes') -> 'None': ...


@schema_final
class _MPTCP(Schema):
    """Header schema for Multipath TCP options in a generic representation."""

    #: Subtype and flags.
    test: 'MPTCPSubtypeTest' = ForwardMatchField(BitField(length=3, namespace={
        'length': (1, 8),
        'subtype': (16, 4),
    }))
    #: Subtype-specific data.
    data: 'MPTCP' = SwitchField(
        selector=mptcp_data_selector,
    )

    def post_process(self, packet: 'dict[str, Any]') -> 'MPTCP':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        ret = self.data

        ret.option = Enum_Option.Multipath_TCP
        ret.length = self.test['length']
        ret.subtype = Enum_MPTCPOption.get(packet['test']['subtype'])

        return ret


# register ``_MPTCP`` as ``Multipath_TCP`` option
Option.register(Enum_Option.Multipath_TCP, _MPTCP)


class MPTCP(EnumSchema[Enum_MPTCPOption]):
    """Header schema for Multipath TCP options."""

    __enum__: 'DefaultDict[Enum_MPTCPOption, Type[MPTCP]]' = collections.defaultdict(lambda: MPTCPUnknown)

    if TYPE_CHECKING:
        #: Option kind.
        kind: 'Enum_Option'
        #: MPTCP length.
        length: 'int'
        #: MPTCP subtype.
        subtype: 'Enum_MPTCPOption'


@schema_final
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


@schema_final
class MPTCPCapable(MPTCP, code=Enum_MPTCPOption.MP_CAPABLE):
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


class MPTCPJoin(MPTCP, code=Enum_MPTCPOption.MP_JOIN):  # register as a placeholder
    """Header schema for Multipath TCP join option."""


@schema_final
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


@schema_final
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


@schema_final
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


@schema_final
class MPTCPDSS(MPTCP, code=Enum_MPTCPOption.DSS):
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


@schema_final
class MPTCPAddAddress(MPTCP, code=Enum_MPTCPOption.ADD_ADDR):
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
        selector=mptcp_add_address_selector,
    )
    #: Port.
    port: 'int' = ConditionalField(
        UInt16Field(),
        lambda pkt: pkt['length'] in (10, 22),
    )

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', test: 'MPTCPSubtypeAddAddress', addr_id: 'int', address: 'IPv4Address | IPv6Address', port: 'Optional[int]') -> 'None': ...


@schema_final
class MPTCPRemoveAddress(MPTCP, code=Enum_MPTCPOption.REMOVE_ADDR):
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


@schema_final
class MPTCPPriority(MPTCP, code=Enum_MPTCPOption.MP_PRIO):
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


@schema_final
class MPTCPFallback(MPTCP, code=Enum_MPTCPOption.MP_FAIL):
    """Header schema for Multipath TCP fallback option."""

    #: Subtype.
    test: 'MPTCPSubtype' = BitField(length=1, namespace={
        'subtype': (0, 4),
    })
    #: Data sequence number.
    dsn: 'int' = UInt64Field()

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', test: 'MPTCPSubtype', dsn: 'int') -> 'None': ...


@schema_final
class MPTCPFastclose(MPTCP, code=Enum_MPTCPOption.MP_FASTCLOSE):
    """Header schema for Multipath TCP fastclose option."""

    #: Subtype.
    test: 'MPTCPSubtype' = BitField(length=1, namespace={
        'subtype': (0, 4),
    })
    #: Option receiver's key.
    key: 'int' = UInt64Field()

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', test: 'MPTCPSubtype', key: 'int') -> 'None': ...


@schema_final
class FastOpenCookie(Option, code=Enum_Option.TCP_Fast_Open_Cookie):
    """"Header schema for TCP Fast Open option."""

    #: Cookie.
    cookie: 'bytes' = ConditionalField(
        BytesField(length=lambda pkt: pkt['length'] - 2),
        lambda pkt: pkt['length'] >= 6,
    )

    if TYPE_CHECKING:
        def __init__(self, kind: 'Enum_Option', length: 'int', cookie: 'Optional[bytes]') -> 'None': ...


@schema_final
class TCP(Schema):
    """Header schema for TCP packet."""

    #: Source port.
    srcport: 'Enum_AppType' = PortEnumField(length=2, namespace=Enum_AppType)
    #: Destination port.
    dstport: 'Enum_AppType' = PortEnumField(length=2, namespace=Enum_AppType)
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
        registry=Option.registry,
        eool=Enum_Option.End_of_Option_List,
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: pkt.get('__option_padding__', 0))  # key generated by OptionField
    #: Payload.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, srcport: 'Enum_AppType | int', dstport: 'Enum_AppType | int', seq: 'int', ack: 'int',
                     offset: 'OffsetFlag', flags: 'Flags', window: 'int', checksum: 'bytes',
                     urgent: 'int', options: 'list[Option | bytes] | bytes', payload: 'bytes | Protocol | Schema') -> 'None': ...
