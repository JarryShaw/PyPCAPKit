# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for pcapng file format"""

import base64
import collections
import collections.abc
import io
import struct
import sys
from typing import TYPE_CHECKING, Any, cast

from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType
from pcapkit.const.pcapng.filter_type import FilterType as Enum_FilterType
from pcapkit.const.pcapng.hash_algorithm import HashAlgorithm as Enum_HashAlgorithm
from pcapkit.const.pcapng.option_type import OptionType as Enum_OptionType
from pcapkit.const.pcapng.record_type import RecordType as Enum_RecordType
from pcapkit.const.pcapng.secrets_type import SecretsType as Enum_SecretsType
from pcapkit.const.pcapng.verdict_type import VerdictType as Enum_VerdictType
from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.corekit.fields.collections import OptionField
from pcapkit.corekit.fields.ipaddress import (IPv4AddressField, IPv4InterfaceField,
                                              IPv6AddressField, IPv6InterfaceField)
from pcapkit.corekit.fields.misc import ForwardMatchField, PayloadField, SchemaField, SwitchField
from pcapkit.corekit.fields.numbers import (EnumField, Int32Field, Int64Field, NumberField,
                                            UInt8Field, UInt16Field, UInt32Field, UInt64Field)
from pcapkit.corekit.fields.strings import BitField, BytesField, PaddingField, StringField
from pcapkit.corekit.multidict import MultiDict, OrderedMultiDict
from pcapkit.protocols.schema.schema import EnumSchema, Schema, schema_final
from pcapkit.utilities.exceptions import FieldValueError, ProtocolError, stacklevel
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING
from pcapkit.utilities.warnings import ProtocolWarning, warn

__all__ = [
    'PCAPNG',

    'Option', 'UnknownOption',
    'EndOfOption', 'CommentOption', 'CustomOption',
    'IF_NameOption', 'IF_DescriptionOption', 'IF_IPv4AddrOption', 'IF_IPv6AddrOption',
    'IF_MACAddrOption', 'IF_EUIAddrOption', 'IF_SpeedOption', 'IF_TSResolOption',
    'IF_TZoneOption', 'IF_FilterOption', 'IF_OSOption', 'IF_FCSLenOption',
    'IF_TSOffsetOption', 'IF_HardwareOption', 'IF_TxSpeedOption', 'IF_RxSpeedOption',
    'EPB_FlagsOption', 'EPB_HashOption', 'EPB_DropCountOption', 'EPB_PacketIDOption',
    'EPB_QueueOption', 'EPB_VerdictOption',
    'NS_DNSNameOption', 'NS_DNSIP4AddrOption', 'NS_DNSIP6AddrOption',
    'ISB_StartTimeOption', 'ISB_EndTimeOption', 'ISB_IFRecvOption', 'ISB_IFDropOption',
    'ISB_FilterAcceptOption', 'ISB_OSDropOption', 'ISB_UsrDelivOption',
    'PACK_FlagsOption', 'PACK_HashOption',

    'NameResolutionRecord', 'UnknownRecord', 'EndRecord', 'IPv4Record', 'IPv6Record',

    'DSBSecrets', 'UnknownSecrets', 'TLSKeyLog', 'WireGuardKeyLog', 'ZigBeeNWKKey',
    'ZigBeeAPSKey',

    'BlockType',
    'UnknownBlock', 'SectionHeaderBlock', 'InterfaceDescriptionBlock',
    'EnhancedPacketBlock', 'SimplePacketBlock', 'NameResolutionBlock',
    'InterfaceStatisticsBlock', 'SystemdJournalExportBlock', 'DecryptionSecretsBlock',
    'CustomBlock', 'PacketBlock',
]

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface
    from typing import Any, Callable, DefaultDict, Iterable, Optional, Type

    from typing_extensions import Literal, Self

    from pcapkit.corekit.fields.field import FieldBase as Field
    from pcapkit.protocols.misc.pcapng import TLSKeyLabel, WireGuardKeyLabel
    from pcapkit.protocols.protocol import ProtocolBase as Protocol

if SPHINX_TYPE_CHECKING:
    from typing_extensions import TypedDict

    class ByteorderTest(TypedDict):
        """Test for byteorder."""

        #: Byteorder magic number.
        byteorder: int

    class ResolutionData(TypedDict):
        """Data for resolution."""

        #: Resolution type flag (0: 10-based, 1: 2-based).
        flag: int
        #: Resolution value.
        resolution: int

    class EPBFlags(TypedDict):
        """EPB flags."""

        #: Inbound / Outbound packet (``00`` = information not available,
        #: ``01`` = inbound, ``10`` = outbound)
        direction: int
        #: Reception type (``000`` = not specified, ``001`` = unicast,
        #: ``010`` = multicast, ``011`` = broadcast, ``100`` = promiscuous).
        reception: int
        #: FCS length, in octets (``0000`` if this information is not available).
        #: This value overrides the ``if_fcslen`` option of the Interface Description
        #: Block, and is used with those link layers (e.g. PPP) where the length of
        #: the FCS can change during time.
        fcs_len: int
        #: Link-layer-dependent error - CRC error (bit 24).
        crc_error: int
        #: Link-layer-dependent error - packet too long error (bit 25).
        too_long: int
        #: Link-layer-dependent error - packet too short error (bit 26).
        too_short: int
        #: Link-layer-dependent error - wrong Inter Frame Gap error (bit 27).
        gap_error: int
        #: Link-layer-dependent error - unaligned frame error (bit 28).
        unaligned_error: int
        #: Link-layer-dependent error - Start Frame Delimiter error (bit 29).
        delimiter_error: int
        #: Link-layer-dependent error - preamble error (bit 30).
        preamble_error: int
        #: Link-layer-dependent error - symbol error (bit 31).
        symbol_error: int

    class PACKFlags(TypedDict):
        """PACK flags."""

        #: Inbound / Outbound packet (``00`` = information not available,
        #: ``01`` = inbound, ``10`` = outbound)
        direction: int
        #: Reception type (``000`` = not specified, ``001`` = unicast,
        #: ``010`` = multicast, ``011`` = broadcast, ``100`` = promiscuous).
        reception: int
        #: FCS length, in octets (``0000`` if this information is not available).
        #: This value overrides the ``if_fcslen`` option of the Interface Description
        #: Block, and is used with those link layers (e.g. PPP) where the length of
        #: the FCS can change during time.
        fcs_len: int
        #: Link-layer-dependent error - CRC error (bit 24).
        crc_error: int
        #: Link-layer-dependent error - packet too long error (bit 25).
        too_long: int
        #: Link-layer-dependent error - packet too short error (bit 26).
        too_short: int
        #: Link-layer-dependent error - wrong Inter Frame Gap error (bit 27).
        gap_error: int
        #: Link-layer-dependent error - unaligned frame error (bit 28).
        unaligned_error: int
        #: Link-layer-dependent error - Start Frame Delimiter error (bit 29).
        delimiter_error: int
        #: Link-layer-dependent error - preamble error (bit 30).
        preamble_error: int
        #: Link-layer-dependent error - symbol error (bit 31).
        symbol_error: int


def byteorder_callback(field: 'NumberField', packet: 'dict[str, Any]') -> 'None':
    """Update byte order of PCAP-NG file.

    Args:
        field: Field instance.
        packet: Packet data.

    """
    if 'byteorder' not in packet and '__packet__' in packet:
        field._byteorder = packet['__packet__'].get('byteorder', sys.byteorder)
    else:
        field._byteorder = packet.get('byteorder', sys.byteorder)


def shb_byteorder_callback(field: 'NumberField', packet: 'dict[str, Any]') -> 'None':
    """Update byte order of PCAP-NG file for SHB.

    Args:
        field: Field instance.
        packet: Packet data.

    """
    magic = packet['match']['byteorder']  # type: int
    if magic == 0x1A2B3C4D:
        field._byteorder = 'big'
    elif magic == 0x4D3C2B1A:
        field._byteorder = 'little'
    else:
        raise ProtocolError(f'unknown byteorder magic: {magic:#x}')


def pcapng_block_selector(packet: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`PCAPNG.block` field.

    Args:
        pkt: Packet data.

    Returns:
        Returns a :class:`~pcapkit.corekit.fields.misc.SchemaField`
        wrapped :class:`~pcapkit.protocols.schema.misc.pcapng.BlockType`
        subclass instance.

    See Also:
        * :class:`pcapkit.const.pcapng.block_type.BlockType`
        * :class:`pcapkit.protocols.schema.misc.pcapng.BlockType`

    """
    block_type = packet['type']  # type: Enum_BlockType
    schema = BlockType.registry[block_type]
    return SchemaField(length=packet['__length__'], schema=schema)


def dsb_secrets_selector(packet: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`DecryptionSecretsBlock.secrets_data` field.

    Args:
        pkt: Packet data.

    Returns:
        * If ``secrets_type`` is unknown, returns a
          :class:`~pcapkit.corekit.fields.strings.BytesField` instance.
        * If ``secret_type`` is :attr:`~pcapkit.const.pcapng.secrets_type.Secrets_Type.TLS_Key_Log`
          and/or :attr:`~pcapkit.const.pcapng.secrets_type.Secrets_Type.WireGuard_Key_Log`,
          returns a :class:`~pcapkit.corekit.fields.strings.StringField` instance.
        * Otherwise, returns a :class:`~pcapkit.corekit.fields.misc.SchemaField`
          wrapped :class:`~pcapkit.protocols.schema.misc.pcapng.DSBSecrets`
          subclass instance.

    See Also:
        * :class:`pcapkit.const.pcapng.secrets_type.Secrets_Type`
        * :class:`pcapkit.protocols.schema.misc.pcapng.DSBSecrets`

    """
    secrets_type = packet['secrets_type']  # type: int
    schema = DSBSecrets.registry[secrets_type]
    return SchemaField(length=packet['secrets_length'], schema=schema)


class OptionEnumField(EnumField):
    """Enumerated value for protocol fields.

    Args:
        length: Field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        default: Field default value, if any.
        signed: Whether the field is signed.
        byteorder: Field byte order.
        bit_length: Field bit length.
        namespace: Option namespace, i.e., namespace of the enum item.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    Important:
        This class is specifically designed for :class:`~pcapkit.const.pcapng.option_type.OptionType`
        as it is actually a :class:`~enum.StrEnum` class.

    """
    if TYPE_CHECKING:
        _namespace: 'Enum_OptionType'

    def __init__(self, length: 'int | Callable[[dict[str, Any]], int]',
                 default: 'Enum_OptionType' = Enum_OptionType.opt_endofopt, signed: 'bool' = False,
                 byteorder: 'Literal["little", "big"]' = 'big',
                 bit_length: 'Optional[int]' = None,
                 namespace: 'str' = 'opt',
                 callback: 'Callable[[Self, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        super().__init__(length, default, signed, byteorder, bit_length, Enum_OptionType, callback)

        self._opt_ns = namespace

    def pre_process(self, value: 'int | Enum_OptionType', packet: 'dict[str, Any]') -> 'int | bytes':
        """Process field value before construction (packing).

        Arguments:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        """
        if isinstance(value, Enum_OptionType):
            value = value.opt_value
        return super().pre_process(value, packet)

    def post_process(self, value: 'int | bytes', packet: 'dict[str, Any]') -> 'Enum_OptionType':
        """Process field value after parsing (unpacked).

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        """
        value = super(EnumField, self).post_process(value, packet)
        return self._namespace.get(value, namespace=self._opt_ns)


@schema_final
class PCAPNG(Schema):
    """Header schema for PCAP-NG file blocks."""

    #: Block type.
    type: 'Enum_BlockType' = EnumField(length=4, namespace=Enum_BlockType, callback=byteorder_callback)
    #: Block specific data.
    block: 'BlockType' = SwitchField(
        selector=pcapng_block_selector,
    )

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_BlockType', block: 'BlockType | bytes') -> 'None': ...


class BlockType(EnumSchema[Enum_BlockType]):
    """Header schema for PCAP-NG file blocks."""

    __default__ = lambda: UnknownBlock

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        This method validates the two block lengths and raises
        :exc:`~pcapkit.utilities.exceptions.ProtocolError` if they are not
        equal.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        if self.length != self.length2:
            block_type = packet.get('__packet__', {}).get('type', 'N/A')
            #raise ProtocolError(f'PCAP-NG: [Block {block_type}] block length mismatch: {self.length} != {self.length2}')
            warn(f'PCAP-NG: [Block {block_type}] block length mismatch: {self.length} != {self.length2}',
                 ProtocolWarning, stacklevel=stacklevel())
        return self

    if TYPE_CHECKING:
        length: int
        length2: int


@schema_final
class UnknownBlock(BlockType):
    """Header schema for unknown PCAP-NG file blocks."""

    #: Block total length.
    length: 'int' = UInt32Field(callback=byteorder_callback)
    #: Block body (including padding).
    body: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 12)
    #: Block total length.
    length2: 'int' = UInt32Field(callback=byteorder_callback)

    if TYPE_CHECKING:
        def __init__(self, length: 'int', body: 'bytes', length2: 'int') -> 'None': ...


class Option(EnumSchema[Enum_OptionType]):
    """Header schema for PCAP-NG file options."""

    __additional__ = ['__enum__', '__namespace__']
    __excluded__ = ['__enum__', '__namespace__']

    #: Namespace of PCAP-NG option type numbers.
    __namespace__: 'str' = None  # type: ignore[assignment]
    #: Mapping of PCAP-NG option type numbers to schemas.
    __enum__: 'DefaultDict[str, DefaultDict[Enum_OptionType, Type[Option]]]' = collections.defaultdict(
        lambda: Option.registry['opt'], {
            'opt': collections.defaultdict(lambda: UnknownOption),
            'if': collections.defaultdict(lambda: UnknownOption),
            'epb': collections.defaultdict(lambda: UnknownOption),
            'ns': collections.defaultdict(lambda: UnknownOption),
            'isb': collections.defaultdict(lambda: UnknownOption),
            'dsb': collections.defaultdict(lambda: UnknownOption),
            'pack': collections.defaultdict(lambda: UnknownOption),
        },
    )

    def __init_subclass__(cls, /, code: 'Optional[Enum_OptionType | Iterable[Enum_OptionType]]' = None,
                          namespace: 'Optional[str]' = None, *args: 'Any', **kwargs: 'Any') -> 'None':
        """Register option type to :attr:`__enum__` mapping.

        Args:
            code: Option type code. It can be either a single option type enumeration
                or a list of option type enumerations.
            namespace: Namespace of option type enumeration. If not given, the value
                will be inferred from the option type code.
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments.

        If ``code`` is provided, the subclass will be registered to the
        :attr:`__enum__` mapping with the given ``code``. If ``code`` is
        not given, the subclass will not be registered.

        Examples:

            .. code-block:: python

               from pcapkit.const.pcapng.option_type import OptionType as Enum_OptionType
               from pcapkit.protocols.schema.misc.pcapng improt Option

               class NewOption(Option, namespace='opt', code=Enum_OptionType.opt_new):
                   ...

        See Also:
            - :class:`pcapkit.const.pcapng.option_type.OptionType`

        """
        if namespace is not None:
            cls.__namespace__ = namespace

        if code is not None:
            if namespace is None:
                namespace = cast('Optional[str]', cls.__namespace__)

            if not isinstance(code, Enum_OptionType):
                for _code in code:
                    Option.register(_code, cls, namespace)
            else:
                Option.register(code, cls, namespace)
        super().__init_subclass__()

    @staticmethod
    def register(code: 'Enum_OptionType', cls: 'Type[Option]', ns: 'Optional[str]' = None) -> 'None':
        """Register option type to :attr:`__enum__` mapping.

        Args:
            code: Option type code.
            cls: Option type schema.
            ns: Namespace of option type enumeration. If not given, the value
                will be inferred from the option type code.

        """
        if ns is None:
            ns = code.name.split('_')[0]

        if ns == 'opt':
            for key in Option.registry:
                Option.registry[key][code] = cls
        elif ns in Option.registry:
            Option.registry[ns][code] = cls
        else:
            Option.registry[ns] = Option.registry['opt'].copy()
            Option.registry[ns][code] = cls

    if TYPE_CHECKING:
        #: Option type.
        type: 'Enum_OptionType'
        #: Option data length.
        length: 'int'


class _OPT_Option(Option, namespace='opt'):
    """Header schema for ``opt_*`` options."""

    #: Option type.
    type: 'Enum_OptionType' = OptionEnumField(length=2, namespace='opt', callback=byteorder_callback)
    #: Option data length.
    length: 'int' = UInt16Field(callback=byteorder_callback)


@schema_final
class UnknownOption(_OPT_Option):
    """Header schema for unknown PCAP-NG file options."""

    #: Option value.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', data: 'bytes') -> 'None': ...


@schema_final
class EndOfOption(_OPT_Option, code=Enum_OptionType.opt_endofopt):
    """Header schema for PCAP-NG file ``opt_endofopt`` options."""

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int') -> 'None': ...


@schema_final
class CommentOption(_OPT_Option, code=Enum_OptionType.opt_comment):
    """Header schema for PCAP-NG file ``opt_comment`` options."""

    #: Comment text.
    comment: 'str' = StringField(length=lambda pkt: pkt['length'], encoding='utf-8')
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', comment: 'str') -> 'None': ...


@schema_final
class CustomOption(_OPT_Option, code=[Enum_OptionType.opt_custom_2988,
                                      Enum_OptionType.opt_custom_2989,
                                      Enum_OptionType.opt_custom_19372,
                                      Enum_OptionType.opt_custom_19373]):
    """Header schema for PCAP-NG file ``opt_custom`` options."""

    #: Private enterprise number (PEN).
    pen: 'int' = UInt32Field(callback=byteorder_callback)
    #: Custom data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 4)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'int', length: 'int', pen: 'int', data: 'bytes') -> 'None': ...


@schema_final
class SectionHeaderBlock(BlockType, code=Enum_BlockType.Section_Header_Block):
    """Header schema for PCAP-NG Section Header Block (SHB)."""

    #: Fast forward field to test the byteorder.
    match: 'ByteorderTest' = ForwardMatchField(BitField(length=8, namespace={
        'byteorder': (32, 32),
    }))
    #: Block total length.
    length: 'int' = UInt32Field(callback=shb_byteorder_callback)
    #: Byte order magic number.
    magic: 'Literal[0x1A2B3C4D]' = UInt32Field(callback=shb_byteorder_callback)
    #: Major version number.
    major: 'int' = UInt16Field(callback=shb_byteorder_callback, default=1)
    #: Minor version number.
    minor: 'int' = UInt16Field(callback=shb_byteorder_callback, default=0)
    #: Section length.
    section_length: 'int' = Int64Field(callback=shb_byteorder_callback, default=0xFFFF_FFFF_FFFF_FFFF)
    #: Options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['length'] - 28,
        base_schema=_OPT_Option,
        type_name='type',
        registry=Option.registry['opt'],
        eool=Enum_OptionType.opt_endofopt,
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: pkt['__option_padding__'])
    #: Block total length.
    length2: 'int' = UInt32Field(callback=shb_byteorder_callback)

    def pre_pack(self, packet: 'dict[str, Any]') -> 'None':
        """Prepare ``packet`` data for packing process.

        Args:
            packet: packet data

        Note:
            This method is expected to directly modify any data stored
            in the ``packet`` and thus no return is required.

        """
        if 'match' in packet:
            return

        packet['match'] = {
            'byteorder': 0x1A2B3C4D if sys.byteorder == 'big' else 0x4D3C2B1A,
        }

    def post_process(self, packet: 'dict[str, Any]') -> 'SectionHeaderBlock':
        """Revise ``schema`` data after unpacking process.

        This method calculate the byteorder value based on
        the parsed schema.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        self = cast('Self', super().post_process(packet))

        if self.section_length == 0xFFFF_FFFF_FFFF_FFFF:
            self.section_length = -1

        magic = packet['match']['byteorder']  # type: int
        if magic == 0x1A2B3C4D:
            self.byteorder = 'big'
        elif magic == 0x4D3C2B1A:
            self.byteorder = 'little'
        else:
            raise ProtocolError(f'unknown byteorder magic: {magic:#x}')
        return self

    if TYPE_CHECKING:
        #: Byteorder.
        byteorder: Literal['big', 'little']

        def __init__(self, length: 'int', magic: 'Literal[0x1A2B3C4D]', major: 'int',
                     minor: 'int', section_length: 'int', options: 'list[Option | bytes] | bytes',
                     length2: 'int') -> 'None': ...


class _IF_Option(Option, namespace='if'):
    """Header schema for ``if_*`` options."""

    #: Option type.
    type: 'Enum_OptionType' = OptionEnumField(length=2, namespace='if', callback=byteorder_callback)
    #: Option data length.
    length: 'int' = UInt16Field(callback=byteorder_callback)


@schema_final
class IF_NameOption(_IF_Option, code=Enum_OptionType.if_name):
    """Header schema for PCAP-NG file ``if_name`` options."""

    #: Interface name.
    name: 'str' = StringField(length=lambda pkt: pkt['length'], encoding='utf-8')
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', name: 'str') -> 'None': ...


@schema_final
class IF_DescriptionOption(_IF_Option, code=Enum_OptionType.if_description):
    """Header schema for PCAP-NG file ``if_description`` options."""

    #: Interface description.
    description: 'str' = StringField(length=lambda pkt: pkt['length'], encoding='utf-8')
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', description: 'str') -> 'None': ...


@schema_final
class IF_IPv4AddrOption(_IF_Option, code=Enum_OptionType.if_IPv4addr):
    """Header schema for PCAP-NG file ``if_IPv4addr`` options."""

    #: IPv4 interface.
    interface: 'IPv4Interface' = IPv4InterfaceField()
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', interface: 'IPv4Interface | str') -> 'None': ...


@schema_final
class IF_IPv6AddrOption(_IF_Option, code=Enum_OptionType.if_IPv6addr):
    """Header schema for PCAP-NG file ``if_IPv6addr`` options."""

    #: IPv6 interface.
    interface: 'IPv6Interface' = IPv6InterfaceField()
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', interface: 'IPv6Interface | str') -> 'None': ...


@schema_final
class IF_MACAddrOption(_IF_Option, code=Enum_OptionType.if_MACaddr):
    """Header schema for PCAP-NG file ``if_MACaddr`` options."""

    #: MAC interface.
    interface: 'bytes' = BytesField(length=6)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', interface: 'bytes') -> 'None': ...


@schema_final
class IF_EUIAddrOption(_IF_Option, code=Enum_OptionType.if_EUIaddr):
    """Header schema for PCAP-NG file ``if_EUIaddr`` options."""

    #: EUI interface.
    interface: 'bytes' = BytesField(length=8)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', interface: 'bytes') -> 'None': ...


@schema_final
class IF_SpeedOption(_IF_Option, code=Enum_OptionType.if_speed):
    """Header schema for PCAP-NG file ``if_speed`` options."""

    #: Interface speed, in bits per second.
    speed: 'int' = UInt64Field(callback=byteorder_callback)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', speed: 'int') -> 'None': ...


@schema_final
class IF_TSResolOption(_IF_Option, code=Enum_OptionType.if_tsresol):
    """Header schema for PCAP-NG file ``if_tsresol`` options."""

    #: Interface timestamp resolution, in units per second.
    tsresol: 'ResolutionData' = BitField(length=1, namespace={
        'flag': (0, 1),
        'resolution': (1, 7),
    })
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    def post_process(self, packet: 'dict[str, Any]') -> 'IF_TSResolOption':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        base = 10 if self.tsresol['flag'] == 0 else 2
        self.resolution = base ** self.tsresol['resolution']
        return self

    if TYPE_CHECKING:
        #: Interface timestamp resolution, in units per second.
        resolution: 'int'

        def __init__(self, type: 'Enum_OptionType', length: 'int', tsresol: 'ResolutionData') -> 'None': ...


@schema_final
class IF_TZoneOption(_IF_Option, code=Enum_OptionType.if_tzone):
    """Header schema for PCAP-NG file ``if_tzone`` options."""

    #: Interface time zone (as in seconds difference from GMT).
    tzone: 'int' = Int32Field(callback=byteorder_callback)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', tzone: 'int') -> 'None': ...


@schema_final
class IF_FilterOption(_IF_Option, code=Enum_OptionType.if_filter):
    """Header schema for PCAP-NG file ``if_filter`` options."""

    #: Filter code.
    code: 'Enum_FilterType' = EnumField(length=1, namespace=Enum_FilterType, callback=byteorder_callback)
    #: Capture filter.
    filter: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 1)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', code: 'Enum_FilterType', filter: 'bytes') -> 'None': ...


@schema_final
class IF_OSOption(_IF_Option, code=Enum_OptionType.if_os):
    """Header schema for PCAP-NG file ``if_os`` options."""

    #: OS information.
    os: 'str' = StringField(length=lambda pkt: pkt['length'], encoding='utf-8')
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', os: 'str') -> 'None': ...


@schema_final
class IF_FCSLenOption(_IF_Option, code=Enum_OptionType.if_fcslen):
    """Header schema for PCAP-NG file ``if_fcslen`` options."""

    #: FCS length.
    fcslen: 'int' = UInt8Field(callback=byteorder_callback)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', fcslen: 'int') -> 'None': ...


@schema_final
class IF_TSOffsetOption(_IF_Option, code=Enum_OptionType.if_tsoffset):
    """Header schema for PCAP-NG file ``if_tsoffset`` options."""

    #: Timestamp offset (in seconds).
    tsoffset: 'int' = Int64Field(callback=byteorder_callback)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', tsoffset: 'int') -> 'None': ...


@schema_final
class IF_HardwareOption(_IF_Option, code=Enum_OptionType.if_hardware):
    """Header schema for PCAP-NG file ``if_hardware`` options."""

    #: Hardware information.
    hardware: 'str' = StringField(length=lambda pkt: pkt['length'], encoding='utf-8')
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', hardware: 'str') -> 'None': ...


@schema_final
class IF_TxSpeedOption(_IF_Option, code=Enum_OptionType.if_txspeed):
    """Header schema for PCAP-NG file ``if_txspeed`` options."""

    #: Interface transmit speed, in bits per second.
    tx_speed: 'int' = UInt64Field(callback=byteorder_callback)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', tx_speed: 'int') -> 'None': ...


@schema_final
class IF_RxSpeedOption(_IF_Option, code=Enum_OptionType.if_rxspeed):
    """Header schema for PCAP-NG file ``if_rxspeed`` options."""

    #: Interface receive speed, in bits per second.
    rx_speed: 'int' = UInt64Field(callback=byteorder_callback)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', rx_speed: 'int') -> 'None': ...


@schema_final
class InterfaceDescriptionBlock(BlockType, code=Enum_BlockType.Interface_Description_Block):
    """Header schema for PCAP-NG Interface Description Block (IDB)."""

    #: Block total length.
    length: 'int' = UInt32Field(callback=byteorder_callback)
    #: Link type.
    linktype: 'Enum_LinkType' = EnumField(length=2, namespace=Enum_LinkType, callback=byteorder_callback)
    #: Reserved.
    reserved: 'bytes' = PaddingField(length=2)
    #: Snap length.
    snaplen: 'int' = UInt32Field(default=0, callback=byteorder_callback)
    #: Options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['length'] - 20,
        base_schema=_IF_Option,
        type_name='type',
        registry=Option.registry['if'],
        eool=Enum_OptionType.opt_endofopt,
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: pkt['__option_padding__'])
    #: Block total length.
    length2: 'int' = UInt32Field(callback=byteorder_callback)

    if TYPE_CHECKING:
        def __init__(self, length: 'int', linktype: 'int', snaplen: 'int',
                     options: 'list[Option | bytes] | bytes', length2: 'int') -> 'None': ...


class _EPB_Option(Option, namespace='epb'):
    """Header schema for ``epb_*`` options."""

    #: Option type.
    type: 'Enum_OptionType' = OptionEnumField(length=2, namespace='epb', callback=byteorder_callback)
    #: Option data length.
    length: 'int' = UInt16Field(callback=byteorder_callback)


@schema_final
class EPB_FlagsOption(_EPB_Option, code=Enum_OptionType.epb_flags):
    """Header schema for PCAP-NG ``epb_flags`` options."""

    #: Flags.
    flags: 'EPBFlags' = BitField(length=4, namespace={
        'direction': (0, 2),
        'reception': (2, 3),
        'fcs_len': (5, 4),
        'crc_error': (24, 1),
        'too_long': (25, 1),
        'too_short': (26, 1),
        'gap_error': (27, 1),
        'unaligned_error': (28, 1),
        'delimiter_error': (29, 1),
        'preamble_error': (30, 1),
        'symbol_error': (31, 1),
    })
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', flags: 'EPBFlags') -> 'None': ...


@schema_final
class EPB_HashOption(_EPB_Option, code=Enum_OptionType.epb_hash):
    """Header schema for PCAP-NG ``epb_hash`` options."""

    #: Hash algorithm.
    func: 'Enum_HashAlgorithm' = EnumField(length=1, namespace=Enum_HashAlgorithm, callback=byteorder_callback)
    #: Hash value.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 1)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', func: 'Enum_HashAlgorithm', data: 'bytes') -> 'None': ...


@schema_final
class EPB_DropCountOption(_EPB_Option, code=Enum_OptionType.epb_dropcount):
    """Header schema for PCAP-NG ``epb_dropcount`` options."""

    #: Number of packets dropped by the interface.
    drop_count: 'int' = UInt64Field(callback=byteorder_callback)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', drop_count: 'int') -> 'None': ...


@schema_final
class EPB_PacketIDOption(_EPB_Option, code=Enum_OptionType.epb_packetid):
    """Header schema for PCAP-NG ``epb_packetid`` options."""

    #: Packet ID.
    packet_id: 'int' = UInt64Field(callback=byteorder_callback)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', packet_id: 'int') -> 'None': ...


@schema_final
class EPB_QueueOption(_EPB_Option, code=Enum_OptionType.epb_queue):
    """Header schema for PCAP-NG ``epb_queue`` options."""

    #: Queue ID.
    queue_id: 'int' = UInt32Field(callback=byteorder_callback)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', queue_id: 'int') -> 'None': ...


@schema_final
class EPB_VerdictOption(_EPB_Option, code=Enum_OptionType.epb_verdict):
    """Header schema for PCAP-NG ``epb_verdict`` options."""

    #: Verdict type.
    verdict: 'Enum_VerdictType' = EnumField(length=1, namespace=Enum_VerdictType, callback=byteorder_callback)
    #: Verdict value.
    value: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 1)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', verdict: 'Enum_VerdictType', value: 'bytes') -> 'None': ...


@schema_final
class EnhancedPacketBlock(BlockType, code=Enum_BlockType.Enhanced_Packet_Block):
    """Header schema for PCAP-NG Enhanced Packet Block (EPB)."""

    __payload__ = 'packet_data'

    #: Block total length.
    length: 'int' = UInt32Field(callback=byteorder_callback)
    #: Interface ID.
    interface_id: 'int' = UInt32Field(callback=byteorder_callback)
    #: Higher 32-bit of timestamp (in seconds).
    timestamp_high: 'int' = UInt32Field(callback=byteorder_callback)
    #: Lower 32-bit of timestamp (in seconds).
    timestamp_low: 'int' = UInt32Field(callback=byteorder_callback)
    #: Captured packet length.
    captured_len: 'int' = UInt32Field(callback=byteorder_callback)
    #: Original packet length.
    original_len: 'int' = UInt32Field(callback=byteorder_callback)
    #: Packet data.
    packet_data: 'bytes' = PayloadField(length=lambda pkt: pkt['captured_len'])
    #: Padding.
    padding_data: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['captured_len'] % 4) % 4)
    #: Options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['length'] - 32 - pkt['captured_len'] - len(pkt['padding_data']),
        base_schema=_EPB_Option,
        type_name='type',
        registry=Option.registry['epb'],
        eool=Enum_OptionType.opt_endofopt,
    )
    #: Padding.
    padding_opts: 'bytes' = PaddingField(length=lambda pkt: pkt['__option_padding__'])
    #: Block total length.
    length2: 'int' = UInt32Field(callback=byteorder_callback)

    if TYPE_CHECKING:
        def __init__(self, length: 'int', interface_id: 'int', timestamp_high: 'int',
                     timestamp_low: 'int', captured_len: 'int', original_len: 'int',
                     packet_data: 'bytes | Protocol | Schema',
                     options: 'list[Option | bytes] | bytes', length2: 'int') -> 'None': ...


@schema_final
class SimplePacketBlock(BlockType, code=Enum_BlockType.Simple_Packet_Block):
    """Header schema for PCAP-NG Simple Packet Block (SPB)."""

    __payload__ = 'packet_data'

    #: Block total length.
    length: 'int' = UInt32Field(callback=byteorder_callback)
    #: Original packet length.
    original_len: 'int' = UInt32Field(callback=byteorder_callback)
    #: Packet data.
    packet_data: 'bytes' = PayloadField(length=lambda pkt: min(pkt.get('snaplen', 0xFFFFFFFFFFFFFFFF),
                                                               pkt['original_len']))
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - len(pkt['packet_data']) % 4) % 4)
    #: Block total length.
    length2: 'int' = UInt32Field(callback=byteorder_callback)

    if TYPE_CHECKING:
        def __init__(self, length: 'int', original_len: 'int',
                     packet_data: 'bytes | Protocol | Schema',
                     length2: 'int') -> 'None': ...


class NameResolutionRecord(EnumSchema[Enum_RecordType]):
    """Header schema for PCAP-NG NRB records."""

    __default__ = lambda: UnknownRecord

    #: Record type.
    type: 'Enum_RecordType' = EnumField(length=2, namespace=Enum_RecordType, callback=byteorder_callback)
    #: Record value length.
    length: 'int' = UInt16Field(callback=byteorder_callback)


@schema_final
class UnknownRecord(NameResolutionRecord):
    """Header schema for PCAP-NG NRB unknown records."""

    #: Unknown record data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'])
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_RecordType', length: 'int', data: 'bytes') -> 'None': ...


@schema_final
class EndRecord(NameResolutionRecord, code=Enum_RecordType.nrb_record_end):
    """Header schema for PCAP-NG ``nrb_record_end`` records."""

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_RecordType', length: 'int') -> 'None': ...


@schema_final
class IPv4Record(NameResolutionRecord, code=Enum_RecordType.nrb_record_ipv4):
    """Header schema for PCAP-NG NRB ``nrb_record_ipv4`` records."""

    #: IPv4 address.
    ip: 'IPv4Address' = IPv4AddressField()
    #: Name resolution data.
    resol: 'str' = StringField(length=lambda pkt: pkt['length'] - 4)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        self.names = self.resol.rstrip('\x00').split('\x00')
        return self

    if TYPE_CHECKING:
        #: Name resolution records.
        names: 'list[str]'

        def __init__(self, type: 'Enum_RecordType', length: 'int', ip: 'IPv4Address | str | bytes | int', resol: 'str') -> 'None': ...


@schema_final
class IPv6Record(NameResolutionRecord, code=Enum_RecordType.nrb_record_ipv6):
    """Header schema for PCAP-NG NRB ``nrb_record_ipv4`` records."""

    #: IPv4 address.
    ip: 'IPv6Address' = IPv6AddressField()
    #: Name resolution data.
    resol: 'str' = StringField(length=lambda pkt: pkt['length'] - 4)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        self.names = self.resol.rstrip('\x00').split('\x00')
        return self

    if TYPE_CHECKING:
        #: Name resolution records.
        names: 'list[str]'

        def __init__(self, type: 'Enum_RecordType', length: 'int', ip: 'IPv6Address | str | bytes | int', resol: 'str') -> 'None': ...


class _NS_Option(Option, namespace='ns'):
    """Header schema for ``ns_*`` options."""

    #: Option type.
    type: 'Enum_OptionType' = OptionEnumField(length=2, namespace='ns', callback=byteorder_callback)
    #: Option data length.
    length: 'int' = UInt16Field(callback=byteorder_callback)


@schema_final
class NS_DNSNameOption(_NS_Option, code=Enum_OptionType.ns_dnsname):
    """Header schema for PCAP-NG ``ns_dnsname`` option."""

    #: DNS name.
    name: 'str' = StringField(length=lambda pkt: pkt['length'])

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', name: 'str') -> 'None': ...


@schema_final
class NS_DNSIP4AddrOption(_NS_Option, code=Enum_OptionType.ns_dnsIP4addr):
    """Header schema for PCAP-NG ``ns_dnsIP4addr`` option."""

    #: IPv4 address.
    ip: 'IPv4Address' = IPv4AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', ip: 'IPv4Address | str | bytes | int') -> 'None': ...


@schema_final
class NS_DNSIP6AddrOption(_NS_Option, code=Enum_OptionType.ns_dnsIP6addr):
    """Header schema for PCAP-NG ``ns_dnsIP6addr`` option."""

    #: IPv6 address.
    ip: 'IPv6Address' = IPv6AddressField()

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', ip: 'IPv6Address | bytes | str | int') -> 'None': ...


@schema_final
class NameResolutionBlock(BlockType, code=Enum_BlockType.Name_Resolution_Block):
    """Header schema for PCAP-NG Name Resolution Block (NRB)."""

    #: Record total length.
    length: 'int' = UInt32Field(callback=byteorder_callback)
    #: Name resolution records.
    records: 'list[NameResolutionRecord]' = OptionField(
        length=lambda pkt: pkt['length'] - 12,
        base_schema=NameResolutionRecord,
        type_name='type',
        registry=NameResolutionRecord.registry,
        eool=Enum_RecordType.nrb_record_end,
    )
    #: Options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['__option_padding__'] - 4 if pkt['__option_padding__'] else 0,
        base_schema=_NS_Option,
        type_name='type',
        registry=Option.registry['ns'],
        eool=Enum_OptionType.opt_endofopt,
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: pkt['__option_padding__'])
    #: Block total length.
    length2: 'int' = UInt32Field(callback=byteorder_callback)

    def post_process(self, packet: 'dict[str, Any]') -> 'Self':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        self = cast('Self', super().post_process(packet))

        mapping = MultiDict()  # type: MultiDict[IPv4Address | IPv6Address, str]
        reverse_mapping = MultiDict()  # type: MultiDict[str, IPv4Address | IPv6Address]

        for record in self.records:
            if isinstance(record, (IPv4Record, IPv6Record)):
                for name in record.names:
                    mapping.add(record.ip, name)
                    reverse_mapping.add(name, record.ip)

        self.mapping = mapping
        self.reverse_mapping = reverse_mapping
        return self

    if TYPE_CHECKING:
        #: Name resolution mapping (IP address -> name).
        mapping: 'MultiDict[IPv4Address | IPv6Address, str]'
        #: Name resolution mapping (name -> IP address).
        reverse_mapping: 'MultiDict[str, IPv4Address | IPv6Address]'

        def __init__(self, length: 'int',
                     records: 'list[NameResolutionRecord | bytes] | bytes',
                     options: 'list[Option | bytes] | bytes', length2: 'int') -> 'None': ...


class _ISB_Option(Option, namespace='isb'):
    """Header schema for ``isb_*`` options."""

    #: Option type.
    type: 'Enum_OptionType' = OptionEnumField(length=2, namespace='isb', callback=byteorder_callback)
    #: Option data length.
    length: 'int' = UInt16Field(callback=byteorder_callback)


@schema_final
class ISB_StartTimeOption(_ISB_Option, code=Enum_OptionType.isb_starttime):
    """Header schema for PCAP-NG ``isb_starttime`` option."""

    #: Timestamp (higher 32 bits).
    timestamp_high: 'int' = UInt32Field(callback=byteorder_callback)
    #: Timestamp (lower 32 bits).
    timestamp_low: 'int' = UInt32Field(callback=byteorder_callback)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', timestamp_high: 'int', timestamp_low: 'int') -> 'None': ...


@schema_final
class ISB_EndTimeOption(_ISB_Option, code=Enum_OptionType.isb_endtime):
    """Header schema for PCAP-NG ``isb_endtime`` option."""

    #: Timestamp (higher 32 bits).
    timestamp_high: 'int' = UInt32Field(callback=byteorder_callback)
    #: Timestamp (lower 32 bits).
    timestamp_low: 'int' = UInt32Field(callback=byteorder_callback)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', timestamp_high: 'int', timestamp_low: 'int') -> 'None': ...


@schema_final
class ISB_IFRecvOption(_ISB_Option, code=Enum_OptionType.isb_ifrecv):
    """Header schema for PCAP-NG ``isb_ifrecv`` option."""

    #: Number of packets received.
    packets: 'int' = UInt64Field(callback=byteorder_callback)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', packets: 'int') -> 'None': ...


@schema_final
class ISB_IFDropOption(_ISB_Option, code=Enum_OptionType.isb_ifdrop):
    """Header schema for PCAP-NG ``isb_ifdrop`` option."""

    #: Number of packets dropped.
    packets: 'int' = UInt64Field(callback=byteorder_callback)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', packets: 'int') -> 'None': ...


@schema_final
class ISB_FilterAcceptOption(_ISB_Option, code=Enum_OptionType.isb_filteraccept):
    """Header schema for PCAP-NG ``isb_filteraccept`` option."""

    #: Number of packets accepted by filter.
    packets: 'int' = UInt64Field(callback=byteorder_callback)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', packets: 'int') -> 'None': ...


@schema_final
class ISB_OSDropOption(_ISB_Option, code=Enum_OptionType.isb_osdrop):
    """Header schema for PCAP-NG ``isb_osdrop`` option."""

    #: Number of packets dropped by OS.
    packets: 'int' = UInt64Field(callback=byteorder_callback)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', packets: 'int') -> 'None': ...


@schema_final
class ISB_UsrDelivOption(_ISB_Option, code=Enum_OptionType.isb_usrdeliv):
    """Header schema for PCAP-NG ``isb_usrdeliv`` option."""

    #: Number of packets delivered to user.
    packets: 'int' = UInt64Field(callback=byteorder_callback)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', packets: 'int') -> 'None': ...


@schema_final
class InterfaceStatisticsBlock(BlockType):
    """Header schema for PCAP-NG Interface Statistics Block (ISB)."""

    #: Block total length.
    length: 'int' = UInt32Field(callback=byteorder_callback)
    #: Interface ID.
    interface_id: 'int' = UInt32Field(callback=byteorder_callback)
    #: Timestamp (higher 32 bits).
    timestamp_high: 'int' = UInt32Field(callback=byteorder_callback)
    #: Timestamp (lower 32 bits).
    timestamp_low: 'int' = UInt32Field(callback=byteorder_callback)
    #: Options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['length'] - 20,
        base_schema=_ISB_Option,
        type_name='type',
        registry=Option.registry['isb'],
        eool=Enum_OptionType.opt_endofopt,
    )
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: pkt['__option_padding__'])
    #: Block total length.
    length2: 'int' = UInt32Field(callback=byteorder_callback)

    if TYPE_CHECKING:
        def __init__(self, length: 'int', interface_id: 'int',
                     timestamp_high: 'int', timestamp_low: 'int',
                     options: 'list[Option | bytes] | bytes', length2: 'int') -> 'None': ...


@schema_final
class SystemdJournalExportBlock(BlockType, code=Enum_BlockType.systemd_Journal_Export_Block):
    """Header schema for PCAP-NG :manpage:`systemd(1)` Journal Export Block."""

    #: Block total length.
    length: 'int' = UInt32Field(callback=byteorder_callback)
    #: Journal entry.
    entry: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 12)
    #: Block total length.
    length2: 'int' = UInt32Field(callback=byteorder_callback)

    def post_process(self, packet: 'dict[str, Any]') -> 'Self':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        self = cast('Self', super().post_process(packet))

        data = []  # type: list[OrderedMultiDict[str, str | bytes]]
        for entry_buffer in self.entry.split(b'\n\n'):
            entry = OrderedMultiDict()  # type: OrderedMultiDict[str, str | bytes]

            entry_data = io.BytesIO(entry_buffer)
            while True:
                line = entry_data.readline().strip()
                if not line:
                    break

                line_split = line.split(b'=', maxsplit=1)
                if len(line_split) == 2:
                    key, value = line_split
                    entry.add(key.decode('utf-8'), value.decode('utf-8'))
                else:
                    length = struct.unpack('<Q', entry_data.read(4))[0]  # type: int
                    entry.add(line.decode('utf-8'), entry_data.read(length))
                    entry_data.read()  # Skip trailing newline.

            data.append(entry)
        self.data = data
        return self

    if TYPE_CHECKING:
        #: Journal entry (decoded).
        data: 'list[OrderedMultiDict[str, str | bytes]]'

        def __init__(self, length: 'int', entry: 'bytes', length2: 'int') -> 'None': ...


class DSBSecrets(EnumSchema[Enum_SecretsType]):
    """Header schema for DSB secrets data."""

    __default__ = lambda: UnknownSecrets


@schema_final
class UnknownSecrets(DSBSecrets):
    """Header schema for unknown DSB secrets data."""

    #: Secrets data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, data: 'bytes') -> 'None': ...


@schema_final
class TLSKeyLog(DSBSecrets, code=Enum_SecretsType.TLS_Key_Log):
    """Header schema for TLS Key Log secrets data."""

    #: TLS key log data.
    data: 'str' = StringField(length=lambda pkt: pkt['__length__'], encoding='ascii')

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        from pcapkit.protocols.misc.pcapng import TLSKeyLabel

        entries = collections.defaultdict(OrderedMultiDict)  # type: dict[TLSKeyLabel, OrderedMultiDict[bytes, bytes]]
        for line in self.data.splitlines():
            if not line or line.startswith('#'):
                continue

            label, random, secret = line.strip().split()
            label_enum = TLSKeyLabel(label.upper())
            entries[label_enum].add(bytes.fromhex(random),
                                    bytes.fromhex(secret))

        self.entries = entries
        return self

    if TYPE_CHECKING:
        #: TLS Key Log entries.
        entries: 'dict[TLSKeyLabel, OrderedMultiDict[bytes, bytes]]'

        def __init__(self, data: 'str') -> 'None': ...


@schema_final
class WireGuardKeyLog(DSBSecrets, code=Enum_SecretsType.WireGuard_Key_Log):
    """Header schema for WireGuard Key Log secrets data."""

    #: WireGuard key log data.
    data: 'str' = StringField(length=lambda pkt: pkt['__length__'], encoding='ascii')

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        from pcapkit.protocols.misc.pcapng import WireGuardKeyLabel

        entries = OrderedMultiDict()  # type: OrderedMultiDict[WireGuardKeyLabel, bytes]
        for line in self.data.splitlines():
            if not line or line.startswith('#'):
                continue

            label, op, secret = line.strip().split()
            if op != '=':
                raise FieldValueError('invalid WireGuard key log format: {line!r}')
            label_enum = WireGuardKeyLabel(label.upper())
            entries.add(label_enum, base64.b64decode(secret))

        self.entries = entries
        return self

    if TYPE_CHECKING:
        #: WireGuard Key Log entries.
        entries: 'OrderedMultiDict[WireGuardKeyLabel, bytes]'

        def __init__(self, data: 'str') -> 'None': ...


@schema_final
class ZigBeeNWKKey(DSBSecrets, code=Enum_SecretsType.ZigBee_NWK_Key):
    """Header schema for ZigBee NWK Key and ZigBee PANID secrets data."""

    #: AES-128 NKW key.
    key: 'bytes' = BytesField(length=16)
    #: ZigBee PANID.
    panid: 'int' = UInt16Field(byteorder='little')
    #: Padding.
    padding: 'bytes' = BytesField(length=2)

    if TYPE_CHECKING:
        def __init__(self, key: 'bytes', panid: 'int') -> 'None': ...


@schema_final
class ZigBeeAPSKey(DSBSecrets, code=Enum_SecretsType.ZigBee_APS_Key):
    """Header schema for ZigBee APS Key secrets data."""

    #: AES-128 APS key.
    key: 'bytes' = BytesField(length=16)
    #: ZigBee PANID.
    panid: 'int' = UInt16Field(byteorder='little')
    #: Low node short address.
    addr_low: 'int' = UInt16Field(byteorder='little')
    #: High node short address.
    addr_high: 'int' = UInt16Field(byteorder='little')
    #: Padding.
    padding: 'bytes' = BytesField(length=2)

    if TYPE_CHECKING:
        def __init__(self, key: 'bytes', panid: 'int', addr_low: 'int', addr_high: 'int') -> 'None': ...


class _DSB_Option(Option, namespace='dsb'):
    """Header schema for ``dsb_*`` options."""

    #: Option type.
    type: 'Enum_OptionType' = OptionEnumField(length=2, namespace='dsb', callback=byteorder_callback)
    #: Option data length.
    length: 'int' = UInt16Field(callback=byteorder_callback)


@schema_final
class DecryptionSecretsBlock(BlockType, code=Enum_BlockType.Decryption_Secrets_Block):
    """Header schema for PCAP-NG Decryption Secrets Block (DSB)."""

    #: Block total length.
    length: 'int' = UInt32Field(callback=byteorder_callback)
    #: Secrets type.
    secrets_type: 'Enum_SecretsType' = EnumField(length=4, namespace=Enum_SecretsType, callback=byteorder_callback)
    #: Secrets length.
    secrets_length: 'int' = UInt32Field(callback=byteorder_callback)
    #: Secrets data.
    secrets_data: 'DSBSecrets' = SwitchField(
        selector=dsb_secrets_selector,
    )
    #: Padding.
    padding_data: 'bytes' = BytesField(length=lambda pkt: (4 - pkt['secrets_length'] % 4) % 4)
    #: Options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['length'] - 20 - pkt['secrets_length'] - len(pkt['padding_data']),
        base_schema=_DSB_Option,
        type_name='type',
        registry=Option.registry['dsb'],
        eool=Enum_OptionType.opt_endofopt,
    )
    #: Padding.
    padding_opts: 'bytes' = PaddingField(length=lambda pkt: pkt['__option_padding__'])
    #: Block total length.
    length2: 'int' = UInt32Field(callback=byteorder_callback)

    if TYPE_CHECKING:
        def __init__(self, length: 'int', secrets_type: 'Enum_SecretsType',
                     secrets_length: 'int', secrets_data: 'DSBSecrets | bytes',
                     options: 'list[Option | bytes] | bytes', length2: 'int') -> 'None': ...


@schema_final
class CustomBlock(BlockType, code=[Enum_BlockType.Custom_Block_that_rewriters_can_copy_into_new_files,
                                   Enum_BlockType.Custom_Block_that_rewriters_should_not_copy_into_new_files]):
    """Header schema for PCAP-NG Custom Block (CB)."""

    #: Block total length.
    length: 'int' = UInt32Field(callback=byteorder_callback)
    #: Private enterprise number.
    pen: 'int' = UInt32Field(callback=byteorder_callback)
    #: Custom data.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 16)
    #: Padding.
    padding: 'bytes' = BytesField(length=lambda pkt: (4 - pkt['data'] % 4) % 4)
    #: Block total length.
    length2: 'int' = UInt32Field(callback=byteorder_callback)

    if TYPE_CHECKING:
        def __init__(self, length: 'int', pen: 'int', data: 'bytes', length2: 'int') -> 'None': ...


class _PACK_Option(Option, namespace='pack'):
    """Header schema for ``pack_*`` options."""

    #: Option type.
    type: 'Enum_OptionType' = OptionEnumField(length=2, namespace='pack', callback=byteorder_callback)
    #: Option data length.
    length: 'int' = UInt16Field(callback=byteorder_callback)


@schema_final
class PACK_FlagsOption(_PACK_Option, code=Enum_OptionType.pack_flags):
    """Header schema for PCAP-NG ``pack_flags`` options."""

    #: Flags.
    flags: 'PACKFlags' = BitField(length=4, namespace={
        'direction': (0, 2),
        'reception': (2, 3),
        'fcs_len': (5, 4),
        'crc_error': (24, 1),
        'too_long': (25, 1),
        'too_short': (26, 1),
        'gap_error': (27, 1),
        'unaligned_error': (28, 1),
        'delimiter_error': (29, 1),
        'preamble_error': (30, 1),
        'symbol_error': (31, 1),
    })
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', flags: 'EPBFlags') -> 'None': ...


@schema_final
class PACK_HashOption(_PACK_Option, code=Enum_OptionType.pack_hash):
    """Header schema for PCAP-NG ``pack_hash`` options."""

    #: Hash algorithm.
    func: 'Enum_HashAlgorithm' = EnumField(length=1, namespace=Enum_HashAlgorithm, callback=byteorder_callback)
    #: Hash value.
    data: 'bytes' = BytesField(length=lambda pkt: pkt['length'] - 1)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', func: 'Enum_HashAlgorithm', data: 'bytes') -> 'None': ...


@schema_final
class PacketBlock(BlockType, code=Enum_BlockType.Packet_Block):
    """Header schema for PCAP-NG Packet Block (obsolete)."""

    __payload__ = 'packet_data'

    #: Block total length.
    length: 'int' = UInt32Field(callback=byteorder_callback)
    #: Interface ID.
    interface_id: 'int' = UInt32Field(callback=byteorder_callback)
    #: Drops count.
    drop_count: 'int' = UInt32Field(callback=byteorder_callback, default=0xFFFF)
    #: Timestamp (high).
    timestamp_high: 'int' = UInt32Field(callback=byteorder_callback)
    #: Timestamp (low).
    timestamp_low: 'int' = UInt32Field(callback=byteorder_callback)
    #: Captured packet length.
    captured_length: 'int' = UInt32Field(callback=byteorder_callback)
    #: Original packet length.
    original_length: 'int' = UInt32Field(callback=byteorder_callback)
    #: Packet data.
    packet_data: 'bytes' = PayloadField(length=lambda pkt: pkt['captured_length'])
    #: Padding.
    padding_data: 'bytes' = BytesField(length=lambda pkt: (4 - pkt['captured_length'] % 4) % 4)
    #: Options.
    options: 'list[Option]' = OptionField(
        length=lambda pkt: pkt['length'] - 32 - pkt['captured_length'] - len(pkt['padding_data']),
        base_schema=_PACK_Option,
        type_name='type',
        registry=Option.registry['pack'],
        eool=Enum_OptionType.opt_endofopt,
    )
    #: Padding.
    padding_opts: 'bytes' = PaddingField(length=lambda pkt: pkt['__option_padding__'])
    #: Block total length.
    length2: 'int' = UInt32Field(callback=byteorder_callback)

    if TYPE_CHECKING:
        def __init__(self, length: 'int', interface_id: 'int', drop_count: 'int',
                     timestamp_high: 'int', timestamp_low: 'int', captured_length: 'int',
                     original_length: 'int', packet_data: 'bytes | Protocol | Schema',
                     options: 'list[Option | bytes] | bytes', length2: 'int') -> 'None': ...
