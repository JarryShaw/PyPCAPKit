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
from pcapkit.corekit.fields.strings import (BitField, BytesField, DecodedString, PaddingField,
                                            StringField)
from pcapkit.corekit.multidict import MultiDict, OrderedMultiDict
from pcapkit.protocols.schema.schema import EnumSchema, Schema, schema_final
from pcapkit.utilities.exceptions import FieldValueError, ProtocolError, stacklevel
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING
from pcapkit.utilities.warnings import ProtocolWarning, RegistryWarning, SchemaWarning, warn

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
    from typing import IO, Any, Callable, DefaultDict, Iterable, Optional, Type

    from typing_extensions import Literal, Self

    from pcapkit.corekit.fields.field import FieldBase as Field
    from pcapkit.protocols.misc.pcapng import TLSKeyLabel, WireGuardKeyLabel
    from pcapkit.protocols.protocol import ProtocolBase

if SPHINX_TYPE_CHECKING:  # pragma: no cover
    from typing_extensions import TypedDict

    class ByteorderTest(TypedDict):
        """Test for byteorder."""

        #: Byteorder magic number.
        byteorder: int

    class ResolutionData(TypedDict):
        """Data for resolution."""

        #: Resolution type flag (``0`` for 10-based, ``1`` for 2-based).
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
        #: Checksum not ready (bit 9).
        checksum_not_ready: int
        #: Checksum valid (bit 10).
        checksum_valid: int
        #: TCP segmentation offloaded (bit 11).
        tcp_segmentation_offloaded: int
        #: Bits 12 to 23, kept verbatim (reserved bits and unnamed
        #: link-layer-dependent errors).
        reserved: int
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
        #: Checksum not ready (bit 9).
        checksum_not_ready: int
        #: Checksum valid (bit 10).
        checksum_valid: int
        #: TCP segmentation offloaded (bit 11).
        tcp_segmentation_offloaded: int
        #: Bits 12 to 23, kept verbatim (reserved bits and unnamed
        #: link-layer-dependent errors).
        reserved: int
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


def packet_byteorder(packet: 'dict[str, Any]') -> 'Literal["big", "little"]':
    """Byte order declared for the section that ``packet`` belongs to.

    A nested schema is handed its parent's packet data under a ``__packet__``
    key (see :meth:`SchemaField.pack
    <pcapkit.corekit.fields.misc.SchemaField.pack>`), so the section byte order
    may live one level up.

    Args:
        packet: Packet data.

    Returns:
        Byte order of the enclosing section, falling back to the host byte
        order when the packet data declares none.

    """
    if 'byteorder' not in packet and '__packet__' in packet:
        return packet['__packet__'].get('byteorder', sys.byteorder)
    return packet.get('byteorder', sys.byteorder)


def byteorder_callback(field: 'NumberField', packet: 'dict[str, Any]') -> 'None':
    """Update byte order of PCAP-NG file.

    Args:
        field: Field instance.
        packet: Packet data.

    """
    field._byteorder = packet_byteorder(packet)


def shb_byteorder_callback(field: 'NumberField', packet: 'dict[str, Any]') -> 'None':
    """Update byte order of PCAP-NG file for SHB.

    A Section Header Block declares the byte order of its own section through
    its Byte-Order Magic, so it cannot take one from the enclosing packet data:
    the first SHB of a file has no section context by construction, and a later
    one would otherwise inherit the *previous* section's byte order. The magic
    is therefore also written back as ``packet['byteorder']``, which is what the
    SHB's own options -- read by :func:`byteorder_callback`, after this field --
    resolve their byte order from.

    A Section Header Block of 12 octets has no room for the magic, and its
    place holds the trailing Block Total Length instead. That length is 12 in
    exactly one byte order, which is the one taken; :meth:`SectionHeaderBlock.post_process`
    then rejects any block that matched this way with a length other than 12
    (:issue:`1422`).

    Args:
        field: Field instance.
        packet: Packet data.

    """
    magic = packet['match']['byteorder']  # type: int
    if magic in (0x1A2B3C4D, 0x0000000C):
        field._byteorder = 'big'
    elif magic in (0x4D3C2B1A, 0x0C000000):
        field._byteorder = 'little'
    else:
        raise ProtocolError(f'unknown byteorder magic: {magic:#x}')
    packet['byteorder'] = field._byteorder


def nonnegative(length: 'Callable[[dict[str, Any]], int]') -> 'Callable[[dict[str, Any]], int]':
    """Floor a computed field length at zero.

    Args:
        length: Callback computing a field's length from the framing a block,
            option or record declares.

    Returns:
        A callback returning that length, never below zero.

    Every span in this module is a subtraction -- a block's own Block Total
    Length less its fixed fields, an option's declared length less the part of
    itself it describes, an option area's leftover -- and every operand of those
    subtractions is a wire field that a malformed or truncated capture is free to
    set to anything. Nothing else makes the difference non-negative, and the field
    layer does not either: :meth:`_TextField.__call__
    <pcapkit.corekit.fields.strings._TextField.__call__>` builds its
    :mod:`struct` template as ``f'{length}s'`` unconditionally, so a negative
    length becomes the format ``'-8s'`` and :func:`struct.calcsize` raises a bare
    :exc:`struct.error`; a negative :class:`~pcapkit.corekit.fields.misc.SchemaField`
    length reaches :meth:`io.RawIOBase.read` and raises a bare :exc:`ValueError`.
    Neither is one of :mod:`pcapkit.utilities.exceptions`, so a caller cannot tell
    either from a bug in its own code, and neither is an :exc:`EOFError`, so
    neither is caught by the frame loop -- one malformed block would therefore
    cost the whole extraction.

    Two shapes reach here. A Block Total Length below the block's own fixed-field
    floor -- 28 octets for a Section Header Block, 20 for an Interface
    Description Block, 16 for a Custom Block -- makes the area negative directly.
    And ``__option_padding__``, which :meth:`OptionField.unpack
    <pcapkit.corekit.fields.collections.OptionField.unpack>` reports as the part
    of a declared area its options did not consume, goes negative when they
    consumed *more* than the area held: it subtracts each parsed option's real
    size from the area without checking that it fits. Both mean the same thing
    for a read -- there are no octets here -- and zero says that, where a
    negative says something :mod:`struct` cannot express.

    Flooring rather than refusing is the choice :func:`bounded_area` makes too:
    a block read has no catch point above :meth:`FieldBase.unpack
    <pcapkit.corekit.fields.field.FieldBase.unpack>`, so one refusal aborts the
    whole extraction rather than one block, so a capture cut short by its
    snapshot length must keep parsing. The end of the file is the one case that is *not* a floor, since
    there no block is being read at all -- see :meth:`PCAPNG._check_block_floor
    <pcapkit.protocols.misc.pcapng.PCAPNG._check_block_floor>`, which reports it
    as the :exc:`~pcapkit.utilities.exceptions.StreamEOFError` the frame loop
    catches.

    Note:
        Unlike :func:`bounded_option` this needs no ``__length__`` opt-out for
        the packing path, because it floors a *difference* rather than checking
        against the remaining area: a negative difference is not a legitimate
        thing to pack either -- ``struct.pack('-8s', ...)`` raises exactly as
        ``calcsize`` does -- where checking against the remainder would have
        refused a perfectly good option.

        That distinction is what keeps the three decryption-secrets payloads --
        :attr:`UnknownSecrets.data`, :attr:`TLSKeyLog.data` and
        :attr:`WireGuardKeyLog.data` -- out of this. They read ``__length__``
        *whole* rather than subtracting from it, and ``Schema.pack`` leaves it at
        ``-1`` for "unknown", so flooring them packs nothing at all. On the
        parsing path their
        ``__length__`` is the length the enclosing
        :class:`~pcapkit.corekit.fields.misc.SchemaField` declared from a 32-bit
        ``secrets_length``, which cannot be negative, so there is nothing there to
        floor.

    """
    def callback(pkt: 'dict[str, Any]') -> 'int':
        nominal = length(pkt)
        if nominal >= 0:
            return nominal

        warn(f'PCAP-NG: computed field length is negative ({nominal}); reading 0',
             SchemaWarning, stacklevel=stacklevel())
        return 0
    return callback


def bounded_option(length: 'Callable[[dict[str, Any]], int]') -> 'Callable[[dict[str, Any]], int]':
    """Refuse an option or record payload that runs past its area.

    Args:
        length: Callback computing the payload's nominal length, as the option's
            or record's own declared length field gives it.

    Returns:
        A callback returning that length.

    Raises:
        ProtocolError: If the payload declares more octets than the enclosing
            option or record area has left.

    An option's length is a 16-bit wire field, so one four-octet option header
    can declare 65,535 octets of payload. Read as declared, every shortfall
    would be zero-padded at the field layer, and the zeros rebuilt as if they
    had been captured (#594, #1325). So a payload that runs past the area is
    refused here instead. Inside a block, :class:`OptionAreaField` then keeps
    the whole option area as the octets captured, so the block still parses and
    rebuilds byte for byte.

    Note:
        The check is skipped when ``__length__`` is absent or negative, which is
        what :meth:`Schema.pack <pcapkit.protocols.schema.schema.Schema.pack>`
        leaves it as when no length is known. The nominal length still goes
        through :func:`nonnegative` first, on both paths, since an option
        declaring less payload than the part of itself it describes makes the
        subtraction negative.

    """
    floored = nonnegative(length)

    def callback(pkt: 'dict[str, Any]') -> 'int':
        nominal = floored(pkt)

        remaining = pkt.get('__length__')
        if not isinstance(remaining, int) or remaining < 0 or nominal <= remaining:
            return nominal

        raise ProtocolError(f'PCAP-NG: option declares {nominal} octet(s) of payload '
                            f'with {remaining} octet(s) left in its area')
    return callback


class OptionAreaField(OptionField):
    """Option list that keeps a malformed option area as the octets captured.

    An option in the area that runs past it, or past the data, raises
    :exc:`~pcapkit.utilities.exceptions.ProtocolError` from
    :meth:`OptionField.unpack <pcapkit.corekit.fields.collections.OptionField.unpack>`
    or :func:`bounded_option`. A block has no catch point above its fields, so
    raising would abort the whole extraction. This field instead returns the
    area as a single :obj:`bytes` item, which packs back verbatim, and reports
    no padding after it (#1325).

    """

    def unpack(self, buffer: 'bytes | IO[bytes]', packet: 'dict[str, Any]') -> 'list[Any]':
        """Unpack field value from :obj:`bytes`.

        Args:
            buffer: Field buffer.
            packet: Packet data.

        Returns:
            Unpacked field value, or the whole area as one :obj:`bytes` item if
            an option in it is malformed.

        """
        if isinstance(buffer, bytes):
            buffer = io.BytesIO(buffer)
        start = buffer.tell()
        try:
            return super().unpack(buffer, packet)
        except ProtocolError as error:
            buffer.seek(start, io.SEEK_SET)
            raw = buffer.read(max(self._length, 0))
            warn(f'PCAP-NG: {error}; option area of {len(raw)} octet(s) kept as captured',
                 ProtocolWarning, stacklevel=stacklevel())
            self._option_padding = 0
            return [raw]


def bounded_area(length: 'Callable[[dict[str, Any]], int]') -> 'Callable[[dict[str, Any]], int]':
    """Clamp a packet block's option area to the octets the block itself holds.

    Args:
        length: Callback computing the option area's nominal span, from the
            block's own declared Block Total Length.

    Returns:
        A callback returning that span, never past the octets left of the block.

    :func:`bounded_option` refuses a payload that runs past the area, and the
    area is sized from the block's declared Block Total Length. Nothing checks
    that length against the file: ``BlockType.post_process`` compares
    ``length`` only against its own trailing copy. A block declaring 1,000,000
    octets while holding 36 would therefore size its option area at 999,964,
    read the trailing Block Total Length into it, and leave that field to be
    zero-filled. Clamping the area to ``__length__`` keeps the trailing length
    out of the area, so the area holds exactly the octets the block was handed
    for it, whatever it declared.

    This is a no-op on every well-formed block rather than a second guess at the
    area. At the option field the only field still to come is the trailing Block
    Total Length, so ``__length__`` is exactly the area plus that field's four
    octets, and subtracting them makes the two equal. Taking ``__length__`` whole
    over-grants by exactly four, which is not academic: the area then reaches the
    trailing length itself and reads it as option payload, measured as four
    octets of payload on a block that holds none.

    Note:
        The five non-packet blocks' option areas -- Section Header, Interface
        Description, Name Resolution, Interface Statistics and Decryption
        Secrets -- are deliberately left unclamped *against the block* here,
        since each computes its span with a different offset and the equality
        above has to be re-established per block rather than assumed. They do go
        through :func:`nonnegative`, which stops a negative declared length
        reaching a read at all; the per-block equality is not enforced for them.

        The nominal span goes through :func:`nonnegative` first here too. That
        closes a hole in this function's own arithmetic: a ``captured_len`` past
        the end of the block makes the span negative, and ``nominal <= available``
        below is then *true*, so the negative would be returned unclamped and
        reach a :mod:`struct` template as ``f'{-N}s'``. Measured on 200 Enhanced Packet
        Blocks declaring ``captured_len`` ``0xFFFFFF`` in 8,048 octets.

    """
    floored = nonnegative(length)

    def callback(pkt: 'dict[str, Any]') -> 'int':
        nominal = floored(pkt)

        remaining = pkt.get('__length__')
        if not isinstance(remaining, int):
            return nominal

        # The trailing Block Total Length follows the option area in both packet
        # block types, so it is not the area's to read.
        available = remaining - 4
        if available < 0 or nominal <= available:
            return nominal

        warn(f'PCAP-NG: block declares an option area of {nominal} octet(s) with '
             f'{available} octet(s) left of the block; reading {available}',
             SchemaWarning, stacklevel=stacklevel())
        return available
    return callback


def captured_area(name: 'str') -> 'Callable[[dict[str, Any]], int]':
    """Bound a packet block's Packet Data to the octets the block holds.

    Args:
        name: Name of the block's captured length field, ``captured_len`` or
            ``captured_length``.

    Returns:
        A callback returning the captured length, never past the block's
        Block Total Length less its 32 framing octets, and never below zero.

    A captured length running past the block would otherwise read the trailing
    Block Total Length, and whatever follows the block, as packet data, so the
    rebuild could not be byte-exact. Bounded, the block keeps its declared
    captured length and exactly the octets it holds, and the padding and option
    area are sized from those octets rather than from the declared length
    (:issue:`1405`).

    """
    def callback(pkt: 'dict[str, Any]') -> 'int':
        return max(0, min(pkt[name], pkt['length'] - 32))
    return callback


def pcapng_block_selector(packet: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`PCAPNG.block` field.

    Args:
        packet: Packet data.

    Returns:
        Returns a :class:`~pcapkit.corekit.fields.misc.SchemaField`
        wrapped :class:`~pcapkit.protocols.schema.misc.pcapng.BlockType`
        subclass instance.

    See Also:
        * :class:`pcapkit.const.pcapng.block_type.BlockType`
        * :class:`pcapkit.protocols.schema.misc.pcapng.BlockType`

    Note:
        ``__length__`` is what is left of the *stream*, not what the block
        declares, and it is decremented by four for :attr:`PCAPNG.type` whether
        or not those four octets were there to read --
        :meth:`FieldBase.unpack <pcapkit.corekit.fields.field.FieldBase.unpack>`
        zero-pads a short read rather than refusing it. A tail of one, two or
        three octets therefore arrives here negative, and
        :meth:`io.RawIOBase.read` would raise a bare ``ValueError``. The floor is a
        backstop: :meth:`PCAPNG._check_block_floor
        <pcapkit.protocols.misc.pcapng.PCAPNG._check_block_floor>` reports that
        tail as end-of-stream before it gets here, and on the packing path
        :meth:`Schema.pack <pcapkit.protocols.schema.schema.Schema.pack>` seeds
        ``__length__`` as ``-1`` for "unknown", which
        :meth:`SchemaField.pack <pcapkit.corekit.fields.misc.SchemaField.pack>`
        does not read at all.

    """
    block_type = packet['type']  # type: Enum_BlockType
    schema = BlockType.registry[block_type]
    return SchemaField(length=max(packet['__length__'], 0), schema=schema)


def dsb_secrets_selector(packet: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`DecryptionSecretsBlock.secrets_data` field.

    Args:
        packet: Packet data.

    Returns:
        * If ``secrets_type`` is unknown, returns a
          :class:`~pcapkit.corekit.fields.strings.BytesField` instance.
        * If ``secret_type`` is :attr:`~pcapkit.const.pcapng.secrets_type.SecretsType.TLS_Key_Log`
          and/or :attr:`~pcapkit.const.pcapng.secrets_type.SecretsType.WireGuard_Key_Log`,
          returns a :class:`~pcapkit.corekit.fields.strings.StringField` instance.
        * Otherwise, returns a :class:`~pcapkit.corekit.fields.misc.SchemaField`
          wrapped :class:`~pcapkit.protocols.schema.misc.pcapng.DSBSecrets`
          subclass instance.

    See Also:
        * :class:`pcapkit.const.pcapng.secrets_type.SecretsType`
        * :class:`pcapkit.protocols.schema.misc.pcapng.DSBSecrets`

    """
    secrets_type = packet['secrets_type']  # type: int
    schema = DSBSecrets.registry[secrets_type]
    return SchemaField(length=packet['secrets_length'], schema=schema)


class FlagsField(UInt32Field):
    """32-bit flags word for protocol fields, with sub-fields numbered from the
    least-significant bit, as the ``epb_flags`` and ``pack_flags`` options number
    them.

    Unlike :class:`~pcapkit.corekit.fields.strings.BitField`, which numbers bits
    from the most-significant bit of the raw octets and ignores byte order, the
    word is read as an integer in the section's byte order first.

    Args:
        namespace: Field namespace (a dict mapping field name to a tuple of
            start bit, counted from the least-significant bit, and width).
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    """

    def __init__(self, namespace: 'dict[str, tuple[int, int]]',
                 callback: 'Callable[[Self, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        super().__init__(callback=callback)

        self._flags = namespace

    def pre_process(self, value: 'dict[str, int]', packet: 'dict[str, Any]') -> 'int | bytes':  # type: ignore[override]
        """Process field value before construction (packing).

        Arguments:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        Raises:
            FieldValueError: If a sub-field value does not fit its bits.

        """
        word = 0
        for name, (start, size) in self._flags.items():
            part = value[name]
            if not 0 <= part < 1 << size:
                raise FieldValueError(f'{type(self).__name__}: subfield {name!r} value {part!r} '
                                      f'does not fit in {size} bit(s)')
            word |= part << start
        return super().pre_process(word, packet)

    def post_process(self, value: 'int | bytes', packet: 'dict[str, Any]') -> 'dict[str, int]':  # type: ignore[override]
        """Process field value after parsing (unpacked).

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        """
        word = super().post_process(value, packet)
        return {name: word >> start & ((1 << size) - 1) for name, (start, size) in self._flags.items()}


#: Sub-fields of the ``epb_flags`` and ``pack_flags`` words. ``reserved`` keeps
#: bits 12 to 23 verbatim -- the reserved bits 12-15 and the link-layer-dependent
#: error bits 16-23 that the data model does not name.
PACKET_FLAGS = {
    'direction': (0, 2),
    'reception': (2, 3),
    'fcs_len': (5, 4),
    'checksum_not_ready': (9, 1),
    'checksum_valid': (10, 1),
    'tcp_segmentation_offloaded': (11, 1),
    'reserved': (12, 12),
    'crc_error': (24, 1),
    'too_long': (25, 1),
    'too_short': (26, 1),
    'gap_error': (27, 1),
    'unaligned_error': (28, 1),
    'delimiter_error': (29, 1),
    'preamble_error': (30, 1),
    'symbol_error': (31, 1),
}  # type: dict[str, tuple[int, int]]


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
            Processed field value -- the registry member declared for the
            option code in this namespace (or in the shared ``opt``
            namespace), or an unregistered member of the same registry,
            carrying the code itself, when neither declares one.

        Notes:
            This replicates the read-only membership test
            :meth:`~pcapkit.const.pcapng.option_type.OptionType.get` itself runs
            first, and calls it only once that test finds the code declared. An
            undeclared option type gets :meth:`EnumField._unregistered_member`
            instead of ``get()``'s own miss path, for pickle-safety: that method
            carries its own ``__reduce_ex__``, so a member built this way
            round-trips through :mod:`pickle` -- see its own docstring -- which
            :meth:`~pcapkit.const.pcapng.option_type.OptionType.
            _unregistered_member`'s override, the miss path, does not. The override's
            :attr:`~pcapkit.const.pcapng.option_type.OptionType._value_` is the
            *formatted* display string (``'opt_unknown [8888]'``, not ``8888``),
            so ``pickle.dumps`` on one succeeds but ``pickle.loads`` of the result
            raises ``ValueError``: the default reduction reconstructs through
            ``cls(self._value_)``, and ``_missing_``'s own int-only guard rejects
            that formatted string outright.

            The base :meth:`~pcapkit.corekit.enum.EnumRegistry._unregistered_member`
            that override replaces fails earlier, on ``repr()`` itself, since
            :attr:`~pcapkit.const.pcapng.option_type.OptionType.opt_name`/
            :attr:`~pcapkit.const.pcapng.option_type.OptionType.opt_value` are
            never set -- which is *why* the override exists, choosing to render
            correctly over round-tripping correctly.
            :meth:`EnumField._unregistered_member` is the only one of the three
            that gets both right. :func:`copy.deepcopy` is not the difference: it
            succeeds on both kinds, since the standard library's
            :class:`enum.Enum` (which :class:`aenum.Enum` subclasses) defines
            ``__copy__``/``__deepcopy__`` to return ``self`` outright, so
            deep-copying any member never reaches ``__reduce_ex__``.

        """
        value = super(EnumField, self).post_process(value, packet)
        namespace = self._opt_ns
        members_ns = self._namespace.__members_ns__
        if value not in members_ns.get('opt', {}) and value not in members_ns.get(namespace, {}):
            # NOTE: an unregistered member of self._namespace itself, per the
            # ruling in EnumField._unregistered_member. ``.opt_name`` and
            # ``.opt_value`` are what a real OptionType member carries --
            # read unconditionally by e.g. pcapng's own ``_option_key`` --
            # and ``<namespace>_unknown`` names an undeclared code. They are
            # passed in the order
            # OptionType.__new__ sets them, because DictDumper.object_hook
            # renders a member's addon keys straight out of its ``__dict__``
            # in insertion order, so any other order here would dump an
            # undeclared option code's keys the other way round from every
            # declared one's.
            opt_name = f'{namespace}_unknown'
            return self._unregistered_member(
                self._namespace, f'{opt_name} [{value:d}]',
                opt_name=opt_name, opt_value=value)
        return self._namespace.get(value, namespace=namespace)


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
    body: 'bytes' = BytesField(length=nonnegative(lambda pkt: pkt['length'] - 12))
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
                          ns: 'Optional[str]' = None, *args: 'Any', **kwargs: 'Any') -> 'None':
        """Register option type to :attr:`__enum__` mapping.

        Args:
            code: Option type code. It can be either a single option type enumeration
                or a list of option type enumerations.
            ns: Namespace of option type enumeration. If not given, the value
                will be inferred from the option type code. Spelled ``ns`` rather
                than ``namespace`` because :meth:`abc.ABCMeta.__new__` names its
                own fourth parameter ``namespace``, and before Python 3.11 that
                parameter is positional-or-keyword rather than positional-only --
                so a class keyword literally called ``namespace`` binds it twice.
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments.

        If ``code`` is provided, the subclass will be registered to the
        :attr:`__enum__` mapping with the given ``code``. If ``code`` is
        not given, the subclass will not be registered.

        Examples:

            .. code-block:: python

               from pcapkit.const.pcapng.option_type import OptionType as Enum_OptionType
               from pcapkit.protocols.schema.misc.pcapng import Option

               class NewOption(Option, ns='opt', code=Enum_OptionType.opt_new):
                   ...

        See Also:
            - :class:`pcapkit.const.pcapng.option_type.OptionType`

        """
        # NOTE: the base hook goes first, before any of the registration work
        # below -- see :meth:`EnumSchema.__init_subclass__`, which makes the same
        # move for the same reason. :meth:`Schema.__init_subclass__` is what
        # refuses to derive from a finalised schema, and a refusal has to land
        # before :meth:`Option.register` writes ``cls`` into ``__enum__``: calling
        # this last would let a raise discard the class object while leaving the
        # registry pointing at it, so a rejected declaration would still
        # displace a built-in option schema for the rest of the process.
        super().__init_subclass__()

        if ns is not None:
            cls.__namespace__ = ns

        if code is not None:
            if ns is None:
                ns = cast('Optional[str]', cls.__namespace__)

            if not isinstance(code, Enum_OptionType):
                for _code in code:
                    Option.register(_code, cls, ns)
            else:
                Option.register(code, cls, ns)

    @staticmethod
    def register(code: 'Enum_OptionType', cls: 'Type[Option]', ns: 'Optional[str]' = None) -> 'None':
        """Register option type to :attr:`__enum__` mapping.

        Args:
            code: Option type code.
            cls: Option type schema.
            ns: Namespace of option type enumeration. If not given, the value
                will be inferred from the option type code.

        A registration that displaces another schema for the same code is
        reported as a :exc:`~pcapkit.utilities.warnings.RegistryWarning`, as
        every other registry in the package does -- the lookup that follows
        cannot tell a deliberate replacement from an accidental one, so an
        unreported overwrite is a parser silently swapped out for another.

        The guard is identity-based: it fires only when the incumbent differs
        from ``cls``, so re-registering the exact same class under the same
        ``code`` is a silent no-op -- in every namespace ``targets`` reaches --
        rather than a warning about nothing displaced. That is what keeps
        :meth:`__init_subclass__` honest: it loops over a ``code`` list with no
        deduplication, so a repeated or aliased entry reaches this method twice
        with the same class, and the second call finds itself already the
        incumbent.

        Note:
            ``ns='opt'`` fans one registration out across every namespace, so the
            collision is reported once for the registration and names the
            namespaces it displaced something in, rather than once per namespace.

            A namespace created by this call starts as a copy of ``opt``'s
            defaults, so nothing in it is a prior registration and it is exempt:
            registering an ``opt``-namespace code into a brand-new namespace is
            exactly what that copy is for.

            Membership is tested with ``.get()``, never by subscripting. The
            per-namespace registries are :class:`collections.defaultdict`\\ s --
            only the outer one is the miss-safe
            :class:`~pcapkit.protocols.schema.schema._EnumRegistry` -- so reading
            ``Option.registry[key][code]`` to see whether it is there would
            *insert* :class:`UnknownOption` for a code nobody registered.

        """
        if ns is None:
            ns = code.name.split('_')[0]

        fresh = ns != 'opt' and ns not in Option.registry
        if fresh:
            Option.registry[ns] = Option.registry['opt'].copy()

        targets = list(Option.registry) if ns == 'opt' else [ns]

        if not fresh:
            clash = [key for key in targets
                     if (incumbent := Option.registry[key].get(code)) is not None
                     and incumbent is not cls]
            if clash:
                warn(f'PCAP-NG: [Option {code}] option already registered in '
                     f'namespace(s) {", ".join(repr(key) for key in clash)}, '
                     f'overwriting with {cls!r}', RegistryWarning, stacklevel=stacklevel())

        for key in targets:
            Option.registry[key][code] = cls

    if TYPE_CHECKING:
        #: Option type.
        type: 'Enum_OptionType'
        #: Option data length.
        length: 'int'


class _OPT_Option(Option, ns='opt'):
    """Header schema for ``opt_*`` options."""

    #: Option type.
    type: 'Enum_OptionType' = OptionEnumField(length=2, namespace='opt', callback=byteorder_callback)
    #: Option data length.
    length: 'int' = UInt16Field(callback=byteorder_callback)


@schema_final
class UnknownOption(_OPT_Option):
    """Header schema for unknown PCAP-NG file options."""

    #: Option value.
    data: 'bytes' = BytesField(length=bounded_option(lambda pkt: pkt['length']))
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
    comment: 'str' = StringField(length=bounded_option(lambda pkt: pkt['length']), encoding='utf-8')
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
    data: 'bytes' = BytesField(length=bounded_option(lambda pkt: pkt['length'] - 4))
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
    options: 'list[Option]' = OptionAreaField(
        length=nonnegative(lambda pkt: pkt['length'] - 28),
        base_schema=_OPT_Option,
        type_name='type',
        registry=Option.registry['opt'],
        eool=Enum_OptionType.opt_endofopt,
    )
    #: Padding, sized from the ``__option_padding__`` key that OptionField generates.
    padding: 'bytes' = PaddingField(
        length=nonnegative(lambda pkt: pkt.get('__option_padding__', 0)))
    #: Block total length.
    length2: 'int' = UInt32Field(callback=shb_byteorder_callback)

    def pre_pack(self, packet: 'dict[str, Any]') -> 'None':
        """Prepare ``packet`` data for packing process.

        Args:
            packet: packet data

        Note:
            This method is expected to directly modify any data stored
            in the ``packet`` and thus no return is required.

            The Byte-Order Magic is not carried by any field of the schema --
            :attr:`magic` is the palindromic constant, identical in either byte
            order -- so it is seeded here from the byte order the packet data
            asks for, and from the host byte order when it asks for none.

        """
        if 'match' in packet:
            return

        packet['match'] = {
            'byteorder': 0x1A2B3C4D if packet_byteorder(packet) == 'big' else 0x4D3C2B1A,
        }

    def post_process(self, packet: 'dict[str, Any]') -> 'SectionHeaderBlock':
        """Revise ``schema`` data after unpacking process.

        This method calculates the byteorder value based on
        the parsed schema.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        A Block Total Length below the 28 octets of the fixed fields reads the
        trailing copy past the block, so the two are not compared here;
        :meth:`PCAPNG._read_block_short_header
        <pcapkit.protocols.misc.pcapng.PCAPNG._read_block_short_header>` keeps
        the block as captured and compares them itself (:issue:`1422`). A block
        of 12 octets has no Byte-Order Magic and takes its byte order from its
        Block Total Length (see :func:`shb_byteorder_callback`).

        """
        if self.length >= 28:
            self = cast('Self', super().post_process(packet))

        if self.section_length == 0xFFFF_FFFF_FFFF_FFFF:
            self.section_length = -1

        magic = packet['match']['byteorder']  # type: int
        if magic == 0x1A2B3C4D or (magic == 0x0000000C and self.length == 12):
            self.byteorder = 'big'
        elif magic == 0x4D3C2B1A or (magic == 0x0C000000 and self.length == 12):
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


class _IF_Option(Option, ns='if'):
    """Header schema for ``if_*`` options."""

    #: Option type.
    type: 'Enum_OptionType' = OptionEnumField(length=2, namespace='if', callback=byteorder_callback)
    #: Option data length.
    length: 'int' = UInt16Field(callback=byteorder_callback)


@schema_final
class IF_NameOption(_IF_Option, code=Enum_OptionType.if_name):
    """Header schema for PCAP-NG file ``if_name`` options."""

    #: Interface name.
    name: 'str' = StringField(length=bounded_option(lambda pkt: pkt['length']), encoding='utf-8')
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', name: 'str') -> 'None': ...


@schema_final
class IF_DescriptionOption(_IF_Option, code=Enum_OptionType.if_description):
    """Header schema for PCAP-NG file ``if_description`` options."""

    #: Interface description.
    description: 'str' = StringField(length=bounded_option(lambda pkt: pkt['length']), encoding='utf-8')
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
    filter: 'bytes' = BytesField(length=bounded_option(lambda pkt: pkt['length'] - 1))
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_OptionType', length: 'int', code: 'Enum_FilterType', filter: 'bytes') -> 'None': ...


@schema_final
class IF_OSOption(_IF_Option, code=Enum_OptionType.if_os):
    """Header schema for PCAP-NG file ``if_os`` options."""

    #: OS information.
    os: 'str' = StringField(length=bounded_option(lambda pkt: pkt['length']), encoding='utf-8')
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
    hardware: 'str' = StringField(length=bounded_option(lambda pkt: pkt['length']), encoding='utf-8')
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
    options: 'list[Option]' = OptionAreaField(
        length=nonnegative(lambda pkt: pkt['length'] - 20),
        base_schema=_IF_Option,
        type_name='type',
        registry=Option.registry['if'],
        eool=Enum_OptionType.opt_endofopt,
    )
    #: Padding, sized from the ``__option_padding__`` key that OptionField generates.
    padding: 'bytes' = PaddingField(
        length=nonnegative(lambda pkt: pkt.get('__option_padding__', 0)))
    #: Block total length.
    length2: 'int' = UInt32Field(callback=byteorder_callback)

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        A Block Total Length below the 20 octets of the fixed fields reads the
        trailing copy past the block, so the two are not compared here;
        :meth:`PCAPNG._read_block_short_header
        <pcapkit.protocols.misc.pcapng.PCAPNG._read_block_short_header>` keeps
        the block as captured and compares them itself (:issue:`1422`).

        """
        if self.length < 20:
            return self
        return super().post_process(packet)

    if TYPE_CHECKING:
        def __init__(self, length: 'int', linktype: 'int', snaplen: 'int',
                     options: 'list[Option | bytes] | bytes', length2: 'int') -> 'None': ...


class _EPB_Option(Option, ns='epb'):
    """Header schema for ``epb_*`` options."""

    #: Option type.
    type: 'Enum_OptionType' = OptionEnumField(length=2, namespace='epb', callback=byteorder_callback)
    #: Option data length.
    length: 'int' = UInt16Field(callback=byteorder_callback)


@schema_final
class EPB_FlagsOption(_EPB_Option, code=Enum_OptionType.epb_flags):
    """Header schema for PCAP-NG ``epb_flags`` options."""

    #: Flags.
    flags: 'EPBFlags' = FlagsField(namespace=PACKET_FLAGS, callback=byteorder_callback)
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
    data: 'bytes' = BytesField(length=bounded_option(lambda pkt: pkt['length'] - 1))
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
    value: 'bytes' = BytesField(length=bounded_option(lambda pkt: pkt['length'] - 1))
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
    #: Packet data, bounded by the block (see :func:`captured_area`).
    packet_data: 'bytes' = PayloadField(length=captured_area('captured_len'))
    #: Padding.
    padding_data: 'bytes' = PaddingField(length=lambda pkt: (4 - captured_area('captured_len')(pkt) % 4) % 4)
    #: Options.
    options: 'list[Option]' = OptionAreaField(
        # NOTE: The padding is recomputed here rather than read back from
        # ``padding_data``: a PaddingField is written straight into the schema
        # buffer while packing and never lands in the packet data, so its name
        # is not a key here on the packing path.
        length=bounded_area(lambda pkt: pkt['length'] - 32
                                        - (captured_area('captured_len')(pkt) + 3) // 4 * 4),
        base_schema=_EPB_Option,
        type_name='type',
        registry=Option.registry['epb'],
        eool=Enum_OptionType.opt_endofopt,
    )
    #: Padding, sized from the ``__option_padding__`` key that OptionField generates.
    padding_opts: 'bytes' = PaddingField(
        length=nonnegative(lambda pkt: pkt.get('__option_padding__', 0)))
    #: Block total length.
    length2: 'int' = UInt32Field(callback=byteorder_callback)

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        A Block Total Length below the 32 octets of the fixed fields reads the
        trailing copy past the block, so the two are not compared here;
        :meth:`PCAPNG._read_block_short
        <pcapkit.protocols.misc.pcapng.PCAPNG._read_block_short>` keeps the block
        as captured and compares them itself (:issue:`1414`).

        """
        if self.length < 32:
            return self
        return super().post_process(packet)

    if TYPE_CHECKING:
        def __init__(self, length: 'int', interface_id: 'int', timestamp_high: 'int',
                     timestamp_low: 'int', captured_len: 'int', original_len: 'int',
                     packet_data: 'bytes | ProtocolBase | Schema',
                     options: 'list[Option | bytes] | bytes', length2: 'int') -> 'None': ...


def _spb_data_length(packet: 'dict[str, Any]') -> 'int':
    """Length of a Simple Packet Block's packet data.

    Args:
        packet: Unpacked data so far, with ``length``, ``original_len`` and,
            when interface 0 sets one, ``snaplen``.

    Returns:
        ``min(original_len, snaplen)``, bounded by the octets the block holds
        less its 16 framing octets. A block that holds more than that length
        and its padding -- past the snaplen (:issue:`1384`) or past
        ``original_len`` (:issue:`1414`) -- keeps the excess as packet data
        instead, so no octet is dropped and the trailing Block Total Length is
        read where it sits.

    """
    area = max(0, packet['length'] - 16)
    size = min(packet['original_len'], area)
    snaplen = packet.get('snaplen')
    if snaplen is not None and snaplen < size:
        size = snaplen
    if area > (size + 3) // 4 * 4:
        size = area
    return size


@schema_final
class SimplePacketBlock(BlockType, code=Enum_BlockType.Simple_Packet_Block):
    """Header schema for PCAP-NG Simple Packet Block (SPB)."""

    __payload__ = 'packet_data'

    #: Block total length.
    length: 'int' = UInt32Field(callback=byteorder_callback)
    #: Original packet length.
    original_len: 'int' = UInt32Field(callback=byteorder_callback)
    #: Packet data, ``min(original_len, snaplen)`` octets, bounded by what the
    #: block holds; see :func:`_spb_data_length`.
    packet_data: 'bytes' = PayloadField(length=_spb_data_length)
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - len(pkt['packet_data']) % 4) % 4)
    #: Block total length.
    length2: 'int' = UInt32Field(callback=byteorder_callback)

    if TYPE_CHECKING:
        def __init__(self, length: 'int', original_len: 'int',
                     packet_data: 'bytes | ProtocolBase | Schema',
                     length2: 'int') -> 'None': ...


def _split_names(resol: 'str') -> 'list[str]':
    """Split NRB record name resolution data into its zero-terminated names.

    Args:
        resol: Name resolution data, as a UTF-8
            :class:`~pcapkit.corekit.fields.strings.StringField` decodes it.

    Returns:
        The names, one per terminator, so an empty name is kept as ``''`` and
        joining them back yields the data exactly (:issue:`1383`). They are
        split from the *octets* the data was decoded from, so that a name that
        is not valid UTF-8 comes back as a
        :class:`~pcapkit.corekit.fields.strings.DecodedString` carrying its own
        octets; splitting the decoded text would return plain strings and lose
        them.

    Raises:
        ProtocolError: If the data is empty or does not end in a zero
            terminator. The record area is then kept as the octets captured
            (see :class:`OptionAreaField`).

    """
    raw = resol.raw if isinstance(resol, DecodedString) else resol.encode('utf-8')
    if not raw.endswith(b'\x00'):
        raise ProtocolError(f'PCAP-NG: [NRB] name resolution data is not zero-terminated: {raw!r}')
    names = []  # type: list[str]
    for octets in raw[:-1].split(b'\x00'):
        text = octets.decode('utf-8', 'replace')
        names.append(text if text.encode('utf-8') == octets else DecodedString(text, octets))
    return names


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
    data: 'bytes' = BytesField(length=bounded_option(lambda pkt: pkt['length']))
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
    resol: 'str' = StringField(length=bounded_option(lambda pkt: pkt['length'] - 4), encoding='utf-8')
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        self.names = _split_names(self.resol)
        return self

    if TYPE_CHECKING:
        #: Name resolution records.
        names: 'list[str]'

        def __init__(self, type: 'Enum_RecordType', length: 'int', ip: 'IPv4Address | str | bytes | int', resol: 'str') -> 'None': ...


@schema_final
class IPv6Record(NameResolutionRecord, code=Enum_RecordType.nrb_record_ipv6):
    """Header schema for PCAP-NG NRB ``nrb_record_ipv6`` records."""

    #: IPv6 address.
    ip: 'IPv6Address' = IPv6AddressField()
    #: Name resolution data.
    resol: 'str' = StringField(length=bounded_option(lambda pkt: pkt['length'] - 16), encoding='utf-8')
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        self.names = _split_names(self.resol)
        return self

    if TYPE_CHECKING:
        #: Name resolution records.
        names: 'list[str]'

        def __init__(self, type: 'Enum_RecordType', length: 'int', ip: 'IPv6Address | str | bytes | int', resol: 'str') -> 'None': ...


class _NS_Option(Option, ns='ns'):
    """Header schema for ``ns_*`` options."""

    #: Option type.
    type: 'Enum_OptionType' = OptionEnumField(length=2, namespace='ns', callback=byteorder_callback)
    #: Option data length.
    length: 'int' = UInt16Field(callback=byteorder_callback)


@schema_final
class NS_DNSNameOption(_NS_Option, code=Enum_OptionType.ns_dnsname):
    """Header schema for PCAP-NG ``ns_dnsname`` option."""

    #: DNS name.
    name: 'str' = StringField(length=bounded_option(lambda pkt: pkt['length']), encoding='utf-8')
    #: Padding.
    padding: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['length'] % 4) % 4)

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
    records: 'list[NameResolutionRecord]' = OptionAreaField(
        length=nonnegative(lambda pkt: pkt['length'] - 12),
        base_schema=NameResolutionRecord,
        type_name='type',
        registry=NameResolutionRecord.registry,
        eool=Enum_RecordType.nrb_record_end,
    )
    #: Options.
    options: 'list[Option]' = OptionAreaField(
        length=nonnegative(lambda pkt: pkt.get('__option_padding__', 0)),  # key from OptionField
        base_schema=_NS_Option,
        type_name='type',
        registry=Option.registry['ns'],
        eool=Enum_OptionType.opt_endofopt,
    )
    #: Padding, sized from the ``__option_padding__`` key that OptionField generates.
    padding: 'bytes' = PaddingField(
        length=nonnegative(lambda pkt: pkt.get('__option_padding__', 0)))
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


class _ISB_Option(Option, ns='isb'):
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
class InterfaceStatisticsBlock(BlockType, code=Enum_BlockType.Interface_Statistics_Block):
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
    options: 'list[Option]' = OptionAreaField(
        length=nonnegative(lambda pkt: pkt['length'] - 24),
        base_schema=_ISB_Option,
        type_name='type',
        registry=Option.registry['isb'],
        eool=Enum_OptionType.opt_endofopt,
    )
    #: Padding, sized from the ``__option_padding__`` key that OptionField generates.
    padding: 'bytes' = PaddingField(
        length=nonnegative(lambda pkt: pkt.get('__option_padding__', 0)))
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
    entry: 'bytes' = BytesField(length=nonnegative(lambda pkt: pkt['length'] - 12))
    #: Block total length.
    length2: 'int' = UInt32Field(callback=byteorder_callback)

    def post_process(self, packet: 'dict[str, Any]') -> 'Self':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        Note:
            The entry is walked once, end to end, rather than split apart with
            ``self.entry.split(b'\\n\\n')``: that delimits a *length-prefixed*
            format by content, which a binary field's own bytes need no escaping
            to defeat (``struct.pack('<Q', 2570) ==
            b'\\n\\n\\x00\\x00\\x00\\x00\\x00\\x00'`` puts the separator inside
            the length prefix itself). A binary field's value is counted out by
            its prefix and never inspected; a blank line -- found by *reading* --
            starts the next entry, even an empty one behind a trailing separator.
            A line of nothing but NUL octets at the end of the entry is the
            block's own 32-bit padding and ends it.

            The walk is strict (:issue:`1406`, :issue:`1413`, the #1325 ruling
            that :class:`OptionAreaField` applies to option areas). Any of the
            following raises :exc:`~pcapkit.utilities.exceptions.ProtocolError`,
            and the whole entry is then kept as the octets captured, as the one
            :obj:`bytes` item of :attr:`data`, which the block's ``make`` writes
            back verbatim:

            * a line, text field or binary field name, with no terminating
              newline, e.g. a bare ``KEY`` at the end of the entry;
            * a binary field whose 64-bit length prefix is cut short, or declares
              more octets than the entry has left -- at ``2**63`` and above
              :meth:`io.BytesIO.read` would refuse it with a bare
              :exc:`OverflowError`;
            * a binary field's value not followed by the newline that
              terminates it, including one that ends the entry;
            * any other entry that the parsed fields would not rebuild octet
              for octet, e.g. a field that is not UTF-8.

            A :exc:`struct.error`, :exc:`OverflowError` or
            :exc:`UnicodeDecodeError` is neither one of
            :mod:`pcapkit.utilities.exceptions` nor an :exc:`EOFError`, so any of
            them would abort the whole extraction rather than this one entry.
            Field names, keys and values are therefore decoded with
            ``errors='replace'`` and reported, which the rebuild check then
            catches, rather than strictly.

        """
        self = cast('Self', super().post_process(packet))

        try:
            self.data = self._read_entries()
            rebuilt = self.dump_entries(cast('list[OrderedMultiDict[str, str | bytes]]', self.data))
            if self.entry not in (rebuilt, rebuilt + bytes(-len(rebuilt) % 4)):
                raise ProtocolError('PCAP-NG: [systemd Journal Export] parsed entry does not '
                                    'rebuild to the octets captured')
        except ProtocolError as error:
            warn(f'{error}; journal entry of {len(self.entry)} octet(s) kept as captured',
                 ProtocolWarning, stacklevel=stacklevel())
            self.data = [self.entry]
        return self

    def _read_entries(self) -> 'list[OrderedMultiDict[str, str | bytes]]':
        """Walk :attr:`entry` into its journal entries, as :meth:`post_process` describes.

        Returns:
            The journal entries.

        Raises:
            ProtocolError: If the entry is malformed, as :meth:`post_process`
                lists.

        """
        data = []  # type: list[OrderedMultiDict[str, str | bytes]]
        total = len(self.entry)
        entry_data = io.BytesIO(self.entry)
        while True:
            entry = OrderedMultiDict()  # type: OrderedMultiDict[str, str | bytes]
            # a blank line that was actually *read* -- as opposed to the
            # block's own NUL padding, or simply running out of octets --
            # is the separator the format puts between entries, so it
            # starts another one, even an empty one
            separator = False

            while True:
                raw_line = entry_data.readline()
                if raw_line == b'\n':
                    separator = True
                    break
                if not raw_line.strip(b'\x00'):
                    break
                if not raw_line.endswith(b'\n'):
                    raise ProtocolError(f'PCAP-NG: [systemd Journal Export] entry field {raw_line!r} '
                                        'has no terminating newline')
                line = raw_line[:-1]

                line_split = line.split(b'=', maxsplit=1)
                if len(line_split) == 2:
                    key, value = line_split
                    entry.add(self._decode_text(key), self._decode_text(value))
                    continue

                prefix = entry_data.read(8)
                if len(prefix) < 8:
                    raise ProtocolError(f'PCAP-NG: [systemd Journal Export] binary field {line!r} '
                                        f'declares its length in {len(prefix)} octet(s) of the 8 it needs')

                length = struct.unpack('<Q', prefix)[0]  # type: int
                available = total - entry_data.tell()
                if length > available:
                    raise ProtocolError(f'PCAP-NG: [systemd Journal Export] binary field {line!r} '
                                        f'declares {length} octet(s) with {available} left in its entry')
                entry.add(self._decode_text(line), entry_data.read(length))

                if entry_data.read(1) != b'\n':
                    raise ProtocolError(f'PCAP-NG: [systemd Journal Export] binary field {line!r} '
                                        'is not followed by the newline that terminates it')

            data.append(entry)
            if entry_data.tell() >= total and not separator:
                break
        return data

    @staticmethod
    def dump_entries(entries: 'list[OrderedMultiDict[str, str | bytes]]') -> 'bytes':
        """Serialise journal entries, without the block's 32-bit padding.

        Args:
            entries: The journal entries.

        Returns:
            Each field as ``KEY=value\\n``, or for a binary value as the name,
            a newline, its 64-bit little-endian length, the value and a newline,
            with one blank line between entries.

        """
        temp = []  # type: list[bytes]
        for entry in entries:
            tmp_buf = []  # type: list[bytes]
            for key, val in entry.items(multi=True):
                if isinstance(val, str):
                    tmp_buf.append(f'{key}={val}\n'.encode())
                else:
                    tmp_buf.append(b'%s\n%s%s\n' % (key.encode(), struct.pack('<Q', len(val)), val))
            temp.append(b''.join(tmp_buf))
        return b'\n'.join(temp)

    @staticmethod
    def _decode_text(octets: 'bytes') -> 'str':
        """Decode a journal field name, key or value, reporting what did not decode.

        Args:
            octets: Field name, key or value, as it came off the wire.

        Returns:
            The decoded text, with any octet that is not UTF-8 replaced.

        See :meth:`post_process` for why this replaces rather than raising.

        """
        try:
            return octets.decode('utf-8')
        except UnicodeDecodeError as error:
            warn(f'PCAP-NG: [systemd Journal Export] {octets!r} is not UTF-8 '
                 f'({error.reason} at position {error.start}); replacing what did not '
                 f'decode', SchemaWarning, stacklevel=stacklevel())
            return octets.decode('utf-8', errors='replace')

    if TYPE_CHECKING:
        #: Journal entry (decoded), or the entry as captured, as one
        #: :obj:`bytes` item, if it is malformed.
        data: 'list[OrderedMultiDict[str, str | bytes] | bytes]'

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

            fields = line.strip().split()
            if len(fields) != 3 or fields[1] != '=':
                raise FieldValueError(f'invalid WireGuard key log format: {line!r}')
            label, _, secret = fields
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

    # NOTE: The two zero octets after the PAN ID are the Decryption Secrets
    # Block's own padding, which Secrets Length does not count, so they belong
    # to :attr:`DecryptionSecretsBlock.padding_data` rather than to this schema.

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

    # NOTE: As for :class:`ZigBeeNWKKey`, the trailing two zero octets are the
    # block's padding, not part of the secrets.

    if TYPE_CHECKING:
        def __init__(self, key: 'bytes', panid: 'int', addr_low: 'int', addr_high: 'int') -> 'None': ...


class _DSB_Option(Option, ns='dsb'):
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
    padding_data: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['secrets_length'] % 4) % 4)
    #: Options.
    options: 'list[Option]' = OptionAreaField(
        # NOTE: see EnhancedPacketBlock.options on why the padding is recomputed
        # here instead of being read back from ``padding_data``.
        length=nonnegative(lambda pkt: pkt['length'] - 20 - pkt['secrets_length']
                           - (4 - pkt['secrets_length'] % 4) % 4),
        base_schema=_DSB_Option,
        type_name='type',
        registry=Option.registry['dsb'],
        eool=Enum_OptionType.opt_endofopt,
    )
    #: Padding, sized from the ``__option_padding__`` key that OptionField generates.
    padding_opts: 'bytes' = PaddingField(
        length=nonnegative(lambda pkt: pkt.get('__option_padding__', 0)))
    #: Block total length.
    length2: 'int' = UInt32Field(callback=byteorder_callback)

    if TYPE_CHECKING:
        def __init__(self, length: 'int', secrets_type: 'Enum_SecretsType',
                     secrets_length: 'int', secrets_data: 'DSBSecrets | bytes',
                     options: 'list[Option | bytes] | bytes', length2: 'int') -> 'None': ...


@schema_final
class CustomBlock(BlockType, code=[Enum_BlockType.Custom_Block_that_rewriters_can_copy_into_new_files,
                                   Enum_BlockType.Custom_Block_that_rewriters_should_not_copy_into_new_files]):
    """Header schema for PCAP-NG Custom Block (CB).

    Note:
        The block carries no length for its custom data, so where the custom
        data ends and the block options begin is known only to the owner of
        the private enterprise number. :attr:`data` therefore spans the whole
        region between :attr:`pen` and the trailing block total length, i.e.
        the custom data, its padding to a 32-bit boundary, and any options.

    """

    #: Block total length.
    length: 'int' = UInt32Field(callback=byteorder_callback)
    #: Private enterprise number.
    pen: 'int' = UInt32Field(callback=byteorder_callback)
    #: Custom data (incl. padding and options).
    data: 'bytes' = BytesField(length=nonnegative(lambda pkt: pkt['length'] - 16))
    #: Block total length.
    length2: 'int' = UInt32Field(callback=byteorder_callback)

    if TYPE_CHECKING:
        def __init__(self, length: 'int', pen: 'int', data: 'bytes', length2: 'int') -> 'None': ...


class _PACK_Option(Option, ns='pack'):
    """Header schema for ``pack_*`` options."""

    #: Option type.
    type: 'Enum_OptionType' = OptionEnumField(length=2, namespace='pack', callback=byteorder_callback)
    #: Option data length.
    length: 'int' = UInt16Field(callback=byteorder_callback)


@schema_final
class PACK_FlagsOption(_PACK_Option, code=Enum_OptionType.pack_flags):
    """Header schema for PCAP-NG ``pack_flags`` options."""

    #: Flags.
    flags: 'PACKFlags' = FlagsField(namespace=PACKET_FLAGS, callback=byteorder_callback)
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
    data: 'bytes' = BytesField(length=bounded_option(lambda pkt: pkt['length'] - 1))
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
    interface_id: 'int' = UInt16Field(callback=byteorder_callback)
    #: Drops count.
    drop_count: 'int' = UInt16Field(callback=byteorder_callback, default=0xFFFF)
    #: Timestamp (high).
    timestamp_high: 'int' = UInt32Field(callback=byteorder_callback)
    #: Timestamp (low).
    timestamp_low: 'int' = UInt32Field(callback=byteorder_callback)
    #: Captured packet length.
    captured_length: 'int' = UInt32Field(callback=byteorder_callback)
    #: Original packet length.
    original_length: 'int' = UInt32Field(callback=byteorder_callback)
    #: Packet data, bounded by the block (see :func:`captured_area`).
    packet_data: 'bytes' = PayloadField(length=captured_area('captured_length'))
    #: Padding.
    padding_data: 'bytes' = PaddingField(length=lambda pkt: (4 - captured_area('captured_length')(pkt) % 4) % 4)
    #: Options.
    options: 'list[Option]' = OptionAreaField(
        # NOTE: see EnhancedPacketBlock.options on why the padding is recomputed
        # here instead of being read back from ``padding_data``.
        length=bounded_area(lambda pkt: pkt['length'] - 32
                                        - (captured_area('captured_length')(pkt) + 3) // 4 * 4),
        base_schema=_PACK_Option,
        type_name='type',
        registry=Option.registry['pack'],
        eool=Enum_OptionType.opt_endofopt,
    )
    #: Padding, sized from the ``__option_padding__`` key that OptionField generates.
    padding_opts: 'bytes' = PaddingField(
        length=nonnegative(lambda pkt: pkt.get('__option_padding__', 0)))
    #: Block total length.
    length2: 'int' = UInt32Field(callback=byteorder_callback)

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        A Block Total Length below the 32 octets of the fixed fields reads the
        trailing copy past the block, so the two are not compared here;
        :meth:`PCAPNG._read_block_short
        <pcapkit.protocols.misc.pcapng.PCAPNG._read_block_short>` keeps the block
        as captured and compares them itself (:issue:`1414`).

        """
        if self.length < 32:
            return self
        return super().post_process(packet)

    if TYPE_CHECKING:
        def __init__(self, length: 'int', interface_id: 'int', drop_count: 'int',
                     timestamp_high: 'int', timestamp_low: 'int', captured_length: 'int',
                     original_length: 'int', packet_data: 'bytes | ProtocolBase | Schema',
                     options: 'list[Option | bytes] | bytes', length2: 'int') -> 'None': ...
