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
    from typing import Any, Callable, DefaultDict, Iterable, Optional, Type

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
    set to anything. Nothing made the difference non-negative, and the field
    layer does not do it either: :meth:`_TextField.__call__
    <pcapkit.corekit.fields.strings._TextField.__call__>` builds its
    :mod:`struct` template as ``f'{length}s'`` unconditionally, so a negative
    length becomes the format ``'-8s'`` and :func:`struct.calcsize` raises a bare
    :exc:`struct.error`; a negative :class:`~pcapkit.corekit.fields.misc.SchemaField`
    length reaches :meth:`io.RawIOBase.read` and raises a bare :exc:`ValueError`.
    Neither is one of :mod:`pcapkit.utilities.exceptions`, so a caller cannot tell
    either from a bug in its own code, and neither is an :exc:`EOFError`, so
    neither is caught by the frame loop -- one malformed block therefore cost the
    whole extraction. See `#678
    <https://github.com/JarryShaw/PyPCAPKit/issues/678>`__.

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

    Clamping rather than refusing is the choice :func:`bounded_option` and
    :func:`bounded_area` already made, for the reason their docstrings give: a
    block read has no catch point above :meth:`FieldBase.unpack
    <pcapkit.corekit.fields.field.FieldBase.unpack>`, so one refusal aborts the
    whole extraction rather than one block, which is what the `#431
    <https://github.com/JarryShaw/PyPCAPKit/issues/431>`__ accommodation exists
    to prevent. The end of the file is the one case that is *not* a clamp, since
    there no block is being read at all -- see :meth:`PCAPNG._check_block_floor
    <pcapkit.protocols.misc.pcapng.PCAPNG._check_block_floor>`, which reports it
    as the :exc:`~pcapkit.utilities.exceptions.StreamEOFError` the frame loop
    catches.

    Note:
        Unlike :func:`bounded_option` this needs no ``__length__`` opt-out for
        the packing path, because it floors a *difference* rather than clamping
        against the remaining area: a negative difference is not a legitimate
        thing to pack either -- ``struct.pack('-8s', ...)`` raises exactly as
        ``calcsize`` does -- where clamping against the remainder would have
        shortened a perfectly good option.

        That distinction is what keeps the three decryption-secrets payloads --
        :attr:`UnknownSecrets.data`, :attr:`TLSKeyLog.data` and
        :attr:`WireGuardKeyLog.data` -- out of this. They read ``__length__``
        *whole* rather than subtracting from it, and ``Schema.pack`` leaves it at
        ``-1`` for "unknown", so flooring them packs nothing at all. Measured: it
        emptied both secrets payloads, and the two ``EXPECTED_FAILURES`` entries
        recording their round-trip mismatch then came back ``OK``, since an empty
        payload compares equal to an empty payload. On the parsing path their
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
    """Clamp an option or record payload to the octets its area still declares.

    Args:
        length: Callback computing the payload's nominal length, as the option's
            or record's own declared length field gives it.

    Returns:
        A callback returning that length, never past the octets the enclosing
        option or record area has left to give.

    An option's length is a 16-bit wire field, so it can declare up to 65,535
    octets of payload from four octets of option header. Nothing bounds that
    against the area the option sits in: :meth:`OptionField.unpack
    <pcapkit.corekit.fields.collections.OptionField.unpack>` subtracts each
    option's *parsed* size from the area it was given but never checks the
    declared size against it, and :meth:`FieldBase.unpack
    <pcapkit.corekit.fields.field.FieldBase.unpack>` zero-pads any shortfall
    within :data:`~pcapkit.corekit.fields.field._MAX_ZERO_PAD_SHORTFALL`
    unconditionally -- deliberately, since that ceiling is the full span of a
    16-bit length and a capture cut short by its snapshot length must still
    parse. Repeating such an option across many blocks therefore synthesised
    padding without limit: 2,000 Enhanced Packet Blocks in 80,048 octets, each
    with one option declaring 65,535 against none present, produced 131,070,000
    octets of zero padding, an amplification of 1,637x linear in the block
    count. See `#594 <https://github.com/JarryShaw/PyPCAPKit/issues/594>`__,
    and `#593 <https://github.com/JarryShaw/PyPCAPKit/issues/593>`__ for the
    32-bit band the field layer's own budget already covers.

    The bound has to come from this layer because the field layer cannot see
    it. What distinguishes the crafted case from the legitimate one is not the
    shortfall's size -- both are inside a 16-bit length, which is why #571's
    ``len(buffer) < length`` rejection was declined -- but whether the option
    is inconsistent with the framing the block itself declares. Block Total
    Length is authoritative and cross-checked against its own trailing copy, so
    the area is ``length`` less the fixed fields, ``captured_len`` and its
    padding; an option declaring more payload than that area has left is
    malformed however complete the file behind it is. A snapshot-truncated
    capture says so through ``captured_len`` instead, and leaves its options
    whole, so it never trips this.

    Clamping rather than refusing is what keeps the `#431
    <https://github.com/JarryShaw/PyPCAPKit/issues/431>`__ accommodation: a
    block read has no catch point above :meth:`FieldBase.unpack
    <pcapkit.corekit.fields.field.FieldBase.unpack>`, so one refusal aborts the
    whole extraction rather than one block, and a truncated capture would stop
    parsing at the cut instead of reporting the frames before it. The clamp is
    also history-independent -- it reads only this block's own declared framing
    -- which a running threshold would not be.

    Note:
        The clamp is skipped when ``__length__`` is absent or negative, which is
        what :meth:`Schema.pack <pcapkit.protocols.schema.schema.Schema.pack>`
        leaves it as when no length is known. That matters here in a way it does
        not for :func:`pcapkit.protocols.schema.transport.sctp.bounded`, whose
        list fields ignore their length while packing: these are
        :class:`~pcapkit.corekit.fields.strings.BytesField` and
        :class:`~pcapkit.corekit.fields.strings.StringField` payloads, and
        :meth:`FieldBase.pack <pcapkit.corekit.fields.field.FieldBase.pack>`
        packs them through ``struct.pack('<n>s', ...)``, which truncates
        silently. A clamp applied while packing would therefore shorten a
        perfectly good option rather than reject it.

        The nominal length still goes through :func:`nonnegative` first, on both
        paths, since an option declaring less payload than the part of itself it
        describes -- ``length`` below the four octets of an ``epb_hash`` or an
        ``ns_dnsIP4addr`` record's own fields -- makes the subtraction negative
        before there is anything to clamp it against, and a negative is not an
        amount to read or to pack.

    """
    floored = nonnegative(length)

    def callback(pkt: 'dict[str, Any]') -> 'int':
        nominal = floored(pkt)

        remaining = pkt.get('__length__')
        if not isinstance(remaining, int) or remaining < 0 or nominal <= remaining:
            return nominal

        warn(f'PCAP-NG: option declares {nominal} octet(s) of payload with '
             f'{remaining} octet(s) left in its area; reading {remaining}',
             SchemaWarning, stacklevel=stacklevel())
        return remaining
    return callback


def bounded_area(length: 'Callable[[dict[str, Any]], int]') -> 'Callable[[dict[str, Any]], int]':
    """Clamp a packet block's option area to the octets the block itself holds.

    Args:
        length: Callback computing the option area's nominal span, from the
            block's own declared Block Total Length.

    Returns:
        A callback returning that span, never past the octets left of the block.

    :func:`bounded_option` bounds a payload by the area, and the area by the
    block's declared Block Total Length. That closes the band only while the
    declared length is itself backed by real octets, and nothing checks that:
    ``BlockType.post_process`` compares ``length`` against its own trailing copy
    and never against the file. A block declaring 1,000,000 octets while holding
    36 therefore sizes its option area at 999,964, an option inside it declaring
    65,535 is under that and is not clamped, and 65,535 octets of zeros are
    synthesised from 36 -- measured, 1,820x, with no warning. Clamping the area
    to ``__length__`` as well removes the step: the payload is then bounded by
    the octets the block was actually handed, whatever it declared.

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
        through :func:`nonnegative`, which is the part of `#678
        <https://github.com/JarryShaw/PyPCAPKit/issues/678>`__ that stops a
        declared length reaching a read at all; the per-block equality is still
        open.

        The nominal span goes through :func:`nonnegative` first here too. That
        closes a hole in this function's own arithmetic: a ``captured_len`` past
        the end of the block makes the span negative, and ``nominal <= available``
        below is then *true*, so the negative was returned unclamped and reached
        a :mod:`struct` template as ``f'{-N}s'``. Measured on 200 Enhanced Packet
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
        three octets therefore arrived here negative and
        :meth:`io.RawIOBase.read` raised a bare ``ValueError``, which is `#678
        <https://github.com/JarryShaw/PyPCAPKit/issues/678>`__. The floor is a
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
            carrying the code itself, when neither declares one. See GitHub
            issue #575.

        Notes:
            :meth:`~pcapkit.const.pcapng.option_type.OptionType.get` mints a
            fresh member -- via :func:`aenum.extend_enum` -- for any code
            neither namespace's row covers, and does so unconditionally on a
            miss: unlike :class:`~pcapkit.const.reg.apptype.AppType`, its
            ``_missing_`` never declines, so it cannot be consulted the way
            :meth:`pcapkit.protocols.schema.transport.tcp.PortEnumField.post_process`
            consults :class:`~pcapkit.const.reg.apptype.AppType`'s. This
            instead replicates the read-only membership test
            :meth:`~pcapkit.const.pcapng.option_type.OptionType.get` itself
            runs first, and only calls it once that test finds the code
            already declared, so an undeclared option type gets
            :meth:`EnumField._unregistered_member` instead of a fresh
            registry row.

        """
        value = super(EnumField, self).post_process(value, packet)
        namespace = self._opt_ns
        members_ns = self._namespace.__members_ns__
        if value not in members_ns.get('opt', {}) and value not in members_ns.get(namespace, {}):
            # NOTE: an unregistered member of self._namespace itself, per
            # GitHub issue #575's owner ruling. ``.opt_name`` and
            # ``.opt_value`` are what a real OptionType member carries --
            # read unconditionally by e.g. pcapng's own ``_option_key`` --
            # and the ``<namespace>_unknown`` name matches what the mint this
            # replaces used to call it, so a rendered or re-keyed member
            # reads the same either way. They are passed in the order
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
                so a class keyword literally called ``namespace`` bound it twice.
                See GitHub issue #439.
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments.

        If ``code`` is provided, the subclass will be registered to the
        :attr:`__enum__` mapping with the given ``code``. If ``code`` is
        not given, the subclass will not be registered.

        Examples:

            .. code-block:: python

               from pcapkit.const.pcapng.option_type import OptionType as Enum_OptionType
               from pcapkit.protocols.schema.misc.pcapng improt Option

               class NewOption(Option, ns='opt', code=Enum_OptionType.opt_new):
                   ...

        See Also:
            - :class:`pcapkit.const.pcapng.option_type.OptionType`

        """
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
        super().__init_subclass__()

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
        unreported overwrite is a parser silently swapped out for another. See
        `#681 <https://github.com/JarryShaw/PyPCAPKit/issues/681>`__ for the
        guard ``register_protocol`` added first, which this one now matches.

        The guard is identity-based: it fires only when the incumbent differs
        from ``cls``, so re-registering the exact same class under the same
        ``code`` is a silent no-op -- in every namespace ``targets`` reaches --
        rather than a warning about nothing displaced. That is what keeps
        :meth:`__init_subclass__` honest: it loops over a ``code`` list with no
        deduplication, so a repeated or aliased entry reaches this method twice
        with the same class, and the second call now finds itself already the
        incumbent. GitHub issue #718 corrected the previous presence-only
        guard, which read every such repeat as a caller mistake whether or not
        the value had actually changed -- the same fix the sibling
        :meth:`register` methods on
        :class:`~pcapkit.protocols.protocol.ProtocolBase` and friends already
        received.

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
    options: 'list[Option]' = OptionField(
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
    options: 'list[Option]' = OptionField(
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
    #: Packet data.
    packet_data: 'bytes' = PayloadField(length=lambda pkt: pkt['captured_len'])
    #: Padding.
    padding_data: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['captured_len'] % 4) % 4)
    #: Options.
    options: 'list[Option]' = OptionField(
        # NOTE: The padding is recomputed here rather than read back from
        # ``padding_data``: a PaddingField is written straight into the schema
        # buffer while packing and never lands in the packet data, so its name
        # is not a key here on the packing path.
        length=bounded_area(lambda pkt: pkt['length'] - 32 - pkt['captured_len']
                                        - (4 - pkt['captured_len'] % 4) % 4),
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

    if TYPE_CHECKING:
        def __init__(self, length: 'int', interface_id: 'int', timestamp_high: 'int',
                     timestamp_low: 'int', captured_len: 'int', original_len: 'int',
                     packet_data: 'bytes | ProtocolBase | Schema',
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
                     packet_data: 'bytes | ProtocolBase | Schema',
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
    resol: 'str' = StringField(length=bounded_option(lambda pkt: pkt['length'] - 4))
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
    """Header schema for PCAP-NG NRB ``nrb_record_ipv6`` records."""

    #: IPv6 address.
    ip: 'IPv6Address' = IPv6AddressField()
    #: Name resolution data.
    resol: 'str' = StringField(length=bounded_option(lambda pkt: pkt['length'] - 16))
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
    name: 'str' = StringField(length=bounded_option(lambda pkt: pkt['length']))
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
    records: 'list[NameResolutionRecord]' = OptionField(
        length=nonnegative(lambda pkt: pkt['length'] - 12),
        base_schema=NameResolutionRecord,
        type_name='type',
        registry=NameResolutionRecord.registry,
        eool=Enum_RecordType.nrb_record_end,
    )
    #: Options.
    options: 'list[Option]' = OptionField(
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
    options: 'list[Option]' = OptionField(
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
            Two ways the entry data runs out mid-field are reported rather than
            raised, for the reason :func:`nonnegative` gives: a bare
            :exc:`struct.error` is neither one of
            :mod:`pcapkit.utilities.exceptions` nor an :exc:`EOFError`, so it
            aborted the whole extraction rather than this one entry. See `#678
            <https://github.com/JarryShaw/PyPCAPKit/issues/678>`__.

            A line of nothing but NUL octets is the block's own 32-bit padding
            and ends the entry. ``bytes.strip()`` takes only ASCII whitespace,
            so those octets survived it and were read as the *name* of a binary
            field -- which made every journal entry whose length is not a
            multiple of four raise, valid or not, since the padding that follows
            it has no 64-bit length prefix behind it to unpack. Measured on a
            14-octet ``MESSAGE=hello\\n`` entry, which is as ordinary as this
            block gets.

            A name line whose 64-bit length prefix is itself cut short ends the
            entry too. There is nothing to read past the end of the entry, so
            stopping at it is what keeps the truncated block parsing.

            A binary field's length is the widest declared length in the format,
            and nothing bounded it against the entry holding it: at ``2**63`` and
            above :meth:`io.BytesIO.read` refuses it outright with a bare
            :exc:`OverflowError` (``cannot fit 'int' into an index-sized
            integer``), and below that it silently returned whatever was there --
            so the same malformed prefix was either fatal or invisible depending
            only on its magnitude. It is clamped to the octets the entry has left
            and reported, which is :func:`nonnegative`'s rule at the other end of
            the same range.

            Field names, keys and values are decoded with ``errors='replace'``
            rather than strictly. A non-UTF-8 octet in any of the three raised a
            bare :exc:`UnicodeDecodeError` -- a :exc:`ValueError`, so foreign on
            both counts, and fatal to the whole extraction over one bad octet in
            one field. ``'replace'`` is the option this module's own
            :class:`~pcapkit.corekit.fields.strings.StringField` already takes for
            the same problem, and a value that is not text is a value the writer
            should have emitted as a *binary* field, so the entry is malformed
            however it is read.

            Entries used to be split apart with ``self.entry.split(b'\\n\\n')``
            before a single field was read -- delimiting a *length-prefixed*
            format by content, which a binary field's own bytes need no
            escaping to defeat. A value that itself contains ``b'\\n\\n'`` was
            cut in the middle of its own data, turning what followed it into a
            bogus field in a fabricated second entry; a value 2,570 octets long
            is worse, since ``struct.pack('<Q', 2570) ==
            b'\\n\\n\\x00\\x00\\x00\\x00\\x00\\x00'`` puts the separator *inside
            the length prefix itself*, so the split landed before a single
            field was read. See `#723
            <https://github.com/JarryShaw/PyPCAPKit/issues/723>`__. The entry is
            now walked once, end to end: a length-prefixed field's bytes are
            never inspected for structure, only counted out by the prefix that
            names them, and a blank line -- found by *reading*, not by
            splitting -- is what starts the next entry. The one-octet
            terminator that must follow a binary field's value, and the warning
            when it is missing, are unchanged from `#722
            <https://github.com/JarryShaw/PyPCAPKit/issues/722>`__; walking the
            buffer whole rather than pre-slicing it also retires that fix's
            newline restoration, which existed only to undo what the slicing
            itself had taken away.

            A trailing separator -- a blank line with nothing behind it -- used
            to be swallowed instead of ending the entry: with nothing left to
            read, the walk stopped without recording that the separator had
            been seen at all, so a rebuild lost that one octet and wrote a
            :attr:`length` one short of what was read. It is now tracked
            explicitly, so a blank line actually read, rather than the block's
            own NUL padding or plain end of data, still starts the next entry --
            even an empty one -- matching what splitting on it always did.

        """
        self = cast('Self', super().post_process(packet))

        data = []  # type: list[OrderedMultiDict[str, str | bytes]]
        total = len(self.entry)
        entry_data = io.BytesIO(self.entry)
        while True:
            entry = OrderedMultiDict()  # type: OrderedMultiDict[str, str | bytes]
            # a blank line that was actually *read* -- as opposed to the
            # block's own NUL padding, or simply running out of octets --
            # is the separator the format puts between entries, so it
            # starts another one, even an empty one, however little is
            # left behind it
            separator = False

            while True:
                raw_line = entry_data.readline()
                line = raw_line.strip()
                if not line:
                    separator = bool(raw_line)
                    break
                if not line.strip(b'\x00'):
                    break

                line_split = line.split(b'=', maxsplit=1)
                if len(line_split) == 2:
                    key, value = line_split
                    entry.add(self._decode_text(key), self._decode_text(value))
                else:
                    prefix = entry_data.read(8)
                    if len(prefix) < 8:
                        warn(f'PCAP-NG: [systemd Journal Export] binary field {line!r} '
                             f'declares its length in {len(prefix)} octet(s) of the 8 it '
                             f'needs; ending the entry', SchemaWarning,
                             stacklevel=stacklevel())
                        break

                    length = struct.unpack('<Q', prefix)[0]  # type: int
                    available = total - entry_data.tell()
                    clamped = length > available
                    if clamped:
                        warn(f'PCAP-NG: [systemd Journal Export] binary field {line!r} '
                             f'declares {length} octet(s) with {available} left in its '
                             f'entry; reading {available}', SchemaWarning,
                             stacklevel=stacklevel())
                        length = available

                    entry.add(self._decode_text(line), entry_data.read(length))

                    if not clamped:
                        # the one octet the format puts here to terminate the
                        # field; a value already clamped to the entry's own end
                        # left nothing behind to check, and was reported above.
                        # the reader's position is well defined either way --
                        # exactly length + 1 octets past where the field name
                        # started -- so a bad octet here ends only this
                        # entry's field collection, matching #722: it does not
                        # abort the walk, which keeps looking for the next
                        # entry's separator from here. See #728's review for
                        # why an outer abort was considered and rejected as
                        # the default.
                        terminator = entry_data.read(1)
                        if terminator != b'\n':
                            warn(f'PCAP-NG: [systemd Journal Export] binary field '
                                 f'{line!r} is not followed by the newline that '
                                 f'terminates it; ending the entry', SchemaWarning,
                                 stacklevel=stacklevel())
                            break

            data.append(entry)
            if entry_data.tell() >= total and not separator:
                break
        self.data = data
        return self

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
    options: 'list[Option]' = OptionField(
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
    #: Packet data.
    packet_data: 'bytes' = PayloadField(length=lambda pkt: pkt['captured_length'])
    #: Padding.
    padding_data: 'bytes' = PaddingField(length=lambda pkt: (4 - pkt['captured_length'] % 4) % 4)
    #: Options.
    options: 'list[Option]' = OptionField(
        # NOTE: see EnhancedPacketBlock.options on why the padding is recomputed
        # here instead of being read back from ``padding_data``.
        length=bounded_area(lambda pkt: pkt['length'] - 32 - pkt['captured_length']
                                        - (4 - pkt['captured_length'] % 4) % 4),
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

    if TYPE_CHECKING:
        def __init__(self, length: 'int', interface_id: 'int', drop_count: 'int',
                     timestamp_high: 'int', timestamp_low: 'int', captured_length: 'int',
                     original_length: 'int', packet_data: 'bytes | ProtocolBase | Schema',
                     options: 'list[Option | bytes] | bytes', length2: 'int') -> 'None': ...
