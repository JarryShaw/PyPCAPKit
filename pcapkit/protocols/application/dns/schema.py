# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for DNS protocol

The domain name codec below reads and writes the label sequence of
:rfc:`1035#section-3.1` with the compression of :rfc:`1035#section-4.1.4`. It
works on octets and labels alone, so other protocols carrying domain names,
such as NDP's DNSSL option (:rfc:`8106#section-5.2`, uncompressed) and DHCP's
domain search option (:rfc:`3397#section-2`), can reuse it.

"""

from typing import TYPE_CHECKING

from pcapkit.corekit.fields.misc import ConditionalField, PayloadField
from pcapkit.corekit.fields.numbers import UInt16Field
from pcapkit.corekit.fields.strings import BitField, BytesField
from pcapkit.protocols.schema import Schema, schema_final
from pcapkit.utilities.exceptions import ProtocolError

__all__ = ['DNS']

if TYPE_CHECKING:
    from typing import Any, Optional, Sequence

    from typing_extensions import TypedDict

    from pcapkit.protocols.protocol import ProtocolBase

    class Flags(TypedDict):
        """DNS header flags."""

        #: Query or response.
        qr: int
        #: Kind of query.
        opcode: int
        #: Authoritative answer.
        aa: int
        #: Truncation.
        tc: int
        #: Recursion desired.
        rd: int
        #: Recursion available.
        ra: int
        #: Reserved bit.
        z: int
        #: Authentic data.
        ad: int
        #: Checking disabled.
        cd: int
        #: Response code.
        rcode: int

#: Length of the fixed header, before the sections (:rfc:`1035#section-4.1.1`).
HEADER_LENGTH = 12

#: Largest offset a compression pointer can carry, in its 14 bits.
POINTER_LIMIT = 0x3FFF


def read_name(data: 'bytes', pos: 'int', *, compression: 'bool' = True,
              alias: 'str' = 'DNS') -> 'tuple[tuple[bytes, ...], int, Optional[int], int]':
    """Read the domain name at ``pos`` in ``data``.

    Args:
        data: The octets compression pointers are offsets into, i.e. the whole
            DNS message for DNS.
        pos: Offset of the name in ``data``.
        compression: Whether a compression pointer may end the name.
        alias: Prefix of the error message.

    Returns:
        Every label of the name, the root's left out; how many of them are
        written in full at ``pos``; the offset the pointer ending the name
        there points to, or :obj:`None` where the root label ends it; and the
        offset just past the name at ``pos``.

    Raises:
        ProtocolError: If the name runs past the end of ``data``, holds a
            label type other than a plain label or, where ``compression``
            allows one, a pointer (:rfc:`6891#section-5`), or its pointers
            loop.

    """
    labels = []  # type: list[bytes]
    literal = None  # type: Optional[int]
    pointer = None  # type: Optional[int]
    end = None  # type: Optional[int]
    seen = set()  # type: set[int]
    cur = pos
    while True:
        if cur >= len(data):
            raise ProtocolError(f'{alias}: invalid format: domain name runs past the end of the buffer')
        octet = data[cur]
        if octet & 0xC0 == 0xC0:
            if not compression:
                raise ProtocolError(f'{alias}: invalid format: compression pointer in an uncompressed name')
            if cur + 1 >= len(data):
                raise ProtocolError(f'{alias}: invalid format: compression pointer runs past the end of the buffer')
            target = ((octet & 0x3F) << 8) | data[cur + 1]
            if end is None:
                literal, pointer, end = len(labels), target, cur + 2
            if target in seen:
                raise ProtocolError(f'{alias}: invalid format: compression pointer loop at offset {target}')
            seen.add(target)
            cur = target
            continue
        if octet & 0xC0:
            raise ProtocolError(f'{alias}: invalid format: unsupported label type {octet >> 6:#04b}')
        if octet == 0:
            if end is None:
                literal, end = len(labels), cur + 1
            return tuple(labels), literal, pointer, end  # type: ignore[return-value]
        label = data[cur + 1:cur + 1 + octet]
        if len(label) != octet:
            raise ProtocolError(f'{alias}: invalid format: domain name label runs past the end of the buffer')
        labels.append(label)
        cur += 1 + octet


def make_name(labels: 'Sequence[bytes]', *, literal: 'Optional[int]' = None, pointer: 'Optional[int]' = None,
              alias: 'str' = 'DNS') -> 'bytes':
    """Write a domain name, the inverse of :func:`read_name`.

    Args:
        labels: Every label of the name, the root's left out.
        literal: How many of ``labels`` to write in full; all of them if
            :obj:`None`.
        pointer: Offset a compression pointer after them points to, or
            :obj:`None` to end the name with the root label.
        alias: Prefix of the error message.

    Returns:
        The name's octets.

    Raises:
        ProtocolError: If a label written is empty or longer than 63 octets,
            ``literal`` is not a count of ``labels``, or ``pointer`` does not
            fit in 14 bits.

    """
    count = len(labels) if literal is None else literal
    if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= len(labels):
        raise ProtocolError(f'{alias}: invalid domain name layout: {count!r} of {len(labels)} labels')
    out = bytearray()
    for label in labels[:count]:
        if not isinstance(label, (bytes, bytearray)) or not 1 <= len(label) <= 63:
            raise ProtocolError(f'{alias}: invalid domain name label: {label!r}')
        out.append(len(label))
        out += label
    if pointer is None:
        out.append(0)
    elif isinstance(pointer, bool) or not isinstance(pointer, int) or not 0 <= pointer <= POINTER_LIMIT:
        raise ProtocolError(f'{alias}: invalid compression pointer: {pointer!r}')
    else:
        out += (0xC000 | pointer).to_bytes(2, 'big')
    return bytes(out)


def compress_name(labels: 'Sequence[bytes]', table: 'dict[tuple[bytes, ...], int]',
                  offset: 'int') -> 'tuple[int, Optional[int]]':
    """Choose how to write a name against the names already written.

    Args:
        labels: Every label of the name, the root's left out.
        table: Each label suffix already written, by its offset; the suffixes
            this name writes in full are added to it.
        offset: Offset the name is written at.

    Returns:
        The ``literal`` and ``pointer`` for :func:`make_name`: the longest
        suffix in ``table`` is pointed to, and the labels before it written.

    """
    literal, pointer = len(labels), None  # type: int, Optional[int]
    for index in range(len(labels)):
        suffix = tuple(labels[index:])
        if suffix in table:
            literal, pointer = index, table[suffix]
            break
    record_name(labels, literal, table, offset)
    return literal, pointer


def record_name(labels: 'Sequence[bytes]', literal: 'int', table: 'dict[tuple[bytes, ...], int]',
                offset: 'int') -> 'None':
    """Add the label suffixes a name writes in full to ``table``.

    Args:
        labels: Every label of the name, the root's left out.
        literal: How many of ``labels`` the name writes in full.
        table: Each label suffix already written, by its offset.
        offset: Offset the name is written at.

    """
    pos = offset
    for index in range(min(literal, len(labels))):
        if pos <= POINTER_LIMIT:
            table.setdefault(tuple(labels[index:]), pos)
        pos += 1 + len(labels[index])


def name_to_text(labels: 'Sequence[bytes]') -> 'str':
    """Render labels in presentation form (:rfc:`1035#section-5.1`).

    Args:
        labels: Every label of the name, the root's left out.

    Returns:
        The absolute name, e.g. ``www.example.com.``, with ``.`` and ``\\``
        escaped by a backslash, and any octet outside printable ASCII or a
        space as ``\\DDD``; the root is ``.``.

    """
    parts = []
    for label in labels:
        text = []
        for octet in label:
            char = chr(octet)
            if char in '.\\':
                text.append(f'\\{char}')
            elif 0x21 <= octet <= 0x7E:
                text.append(char)
            else:
                text.append(f'\\{octet:03d}')
        parts.append(''.join(text))
    return '.'.join(parts) + '.'


def text_to_labels(text: 'str', *, alias: 'str' = 'DNS') -> 'tuple[bytes, ...]':
    """Read a name in presentation form into labels, the inverse of :func:`name_to_text`.

    Args:
        text: The name; the trailing ``.`` is optional, and ``''`` or ``.``
            is the root.
        alias: Prefix of the error message.

    Returns:
        Every label of the name, the root's left out.

    Raises:
        ProtocolError: If ``text`` holds an empty label, or a backslash not
            followed by a character or by three decimal digits up to 255.

    """
    if text in ('', '.'):
        return ()
    labels = []  # type: list[bytes]
    label = bytearray()
    pos = 0
    while pos < len(text):
        char = text[pos]
        if char == '\\':
            digits = text[pos + 1:pos + 4]
            if len(digits) == 3 and digits.isdigit() and int(digits) <= 255:
                label.append(int(digits))
                pos += 4
                continue
            if pos + 1 >= len(text) or text[pos + 1].isdigit():
                raise ProtocolError(f'{alias}: invalid domain name escape: {text!r}')
            label += text[pos + 1].encode('utf-8')
            pos += 2
            continue
        if char == '.':
            if not label:
                raise ProtocolError(f'{alias}: invalid domain name: empty label in {text!r}')
            labels.append(bytes(label))
            label = bytearray()
            pos += 1
            continue
        label += char.encode('utf-8')
        pos += 1
    if label:
        labels.append(bytes(label))
    return tuple(labels)


def dns_body_length(pkt: 'dict[str, Any]') -> 'int':
    """Length of :attr:`DNS.body`.

    Args:
        pkt: Packet data.

    Returns:
        Over TCP, the message length the prefix gives less the header; else
        the rest of the data. Packing, where ``__length__`` is unset, the
        body as given.

    """
    if pkt['__framed__'] and pkt['__length__'] >= 0:
        return max(pkt['length'] - HEADER_LENGTH, 0)
    return pkt['__length__']


@schema_final
class DNS(Schema):
    """Header schema for DNS message.

    The two-octet length precedes the message over TCP alone
    (:rfc:`1035#section-4.2.2`), which ``__framed__`` in the packet context
    says when unpacking; packing, a :attr:`length` given says it.

    """

    #: Message length, over TCP.
    length: 'Optional[int]' = ConditionalField(
        UInt16Field(),
        lambda pkt: pkt['__framed__'],
    )
    #: Identifier.
    id: 'int' = UInt16Field()
    #: Flags.
    flags: 'Flags' = BitField(length=2, namespace={
        'qr': (0, 1),
        'opcode': (1, 4),
        'aa': (5, 1),
        'tc': (6, 1),
        'rd': (7, 1),
        'ra': (8, 1),
        'z': (9, 1),
        'ad': (10, 1),
        'cd': (11, 1),
        'rcode': (12, 4),
    })
    #: Number of question entries.
    qdcount: 'int' = UInt16Field()
    #: Number of answer records.
    ancount: 'int' = UInt16Field()
    #: Number of authority records.
    nscount: 'int' = UInt16Field()
    #: Number of additional records.
    arcount: 'int' = UInt16Field()
    #: The four sections, undecoded.
    body: 'bytes' = BytesField(length=dns_body_length)
    #: Octets after the message, e.g. a further message over TCP.
    payload: 'bytes' = PayloadField()

    @classmethod
    def pre_unpack(cls, packet: 'dict[str, Any]') -> 'None':
        """Prepare ``packet`` data for unpacking process.

        Args:
            packet: packet data

        """
        packet.setdefault('__framed__', False)

    def pre_pack(self, packet: 'dict[str, Any]') -> 'None':
        """Prepare ``packet`` data for packing process.

        Args:
            packet: packet data

        """
        packet['__framed__'] = packet.get('length') is not None

    if TYPE_CHECKING:
        def __init__(self, length: 'Optional[int]', id: 'int', flags: 'Flags', qdcount: 'int',
                     ancount: 'int', nscount: 'int', arcount: 'int', body: 'bytes',
                     payload: 'bytes | ProtocolBase | Schema') -> 'None': ...
