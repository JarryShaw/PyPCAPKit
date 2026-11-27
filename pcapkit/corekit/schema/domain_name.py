# -*- coding: utf-8 -*-
"""Domain Name Codec
=======================

.. module:: pcapkit.corekit.schema.domain_name

:mod:`pcapkit.corekit.schema.domain_name` reads and writes the label sequence of
:rfc:`1035#section-3.1`, with the compression pointers of
:rfc:`1035#section-4.1.4`, and renders it in presentation form. It works on
octets and labels alone, for DNS and for ICMPv6's DNS Search List option
(:rfc:`8106#section-5.2`), which carries its names uncompressed. It is one of the
:mod:`pcapkit.corekit.schema` helpers shared across the schema layer, not part of
the header schema framework in :mod:`pcapkit.protocols.schema`; see
:ref:`utilities-or-corekit`.

.. versionadded:: 1.9.0

   Moved here from ``pcapkit.protocols.application.dns.schema`` (:issue:`2934`).

"""

from typing import TYPE_CHECKING

from pcapkit.corekit.const.domain_name import POINTER_LIMIT
from pcapkit.utilities.exceptions import ProtocolError

__all__ = ['read_name', 'make_name', 'name_to_text', 'text_to_labels']

if TYPE_CHECKING:
    from typing import Optional, Sequence


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
