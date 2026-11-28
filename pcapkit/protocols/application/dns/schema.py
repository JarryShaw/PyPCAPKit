# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for DNS protocol

:func:`compress_name` and :func:`record_name` lay a message's names out against
the compression of :rfc:`1035#section-4.1.4`, for the codec of
:mod:`pcapkit.corekit.schema.domain_name`.

.. versionremoved:: 1.9.0

   ``pcapkit.protocols.application.dns.schema.read_name``,
   ``pcapkit.protocols.application.dns.schema.make_name``,
   ``pcapkit.protocols.application.dns.schema.name_to_text`` and
   ``pcapkit.protocols.application.dns.schema.text_to_labels``, now in
   :mod:`pcapkit.corekit.schema.domain_name` (:issue:`2934`).

"""

from typing import TYPE_CHECKING

from pcapkit.corekit.const.domain_name import POINTER_LIMIT
from pcapkit.corekit.fields.misc import ConditionalField, PayloadField
from pcapkit.corekit.fields.numbers import UInt16Field
from pcapkit.corekit.fields.strings import BitField, BytesField
from pcapkit.protocols.application.dns.const import HEADER_LENGTH
from pcapkit.protocols.schema import Schema, schema_final

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


def compress_name(labels: 'Sequence[bytes]', table: 'dict[tuple[bytes, ...], int]',
                  offset: 'int') -> 'tuple[int, Optional[int]]':
    """Choose how to write a name against the names already written.

    Args:
        labels: Every label of the name, the root's left out.
        table: Each label suffix already written, by its offset; the suffixes
            this name writes in full are added to it.
        offset: Offset the name is written at.

    Returns:
        The ``literal`` and ``pointer`` for
        :func:`~pcapkit.corekit.schema.domain_name.make_name`: the longest
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
