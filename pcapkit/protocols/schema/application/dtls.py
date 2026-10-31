# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for DTLS protocol"""

from typing import TYPE_CHECKING

from pcapkit.const.tls.content_type import ContentType as Enum_ContentType
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import EnumField, NumberField, UInt16Field
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['DTLS']

if TYPE_CHECKING:
    from pcapkit.protocols.protocol import ProtocolBase


@schema_final
class DTLS(Schema):
    """Header schema for DTLS record layer packet.

    Same :class:`ContentType <pcapkit.const.tls.content_type.ContentType>`,
    legacy-version and length fields as :class:`TLS
    <pcapkit.protocols.schema.application.tls.TLS>`'s record header, with the
    explicit ``epoch``/``sequence_number`` pair DTLS inserts between the
    version and the length (:rfc:`9147#section-4`) -- the divergence a
    reliable TLS stream never needs, since DTLS runs over an unreliable,
    unordered datagram transport.

    """

    #: Content type.
    content_type: 'Enum_ContentType' = EnumField(length=1, namespace=Enum_ContentType)
    #: Legacy record version (``major << 8 | minor``).
    version: 'int' = UInt16Field()
    #: Epoch -- incremented on every change of cipher state.
    epoch: 'int' = UInt16Field()
    #: Sequence number within :attr:`epoch` (48-bit).
    sequence_number: 'int' = NumberField(length=6, signed=False)
    #: Length of :attr:`fragment`.
    length: 'int' = UInt16Field()
    #: Record fragment, undecoded.
    fragment: 'bytes' = BytesField(length=lambda pkt: pkt['length'])
    #: Octets after the record, e.g. a further record coalesced in the same
    #: buffer.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, content_type: 'Enum_ContentType', version: 'int', epoch: 'int',
                     sequence_number: 'int', length: 'int', fragment: 'bytes',
                     payload: 'bytes | ProtocolBase | Schema') -> 'None': ...
