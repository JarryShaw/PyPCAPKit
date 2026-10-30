# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for TLS protocol"""

from typing import TYPE_CHECKING

from pcapkit.const.tls.content_type import ContentType as Enum_ContentType
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt16Field
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['TLS']

if TYPE_CHECKING:
    from pcapkit.protocols.protocol import ProtocolBase


@schema_final
class TLS(Schema):
    """Header schema for TLS record layer packet.

    The record header has :class:`DTLS
    <pcapkit.protocols.schema.application.dtls.DTLS>`'s fields minus the epoch
    and sequence number (:rfc:`9846#section-5.1`). :attr:`fragment` is decoded
    by :class:`~pcapkit.protocols.application.ssl.SSL`, which DTLS shares.

    """

    #: Content type.
    content_type: 'Enum_ContentType' = EnumField(length=1, namespace=Enum_ContentType)
    #: Legacy record version (``major << 8 | minor``).
    version: 'int' = UInt16Field()
    #: Length of :attr:`fragment`.
    length: 'int' = UInt16Field()
    #: Record fragment, undecoded.
    fragment: 'bytes' = BytesField(length=lambda pkt: pkt['length'])
    #: Octets after the record, e.g. a further record coalesced in the same
    #: buffer.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, content_type: 'Enum_ContentType', version: 'int', length: 'int',
                     fragment: 'bytes', payload: 'bytes | ProtocolBase | Schema') -> 'None': ...
