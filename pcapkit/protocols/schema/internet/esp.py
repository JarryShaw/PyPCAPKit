# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for encapsulating security payload"""

from typing import TYPE_CHECKING

from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import UInt32Field
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['ESP']

if TYPE_CHECKING:
    from pcapkit.protocols.protocol import ProtocolBase as Protocol


@schema_final
class ESP(Schema):
    """Header schema for ESP packet.

    Notes:
        Only the two fixed fields of :rfc:`4303` -- ``SPI`` and ``Sequence
        Number`` -- can be described declaratively. Everything after them
        (the payload data, including any cryptographic synchronisation such
        as an IV, the ESP trailer and the optional Integrity Check Value) is
        of a length that is a property of the Security Association rather
        than of the packet, so it is captured verbatim as :attr:`payload`
        and split by :meth:`ESP.read <pcapkit.protocols.internet.esp.ESP.read>`.

        This also means :attr:`payload` is **not** the next layer's data:
        the next layer lives inside the ciphertext, and is handed to
        :meth:`Protocol._decode_next_layer <pcapkit.protocols.protocol.ProtocolBase._decode_next_layer>`
        explicitly once decrypted.

    """

    #: Security parameters index.
    spi: 'int' = UInt32Field()
    #: Sequence number field.
    seq: 'int' = UInt32Field()
    #: Payload data, ESP trailer and integrity check value, verbatim.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, spi: 'int', seq: 'int',
                     payload: 'bytes | Protocol | Schema') -> 'None': ...
