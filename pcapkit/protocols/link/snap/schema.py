# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for IEEE 802 Subnetwork Access Protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import UInt16Field
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema import Schema, schema_final

__all__ = ['SNAP']

if TYPE_CHECKING:
    from pcapkit.protocols.protocol import ProtocolBase


@schema_final
class SNAP(Schema):
    """Header schema for SNAP headers."""

    #: Organizationally Unique Identifier.
    oui: 'bytes' = BytesField(length=3)
    #: Protocol identifier.
    pid: 'int' = UInt16Field()
    #: Payload.
    payload: 'bytes' = PayloadField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, oui: 'bytes', pid: 'int', payload: 'bytes | ProtocolBase | Schema') -> 'None': ...
