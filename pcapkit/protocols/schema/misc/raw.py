# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for raw packet"""

from typing import TYPE_CHECKING

from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['Raw']

if TYPE_CHECKING:
    from pcapkit.protocols.protocol import ProtocolBase as Protocol


@schema_final
class Raw(Schema):
    """Schema for raw packet."""

    #: Packet data.
    packet: 'bytes' = PayloadField(length=lambda x: x['__length__'], default=b'')

    if TYPE_CHECKING:
        def __init__(self, packet: 'bytes | Schema | Protocol') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
