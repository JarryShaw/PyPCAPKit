# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for simple mail transfer protocol

.. versionadded:: 1.10.0

"""

from typing import TYPE_CHECKING

from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema import Schema, schema_final

__all__ = ['SMTP']


@schema_final
class SMTP(Schema):
    """Header schema for SMTP packet."""

    #: Packet data.
    data: 'bytes' = BytesField(lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, data: 'bytes') -> 'None': ...
