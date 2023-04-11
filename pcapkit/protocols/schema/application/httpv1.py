# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for HTTP/1.* protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema.schema import Schema

__all__ = ['HTTP']


class HTTP(Schema):
    """Header schema for HTTP/1.\* packet."""

    #: Packet data.
    data: 'bytes' = BytesField(lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, data: 'bytes') -> 'None': ...
