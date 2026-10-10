# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for BSD loopback encapsulation"""

from typing import TYPE_CHECKING

from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['Loopback']

if TYPE_CHECKING:
    from pcapkit.protocols.protocol import ProtocolBase


@schema_final
class Loopback(Schema):
    """Header schema for BSD loopback encapsulation.

    The address family is kept as its 4 octets, since their byte order depends
    on the link type the frame was captured under; see
    :func:`~pcapkit.protocols.link.loopback.family_byteorder`.

    """

    #: Address family.
    family: 'bytes' = BytesField(length=4)
    #: Payload.
    payload: 'bytes' = PayloadField(length=lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, family: 'bytes', payload: 'bytes | ProtocolBase | Schema') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
