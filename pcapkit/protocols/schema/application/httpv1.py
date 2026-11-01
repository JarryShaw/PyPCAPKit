# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for HTTP/1.* protocol

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.application.httpv1.HTTP``, with no alias. The
   class is renamed :class:`~pcapkit.protocols.schema.application.httpv1.HTTPv1`,
   after its module (:issue:`2529`).

"""

from typing import TYPE_CHECKING

from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['HTTPv1']


@schema_final
class HTTPv1(Schema):
    r"""Header schema for HTTP/1.\* packet.

    .. versionchanged:: 1.6.0

       Renamed from ``HTTP``, after its module (:issue:`2529`).

    """

    #: Packet data.
    data: 'bytes' = BytesField(lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, data: 'bytes') -> 'None': ...
