# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for NGAP protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.fields.strings import BytesField
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['NGAP']


@schema_final
class NGAP(Schema):
    """Header schema for NGAP packet.

    NGAP has no header of its own: an SCTP DATA chunk whose payload protocol
    identifier names NGAP carries exactly one aligned-PER-encoded ``NGAP-PDU``
    and nothing else, so there is no length field to read and no framing to
    resolve. The whole payload is the encoding, and its structure only becomes
    visible once the ASN.1 decoder has run.

    """

    #: Aligned PER encoding of one ``NGAP-PDU``.
    data: 'bytes' = BytesField(lambda pkt: pkt['__length__'])

    if TYPE_CHECKING:
        def __init__(self, data: 'bytes') -> 'None': ...
