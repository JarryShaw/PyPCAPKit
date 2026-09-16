# -*- coding: utf-8 -*-
"""data models for NGAP protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from typing import Any

    from pcapkit.protocols.application.ngap import Criticality, PDUKind, ProcedureCode, ProtocolIE

__all__ = [
    'NGAP',
    'IE', 'Choice', 'BitString', 'Sequence',
]


@info_final
class Sequence(Data):
    """Data model for an ASN.1 ``SEQUENCE``, ``SET`` or ``SEQUENCE OF`` member.

    Fields are whatever the specification names them, so this model carries no
    fixed annotations: it is populated from the decoded value tree. ASN.1
    identifiers are hyphenated where Python identifiers cannot be, e.g.
    ``gNB-ID``, so such fields are reachable by subscription
    (``seq['gNB-ID']``) rather than by attribute access.

    """


@info_final
class BitString(Data):
    """Data model for an ASN.1 ``BIT STRING``.

    A bit string is not a whole number of octets, so its length is carried
    alongside its value rather than being implied by it -- ``gNB-ID`` is a
    22-to-32-bit field, and ``(0x000102, 24)`` and ``(0x000102, 32)`` are
    different identifiers.

    """

    #: Bits, as a big-endian unsigned integer.
    value: 'int'
    #: Number of significant bits in :attr:`value`.
    length: 'int'

    if TYPE_CHECKING:
        def __init__(self, value: 'int', length: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class Choice(Data):
    """Data model for an ASN.1 ``CHOICE`` alternative or open type.

    Both the selected alternative's name and its value are kept, since the name
    is the only thing that says *which* of the alternatives was sent -- an
    ``NGAP-PDU`` carrying ``('globalGNB-ID', ...)`` and one carrying
    ``('globalNgENB-ID', ...)`` are otherwise indistinguishable once the value
    has been converted.

    """

    #: Name of the selected alternative, as spelled in 3GPP TS 38.413.
    name: 'str'
    #: Value of the selected alternative.
    value: 'Any'

    if TYPE_CHECKING:
        def __init__(self, name: 'str', value: 'Any') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class IE(Data):
    """Data model for one NGAP protocol information element."""

    #: Protocol IE ID.
    id: 'ProtocolIE'
    #: Criticality, i.e. what a receiver must do when it does not understand
    #: :attr:`id`.
    criticality: 'Criticality'
    #: Name of the IE's open type, as spelled in 3GPP TS 38.413. This is not
    #: always :attr:`id`'s own spelling -- IE 21 is ``id-DefaultPagingDRX``
    #: but its value is keyed ``PagingDRX``.
    type: 'str'
    #: Value of the IE.
    value: 'Any'

    if TYPE_CHECKING:
        def __init__(self, id: 'ProtocolIE', criticality: 'Criticality', type: 'str', value: 'Any') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin,line-too-long


@info_final
class NGAP(Protocol):
    """Data model for NGAP protocol.

    The three ``NGAP-PDU`` alternatives -- ``initiatingMessage``,
    ``successfulOutcome`` and ``unsuccessfulOutcome`` -- carry an identical
    field set and are distinguished by :attr:`kind` rather than by three
    near-identical models.

    """

    #: Which of the three ``NGAP-PDU`` alternatives this is.
    kind: 'PDUKind'
    #: Procedure code.
    procedure: 'ProcedureCode'
    #: Criticality of the procedure.
    criticality: 'Criticality'
    #: Name of the message type, e.g. ``NGSetupRequest``.
    message: 'str'
    #: Protocol IEs of the message, in the order they were encoded. Empty for
    #: the few messages that carry no ``protocolIEs`` field.
    ies: 'tuple[IE, ...]'
    #: The message body, converted in full. :attr:`ies` is a flattened view of
    #: its ``protocolIEs`` field, so anything not surfaced above is reachable
    #: here.
    value: 'Sequence'

    if TYPE_CHECKING:
        def __init__(self, kind: 'PDUKind', procedure: 'ProcedureCode', criticality: 'Criticality', message: 'str', ies: 'tuple[IE, ...]', value: 'Sequence') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long
