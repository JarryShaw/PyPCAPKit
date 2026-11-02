# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for DTLS protocol"""

from typing import TYPE_CHECKING

from pcapkit.const.tls.content_type import ContentType as Enum_ContentType
from pcapkit.corekit.fields.misc import ConditionalField, PayloadField, SwitchField
from pcapkit.corekit.fields.numbers import EnumField, NumberField, UInt8Field, UInt16Field
from pcapkit.corekit.fields.strings import BitField, BytesField
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['DTLS', 'DTLSCiphertext', 'DTLSCIDCiphertext']

if TYPE_CHECKING:
    from typing import Any

    from pcapkit.protocols.protocol import ProtocolBase


@schema_final
class DTLS(Schema):
    """Header schema for DTLS record layer packet.

    Same :class:`ContentType <pcapkit.const.tls.content_type.ContentType>`,
    legacy-version and length fields as :class:`TLS
    <pcapkit.protocols.schema.application.tls.TLS>`'s record header, with the
    explicit ``epoch``/``sequence_number`` pair DTLS inserts between the
    version and the length (:rfc:`9147#section-4`) -- the divergence a
    reliable TLS stream never needs, since DTLS runs over an unreliable,
    unordered datagram transport.

    """

    #: Content type.
    content_type: 'Enum_ContentType' = EnumField(length=1, namespace=Enum_ContentType)
    #: Legacy record version (``major << 8 | minor``).
    version: 'int' = UInt16Field()
    #: Epoch -- incremented on every change of cipher state.
    epoch: 'int' = UInt16Field()
    #: Sequence number within :attr:`epoch` (48-bit).
    sequence_number: 'int' = NumberField(length=6, signed=False)
    #: Length of :attr:`fragment`.
    length: 'int' = UInt16Field()
    #: Record fragment, undecoded.
    fragment: 'bytes' = BytesField(length=lambda pkt: pkt['length'])
    #: Octets after the record, e.g. a further record coalesced in the same
    #: buffer.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, content_type: 'Enum_ContentType', version: 'int', epoch: 'int',
                     sequence_number: 'int', length: 'int', fragment: 'bytes',
                     payload: 'bytes | ProtocolBase | Schema') -> 'None': ...


@schema_final
class DTLSCiphertext(Schema):
    """Header schema for a DTLS 1.3 ciphertext record, which has a unified header.

    The first octet is ``001CSLEE`` (:rfc:`9147#section-4.1`): ``C`` names a
    connection ID, ``S`` an 8- or 16-bit sequence number, ``L`` a length field,
    and ``EE`` the low two bits of the epoch. The record has no content type or
    version octet, since both are inside the ciphertext, so
    :class:`DTLS <pcapkit.protocols.schema.application.dtls.DTLS>`'s legacy
    header cannot describe it.

    """

    #: Unified-header first octet: fixed prefix, ``C``, ``S``, ``L`` and ``EE``.
    flags: 'dict[str, int]' = BitField(length=1, namespace={
        'fixed': (0, 3),
        'connection_id': (3, 1),
        'sequence_long': (4, 1),
        'length_present': (5, 1),
        'epoch': (6, 2),
    })
    #: Sequence number, 8 or 16 bits as ``S`` says (header-protected on the wire).
    sequence_number: 'int' = SwitchField(
        selector=lambda pkt: UInt16Field() if pkt['flags']['sequence_long'] else UInt8Field(),
    )
    #: Length of :attr:`fragment`; absent when ``L`` is clear.
    length: 'int | None' = ConditionalField(
        UInt16Field(),
        condition=lambda pkt: bool(pkt['flags']['length_present']),
    )
    #: Ciphertext, undecoded. Without a length it runs to the end of the buffer.
    fragment: 'bytes' = SwitchField(
        selector=lambda pkt: (BytesField(length=pkt['length'])
                              if pkt['flags']['length_present'] else PayloadField()),
    )
    #: Octets after the record, e.g. a further record coalesced in the same
    #: buffer. Empty when :attr:`fragment` runs to the end of the buffer.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, flags: 'dict[str, int]', sequence_number: 'int', length: 'int | None', fragment: 'bytes', payload: 'bytes | ProtocolBase | Schema') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@schema_final
class DTLSCIDCiphertext(Schema):
    """Header schema for a DTLS 1.2 record with a connection ID (:rfc:`9146#section-4`).

    :class:`DTLS <pcapkit.protocols.schema.application.dtls.DTLS>`'s legacy
    header with ``cid`` between the sequence number and the length. The record
    does not carry the CID's length, so the parser gives it as the
    ``__cid_length__`` key of the packet context; packing takes it from ``cid``.

    """

    #: Outer content type, always ``tls12_cid``.
    content_type: 'Enum_ContentType' = EnumField(length=1, namespace=Enum_ContentType)
    #: Legacy record version (``major << 8 | minor``).
    version: 'int' = UInt16Field()
    #: Epoch -- incremented on every change of cipher state.
    epoch: 'int' = UInt16Field()
    #: Sequence number within :attr:`epoch` (48-bit).
    sequence_number: 'int' = NumberField(length=6, signed=False)
    #: Connection ID.
    cid: 'bytes' = BytesField(length=lambda pkt: pkt['__cid_length__'])
    #: Length of :attr:`fragment`.
    length: 'int' = UInt16Field()
    #: Encrypted record content, undecoded.
    fragment: 'bytes' = BytesField(length=lambda pkt: pkt['length'])
    #: Octets after the record, e.g. a further record coalesced in the same
    #: buffer.
    payload: 'bytes' = PayloadField()

    def pre_pack(self, packet: 'dict[str, Any]') -> 'None':
        """Give packing the length of :attr:`cid`, which the record does not carry.

        Args:
            packet: packet data

        """
        packet['__cid_length__'] = len(packet['cid'])

    if TYPE_CHECKING:
        def __init__(self, content_type: 'Enum_ContentType', version: 'int', epoch: 'int', sequence_number: 'int', cid: 'bytes', length: 'int', fragment: 'bytes', payload: 'bytes | ProtocolBase | Schema') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long
