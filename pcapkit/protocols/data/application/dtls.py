# -*- coding: utf-8 -*-
"""data models for DTLS protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.application.tls import Handshake
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from typing import Any, Optional, Union

    from pcapkit.const.tls.content_type import ContentType as Enum_ContentType
    from pcapkit.const.tls.handshake_type import HandshakeType as Enum_HandshakeType
    from pcapkit.protocols.data.application.tls import ClientHello, EncryptedExtensions, ServerHello

__all__ = [
    'DTLS',
    'DTLSCiphertext',
    'DTLSCIDCiphertext',

    'DTLSHandshake',
]


@info_final
class DTLSHandshake(Handshake):
    """Data model for a DTLS handshake message.

    DTLS adds a fragment header -- ``message_seq``, ``fragment_offset`` and
    ``fragment_length`` -- on top of the TLS handshake header shared with
    :class:`~pcapkit.protocols.data.application.tls.Handshake`
    (:rfc:`6347#section-4.2.2`), so that a handshake message that does not fit
    in one datagram can be split across several.

    :attr:`body` decodes to a :class:`~pcapkit.protocols.data.application.tls.ClientHello`,
    :class:`~pcapkit.protocols.data.application.tls.ServerHello` or
    :class:`~pcapkit.protocols.data.application.tls.EncryptedExtensions` when
    :attr:`is_fragmented` is :data:`False`. A fragmented message's :attr:`body`
    is the fragment's raw octets;
    :func:`~pcapkit.foundation.analysis.dtls.dtls_handshake` decodes the
    message once :class:`~pcapkit.foundation.reassembly.dtls.DTLS` has
    reassembled it (:issue:`2440`).

    """

    #: Handshake message type.
    msg_type: 'Enum_HandshakeType'
    #: Total message length (24-bit), fragment headers and bodies excluded.
    length: 'int'
    #: Message body -- see the class docstring for when this decodes.
    body: 'Union[ClientHello, ServerHello, EncryptedExtensions, bytes]'
    #: Message sequence number.
    message_seq: 'int'
    #: Fragment offset (24-bit) into the reassembled message.
    fragment_offset: 'int'
    #: Length (24-bit) of this fragment.
    fragment_length: 'int'
    #: Whether this fragment is a strict subset of the message, i.e.
    #: ``fragment_offset != 0`` or ``fragment_length != length``.
    is_fragmented: 'bool'

    if TYPE_CHECKING:
        def __init__(self, msg_type: 'Enum_HandshakeType', length: 'int', body: 'Union[ClientHello, ServerHello, EncryptedExtensions, bytes]', message_seq: 'int', fragment_offset: 'int', fragment_length: 'int', is_fragmented: 'bool') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class DTLS(Protocol):
    """Data model for DTLS protocol."""

    #: Content type.
    content_type: 'Enum_ContentType'
    #: Legacy record version (``major << 8 | minor``).
    version: 'int'
    #: Epoch -- incremented on every change of cipher state.
    epoch: 'int'
    #: Sequence number within :attr:`epoch` (48-bit).
    sequence_number: 'int'
    #: Length of the record fragment.
    length: 'int'
    #: Decoded record content. For ``handshake``, ``alert``, and
    #: ``change_cipher_spec``, this is a tuple of :class:`DTLSHandshake`, an
    #: :class:`~pcapkit.protocols.data.application.tls.Alert`, or a
    #: :class:`~pcapkit.protocols.data.application.tls.ChangeCipherSpec`
    #: respectively *only when the record is cleartext*, i.e. ``epoch == 0``
    #: (as decided by :meth:`SSL._tls_content_is_cleartext
    #: <pcapkit.protocols.application.ssl.SSL._tls_content_is_cleartext>`) --
    #: an encrypted record of any of those three types, which is any record
    #: at a later epoch, stays raw :obj:`bytes` instead, same as every other
    #: content type.
    content: 'Any'

    if TYPE_CHECKING:
        def __init__(self, content_type: 'Enum_ContentType', version: 'int', epoch: 'int', sequence_number: 'int', length: 'int', content: 'Any') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class DTLSCiphertext(Protocol):
    """Data model for a DTLS 1.3 ciphertext record (:rfc:`9147#section-4`).

    The unified header carries neither a content type nor a version, and only
    the low two bits of the epoch, so those fields are absent here: the
    content type is inside :attr:`content`.

    """

    #: Low two bits of the epoch; the full 16-bit epoch is not on the wire.
    epoch: 'int'
    #: Sequence number as carried, 8 or 16 bits per :attr:`sequence_long`. It
    #: is header-protected, so it is the value on the wire, not the record's.
    sequence_number: 'int'
    #: Whether :attr:`sequence_number` is 16 bits rather than 8.
    sequence_long: 'bool'
    #: Length of :attr:`content`, or :data:`None` when the record runs to the
    #: end of the datagram.
    length: 'Optional[int]'
    #: Encrypted record content, undecoded.
    content: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, epoch: 'int', sequence_number: 'int', sequence_long: 'bool', length: 'Optional[int]', content: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class DTLSCIDCiphertext(Protocol):
    """Data model for a DTLS 1.2 record with a connection ID (:rfc:`9146#section-4`).

    The record is always encrypted, so its real content type is inside
    :attr:`content` and :attr:`content_type` is ``tls12_cid``.

    """

    #: Outer content type, always ``tls12_cid``.
    content_type: 'Enum_ContentType'
    #: Legacy record version (``major << 8 | minor``), DTLS 1.2's.
    version: 'int'
    #: Epoch -- incremented on every change of cipher state.
    epoch: 'int'
    #: Sequence number within :attr:`epoch` (48-bit).
    sequence_number: 'int'
    #: Connection ID, as long as the handshake or the caller says.
    cid: 'bytes'
    #: Length of :attr:`content`.
    length: 'int'
    #: Encrypted record content, undecoded.
    content: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, content_type: 'Enum_ContentType', version: 'int', epoch: 'int', sequence_number: 'int', cid: 'bytes', length: 'int', content: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long
