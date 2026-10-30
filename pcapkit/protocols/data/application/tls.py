# -*- coding: utf-8 -*-
"""data models for TLS protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from typing import Any, Optional, Union

    from pcapkit.const.tls.content_type import ContentType as Enum_ContentType
    from pcapkit.const.tls.handshake_type import HandshakeType as Enum_HandshakeType

__all__ = [
    'TLS',

    'Handshake', 'ClientHello', 'ServerHello', 'Extension',
    'Alert', 'ChangeCipherSpec',
]


@info_final
class Extension(Data):
    """Data model for a TLS/DTLS extension list entry.

    Only the TYPE and LENGTH framing is decoded (:issue:`2437`); an
    extension's own body is kept as :attr:`data`, undecoded.

    """

    #: Extension type.
    type: 'int'
    #: Extension data, undecoded.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'int', data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class ClientHello(Data):
    """Data model for a TLS/DTLS ``ClientHello`` handshake message body."""

    #: Client (legacy) version.
    version: 'int'
    #: Client random (32 octets).
    random: 'bytes'
    #: Session ID.
    session_id: 'bytes'
    #: DTLS's ``cookie`` (:rfc:`6347#section-4.2.1`; carried forward as
    #: ``legacy_cookie`` by :rfc:`9147#section-5.3`), or :data:`None` for
    #: TLS, whose ``ClientHello`` carries no cookie field at all -- distinct
    #: from DTLS's *empty* cookie, which is ``b''``.
    cookie: 'Optional[bytes]'
    #: Cipher suites offered.
    cipher_suites: 'tuple[int, ...]'
    #: Compression methods offered.
    compression_methods: 'tuple[int, ...]'
    #: Extensions, or :data:`None` when the message carries no extensions
    #: field at all -- distinct from an *empty* extension list, which is
    #: ``()``.
    extensions: 'Optional[tuple[Extension, ...]]'

    if TYPE_CHECKING:
        def __init__(self, version: 'int', random: 'bytes', session_id: 'bytes', cookie: 'Optional[bytes]', cipher_suites: 'tuple[int, ...]', compression_methods: 'tuple[int, ...]', extensions: 'Optional[tuple[Extension, ...]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class ServerHello(Data):
    """Data model for a TLS/DTLS ``ServerHello`` handshake message body."""

    #: Server (legacy) version.
    version: 'int'
    #: Server random (32 octets).
    random: 'bytes'
    #: Session ID.
    session_id: 'bytes'
    #: Cipher suite selected.
    cipher_suite: 'int'
    #: Compression method selected.
    compression_method: 'int'
    #: Extensions, or :data:`None` when the message carries no extensions
    #: field at all -- distinct from an *empty* extension list, which is
    #: ``()``.
    extensions: 'Optional[tuple[Extension, ...]]'

    if TYPE_CHECKING:
        def __init__(self, version: 'int', random: 'bytes', session_id: 'bytes', cipher_suite: 'int', compression_method: 'int', extensions: 'Optional[tuple[Extension, ...]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


class Handshake(Data):
    """Data model for a TLS/DTLS handshake message.

    :attr:`body` holds a :class:`ClientHello` or :class:`ServerHello` for
    those two message types, and the raw, undecoded message body for every
    other :class:`~pcapkit.const.tls.handshake_type.HandshakeType` --
    message-TYPE-level framing only (:issue:`2437`).

    """

    #: Handshake message type.
    msg_type: 'Enum_HandshakeType'
    #: Message length (24-bit), the 4-octet handshake header excluded.
    length: 'int'
    #: Message body.
    body: 'Union[ClientHello, ServerHello, bytes]'

    if TYPE_CHECKING:
        def __init__(self, msg_type: 'Enum_HandshakeType', length: 'int', body: 'Union[ClientHello, ServerHello, bytes]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class Alert(Data):
    """Data model for a TLS/DTLS ``Alert`` record."""

    #: Alert level.
    level: 'int'
    #: Alert description.
    description: 'int'

    if TYPE_CHECKING:
        def __init__(self, level: 'int', description: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class ChangeCipherSpec(Data):
    """Data model for a TLS/DTLS ``ChangeCipherSpec`` record."""

    #: ``change_cipher_spec`` message (always ``1`` on the wire).
    msg: 'int'

    if TYPE_CHECKING:
        def __init__(self, msg: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class TLS(Protocol):
    """Data model for TLS protocol."""

    #: Content type.
    content_type: 'Enum_ContentType'
    #: Legacy record version (``major << 8 | minor``).
    version: 'int'
    #: Length of the record fragment.
    length: 'int'
    #: Decoded record content. For ``handshake``, ``alert``, and
    #: ``change_cipher_spec``, this is a tuple of :class:`Handshake`, an
    #: :class:`Alert`, or a :class:`ChangeCipherSpec` respectively *only when
    #: the record is cleartext* (as decided by
    #: :meth:`SSL._tls_content_is_cleartext
    #: <pcapkit.protocols.application.ssl.SSL._tls_content_is_cleartext>`) --
    #: an encrypted record of any of those three types, which is the common
    #: case for TLS 1.2 post-handshake traffic, stays raw :obj:`bytes` instead,
    #: same as every other content type.
    content: 'Any'

    if TYPE_CHECKING:
        def __init__(self, content_type: 'Enum_ContentType', version: 'int', length: 'int', content: 'Any') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long
