# -*- coding: utf-8 -*-
"""data models for TLS protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from typing import Any, Optional, Union

    from pcapkit.const.tls.content_type import ContentType as Enum_ContentType
    from pcapkit.const.tls.extension_type import ExtensionType as Enum_ExtensionType
    from pcapkit.const.tls.handshake_type import HandshakeType as Enum_HandshakeType

__all__ = [
    'TLS',

    'Handshake', 'ClientHello', 'ServerHello', 'EncryptedExtensions',

    'Extension', 'ExtensionData',
    'ServerName', 'ServerNameList', 'NamedGroupList', 'SignatureSchemeList',
    'ProtocolNameList', 'SupportedVersionsClientHello', 'SupportedVersionsServerHello',
    'KeyShareEntry', 'KeyShareClientHello', 'KeyShareHelloRetryRequest', 'KeyShareServerHello',

    'Alert', 'ChangeCipherSpec',
]


class ExtensionData(Data):
    """Data model for a decoded TLS/DTLS ``extension_data`` field.

    Each subclass is the structure one
    :class:`~pcapkit.const.tls.extension_type.ExtensionType` carries, named
    as its specification names it.

    """


@info_final
class Extension(Data):
    """Data model for a TLS/DTLS extension list entry (:rfc:`9846#section-4.3`).

    :attr:`data` holds the decoded ``extension_data`` where
    :attr:`SSL.__extension__ <pcapkit.protocols.application.ssl.SSL.__extension__>`
    registers a decoder for :attr:`type`, and the raw octets otherwise --
    including a body its decoder cannot read exactly, or one in a message
    whose structure for it the decoder does not know.

    """

    #: Extension type.
    type: 'Enum_ExtensionType'
    #: Extension data: decoded, or the raw octets.
    data: 'Union[ExtensionData, bytes]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_ExtensionType', data: 'Union[ExtensionData, bytes]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin,line-too-long


@info_final
class ServerName(Data):
    """Data model for one ``ServerName`` of a ``server_name`` extension (:rfc:`6066#section-3`)."""

    #: Name type; ``0`` is ``host_name``, the only one defined.
    name_type: 'int'
    #: Name, i.e. the ``HostName`` octets.
    name: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, name_type: 'int', name: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class ServerNameList(ExtensionData):
    """Data model for the ``server_name`` extension (:rfc:`6066#section-3`).

    A ``ServerHello`` or ``EncryptedExtensions`` carries the extension with
    empty ``extension_data``, which stays ``b''``.

    """

    #: Server names.
    server_name_list: 'tuple[ServerName, ...]'

    if TYPE_CHECKING:
        def __init__(self, server_name_list: 'tuple[ServerName, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class NamedGroupList(ExtensionData):
    """Data model for the ``supported_groups`` extension (:rfc:`9846#section-4.3.7`)."""

    #: ``NamedGroup`` values, most preferred first.
    named_group_list: 'tuple[int, ...]'

    if TYPE_CHECKING:
        def __init__(self, named_group_list: 'tuple[int, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class SignatureSchemeList(ExtensionData):
    """Data model for the ``signature_algorithms`` extension (:rfc:`9846#section-4.3.3`)."""

    #: ``SignatureScheme`` values, most preferred first.
    supported_signature_algorithms: 'tuple[int, ...]'

    if TYPE_CHECKING:
        def __init__(self, supported_signature_algorithms: 'tuple[int, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class ProtocolNameList(ExtensionData):
    """Data model for the ``application_layer_protocol_negotiation`` extension
    (:rfc:`7301#section-3.1`)."""

    #: ``ProtocolName`` octet strings, e.g. ``b'h2'``.
    protocol_name_list: 'tuple[bytes, ...]'

    if TYPE_CHECKING:
        def __init__(self, protocol_name_list: 'tuple[bytes, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class SupportedVersionsClientHello(ExtensionData):
    """Data model for a ``ClientHello``'s ``supported_versions`` extension
    (:rfc:`9846#section-4.3.1`)."""

    #: ``ProtocolVersion`` values, most preferred first.
    versions: 'tuple[int, ...]'

    if TYPE_CHECKING:
        def __init__(self, versions: 'tuple[int, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class SupportedVersionsServerHello(ExtensionData):
    """Data model for a ``ServerHello``'s or ``HelloRetryRequest``'s
    ``supported_versions`` extension (:rfc:`9846#section-4.3.1`)."""

    #: The ``ProtocolVersion`` selected.
    selected_version: 'int'

    if TYPE_CHECKING:
        def __init__(self, selected_version: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class KeyShareEntry(Data):
    """Data model for one ``KeyShareEntry`` of a ``key_share`` extension (:rfc:`9846#section-4.3.8`)."""

    #: ``NamedGroup`` of the key.
    group: 'int'
    #: Key exchange information.
    key_exchange: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, group: 'int', key_exchange: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class KeyShareClientHello(ExtensionData):
    """Data model for a ``ClientHello``'s ``key_share`` extension (:rfc:`9846#section-4.3.8`)."""

    #: Key shares offered, most preferred first.
    client_shares: 'tuple[KeyShareEntry, ...]'

    if TYPE_CHECKING:
        def __init__(self, client_shares: 'tuple[KeyShareEntry, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class KeyShareHelloRetryRequest(ExtensionData):
    """Data model for a ``HelloRetryRequest``'s ``key_share`` extension (:rfc:`9846#section-4.3.8`)."""

    #: ``NamedGroup`` the server asks a retried ``ClientHello`` to share.
    selected_group: 'int'

    if TYPE_CHECKING:
        def __init__(self, selected_group: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class KeyShareServerHello(ExtensionData):
    """Data model for a ``ServerHello``'s ``key_share`` extension (:rfc:`9846#section-4.3.8`)."""

    #: The server's key share.
    server_share: 'KeyShareEntry'

    if TYPE_CHECKING:
        def __init__(self, server_share: 'KeyShareEntry') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


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
    """Data model for a TLS/DTLS ``ServerHello`` handshake message body.

    A ``HelloRetryRequest`` shares the structure and is told apart by its
    :attr:`random` (:rfc:`9846#section-4.2.3`); its extensions decode in the
    shapes a ``HelloRetryRequest`` gives them.

    """

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


@info_final
class EncryptedExtensions(Data):
    """Data model for a TLS/DTLS ``EncryptedExtensions`` handshake message body
    (:rfc:`9846#section-4.4.1`)."""

    #: Extensions.
    extensions: 'tuple[Extension, ...]'

    if TYPE_CHECKING:
        def __init__(self, extensions: 'tuple[Extension, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


class Handshake(Data):
    """Data model for a TLS/DTLS handshake message.

    :attr:`body` holds a :class:`ClientHello`, :class:`ServerHello` or
    :class:`EncryptedExtensions` for those message types, and the raw,
    undecoded message body for every other
    :class:`~pcapkit.const.tls.handshake_type.HandshakeType` --
    message-TYPE-level framing only (:issue:`2437`).

    """

    #: Handshake message type.
    msg_type: 'Enum_HandshakeType'
    #: Message length (24-bit), the 4-octet handshake header excluded.
    length: 'int'
    #: Message body.
    body: 'Union[ClientHello, ServerHello, EncryptedExtensions, bytes]'

    if TYPE_CHECKING:
        def __init__(self, msg_type: 'Enum_HandshakeType', length: 'int', body: 'Union[ClientHello, ServerHello, EncryptedExtensions, bytes]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


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
