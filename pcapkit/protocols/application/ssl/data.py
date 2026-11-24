# -*- coding: utf-8 -*-
"""data models the SSL family shares

:mod:`pcapkit.protocols.application.ssl.data` holds the data models
:class:`~pcapkit.protocols.application.ssl.protocol.SSL` and its members read:
a family's shared pieces live in its base's package (:issue:`2534`).

"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data import Data

if TYPE_CHECKING:
    from typing import Optional, Union

    from pcapkit.const.tls.certificate_compression_algorithm import \
        CertificateCompressionAlgorithm as Enum_CertificateCompressionAlgorithm
    from pcapkit.const.tls.certificate_status_type import \
        CertificateStatusType as Enum_CertificateStatusType
    from pcapkit.const.tls.ec_point_format import ECPointFormat as Enum_ECPointFormat
    from pcapkit.const.tls.extension_type import ExtensionType as Enum_ExtensionType
    from pcapkit.const.tls.handshake_type import HandshakeType as Enum_HandshakeType
    from pcapkit.const.tls.hpke_aead_id import HpkeAeadId as Enum_HpkeAeadId
    from pcapkit.const.tls.hpke_kdf_id import HpkeKdfId as Enum_HpkeKdfId
    from pcapkit.const.tls.hpke_kem_id import HpkeKemId as Enum_HpkeKemId
    from pcapkit.const.tls.psk_key_exchange_mode import \
        PskKeyExchangeMode as Enum_PskKeyExchangeMode

__all__ = [
    'Handshake', 'ClientHello', 'ServerHello', 'EncryptedExtensions', 'Extension', 'ExtensionData',
    'ServerName', 'ServerNameList', 'NamedGroupList', 'SignatureSchemeList', 'ProtocolNameList',
    'SupportedVersionsClientHello', 'SupportedVersionsServerHello', 'KeyShareEntry',
    'KeyShareClientHello', 'KeyShareHelloRetryRequest', 'KeyShareServerHello', 'ConnectionId',
    'Empty', 'CertificateStatusRequest', 'OCSPStatusRequest', 'ECPointFormatList',
    'SignedCertificateTimestampList', 'Padding', 'CertificateCompressionAlgorithms', 'RecordSizeLimit',
    'SessionTicket', 'OfferedPsks', 'PskIdentity', 'PreSharedKeyServerHello', 'Cookie',
    'PskKeyExchangeModes', 'ECHClientHelloOuter', 'ECHClientHelloInner', 'ECHHelloRetryRequest',
    'ECHEncryptedExtensions', 'ECHConfig', 'ECHConfigContents', 'HpkeKeyConfig',
    'HpkeSymmetricCipherSuite', 'ECHConfigExtension', 'RenegotiationInfo',
    'Alert', 'ChangeCipherSpec',
]


class ExtensionData(Data):
    """Data model for a decoded TLS/DTLS ``extension_data`` field.

    Each subclass is a structure an
    :class:`~pcapkit.const.tls.extension_type.ExtensionType` carries, named
    as its specification names it; :class:`Empty` serves every type whose
    ``extension_data`` is empty.

    """


@info_final
class Extension(Data):
    """Data model for a TLS/DTLS extension list entry (:rfc:`9846#section-4.3`).

    :attr:`data` holds the decoded ``extension_data`` where
    :attr:`SSL.__extension__ <pcapkit.protocols.application.ssl.protocol.SSL.__extension__>`
    registers a decoder for :attr:`type`, and the raw octets otherwise --
    including a body its decoder cannot read exactly, or one in a message
    whose structure for it the decoder does not know.

    """

    #: Extension type.
    type: 'Enum_ExtensionType'
    #: Extension data -- decoded, or the raw octets.
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
class ConnectionId(ExtensionData):
    """Data model for the ``connection_id`` extension (:rfc:`9146#section-3`).

    The extension is DTLS-only (:rfc:`9146#section-10.2`); a TLS hello that
    carries it, which does not conform, decodes to this model all the same.

    """

    #: The connection ID its sender wants to receive; empty when it wants none.
    cid: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, cid: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class Empty(ExtensionData):
    """Data model for an ``extension_data`` that is empty in the message carrying it,
    the ``Empty`` structure of :rfc:`9846#section-4.3.10`.

    ``extended_main_secret`` (:rfc:`7627#section-5.1`) and ``post_handshake_auth``
    (:rfc:`9846#section-4.3.6`) are always empty, ``early_data`` in a ``ClientHello``
    and ``EncryptedExtensions`` (:rfc:`9846#section-4.3.10`),
    ``signed_certificate_timestamp`` in a ``ClientHello`` (:rfc:`6962#section-3.3.1`),
    and ``status_request`` in a ``ServerHello`` (:rfc:`6066#section-8`).

    .. versionadded:: 1.7.0

    """

    if TYPE_CHECKING:
        def __init__(self) -> 'None': ...  # pylint: disable=super-init-not-called,multiple-statements


@info_final
class OCSPStatusRequest(Data):
    """Data model for the ``OCSPStatusRequest`` of a ``status_request`` extension (:rfc:`6066#section-8`).

    .. versionadded:: 1.7.0

    """

    #: DER-encoded ``ResponderID`` values; empty when the server knows the responders.
    responder_id_list: 'tuple[bytes, ...]'
    #: DER-encoded OCSP request ``Extensions``; empty for none.
    request_extensions: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, responder_id_list: 'tuple[bytes, ...]', request_extensions: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class CertificateStatusRequest(ExtensionData):
    """Data model for a ``ClientHello``'s ``status_request`` extension (:rfc:`6066#section-8`).

    Only ``ocsp`` has a ``request`` structure, so a body naming another
    :attr:`status_type` stays raw octets.

    .. versionadded:: 1.7.0

    """

    #: Status type.
    status_type: 'Enum_CertificateStatusType'
    #: The OCSP request.
    request: 'OCSPStatusRequest'

    if TYPE_CHECKING:
        def __init__(self, status_type: 'Enum_CertificateStatusType', request: 'OCSPStatusRequest') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class ECPointFormatList(ExtensionData):
    """Data model for the ``ec_point_formats`` extension (:rfc:`8422#section-5.1.2`).

    .. versionadded:: 1.7.0

    """

    #: Point formats, most preferred first.
    ec_point_format_list: 'tuple[Enum_ECPointFormat, ...]'

    if TYPE_CHECKING:
        def __init__(self, ec_point_format_list: 'tuple[Enum_ECPointFormat, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class SignedCertificateTimestampList(ExtensionData):
    """Data model for a ``ServerHello``'s ``signed_certificate_timestamp`` extension
    (:rfc:`6962#section-3.3`).

    .. versionadded:: 1.7.0

    """

    #: ``SerializedSCT`` octet strings.
    sct_list: 'tuple[bytes, ...]'

    if TYPE_CHECKING:
        def __init__(self, sct_list: 'tuple[bytes, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class Padding(ExtensionData):
    """Data model for the ``padding`` extension (:rfc:`7685#section-3`).

    .. versionadded:: 1.7.0

    """

    #: Padding octets as captured, which :rfc:`7685#section-3` requires to be zero.
    padding: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, padding: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class CertificateCompressionAlgorithms(ExtensionData):
    """Data model for the ``compress_certificate`` extension (:rfc:`8879#section-3`).

    .. versionadded:: 1.7.0

    """

    #: Compression algorithms, most preferred first.
    algorithms: 'tuple[Enum_CertificateCompressionAlgorithm, ...]'

    if TYPE_CHECKING:
        def __init__(self, algorithms: 'tuple[Enum_CertificateCompressionAlgorithm, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class RecordSizeLimit(ExtensionData):
    """Data model for the ``record_size_limit`` extension (:rfc:`8449#section-4`).

    .. versionadded:: 1.7.0

    """

    #: Largest record, in octets, the sender is willing to receive.
    record_size_limit: 'int'

    if TYPE_CHECKING:
        def __init__(self, record_size_limit: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class SessionTicket(ExtensionData):
    """Data model for the ``session_ticket`` extension (:rfc:`5077#section-3.2`).

    .. versionadded:: 1.7.0

    """

    #: The ticket; empty when the client has none to offer, and in a ``ServerHello``.
    ticket: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, ticket: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class PskIdentity(Data):
    """Data model for one ``PskIdentity`` of a ``pre_shared_key`` extension (:rfc:`9846#section-4.3.11`).

    .. versionadded:: 1.7.0

    """

    #: Label of the key, e.g. a ticket.
    identity: 'bytes'
    #: Obfuscated age of the key.
    obfuscated_ticket_age: 'int'

    if TYPE_CHECKING:
        def __init__(self, identity: 'bytes', obfuscated_ticket_age: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class OfferedPsks(ExtensionData):
    """Data model for a ``ClientHello``'s ``pre_shared_key`` extension (:rfc:`9846#section-4.3.11`).

    .. versionadded:: 1.7.0

    """

    #: Identities offered.
    identities: 'tuple[PskIdentity, ...]'
    #: ``PskBinderEntry`` HMAC values, one per identity.
    binders: 'tuple[bytes, ...]'

    if TYPE_CHECKING:
        def __init__(self, identities: 'tuple[PskIdentity, ...]', binders: 'tuple[bytes, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class PreSharedKeyServerHello(ExtensionData):
    """Data model for a ``ServerHello``'s ``pre_shared_key`` extension (:rfc:`9846#section-4.3.11`).

    .. versionadded:: 1.7.0

    """

    #: Index of the identity selected, into the ``ClientHello``'s list.
    selected_identity: 'int'

    if TYPE_CHECKING:
        def __init__(self, selected_identity: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class Cookie(ExtensionData):
    """Data model for the ``cookie`` extension (:rfc:`9846#section-4.3.2`).

    .. versionadded:: 1.7.0

    """

    #: The cookie, which a ``ClientHello`` copies from the ``HelloRetryRequest``.
    cookie: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, cookie: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class PskKeyExchangeModes(ExtensionData):
    """Data model for the ``psk_key_exchange_modes`` extension (:rfc:`9846#section-4.3.9`).

    .. versionadded:: 1.7.0

    """

    #: Key exchange modes the client supports with a PSK.
    ke_modes: 'tuple[Enum_PskKeyExchangeMode, ...]'

    if TYPE_CHECKING:
        def __init__(self, ke_modes: 'tuple[Enum_PskKeyExchangeMode, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class HpkeSymmetricCipherSuite(Data):
    """Data model for an ``HpkeSymmetricCipherSuite`` (:rfc:`9849#section-4`).

    .. versionadded:: 1.7.0

    """

    #: HPKE KDF identifier (:rfc:`9180#section-7.2`).
    kdf_id: 'Enum_HpkeKdfId'
    #: HPKE AEAD identifier (:rfc:`9180#section-7.3`).
    aead_id: 'Enum_HpkeAeadId'

    if TYPE_CHECKING:
        def __init__(self, kdf_id: 'Enum_HpkeKdfId', aead_id: 'Enum_HpkeAeadId') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class ECHClientHelloOuter(ExtensionData):
    """Data model for the outer variant of a ``ClientHello``'s ``encrypted_client_hello``
    extension (:rfc:`9849#section-5`).

    .. versionadded:: 1.7.0

    """

    #: Cipher suite encrypting the inner ``ClientHello``.
    cipher_suite: 'HpkeSymmetricCipherSuite'
    #: ``config_id`` of the ``ECHConfig`` chosen.
    config_id: 'int'
    #: HPKE encapsulated key; empty after a ``HelloRetryRequest``.
    enc: 'bytes'
    #: Encrypted ``EncodedClientHelloInner``.
    payload: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, cipher_suite: 'HpkeSymmetricCipherSuite', config_id: 'int', enc: 'bytes', payload: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class ECHClientHelloInner(ExtensionData):
    """Data model for the inner variant of a ``ClientHello``'s ``encrypted_client_hello``
    extension (:rfc:`9849#section-5`), which carries its type alone.

    .. versionadded:: 1.7.0

    """

    if TYPE_CHECKING:
        def __init__(self) -> 'None': ...  # pylint: disable=super-init-not-called,multiple-statements


@info_final
class ECHHelloRetryRequest(ExtensionData):
    """Data model for a ``HelloRetryRequest``'s ``encrypted_client_hello`` extension
    (:rfc:`9849#section-5`).

    .. versionadded:: 1.7.0

    """

    #: Acceptance confirmation (8 octets).
    confirmation: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, confirmation: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class ECHConfigExtension(Data):
    """Data model for one ``ECHConfigExtension`` of an ``ECHConfig`` (:rfc:`9849#section-4.2`).

    .. versionadded:: 1.7.0

    """

    #: ``ECHConfigExtensionType``.
    type: 'int'
    #: Extension data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'int', data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class HpkeKeyConfig(Data):
    """Data model for the ``HpkeKeyConfig`` of an ``ECHConfig`` (:rfc:`9849#section-4`).

    .. versionadded:: 1.7.0

    """

    #: Identifier of the configuration.
    config_id: 'int'
    #: HPKE KEM identifier (:rfc:`9180#section-7.1`).
    kem_id: 'Enum_HpkeKemId'
    #: HPKE public key.
    public_key: 'bytes'
    #: Cipher suites a client may encrypt with.
    cipher_suites: 'tuple[HpkeSymmetricCipherSuite, ...]'

    if TYPE_CHECKING:
        def __init__(self, config_id: 'int', kem_id: 'Enum_HpkeKemId', public_key: 'bytes', cipher_suites: 'tuple[HpkeSymmetricCipherSuite, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class ECHConfigContents(Data):
    """Data model for the ``ECHConfigContents`` of an ``ECHConfig`` (:rfc:`9849#section-4`).

    .. versionadded:: 1.7.0

    """

    #: HPKE key configuration.
    key_config: 'HpkeKeyConfig'
    #: Longest name of a backend server, or ``0`` if not known.
    maximum_name_length: 'int'
    #: DNS name of the client-facing server.
    public_name: 'bytes'
    #: Configuration extensions.
    extensions: 'tuple[ECHConfigExtension, ...]'

    if TYPE_CHECKING:
        def __init__(self, key_config: 'HpkeKeyConfig', maximum_name_length: 'int', public_name: 'bytes', extensions: 'tuple[ECHConfigExtension, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class ECHConfig(Data):
    """Data model for one ``ECHConfig`` of an ``ECHConfigList`` (:rfc:`9849#section-4`).

    .. versionadded:: 1.7.0

    """

    #: ECH version of the configuration.
    version: 'int'
    #: The decoded contents for the version :rfc:`9849` defines, ``0xFE0D``, and
    #: the raw octets for any other, which a client skips.
    contents: 'Union[ECHConfigContents, bytes]'

    if TYPE_CHECKING:
        def __init__(self, version: 'int', contents: 'Union[ECHConfigContents, bytes]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class ECHEncryptedExtensions(ExtensionData):
    """Data model for an ``EncryptedExtensions``' ``encrypted_client_hello`` extension
    (:rfc:`9849#section-5`).

    .. versionadded:: 1.7.0

    """

    #: The server's retry configurations, most preferred first.
    retry_configs: 'tuple[ECHConfig, ...]'

    if TYPE_CHECKING:
        def __init__(self, retry_configs: 'tuple[ECHConfig, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class RenegotiationInfo(ExtensionData):
    """Data model for the ``renegotiation_info`` extension (:rfc:`5746#section-3.2`).

    .. versionadded:: 1.7.0

    """

    #: ``verify_data`` of the previous handshake; empty on an initial one.
    renegotiated_connection: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, renegotiated_connection: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


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
