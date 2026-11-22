# -*- coding: utf-8 -*-
"""SSL - Secure Sockets Layer
================================

.. module:: pcapkit.protocols.application.ssl.protocol

:mod:`pcapkit.protocols.application.ssl.protocol` holds
:class:`~pcapkit.protocols.application.ssl.protocol.SSL`, the base class of the
Secure Sockets Layer family [*]_:
:class:`~pcapkit.protocols.application.sslv2.protocol.SSLv2`, Transport Layer
Security (:class:`~pcapkit.protocols.application.tls.protocol.TLS`, which also
covers SSLv3 through :class:`~pcapkit.protocols.application.sslv3.protocol.SSLv3`)
and Datagram TLS (:class:`~pcapkit.protocols.application.dtls.protocol.DTLS`).

The TLS record header (:rfc:`9846#section-5.1`) is a
:class:`~pcapkit.const.tls.content_type.ContentType`, a legacy record version
and a length. The DTLS ``DTLSPlaintext`` header (:rfc:`9147#section-4`) has
the same fields plus an epoch and a 48-bit sequence number *between* the
version and the length, and DTLS adds a fragment header to each handshake
message. Each record header is declared in its subclass's own schema
(:class:`~pcapkit.protocols.application.tls.schema.TLS` and
:class:`~pcapkit.protocols.application.dtls.schema.DTLS`), and
:class:`~pcapkit.protocols.application.dtls.protocol.DTLS` reads the epoch and sequence
number. This base class carries the logic the two share -- content-type
dispatch, handshake-message decoding and the extension registry -- parameterised
by a ``dtls`` flag where the DTLS handshake fragment header has to be read or
written.

.. [*] https://en.wikipedia.org/wiki/Transport_Layer_Security

.. versionadded:: 1.6.0

"""
import collections
from typing import TYPE_CHECKING, Generic, cast

from pcapkit.const.tls.certificate_compression_algorithm import \
    CertificateCompressionAlgorithm as Enum_CertificateCompressionAlgorithm
from pcapkit.const.tls.certificate_status_type import \
    CertificateStatusType as Enum_CertificateStatusType
from pcapkit.const.tls.content_type import ContentType as Enum_ContentType
from pcapkit.const.tls.ec_point_format import ECPointFormat as Enum_ECPointFormat
from pcapkit.const.tls.extension_type import ExtensionType as Enum_ExtensionType
from pcapkit.const.tls.handshake_type import HandshakeType as Enum_HandshakeType
from pcapkit.const.tls.psk_key_exchange_mode import PskKeyExchangeMode as Enum_PskKeyExchangeMode
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.application.application import Application
from pcapkit.protocols.application.ssl.data import Alert as Data_Alert
from pcapkit.protocols.application.ssl.data import \
    CertificateCompressionAlgorithms as Data_CertificateCompressionAlgorithms
from pcapkit.protocols.application.ssl.data import \
    CertificateStatusRequest as Data_CertificateStatusRequest
from pcapkit.protocols.application.ssl.data import ChangeCipherSpec as Data_ChangeCipherSpec
from pcapkit.protocols.application.ssl.data import ClientHello as Data_ClientHello
from pcapkit.protocols.application.ssl.data import ConnectionId as Data_ConnectionId
from pcapkit.protocols.application.ssl.data import Cookie as Data_Cookie
from pcapkit.protocols.application.ssl.data import ECHClientHelloInner as Data_ECHClientHelloInner
from pcapkit.protocols.application.ssl.data import ECHClientHelloOuter as Data_ECHClientHelloOuter
from pcapkit.protocols.application.ssl.data import ECHConfig as Data_ECHConfig
from pcapkit.protocols.application.ssl.data import ECHConfigContents as Data_ECHConfigContents
from pcapkit.protocols.application.ssl.data import ECHConfigExtension as Data_ECHConfigExtension
from pcapkit.protocols.application.ssl.data import \
    ECHEncryptedExtensions as Data_ECHEncryptedExtensions
from pcapkit.protocols.application.ssl.data import ECHHelloRetryRequest as Data_ECHHelloRetryRequest
from pcapkit.protocols.application.ssl.data import ECPointFormatList as Data_ECPointFormatList
from pcapkit.protocols.application.ssl.data import Empty as Data_Empty
from pcapkit.protocols.application.ssl.data import EncryptedExtensions as Data_EncryptedExtensions
from pcapkit.protocols.application.ssl.data import Extension as Data_Extension
from pcapkit.protocols.application.ssl.data import Handshake as Data_Handshake
from pcapkit.protocols.application.ssl.data import HpkeKeyConfig as Data_HpkeKeyConfig
from pcapkit.protocols.application.ssl.data import \
    HpkeSymmetricCipherSuite as Data_HpkeSymmetricCipherSuite
from pcapkit.protocols.application.ssl.data import KeyShareClientHello as Data_KeyShareClientHello
from pcapkit.protocols.application.ssl.data import KeyShareEntry as Data_KeyShareEntry
from pcapkit.protocols.application.ssl.data import \
    KeyShareHelloRetryRequest as Data_KeyShareHelloRetryRequest
from pcapkit.protocols.application.ssl.data import KeyShareServerHello as Data_KeyShareServerHello
from pcapkit.protocols.application.ssl.data import NamedGroupList as Data_NamedGroupList
from pcapkit.protocols.application.ssl.data import OCSPStatusRequest as Data_OCSPStatusRequest
from pcapkit.protocols.application.ssl.data import OfferedPsks as Data_OfferedPsks
from pcapkit.protocols.application.ssl.data import Padding as Data_Padding
from pcapkit.protocols.application.ssl.data import \
    PreSharedKeyServerHello as Data_PreSharedKeyServerHello
from pcapkit.protocols.application.ssl.data import ProtocolNameList as Data_ProtocolNameList
from pcapkit.protocols.application.ssl.data import PskIdentity as Data_PskIdentity
from pcapkit.protocols.application.ssl.data import PskKeyExchangeModes as Data_PskKeyExchangeModes
from pcapkit.protocols.application.ssl.data import RecordSizeLimit as Data_RecordSizeLimit
from pcapkit.protocols.application.ssl.data import RenegotiationInfo as Data_RenegotiationInfo
from pcapkit.protocols.application.ssl.data import ServerHello as Data_ServerHello
from pcapkit.protocols.application.ssl.data import ServerName as Data_ServerName
from pcapkit.protocols.application.ssl.data import ServerNameList as Data_ServerNameList
from pcapkit.protocols.application.ssl.data import SessionTicket as Data_SessionTicket
from pcapkit.protocols.application.ssl.data import SignatureSchemeList as Data_SignatureSchemeList
from pcapkit.protocols.application.ssl.data import \
    SignedCertificateTimestampList as Data_SignedCertificateTimestampList
from pcapkit.protocols.application.ssl.data import \
    SupportedVersionsClientHello as Data_SupportedVersionsClientHello
from pcapkit.protocols.application.ssl.data import \
    SupportedVersionsServerHello as Data_SupportedVersionsServerHello
from pcapkit.protocols.misc.no_payload.protocol import NoPayload
from pcapkit.protocols.protocol import _PT, _ST
from pcapkit.utilities.exceptions import CaughtByCaller, ProtocolError
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from typing import Any, Callable, DefaultDict, Iterable, Optional, Type, Union

    from mypy_extensions import DefaultArg, KwArg, NamedArg
    from typing_extensions import Literal

    from pcapkit.protocols.application.ssl.data import ExtensionData as Data_ExtensionData
    from pcapkit.protocols.protocol import _ET

    #: Parser of an ``extension_data`` field registered as a callable.
    ExtensionParser = Callable[[Enum_ExtensionType, bytes, NamedArg(Enum_HandshakeType, 'msg_type')],
                               Union[Data_ExtensionData, bytes]]
    #: Constructor of an ``extension_data`` field registered as a callable.
    ExtensionConstructor = Callable[[Enum_ExtensionType, DefaultArg(Optional[Data_ExtensionData]),
                                     NamedArg(Enum_HandshakeType, 'msg_type'), KwArg(Any)], bytes]

__all__ = ['SSL']


#: Legacy record-version major octet TLS records carry (SSLv3 through the
#: TLS 1.3 wire value, all ``0x03xx``).
_TLS_VERSION_MAJOR = 0x03
#: Legacy record-version major octet DTLS records carry (``0xFExx`` --
#: DTLS encodes its legacy version as the one's complement of TLS's).
_DTLS_VERSION_MAJOR = 0xFE

#: The content types a genuine record may carry. An allowlist rather than
#: every :class:`~pcapkit.const.tls.content_type.ContentType` member: 0 is
#: never assigned, a value :rfc:`9846#section-5.1` rejects outright, and the
#: enum mints an ``Unassigned``/``Reserved`` member for any value IANA has
#: not named.
#:
#: ``tls12_cid`` (25, :rfc:`9146#section-4`) is left out: its connection ID
#: precedes ``length`` and has a negotiated length the record does not carry,
#: so reading ``length`` at the fixed offset would fabricate a fragment.
_WIRE_CONTENT_TYPES = frozenset({
    Enum_ContentType.change_cipher_spec,
    Enum_ContentType.alert,
    Enum_ContentType.handshake,
    Enum_ContentType.application_data,
    Enum_ContentType.heartbeat,
    Enum_ContentType.ack,
    Enum_ContentType.return_routability_check,
})

#: The ``supported_versions`` value for TLS 1.3 (:rfc:`9846#section-4.3.1`).
TLS13_VERSION = 0x0304
#: The ``supported_versions`` value for DTLS 1.3 (:rfc:`9147#section-5.3`).
DTLS13_VERSION = 0xFEFC

#: The ``random`` that makes a ``ServerHello`` a ``HelloRetryRequest`` -- the
#: SHA-256 of ``"HelloRetryRequest"`` (:rfc:`9846#section-4.2.3`).
_HRR_RANDOM = bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c')

#: The ``host_name`` ``NameType`` of ``server_name``, the only one defined
#: (:rfc:`6066#section-3`).
_HOST_NAME = 0

#: The ``outer`` and ``inner`` ``ECHClientHelloType`` of ``encrypted_client_hello``
#: (:rfc:`9849#section-5`).
_ECH_OUTER, _ECH_INNER = 0, 1
#: Length of an ``ECHHelloRetryRequest``'s ``confirmation`` (:rfc:`9849#section-5`).
_ECH_CONFIRMATION_LENGTH = 8
#: The ``ECHConfig`` version whose ``contents`` :rfc:`9849#section-4` defines, which
#: is the ``encrypted_client_hello`` code point.
_ECH_CONFIG_VERSION = int(Enum_ExtensionType.encrypted_client_hello)


def _negotiated_versions(message: 'Any') -> 'tuple[int, ...]':
    """The versions a ``supported_versions`` extension on ``message`` lists.

    Args:
        message: A decoded handshake message's body -- typically
            :class:`~pcapkit.protocols.application.ssl.data.ClientHello` or
            :class:`~pcapkit.protocols.application.ssl.data.ServerHello`.
            Any other type (raw :obj:`bytes`, or a message with no
            ``extensions`` attribute) yields nothing.

    Returns:
        Every version the extension lists, in order: zero or more for a
        ``ClientHello`` (a list), exactly one for a ``ServerHello`` (a bare
        selection), or nothing at all when ``message`` carries no
        ``supported_versions`` extension, or one left undecoded. A
        ``ClientHello`` list of odd length is left undecoded, so it yields
        nothing, not even the whole pairs before its stray octet.

    """
    extensions = getattr(message, 'extensions', None)
    if not extensions:
        return ()
    for extension in extensions:
        if extension.type != Enum_ExtensionType.supported_versions:
            continue
        data = extension.data
        if isinstance(data, Data_SupportedVersionsClientHello):
            return tuple(data.versions)
        if isinstance(data, Data_SupportedVersionsServerHello):
            return (data.selected_version,)
        return ()
    return ()


def _read_key_share_entry(proto: 'SSL', data: 'bytes', pos: 'int') -> 'tuple[Data_KeyShareEntry, int]':
    """Read one ``KeyShareEntry`` (:rfc:`9846#section-4.3.8`) at ``pos``.

    Args:
        proto: Protocol reading the entry, whose alias the error message names.
        data: Buffer being read.
        pos: Offset of the entry.

    Returns:
        The entry, and the offset just past it.

    Raises:
        ProtocolError: If the entry runs past the end of ``data``.

    """
    group = proto._read_uint(data, pos, size=2, what='key_share.group')  # pylint: disable=protected-access
    key_exchange, end = proto._read_vector(data, pos + 2, size=2,  # pylint: disable=protected-access
                                           what='key_share.key_exchange')
    return Data_KeyShareEntry(group=group, key_exchange=key_exchange), end


def _make_key_share_entry(proto: 'SSL', entry: 'Data_KeyShareEntry') -> 'bytes':
    """Write one ``KeyShareEntry`` -- the inverse of :func:`_read_key_share_entry`."""
    group = proto._make_pack(int(entry.group), size=2)  # pylint: disable=protected-access
    key_exchange = proto._make_vector(entry.key_exchange, size=2)  # pylint: disable=protected-access
    return group + key_exchange


def _read_vectors(proto: 'SSL', data: 'bytes', *, size: 'int', what: 'str') -> 'tuple[bytes, ...]':
    """Read ``data`` as a run of ``size``-octet length-prefixed vectors.

    Args:
        proto: Protocol reading the vectors, whose alias the error message names.
        data: Buffer holding the vectors and nothing else.
        size: Octets in each length prefix.
        what: Name of a vector, for the error message.

    Returns:
        The vectors' octets, in order.

    Raises:
        ProtocolError: If a vector runs past the end of ``data``.

    """
    items = []  # type: list[bytes]
    pos = 0
    while pos < len(data):
        item, pos = proto._read_vector(data, pos, size=size, what=what)  # pylint: disable=protected-access
        items.append(item)
    return tuple(items)


def _make_codes(proto: 'SSL', values: 'Iterable[Any]', namespace: 'Type[_ET]', *, size: 'int', name: 'str') -> 'bytes':
    """Write ``values``, members of ``namespace`` or :class:`int` codes, as a run of
    ``size``-octet integers, each resolved by :meth:`~pcapkit.protocols.protocol.Protocol._make_index`.

    Args:
        proto: Protocol making the list, whose alias the error message names.
        values: Members or codes.
        namespace: Enumeration the list holds.
        size: Octets in each code.
        name: Name of a code, for the error message.

    Returns:
        The packed codes, concatenated in order.

    Raises:
        ProtocolError: If a value is not an :class:`int`, or does not fit in
            ``size`` octets.

    """
    return b''.join(proto._make_pack(int(cast('int', proto._make_index(value, namespace, bits=size * 8, name=name))),  # pylint: disable=protected-access
                                     size=size) for value in values)


def _read_empty(proto: 'SSL', data: 'bytes', *, what: 'str') -> 'Data_Empty':
    """Read an ``extension_data`` that has to be empty.

    Args:
        proto: Protocol reading the extension, whose alias the error message names.
        data: ``extension_data`` octets.
        what: Name of the extension, for the error message.

    Returns:
        An :class:`~pcapkit.protocols.application.ssl.data.Empty`.

    Raises:
        ProtocolError: If ``data`` is not empty.

    """
    if data:
        raise ProtocolError(f'{proto.alias}: invalid format: {what} carries excess octets')
    return Data_Empty()


def _make_empty(proto: 'SSL', ext_type: 'Enum_ExtensionType', data: 'Optional[Data_ExtensionData]') -> 'bytes':
    """Write an ``extension_data`` that has to be empty -- the inverse of :func:`_read_empty`.

    Args:
        proto: Protocol making the extension, whose alias the error message names.
        ext_type: Extension type.
        data: Decoded ``extension_data``.

    Returns:
        Empty ``extension_data``.

    Raises:
        ProtocolError: If ``data`` is neither :data:`None` nor an
            :class:`~pcapkit.protocols.application.ssl.data.Empty`.

    """
    if data is not None and not isinstance(data, Data_Empty):
        raise ProtocolError(f'{proto.alias}: [Extension {ext_type}] no constructor for '
                            f'{type(data).__name__}; pass the raw octets instead')
    return b''


def _read_hpke_cipher_suite(proto: 'SSL', data: 'bytes', pos: 'int') -> 'Data_HpkeSymmetricCipherSuite':
    """Read one ``HpkeSymmetricCipherSuite`` (:rfc:`9849#section-4`) at ``pos``.

    Args:
        proto: Protocol reading the suite, whose alias the error message names.
        data: Buffer being read.
        pos: Offset of the suite, which is four octets long.

    Returns:
        The cipher suite.

    Raises:
        ProtocolError: If the suite runs past the end of ``data``.

    """
    kdf_id, aead_id = proto._read_uints(proto._read_octets(data, pos, size=4, what='HpkeSymmetricCipherSuite'),  # pylint: disable=protected-access
                                        size=2, what='HpkeSymmetricCipherSuite')
    return Data_HpkeSymmetricCipherSuite(kdf_id=kdf_id, aead_id=aead_id)


def _make_hpke_cipher_suite(proto: 'SSL', suite: 'Data_HpkeSymmetricCipherSuite') -> 'bytes':
    """Write one ``HpkeSymmetricCipherSuite`` -- the inverse of :func:`_read_hpke_cipher_suite`."""
    return proto._make_uints((suite.kdf_id, suite.aead_id), size=2)  # pylint: disable=protected-access


def _read_ech_config(proto: 'SSL', data: 'bytes', pos: 'int') -> 'tuple[Data_ECHConfig, int]':
    """Read one ``ECHConfig`` (:rfc:`9849#section-4`) at ``pos``.

    Structure of ``ECHConfig``:

    .. code-block:: text

       opaque HpkePublicKey<1..2^16-1>;
       uint16 HpkeKemId;
       uint16 HpkeKdfId;
       uint16 HpkeAeadId;
       uint16 ECHConfigExtensionType;

       struct {
           HpkeKdfId kdf_id;
           HpkeAeadId aead_id;
       } HpkeSymmetricCipherSuite;

       struct {
           uint8 config_id;
           HpkeKemId kem_id;
           HpkePublicKey public_key;
           HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>;
       } HpkeKeyConfig;

       struct {
           ECHConfigExtensionType type;
           opaque data<0..2^16-1>;
       } ECHConfigExtension;

       struct {
           HpkeKeyConfig key_config;
           uint8 maximum_name_length;
           opaque public_name<1..255>;
           ECHConfigExtension extensions<0..2^16-1>;
       } ECHConfigContents;

       struct {
           uint16 version;
           uint16 length;
           select (ECHConfig.version) {
             case 0xfe0d: ECHConfigContents contents;
           }
       } ECHConfig;

    Args:
        proto: Protocol reading the configuration, whose alias the error message names.
        data: Buffer being read.
        pos: Offset of the configuration.

    Returns:
        The configuration, its ``contents`` the raw octets for a version other
        than ``0xFE0D``; and the offset just past it.

    Raises:
        ProtocolError: If the configuration runs past the end of ``data``, or
            a version ``0xFE0D`` configuration's ``contents`` is malformed.

    """
    version = proto._read_uint(data, pos, size=2, what='ECHConfig.version')  # pylint: disable=protected-access
    contents, end = proto._read_vector(data, pos + 2, size=2, what='ECHConfig.contents')  # pylint: disable=protected-access
    if version != _ECH_CONFIG_VERSION:
        return Data_ECHConfig(version=version, contents=contents), end

    config_id = proto._read_uint(contents, size=1, what='ECHConfig.config_id')  # pylint: disable=protected-access
    kem_id = proto._read_uint(contents, 1, size=2, what='ECHConfig.kem_id')  # pylint: disable=protected-access
    public_key, cur = proto._read_vector(contents, 3, size=2, what='ECHConfig.public_key')  # pylint: disable=protected-access
    suites, cur = proto._read_vector(contents, cur, size=2, what='ECHConfig.cipher_suites')  # pylint: disable=protected-access
    if len(suites) % 4:
        raise ProtocolError(f'{proto.alias}: invalid format: ECHConfig.cipher_suites length '
                            f'{len(suites)} is not a multiple of 4')
    maximum_name_length = proto._read_uint(contents, cur, size=1, what='ECHConfig.maximum_name_length')  # pylint: disable=protected-access
    public_name, cur = proto._read_vector(contents, cur + 1, size=1, what='ECHConfig.public_name')  # pylint: disable=protected-access
    extensions_raw, cur = proto._read_vector(contents, cur, size=2, what='ECHConfig.extensions')  # pylint: disable=protected-access
    if cur != len(contents):
        raise ProtocolError(f'{proto.alias}: invalid format: ECHConfig.contents carries excess octets')

    extensions = []  # type: list[Data_ECHConfigExtension]
    cur = 0
    while cur < len(extensions_raw):
        ext_type = proto._read_uint(extensions_raw, cur, size=2, what='ECHConfigExtension.type')  # pylint: disable=protected-access
        ext_data, cur = proto._read_vector(extensions_raw, cur + 2, size=2, what='ECHConfigExtension.data')  # pylint: disable=protected-access
        extensions.append(Data_ECHConfigExtension(type=ext_type, data=ext_data))

    key_config = Data_HpkeKeyConfig(
        config_id=config_id, kem_id=kem_id, public_key=public_key,
        cipher_suites=tuple(_read_hpke_cipher_suite(proto, suites, index) for index in range(0, len(suites), 4)),
    )
    return Data_ECHConfig(version=version, contents=Data_ECHConfigContents(
        key_config=key_config, maximum_name_length=maximum_name_length, public_name=public_name,
        extensions=tuple(extensions),
    )), end


def _make_ech_config(proto: 'SSL', config: 'Data_ECHConfig') -> 'bytes':
    """Write one ``ECHConfig`` -- the inverse of :func:`_read_ech_config`.

    ``contents`` given as octets is written as it is, whatever the version.

    """
    pack, vector = proto._make_pack, proto._make_vector  # pylint: disable=protected-access
    contents = config.contents
    if not isinstance(contents, bytes):
        key = contents.key_config
        contents = b''.join((
            pack(int(key.config_id), size=1), pack(int(key.kem_id), size=2), vector(key.public_key, size=2),
            vector(b''.join(_make_hpke_cipher_suite(proto, suite) for suite in key.cipher_suites), size=2),
            pack(int(contents.maximum_name_length), size=1), vector(contents.public_name, size=1),
            vector(b''.join(pack(int(ext.type), size=2) + vector(ext.data, size=2) for ext in contents.extensions),
                   size=2),
        ))
    return pack(int(config.version), size=2) + vector(contents, size=2)


def _hello_type(random: 'bytes') -> 'Enum_HandshakeType':
    """The message a ``ServerHello`` with ``random`` is: a ``HelloRetryRequest``
    for :data:`_HRR_RANDOM`, a ``ServerHello`` otherwise."""
    if random == _HRR_RANDOM:
        return cast('Enum_HandshakeType', Enum_HandshakeType.hello_retry_request)
    return cast('Enum_HandshakeType', Enum_HandshakeType.server_hello)


def _tls_handshake_tiles(fragment: 'bytes') -> 'bool':
    """Whether ``fragment`` is tiled exactly by handshake-message headers.

    Once keys are derived a ``handshake`` record carries ciphertext, and its
    header does not say so. A cleartext fragment is a whole number of
    ``msg_type``/``length``-framed messages; ciphertext almost never is.

    Args:
        fragment: Record fragment, i.e. the candidate handshake messages.

    Returns:
        Whether the walk lands exactly on the end of ``fragment``.

    Notes:
        A heuristic: ciphertext that happens to tile is decoded, and a
        message split across records is not. Keeping a cleartext message
        opaque loses nothing; decoding ciphertext would fabricate messages.

    """
    pos = 0
    total = len(fragment)
    while pos < total:
        if total - pos < 4:
            return False
        pos += 4 + int.from_bytes(fragment[pos + 1:pos + 4], 'big')
    return pos == total


class SSL(Application[_PT, _ST], Generic[_PT, _ST]):  # pylint: disable=abstract-method
    """Umbrella base class for the SSL protocol family: the SSL versions, TLS and DTLS.

    - SSL 2.0 (:class:`~pcapkit.protocols.application.sslv2.protocol.SSLv2`) [draft-hickman-netscape-ssl-00]
    - Transport Layer Security, SSLv3 through TLS 1.3
      (:class:`~pcapkit.protocols.application.tls.protocol.TLS`) [:rfc:`6101`, :rfc:`5246`, :rfc:`9846`]
    - Datagram TLS, DTLS 1.0 through DTLS 1.3
      (:class:`~pcapkit.protocols.application.dtls.protocol.DTLS`) [:rfc:`4347`, :rfc:`6347`, :rfc:`9147`]

    The ``extension_data`` of these extensions decodes, in ``ClientHello``,
    ``ServerHello``, ``HelloRetryRequest`` and ``EncryptedExtensions``:

    .. list-table::
       :header-rows: 1

       * - Extension Type
         - Extension Parser
         - Extension Constructor
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.server_name`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._read_ext_server_name`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._make_ext_server_name`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.status_request`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._read_ext_status_request`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._make_ext_status_request`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.supported_groups`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._read_ext_supported_groups`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._make_ext_supported_groups`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.ec_point_formats`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._read_ext_ec_point_formats`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._make_ext_ec_point_formats`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.signature_algorithms`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._read_ext_signature_algorithms`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._make_ext_signature_algorithms`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.application_layer_protocol_negotiation`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._read_ext_alpn`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._make_ext_alpn`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.signed_certificate_timestamp`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._read_ext_signed_certificate_timestamp`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._make_ext_signed_certificate_timestamp`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.padding`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._read_ext_padding`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._make_ext_padding`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.extended_main_secret`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._read_ext_extended_main_secret`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._make_ext_extended_main_secret`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.compress_certificate`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._read_ext_compress_certificate`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._make_ext_compress_certificate`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.record_size_limit`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._read_ext_record_size_limit`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._make_ext_record_size_limit`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.session_ticket`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._read_ext_session_ticket`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._make_ext_session_ticket`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.pre_shared_key`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._read_ext_pre_shared_key`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._make_ext_pre_shared_key`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.early_data`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._read_ext_early_data`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._make_ext_early_data`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.supported_versions`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._read_ext_supported_versions`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._make_ext_supported_versions`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.cookie`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._read_ext_cookie`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._make_ext_cookie`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.psk_key_exchange_modes`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._read_ext_psk_key_exchange_modes`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._make_ext_psk_key_exchange_modes`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.post_handshake_auth`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._read_ext_post_handshake_auth`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._make_ext_post_handshake_auth`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.key_share`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._read_ext_key_share`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._make_ext_key_share`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.connection_id`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._read_ext_connection_id`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._make_ext_connection_id`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.encrypted_client_hello`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._read_ext_ech`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._make_ext_ech`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.renegotiation_info`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._read_ext_renegotiation_info`
         - :meth:`~pcapkit.protocols.application.ssl.protocol.SSL._make_ext_renegotiation_info`

    GREASE values (:rfc:`8701`) are ``Reserved`` extension types with no
    decoder, so their bodies stay raw octets.

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Extension type to method mapping, see :meth:`_read_tls_extensions` and
    #: :meth:`_make_tls_extensions`. A :obj:`str` value names the methods
    #: ``_read_ext_${name}`` and ``_make_ext_${name}``, falling back to
    #: :meth:`_read_ext_unknown` and :meth:`_make_ext_unknown` when the class
    #: has no such method, as an unregistered type does; any other value is a
    #: ``(parser, constructor)`` pair of callables.
    __extension__ = collections.defaultdict(
        lambda: 'unknown',
        {
            Enum_ExtensionType.server_name: 'server_name',                         # [RFC 6066]
            Enum_ExtensionType.status_request: 'status_request',                   # [RFC 6066]
            Enum_ExtensionType.supported_groups: 'supported_groups',               # [RFC 9846]
            Enum_ExtensionType.ec_point_formats: 'ec_point_formats',               # [RFC 8422]
            Enum_ExtensionType.signature_algorithms: 'signature_algorithms',       # [RFC 9846]
            Enum_ExtensionType.application_layer_protocol_negotiation: 'alpn',     # [RFC 7301]
            Enum_ExtensionType.signed_certificate_timestamp: 'signed_certificate_timestamp',  # [RFC 6962]
            Enum_ExtensionType.padding: 'padding',                                 # [RFC 7685]
            Enum_ExtensionType.extended_main_secret: 'extended_main_secret',       # [RFC 7627]
            Enum_ExtensionType.compress_certificate: 'compress_certificate',       # [RFC 8879]
            Enum_ExtensionType.record_size_limit: 'record_size_limit',             # [RFC 8449]
            Enum_ExtensionType.session_ticket: 'session_ticket',                   # [RFC 5077]
            Enum_ExtensionType.pre_shared_key: 'pre_shared_key',                   # [RFC 9846]
            Enum_ExtensionType.early_data: 'early_data',                           # [RFC 9846]
            Enum_ExtensionType.supported_versions: 'supported_versions',           # [RFC 9846]
            Enum_ExtensionType.cookie: 'cookie',                                   # [RFC 9846]
            Enum_ExtensionType.psk_key_exchange_modes: 'psk_key_exchange_modes',   # [RFC 9846]
            Enum_ExtensionType.post_handshake_auth: 'post_handshake_auth',         # [RFC 9846]
            Enum_ExtensionType.key_share: 'key_share',                             # [RFC 9846]
            Enum_ExtensionType.connection_id: 'connection_id',                     # [RFC 9146]
            Enum_ExtensionType.encrypted_client_hello: 'ech',                      # [RFC 9849]
            Enum_ExtensionType.renegotiation_info: 'renegotiation_info',           # [RFC 5746]
        },
    )  # type: DefaultDict[Enum_ExtensionType | int, str | tuple[ExtensionParser, ExtensionConstructor]]

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["SSLv2"], Literal["TLS"], Literal["DTLS"]]':
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol: the direct concrete members of the family.
            SSLv3 is not listed, as it is a subclass of
            :class:`~pcapkit.protocols.application.tls.protocol.TLS`.

        """
        return ('SSLv2', 'TLS', 'DTLS')

    @classmethod
    def register_extension(cls, code: 'Enum_ExtensionType',
                           meth: 'str | tuple[ExtensionParser, ExtensionConstructor]') -> 'None':
        """Register an extension parser.

        Args:
            code: TLS/DTLS extension type.
            meth: Name of the ``_read_ext_${name}`` and ``_make_ext_${name}``
                methods, or a ``(parser, constructor)`` pair of callables; see
                :attr:`__extension__`.

        Warns:
            RegistryWarning: If a different entry is already registered for
                ``code``; it is overwritten. Handing back the entry already
                stored, or one equal to it, is a silent no-op. The entry
                ``code`` shipped with is accepted like any other, so an
                override can be undone (:issue:`1362`, :issue:`1363`).

        """
        incumbent = cls.__extension__.get(code)
        if incumbent is not None and incumbent == meth:
            return
        if incumbent is not None:
            warn(f'TLS: [Extension {code}] extension already registered, overwriting', RegistryWarning)
        cls.__extension__[code] = meth

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_ext_unknown(self, ext_type: 'Enum_ExtensionType', data: 'bytes', *,  # pylint: disable=unused-argument
                          msg_type: 'Enum_HandshakeType') -> 'bytes':  # pylint: disable=unused-argument
        """Read an extension with no decoder registered: its raw octets.

        Args:
            ext_type: Extension type.
            data: ``extension_data`` octets.
            msg_type: Handshake message carrying the extension.

        Returns:
            ``data`` unchanged.

        """
        return data

    def _read_ext_server_name(self, ext_type: 'Enum_ExtensionType', data: 'bytes', *,  # pylint: disable=unused-argument
                              msg_type: 'Enum_HandshakeType') -> 'Data_ServerNameList | bytes':  # pylint: disable=unused-argument
        """Read a ``server_name`` extension.

        Structure of ``ServerNameList`` [:rfc:`6066#section-3`]:

        .. code-block:: text

           struct {
               NameType name_type;
               select (name_type) {
                   case host_name: HostName;
               } name;
           } ServerName;

           enum {
               host_name(0), (255)
           } NameType;

           opaque HostName<1..2^16-1>;

           struct {
               ServerName server_name_list<1..2^16-1>
           } ServerNameList;

        Args:
            ext_type: Extension type.
            data: ``extension_data`` octets.
            msg_type: Handshake message carrying the extension.

        Returns:
            The decoded list; or ``data`` when empty, as a ``ServerHello``'s
            and an ``EncryptedExtensions``' are.

        Raises:
            ProtocolError: If ``data`` is malformed, or names a type other
                than ``host_name``, whose ``name`` has no defined structure.

        """
        if not data:
            return data

        alias = self.alias
        body = self._read_whole_vector(data, size=2, what='server_name.server_name_list')
        names = []  # type: list[Data_ServerName]
        pos = 0
        while pos < len(body):
            name_type = self._read_uint(body, pos, size=1, what='server_name.name_type')
            if name_type != _HOST_NAME:
                raise ProtocolError(f'{alias}: invalid format: server_name.name_type {name_type} '
                                    'is not host_name')
            name, pos = self._read_vector(body, pos + 1, size=2, what='server_name.name')
            names.append(Data_ServerName(name_type=name_type, name=name))
        return Data_ServerNameList(server_name_list=tuple(names))

    def _read_ext_status_request(self, ext_type: 'Enum_ExtensionType', data: 'bytes', *,  # pylint: disable=unused-argument
                                 msg_type: 'Enum_HandshakeType') -> 'Data_CertificateStatusRequest | Data_Empty | bytes':  # pylint: disable=line-too-long
        """Read a ``status_request`` extension.

        Structure of ``CertificateStatusRequest`` [:rfc:`6066#section-8`]:

        .. code-block:: text

           struct {
               CertificateStatusType status_type;
               select (status_type) {
                   case ocsp: OCSPStatusRequest;
               } request;
           } CertificateStatusRequest;

           enum { ocsp(1), (255) } CertificateStatusType;

           struct {
               ResponderID responder_id_list<0..2^16-1>;
               Extensions  request_extensions;
           } OCSPStatusRequest;

           opaque ResponderID<1..2^16-1>;
           opaque Extensions<0..2^16-1>;

        A ``ServerHello`` carries the extension empty.

        Args:
            ext_type: Extension type.
            data: ``extension_data`` octets.
            msg_type: Handshake message carrying the extension.

        Returns:
            The decoded request for a ``ClientHello``, an empty structure for a
            ``ServerHello``, or ``data`` for a message the structure does not cover.

        Raises:
            ProtocolError: If ``data`` is malformed, or names a status type
                other than ``ocsp``, whose ``request`` has no defined structure.

        """
        if msg_type == Enum_HandshakeType.server_hello:
            return _read_empty(self, data, what='status_request')
        if msg_type != Enum_HandshakeType.client_hello:
            return data

        alias = self.alias
        status_type = Enum_CertificateStatusType.get(self._read_uint(data, size=1, what='status_request.status_type'))
        if status_type != Enum_CertificateStatusType.ocsp:
            raise ProtocolError(f'{alias}: invalid format: status_request.status_type {int(status_type)} '
                                'is not ocsp')
        ids, pos = self._read_vector(data, 1, size=2, what='status_request.responder_id_list')
        request_extensions, pos = self._read_vector(data, pos, size=2, what='status_request.request_extensions')
        if pos != len(data):
            raise ProtocolError(f'{alias}: invalid format: status_request carries excess octets')
        return Data_CertificateStatusRequest(status_type=status_type, request=Data_OCSPStatusRequest(
            responder_id_list=_read_vectors(self, ids, size=2, what='status_request.responder_id'),
            request_extensions=request_extensions,
        ))

    def _read_ext_supported_groups(self, ext_type: 'Enum_ExtensionType', data: 'bytes', *,  # pylint: disable=unused-argument
                                   msg_type: 'Enum_HandshakeType') -> 'Data_NamedGroupList':  # pylint: disable=unused-argument
        """Read a ``supported_groups`` extension.

        Structure of ``NamedGroupList`` [:rfc:`9846#section-4.3.7`]:

        .. code-block:: text

           struct {
               NamedGroup named_group_list<2..2^16-1>;
           } NamedGroupList;

        Args:
            ext_type: Extension type.
            data: ``extension_data`` octets.
            msg_type: Handshake message carrying the extension.

        Returns:
            The decoded list.

        Raises:
            ProtocolError: If ``data`` is malformed.

        """
        what = 'supported_groups.named_group_list'
        body = self._read_whole_vector(data, size=2, what=what)
        return Data_NamedGroupList(named_group_list=self._read_uints(body, size=2, what=what))

    def _read_ext_ec_point_formats(self, ext_type: 'Enum_ExtensionType', data: 'bytes', *,  # pylint: disable=unused-argument
                                   msg_type: 'Enum_HandshakeType') -> 'Data_ECPointFormatList | bytes':
        """Read an ``ec_point_formats`` extension.

        Structure of ``ECPointFormatList`` [:rfc:`8422#section-5.1.2`]:

        .. code-block:: text

           enum {
               uncompressed (0),
               deprecated (1..2),
               reserved (248..255)
           } ECPointFormat;
           struct {
               ECPointFormat ec_point_format_list<1..2^8-1>
           } ECPointFormatList;

        Args:
            ext_type: Extension type.
            data: ``extension_data`` octets.
            msg_type: Handshake message carrying the extension.

        Returns:
            The decoded list in a ``ClientHello`` or ``ServerHello``, where the extension is
            defined; or ``data`` in any other message.

        Raises:
            ProtocolError: If ``data`` is malformed.

        """
        if msg_type not in (Enum_HandshakeType.client_hello, Enum_HandshakeType.server_hello):
            return data
        body = self._read_whole_vector(data, size=1, what='ec_point_formats.ec_point_format_list')
        return Data_ECPointFormatList(ec_point_format_list=tuple(Enum_ECPointFormat.get(code) for code in body))

    def _read_ext_signature_algorithms(self, ext_type: 'Enum_ExtensionType', data: 'bytes', *,  # pylint: disable=unused-argument
                                       msg_type: 'Enum_HandshakeType') -> 'Data_SignatureSchemeList':  # pylint: disable=unused-argument
        """Read a ``signature_algorithms`` extension.

        Structure of ``SignatureSchemeList`` [:rfc:`9846#section-4.3.3`]:

        .. code-block:: text

           struct {
               SignatureScheme supported_signature_algorithms<2..2^16-2>;
           } SignatureSchemeList;

        Args:
            ext_type: Extension type.
            data: ``extension_data`` octets.
            msg_type: Handshake message carrying the extension.

        Returns:
            The decoded list.

        Raises:
            ProtocolError: If ``data`` is malformed.

        """
        what = 'signature_algorithms.supported_signature_algorithms'
        body = self._read_whole_vector(data, size=2, what=what)
        return Data_SignatureSchemeList(supported_signature_algorithms=self._read_uints(body, size=2, what=what))

    def _read_ext_alpn(self, ext_type: 'Enum_ExtensionType', data: 'bytes', *,  # pylint: disable=unused-argument
                       msg_type: 'Enum_HandshakeType') -> 'Data_ProtocolNameList':  # pylint: disable=unused-argument
        """Read an ``application_layer_protocol_negotiation`` extension.

        Structure of ``ProtocolNameList`` [:rfc:`7301#section-3.1`]:

        .. code-block:: text

           opaque ProtocolName<1..2^8-1>;

           struct {
               ProtocolName protocol_name_list<2..2^16-1>
           } ProtocolNameList;

        Args:
            ext_type: Extension type.
            data: ``extension_data`` octets.
            msg_type: Handshake message carrying the extension.

        Returns:
            The decoded list.

        Raises:
            ProtocolError: If ``data`` is malformed.

        """
        body = self._read_whole_vector(data, size=2, what='alpn.protocol_name_list')
        names = []  # type: list[bytes]
        pos = 0
        while pos < len(body):
            name, pos = self._read_vector(body, pos, size=1, what='alpn.protocol_name')
            names.append(name)
        return Data_ProtocolNameList(protocol_name_list=tuple(names))

    def _read_ext_signed_certificate_timestamp(self, ext_type: 'Enum_ExtensionType', data: 'bytes', *,  # pylint: disable=unused-argument
                                               msg_type: 'Enum_HandshakeType') -> 'Data_SignedCertificateTimestampList | Data_Empty | bytes':  # pylint: disable=line-too-long
        """Read a ``signed_certificate_timestamp`` extension.

        Structure of ``SignedCertificateTimestampList`` [:rfc:`6962#section-3.3`]:

        .. code-block:: text

           opaque SerializedSCT<1..2^16-1>;

           struct {
               SerializedSCT sct_list <1..2^16-1>;
           } SignedCertificateTimestampList;

        A ``ClientHello`` carries the extension empty, and a ``ServerHello``
        the list (:rfc:`6962#section-3.3.1`).

        Args:
            ext_type: Extension type.
            data: ``extension_data`` octets.
            msg_type: Handshake message carrying the extension.

        Returns:
            An empty structure for a ``ClientHello``, the decoded list for a
            ``ServerHello``, or ``data`` for a message the structure does not cover.

        Raises:
            ProtocolError: If ``data`` is malformed.

        """
        if msg_type == Enum_HandshakeType.client_hello:
            return _read_empty(self, data, what='signed_certificate_timestamp')
        if msg_type == Enum_HandshakeType.server_hello:
            body = self._read_whole_vector(data, size=2, what='signed_certificate_timestamp.sct_list')
            return Data_SignedCertificateTimestampList(sct_list=_read_vectors(
                self, body, size=2, what='signed_certificate_timestamp.serialized_sct'))
        return data

    def _read_ext_padding(self, ext_type: 'Enum_ExtensionType', data: 'bytes', *,  # pylint: disable=unused-argument
                          msg_type: 'Enum_HandshakeType') -> 'Data_Padding | bytes':
        """Read a ``padding`` extension.

        Its ``extension_data`` is any number of zero octets [:rfc:`7685#section-3`],
        kept as captured.

        Args:
            ext_type: Extension type.
            data: ``extension_data`` octets.
            msg_type: Handshake message carrying the extension.

        Returns:
            The padding in a ``ClientHello``, where the extension is defined; or ``data`` in
            any other message.

        """
        if msg_type != Enum_HandshakeType.client_hello:
            return data
        return Data_Padding(padding=data)

    def _read_ext_extended_main_secret(self, ext_type: 'Enum_ExtensionType', data: 'bytes', *,  # pylint: disable=unused-argument
                                       msg_type: 'Enum_HandshakeType') -> 'Data_Empty | bytes':
        """Read an ``extended_main_secret`` extension, whose ``extension_data``
        is empty [:rfc:`7627#section-5.1`].

        Args:
            ext_type: Extension type.
            data: ``extension_data`` octets.
            msg_type: Handshake message carrying the extension.

        Returns:
            An empty structure in a ``ClientHello`` or ``ServerHello``, where the extension
            is defined; or ``data`` in any other message.

        Raises:
            ProtocolError: If ``data`` is not empty.

        """
        if msg_type not in (Enum_HandshakeType.client_hello, Enum_HandshakeType.server_hello):
            return data
        return _read_empty(self, data, what='extended_main_secret')

    def _read_ext_compress_certificate(self, ext_type: 'Enum_ExtensionType', data: 'bytes', *,  # pylint: disable=unused-argument
                                       msg_type: 'Enum_HandshakeType') -> 'Data_CertificateCompressionAlgorithms | bytes':  # pylint: disable=line-too-long
        """Read a ``compress_certificate`` extension.

        Structure of ``CertificateCompressionAlgorithms`` [:rfc:`8879#section-3`]:

        .. code-block:: text

           enum {
               zlib(1),
               brotli(2),
               zstd(3),
               (65535)
           } CertificateCompressionAlgorithm;

           struct {
               CertificateCompressionAlgorithm algorithms<2..2^8-2>;
           } CertificateCompressionAlgorithms;

        Args:
            ext_type: Extension type.
            data: ``extension_data`` octets.
            msg_type: Handshake message carrying the extension.

        Returns:
            The decoded list in a ``ClientHello``, where the extension is defined; or
            ``data`` in any other message.

        Raises:
            ProtocolError: If ``data`` is malformed.

        """
        if msg_type != Enum_HandshakeType.client_hello:
            return data
        what = 'compress_certificate.algorithms'
        body = self._read_whole_vector(data, size=1, what=what)
        return Data_CertificateCompressionAlgorithms(algorithms=tuple(
            Enum_CertificateCompressionAlgorithm.get(code) for code in self._read_uints(body, size=2, what=what)))

    def _read_ext_record_size_limit(self, ext_type: 'Enum_ExtensionType', data: 'bytes', *,  # pylint: disable=unused-argument
                                    msg_type: 'Enum_HandshakeType') -> 'Data_RecordSizeLimit | bytes':
        """Read a ``record_size_limit`` extension.

        Structure of ``RecordSizeLimit`` [:rfc:`8449#section-4`]:

        .. code-block:: text

           uint16 RecordSizeLimit;

        The extension is valid in every TLS version (:rfc:`8449#section-1`), so a
        server answers in its ``ServerHello`` before TLS 1.3 and in
        ``EncryptedExtensions`` from it.

        Args:
            ext_type: Extension type.
            data: ``extension_data`` octets.
            msg_type: Handshake message carrying the extension.

        Returns:
            The decoded limit in a ``ClientHello``, ``ServerHello`` or
            ``EncryptedExtensions``, where the extension is defined; or ``data`` in any
            other message.

        Raises:
            ProtocolError: If ``data`` is not exactly two octets.

        """
        if msg_type not in (Enum_HandshakeType.client_hello, Enum_HandshakeType.server_hello,
                            Enum_HandshakeType.encrypted_extensions):
            return data
        if len(data) != 2:
            raise ProtocolError(f'{self.alias}: invalid format: record_size_limit must be exactly two octets')
        return Data_RecordSizeLimit(record_size_limit=self._read_uint(data, size=2, what='record_size_limit'))

    def _read_ext_session_ticket(self, ext_type: 'Enum_ExtensionType', data: 'bytes', *,  # pylint: disable=unused-argument
                                 msg_type: 'Enum_HandshakeType') -> 'Data_SessionTicket | bytes':
        """Read a ``session_ticket`` extension, whose ``extension_data`` is the
        ticket itself, with no length of its own [:rfc:`5077#section-3.2`].

        Args:
            ext_type: Extension type.
            data: ``extension_data`` octets.
            msg_type: Handshake message carrying the extension.

        Returns:
            The ticket in a ``ClientHello`` or ``ServerHello``, where the extension is
            defined; or ``data`` in any other message.

        """
        if msg_type not in (Enum_HandshakeType.client_hello, Enum_HandshakeType.server_hello):
            return data
        return Data_SessionTicket(ticket=data)

    def _read_ext_pre_shared_key(self, ext_type: 'Enum_ExtensionType', data: 'bytes', *,  # pylint: disable=unused-argument
                                 msg_type: 'Enum_HandshakeType') -> 'Data_OfferedPsks | Data_PreSharedKeyServerHello | bytes':  # pylint: disable=line-too-long
        """Read a ``pre_shared_key`` extension.

        Structure of ``PreSharedKeyExtension`` [:rfc:`9846#section-4.3.11`]:

        .. code-block:: text

           struct {
               opaque identity<1..2^16-1>;
               uint32 obfuscated_ticket_age;
           } PskIdentity;

           opaque PskBinderEntry<32..255>;

           struct {
               PskIdentity identities<7..2^16-1>;
               PskBinderEntry binders<33..2^16-1>;
           } OfferedPsks;

           struct {
               select (Handshake.msg_type) {
                   case client_hello: OfferedPsks;
                   case server_hello: uint16 selected_identity;
               };
           } PreSharedKeyExtension;

        Args:
            ext_type: Extension type.
            data: ``extension_data`` octets.
            msg_type: Handshake message carrying the extension.

        Returns:
            The decoded structure for ``msg_type``; or ``data`` for a message
            the structure does not cover.

        Raises:
            ProtocolError: If ``data`` is malformed.

        """
        alias = self.alias
        if msg_type == Enum_HandshakeType.client_hello:
            body, pos = self._read_vector(data, size=2, what='pre_shared_key.identities')
            binders, end = self._read_vector(data, pos, size=2, what='pre_shared_key.binders')
            if end != len(data):
                raise ProtocolError(f'{alias}: invalid format: pre_shared_key carries excess octets')
            identities = []  # type: list[Data_PskIdentity]
            pos = 0
            while pos < len(body):
                identity, pos = self._read_vector(body, pos, size=2, what='pre_shared_key.identity')
                age = self._read_uint(body, pos, size=4, what='pre_shared_key.obfuscated_ticket_age')
                identities.append(Data_PskIdentity(identity=identity, obfuscated_ticket_age=age))
                pos += 4
            return Data_OfferedPsks(identities=tuple(identities),
                                    binders=_read_vectors(self, binders, size=1, what='pre_shared_key.binder'))
        if msg_type == Enum_HandshakeType.server_hello:
            if len(data) != 2:
                raise ProtocolError(f'{alias}: invalid format: pre_shared_key.selected_identity '
                                    'must be exactly two octets')
            return Data_PreSharedKeyServerHello(selected_identity=self._read_uint(
                data, size=2, what='pre_shared_key.selected_identity'))
        return data

    def _read_ext_early_data(self, ext_type: 'Enum_ExtensionType', data: 'bytes', *,  # pylint: disable=unused-argument
                             msg_type: 'Enum_HandshakeType') -> 'Data_Empty | bytes':
        """Read an ``early_data`` extension.

        Structure of ``EarlyDataIndication`` [:rfc:`9846#section-4.3.10`]:

        .. code-block:: text

           struct {} Empty;

           struct {
               select (Handshake.msg_type) {
                   case new_session_ticket:   uint32 max_early_data_size;
                   case client_hello:         Empty;
                   case encrypted_extensions: Empty;
               };
           } EarlyDataIndication;

        Args:
            ext_type: Extension type.
            data: ``extension_data`` octets.
            msg_type: Handshake message carrying the extension.

        Returns:
            An empty structure for a ``ClientHello`` or ``EncryptedExtensions``,
            or ``data`` for a message the structure does not cover.

        Raises:
            ProtocolError: If ``data`` is not empty in a message whose structure
                is empty.

        """
        if msg_type in (Enum_HandshakeType.client_hello, Enum_HandshakeType.encrypted_extensions):
            return _read_empty(self, data, what='early_data')
        return data

    def _read_ext_supported_versions(self, ext_type: 'Enum_ExtensionType', data: 'bytes', *,  # pylint: disable=unused-argument
                                     msg_type: 'Enum_HandshakeType') -> 'Data_SupportedVersionsClientHello | Data_SupportedVersionsServerHello | bytes':  # pylint: disable=line-too-long
        """Read a ``supported_versions`` extension.

        Structure of ``SupportedVersions`` [:rfc:`9846#section-4.3.1`]:

        .. code-block:: text

           struct {
               select (Handshake.msg_type) {
                   case client_hello:
                        ProtocolVersion versions<2..254>;

                   case server_hello: /* and HelloRetryRequest */
                        ProtocolVersion selected_version;
               };
           } SupportedVersions;

        Args:
            ext_type: Extension type.
            data: ``extension_data`` octets.
            msg_type: Handshake message carrying the extension.

        Returns:
            The decoded versions for ``msg_type``; or ``data`` for a message
            the structure does not cover.

        Raises:
            ProtocolError: If ``data`` is malformed.

        """
        alias = self.alias
        if msg_type == Enum_HandshakeType.client_hello:
            what = 'supported_versions.versions'
            body = self._read_whole_vector(data, size=1, what=what)
            return Data_SupportedVersionsClientHello(versions=self._read_uints(body, size=2, what=what))
        if msg_type in (Enum_HandshakeType.server_hello, Enum_HandshakeType.hello_retry_request):
            if len(data) != 2:
                raise ProtocolError(f'{alias}: invalid format: supported_versions.selected_version '
                                    'must be exactly two octets')
            return Data_SupportedVersionsServerHello(selected_version=self._read_uint(
                data, size=2, what='supported_versions.selected_version'))
        return data

    def _read_ext_cookie(self, ext_type: 'Enum_ExtensionType', data: 'bytes', *,  # pylint: disable=unused-argument
                         msg_type: 'Enum_HandshakeType') -> 'Data_Cookie | bytes':
        """Read a ``cookie`` extension.

        Structure of ``Cookie`` [:rfc:`9846#section-4.3.2`]:

        .. code-block:: text

           struct {
               opaque cookie<1..2^16-1>;
           } Cookie;

        Args:
            ext_type: Extension type.
            data: ``extension_data`` octets.
            msg_type: Handshake message carrying the extension.

        Returns:
            The decoded cookie in a ``ClientHello`` or ``HelloRetryRequest``, where the
            extension is defined; or ``data`` in any other message.

        Raises:
            ProtocolError: If ``data`` is malformed.

        """
        if msg_type not in (Enum_HandshakeType.client_hello, Enum_HandshakeType.hello_retry_request):
            return data
        return Data_Cookie(cookie=self._read_whole_vector(data, size=2, what='cookie.cookie'))

    def _read_ext_psk_key_exchange_modes(self, ext_type: 'Enum_ExtensionType', data: 'bytes', *,  # pylint: disable=unused-argument
                                         msg_type: 'Enum_HandshakeType') -> 'Data_PskKeyExchangeModes | bytes':
        """Read a ``psk_key_exchange_modes`` extension.

        Structure of ``PskKeyExchangeModes`` [:rfc:`9846#section-4.3.9`]:

        .. code-block:: text

           enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;

           struct {
               PskKeyExchangeMode ke_modes<1..255>;
           } PskKeyExchangeModes;

        Args:
            ext_type: Extension type.
            data: ``extension_data`` octets.
            msg_type: Handshake message carrying the extension.

        Returns:
            The decoded modes in a ``ClientHello``, where the extension is defined; or
            ``data`` in any other message.

        Raises:
            ProtocolError: If ``data`` is malformed.

        """
        if msg_type != Enum_HandshakeType.client_hello:
            return data
        body = self._read_whole_vector(data, size=1, what='psk_key_exchange_modes.ke_modes')
        return Data_PskKeyExchangeModes(ke_modes=tuple(Enum_PskKeyExchangeMode.get(code) for code in body))

    def _read_ext_post_handshake_auth(self, ext_type: 'Enum_ExtensionType', data: 'bytes', *,  # pylint: disable=unused-argument
                                      msg_type: 'Enum_HandshakeType') -> 'Data_Empty | bytes':
        """Read a ``post_handshake_auth`` extension, whose ``extension_data`` is
        empty [:rfc:`9846#section-4.3.6`].

        Args:
            ext_type: Extension type.
            data: ``extension_data`` octets.
            msg_type: Handshake message carrying the extension.

        Returns:
            An empty structure in a ``ClientHello``, where the extension is defined; or
            ``data`` in any other message.

        Raises:
            ProtocolError: If ``data`` is not empty.

        """
        if msg_type != Enum_HandshakeType.client_hello:
            return data
        return _read_empty(self, data, what='post_handshake_auth')

    def _read_ext_key_share(self, ext_type: 'Enum_ExtensionType', data: 'bytes', *,  # pylint: disable=unused-argument
                            msg_type: 'Enum_HandshakeType') -> 'Data_KeyShareClientHello | Data_KeyShareHelloRetryRequest | Data_KeyShareServerHello | bytes':  # pylint: disable=line-too-long
        """Read a ``key_share`` extension.

        Structure of ``key_share`` [:rfc:`9846#section-4.3.8`]:

        .. code-block:: text

           struct {
               NamedGroup group;
               opaque key_exchange<1..2^16-1>;
           } KeyShareEntry;

           struct {
               KeyShareEntry client_shares<0..2^16-1>;
           } KeyShareClientHello;

           struct {
               NamedGroup selected_group;
           } KeyShareHelloRetryRequest;

           struct {
               KeyShareEntry server_share;
           } KeyShareServerHello;

        Args:
            ext_type: Extension type.
            data: ``extension_data`` octets.
            msg_type: Handshake message carrying the extension.

        Returns:
            The decoded structure for ``msg_type``; or ``data`` for a message
            the structure does not cover.

        Raises:
            ProtocolError: If ``data`` is malformed.

        """
        alias = self.alias
        if msg_type == Enum_HandshakeType.client_hello:
            body = self._read_whole_vector(data, size=2, what='key_share.client_shares')
            shares = []  # type: list[Data_KeyShareEntry]
            pos = 0
            while pos < len(body):
                entry, pos = _read_key_share_entry(self, body, pos)
                shares.append(entry)
            return Data_KeyShareClientHello(client_shares=tuple(shares))
        if msg_type == Enum_HandshakeType.hello_retry_request:
            if len(data) != 2:
                raise ProtocolError(f'{alias}: invalid format: key_share.selected_group '
                                    'must be exactly two octets')
            return Data_KeyShareHelloRetryRequest(selected_group=self._read_uint(
                data, size=2, what='key_share.selected_group'))
        if msg_type == Enum_HandshakeType.server_hello:
            entry, end = _read_key_share_entry(self, data, 0)
            if end != len(data):
                raise ProtocolError(f'{alias}: invalid format: key_share.server_share carries excess octets')
            return Data_KeyShareServerHello(server_share=entry)
        return data

    def _read_ext_connection_id(self, ext_type: 'Enum_ExtensionType', data: 'bytes', *,  # pylint: disable=unused-argument
                                msg_type: 'Enum_HandshakeType') -> 'Data_ConnectionId':  # pylint: disable=unused-argument
        """Read a ``connection_id`` extension.

        Structure of ``ConnectionId`` [:rfc:`9146#section-3`]:

        .. code-block:: text

           struct {
               opaque cid<0..2^8-1>;
           } ConnectionId;

        The extension is DTLS-only (:rfc:`9146#section-10.2`). A TLS hello
        carrying it does not conform, and it decodes all the same.

        Args:
            ext_type: Extension type.
            data: ``extension_data`` octets.
            msg_type: Handshake message carrying the extension.

        Returns:
            The decoded connection ID.

        Raises:
            ProtocolError: If ``data`` is malformed.

        """
        return Data_ConnectionId(cid=self._read_whole_vector(data, size=1, what='connection_id.cid'))

    def _read_ext_ech(self, ext_type: 'Enum_ExtensionType', data: 'bytes', *,  # pylint: disable=unused-argument
                      msg_type: 'Enum_HandshakeType') -> 'Data_ECHClientHelloOuter | Data_ECHClientHelloInner | Data_ECHHelloRetryRequest | Data_ECHEncryptedExtensions | bytes':  # pylint: disable=line-too-long
        """Read an ``encrypted_client_hello`` extension.

        Structure of ``encrypted_client_hello`` [:rfc:`9849#section-5`]:

        .. code-block:: text

           enum { outer(0), inner(1) } ECHClientHelloType;

           struct {
              ECHClientHelloType type;
              select (ECHClientHello.type) {
                  case outer:
                      HpkeSymmetricCipherSuite cipher_suite;
                      uint8 config_id;
                      opaque enc<0..2^16-1>;
                      opaque payload<1..2^16-1>;
                  case inner:
                      Empty;
              };
           } ECHClientHello;

           struct {
              ECHConfigList retry_configs;
           } ECHEncryptedExtensions;

           struct {
              opaque confirmation[8];
           } ECHHelloRetryRequest;

        ``ECHConfigList`` is ``ECHConfig ECHConfigList<4..2^16-1>``, each
        ``ECHConfig`` read by :func:`_read_ech_config`.

        Args:
            ext_type: Extension type.
            data: ``extension_data`` octets.
            msg_type: Handshake message carrying the extension.

        Returns:
            The decoded structure for ``msg_type``: an ``ECHClientHello`` of
            either type, an ``ECHHelloRetryRequest`` or an
            ``ECHEncryptedExtensions``; or ``data`` for a message the structure
            does not cover.

        Raises:
            ProtocolError: If ``data`` is malformed, or a ``ClientHello``'s
                names a type other than ``outer`` and ``inner``.

        """
        alias = self.alias
        if msg_type == Enum_HandshakeType.client_hello:
            ch_type = self._read_uint(data, size=1, what='encrypted_client_hello.type')
            if ch_type == _ECH_INNER:
                if len(data) != 1:
                    raise ProtocolError(f'{alias}: invalid format: encrypted_client_hello carries excess octets')
                return Data_ECHClientHelloInner()
            if ch_type != _ECH_OUTER:
                raise ProtocolError(f'{alias}: invalid format: encrypted_client_hello.type {ch_type} '
                                    'is neither outer nor inner')
            # NOTE: the type octet, then a four-octet cipher suite and the one-octet config_id.
            pos = 1
            cipher_suite = _read_hpke_cipher_suite(self, data, pos)
            config_id = self._read_uint(data, pos + 4, size=1, what='encrypted_client_hello.config_id')
            enc, pos = self._read_vector(data, pos + 5, size=2, what='encrypted_client_hello.enc')
            payload, pos = self._read_vector(data, pos, size=2, what='encrypted_client_hello.payload')
            if pos != len(data):
                raise ProtocolError(f'{alias}: invalid format: encrypted_client_hello carries excess octets')
            return Data_ECHClientHelloOuter(cipher_suite=cipher_suite, config_id=config_id, enc=enc, payload=payload)
        if msg_type == Enum_HandshakeType.hello_retry_request:
            if len(data) != _ECH_CONFIRMATION_LENGTH:
                raise ProtocolError(f'{alias}: invalid format: encrypted_client_hello.confirmation '
                                    f'must be exactly {_ECH_CONFIRMATION_LENGTH} octets')
            return Data_ECHHelloRetryRequest(confirmation=data)
        if msg_type == Enum_HandshakeType.encrypted_extensions:
            body = self._read_whole_vector(data, size=2, what='encrypted_client_hello.retry_configs')
            configs = []  # type: list[Data_ECHConfig]
            pos = 0
            while pos < len(body):
                config, pos = _read_ech_config(self, body, pos)
                configs.append(config)
            return Data_ECHEncryptedExtensions(retry_configs=tuple(configs))
        return data

    def _read_ext_renegotiation_info(self, ext_type: 'Enum_ExtensionType', data: 'bytes', *,  # pylint: disable=unused-argument
                                     msg_type: 'Enum_HandshakeType') -> 'Data_RenegotiationInfo | bytes':
        """Read a ``renegotiation_info`` extension.

        Structure of ``RenegotiationInfo`` [:rfc:`5746#section-3.2`]:

        .. code-block:: text

           struct {
               opaque renegotiated_connection<0..255>;
           } RenegotiationInfo;

        Args:
            ext_type: Extension type.
            data: ``extension_data`` octets.
            msg_type: Handshake message carrying the extension.

        Returns:
            The decoded structure in a ``ClientHello`` or ``ServerHello``, where the
            extension is defined; or ``data`` in any other message.

        Raises:
            ProtocolError: If ``data`` is malformed.

        """
        if msg_type not in (Enum_HandshakeType.client_hello, Enum_HandshakeType.server_hello):
            return data
        return Data_RenegotiationInfo(renegotiated_connection=self._read_whole_vector(
            data, size=1, what='renegotiation_info.renegotiated_connection'))

    def _make_ext_unknown(self, ext_type: 'Enum_ExtensionType', data: 'Optional[Data_ExtensionData]' = None, *,  # pylint: disable=unused-argument
                          msg_type: 'Enum_HandshakeType', **kwargs: 'Any') -> 'bytes':  # pylint: disable=unused-argument
        """Make an extension with no constructor registered.

        Args:
            ext_type: Extension type.
            data: Decoded ``extension_data``, which this type has no
                structure to write.
            msg_type: Handshake message carrying the extension.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Empty ``extension_data`` when ``data`` is :data:`None`.

        Raises:
            ProtocolError: If ``data`` is given.

        """
        if data is not None:
            raise ProtocolError(f'{self.alias}: [Extension {ext_type}] no constructor for '
                                f'{type(data).__name__}; pass the raw octets instead')
        return b''

    def _make_ext_server_name(self, ext_type: 'Enum_ExtensionType', data: 'Optional[Data_ServerNameList]' = None, *,  # pylint: disable=unused-argument
                              msg_type: 'Enum_HandshakeType',  # pylint: disable=unused-argument
                              server_name_list: 'Iterable[Data_ServerName]' = (), **kwargs: 'Any') -> 'bytes':
        """Make a ``server_name`` extension.

        Args:
            ext_type: Extension type.
            data: Decoded ``extension_data``.
            msg_type: Handshake message carrying the extension.
            server_name_list: Server names, if ``data`` is not given.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed ``extension_data``.

        """
        names = data.server_name_list if data is not None else server_name_list
        return self._make_vector(b''.join(self._make_pack(int(name.name_type), size=1)
                                          + self._make_vector(name.name, size=2) for name in names), size=2)

    def _make_ext_status_request(self, ext_type: 'Enum_ExtensionType',  # pylint: disable=unused-argument
                                 data: 'Optional[Data_CertificateStatusRequest | Data_Empty]' = None, *,
                                 msg_type: 'Enum_HandshakeType',
                                 status_type: 'Enum_CertificateStatusType | int' = Enum_CertificateStatusType.ocsp,
                                 responder_id_list: 'Iterable[bytes]' = (), request_extensions: 'bytes' = b'',
                                 **kwargs: 'Any') -> 'bytes':
        """Make a ``status_request`` extension.

        ``data`` decides the structure when given, ``msg_type`` otherwise.

        Args:
            ext_type: Extension type.
            data: Decoded ``extension_data``.
            msg_type: Handshake message carrying the extension.
            status_type: Status type for a ``ClientHello``, if ``data`` is not given.
            responder_id_list: ``ResponderID`` values for a ``ClientHello``, if
                ``data`` is not given.
            request_extensions: OCSP request ``Extensions`` for a ``ClientHello``,
                if ``data`` is not given.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed ``extension_data``.

        Raises:
            ProtocolError: If neither ``data`` nor ``msg_type`` names a
                structure, or the status type is not ``ocsp``.

        """
        if data is None:
            if msg_type == Enum_HandshakeType.client_hello:
                code = self._make_index(status_type, Enum_CertificateStatusType, bits=8,
                                        name='status_request.status_type')
                data = Data_CertificateStatusRequest(status_type=code, request=Data_OCSPStatusRequest(
                    responder_id_list=tuple(responder_id_list), request_extensions=request_extensions))
            elif msg_type == Enum_HandshakeType.server_hello:
                data = Data_Empty()
        if isinstance(data, Data_CertificateStatusRequest):
            code = self._make_index(data.status_type, Enum_CertificateStatusType, bits=8,
                                    name='status_request.status_type')
            if code != Enum_CertificateStatusType.ocsp:
                raise ProtocolError(f'{self.alias}: [Extension {ext_type}] no request structure for '
                                    f'status type {int(code)}')
            request = data.request
            return (self._make_pack(int(code), size=1)
                    + self._make_vector(b''.join(self._make_vector(responder_id, size=2)
                                                 for responder_id in request.responder_id_list), size=2)
                    + self._make_vector(request.request_extensions, size=2))
        if isinstance(data, Data_Empty):
            return b''
        raise ProtocolError(f'{self.alias}: [Extension {ext_type}] no status_request structure for {msg_type!r}')

    def _make_ext_supported_groups(self, ext_type: 'Enum_ExtensionType', data: 'Optional[Data_NamedGroupList]' = None, *,  # pylint: disable=unused-argument,line-too-long
                                   msg_type: 'Enum_HandshakeType',  # pylint: disable=unused-argument
                                   named_group_list: 'Iterable[int]' = (), **kwargs: 'Any') -> 'bytes':
        """Make a ``supported_groups`` extension.

        Args:
            ext_type: Extension type.
            data: Decoded ``extension_data``.
            msg_type: Handshake message carrying the extension.
            named_group_list: ``NamedGroup`` values, if ``data`` is not given.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed ``extension_data``.

        """
        groups = data.named_group_list if data is not None else named_group_list
        return self._make_vector(self._make_uints(groups, size=2), size=2)

    def _make_ext_ec_point_formats(self, ext_type: 'Enum_ExtensionType', data: 'Optional[Data_ECPointFormatList]' = None, *,  # pylint: disable=unused-argument,line-too-long
                                   msg_type: 'Enum_HandshakeType',
                                   ec_point_format_list: 'Iterable[Enum_ECPointFormat | int]' = (),
                                   **kwargs: 'Any') -> 'bytes':
        """Make an ``ec_point_formats`` extension.

        Args:
            ext_type: Extension type.
            data: Decoded ``extension_data``.
            msg_type: Handshake message carrying the extension.
            ec_point_format_list: Point formats, members or codes, if ``data`` is
                not given.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed ``extension_data``.

        Raises:
            ProtocolError: If ``data`` is not given for a message other than a
                ``ClientHello`` or ``ServerHello``, or if a point format is not an
                :class:`int` that fits in one octet.

        """
        if data is None and msg_type not in (Enum_HandshakeType.client_hello, Enum_HandshakeType.server_hello):
            raise ProtocolError(f'{self.alias}: [Extension {ext_type}] no ec_point_formats structure '
                                f'for {msg_type!r}')
        formats = data.ec_point_format_list if data is not None else ec_point_format_list
        return self._make_vector(_make_codes(self, formats, Enum_ECPointFormat, size=1,
                                             name='ec_point_formats.ec_point_format'), size=1)

    def _make_ext_signature_algorithms(self, ext_type: 'Enum_ExtensionType', data: 'Optional[Data_SignatureSchemeList]' = None, *,  # pylint: disable=unused-argument,line-too-long
                                       msg_type: 'Enum_HandshakeType',  # pylint: disable=unused-argument
                                       supported_signature_algorithms: 'Iterable[int]' = (),
                                       **kwargs: 'Any') -> 'bytes':
        """Make a ``signature_algorithms`` extension.

        Args:
            ext_type: Extension type.
            data: Decoded ``extension_data``.
            msg_type: Handshake message carrying the extension.
            supported_signature_algorithms: ``SignatureScheme`` values, if
                ``data`` is not given.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed ``extension_data``.

        """
        schemes = data.supported_signature_algorithms if data is not None else supported_signature_algorithms
        return self._make_vector(self._make_uints(schemes, size=2), size=2)

    def _make_ext_alpn(self, ext_type: 'Enum_ExtensionType', data: 'Optional[Data_ProtocolNameList]' = None, *,  # pylint: disable=unused-argument
                       msg_type: 'Enum_HandshakeType',  # pylint: disable=unused-argument
                       protocol_name_list: 'Iterable[bytes]' = (), **kwargs: 'Any') -> 'bytes':
        """Make an ``application_layer_protocol_negotiation`` extension.

        Args:
            ext_type: Extension type.
            data: Decoded ``extension_data``.
            msg_type: Handshake message carrying the extension.
            protocol_name_list: ``ProtocolName`` octet strings, if ``data`` is
                not given.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed ``extension_data``.

        """
        names = data.protocol_name_list if data is not None else protocol_name_list
        return self._make_vector(b''.join(self._make_vector(name, size=1) for name in names), size=2)

    def _make_ext_signed_certificate_timestamp(self, ext_type: 'Enum_ExtensionType',  # pylint: disable=unused-argument
                                               data: 'Optional[Data_SignedCertificateTimestampList | Data_Empty]' = None, *,  # pylint: disable=line-too-long
                                               msg_type: 'Enum_HandshakeType', sct_list: 'Iterable[bytes]' = (),
                                               **kwargs: 'Any') -> 'bytes':
        """Make a ``signed_certificate_timestamp`` extension.

        ``data`` decides the structure when given, ``msg_type`` otherwise.

        Args:
            ext_type: Extension type.
            data: Decoded ``extension_data``.
            msg_type: Handshake message carrying the extension.
            sct_list: ``SerializedSCT`` octet strings for a ``ServerHello``, if
                ``data`` is not given.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed ``extension_data``.

        Raises:
            ProtocolError: If neither ``data`` nor ``msg_type`` names a structure.

        """
        if data is None:
            if msg_type == Enum_HandshakeType.client_hello:
                data = Data_Empty()
            elif msg_type == Enum_HandshakeType.server_hello:
                data = Data_SignedCertificateTimestampList(sct_list=tuple(sct_list))
        if isinstance(data, Data_SignedCertificateTimestampList):
            return self._make_vector(b''.join(self._make_vector(sct, size=2) for sct in data.sct_list), size=2)
        if isinstance(data, Data_Empty):
            return b''
        raise ProtocolError(f'{self.alias}: [Extension {ext_type}] no signed_certificate_timestamp structure '
                            f'for {msg_type!r}')

    def _make_ext_padding(self, ext_type: 'Enum_ExtensionType', data: 'Optional[Data_Padding]' = None, *,  # pylint: disable=unused-argument
                          msg_type: 'Enum_HandshakeType',
                          padding: 'bytes' = b'', **kwargs: 'Any') -> 'bytes':
        """Make a ``padding`` extension.

        Args:
            ext_type: Extension type.
            data: Decoded ``extension_data``.
            msg_type: Handshake message carrying the extension.
            padding: Padding octets, if ``data`` is not given.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed ``extension_data``.

        Raises:
            ProtocolError: If ``data`` is not given for a message other than a
                ``ClientHello``.

        """
        if data is None and msg_type != Enum_HandshakeType.client_hello:
            raise ProtocolError(f'{self.alias}: [Extension {ext_type}] no padding structure '
                                f'for {msg_type!r}')
        return bytes(data.padding if data is not None else padding)

    def _make_ext_extended_main_secret(self, ext_type: 'Enum_ExtensionType', data: 'Optional[Data_Empty]' = None, *,  # pylint: disable=unused-argument
                                       msg_type: 'Enum_HandshakeType', **kwargs: 'Any') -> 'bytes':  # pylint: disable=unused-argument
        """Make an ``extended_main_secret`` extension.

        Args:
            ext_type: Extension type.
            data: Decoded ``extension_data``.
            msg_type: Handshake message carrying the extension.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Empty ``extension_data``.

        Raises:
            ProtocolError: If ``data`` is not given for a message other than a
                ``ClientHello`` or ``ServerHello``, or if ``data`` is a structure other than
                an empty one.

        """
        if data is None and msg_type not in (Enum_HandshakeType.client_hello, Enum_HandshakeType.server_hello):
            raise ProtocolError(f'{self.alias}: [Extension {ext_type}] no extended_main_secret structure '
                                f'for {msg_type!r}')
        return _make_empty(self, ext_type, data)

    def _make_ext_compress_certificate(self, ext_type: 'Enum_ExtensionType',  # pylint: disable=unused-argument
                                       data: 'Optional[Data_CertificateCompressionAlgorithms]' = None, *,
                                       msg_type: 'Enum_HandshakeType',
                                       algorithms: 'Iterable[Enum_CertificateCompressionAlgorithm | int]' = (),
                                       **kwargs: 'Any') -> 'bytes':
        """Make a ``compress_certificate`` extension.

        Args:
            ext_type: Extension type.
            data: Decoded ``extension_data``.
            msg_type: Handshake message carrying the extension.
            algorithms: Compression algorithms, members or codes, if ``data`` is
                not given.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed ``extension_data``.

        Raises:
            ProtocolError: If ``data`` is not given for a message other than a
                ``ClientHello``, or if an algorithm is not an :class:`int` that fits in two
                octets.

        """
        if data is None and msg_type != Enum_HandshakeType.client_hello:
            raise ProtocolError(f'{self.alias}: [Extension {ext_type}] no compress_certificate structure '
                                f'for {msg_type!r}')
        values = data.algorithms if data is not None else algorithms
        return self._make_vector(_make_codes(self, values, Enum_CertificateCompressionAlgorithm, size=2,
                                             name='compress_certificate.algorithm'), size=1)

    def _make_ext_record_size_limit(self, ext_type: 'Enum_ExtensionType', data: 'Optional[Data_RecordSizeLimit]' = None, *,  # pylint: disable=unused-argument,line-too-long
                                    msg_type: 'Enum_HandshakeType',
                                    record_size_limit: 'Optional[int]' = None, **kwargs: 'Any') -> 'bytes':
        """Make a ``record_size_limit`` extension.

        Args:
            ext_type: Extension type.
            data: Decoded ``extension_data``.
            msg_type: Handshake message carrying the extension.
            record_size_limit: Largest record, in octets, if ``data`` is not given.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed ``extension_data``.

        Raises:
            ProtocolError: If ``data`` is not given for a message other than a
                ``ClientHello``, ``ServerHello`` or ``EncryptedExtensions``, or if neither
                ``data`` nor ``record_size_limit`` is given.

        """
        if data is None and msg_type not in (Enum_HandshakeType.client_hello,
                                             Enum_HandshakeType.server_hello,
                                             Enum_HandshakeType.encrypted_extensions):
            raise ProtocolError(f'{self.alias}: [Extension {ext_type}] no record_size_limit structure '
                                f'for {msg_type!r}')
        limit = data.record_size_limit if data is not None else record_size_limit
        if limit is None:
            raise ProtocolError(f'{self.alias}: [Extension {ext_type}] record_size_limit missing')
        return self._make_pack(int(limit), size=2)

    def _make_ext_session_ticket(self, ext_type: 'Enum_ExtensionType', data: 'Optional[Data_SessionTicket]' = None, *,  # pylint: disable=unused-argument,line-too-long
                                 msg_type: 'Enum_HandshakeType',
                                 ticket: 'bytes' = b'', **kwargs: 'Any') -> 'bytes':
        """Make a ``session_ticket`` extension.

        Args:
            ext_type: Extension type.
            data: Decoded ``extension_data``.
            msg_type: Handshake message carrying the extension.
            ticket: The ticket, if ``data`` is not given.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed ``extension_data``.

        Raises:
            ProtocolError: If ``data`` is not given for a message other than a
                ``ClientHello`` or ``ServerHello``.

        """
        if data is None and msg_type not in (Enum_HandshakeType.client_hello, Enum_HandshakeType.server_hello):
            raise ProtocolError(f'{self.alias}: [Extension {ext_type}] no session_ticket structure '
                                f'for {msg_type!r}')
        return bytes(data.ticket if data is not None else ticket)

    def _make_ext_pre_shared_key(self, ext_type: 'Enum_ExtensionType',  # pylint: disable=unused-argument
                                 data: 'Optional[Data_OfferedPsks | Data_PreSharedKeyServerHello]' = None, *,
                                 msg_type: 'Enum_HandshakeType', identities: 'Iterable[Data_PskIdentity]' = (),
                                 binders: 'Iterable[bytes]' = (), selected_identity: 'Optional[int]' = None,
                                 **kwargs: 'Any') -> 'bytes':
        """Make a ``pre_shared_key`` extension.

        ``data`` decides the structure when given, ``msg_type`` otherwise.

        Args:
            ext_type: Extension type.
            data: Decoded ``extension_data``.
            msg_type: Handshake message carrying the extension.
            identities: Identities for a ``ClientHello``, if ``data`` is not given.
            binders: ``PskBinderEntry`` values for a ``ClientHello``, if ``data``
                is not given.
            selected_identity: Index of the identity a ``ServerHello`` selects,
                if ``data`` is not given.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed ``extension_data``.

        Raises:
            ProtocolError: If neither ``data`` nor ``msg_type`` names a
                structure, or ``selected_identity`` is missing.

        """
        if data is None:
            if msg_type == Enum_HandshakeType.client_hello:
                data = Data_OfferedPsks(identities=tuple(identities), binders=tuple(binders))
            elif msg_type == Enum_HandshakeType.server_hello and selected_identity is not None:
                data = Data_PreSharedKeyServerHello(selected_identity=selected_identity)
        if isinstance(data, Data_OfferedPsks):
            return (self._make_vector(b''.join(self._make_vector(entry.identity, size=2)
                                               + self._make_pack(int(entry.obfuscated_ticket_age), size=4)
                                               for entry in data.identities), size=2)
                    + self._make_vector(b''.join(self._make_vector(binder, size=1) for binder in data.binders),
                                        size=2))
        if isinstance(data, Data_PreSharedKeyServerHello):
            return self._make_pack(int(data.selected_identity), size=2)
        raise ProtocolError(f'{self.alias}: [Extension {ext_type}] no pre_shared_key structure for {msg_type!r}')

    def _make_ext_early_data(self, ext_type: 'Enum_ExtensionType', data: 'Optional[Data_Empty]' = None, *,  # pylint: disable=unused-argument
                             msg_type: 'Enum_HandshakeType', **kwargs: 'Any') -> 'bytes':
        """Make an ``early_data`` extension.

        Args:
            ext_type: Extension type.
            data: Decoded ``extension_data``.
            msg_type: Handshake message carrying the extension.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Empty ``extension_data``.

        Raises:
            ProtocolError: If ``data`` is a structure other than an empty one,
                or is not given for a message whose structure is not empty.

        """
        if data is None and msg_type not in (Enum_HandshakeType.client_hello,
                                             Enum_HandshakeType.encrypted_extensions):
            raise ProtocolError(f'{self.alias}: [Extension {ext_type}] no early_data structure for {msg_type!r}')
        return _make_empty(self, ext_type, data)

    def _make_ext_supported_versions(self, ext_type: 'Enum_ExtensionType',  # pylint: disable=unused-argument
                                     data: 'Optional[Data_SupportedVersionsClientHello | Data_SupportedVersionsServerHello]' = None, *,  # pylint: disable=line-too-long
                                     msg_type: 'Enum_HandshakeType', versions: 'Iterable[int]' = (),
                                     selected_version: 'Optional[int]' = None, **kwargs: 'Any') -> 'bytes':
        """Make a ``supported_versions`` extension.

        ``data`` decides the structure when given, ``msg_type`` otherwise.

        Args:
            ext_type: Extension type.
            data: Decoded ``extension_data``.
            msg_type: Handshake message carrying the extension.
            versions: ``ProtocolVersion`` values for a ``ClientHello``, if
                ``data`` is not given.
            selected_version: ``ProtocolVersion`` selected by a
                ``ServerHello`` or ``HelloRetryRequest``, if ``data`` is not
                given.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed ``extension_data``.

        Raises:
            ProtocolError: If neither ``data`` nor ``msg_type`` names a
                structure, or ``selected_version`` is missing.

        """
        if data is None:
            if msg_type == Enum_HandshakeType.client_hello:
                data = Data_SupportedVersionsClientHello(versions=tuple(versions))
            elif selected_version is not None and msg_type in (Enum_HandshakeType.server_hello,
                                                               Enum_HandshakeType.hello_retry_request):
                data = Data_SupportedVersionsServerHello(selected_version=selected_version)
        if isinstance(data, Data_SupportedVersionsClientHello):
            return self._make_vector(self._make_uints(data.versions, size=2), size=1)
        if isinstance(data, Data_SupportedVersionsServerHello):
            return self._make_pack(int(data.selected_version), size=2)
        raise ProtocolError(f'{self.alias}: [Extension {ext_type}] no supported_versions structure '
                            f'for {msg_type!r}')

    def _make_ext_cookie(self, ext_type: 'Enum_ExtensionType', data: 'Optional[Data_Cookie]' = None, *,  # pylint: disable=unused-argument
                         msg_type: 'Enum_HandshakeType',
                         cookie: 'bytes' = b'', **kwargs: 'Any') -> 'bytes':
        """Make a ``cookie`` extension.

        Args:
            ext_type: Extension type.
            data: Decoded ``extension_data``.
            msg_type: Handshake message carrying the extension.
            cookie: The cookie, if ``data`` is not given.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed ``extension_data``.

        Raises:
            ProtocolError: If ``data`` is not given for a message other than a
                ``ClientHello`` or ``HelloRetryRequest``.

        """
        if data is None and msg_type not in (Enum_HandshakeType.client_hello, Enum_HandshakeType.hello_retry_request):
            raise ProtocolError(f'{self.alias}: [Extension {ext_type}] no cookie structure '
                                f'for {msg_type!r}')
        return self._make_vector(data.cookie if data is not None else cookie, size=2)

    def _make_ext_psk_key_exchange_modes(self, ext_type: 'Enum_ExtensionType',  # pylint: disable=unused-argument
                                         data: 'Optional[Data_PskKeyExchangeModes]' = None, *,
                                         msg_type: 'Enum_HandshakeType',
                                         ke_modes: 'Iterable[Enum_PskKeyExchangeMode | int]' = (),
                                         **kwargs: 'Any') -> 'bytes':
        """Make a ``psk_key_exchange_modes`` extension.

        Args:
            ext_type: Extension type.
            data: Decoded ``extension_data``.
            msg_type: Handshake message carrying the extension.
            ke_modes: Key exchange modes, members or codes, if ``data`` is not
                given.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed ``extension_data``.

        Raises:
            ProtocolError: If ``data`` is not given for a message other than a
                ``ClientHello``, or if a mode is not an :class:`int` that fits in one octet.

        """
        if data is None and msg_type != Enum_HandshakeType.client_hello:
            raise ProtocolError(f'{self.alias}: [Extension {ext_type}] no psk_key_exchange_modes structure '
                                f'for {msg_type!r}')
        modes = data.ke_modes if data is not None else ke_modes
        return self._make_vector(_make_codes(self, modes, Enum_PskKeyExchangeMode, size=1,
                                             name='psk_key_exchange_modes.ke_mode'), size=1)

    def _make_ext_post_handshake_auth(self, ext_type: 'Enum_ExtensionType', data: 'Optional[Data_Empty]' = None, *,  # pylint: disable=unused-argument
                                      msg_type: 'Enum_HandshakeType', **kwargs: 'Any') -> 'bytes':  # pylint: disable=unused-argument
        """Make a ``post_handshake_auth`` extension.

        Args:
            ext_type: Extension type.
            data: Decoded ``extension_data``.
            msg_type: Handshake message carrying the extension.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Empty ``extension_data``.

        Raises:
            ProtocolError: If ``data`` is not given for a message other than a
                ``ClientHello``, or if ``data`` is a structure other than an empty one.

        """
        if data is None and msg_type != Enum_HandshakeType.client_hello:
            raise ProtocolError(f'{self.alias}: [Extension {ext_type}] no post_handshake_auth structure '
                                f'for {msg_type!r}')
        return _make_empty(self, ext_type, data)

    def _make_ext_key_share(self, ext_type: 'Enum_ExtensionType',  # pylint: disable=unused-argument
                            data: 'Optional[Data_KeyShareClientHello | Data_KeyShareHelloRetryRequest | Data_KeyShareServerHello]' = None, *,  # pylint: disable=line-too-long
                            msg_type: 'Enum_HandshakeType', client_shares: 'Iterable[Data_KeyShareEntry]' = (),
                            selected_group: 'Optional[int]' = None,
                            server_share: 'Optional[Data_KeyShareEntry]' = None, **kwargs: 'Any') -> 'bytes':
        """Make a ``key_share`` extension.

        ``data`` decides the structure when given, ``msg_type`` otherwise.

        Args:
            ext_type: Extension type.
            data: Decoded ``extension_data``.
            msg_type: Handshake message carrying the extension.
            client_shares: Key shares for a ``ClientHello``, if ``data`` is
                not given.
            selected_group: ``NamedGroup`` for a ``HelloRetryRequest``, if
                ``data`` is not given.
            server_share: Key share for a ``ServerHello``, if ``data`` is
                not given.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed ``extension_data``.

        Raises:
            ProtocolError: If neither ``data`` nor ``msg_type`` names a
                structure, or the argument it needs is missing.

        """
        if data is None:
            if msg_type == Enum_HandshakeType.client_hello:
                data = Data_KeyShareClientHello(client_shares=tuple(client_shares))
            elif msg_type == Enum_HandshakeType.hello_retry_request and selected_group is not None:
                data = Data_KeyShareHelloRetryRequest(selected_group=selected_group)
            elif msg_type == Enum_HandshakeType.server_hello and server_share is not None:
                data = Data_KeyShareServerHello(server_share=server_share)
        if isinstance(data, Data_KeyShareClientHello):
            return self._make_vector(b''.join(_make_key_share_entry(self, entry) for entry in data.client_shares),
                                     size=2)
        if isinstance(data, Data_KeyShareHelloRetryRequest):
            return self._make_pack(int(data.selected_group), size=2)
        if isinstance(data, Data_KeyShareServerHello):
            return _make_key_share_entry(self, data.server_share)
        raise ProtocolError(f'{self.alias}: [Extension {ext_type}] no key_share structure for {msg_type!r}')

    def _make_ext_connection_id(self, ext_type: 'Enum_ExtensionType', data: 'Optional[Data_ConnectionId]' = None, *,  # pylint: disable=unused-argument
                                msg_type: 'Enum_HandshakeType',  # pylint: disable=unused-argument
                                cid: 'bytes' = b'', **kwargs: 'Any') -> 'bytes':
        """Make a ``connection_id`` extension.

        Args:
            ext_type: Extension type.
            data: Decoded ``extension_data``.
            msg_type: Handshake message carrying the extension.
            cid: Connection ID, if ``data`` is not given.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed ``extension_data``.

        """
        return self._make_vector(data.cid if data is not None else cid, size=1)

    def _make_ext_ech(self, ext_type: 'Enum_ExtensionType',  # pylint: disable=unused-argument
                      data: 'Optional[Data_ECHClientHelloOuter | Data_ECHClientHelloInner | Data_ECHHelloRetryRequest | Data_ECHEncryptedExtensions]' = None, *,  # pylint: disable=line-too-long
                      msg_type: 'Enum_HandshakeType', inner: 'bool' = False,
                      cipher_suite: 'Optional[Data_HpkeSymmetricCipherSuite]' = None, config_id: 'int' = 0,
                      enc: 'bytes' = b'', payload: 'bytes' = b'', confirmation: 'Optional[bytes]' = None,
                      retry_configs: 'Iterable[Data_ECHConfig]' = (), **kwargs: 'Any') -> 'bytes':
        """Make an ``encrypted_client_hello`` extension.

        ``data`` decides the structure when given, ``msg_type`` otherwise.

        Args:
            ext_type: Extension type.
            data: Decoded ``extension_data``.
            msg_type: Handshake message carrying the extension.
            inner: Whether a ``ClientHello`` carries the inner variant, if
                ``data`` is not given.
            cipher_suite: Cipher suite of the outer variant, if ``data`` is not
                given.
            config_id: ``config_id`` of the outer variant, if ``data`` is not given.
            enc: Encapsulated key of the outer variant, if ``data`` is not given.
            payload: Encrypted payload of the outer variant, if ``data`` is not
                given.
            confirmation: Confirmation for a ``HelloRetryRequest``, if ``data``
                is not given.
            retry_configs: Retry configurations for ``EncryptedExtensions``, if
                ``data`` is not given.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed ``extension_data``.

        Raises:
            ProtocolError: If neither ``data`` nor ``msg_type`` names a
                structure, the argument it needs is missing, or a confirmation
                is not 8 octets.

        """
        if data is None:
            if msg_type == Enum_HandshakeType.client_hello and inner:
                data = Data_ECHClientHelloInner()
            elif msg_type == Enum_HandshakeType.client_hello and cipher_suite is not None:
                data = Data_ECHClientHelloOuter(cipher_suite=cipher_suite, config_id=config_id, enc=enc,
                                                payload=payload)
            elif msg_type == Enum_HandshakeType.hello_retry_request and confirmation is not None:
                data = Data_ECHHelloRetryRequest(confirmation=confirmation)
            elif msg_type == Enum_HandshakeType.encrypted_extensions:
                data = Data_ECHEncryptedExtensions(retry_configs=tuple(retry_configs))
        if isinstance(data, Data_ECHClientHelloOuter):
            return (self._make_pack(_ECH_OUTER, size=1) + _make_hpke_cipher_suite(self, data.cipher_suite)
                    + self._make_pack(int(data.config_id), size=1) + self._make_vector(data.enc, size=2)
                    + self._make_vector(data.payload, size=2))
        if isinstance(data, Data_ECHClientHelloInner):
            return self._make_pack(_ECH_INNER, size=1)
        if isinstance(data, Data_ECHHelloRetryRequest):
            if len(data.confirmation) != _ECH_CONFIRMATION_LENGTH:
                raise ProtocolError(f'{self.alias}: [Extension {ext_type}] confirmation must be exactly '
                                    f'{_ECH_CONFIRMATION_LENGTH} octets')
            return bytes(data.confirmation)
        if isinstance(data, Data_ECHEncryptedExtensions):
            return self._make_vector(b''.join(_make_ech_config(self, config) for config in data.retry_configs),
                                     size=2)
        raise ProtocolError(f'{self.alias}: [Extension {ext_type}] no encrypted_client_hello structure '
                            f'for {msg_type!r}')

    def _make_ext_renegotiation_info(self, ext_type: 'Enum_ExtensionType', data: 'Optional[Data_RenegotiationInfo]' = None, *,  # pylint: disable=unused-argument,line-too-long
                                     msg_type: 'Enum_HandshakeType',
                                     renegotiated_connection: 'bytes' = b'', **kwargs: 'Any') -> 'bytes':
        """Make a ``renegotiation_info`` extension.

        Args:
            ext_type: Extension type.
            data: Decoded ``extension_data``.
            msg_type: Handshake message carrying the extension.
            renegotiated_connection: ``verify_data`` of the previous handshake,
                if ``data`` is not given.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed ``extension_data``.

        Raises:
            ProtocolError: If ``data`` is not given for a message other than a
                ``ClientHello`` or ``ServerHello``.

        """
        if data is None and msg_type not in (Enum_HandshakeType.client_hello, Enum_HandshakeType.server_hello):
            raise ProtocolError(f'{self.alias}: [Extension {ext_type}] no renegotiation_info structure '
                                f'for {msg_type!r}')
        return self._make_vector(data.renegotiated_connection if data is not None else renegotiated_connection,
                                 size=1)

    def _adopt_dispatched(self, obj: 'Any') -> 'Any':
        """Adopt the parse of a sibling tier this dispatcher delegated to.

        Copies the delegate's :attr:`alias` and :attr:`name`, and any next
        layer it already decoded, so the dispatcher reports the tier that
        actually parsed the record.

        Args:
            obj: The delegate's own, already-parsed instance.

        Returns:
            ``obj``'s parsed data model, which becomes this dispatcher's own
            :attr:`~pcapkit.protocols.protocol.ProtocolBase.info`.

        """
        self._alias = obj.alias  # pylint: disable=attribute-defined-outside-init
        self._name = obj.name  # pylint: disable=attribute-defined-outside-init
        next_ = getattr(obj, '_next', None)
        if next_ is not None and not isinstance(next_, NoPayload):
            self._next = next_  # pylint: disable=attribute-defined-outside-init
            self._protos = ProtoChain(self.__class__, self.alias, basis=next_.protochain)  # pylint: disable=attribute-defined-outside-init
        return obj.info

    def _validate_tls_record(self, schema: 'Any', *, available: 'int', dtls: 'bool') -> 'None':
        """Reject octets that cannot be a genuine TLS/DTLS record.

        Dispatch hands this class every payload on its port, most of them
        mid-stream continuations with no record header. Without this check
        any octets decode as a record: the content-type registry mints a
        member for unknown values, and a ``length`` past the buffer is
        zero-padded by :meth:`FieldBase.unpack
        <pcapkit.corekit.fields.field.FieldBase.unpack>`.

        Args:
            schema: The just-parsed record header.
            available: Octets actually available to this layer -- the record
                header plus its fragment, and anything coalesced after it.
            dtls: Whether this is a DTLS record, for the legacy-version range
                it checks.

        Raises:
            ProtocolError: If ``schema`` cannot be a genuine record, so that
                :func:`~pcapkit.corekit.decorators.beholder` degrades
                dispatch to :class:`~pcapkit.protocols.misc.raw.protocol.Raw` instead
                of accepting a fabricated one.

        Note:
            A record split across TCP segments is rejected too: this layer
            holds only a fragment of it, and reassembly is
            :class:`~pcapkit.foundation.reassembly.tcp.TCP`'s job.

        """
        # NOTE: ``make()`` leaves ``content_type`` a bare :obj:`int`, not the enum member a
        # parse yields, so resolve it through the registry to cover both.
        # NOTE: Checked against ``_WIRE_CONTENT_TYPES``, not by name: ``_missing_`` names
        # even an unassigned or reserved value, which is never a genuine content type.
        content_type = Enum_ContentType.get(int(schema.content_type))
        if content_type not in _WIRE_CONTENT_TYPES:
            raise ProtocolError(
                f'{self.alias}: invalid format: unrecognised content type {int(content_type)}')

        major = schema.version >> 8
        expected_major = _DTLS_VERSION_MAJOR if dtls else _TLS_VERSION_MAJOR
        if major != expected_major:
            raise ProtocolError(
                f'{self.alias}: invalid format: legacy record version {schema.version:#06x} is '
                f'not a {"DTLS" if dtls else "TLS"} one')

        if self.length + schema.length > available:
            raise ProtocolError(
                f'{self.alias}: invalid format: record length {schema.length} runs past '
                'the end of the buffer')

    def _tls_negotiates(self, schema: 'Any', target: 'int', *, dtls: 'bool') -> 'bool':
        """Whether this record's first handshake message negotiates ``target``.

        A best-effort peek ahead of the real parse: any decoding failure here
        is reported as "no", leaving the real parse to raise.

        Args:
            schema: The just-parsed record header.
            target: The negotiated-version value to look for
                (:data:`TLS13_VERSION` or :data:`DTLS13_VERSION`).
            dtls: Whether this is a DTLS record.

        Returns:
            Whether the record's fragment decodes as cleartext handshake
            messages whose first one carries a ``supported_versions``
            extension listing ``target``.

        """
        try:
            content = self._read_tls_content(schema.content_type, schema.fragment,
                                             dtls=dtls, epoch=getattr(schema, 'epoch', 0))
        except ProtocolError:
            return False
        if not isinstance(content, tuple) or not content:
            return False
        body = getattr(content[0], 'body', None)
        return target in _negotiated_versions(body)

    def _tls_content_is_cleartext(self, content_type: 'Enum_ContentType', fragment: 'bytes', *,
                                  dtls: 'bool', epoch: 'int') -> 'bool':
        """Whether a record's fragment is cleartext to decode structurally.

        ``handshake``, ``alert`` and ``change_cipher_spec`` carry ciphertext
        once keys are derived, and the record header does not say so.
        Decoding ciphertext would fabricate content, or fail and lose the
        cleartext header to :class:`~pcapkit.protocols.misc.raw.protocol.Raw`.

        * **DTLS**: epoch 0 is cleartext, any later epoch encrypted
          (:rfc:`9147#section-4.2`).
        * **TLS**: ``handshake`` must tile (:func:`_tls_handshake_tiles`);
          ``alert`` must be exactly 2 octets and ``change_cipher_spec``
          exactly 1, which encryption overhead never yields.

        Any other content type is reported as not cleartext.

        Args:
            content_type: Record content type.
            fragment: Record fragment, undecoded.
            dtls: Whether this is a DTLS record.
            epoch: The DTLS record's epoch; unused when ``dtls`` is false.

        Returns:
            Whether to decode ``fragment`` structurally for its content type.

        """
        if dtls:
            return not epoch  # i.e. epoch 0, the cleartext initial handshake
        if content_type == Enum_ContentType.handshake:
            return _tls_handshake_tiles(fragment)
        if content_type == Enum_ContentType.alert:
            return len(fragment) == 2
        if content_type == Enum_ContentType.change_cipher_spec:
            return len(fragment) == 1
        return False

    def _read_tls_content(self, content_type: 'Enum_ContentType', fragment: 'bytes', *,
                          dtls: 'bool', epoch: 'int' = 0) -> 'Any':
        """Decode a record fragment by its content type.

        Args:
            content_type: Record content type.
            fragment: Record fragment, undecoded.
            dtls: Whether this is a DTLS record, i.e. whether a handshake
                message carries DTLS's fragment header.
            epoch: The DTLS record's epoch, which says whether its fragment is
                encrypted; ignored when ``dtls`` is false, since a TLS record
                header carries no equivalent.

        Returns:
            A :obj:`tuple` of handshake messages for
            :attr:`~pcapkit.const.tls.content_type.ContentType.handshake`, an
            :class:`~pcapkit.protocols.application.ssl.data.Alert` for
            :attr:`~pcapkit.const.tls.content_type.ContentType.alert`, a
            :class:`~pcapkit.protocols.application.ssl.data.ChangeCipherSpec`
            for :attr:`~pcapkit.const.tls.content_type.ContentType.change_cipher_spec`,
            or ``fragment`` unchanged for every other content type --
            application data, heartbeat, ACK, and any content type this
            version does not name.

        Raises:
            ProtocolError: If ``fragment`` is malformed for ``content_type``.

        Notes:
            ``handshake``, ``alert`` and ``change_cipher_spec`` are kept as
            :obj:`bytes` when :meth:`_tls_content_is_cleartext` says they are
            encrypted.

        """
        if content_type == Enum_ContentType.handshake:
            if not self._tls_content_is_cleartext(content_type, fragment, dtls=dtls, epoch=epoch):
                return fragment
            return self._read_tls_handshake_messages(fragment, dtls=dtls)
        if content_type == Enum_ContentType.alert:
            if not self._tls_content_is_cleartext(content_type, fragment, dtls=dtls, epoch=epoch):
                return fragment
            if len(fragment) != 2:
                raise ProtocolError(f'{self.alias}: invalid format: alert record must be exactly two octets')
            level, description = self._read_octets(fragment, size=2, what='alert')
            return Data_Alert(level=level, description=description)
        if content_type == Enum_ContentType.change_cipher_spec:
            if not self._tls_content_is_cleartext(content_type, fragment, dtls=dtls, epoch=epoch):
                return fragment
            if len(fragment) != 1:
                raise ProtocolError(f'{self.alias}: invalid format: change_cipher_spec '
                                    'record must be exactly one octet')
            return Data_ChangeCipherSpec(msg=fragment[0])
        return fragment

    def _read_tls_handshake_messages(self, fragment: 'bytes', *,
                                     dtls: 'bool') -> 'tuple[Any, ...]':
        """Decode a ``handshake`` record fragment into its handshake messages.

        A record may coalesce several handshake messages.

        Args:
            fragment: Record fragment, i.e. one or more concatenated
                handshake messages.
            dtls: Whether each message carries DTLS's fragment header
                (``message_seq``, ``fragment_offset``, ``fragment_length``;
                :rfc:`6347#section-4.2.2`) after the 4-octet
                ``msg_type``/``length`` header shared with TLS.

        Returns:
            The decoded handshake messages, in order.

        Raises:
            ProtocolError: If a message's header or body runs past the end of
                ``fragment``.

        Notes:
            Only an unfragmented ``ClientHello``, ``ServerHello`` or
            ``EncryptedExtensions`` body is decoded; other bodies stay
            undecoded (:issue:`2437`). A fragmented DTLS message is decoded
            once reassembled, by
            :func:`~pcapkit.foundation.analysis.dtls.dtls_handshake` (:issue:`2440`).

        """
        from pcapkit.protocols.application.dtls.data import \
            DTLSHandshake as Data_DTLSHandshake  # pylint: disable=import-outside-toplevel

        messages = []  # type: list[Any]
        pos = 0
        total = len(fragment)
        while pos < total:
            code = self._read_uint(fragment, pos, size=1, what='handshake header')
            length = self._read_uint(fragment, pos + 1, size=3, what='handshake header')
            msg_type = Enum_HandshakeType.get(code)
            pos += 4

            is_fragmented = False
            # NOTE: 0 rather than ``None``: unused when ``dtls`` is false, and
            # :class:`DTLSHandshake` declares these as plain ``int``.
            message_seq = fragment_offset = fragment_length = 0
            if dtls:
                what = 'DTLS fragment header'
                message_seq = self._read_uint(fragment, pos, size=2, what=what)
                fragment_offset = self._read_uint(fragment, pos + 2, size=3, what=what)
                fragment_length = self._read_uint(fragment, pos + 5, size=3, what=what)
                pos += 8
                is_fragmented = bool(fragment_offset) or fragment_length != length
                body_length = fragment_length
            else:
                body_length = length

            body_bytes = self._read_octets(fragment, pos, size=body_length, what='handshake body')
            pos += body_length

            if not is_fragmented and msg_type == Enum_HandshakeType.client_hello:
                body = self._read_tls_client_hello(body_bytes, dtls=dtls)  # type: Any
            elif not is_fragmented and msg_type == Enum_HandshakeType.server_hello:
                body = self._read_tls_server_hello(body_bytes)
            elif not is_fragmented and msg_type == Enum_HandshakeType.encrypted_extensions:
                body = self._read_tls_encrypted_extensions(body_bytes)
            else:
                body = body_bytes

            if dtls:
                messages.append(Data_DTLSHandshake(
                    msg_type=msg_type, length=length, body=body,
                    message_seq=message_seq, fragment_offset=fragment_offset,
                    fragment_length=fragment_length, is_fragmented=is_fragmented,
                ))
            else:
                messages.append(Data_Handshake(msg_type=msg_type, length=length, body=body))
        return tuple(messages)

    def _make_tls_handshake_messages(self, messages: 'tuple[Any, ...]', *,
                                     dtls: 'bool') -> 'bytes':
        """Encode handshake messages back into a record fragment -- the
        inverse of :meth:`_read_tls_handshake_messages`.

        Args:
            messages: Handshake messages, as returned by
                :meth:`_read_tls_handshake_messages`, or already-encoded
                :obj:`bytes` per message. A fragmented DTLS message's body is
                its fragment's octets, or the whole message, of which only the
                fragment's range is written.
            dtls: Whether to write DTLS's fragment header after each
                message's ``msg_type``/``length`` header.

        Returns:
            Encoded record fragment.

        Raises:
            ProtocolError: If a fragmented DTLS message's body does not yield
                exactly ``fragment_length`` octets, which a fragment carries
                (:rfc:`6347#section-4.2.3`).

        """
        out = bytearray()
        for message in messages:
            if isinstance(message, bytes):
                out += message
                continue

            body = message.body
            if isinstance(body, Data_ClientHello):
                body_bytes = self._make_tls_client_hello(body, dtls=dtls)
            elif isinstance(body, Data_ServerHello):
                body_bytes = self._make_tls_server_hello(body)
            elif isinstance(body, Data_EncryptedExtensions):
                body_bytes = self._make_tls_encrypted_extensions(body)
            else:
                body_bytes = bytes(body)

            # NOTE: the message's ``length`` is trusted only for a fragmented DTLS message;
            # otherwise it is recomputed from ``body_bytes``, so a rebuild stays exact.
            is_fragmented = dtls and message.is_fragmented
            length = message.length if is_fragmented else len(body_bytes)

            if is_fragmented:
                fragment_length = message.fragment_length
                # NOTE: a fragment's body is exactly ``fragment_length`` octets (RFC 6347,
                # section 4.2.3); a whole-message body is cut down to this fragment's range.
                if len(body_bytes) != fragment_length and len(body_bytes) == length:
                    start = message.fragment_offset
                    body_bytes = body_bytes[start:start + fragment_length]
                if len(body_bytes) != fragment_length:
                    raise ProtocolError(f'{self.alias}: invalid format: handshake fragment body '
                                        f'of {len(body_bytes)} octets, fragment_length '
                                        f'{fragment_length}')
            else:
                fragment_length = len(body_bytes)

            out += self._make_pack(int(message.msg_type), size=1) + self._make_pack(length, size=3)
            if dtls:
                out += (self._make_pack(message.message_seq, size=2)
                        + self._make_pack(message.fragment_offset, size=3)
                        + self._make_pack(fragment_length, size=3))
            out += body_bytes
        return bytes(out)

    def _read_tls_client_hello(self, body: 'bytes', *, dtls: 'bool') -> 'Data_ClientHello':
        """Decode a ``ClientHello`` handshake message body.

        Structure of TLS's ``ClientHello`` [:rfc:`9846#section-4.2.2`]:

        .. code-block:: text

           uint16 ProtocolVersion;
           opaque Random[32];

           uint8 CipherSuite[2];    /* Cryptographic suite selector */

           struct {
               ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
               Random random;
               opaque legacy_session_id<0..32>;
               CipherSuite cipher_suites<2..2^16-2>;
               opaque legacy_compression_methods<1..2^8-1>;
               Extension extensions<7..2^16-1>;
           } ClientHello;

        DTLS inserts a ``cookie`` after ``legacy_session_id``
        [:rfc:`6347#section-4.2.1`, :rfc:`9147#section-5.3`]:

        .. code-block:: text

           struct {
               ProtocolVersion legacy_version = { 254,253 }; // DTLSv1.2
               Random random;
               opaque legacy_session_id<0..32>;
               opaque legacy_cookie<0..2^8-1>;                  // DTLS
               CipherSuite cipher_suites<2..2^16-2>;
               opaque legacy_compression_methods<1..2^8-1>;
               Extension extensions<8..2^16-1>;
           } ClientHello;

        Args:
            body: Message body.
            dtls: Whether this is a DTLS ``ClientHello``, i.e. whether
                ``cookie`` is present.

        Returns:
            Decoded ``ClientHello``.

        Raises:
            ProtocolError: If ``body`` is malformed.

        """
        alias = self.alias
        version = self._read_uint(body, size=2, what='client_hello.version')
        random = self._read_octets(body, 2, size=32, what='client_hello.random')
        session_id, pos = self._read_vector(body, 34, size=1, what='client_hello.session_id')

        cookie = None  # type: Optional[bytes]
        if dtls:
            cookie, pos = self._read_vector(body, pos, size=1, what='client_hello.cookie')

        what = 'client_hello.cipher_suites'
        cipher_suites_len = self._read_uint(body, pos, size=2, what=f'{what} length')
        pos += 2
        # NOTE: a ``CipherSuite`` is 2 octets (:rfc:`9846#section-4.2.2`), so an odd length is
        # refused before the short read is checked, rather than decoded and re-padded on rebuild.
        if cipher_suites_len % 2:
            raise ProtocolError(f'{alias}: invalid format: {what} length {cipher_suites_len} is not a multiple of 2')
        cipher_suites = self._read_uints(self._read_octets(body, pos, size=cipher_suites_len, what=what),
                                         size=2, what=what)
        pos += cipher_suites_len

        compression_methods_raw, pos = self._read_vector(body, pos, size=1, what='client_hello.compression_methods')
        compression_methods = tuple(compression_methods_raw)

        extensions = None  # type: Optional[tuple[Data_Extension, ...]]
        if pos < len(body):
            extensions_raw, pos = self._read_vector(body, pos, size=2, what='client_hello.extensions')
            extensions = self._read_tls_extensions(
                extensions_raw, msg_type=cast('Enum_HandshakeType', Enum_HandshakeType.client_hello))

        if pos != len(body):
            raise ProtocolError(f'{alias}: invalid format: client_hello carries excess octets')

        return Data_ClientHello(
            version=version, random=random, session_id=session_id, cookie=cookie,
            cipher_suites=cipher_suites, compression_methods=compression_methods,
            extensions=extensions,
        )

    def _read_tls_server_hello(self, body: 'bytes') -> 'Data_ServerHello':
        """Decode a ``ServerHello`` handshake message body, or a
        ``HelloRetryRequest``'s, whose ``random`` is :data:`_HRR_RANDOM`.

        Structure of ``ServerHello`` [:rfc:`9846#section-4.2.3`]:

        .. code-block:: text

           struct {
               ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
               Random random;
               opaque legacy_session_id_echo<0..32>;
               CipherSuite cipher_suite;
               uint8 legacy_compression_method = 0;
               Extension extensions<6..2^16-1>;
           } ServerHello;

        Args:
            body: Message body.

        Returns:
            Decoded ``ServerHello``.

        Raises:
            ProtocolError: If ``body`` is malformed.

        """
        version = self._read_uint(body, size=2, what='server_hello.version')
        random = self._read_octets(body, 2, size=32, what='server_hello.random')
        session_id, pos = self._read_vector(body, 34, size=1, what='server_hello.session_id')

        cipher_suite = self._read_uint(body, pos, size=2, what='server_hello.cipher_suite')
        compression_method = self._read_uint(body, pos + 2, size=1, what='server_hello.compression_method')
        pos += 3

        extensions = None  # type: Optional[tuple[Data_Extension, ...]]
        if pos < len(body):
            extensions_raw, pos = self._read_vector(body, pos, size=2, what='server_hello.extensions')
            extensions = self._read_tls_extensions(extensions_raw, msg_type=_hello_type(random))

        if pos != len(body):
            raise ProtocolError(f'{self.alias}: invalid format: server_hello carries excess octets')

        return Data_ServerHello(
            version=version, random=random, session_id=session_id, cipher_suite=cipher_suite,
            compression_method=compression_method, extensions=extensions,
        )

    def _read_tls_encrypted_extensions(self, body: 'bytes') -> 'Data_EncryptedExtensions':
        """Decode an ``EncryptedExtensions`` handshake message body.

        Structure of ``EncryptedExtensions`` [:rfc:`9846#section-4.4.1`]:

        .. code-block:: text

           struct {
               Extension extensions<0..2^16-1>;
           } EncryptedExtensions;

        Args:
            body: Message body.

        Returns:
            Decoded ``EncryptedExtensions``.

        Raises:
            ProtocolError: If ``body`` is malformed.

        """
        extensions_raw = self._read_whole_vector(body, size=2, what='encrypted_extensions.extensions')
        msg_type = cast('Enum_HandshakeType', Enum_HandshakeType.encrypted_extensions)
        return Data_EncryptedExtensions(extensions=self._read_tls_extensions(extensions_raw, msg_type=msg_type))

    def _read_tls_extensions(self, data: 'bytes', *, msg_type: 'Enum_HandshakeType') -> 'tuple[Data_Extension, ...]':
        """Decode an extension list.

        Structure of one extension [:rfc:`9846#section-4.3`]:

        .. code-block:: text

           struct {
               ExtensionType extension_type;
               opaque extension_data<0..2^16-1>;
           } Extension;

        Each ``extension_data`` is read by the parser :attr:`__extension__`
        registers for its type. The framing delimits it, so one its parser
        rejects with a :exc:`~pcapkit.utilities.exceptions.ProtocolError` is
        kept as its raw octets rather than failing the message. The parser runs
        in a :class:`~pcapkit.utilities.exceptions.CaughtByCaller` block, so
        that error is quiet: nothing is logged and no exception hook installed.

        Args:
            data: The extension list, i.e. one or more concatenated
                extensions, with no further length prefix of its own.
            msg_type: Handshake message carrying the list, which the structure
                of some extensions depends on; ``hello_retry_request`` for a
                ``ServerHello`` that is a ``HelloRetryRequest``.

        Returns:
            The decoded extensions, in order.

        Raises:
            ProtocolError: If an extension's header or body runs past the
                end of ``data``.

        """
        extensions = []  # type: list[Data_Extension]
        pos = 0
        total = len(data)
        while pos < total:
            code = self._read_uint(data, pos, size=2, what='extension header')
            ext_len = self._read_uint(data, pos + 2, size=2, what='extension header')
            ext_type = Enum_ExtensionType.get(code)
            pos += 4
            ext_data = self._read_octets(data, pos, size=ext_len, what='extension data')
            pos += ext_len

            name = self._lookup_registry(self.__extension__, ext_type)
            if isinstance(name, str):
                meth = cast('ExtensionParser', getattr(self, f'_read_ext_{name}', self._read_ext_unknown))
            else:
                meth = name[0]
            try:
                # NOTE: a rejected body is kept raw below, so its ProtocolError is
                # quiet, whoever raised it, as EnumLookup.get's misses are (#1845).
                with CaughtByCaller(ProtocolError):
                    ext_body = meth(ext_type, ext_data, msg_type=msg_type)  # type: Data_ExtensionData | bytes
            except ProtocolError:
                ext_body = ext_data
            extensions.append(Data_Extension(type=ext_type, data=ext_body))
        return tuple(extensions)

    def _make_tls_content(self, content_type: 'Enum_ContentType', content: 'Any', *,
                          dtls: 'bool') -> 'bytes':
        """Encode a record fragment by its content type -- the inverse of
        :meth:`_read_tls_content`.

        Args:
            content_type: Record content type.
            content: Decoded record content, or already-encoded :obj:`bytes`.
            dtls: Whether this is a DTLS record.

        Returns:
            Encoded record fragment.

        """
        if isinstance(content, bytes):
            return content
        if content_type == Enum_ContentType.handshake:
            return self._make_tls_handshake_messages(content, dtls=dtls)
        if content_type == Enum_ContentType.alert:
            return self._make_uints((content.level, content.description), size=1)
        if content_type == Enum_ContentType.change_cipher_spec:
            return self._make_pack(int(content.msg), size=1)
        return bytes(content)

    def _make_tls_client_hello(self, data: 'Data_ClientHello', *, dtls: 'bool') -> 'bytes':
        """Encode a ``ClientHello`` handshake message body -- the inverse of
        :meth:`_read_tls_client_hello`.

        Args:
            data: Decoded ``ClientHello``.
            dtls: Whether this is a DTLS ``ClientHello``, i.e. whether to
                write the ``cookie`` field.

        Returns:
            Encoded message body.

        """
        out = bytearray()
        out += self._make_pack(int(data.version), size=2)
        out += data.random
        out += self._make_vector(data.session_id, size=1)

        if dtls:
            out += self._make_vector(data.cookie if data.cookie is not None else b'', size=1)

        out += self._make_vector(self._make_uints(data.cipher_suites, size=2), size=2)
        out += self._make_vector(self._make_uints(data.compression_methods, size=1), size=1)

        if data.extensions is not None:
            extensions_raw = self._make_tls_extensions(
                data.extensions, msg_type=cast('Enum_HandshakeType', Enum_HandshakeType.client_hello))
            out += self._make_vector(extensions_raw, size=2)
        return bytes(out)

    def _make_tls_server_hello(self, data: 'Data_ServerHello') -> 'bytes':
        """Encode a ``ServerHello`` handshake message body -- the inverse of
        :meth:`_read_tls_server_hello`.

        Args:
            data: Decoded ``ServerHello``.

        Returns:
            Encoded message body.

        """
        out = bytearray()
        out += self._make_pack(int(data.version), size=2)
        out += data.random
        out += self._make_vector(data.session_id, size=1)
        out += self._make_pack(int(data.cipher_suite), size=2)
        out += self._make_pack(int(data.compression_method), size=1)

        if data.extensions is not None:
            extensions_raw = self._make_tls_extensions(data.extensions, msg_type=_hello_type(data.random))
            out += self._make_vector(extensions_raw, size=2)
        return bytes(out)

    def _make_tls_encrypted_extensions(self, data: 'Data_EncryptedExtensions') -> 'bytes':
        """Encode an ``EncryptedExtensions`` handshake message body -- the
        inverse of :meth:`_read_tls_encrypted_extensions`.

        Args:
            data: Decoded ``EncryptedExtensions``.

        Returns:
            Encoded message body.

        """
        msg_type = cast('Enum_HandshakeType', Enum_HandshakeType.encrypted_extensions)
        return self._make_vector(self._make_tls_extensions(data.extensions, msg_type=msg_type), size=2)

    def _make_tls_extensions(self, extensions: 'Iterable[Data_Extension | tuple[Enum_ExtensionType | int, dict[str, Any]]]',  # pylint: disable=line-too-long
                             *, msg_type: 'Enum_HandshakeType') -> 'bytes':
        """Encode an extension list -- the inverse of :meth:`_read_tls_extensions`.

        Raw ``extension_data`` octets are written as they are; anything else
        goes to the constructor :attr:`__extension__` registers for the type.

        Args:
            extensions: Decoded extensions, or ``(type, kwargs)`` pairs for the
                registered constructor to build from.
            msg_type: Handshake message carrying the list, as for
                :meth:`_read_tls_extensions`.

        Returns:
            Encoded extension list, with no further length prefix of its own.

        Raises:
            ProtocolError: If the type of a ``(type, kwargs)`` pair is a name,
                a :obj:`bool`, or a member or code the 16-bit extension type
                field cannot carry.

        """
        out = bytearray()
        for extension in extensions:
            if isinstance(extension, tuple):
                code, kwargs = extension
                ext_type = self._make_index(code, Enum_ExtensionType, bits=16, name='extension type')
                data = None  # type: Optional[Data_ExtensionData | bytes]
            else:
                ext_type, data, kwargs = extension.type, extension.data, {}

            if isinstance(data, bytes):
                ext_data = data
            else:
                name = self._lookup_registry(self.__extension__, ext_type)
                if isinstance(name, str):
                    meth = cast('ExtensionConstructor', getattr(self, f'_make_ext_{name}', self._make_ext_unknown))
                else:
                    meth = name[1]
                ext_data = meth(ext_type, data, msg_type=msg_type, **kwargs)

            out += self._make_pack(int(ext_type), size=2) + self._make_vector(ext_data, size=2)
        return bytes(out)
