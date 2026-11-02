# -*- coding: utf-8 -*-
"""SSL - Secure Sockets Layer
===============================

.. module:: pcapkit.protocols.application.ssl

:mod:`pcapkit.protocols.application.ssl` contains
:class:`~pcapkit.protocols.application.ssl.SSL` only,
which is the umbrella base class for the Secure Sockets Layer protocol
family [*]_ -- the SSL versions, Transport Layer Security
(:class:`~pcapkit.protocols.application.tls.TLS`, which also covers SSLv3
through :class:`~pcapkit.protocols.application.sslv3.SSLv3`) and Datagram TLS
(:class:`~pcapkit.protocols.application.dtls.DTLS`).

The TLS record header (:rfc:`9846#section-5.1`) is a
:class:`~pcapkit.const.tls.content_type.ContentType`, a legacy record version
and a length. The DTLS ``DTLSPlaintext`` header (:rfc:`9147#section-4`) has
the same fields plus an epoch and a 48-bit sequence number *between* the
version and the length, and DTLS adds a fragment header to each handshake
message. Each record header is declared in its subclass's own schema
(:class:`~pcapkit.protocols.schema.application.tls.TLS` and
:class:`~pcapkit.protocols.schema.application.dtls.DTLS`), and
:class:`~pcapkit.protocols.application.dtls.DTLS` reads the epoch and sequence
number. This base class carries the logic the two share -- content-type
dispatch, handshake-message decoding and the extension registry -- parameterised
by a ``dtls`` flag where the DTLS handshake fragment header has to be read or
written.

.. [*] https://en.wikipedia.org/wiki/Transport_Layer_Security

.. versionadded:: 1.6.0

"""
import collections
from typing import TYPE_CHECKING, Generic, cast

from pcapkit.const.tls.content_type import ContentType as Enum_ContentType
from pcapkit.const.tls.extension_type import ExtensionType as Enum_ExtensionType
from pcapkit.const.tls.handshake_type import HandshakeType as Enum_HandshakeType
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.application.application import Application
from pcapkit.protocols.data.application.tls import Alert as Data_Alert
from pcapkit.protocols.data.application.tls import ChangeCipherSpec as Data_ChangeCipherSpec
from pcapkit.protocols.data.application.tls import ClientHello as Data_ClientHello
from pcapkit.protocols.data.application.tls import ConnectionId as Data_ConnectionId
from pcapkit.protocols.data.application.tls import EncryptedExtensions as Data_EncryptedExtensions
from pcapkit.protocols.data.application.tls import Extension as Data_Extension
from pcapkit.protocols.data.application.tls import Handshake as Data_Handshake
from pcapkit.protocols.data.application.tls import KeyShareClientHello as Data_KeyShareClientHello
from pcapkit.protocols.data.application.tls import KeyShareEntry as Data_KeyShareEntry
from pcapkit.protocols.data.application.tls import \
    KeyShareHelloRetryRequest as Data_KeyShareHelloRetryRequest
from pcapkit.protocols.data.application.tls import KeyShareServerHello as Data_KeyShareServerHello
from pcapkit.protocols.data.application.tls import NamedGroupList as Data_NamedGroupList
from pcapkit.protocols.data.application.tls import ProtocolNameList as Data_ProtocolNameList
from pcapkit.protocols.data.application.tls import ServerHello as Data_ServerHello
from pcapkit.protocols.data.application.tls import ServerName as Data_ServerName
from pcapkit.protocols.data.application.tls import ServerNameList as Data_ServerNameList
from pcapkit.protocols.data.application.tls import SignatureSchemeList as Data_SignatureSchemeList
from pcapkit.protocols.data.application.tls import \
    SupportedVersionsClientHello as Data_SupportedVersionsClientHello
from pcapkit.protocols.data.application.tls import \
    SupportedVersionsServerHello as Data_SupportedVersionsServerHello
from pcapkit.protocols.misc.null import NoPayload
from pcapkit.protocols.protocol import _PT, _ST
from pcapkit.utilities.exceptions import CaughtByCaller, ProtocolError
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from typing import Any, Callable, DefaultDict, Iterable, Optional, Union

    from mypy_extensions import DefaultArg, KwArg, NamedArg
    from typing_extensions import Literal

    from pcapkit.protocols.data.application.tls import ExtensionData as Data_ExtensionData

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

#: The ``random`` that makes a ``ServerHello`` a ``HelloRetryRequest``: the
#: SHA-256 of ``"HelloRetryRequest"`` (:rfc:`9846#section-4.2.3`).
_HRR_RANDOM = bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c')

#: The ``host_name`` ``NameType`` of ``server_name``, the only one defined
#: (:rfc:`6066#section-3`).
_HOST_NAME = 0


def _negotiated_versions(message: 'Any') -> 'tuple[int, ...]':
    """The versions a ``supported_versions`` extension on ``message`` lists.

    Args:
        message: A decoded handshake message's body -- typically
            :class:`~pcapkit.protocols.data.application.tls.ClientHello` or
            :class:`~pcapkit.protocols.data.application.tls.ServerHello`.
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


def _take(data: 'bytes', pos: 'int', size: 'int', *, what: 'str', alias: 'str') -> 'bytes':
    """Slice ``size`` octets out of ``data`` at ``pos``, refusing a short read.

    Plain slicing silently returns fewer octets, which would let a truncated
    message parse short rather than fail.

    Args:
        data: Buffer being read.
        pos: Offset to start at.
        size: Number of octets to take.
        what: Name of the field being read, for the error message.
        alias: Protocol alias, for the error message.

    Returns:
        The requested slice.

    Raises:
        ProtocolError: If fewer than ``size`` octets remain from ``pos``.

    """
    chunk = data[pos:pos + size]
    if len(chunk) != size:
        raise ProtocolError(f'{alias}: invalid format: {what} runs past the end of the buffer')
    return chunk


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
    group = int.from_bytes(_take(data, pos, 2, what='key_share.group', alias=proto.alias), 'big')
    key_exchange, end = proto._read_vector(data, pos + 2, size=2,  # pylint: disable=protected-access
                                           what='key_share.key_exchange')
    return Data_KeyShareEntry(group=group, key_exchange=key_exchange), end


def _make_key_share_entry(proto: 'SSL', entry: 'Data_KeyShareEntry') -> 'bytes':
    """Write one ``KeyShareEntry`` -- the inverse of :func:`_read_key_share_entry`."""
    key_exchange = proto._make_vector(entry.key_exchange, size=2)  # pylint: disable=protected-access
    return int(entry.group).to_bytes(2, 'big') + key_exchange


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

    - SSL 2.0 (:class:`~pcapkit.protocols.application.sslv2.SSLv2`) [draft-hickman-netscape-ssl-00]
    - Transport Layer Security, SSLv3 through TLS 1.3
      (:class:`~pcapkit.protocols.application.tls.TLS`) [:rfc:`6101`, :rfc:`5246`, :rfc:`9846`]
    - Datagram TLS, DTLS 1.0 through DTLS 1.3
      (:class:`~pcapkit.protocols.application.dtls.DTLS`) [:rfc:`4347`, :rfc:`6347`, :rfc:`9147`]

    The ``extension_data`` of these extensions decodes, in ``ClientHello``,
    ``ServerHello``, ``HelloRetryRequest`` and ``EncryptedExtensions``:

    .. list-table::
       :header-rows: 1

       * - Extension Type
         - Extension Parser
         - Extension Constructor
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.server_name`
         - :meth:`~pcapkit.protocols.application.ssl.SSL._read_ext_server_name`
         - :meth:`~pcapkit.protocols.application.ssl.SSL._make_ext_server_name`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.supported_groups`
         - :meth:`~pcapkit.protocols.application.ssl.SSL._read_ext_supported_groups`
         - :meth:`~pcapkit.protocols.application.ssl.SSL._make_ext_supported_groups`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.signature_algorithms`
         - :meth:`~pcapkit.protocols.application.ssl.SSL._read_ext_signature_algorithms`
         - :meth:`~pcapkit.protocols.application.ssl.SSL._make_ext_signature_algorithms`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.application_layer_protocol_negotiation`
         - :meth:`~pcapkit.protocols.application.ssl.SSL._read_ext_alpn`
         - :meth:`~pcapkit.protocols.application.ssl.SSL._make_ext_alpn`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.supported_versions`
         - :meth:`~pcapkit.protocols.application.ssl.SSL._read_ext_supported_versions`
         - :meth:`~pcapkit.protocols.application.ssl.SSL._make_ext_supported_versions`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.key_share`
         - :meth:`~pcapkit.protocols.application.ssl.SSL._read_ext_key_share`
         - :meth:`~pcapkit.protocols.application.ssl.SSL._make_ext_key_share`
       * - :attr:`~pcapkit.const.tls.extension_type.ExtensionType.connection_id`
         - :meth:`~pcapkit.protocols.application.ssl.SSL._read_ext_connection_id`
         - :meth:`~pcapkit.protocols.application.ssl.SSL._make_ext_connection_id`

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
            Enum_ExtensionType.supported_groups: 'supported_groups',               # [RFC 9846]
            Enum_ExtensionType.signature_algorithms: 'signature_algorithms',       # [RFC 9846]
            Enum_ExtensionType.application_layer_protocol_negotiation: 'alpn',     # [RFC 7301]
            Enum_ExtensionType.supported_versions: 'supported_versions',           # [RFC 9846]
            Enum_ExtensionType.key_share: 'key_share',                             # [RFC 9846]
            Enum_ExtensionType.connection_id: 'connection_id',                     # [RFC 9146]
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
            :class:`~pcapkit.protocols.application.tls.TLS`.

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
            name_type = _take(body, pos, 1, what='server_name.name_type', alias=alias)[0]
            if name_type != _HOST_NAME:
                raise ProtocolError(f'{alias}: invalid format: server_name.name_type {name_type} '
                                    'is not host_name')
            name, pos = self._read_vector(body, pos + 1, size=2, what='server_name.name')
            names.append(Data_ServerName(name_type=name_type, name=name))
        return Data_ServerNameList(server_name_list=tuple(names))

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
            return Data_SupportedVersionsServerHello(selected_version=int.from_bytes(data, 'big'))
        return data

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
            return Data_KeyShareHelloRetryRequest(selected_group=int.from_bytes(data, 'big'))
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
        return self._make_vector(b''.join(bytes([int(name.name_type)]) + self._make_vector(name.name, size=2)
                                          for name in names), size=2)

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
            return int(data.selected_version).to_bytes(2, 'big')
        raise ProtocolError(f'{self.alias}: [Extension {ext_type}] no supported_versions structure '
                            f'for {msg_type!r}')

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
            return int(data.selected_group).to_bytes(2, 'big')
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
                dispatch to :class:`~pcapkit.protocols.misc.raw.Raw` instead
                of accepting a fabricated one.

        Note:
            A record split across TCP segments is rejected too: this layer
            holds only a fragment of it, and reassembly is
            :class:`~pcapkit.foundation.reassembly.tcp.TCP`'s job.

        """
        # NOTE: ``make()`` leaves ``content_type`` a bare :obj:`int`, not the enum member a
        # parse yields, so resolve it through the registry to cover both.
        # NOTE: checked against ``_WIRE_CONTENT_TYPES``, not by name: an
        # unassigned or reserved value still resolves to a named member via
        # ``_missing_``, yet is never a record's genuine content type.
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
        cleartext header to :class:`~pcapkit.protocols.misc.raw.Raw`.

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
            :class:`~pcapkit.protocols.data.application.tls.Alert` for
            :attr:`~pcapkit.const.tls.content_type.ContentType.alert`, a
            :class:`~pcapkit.protocols.data.application.tls.ChangeCipherSpec`
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
            level, description = _take(fragment, 0, 2, what='alert', alias=self.alias)
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
        from pcapkit.protocols.data.application.dtls import \
            DTLSHandshake as Data_DTLSHandshake  # pylint: disable=import-outside-toplevel

        messages = []  # type: list[Any]
        pos = 0
        total = len(fragment)
        while pos < total:
            header = _take(fragment, pos, 4, what='handshake header', alias=self.alias)
            msg_type = Enum_HandshakeType.get(header[0])
            length = int.from_bytes(header[1:4], 'big')
            pos += 4

            is_fragmented = False
            # NOTE: 0 rather than ``None``: unused when ``dtls`` is false, and
            # :class:`DTLSHandshake` declares these as plain ``int``.
            message_seq = fragment_offset = fragment_length = 0
            if dtls:
                frag_header = _take(fragment, pos, 8, what='DTLS fragment header', alias=self.alias)
                pos += 8
                message_seq = int.from_bytes(frag_header[0:2], 'big')
                fragment_offset = int.from_bytes(frag_header[2:5], 'big')
                fragment_length = int.from_bytes(frag_header[5:8], 'big')
                is_fragmented = bool(fragment_offset) or fragment_length != length
                body_length = fragment_length
            else:
                body_length = length

            body_bytes = _take(fragment, pos, body_length, what='handshake body', alias=self.alias)
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

            out += bytes([int(message.msg_type)]) + length.to_bytes(3, 'big')
            if dtls:
                out += (message.message_seq.to_bytes(2, 'big')
                       + message.fragment_offset.to_bytes(3, 'big')
                       + fragment_length.to_bytes(3, 'big'))
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
        version = int.from_bytes(_take(body, 0, 2, what='client_hello.version', alias=alias), 'big')
        random = _take(body, 2, 32, what='client_hello.random', alias=alias)
        pos = 34

        session_id_len = _take(body, pos, 1, what='client_hello.session_id length', alias=alias)[0]
        pos += 1
        session_id = _take(body, pos, session_id_len, what='client_hello.session_id', alias=alias)
        pos += session_id_len

        cookie = None  # type: Optional[bytes]
        if dtls:
            cookie_len = _take(body, pos, 1, what='client_hello.cookie length', alias=alias)[0]
            pos += 1
            cookie = _take(body, pos, cookie_len, what='client_hello.cookie', alias=alias)
            pos += cookie_len

        cipher_suites_len = int.from_bytes(
            _take(body, pos, 2, what='client_hello.cipher_suites length', alias=alias), 'big')
        pos += 2
        # NOTE: a ``CipherSuite`` is 2 octets (:rfc:`9846#section-4.2.2`): an odd length
        # would decode a lone octet and re-pad it on rebuild, so it is refused.
        if cipher_suites_len % 2:
            raise ProtocolError(
                f'{alias}: invalid format: client_hello.cipher_suites length '
                f'{cipher_suites_len} is not a multiple of 2')
        cipher_suites_raw = _take(body, pos, cipher_suites_len, what='client_hello.cipher_suites', alias=alias)
        pos += cipher_suites_len
        cipher_suites = tuple(
            int.from_bytes(cipher_suites_raw[i:i + 2], 'big') for i in range(0, cipher_suites_len, 2)
        )

        compression_len = _take(body, pos, 1, what='client_hello.compression_methods length', alias=alias)[0]
        pos += 1
        compression_methods = tuple(
            _take(body, pos, compression_len, what='client_hello.compression_methods', alias=alias))
        pos += compression_len

        extensions = None  # type: Optional[tuple[Data_Extension, ...]]
        if pos < len(body):
            ext_total_len = int.from_bytes(
                _take(body, pos, 2, what='client_hello.extensions length', alias=alias), 'big')
            pos += 2
            extensions_raw = _take(body, pos, ext_total_len, what='client_hello.extensions', alias=alias)
            pos += ext_total_len
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
        alias = self.alias
        version = int.from_bytes(_take(body, 0, 2, what='server_hello.version', alias=alias), 'big')
        random = _take(body, 2, 32, what='server_hello.random', alias=alias)
        pos = 34

        session_id_len = _take(body, pos, 1, what='server_hello.session_id length', alias=alias)[0]
        pos += 1
        session_id = _take(body, pos, session_id_len, what='server_hello.session_id', alias=alias)
        pos += session_id_len

        cipher_suite = int.from_bytes(_take(body, pos, 2, what='server_hello.cipher_suite', alias=alias), 'big')
        pos += 2
        compression_method = _take(body, pos, 1, what='server_hello.compression_method', alias=alias)[0]
        pos += 1

        extensions = None  # type: Optional[tuple[Data_Extension, ...]]
        if pos < len(body):
            ext_total_len = int.from_bytes(
                _take(body, pos, 2, what='server_hello.extensions length', alias=alias), 'big')
            pos += 2
            extensions_raw = _take(body, pos, ext_total_len, what='server_hello.extensions', alias=alias)
            pos += ext_total_len
            extensions = self._read_tls_extensions(extensions_raw, msg_type=_hello_type(random))

        if pos != len(body):
            raise ProtocolError(f'{alias}: invalid format: server_hello carries excess octets')

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
            header = _take(data, pos, 4, what='extension header', alias=self.alias)
            ext_type = Enum_ExtensionType.get(int.from_bytes(header[0:2], 'big'))
            ext_len = int.from_bytes(header[2:4], 'big')
            pos += 4
            ext_data = _take(data, pos, ext_len, what='extension data', alias=self.alias)
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
            return bytes([int(content.level), int(content.description)])
        if content_type == Enum_ContentType.change_cipher_spec:
            return bytes([int(content.msg)])
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
        out += int(data.version).to_bytes(2, 'big')
        out += data.random
        out += bytes([len(data.session_id)]) + data.session_id

        if dtls:
            cookie = data.cookie if data.cookie is not None else b''
            out += bytes([len(cookie)]) + cookie

        cipher_suites = b''.join(int(suite).to_bytes(2, 'big') for suite in data.cipher_suites)
        out += len(cipher_suites).to_bytes(2, 'big') + cipher_suites

        compression_methods = bytes(int(method) for method in data.compression_methods)
        out += bytes([len(compression_methods)]) + compression_methods

        if data.extensions is not None:
            extensions_raw = self._make_tls_extensions(
                data.extensions, msg_type=cast('Enum_HandshakeType', Enum_HandshakeType.client_hello))
            out += len(extensions_raw).to_bytes(2, 'big') + extensions_raw
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
        out += int(data.version).to_bytes(2, 'big')
        out += data.random
        out += bytes([len(data.session_id)]) + data.session_id
        out += int(data.cipher_suite).to_bytes(2, 'big')
        out += bytes([int(data.compression_method)])

        if data.extensions is not None:
            extensions_raw = self._make_tls_extensions(data.extensions, msg_type=_hello_type(data.random))
            out += len(extensions_raw).to_bytes(2, 'big') + extensions_raw
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

        """
        out = bytearray()
        for extension in extensions:
            if isinstance(extension, tuple):
                code, kwargs = extension
                ext_type = Enum_ExtensionType.get(code)
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

            out += int(ext_type).to_bytes(2, 'big') + self._make_vector(ext_data, size=2)
        return bytes(out)
