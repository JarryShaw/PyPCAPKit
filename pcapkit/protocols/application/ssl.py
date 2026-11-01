# -*- coding: utf-8 -*-
"""SSL - Secure Sockets Layer
===============================

.. module:: pcapkit.protocols.application.ssl

:mod:`pcapkit.protocols.application.ssl` contains
:class:`~pcapkit.protocols.application.ssl.SSL` only,
which is the umbrella base class for the Secure Sockets Layer protocol
family [*]_ -- the SSL versions, Transport Layer Security
(:class:`~pcapkit.protocols.application.tls.TLS`, which also covers SSLv3
through :class:`~pcapkit.protocols.application.tls.SSLv3`) and Datagram TLS
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
dispatch and handshake-message decoding -- parameterised by a ``dtls`` flag
where the DTLS handshake fragment header has to be read or written.

.. [*] https://en.wikipedia.org/wiki/Transport_Layer_Security

.. versionadded:: 1.6.0

"""
from typing import TYPE_CHECKING, Generic

from pcapkit.const.tls.content_type import ContentType as Enum_ContentType
from pcapkit.const.tls.handshake_type import HandshakeType as Enum_HandshakeType
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.application.application import Application
from pcapkit.protocols.data.application.tls import Alert as Data_Alert
from pcapkit.protocols.data.application.tls import ChangeCipherSpec as Data_ChangeCipherSpec
from pcapkit.protocols.data.application.tls import ClientHello as Data_ClientHello
from pcapkit.protocols.data.application.tls import Extension as Data_Extension
from pcapkit.protocols.data.application.tls import Handshake as Data_Handshake
from pcapkit.protocols.data.application.tls import ServerHello as Data_ServerHello
from pcapkit.protocols.misc.null import NoPayload
from pcapkit.protocols.protocol import _PT, _ST
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from typing import Any, Optional

    from typing_extensions import Literal

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

#: The ``supported_versions`` extension type (:rfc:`9846#section-4.3.1`), where
#: TLS 1.3 and DTLS 1.3 negotiate the version their record header does not carry.
_EXT_SUPPORTED_VERSIONS = 43

#: The ``supported_versions`` value for TLS 1.3 (:rfc:`9846#section-4.3.1`).
TLS13_VERSION = 0x0304
#: The ``supported_versions`` value for DTLS 1.3 (:rfc:`9147#section-5.3`).
DTLS13_VERSION = 0xFEFC


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
        ``supported_versions`` extension -- including when it carries no
        ``extensions`` at all.

    """
    extensions = getattr(message, 'extensions', None)
    if not extensions:
        return ()
    for extension in extensions:
        if int(extension.type) != _EXT_SUPPORTED_VERSIONS:
            continue
        data = extension.data
        # A ``ClientHello`` lists several versions behind a 1-octet length
        # prefix; a ``ServerHello`` selects exactly one, with no length
        # prefix of its own (:rfc:`9846#section-4.3.1`).
        versions = data[1:] if isinstance(message, Data_ClientHello) else data
        return tuple(
            int.from_bytes(versions[i:i + 2], 'big') for i in range(0, len(versions) - 1, 2)
        )
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

    """

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

    ##########################################################################
    # Utilities.
    ##########################################################################

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
            Only an unfragmented ``ClientHello``/``ServerHello`` body is
            decoded; other bodies stay undecoded (:issue:`2437`). A fragmented
            DTLS message is decoded once reassembled, by
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
            extensions = self._read_tls_extensions(extensions_raw)

        if pos != len(body):
            raise ProtocolError(f'{alias}: invalid format: client_hello carries excess octets')

        return Data_ClientHello(
            version=version, random=random, session_id=session_id, cookie=cookie,
            cipher_suites=cipher_suites, compression_methods=compression_methods,
            extensions=extensions,
        )

    def _read_tls_server_hello(self, body: 'bytes') -> 'Data_ServerHello':
        """Decode a ``ServerHello`` handshake message body.

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
            extensions = self._read_tls_extensions(extensions_raw)

        if pos != len(body):
            raise ProtocolError(f'{alias}: invalid format: server_hello carries excess octets')

        return Data_ServerHello(
            version=version, random=random, session_id=session_id, cipher_suite=cipher_suite,
            compression_method=compression_method, extensions=extensions,
        )

    def _read_tls_extensions(self, data: 'bytes') -> 'tuple[Data_Extension, ...]':
        """Decode an extension list -- TYPE and LENGTH framing only.

        Structure of one extension [:rfc:`9846#section-4.3`]:

        .. code-block:: text

           struct {
               ExtensionType extension_type;
               opaque extension_data<0..2^16-1>;
           } Extension;

        An extension's body is kept undecoded (:issue:`2437`).

        Args:
            data: The extension list, i.e. one or more concatenated
                extensions, with no further length prefix of its own.

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
            ext_type = int.from_bytes(header[0:2], 'big')
            ext_len = int.from_bytes(header[2:4], 'big')
            pos += 4
            ext_data = _take(data, pos, ext_len, what='extension data', alias=self.alias)
            pos += ext_len
            extensions.append(Data_Extension(type=ext_type, data=ext_data))
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
            extensions_raw = self._make_tls_extensions(data.extensions)
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
            extensions_raw = self._make_tls_extensions(data.extensions)
            out += len(extensions_raw).to_bytes(2, 'big') + extensions_raw
        return bytes(out)

    def _make_tls_extensions(self, extensions: 'tuple[Data_Extension, ...]') -> 'bytes':
        """Encode an extension list -- the inverse of :meth:`_read_tls_extensions`.

        Args:
            extensions: Decoded extensions.

        Returns:
            Encoded extension list, with no further length prefix of its own.

        """
        out = bytearray()
        for extension in extensions:
            out += int(extension.type).to_bytes(2, 'big')
            out += len(extension.data).to_bytes(2, 'big')
            out += extension.data
        return bytes(out)
