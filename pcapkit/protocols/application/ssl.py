# -*- coding: utf-8 -*-
"""SSL - Secure Sockets Layer
===============================

.. module:: pcapkit.protocols.application.ssl

:mod:`pcapkit.protocols.application.ssl` contains
:class:`~pcapkit.protocols.application.ssl.SSL` only,
which is a base class for Transport Layer Security (TLS) protocol
family [*]_, e.g.
:class:`~pcapkit.protocols.application.tls.TLS` and
:class:`~pcapkit.protocols.application.dtls.DTLS`.

The record-layer header -- a :class:`~pcapkit.const.tls.content_type.ContentType`,
a legacy record version, and a length -- is byte-identical in shape between
TLS (:rfc:`9846#section-5.1`) and DTLS (:rfc:`9147#section-4`); DTLS's own
divergence (an explicit epoch and sequence number in the record header, and
handshake-message fragmentation that a reliable TLS stream never needs) stays
entirely in :class:`~pcapkit.protocols.application.dtls.DTLS`. This base class
carries the logic the two genuinely share -- content-type dispatch and
handshake-message decoding -- parameterised by a ``dtls`` flag where DTLS's
extra fragment header has to be read or written; the record header fields
themselves are declared separately in each subclass's own schema
(:class:`~pcapkit.protocols.schema.application.tls.TLS` and
:class:`~pcapkit.protocols.schema.application.dtls.DTLS`), since DTLS inserts
its epoch and sequence number *between* the version and the length rather than
appending them.

.. [*] https://en.wikipedia.org/wiki/Transport_Layer_Security

.. versionadded:: 1.6.0

"""
from typing import TYPE_CHECKING, Generic

from pcapkit.const.tls.content_type import ContentType as Enum_ContentType
from pcapkit.const.tls.handshake_type import HandshakeType as Enum_HandshakeType
from pcapkit.protocols.application.application import Application
from pcapkit.protocols.data.application.tls import Alert as Data_Alert
from pcapkit.protocols.data.application.tls import ChangeCipherSpec as Data_ChangeCipherSpec
from pcapkit.protocols.data.application.tls import ClientHello as Data_ClientHello
from pcapkit.protocols.data.application.tls import Extension as Data_Extension
from pcapkit.protocols.data.application.tls import Handshake as Data_Handshake
from pcapkit.protocols.data.application.tls import ServerHello as Data_ServerHello
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

#: The content types a genuine record may carry, i.e. every value IANA's ``TLS
#: ContentType`` registry assigns. Written out rather than taken as "every
#: member :class:`~pcapkit.const.tls.content_type.ContentType` names" for two
#: reasons: :attr:`~pcapkit.const.tls.content_type.ContentType.invalid` is a
#: named member that is *not* a wire value -- :rfc:`9846#section-5.1` defines
#: ``invalid(0)`` as a sentinel to be rejected, and IANA keeps 0 inside its
#: Unassigned 0-19 band -- and iterating the registry would also be a moving
#: target, since a lookup of an unassigned value mints a member rather than
#: raising. An allowlist is what makes this a *decision* about the wire rather
#: than a restatement of whatever the registry happens to hold.
#:
#: :attr:`~pcapkit.const.tls.content_type.ContentType.tls12_cid` (25,
#: :rfc:`9146`) is deliberately left out. Every other type here keeps
#: ``length`` at the fixed offset :class:`~pcapkit.protocols.schema.application.tls.TLS`/
#: :class:`~pcapkit.protocols.schema.application.dtls.DTLS` declare it at, but
#: a Connection ID record inserts the CID *before* ``length``
#: (:rfc:`9146#section-4`), and the CID's own length is negotiated out of band
#: during the handshake -- it is not on the wire of the record itself. Reading
#: ``length`` at the fixed offset for a type-25 record decodes the tail of the
#: CID as the length field, fabricating a fragment that was never on the wire
#: (confirmed: an 8-octet CID made an 8-octet fragment read back as
#: ``length=17``). Parsing it correctly needs this dissector to track the
#: negotiated CID length per connection, which the current stateless,
#: per-packet schema read has nowhere to keep; until a follow-up adds that,
#: type 25 is excluded here so it falls back to
#: :class:`~pcapkit.protocols.misc.raw.Raw` instead of being decoded wrong.
_WIRE_CONTENT_TYPES = frozenset({
    Enum_ContentType.change_cipher_spec,
    Enum_ContentType.alert,
    Enum_ContentType.handshake,
    Enum_ContentType.application_data,
    Enum_ContentType.heartbeat,
    Enum_ContentType.ack,
    Enum_ContentType.return_routability_check,
})


def _take(data: 'bytes', pos: 'int', size: 'int', *, what: 'str', alias: 'str') -> 'bytes':
    """Slice ``size`` octets out of ``data`` at ``pos``, refusing a short read.

    Plain slicing never raises on a short buffer -- ``b'ab'[0:4]`` is ``b'ab'``
    -- so a truncated handshake message would otherwise parse a few octets
    short rather than fail. This is what makes each caller's spec-shaped slice
    actually bounds-checked.

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

    A ``handshake`` record's fragment is cleartext only until the handshake
    derives keys; after that a record still typed ``handshake`` (a ``Finished``,
    a post-handshake ``NewSessionTicket`` or ``KeyUpdate``) carries ciphertext,
    and nothing in the cleartext header says which it is. What does distinguish
    them is self-consistency: a cleartext fragment is a whole number of
    messages, each a 4-octet ``msg_type``/``length`` header followed by exactly
    ``length`` octets, so walking those headers lands on the fragment's last
    octet exactly. Ciphertext is pseudorandom and overwhelmingly does not.

    Args:
        fragment: Record fragment, i.e. the candidate handshake messages.

    Returns:
        Whether the walk lands exactly on the end of ``fragment``.

    Notes:
        This is a heuristic, and an imperfect one in both directions. A
        ciphertext fragment whose octets happen to tile is still taken for
        cleartext -- telling the two apart needs the session keys, which a
        passive dissector does not have. And a genuine cleartext handshake
        message that :rfc:`9846#section-5.1` has split across more than one
        TLS record does *not* tile within a single record either, so this
        walk fails it the same way it fails ciphertext; the "always tiles"
        case holds only for a message that fits in one record, which is the
        common one. Both misses land on the same, conservative side, though:
        this method is consulted only to decide whether to decode, and
        keeping either case's octets opaque loses nothing, while mis-decoding
        ciphertext fabricates messages.

    """
    pos = 0
    total = len(fragment)
    while pos < total:
        if total - pos < 4:
            return False
        pos += 4 + int.from_bytes(fragment[pos + 1:pos + 4], 'big')
    return pos == total


class SSL(Application[_PT, _ST], Generic[_PT, _ST]):  # pylint: disable=abstract-method
    """Base class for the TLS protocol family.

    - Transport Layer Security (:class:`~pcapkit.protocols.application.tls.TLS`) [:rfc:`5246`, :rfc:`9846`]
    - Datagram TLS (:class:`~pcapkit.protocols.application.dtls.DTLS`) [:rfc:`6347`, :rfc:`9147`]

    """

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["TLS"], Literal["DTLS"]]':
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return ('TLS', 'DTLS')

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _validate_tls_record(self, schema: 'Any', *, available: 'int', dtls: 'bool') -> 'None':
        """Reject octets that cannot be a genuine TLS/DTLS record.

        Dispatch hands this class *every* payload on TCP port 443 (or UDP
        port 5684), and once a connection is past its handshake most of those
        are mid-stream ciphertext continuations with no record header in them
        at all -- not an edge case, the common case. Without this check, any
        content-type octet and legacy version decode as *some* record:
        :class:`~pcapkit.corekit.enum.EnumRegistry`'s ``_missing_`` mints an
        ``Unassigned`` pseudo-member for a value no :class:`~pcapkit.const.tls.content_type.ContentType`
        names rather than refusing it, and a declared :attr:`~pcapkit.protocols.schema.application.tls.TLS.length`
        longer than what is actually left is silently zero-padded out to that
        length by :meth:`FieldBase.unpack <pcapkit.corekit.fields.field.FieldBase.unpack>`'s
        truncated-capture tolerance -- fabricating record content from octets
        that were never on the wire, rather than signalling that this was not
        a record to begin with.

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
            **A record split across two TCP segments is rejected**, since its
            first segment carries a header whose declared ``length`` genuinely
            does run past the end of that segment. A TLS record may be up to
            16 KiB (:rfc:`9846#section-5.1`) against a typical 1460-octet MSS,
            so this is routine rather than rare -- a post-quantum
            ``ClientHello`` alone exceeds one segment. Accepting it would need
            the record reassembled across the stream first, which is
            :class:`~pcapkit.foundation.reassembly.tcp.TCP`'s job and not
            something this layer can see; until a record arrives whole,
            degrading to :class:`~pcapkit.protocols.misc.raw.Raw` is the honest
            answer, because the fragment this layer holds is not a record.

        """
        # NOTE: ``schema.content_type`` is the registry member when this
        # schema came from a genuine parse (``EnumField.post_process``
        # resolves it there), but a plain :obj:`int` when it came from
        # ``make()`` instead -- :meth:`Protocol._make_index` with
        # ``pack=False`` returns the bare index despite its ``cast`` to the
        # enum type, which is a typing fiction rather than a runtime one. So
        # it is resolved through the registry explicitly here rather than
        # read off the value directly, to cover both.
        #
        # NOTE: checked against ``_WIRE_CONTENT_TYPES`` rather than by asking
        # whether the registry named the value: ``invalid(0)`` *is* named, and
        # is still not a content type any record carries, so a name-based test
        # accepted ``00 03 03 ...`` as a TLS record and decoded its fragment.
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

    def _tls_content_is_cleartext(self, content_type: 'Enum_ContentType', fragment: 'bytes', *,
                                  dtls: 'bool', epoch: 'int') -> 'bool':
        """Whether a record's fragment is cleartext to decode structurally.

        Three content types -- ``handshake``, ``alert``, and
        ``change_cipher_spec`` -- carry a record format that is genuine only
        before keys are derived; once they are, a record still typed the same
        way carries ciphertext, with nothing in the cleartext record header to
        say which it is. Decoding the ciphertext case structurally either
        fabricates content out of pseudorandom octets or fails and drops the
        whole record to :class:`~pcapkit.protocols.misc.raw.Raw`, losing the
        record header that *was* in the clear -- the bug this method exists to
        avoid for all three types rather than just ``handshake``, where it was
        first caught.

        The two protocols answer this differently because DTLS gives a direct
        answer and TLS does not:

        * **DTLS** states it in the record header, for every content type:
          the epoch counts cipher changes (:rfc:`9147#section-4.2`), so epoch
          0 is exactly the cleartext initial handshake and any later epoch is
          encrypted.
        * **TLS** has no such field, so each type falls back to its own
          self-consistency check instead:

          * ``handshake`` -- :func:`_tls_handshake_tiles` asks whether the
            fragment is a whole number of messages.
          * ``alert`` -- a genuine cleartext alert is always exactly 2 octets
            (``level`` + ``description``); an encrypted one can never land on
            exactly 2, because of the MAC/tag overhead encryption adds.
          * ``change_cipher_spec`` -- the same reasoning, at exactly 1 octet.

        Any other content type is reported as *not* cleartext -- a miss lands
        on the conservative side, same as :func:`_tls_handshake_tiles` -- even
        though callers today only consult this for the three above, so that a
        future content type ever routed through this method without adding a
        branch for it fails closed instead of silently reintroducing the bug
        this method exists to avoid.

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
            None of ``handshake``, ``alert``, or ``change_cipher_spec`` are
            necessarily *cleartext* just because of their content type.
            TLS 1.2's ``Finished`` and any renegotiation handshake travel as
            ciphertext under ``handshake`` once keys are derived, with no
            flag in the cleartext header to say so -- and TLS 1.3's
            post-handshake messages (``NewSessionTicket``, ``KeyUpdate``) are
            not under this type at all, since TLS 1.3's outer record type is
            always ``application_data`` once encryption starts, and
            ``KeyUpdate`` has no TLS 1.2 equivalent to begin with. An
            encrypted TLS 1.2 ``alert`` -- including the ``close_notify``
            that ends nearly every connection -- or a ``change_cipher_spec``
            sent mid-renegotiation is the same shape of problem under those
            two types. Every one of the three is kept as opaque :obj:`bytes`
            rather than decoded when it is not cleartext, which is what
            :meth:`_tls_content_is_cleartext` decides.

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

    def _read_tls_handshake_messages(self, fragment: 'bytes', *,
                                     dtls: 'bool') -> 'tuple[Any, ...]':
        """Decode a ``handshake`` record fragment into its handshake messages.

        A TLS record may coalesce several handshake messages (e.g.
        ``Certificate``, ``ServerKeyExchange`` and ``ServerHelloDone`` in one
        record), so this reads however many fit in ``fragment`` rather than
        exactly one.

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
            A ``ClientHello``/``ServerHello`` body is decoded into
            :class:`~pcapkit.protocols.data.application.tls.ClientHello`/
            :class:`~pcapkit.protocols.data.application.tls.ServerHello`
            only when the whole message is present -- always true for TLS,
            and true for DTLS only when the message is not fragmented across
            several records. A DTLS message that is split across records is
            not reassembled in this version (:issue:`2440`), so its body is
            kept as the single fragment's raw octets regardless of
            ``msg_type``. Every other ``msg_type`` is message-TYPE-level
            framing only: its body is kept undecoded, as :issue:`2437` scopes
            this PR to.

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
            # NOTE: 0 rather than ``None`` -- unused by the ``else`` branch
            # below when ``dtls`` is false, so there is no "not yet known"
            # state for a type to carry, only a value :class:`DTLSHandshake`
            # declares as plain ``int``.
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
                :obj:`bytes` per message.
            dtls: Whether to write DTLS's fragment header after each
                message's ``msg_type``/``length`` header.

        Returns:
            Encoded record fragment.

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

            # NOTE: the message's own ``length`` is trusted only when it
            # cannot be recovered any other way -- a fragmented DTLS message,
            # where this fragment's body is a strict subset of the total.
            # Otherwise it is recomputed from ``body_bytes``, so a message
            # built by hand need not get a redundant length right, and a
            # parse-then-rebuild stays exact either way (a read message's
            # ``length`` already equals its body's, there or in DTLS's
            # unfragmented case).
            is_fragmented = dtls and message.is_fragmented
            length = message.length if is_fragmented else len(body_bytes)

            out += bytes([int(message.msg_type)]) + length.to_bytes(3, 'big')
            if dtls:
                fragment_length = message.fragment_length if is_fragmented else len(body_bytes)
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

        DTLS's ``ClientHello`` is identical except for one insertion: a
        length-prefixed ``cookie`` directly after ``legacy_session_id`` and
        before ``cipher_suites`` [:rfc:`6347#section-4.2.1`;
        :rfc:`9147#section-5.3`'s ``legacy_cookie`` carries it forward
        unchanged], which TLS's ``ClientHello`` does not carry at all:

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
        # NOTE: a ``CipherSuite`` is 2 octets (:rfc:`9846#section-4.2.2`), so an
        # odd length never has an RFC-compliant decoding -- and without this
        # check, the last, incomplete pair would quietly decode as one lone
        # octet rather than fail, and :meth:`_make_tls_client_hello` would then
        # re-pad it to 2 octets on rebuild, losing byte-exactness silently
        # rather than refusing to parse.
        if cipher_suites_len % 2 != 0:
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

    def _read_tls_extensions(self, data: 'bytes') -> 'tuple[Data_Extension, ...]':
        """Decode an extension list -- TYPE and LENGTH framing only.

        Structure of one extension [:rfc:`9846#section-4.3`]:

        .. code-block:: text

           struct {
               ExtensionType extension_type;
               opaque extension_data<0..2^16-1>;
           } Extension;

        An extension's own body is not decoded (:issue:`2437`): it is kept
        as :attr:`~pcapkit.protocols.data.application.tls.Extension.data`,
        undecoded, which is what this PR scopes extension support to.

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
