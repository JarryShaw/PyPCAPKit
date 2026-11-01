# -*- coding: utf-8 -*-
"""SSLv2 - Secure Sockets Layer version 2
============================================

.. module:: pcapkit.protocols.application.sslv2

:mod:`pcapkit.protocols.application.sslv2` contains
:class:`~pcapkit.protocols.application.sslv2.SSLv2` only,
which implements an extractor for Secure Sockets Layer
version 2 (SSLv2) [*]_, as defined by the (long expired)
Netscape draft that introduced it.

SSLv2 is wire-*incompatible* with SSLv3 and TLS: it carries no
content-type byte and no ``0x03xx``-style record version, its record header
is 2 or 3 octets rather than a fixed 5, and its handshake message type is
the first octet of the record's data rather than a separate record-layer
field. See :func:`~pcapkit.protocols.schema.application.sslv2.sslv2_record_length`
for the header's exact shape.

SSLv1 has no module here, nor does it need one: it was never publicly
released, so there is no wire format to dissect.

Decoding ``CLIENT-HELLO``/``SERVER-HELLO`` bodies assumes the record is
genuinely cleartext. Per the draft's §5.4, most other message types are sent
*encrypted* once session keys exist, and this package implements no
decryption -- so a ``CLIENT-HELLO``/``SERVER-HELLO``-tagged record that is
actually ciphertext (e.g. a replayed or malformed capture) is only partly
caught. Before decoding, the body's own declared sub-field lengths are
checked against the record's ``RECORD-LENGTH`` (see
:func:`~pcapkit.protocols.schema.application.sslv2.sslv2_hello_probe_is_plausible`):
when they do not add up, the body is kept as raw octets instead. When they
happen to add up, the ciphertext still decodes as if it were the hello's own
fields, rather than failing cleanly. ``CIPHER-SPECS-DATA`` itself is kept as
an opaque concatenation of 3-octet ``CIPHER-KIND`` entries in every case;
none of the draft's own constraints on it, or on e.g. ``session_id`` being
``0`` or ``16`` octets, are validated here.

.. [*] https://datatracker.ietf.org/doc/html/draft-hickman-netscape-ssl-00

.. versionadded:: 1.6.0

"""
from typing import TYPE_CHECKING, cast

from pcapkit.const.sslv2.handshake_type import HandshakeType as Enum_HandshakeType
from pcapkit.const.sslv2.version import Version as Enum_Version
from pcapkit.protocols.application.ssl import SSL
from pcapkit.protocols.data.application.sslv2 import ClientHello as Data_ClientHello
from pcapkit.protocols.data.application.sslv2 import ServerHello as Data_ServerHello
from pcapkit.protocols.data.application.sslv2 import SSLv2 as Data_SSLv2
from pcapkit.protocols.schema.application.sslv2 import ClientHello as Schema_ClientHello
from pcapkit.protocols.schema.application.sslv2 import ServerHello as Schema_ServerHello
from pcapkit.protocols.schema.application.sslv2 import SSLv2 as Schema_SSLv2
from pcapkit.protocols.schema.application.sslv2 import \
    UnknownHandshakeBody as Schema_UnknownHandshakeBody
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import Any, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['SSLv2']


class SSLv2(SSL[Data_SSLv2, Schema_SSLv2],
           schema=Schema_SSLv2, data=Data_SSLv2):
    """This class implements Secure Sockets Layer version 2.

    Note:
        This class is not bound to TCP port 443 in
        :attr:`TCP.__proto__ <pcapkit.protocols.transport.tcp.TCP.__proto__>`:
        SSLv3 and TLS reuse that port. On 443 it is reached only as
        :class:`~pcapkit.protocols.application.tls.TLS`'s fallback, after
        TLS has rejected the record. Callers that know a stream is SSLv2
        construct this class directly.

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Secure Sockets Layer version 2"]':
        """Name of current protocol."""
        return 'Secure Sockets Layer version 2'

    @property
    def alias(self) -> 'Literal["SSLv2"]':
        """Acronym of current protocol."""
        return 'SSLv2'

    @property
    def length(self) -> 'int':
        """Header length of current protocol -- ``2`` or ``3`` octets,
        depending on the record's own header form."""
        return self._info.header_len

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["SSLv2"]]':  # type: ignore[override]
        """Index ID of the protocol."""
        return ('SSLv2',)

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_SSLv2':
        """Read Secure Sockets Layer version 2.

        Structure of an SSLv2 record, 2-octet header form:

        .. code-block:: text

           +-+-----------------------------+---------------+
           |1|      RECORD-LENGTH (15)     |  MSG-TYPE (8) |
           +-+-----------------------------+---------------+
           |                   Body (*)                  ...
           +-----------------------------------------------+

        3-octet header form:

        .. code-block:: text

           +-+-+---------------------------+---------------+---------------+
           |0|E|     RECORD-LENGTH (14)    |  PADDING (8)  |  MSG-TYPE (8) |
           +-+-+---------------------------+---------------+---------------+
           |                           Body (*)                          ...
           +---------------------------------------------------------------+

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        two_byte_header = bool(schema.indicator & 0x80)
        if two_byte_header:
            header_len = 2
            is_escape = False
            padding = 0
            record_length = ((schema.indicator & 0x7F) << 8) | schema.length_low
        else:
            header_len = 3
            is_escape = bool(schema.indicator & 0x40)
            padding = schema.padding
            record_length = ((schema.indicator & 0x3F) << 8) | schema.length_low

        if record_length < 1:
            # NOTE: ``RECORD-LENGTH`` counts ``MSG-TYPE``, so ``0`` is malformed; the
            # ``MSG-TYPE`` octet already read belongs to the next record.
            raise ProtocolError(f'SSLv2: record length ({record_length}) is too short to '
                                f'include a MSG-TYPE octet')

        body_schema = schema.body
        if isinstance(body_schema, Schema_ClientHello):
            body = Data_ClientHello(
                client_version=body_schema.client_version,
                cipher_specs=body_schema.cipher_specs,
                session_id=body_schema.session_id,
                challenge=body_schema.challenge,
            )  # type: bytes | Data_ClientHello | Data_ServerHello
        elif isinstance(body_schema, Schema_ServerHello):
            # NOTE: wire bytes always fit; this refuses a programmatically built
            # schema, e.g. ``make(body=Schema_ServerHello(session_id_hit=256))``.
            if not 0 <= body_schema.session_id_hit <= 255:
                raise ProtocolError(f'SSLv2: SESSION-ID-HIT ({body_schema.session_id_hit}) out '
                                    f'of range for a single octet (0-255)')
            body = Data_ServerHello(
                # NOTE: kept as the raw octet, not normalised to a strict
                # bool -- see ``Data_ServerHello.session_id_hit``.
                session_id_hit=body_schema.session_id_hit,
                certificate_type=body_schema.certificate_type,
                server_version=body_schema.server_version,
                certificate=body_schema.certificate,
                cipher_specs=body_schema.cipher_specs,
                connection_id=body_schema.connection_id,
            )
        else:
            # NOTE: non-hello types, and hello-tagged records failing the length
            # probe (likely ciphertext), are kept as raw octets.
            body = cast('Schema_UnknownHandshakeBody', body_schema).data

        sslv2 = Data_SSLv2(
            header_len=header_len,
            two_byte_header=two_byte_header,
            is_escape=is_escape,
            padding=padding,
            record_length=record_length,
            msg_type=schema.msg_type,
            body=body,
        )
        return self._decode_next_layer(sslv2, -1, length - header_len - record_length)

    def make(self,
             msg_type: 'Enum_HandshakeType | StdlibEnum | AenumEnum | str | int' = Enum_HandshakeType.CLIENT_HELLO,
             msg_type_default: 'Optional[int]' = None,
             msg_type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             msg_type_reversed: 'bool' = False,
             two_byte_header: 'bool' = True,
             is_escape: 'bool' = False,
             padding: 'int' = 0,
             body: 'Optional[bytes | Data_ClientHello | Data_ServerHello | Schema_ClientHello | Schema_ServerHello | Schema_UnknownHandshakeBody | dict[str, Any]]' = None,  # pylint: disable=line-too-long
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_SSLv2':
        """Make (construct) packet data.

        Args:
            msg_type: Handshake message type.
            msg_type_default: Default value for ``msg_type``.
            msg_type_namespace: Namespace for ``msg_type``.
            msg_type_reversed: Reverse namespace for ``msg_type``.
            two_byte_header: Whether to emit the 2-octet header form (the
                more common of the two on real traffic) rather than the
                3-octet form.
            is_escape: ``IS-ESCAPE`` flag; only meaningful -- and only
                written -- for the 3-octet header form.
            padding: The header's third, padding octet; only meaningful --
                and only written -- for the 3-octet header form.
            body: Handshake message body. A :obj:`dict` or a
                :class:`~pcapkit.protocols.data.application.sslv2.ClientHello`
                /:class:`~pcapkit.protocols.data.application.sslv2.ServerHello`
                data model builds the body according to ``msg_type``, which
                must then be ``CLIENT_HELLO`` or ``SERVER_HELLO``
                respectively; omitting it, i.e. :data:`None`, builds an
                empty one the same way, as ``{}`` does. A schema instance is
                taken as is. Raw :obj:`bytes` are written verbatim. A
                message type whose body this package does not parse is
                given its body as :obj:`bytes` or as an
                :class:`~pcapkit.protocols.schema.application.sslv2.UnknownHandshakeBody`.
            payload: Octets after the record, e.g. the next record.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``body`` is a :obj:`dict` and ``msg_type`` is
                not ``CLIENT_HELLO``/``SERVER_HELLO``; if ``body`` is a
                :class:`~pcapkit.protocols.data.application.sslv2.ClientHello`/
                :class:`~pcapkit.protocols.data.application.sslv2.ServerHello`
                data model and ``msg_type`` does not match it (``CLIENT_HELLO``
                for the former, ``SERVER_HELLO`` for the latter); if ``body``
                is of a type this maker does not recognise; if the
                resulting record is longer than the chosen header form
                allows; or if ``padding`` does not fit the 3-octet header
                form's single padding octet (``0``-``255``).

        """
        msg_type_val = cast('Enum_HandshakeType',
                            self._make_index(msg_type, msg_type_default, namespace=msg_type_namespace,
                                             reversed=msg_type_reversed, pack=False))

        if body is None:
            body = {}

        if isinstance(body, bytes):
            body_val = body  # type: bytes | Schema_ClientHello | Schema_ServerHello | Schema_UnknownHandshakeBody
        elif isinstance(body, (Schema_ClientHello, Schema_ServerHello, Schema_UnknownHandshakeBody)):
            body_val = body
        elif isinstance(body, Data_ClientHello):
            if msg_type_val != Enum_HandshakeType.CLIENT_HELLO:
                # NOTE: a mismatched ``msg_type`` would re-parse this body as
                # another type's fields, e.g. as a ``ServerHello``.
                raise ProtocolError(f'SSLv2: a ClientHello body must be given with '
                                    f'msg_type=CLIENT_HELLO, not {msg_type_val!s}')
            body_val = self._make_sslv2_client_hello(
                client_version=body.client_version,
                cipher_specs=body.cipher_specs,
                session_id=body.session_id,
                challenge=body.challenge,
            )
        elif isinstance(body, Data_ServerHello):
            if msg_type_val != Enum_HandshakeType.SERVER_HELLO:
                raise ProtocolError(f'SSLv2: a ServerHello body must be given with '
                                    f'msg_type=SERVER_HELLO, not {msg_type_val!s}')
            body_val = self._make_sslv2_server_hello(
                session_id_hit=body.session_id_hit,
                certificate_type=body.certificate_type,
                server_version=body.server_version,
                certificate=body.certificate,
                cipher_specs=body.cipher_specs,
                connection_id=body.connection_id,
            )
        elif isinstance(body, dict):
            if msg_type_val == Enum_HandshakeType.CLIENT_HELLO:
                body_val = self._make_sslv2_client_hello(**body)
            elif msg_type_val == Enum_HandshakeType.SERVER_HELLO:
                body_val = self._make_sslv2_server_hello(**body)
            else:
                raise ProtocolError(f'SSLv2: a {msg_type_val!s} body must be given as bytes, '
                                    f'not a dict -- this package only builds '
                                    f'CLIENT-HELLO/SERVER-HELLO bodies from one')
        else:
            raise ProtocolError(f'SSLv2: invalid body: {body!r}')

        body_bytes_len = len(body_val) if isinstance(body_val, bytes) else len(bytes(body_val))
        # NOTE: ``+ 1`` for ``MSG-TYPE``, which is part of ``RECORD-LENGTH``
        # but not part of ``body`` -- see ``Schema_SSLv2.msg_type``.
        record_length = body_bytes_len + 1

        if two_byte_header:
            if not 0 <= record_length <= 0x7FFF:
                raise ProtocolError(f'SSLv2: record ({record_length} octet(s)) too long for '
                                    f"the 2-octet header form's 32767-octet limit")
            indicator = 0x80 | (record_length >> 8)
            padding_val = 0
        else:
            if not 0 <= record_length <= 0x3FFF:
                raise ProtocolError(f'SSLv2: record ({record_length} octet(s)) too long for '
                                    f"the 3-octet header form's 16383-octet limit")
            if not 0 <= padding <= 0xFF:
                raise ProtocolError(f'SSLv2: padding ({padding}) out of range for the '
                                    f"3-octet header form's single padding octet (0-255)")
            indicator = (0x40 if is_escape else 0x00) | (record_length >> 8)
            padding_val = padding
        length_low = record_length & 0xFF

        return Schema_SSLv2(
            indicator=indicator,
            length_low=length_low,
            padding=padding_val,
            msg_type=msg_type_val,
            body=body_val,
            payload=payload,
        )

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_SSLv2') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Only the fields :meth:`make` accepts are passed, so derived fields
        such as ``record_length`` raise no
        :class:`~pcapkit.utilities.warnings.UnknownFieldWarning`, and
        ``payload`` carries any chained next record through a
        :meth:`~pcapkit.protocols.protocol.Protocol.from_data` round trip.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'msg_type': data.msg_type,
            'two_byte_header': data.two_byte_header,
            'is_escape': data.is_escape,
            'padding': data.padding,
            'body': data.body,
            'payload': cls._make_payload(data),
        }

    def _make_sslv2_client_hello(self,
                                client_version: 'Enum_Version | StdlibEnum | AenumEnum | str | int' = Enum_Version.SSLv2,  # pylint: disable=line-too-long
                                client_version_default: 'Optional[int]' = None,
                                client_version_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                                client_version_reversed: 'bool' = False,
                                cipher_specs: 'bytes' = b'',
                                session_id: 'bytes' = b'',
                                challenge: 'bytes' = b'\x00' * 16) -> 'Schema_ClientHello':
        """Make a ``CLIENT-HELLO`` handshake message body.

        Args:
            client_version: Client's maximum supported version.
            client_version_default: Default value for ``client_version``.
            client_version_namespace: Namespace for ``client_version``.
            client_version_reversed: Reverse namespace for ``client_version``.
            cipher_specs: Cipher kinds the client supports, as a
                concatenation of 3-octet ``CIPHER-KIND`` entries. The draft
                (§5.5.1) requires ``CIPHER-SPECS-LENGTH`` to be greater than
                zero, i.e. at least one entry -- the default, ``b''``, builds
                a ``CLIENT-HELLO`` the draft forbids, so a caller building a
                conformant one must supply this.
            session_id: Session identifier; ``0`` or ``16`` octets.
            challenge: Client's challenge data; ``16``-``32`` octets.

        Returns:
            ``CLIENT-HELLO`` message body schema.

        """
        client_version_val = cast('Enum_Version',
                                  self._make_index(client_version, client_version_default,
                                                   namespace=client_version_namespace,
                                                   reversed=client_version_reversed, pack=False))
        return Schema_ClientHello(
            client_version=client_version_val,
            cipher_specs_length=len(cipher_specs),
            session_id_length=len(session_id),
            challenge_length=len(challenge),
            cipher_specs=cipher_specs,
            session_id=session_id,
            challenge=challenge,
        )

    def _make_sslv2_server_hello(self,
                                session_id_hit: 'int | bool' = 0,
                                certificate_type: 'int' = 0,
                                server_version: 'Enum_Version | StdlibEnum | AenumEnum | str | int' = Enum_Version.SSLv2,  # pylint: disable=line-too-long
                                server_version_default: 'Optional[int]' = None,
                                server_version_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                                server_version_reversed: 'bool' = False,
                                certificate: 'bytes' = b'',
                                cipher_specs: 'bytes' = b'',
                                connection_id: 'bytes' = b'\x00' * 16) -> 'Schema_ServerHello':
        """Make a ``SERVER-HELLO`` handshake message body.

        Args:
            session_id_hit: ``SESSION-ID-HIT`` octet. Per the draft (§5.6.1)
                any *non-zero* value means "hit", not specifically ``1`` --
                this is written through verbatim (so a caller reconstructing
                from parsed data reproduces the exact octet observed on the
                wire), with :data:`True`/:data:`False` taken as
                ``1``/``0`` for callers that only care about the boolean
                sense. Must fit the single octet the wire format has for it
                (``0``-``255``); anything else raises
                :class:`~pcapkit.utilities.exceptions.ProtocolError`
                rather than wrapping mod 256.
            certificate_type: Certificate type.
            server_version: Server's selected version.
            server_version_default: Default value for ``server_version``.
            server_version_namespace: Namespace for ``server_version``.
            server_version_reversed: Reverse namespace for ``server_version``.
            certificate: Server's certificate.
            cipher_specs: Cipher kinds the server supports, as a
                concatenation of 3-octet ``CIPHER-KIND`` entries -- empty
                when ``session_id_hit`` is non-zero, but the default,
                ``b''``, is also what this builds for a non-hit
                ``SERVER-HELLO`` unless a caller overrides it, which the
                draft does not sanction (the server picks from the client's
                offered specs, so it always has at least one to report when
                it is not a hit).
            connection_id: Connection identifier; ``16``-``32`` octets.

        Returns:
            ``SERVER-HELLO`` message body schema.

        """
        server_version_val = cast('Enum_Version',
                                  self._make_index(server_version, server_version_default,
                                                   namespace=server_version_namespace,
                                                   reversed=server_version_reversed, pack=False))
        session_id_hit_val = int(session_id_hit)
        if not 0 <= session_id_hit_val <= 255:
            # NOTE: ``UInt8Field`` packs mod 256, so ``256`` would silently
            # write as ``0x00``, turning a hit into a miss.
            raise ProtocolError(f'SSLv2: SESSION-ID-HIT ({session_id_hit_val}) out of range '
                                f'for a single octet (0-255)')
        return Schema_ServerHello(
            # NOTE: preserved as given, not collapsed to a strict 0/1 --
            # see ``Data_ServerHello.session_id_hit``.
            session_id_hit=session_id_hit_val,
            certificate_type=certificate_type,
            server_version=server_version_val,
            certificate_length=len(certificate),
            cipher_specs_length=len(cipher_specs),
            connection_id_length=len(connection_id),
            certificate=certificate,
            cipher_specs=cipher_specs,
            connection_id=connection_id,
        )
