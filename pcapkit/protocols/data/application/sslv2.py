# -*- coding: utf-8 -*-
"""data models for SSLv2 protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from pcapkit.const.sslv2.handshake_type import HandshakeType
    from pcapkit.const.sslv2.version import Version

__all__ = ['SSLv2', 'ClientHello', 'ServerHello']


@info_final
class ClientHello(Data):
    """Data model for the SSLv2 ``CLIENT-HELLO`` handshake message."""

    #: Client's maximum supported version.
    client_version: 'Version'
    #: Cipher kinds the client supports, as a concatenation of 3-octet
    #: ``CIPHER-KIND`` entries.
    cipher_specs: 'bytes'
    #: Session identifier, ``0`` or ``16`` octets.
    session_id: 'bytes'
    #: Client's challenge data, ``16``-``32`` octets.
    challenge: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, client_version: 'Version', cipher_specs: 'bytes',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     session_id: 'bytes', challenge: 'bytes') -> 'None': ...


@info_final
class ServerHello(Data):
    """Data model for the SSLv2 ``SERVER-HELLO`` handshake message."""

    #: Raw ``SESSION-ID-HIT`` octet, kept as read rather than normalised to a
    #: :obj:`bool`: per `draft-hickman-netscape-ssl-00`_ §5.6.1 any *non-zero*
    #: value is a hit. When non-zero, :attr:`certificate_type`, :attr:`certificate`
    #: and :attr:`cipher_specs` carry no data.
    #:
    #: .. _draft-hickman-netscape-ssl-00: https://datatracker.ietf.org/doc/html/draft-hickman-netscape-ssl-00
    session_id_hit: 'int'
    #: Certificate type, zero when :attr:`session_id_hit` is non-zero.
    certificate_type: 'int'
    #: Server's selected version.
    server_version: 'Version'
    #: Server's certificate, empty when :attr:`session_id_hit` is non-zero.
    certificate: 'bytes'
    #: Cipher kinds the server supports, as a concatenation of 3-octet
    #: ``CIPHER-KIND`` entries; empty when :attr:`session_id_hit` is non-zero.
    cipher_specs: 'bytes'
    #: Connection identifier, ``16``-``32`` octets.
    connection_id: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, session_id_hit: 'int', certificate_type: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     server_version: 'Version', certificate: 'bytes', cipher_specs: 'bytes',
                     connection_id: 'bytes') -> 'None': ...


@info_final
class SSLv2(Protocol):
    """Data model for SSLv2 packet."""

    #: Header length (``2`` or ``3`` octets), chosen by the high bit of the
    #: record header's first octet.
    header_len: 'int'
    #: Whether the record uses the 2-octet header form.
    two_byte_header: 'bool'
    #: ``IS-ESCAPE`` flag; always :data:`False` for a 2-octet header, which
    #: has no bit for it.
    is_escape: 'bool'
    #: The header's third, padding octet; ``0`` for a 2-octet header, which
    #: has none.
    padding: 'int'
    #: ``RECORD-LENGTH``, the record's data length, header excluded.
    record_length: 'int'
    #: Handshake message type.
    msg_type: 'HandshakeType'
    #: Handshake message body -- a parsed data model for ``CLIENT-HELLO`` and
    #: ``SERVER-HELLO``, or raw octets for every other
    #: :class:`~pcapkit.const.sslv2.handshake_type.HandshakeType` and for a
    #: hello-tagged body whose declared sub-field lengths do not fit the
    #: record, e.g. ciphertext.
    body: 'ClientHello | ServerHello | bytes'

    if TYPE_CHECKING:
        def __init__(self, header_len: 'int', two_byte_header: 'bool', is_escape: 'bool',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     padding: 'int', record_length: 'int', msg_type: 'HandshakeType',
                     body: 'ClientHello | ServerHello | bytes') -> 'None': ...
