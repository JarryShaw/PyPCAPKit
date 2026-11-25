# -*- coding: utf-8 -*-
"""The ``tls-extension`` family: TLS handshake extensions.

Each case is one extension in a ``ClientHello``, built from keyword arguments
by the extension's ``_make_ext_*``: a DTLS one for a DTLS-only type, which a
TLS record has no structure for (#2853), a TLS one otherwise. No capture is
written: the ``tcp`` envelope is addressed to port 80, which dispatches to HTTP
rather than TLS.

A family module of :file:`examples/generators/options.py`, which loads it by
path and binds ``generator`` to itself before this body runs (#2615).

"""
# Deferring these is the design, as in options.py -- see its module docstring.
# pylint: disable=import-outside-toplevel

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

#: :file:`examples/generators/options.py`, which its loader binds here
#: before this body runs.
generator = globals()['generator']  # type: Any


def _tls_extension_registry() -> 'Any':
    from pcapkit.protocols.application.tls.protocol import TLS
    return TLS.__extension__


def _tls_extension_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.tls.extension_type import ExtensionType as Enum_ExtensionType
    from pcapkit.protocols.application.ssl.data import (HpkeSymmetricCipherSuite, KeyShareEntry,
                                                        PskIdentity, ServerName)
    return {
        # Each of these defaults to an empty list or empty octets.
        Enum_ExtensionType.server_name: {
            'server_name_list': (ServerName(name_type=0, name=b'example.com'),)},
        Enum_ExtensionType.status_request: {'responder_id_list': (b'\x30\x00',), 'request_extensions': b'\x30\x00'},
        Enum_ExtensionType.supported_groups: {'named_group_list': (0x001D, 0x0017)},
        Enum_ExtensionType.ec_point_formats: {'ec_point_format_list': (0, 1, 2)},
        Enum_ExtensionType.signature_algorithms: {'supported_signature_algorithms': (0x0403, 0x0804)},
        Enum_ExtensionType.application_layer_protocol_negotiation: {
            'protocol_name_list': (b'h2', b'http/1.1')},
        Enum_ExtensionType.padding: {'padding': bytes(5)},
        Enum_ExtensionType.compress_certificate: {'algorithms': (2, 1)},
        Enum_ExtensionType.session_ticket: {'ticket': bytes(range(16))},
        Enum_ExtensionType.pre_shared_key: {
            'identities': (PskIdentity(identity=b'ticket', obfuscated_ticket_age=0x01020304),),
            'binders': (bytes(range(32)),)},
        Enum_ExtensionType.supported_versions: {'versions': (0x0304, 0x0303)},
        Enum_ExtensionType.cookie: {'cookie': b'cookie'},
        Enum_ExtensionType.psk_key_exchange_modes: {'ke_modes': (1, 0)},
        Enum_ExtensionType.key_share: {
            'client_shares': (KeyShareEntry(group=0x001D, key_exchange=bytes(range(32))),)},
        Enum_ExtensionType.renegotiation_info: {'renegotiated_connection': bytes(12)},
        # These have no default to build from.
        Enum_ExtensionType.record_size_limit: {'record_size_limit': 0x4001},
        Enum_ExtensionType.encrypted_client_hello: {
            'cipher_suite': HpkeSymmetricCipherSuite(kdf_id=0x0001, aead_id=0x0001), 'config_id': 0x2A,
            'enc': bytes(32), 'payload': bytes(range(16))},
    }


def _dtls_only() -> 'frozenset[Any]':
    """The types the IANA registry marks DTLS-only (RFC 9146 section 10.2)."""
    from pcapkit.const.tls.extension_type import ExtensionType as Enum_ExtensionType
    return frozenset({Enum_ExtensionType.connection_id})


def _tls_client_hello(extensions: 'Any') -> 'Any':
    """A record carrying one ``ClientHello`` with ``extensions``: DTLS's if one
    of them is DTLS-only, TLS's otherwise."""
    from pcapkit.const.tls.content_type import ContentType as Enum_ContentType
    from pcapkit.const.tls.handshake_type import HandshakeType as Enum_HandshakeType
    from pcapkit.protocols.application.dtls.data import DTLSHandshake
    from pcapkit.protocols.application.dtls.protocol import DTLS
    from pcapkit.protocols.application.ssl.data import ClientHello, Handshake
    from pcapkit.protocols.application.tls.protocol import TLS

    msg_type = Enum_HandshakeType.client_hello
    codes = {extension[0] if isinstance(extension, tuple) else extension.type for extension in extensions}
    if codes & _dtls_only():
        hello = ClientHello(version=0xFEFD, random=bytes(32), session_id=b'', cookie=b'',
                            cipher_suites=(0x1301,), compression_methods=(0,), extensions=extensions)
        return DTLS.from_fields(content_type=Enum_ContentType.handshake, version=0xFEFD, content=(DTLSHandshake(
            msg_type=msg_type, length=0, body=hello, message_seq=0, fragment_offset=0, fragment_length=0,
            is_fragmented=False),))
    hello = ClientHello(version=0x0303, random=bytes(32), session_id=b'', cookie=None,
                        cipher_suites=(0x1301,), compression_methods=(0,), extensions=extensions)
    return TLS.from_fields(content_type=Enum_ContentType.handshake, version=0x0303,
                           content=(Handshake(msg_type=msg_type, length=0, body=hello),))


def _tls_extension_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    return _tls_client_hello(((code, dict(kwargs)),))


def _tls_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.application.dtls.protocol import DTLS
    from pcapkit.protocols.application.tls.protocol import TLS

    # NOTE: a DTLS record version's major octet is 0xFE (RFC 9147 section 4).
    return (DTLS if octets[1] == 0xFE else TLS)(octets, len(octets))


def _tls_extension_extract(parsed: 'Any') -> 'Any':
    return parsed.info.content[0].body.extensions


#: The families this module adds.
FAMILIES = (
    # No capture -- see the comment at the top of this module.
    generator.Family('tls-extension', _tls_extension_registry, _tls_extension_overrides,
                     _tls_extension_build, _tls_parse, _tls_extension_extract,
                     _tls_client_hello, capture=None, envelope=None),
)
