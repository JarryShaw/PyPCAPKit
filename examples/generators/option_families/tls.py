# -*- coding: utf-8 -*-
"""The ``tls-extension`` family: TLS handshake extensions.

Each case is one extension in a ``ClientHello``, built from keyword arguments
by the extension's ``_make_ext_*``. No capture is written: the ``tcp``
envelope is addressed to port 80, which dispatches to HTTP rather than TLS.

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
    from pcapkit.protocols.application.tls import TLS
    return TLS.__extension__


def _tls_extension_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.tls.extension_type import ExtensionType as Enum_ExtensionType
    from pcapkit.protocols.data.application.tls import KeyShareEntry, ServerName
    return {
        # Each of these defaults to an empty list.
        Enum_ExtensionType.server_name: {
            'server_name_list': (ServerName(name_type=0, name=b'example.com'),)},
        Enum_ExtensionType.supported_groups: {'named_group_list': (0x001D, 0x0017)},
        Enum_ExtensionType.signature_algorithms: {'supported_signature_algorithms': (0x0403, 0x0804)},
        Enum_ExtensionType.application_layer_protocol_negotiation: {
            'protocol_name_list': (b'h2', b'http/1.1')},
        Enum_ExtensionType.supported_versions: {'versions': (0x0304, 0x0303)},
        Enum_ExtensionType.key_share: {
            'client_shares': (KeyShareEntry(group=0x001D, key_exchange=bytes(range(32))),)},
    }


def _tls_client_hello(extensions: 'Any') -> 'Any':
    """A TLS record carrying one ``ClientHello`` with ``extensions``."""
    from pcapkit.const.tls.content_type import ContentType as Enum_ContentType
    from pcapkit.const.tls.handshake_type import HandshakeType as Enum_HandshakeType
    from pcapkit.protocols.application.tls import TLS
    from pcapkit.protocols.data.application.tls import ClientHello, Handshake

    hello = ClientHello(version=0x0303, random=bytes(32), session_id=b'', cookie=None,
                        cipher_suites=(0x1301,), compression_methods=(0,), extensions=extensions)
    return TLS(content_type=Enum_ContentType.handshake, version=0x0303,
               content=(Handshake(msg_type=Enum_HandshakeType.client_hello, length=0, body=hello),))


def _tls_extension_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    return _tls_client_hello(((code, dict(kwargs)),))


def _tls_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.application.tls import TLS
    return TLS(octets, len(octets))


def _tls_extension_extract(parsed: 'Any') -> 'Any':
    return parsed.info.content[0].body.extensions


#: The families this module adds.
FAMILIES = (
    # No capture -- see the comment at the top of this module.
    generator.Family('tls-extension', _tls_extension_registry, _tls_extension_overrides,
                     _tls_extension_build, _tls_parse, _tls_extension_extract,
                     _tls_client_hello, capture=None, envelope=None),
)
