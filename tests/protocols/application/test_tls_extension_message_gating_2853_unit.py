# -*- coding: utf-8 -*-
"""``server_name``, ``supported_groups``, ``signature_algorithms``, ALPN and ``connection_id``
decode only in the messages their RFCs define (#2852, #2853).

An empty ``server_name`` in a ``ServerHello`` or ``EncryptedExtensions`` is the
``Empty`` record and builds back empty (RFC 6066 section 3); in a ``ClientHello``
it is refused, quietly, and kept raw. ``signature_algorithms`` also decodes in a
``CertificateRequest`` (RFC 9846 section 4.3), and ``connection_id`` in a DTLS hello
alone (RFC 9146 sections 3 and 10.2). The hello sweeps in
:file:`tests/protocols/application/test_tls_hello_extensions_2810_unit.py` cover the
TLS hello messages; these cases cover the rest.

"""
from __future__ import annotations

import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class
from tests.utilities._harness import capture

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): hand-picked round-trip cases, not a sweep.
__tier__ = 'ALL'


def _ext(code: int, data: bytes) -> bytes:
    return code.to_bytes(2, 'big') + len(data).to_bytes(2, 'big') + data


def _vec(data: bytes, width: int = 2) -> bytes:
    return len(data).to_bytes(width, 'big') + data


def _record(fragment: bytes) -> bytes:
    return b'\x16\x03\x03' + len(fragment).to_bytes(2, 'big') + fragment


def _handshake(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + len(body).to_bytes(3, 'big') + body


def _client_hello(*extensions: bytes) -> bytes:
    return _record(_handshake(1, b'\x03\x03' + bytes(range(32)) + b'\x00' + _vec(b'\x13\x01')
                              + _vec(b'\x00', 1) + _vec(b''.join(extensions))))


def _server_hello(*extensions: bytes) -> bytes:
    return _record(_handshake(2, b'\x03\x03' + bytes(range(32, 64)) + b'\x00' + b'\x13\x01' + b'\x00'
                              + _vec(b''.join(extensions))))


def _encrypted_extensions(*extensions: bytes) -> bytes:
    return _record(_handshake(8, _vec(b''.join(extensions))))


def _dtls_client_hello(*extensions: bytes) -> bytes:
    body = (b'\xfe\xfd' + bytes(32) + b'\x00' + b'\x00' + _vec(b'\x13\x01') + _vec(b'\x00', 1)
            + _vec(b''.join(extensions)))
    message = b'\x01' + len(body).to_bytes(3, 'big') + bytes(5) + len(body).to_bytes(3, 'big') + body
    return b'\x16\xfe\xfd' + bytes(2) + (1).to_bytes(6, 'big') + _vec(message)


#: ``supported_versions`` in a ``ClientHello``: TLS 1.3, TLS 1.2.
VERSIONS = _ext(43, _vec(b'\x03\x04\x03\x03', 1))
#: ``supported_groups``: secp256r1, the issue's reproduction.
GROUPS = _vec(b'\x00\x17')
#: ``signature_algorithms``: ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256.
SIGALGS = _vec(b'\x04\x03\x08\x04')


class EmptyServerNameTests(unittest.TestCase):
    """A server's ``server_name`` is empty, and a client's is not (RFC 6066 section 3, #2852)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_a_servers_empty_server_name_reads_and_builds_as_empty(self) -> None:
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.protocols.application.ssl.data import Empty
        from pcapkit.protocols.application.tls.protocol import TLS

        for name, wire in (('ServerHello', _server_hello(_ext(0, b''))),
                           ('EncryptedExtensions', _encrypted_extensions(_ext(0, b'')))):
            with self.subTest(message=name):
                parsed = TLS(wire, len(wire))
                ext, = parsed.info.content[0].body.extensions
                self.assertEqual((ext.type, ext.data), (ExtensionType.server_name, Empty()))
                rebuilt = TLS.from_data(parsed.info)
                self.assertEqual(bytes(rebuilt).hex(), wire.hex())
                self.assertEqual(rebuilt.info, parsed.info)
                made = object.__new__(TLS).make(content_type=ContentType.handshake, version=0x0303,
                                                content=parsed.info.content)
                self.assertEqual(bytes(made).hex(), wire.hex())

    def test_empty_builds_empty_octets(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.const.tls.handshake_type import HandshakeType
        from pcapkit.protocols.application.ssl.data import Empty, Extension
        from pcapkit.protocols.application.tls.protocol import TLS

        wire = _server_hello()
        proto = TLS(wire, len(wire))
        for msg_type in (HandshakeType.server_hello, HandshakeType.encrypted_extensions):
            for name, extension in (('from data', Extension(type=ExtensionType.server_name, data=Empty())),
                                    ('from kwargs', (ExtensionType.server_name, {}))):
                with self.subTest(message=msg_type.name, case=name):
                    made = proto._make_tls_extensions([extension], msg_type=msg_type)  # pylint: disable=protected-access
                    self.assertEqual(made.hex(), '00000000')

    def test_a_clients_empty_server_name_is_refused_quietly(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.const.tls.handshake_type import HandshakeType
        from pcapkit.protocols.application.ssl.data import SupportedVersionsClientHello
        from pcapkit.protocols.application.tls.protocol import TLS
        from pcapkit.utilities.exceptions import CaughtByCaller, ProtocolError
        from pcapkit.utilities.logging import logger

        wire = _client_hello(_ext(0, b''), VERSIONS)
        with capture(logger) as logs:
            parsed = TLS(wire, len(wire))
        sni, versions = parsed.info.content[0].body.extensions
        self.assertEqual((sni.type, sni.data), (ExtensionType.server_name, b''))
        self.assertIsInstance(versions.data, SupportedVersionsClientHello)
        self.assertEqual(logs.messages, [])
        self.assertEqual(bytes(TLS.from_data(parsed.info)).hex(), wire.hex())

        # The dispatcher's own block keeps the refusal quiet (#1845).
        with CaughtByCaller(ProtocolError), self.assertRaises(ProtocolError):
            parsed._read_ext_schema(ExtensionType.server_name, b'',  # pylint: disable=protected-access
                                    msg_type=HandshakeType.client_hello)

    def test_a_server_name_a_message_does_not_define_stays_raw(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.const.tls.handshake_type import HandshakeType
        from pcapkit.protocols.application.ssl.data import Cookie, Extension
        from pcapkit.protocols.application.tls.protocol import TLS
        from pcapkit.utilities.exceptions import ProtocolError
        from pcapkit.utilities.logging import logger

        wire = _server_hello()
        proto = TLS(wire, len(wire))
        names = _vec(b'\x00' + _vec(b'example.com'))
        for msg_type, data in ((HandshakeType.server_hello, names), (HandshakeType.encrypted_extensions, b'\x00'),
                               (HandshakeType.hello_retry_request, b''),
                               (HandshakeType.certificate_request, names)):
            with self.subTest(message=msg_type.name, data=data.hex()), capture(logger) as logs:
                ext, = proto._read_tls_extensions(_ext(0, data), msg_type=msg_type)  # pylint: disable=protected-access
                self.assertEqual(ext.data, data)
                self.assertEqual(logs.messages, [])
        for msg_type in (HandshakeType.hello_retry_request, HandshakeType.certificate_request):
            with self.subTest(make=msg_type.name), self.assertRaises(ProtocolError):
                proto._make_tls_extensions([(ExtensionType.server_name, {})], msg_type=msg_type)  # pylint: disable=protected-access
        with self.assertRaises(ProtocolError):
            proto._make_tls_extensions(  # pylint: disable=protected-access
                [Extension(type=ExtensionType.server_name, data=Cookie(cookie=b'x'))],
                msg_type=HandshakeType.server_hello)


class MessageGatingTests(unittest.TestCase):
    """Each extension decodes, and builds from keyword arguments, only where its RFC defines it (#2853)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _proto(self) -> 'Any':
        from pcapkit.protocols.application.tls.protocol import TLS

        wire = _client_hello()
        return TLS(wire, len(wire))

    def test_a_message_the_rfc_does_not_name_keeps_the_octets(self) -> None:
        """The issue's reproduction: a ``NamedGroupList`` in a ``Certificate`` is no list."""
        from pcapkit.const.tls.handshake_type import HandshakeType as HT
        from pcapkit.utilities.exceptions import ProtocolError

        proto = self._proto()
        for code, data, messages in (
                (10, GROUPS, (HT.server_hello, HT.hello_retry_request, HT.certificate, HT.certificate_request)),
                (16, _vec(_vec(b'h2', 1)), (HT.hello_retry_request, HT.certificate, HT.certificate_request)),
                (54, _vec(b'\xab', 1), (HT.hello_retry_request, HT.encrypted_extensions, HT.certificate)),
        ):
            for msg_type in messages:
                with self.subTest(code=code, message=msg_type.name):
                    ext, = proto._read_tls_extensions(_ext(code, data), msg_type=msg_type)  # pylint: disable=protected-access
                    self.assertEqual(ext.data, data)
                    with self.assertRaises(ProtocolError):
                        proto._make_tls_extensions([(code, {})], msg_type=msg_type)  # pylint: disable=protected-access

    def test_signature_algorithms_in_a_certificate_request_only_of_the_server_messages(self) -> None:
        """A TLS 1.3 ``CertificateRequest`` carries a ``SignatureSchemeList`` (RFC 9846 section 4.4.2)."""
        from pcapkit.const.tls.handshake_type import HandshakeType as HT
        from pcapkit.protocols.application.ssl.data import SignatureSchemeList
        from pcapkit.utilities.exceptions import ProtocolError

        proto = self._proto()
        kwargs = {'supported_signature_algorithms': (0x0403, 0x0804)}
        ext, = proto._read_tls_extensions(_ext(13, SIGALGS), msg_type=HT.certificate_request)  # pylint: disable=protected-access
        self.assertEqual(ext.data, SignatureSchemeList(supported_signature_algorithms=(0x0403, 0x0804)))
        for extension in (ext, (13, kwargs)):
            with self.subTest(case=type(extension).__name__):
                made = proto._make_tls_extensions([extension], msg_type=HT.certificate_request)  # pylint: disable=protected-access
                self.assertEqual(made.hex(), _ext(13, SIGALGS).hex())
        for msg_type in (HT.server_hello, HT.encrypted_extensions, HT.certificate):
            with self.subTest(message=msg_type.name):
                ext, = proto._read_tls_extensions(_ext(13, SIGALGS), msg_type=msg_type)  # pylint: disable=protected-access
                self.assertEqual(ext.data, SIGALGS)
                with self.assertRaises(ProtocolError):
                    proto._make_tls_extensions([(13, kwargs)], msg_type=msg_type)  # pylint: disable=protected-access

    def test_connection_id_in_dtls_hellos_only(self) -> None:
        """RFC 9146 section 3 sends it in a DTLS ``ClientHello`` and ``ServerHello``, and RFC 9147
        section 9.1 in DTLS 1.3's."""
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.const.tls.handshake_type import HandshakeType
        from pcapkit.protocols.application.dtls.protocol import DTLS
        from pcapkit.protocols.application.ssl.data import ConnectionId
        from pcapkit.utilities.exceptions import ProtocolError

        cid = _ext(54, _vec(b'\x01\x02', 1))
        wire = _dtls_client_hello(cid)
        parsed = DTLS(wire, len(wire))
        ext, = parsed.info.content[0].body.extensions
        self.assertEqual((ext.type, ext.data), (ExtensionType.connection_id, ConnectionId(cid=b'\x01\x02')))
        self.assertEqual(bytes(DTLS.from_data(parsed.info)).hex(), wire.hex())

        for msg_type in (HandshakeType.server_hello, HandshakeType.encrypted_extensions):
            with self.subTest(message=msg_type.name):
                ext, = parsed._read_tls_extensions(cid, msg_type=msg_type)  # pylint: disable=protected-access
                if msg_type == HandshakeType.server_hello:
                    self.assertEqual(ext.data, ConnectionId(cid=b'\x01\x02'))
                    self.assertEqual(parsed._make_tls_extensions(  # pylint: disable=protected-access
                        [(54, {'cid': b'\x01\x02'})], msg_type=msg_type).hex(), cid.hex())
                else:
                    self.assertEqual(ext.data, cid[4:])
                    with self.assertRaises(ProtocolError):
                        parsed._make_tls_extensions([(54, {'cid': b'\x01\x02'})], msg_type=msg_type)  # pylint: disable=protected-access

    def test_connection_id_in_a_tls_record_keeps_the_octets(self) -> None:
        """A DTLS-only type has no structure in a TLS record (RFC 9146 section 10.2)."""
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.const.tls.handshake_type import HandshakeType
        from pcapkit.protocols.application.ssl.data import ConnectionId, Extension
        from pcapkit.protocols.application.tls.protocol import TLS
        from pcapkit.utilities.exceptions import ProtocolError
        from pcapkit.utilities.logging import logger

        cid = _ext(54, _vec(b'\x01\x02', 1))
        for name, wire in (('ClientHello', _client_hello(cid)), ('ServerHello', _server_hello(cid))):
            with self.subTest(message=name), capture(logger) as logs:
                parsed = TLS(wire, len(wire))
                ext, = parsed.info.content[0].body.extensions
                self.assertEqual((ext.type, ext.data), (ExtensionType.connection_id, cid[4:]))
                self.assertEqual(bytes(TLS.from_data(parsed.info)).hex(), wire.hex())
                self.assertEqual(logs.messages, [])
        for msg_type in (HandshakeType.client_hello, HandshakeType.server_hello):
            with self.subTest(make=msg_type.name):
                with self.assertRaises(ProtocolError):
                    parsed._make_tls_extensions([(54, {'cid': b'\x01\x02'})], msg_type=msg_type)  # pylint: disable=protected-access
                # NOTE: a decoded body decides the structure itself, as for every gated pair.
                made = parsed._make_tls_extensions(  # pylint: disable=protected-access
                    [Extension(type=ExtensionType.connection_id, data=ConnectionId(cid=b'\x01\x02'))],
                    msg_type=msg_type)
                self.assertEqual(made.hex(), cid.hex())


if __name__ == '__main__':
    unittest.main()
