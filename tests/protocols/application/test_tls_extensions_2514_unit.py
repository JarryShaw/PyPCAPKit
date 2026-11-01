# -*- coding: utf-8 -*-
"""TLS/DTLS handshake extensions decode, and rebuild byte for byte (#2514).

``SSL.__extension__`` registers a decoder for ``server_name``,
``supported_groups``, ``signature_algorithms``, ALPN, ``supported_versions``
and ``key_share``; every other extension keeps its raw octets. Each case is
checked against the field values of its specification, and both ways round:
parse then ``from_data``, and ``make`` from the parsed content.

"""
from __future__ import annotations

import unittest
import warnings

from tests._support import reimport_once_per_class

#: ``random`` of a ``HelloRetryRequest`` (RFC 9846 section 4.2.3).
HRR_RANDOM = bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c')


def _ext(code: int, data: bytes) -> bytes:
    return code.to_bytes(2, 'big') + len(data).to_bytes(2, 'big') + data


def _vec(data: bytes, width: int = 2) -> bytes:
    return len(data).to_bytes(width, 'big') + data


def _record(fragment: bytes, content_type: int = 22) -> bytes:
    return bytes([content_type]) + b'\x03\x03' + len(fragment).to_bytes(2, 'big') + fragment


def _handshake(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + len(body).to_bytes(3, 'big') + body


def _client_hello(*extensions: bytes) -> bytes:
    return _record(_handshake(1, b'\x03\x03' + bytes(range(32)) + b'\x00' + _vec(b'\x13\x01')
                              + _vec(b'\x00', 1) + _vec(b''.join(extensions))))


def _server_hello(*extensions: bytes, random: bytes = bytes(range(32, 64))) -> bytes:
    return _record(_handshake(2, b'\x03\x03' + random + b'\x00' + b'\x13\x01' + b'\x00'
                              + _vec(b''.join(extensions))))


def _encrypted_extensions(*extensions: bytes) -> bytes:
    return _record(_handshake(8, _vec(b''.join(extensions))))


#: ``server_name`` with one ``host_name`` (RFC 6066 section 3).
SNI = _ext(0, _vec(b'\x00' + _vec(b'example.com')))
#: ``supported_groups``: x25519, secp256r1 (RFC 9846 section 4.3.7).
GROUPS = _ext(10, _vec(b'\x00\x1d\x00\x17'))
#: ``signature_algorithms``: ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256.
SIGALGS = _ext(13, _vec(b'\x04\x03\x08\x04'))
#: ALPN: ``h2``, ``http/1.1`` (RFC 7301 section 3.1).
ALPN = _ext(16, _vec(_vec(b'h2', 1) + _vec(b'http/1.1', 1)))
#: ``supported_versions`` in a ``ClientHello``: TLS 1.3, TLS 1.2.
VERSIONS = _ext(43, _vec(b'\x03\x04\x03\x03', 1))
#: ``key_share`` in a ``ClientHello``: one x25519 share.
KEY_SHARE = _ext(51, _vec(b'\x00\x1d' + _vec(bytes(range(32)))))


class ExtensionDecodingTests(unittest.TestCase):
    """Each registered extension decodes to its specification's fields."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _extensions(self, wire: bytes) -> 'tuple':
        from pcapkit.protocols.application.tls import TLS

        parsed = TLS(wire, len(wire))
        self.assertEqual(bytes(TLS.from_data(parsed.info)).hex(), wire.hex())
        maker = object.__new__(TLS)
        made = maker.make(content_type=parsed.info.content_type, version=parsed.info.version,
                          content=parsed.info.content)
        self.assertEqual(bytes(made).hex(), wire.hex())
        return parsed.info.content[0].body.extensions

    def test_client_hello_extensions(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.protocols.data.application.tls import (KeyShareClientHello, KeyShareEntry,
                                                            NamedGroupList, ProtocolNameList,
                                                            ServerName, ServerNameList,
                                                            SignatureSchemeList,
                                                            SupportedVersionsClientHello)

        sni, groups, sigalgs, alpn, versions, key_share = self._extensions(
            _client_hello(SNI, GROUPS, SIGALGS, ALPN, VERSIONS, KEY_SHARE))
        self.assertEqual([ext.type for ext in (sni, groups, sigalgs, alpn, versions, key_share)], [
            ExtensionType.server_name, ExtensionType.supported_groups, ExtensionType.signature_algorithms,
            ExtensionType.application_layer_protocol_negotiation, ExtensionType.supported_versions,
            ExtensionType.key_share])
        self.assertEqual(sni.data, ServerNameList(server_name_list=(ServerName(name_type=0, name=b'example.com'),)))
        self.assertEqual(groups.data, NamedGroupList(named_group_list=(0x001D, 0x0017)))
        self.assertEqual(sigalgs.data, SignatureSchemeList(supported_signature_algorithms=(0x0403, 0x0804)))
        self.assertEqual(alpn.data, ProtocolNameList(protocol_name_list=(b'h2', b'http/1.1')))
        self.assertEqual(versions.data, SupportedVersionsClientHello(versions=(0x0304, 0x0303)))
        self.assertEqual(key_share.data, KeyShareClientHello(
            client_shares=(KeyShareEntry(group=0x001D, key_exchange=bytes(range(32))),)))
        for ext, model in zip((sni, groups, sigalgs, alpn, versions, key_share),
                              (ServerNameList, NamedGroupList, SignatureSchemeList, ProtocolNameList,
                               SupportedVersionsClientHello, KeyShareClientHello)):
            self.assertIsInstance(ext.data, model)

    def test_empty_key_share_in_a_client_hello(self) -> None:
        """A client asking for a ``HelloRetryRequest`` sends no shares (RFC 9846 section 4.3.8)."""
        from pcapkit.protocols.data.application.tls import KeyShareClientHello

        key_share, = self._extensions(_client_hello(_ext(51, _vec(b''))))
        self.assertEqual(key_share.data, KeyShareClientHello(client_shares=()))

    def test_server_hello_extensions(self) -> None:
        from pcapkit.protocols.data.application.tls import (KeyShareEntry, KeyShareServerHello,
                                                            ProtocolNameList,
                                                            SupportedVersionsServerHello)

        versions, key_share, sni, alpn = self._extensions(_server_hello(
            _ext(43, b'\x03\x04'), _ext(51, b'\x00\x1d' + _vec(b'\xaa' * 32)), _ext(0, b''),
            _ext(16, _vec(_vec(b'h2', 1)))))
        self.assertEqual(versions.data, SupportedVersionsServerHello(selected_version=0x0304))
        self.assertEqual(key_share.data, KeyShareServerHello(
            server_share=KeyShareEntry(group=0x001D, key_exchange=b'\xaa' * 32)))
        self.assertEqual(sni.data, b'')
        self.assertEqual(alpn.data, ProtocolNameList(protocol_name_list=(b'h2',)))

    def test_hello_retry_request_extensions(self) -> None:
        """A ``ServerHello`` carrying the ``HelloRetryRequest`` random takes that message's shapes."""
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.protocols.data.application.tls import (KeyShareHelloRetryRequest,
                                                            SupportedVersionsServerHello)

        wire = _server_hello(_ext(43, b'\x03\x04'), _ext(51, b'\x00\x17'), _ext(44, _vec(b'cookie')),
                             random=HRR_RANDOM)
        versions, key_share, cookie = self._extensions(wire)
        self.assertEqual(versions.data, SupportedVersionsServerHello(selected_version=0x0304))
        self.assertEqual(key_share.data, KeyShareHelloRetryRequest(selected_group=0x0017))
        self.assertEqual(cookie.data, _vec(b'cookie'))
        self.assertEqual(TLS(wire, len(wire)).alias, 'TLS 1.3')

        # The same two octets in a plain ServerHello are no KeyShareEntry.
        key_share, = self._extensions(_server_hello(_ext(51, b'\x00\x17')))
        self.assertEqual(key_share.data, b'\x00\x17')

    def test_encrypted_extensions(self) -> None:
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.protocols.data.application.tls import (EncryptedExtensions, NamedGroupList,
                                                            ProtocolNameList)

        wire = _encrypted_extensions(_ext(0, b''), GROUPS, _ext(16, _vec(_vec(b'h2', 1))))
        body = TLS(wire, len(wire)).info.content[0].body
        self.assertIsInstance(body, EncryptedExtensions)
        sni, groups, alpn = self._extensions(wire)
        self.assertEqual(sni.data, b'')
        self.assertEqual(groups.data, NamedGroupList(named_group_list=(0x001D, 0x0017)))
        self.assertEqual(alpn.data, ProtocolNameList(protocol_name_list=(b'h2',)))

        empty = _encrypted_extensions()
        self.assertEqual(self._extensions(empty), ())

    def test_dtls_client_hello_extensions(self) -> None:
        """DTLS shares the registry, so its ``ClientHello`` decodes the same."""
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.protocols.data.application.tls import SupportedVersionsClientHello

        body = (b'\xfe\xfd' + bytes(32) + b'\x00' + b'\x00' + _vec(b'\x13\x01') + _vec(b'\x00', 1)
                + _vec(_ext(43, _vec(b'\xfe\xfc', 1)) + ALPN))
        message = (b'\x01' + len(body).to_bytes(3, 'big') + bytes(2) + bytes(3)
                   + len(body).to_bytes(3, 'big') + body)
        wire = b'\x16\xfe\xfd' + bytes(2) + (1).to_bytes(6, 'big') + _vec(message)
        parsed = DTLS(wire, len(wire))
        self.assertEqual(parsed.alias, 'DTLS 1.3')
        versions, alpn = parsed.info.content[0].body.extensions
        self.assertEqual(versions.data, SupportedVersionsClientHello(versions=(0xFEFC,)))
        self.assertEqual(alpn.data.protocol_name_list, (b'h2', b'http/1.1'))
        self.assertEqual(bytes(DTLS.from_data(parsed.info)).hex(), wire.hex())


class UnknownExtensionTests(unittest.TestCase):
    """An extension with no decoder keeps its octets, under its registry member."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_unregistered_types_stay_raw(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.protocols.application.tls import TLS

        cases = (
            (21, bytes(7), 'padding'),
            (0x0A0A, b'', 'Reserved_2570'),           # GREASE (RFC 8701)
            (0x1234, b'\x01\x02', 'Unassigned'),
            (0xFF01, b'\x00', 'renegotiation_info'),
            (0xFF05, b'\xde\xad', 'Reserved_for_Private_Use'),
        )
        wire = _client_hello(*(_ext(code, data) for code, data, _ in cases))
        extensions = TLS(wire, len(wire)).info.content[0].body.extensions
        for ext, (code, data, name) in zip(extensions, cases):
            with self.subTest(code=code):
                self.assertIsInstance(ext.type, ExtensionType)
                self.assertEqual((int(ext.type), ext.type.name), (code, name))
                self.assertEqual(ext.data, data)
        self.assertEqual(bytes(TLS.from_data(TLS(wire, len(wire)).info)).hex(), wire.hex())


class MalformedExtensionTests(unittest.TestCase):
    """A body its decoder cannot read exactly keeps its octets; broken framing still raises."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_malformed_bodies_stay_raw_and_rebuild(self) -> None:
        """The rest of the list still decodes, here a ``supported_versions`` after it."""
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.protocols.data.application.tls import (SupportedVersionsClientHello,
                                                            SupportedVersionsServerHello)

        cases = {
            'server_name list length too long': (_client_hello, _ext(0, b'\x00\x10\x00\x00\x01a')),
            'server_name list length too short': (_client_hello, _ext(0, b'\x00\x03\x00\x00\x01ab')),
            'server_name of an undefined name type': (_client_hello, _ext(0, _vec(b'\x01' + _vec(b'x')))),
            'server_name name past its list': (_client_hello, _ext(0, _vec(b'\x00\x00\x05abc'))),
            'supported_groups odd length': (_client_hello, _ext(10, _vec(b'\x00\x1d\x00'))),
            'supported_groups trailing octets': (_client_hello, _ext(10, _vec(b'\x00\x1d') + b'\x00')),
            'supported_groups no length prefix': (_client_hello, _ext(10, b'\x00')),
            'signature_algorithms odd length': (_client_hello, _ext(13, _vec(b'\x04'))),
            'signature_algorithms list length mismatch': (_client_hello, _ext(13, b'\xab\xcd')),
            'alpn name past its list': (_client_hello, _ext(16, _vec(b'\x05h2'))),
            'alpn list length mismatch': (_client_hello, _ext(16, b'\x00\x09\x02h2')),
            'supported_versions odd length': (_client_hello, _ext(43, _vec(b'\x03\x04\x03', 1))),
            'supported_versions length mismatch': (_client_hello, _ext(43, b'\x04\x03\x04')),
            'supported_versions selected_version too long': (_server_hello, _ext(43, b'\x03\x04\x00')),
            'key_share entry past its list': (_client_hello, _ext(51, _vec(b'\x00\x1d\x00\x20\x01'))),
            'key_share server_share trailing octets': (_server_hello, _ext(51, b'\x00\x1d\x00\x01\xaa\x00')),
            'key_share selected_group too long': (
                lambda *exts: _server_hello(*exts, random=HRR_RANDOM), _ext(51, b'\x00\x17\x00')),
        }
        for name, (hello, extension) in cases.items():
            with self.subTest(case=name):
                client = hello is _client_hello
                wire = hello(extension, VERSIONS if client else _ext(43, b'\x03\x04'))
                parsed = TLS(wire, len(wire))
                ext, versions = parsed.info.content[0].body.extensions
                self.assertEqual(ext.data, extension[4:])
                self.assertIsInstance(versions.data, SupportedVersionsClientHello if client
                                      else SupportedVersionsServerHello)
                self.assertEqual(bytes(TLS.from_data(parsed.info)).hex(), wire.hex())

    def test_a_structure_the_message_does_not_have_stays_raw(self) -> None:
        from pcapkit.protocols.application.tls import TLS

        for extension in (_ext(43, b'\x03\x04'), _ext(51, b'\x00\x17')):
            with self.subTest(extension=extension.hex()):
                wire = _encrypted_extensions(extension)
                parsed = TLS(wire, len(wire))
                ext, = parsed.info.content[0].body.extensions
                self.assertEqual(ext.data, extension[4:])
                self.assertEqual(bytes(TLS.from_data(parsed.info)).hex(), wire.hex())

    def test_a_malformed_extension_leaves_version_detection_alone(self) -> None:
        from pcapkit.protocols.application.tls import TLS

        wire = _client_hello(_ext(16, b'\x00\x09\x02h2'), VERSIONS)
        parsed = TLS(wire, len(wire))
        self.assertEqual(parsed.alias, 'TLS 1.3')
        alpn, versions = parsed.info.content[0].body.extensions
        self.assertEqual(alpn.data, b'\x00\x09\x02h2')
        self.assertEqual(versions.data.versions, (0x0304, 0x0303))

    def test_broken_framing_raises(self) -> None:
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.utilities.exceptions import ProtocolError

        for name, wire in {
                'extension past its list': _client_hello(b'\x00\x0a\x00\xff'),
                'encrypted_extensions list length mismatch': _record(_handshake(8, b'\x00\x05' + GROUPS)),
                'encrypted_extensions without its length': _record(_handshake(8, b'\x00')),
        }.items():
            with self.subTest(case=name), self.assertRaises(ProtocolError):
                TLS(wire, len(wire))


class ExtensionConstructionTests(unittest.TestCase):
    """``make`` builds an extension from a data model, raw octets or keyword arguments."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _hello(extensions: 'tuple', *, random: bytes = bytes(range(32)), server: bool = False) -> bytes:
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.const.tls.handshake_type import HandshakeType
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.protocols.data.application.tls import ClientHello, Handshake, ServerHello

        if server:
            body = ServerHello(version=0x0303, random=random, session_id=b'', cipher_suite=0x1301,
                               compression_method=0, extensions=extensions)  # type: object
            msg_type = HandshakeType.server_hello
        else:
            body = ClientHello(version=0x0303, random=random, session_id=b'', cookie=None,
                               cipher_suites=(0x1301,), compression_methods=(0,), extensions=extensions)
            msg_type = HandshakeType.client_hello
        maker = object.__new__(TLS)
        return bytes(maker.make(content_type=ContentType.handshake, version=0x0303,
                                content=(Handshake(msg_type=msg_type, length=0, body=body),)))

    def test_client_hello_from_keyword_arguments(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.protocols.data.application.tls import KeyShareEntry, ServerName

        made = self._hello((
            (ExtensionType.server_name, {'server_name_list': (ServerName(name_type=0, name=b'example.com'),)}),
            (ExtensionType.supported_groups, {'named_group_list': (0x001D, 0x0017)}),
            (13, {'supported_signature_algorithms': (0x0403, 0x0804)}),
            (ExtensionType.application_layer_protocol_negotiation, {'protocol_name_list': (b'h2', b'http/1.1')}),
            (ExtensionType.supported_versions, {'versions': (0x0304, 0x0303)}),
            (ExtensionType.key_share, {'client_shares': (KeyShareEntry(group=0x001D, key_exchange=bytes(range(32))),)}),
            (ExtensionType.padding, {}),
        ))
        self.assertEqual(made.hex(), _client_hello(SNI, GROUPS, SIGALGS, ALPN, VERSIONS, KEY_SHARE,
                                                   _ext(21, b'')).hex())

    def test_server_and_retry_hellos_from_keyword_arguments(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.protocols.data.application.tls import KeyShareEntry

        share = KeyShareEntry(group=0x001D, key_exchange=b'\xaa')
        made = self._hello(((ExtensionType.supported_versions, {'selected_version': 0x0304}),
                            (ExtensionType.key_share, {'server_share': share})),
                           random=bytes(range(32, 64)), server=True)
        self.assertEqual(made.hex(), _server_hello(_ext(43, b'\x03\x04'), _ext(51, b'\x00\x1d\x00\x01\xaa')).hex())

        made = self._hello(((ExtensionType.supported_versions, {'selected_version': 0x0304}),
                            (ExtensionType.key_share, {'selected_group': 0x0017})),
                           random=HRR_RANDOM, server=True)
        self.assertEqual(made.hex(), _server_hello(_ext(43, b'\x03\x04'), _ext(51, b'\x00\x17'),
                                                   random=HRR_RANDOM).hex())

    def test_raw_octets_are_written_as_they_are(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.protocols.data.application.tls import Extension

        made = self._hello((Extension(type=ExtensionType.supported_groups, data=b'\xab\xcd'),))
        self.assertEqual(made.hex(), _client_hello(_ext(10, b'\xab\xcd')).hex())

    def test_a_structure_with_nothing_to_build_from_raises(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.protocols.data.application.tls import Extension, NamedGroupList
        from pcapkit.utilities.exceptions import ProtocolError

        for name, extensions, server in (
                ('selected_version missing', ((ExtensionType.supported_versions, {}),), True),
                ('server_share missing', ((ExtensionType.key_share, {}),), True),
                ('a model under a type with no constructor', (
                    Extension(type=ExtensionType.padding, data=NamedGroupList(named_group_list=())),), False),
        ):
            with self.subTest(case=name), self.assertRaises(ProtocolError):
                self._hello(extensions, server=server)


class ExtensionRegistryTests(unittest.TestCase):
    """``register_tls_extension`` writes ``SSL.__extension__``, which TLS and DTLS read."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_callable_pair_overrides_and_the_shipped_entry_restores(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.const.tls.handshake_type import HandshakeType
        from pcapkit.foundation.registry.protocols import register_tls_extension
        from pcapkit.protocols.application.ssl import SSL
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.protocols.data.application.tls import ProtocolNameList
        from pcapkit.utilities.warnings import RegistryWarning

        calls = []

        def parser(ext_type: object, data: bytes, *, msg_type: object) -> object:
            calls.append(('read', ext_type, msg_type))
            return ProtocolNameList(protocol_name_list=(data,))

        def constructor(ext_type: object, data: object = None, *, msg_type: object,
                        **kwargs: object) -> bytes:  # pylint: disable=unused-argument
            calls.append(('make', ext_type, msg_type))
            return data.protocol_name_list[0]  # type: ignore[attr-defined]

        shipped = dict(SSL.__extension__)
        try:
            with self.assertWarns(RegistryWarning):
                register_tls_extension(ExtensionType.supported_groups, (parser, constructor))
            wire = _client_hello(GROUPS)
            parsed = TLS(wire, len(wire))
            self.assertEqual(parsed.info.content[0].body.extensions[0].data,
                             ProtocolNameList(protocol_name_list=(GROUPS[4:],)))
            self.assertEqual(bytes(TLS.from_data(parsed.info)).hex(), wire.hex())
            for kind in ('read', 'make'):
                self.assertIn((kind, ExtensionType.supported_groups, HandshakeType.client_hello), calls)

            with warnings.catch_warnings():
                warnings.simplefilter('ignore', RegistryWarning)
                register_tls_extension(ExtensionType.supported_groups, 'supported_groups')
            self.assertEqual(dict(SSL.__extension__), shipped)
            self.assertIs(TLS.__extension__, SSL.__extension__)
        finally:
            SSL.__extension__.clear()
            SSL.__extension__.update(shipped)

    def test_a_type_with_no_shipped_entry(self) -> None:
        """``padding`` (RFC 7685 section 3) has no decoder until one is registered, silently."""
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.const.tls.handshake_type import HandshakeType
        from pcapkit.corekit.infoclass import info_final
        from pcapkit.foundation.registry.protocols import register_tls_extension
        from pcapkit.protocols.application.ssl import SSL
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.protocols.data.application.tls import ExtensionData
        from pcapkit.utilities.exceptions import ProtocolError

        @info_final
        class Padding(ExtensionData):
            """``extension_data`` of ``padding``: zero octets, counted."""

            length: 'int'

        def parser(ext_type: object, data: bytes, *, msg_type: object) -> object:  # pylint: disable=unused-argument
            if data.strip(b'\x00'):
                raise ProtocolError('padding: non-zero octet')
            return Padding(length=len(data))

        def constructor(ext_type: object, data: object = None, *, msg_type: object,
                        length: int = 0, **kwargs: object) -> bytes:  # pylint: disable=unused-argument
            self.assertEqual(msg_type, HandshakeType.client_hello)
            return bytes(data.length if data is not None else length)  # type: ignore[attr-defined]

        wire = _client_hello(_ext(21, bytes(5)), _ext(21, b'\x00\x01'), VERSIONS)
        self.assertNotIn(ExtensionType.padding, SSL.__extension__)
        shipped = dict(SSL.__extension__)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('error')
                register_tls_extension(ExtensionType.padding, (parser, constructor))
            parsed = TLS(wire, len(wire))
            padding, rejected, versions = parsed.info.content[0].body.extensions
            self.assertEqual(padding.data, Padding(length=5))
            self.assertEqual(rejected.data, b'\x00\x01')
            self.assertEqual(versions.data.versions, (0x0304, 0x0303))
            self.assertEqual(bytes(TLS.from_data(parsed.info)).hex(), wire.hex())
            self.assertEqual(ExtensionConstructionTests._hello(((ExtensionType.padding, {'length': 3}),)).hex(),
                             _client_hello(_ext(21, bytes(3))).hex())
        finally:
            SSL.__extension__.clear()
            SSL.__extension__.update(shipped)
        padding, _, _ = TLS(wire, len(wire)).info.content[0].body.extensions
        self.assertEqual(padding.data, bytes(5))

    def test_handing_back_the_shipped_entry_is_a_silent_no_op(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.foundation.registry.protocols import register_tls_extension
        from pcapkit.protocols.application.ssl import SSL

        shipped = dict(SSL.__extension__)
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            register_tls_extension(ExtensionType.key_share, 'key_share')
        self.assertEqual(dict(SSL.__extension__), shipped)

    def test_bad_registrations_change_nothing(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.const.tls.handshake_type import HandshakeType
        from pcapkit.foundation.registry.protocols import register_tls_extension
        from pcapkit.protocols.application.ssl import SSL
        from pcapkit.utilities.exceptions import RegistryError

        shipped = dict(SSL.__extension__)
        for code, meth, pattern in (
                (10, 'supported_groups', '^SSL: code must be '),
                (HandshakeType.client_hello, 'supported_groups', '^SSL: code must be '),
                (ExtensionType.padding, 'no_such_parser', 'TLS extension parser'),
        ):
            with self.subTest(code=code, meth=meth), self.assertRaisesRegex(RegistryError, pattern):
                register_tls_extension(code, meth)  # type: ignore[arg-type]
        self.assertEqual(dict(SSL.__extension__), shipped)


class ExtensionTypeRegistryTests(unittest.TestCase):
    """``ExtensionType``, as its crawler renders IANA's registry."""

    def test_names_and_ranges(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType

        for value, name in ((0, 'server_name'), (10, 'supported_groups'), (35, 'session_ticket'),
                            (36, 'TLMSP'), (40, 'Reserved_40'), (53, 'connection_id_deprecated'),
                            (54, 'connection_id'), (0x0A0A, 'Reserved_2570'),
                            (0xFF00, 'Reserved_for_Private_Use'), (0xFF01, 'renegotiation_info'),
                            (63, 'Unassigned'), (0xFFFF, 'Reserved_for_Private_Use')):
            with self.subTest(value=value):
                self.assertEqual(ExtensionType(value).name, name)
        with self.assertRaises(ValueError):
            ExtensionType(0x10000)

    def test_crawler_cleans_the_parentheticals(self) -> None:
        from pcapkit.vendor.tls.extension_type import ExtensionType

        crawler = object.__new__(ExtensionType)
        for raw, name in (('supported_groups (renamed from "elliptic_curves")', 'supported_groups'),
                          ('session_ticket (renamed from "SessionTicket TLS")', 'session_ticket'),
                          ('connection_id (deprecated)', 'connection_id_deprecated'),
                          ('TLMSP', 'TLMSP')):
            with self.subTest(raw=raw):
                self.assertEqual(crawler.clean_name(raw), name)


if __name__ == '__main__':
    unittest.main()
