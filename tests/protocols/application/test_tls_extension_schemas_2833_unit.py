# -*- coding: utf-8 -*-
"""Every TLS extension decodes and builds through its own Schema class (#2833).

:class:`~pcapkit.protocols.application.ssl.schema.Extension` registers a concrete
schema for each type ``SSL.__extension__`` decodes; the dispatcher unpacks the
``extension_data`` by it, refuses one its structure does not tile, and packs
what a constructor makes. ``register_tls_extension`` takes a ``schema``.

"""
from __future__ import annotations

import unittest
import warnings

from tests._support import reimport_once_per_class
from tests.utilities._harness import capture

#: Test tier (#1958): hand-picked round-trip cases, not a sweep.
__tier__ = 'ALL'


def _ext(code: int, data: bytes) -> bytes:
    return code.to_bytes(2, 'big') + len(data).to_bytes(2, 'big') + data


def _client_hello(*extensions: bytes) -> bytes:
    body = b'\x03\x03' + bytes(32) + b'\x00' + b'\x00\x02\x13\x01' + b'\x01\x00'
    exts = b''.join(extensions)
    body += len(exts).to_bytes(2, 'big') + exts
    handshake = b'\x01' + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x03' + len(handshake).to_bytes(2, 'big') + handshake


class ExtensionSchemaTests(unittest.TestCase):
    """The schema registry, the dispatcher's refusals, and the ``schema`` registrar argument."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_every_decoded_type_has_a_concrete_schema(self) -> None:
        from pcapkit.protocols.application.ssl.protocol import SSL
        from pcapkit.protocols.application.ssl.schema import Extension, UnknownExtension
        from pcapkit.protocols.schema import Schema

        self.assertTrue(SSL.__extension__)
        for code in SSL.__extension__:
            with self.subTest(code=code):
                layout = Extension.registry[code]
                self.assertTrue(issubclass(layout, Extension))
                self.assertIsNot(layout, UnknownExtension)
                for name in layout.__fields__:
                    self.assertNotIn(name, Schema.__dict__)
        self.assertIs(Extension.registry[0x0A0A], UnknownExtension)  # GREASE (RFC 8701)

    def test_a_body_its_structure_does_not_tile_is_refused_quietly(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.const.tls.handshake_type import HandshakeType
        from pcapkit.protocols.application.tls.protocol import TLS
        from pcapkit.utilities.exceptions import CaughtByCaller, ProtocolError
        from pcapkit.utilities.logging import logger

        wire = _client_hello()
        proto = TLS(wire, len(wire))
        share = b'\x00\x1d\x00\x01\x11'
        for name, code, msg_type, data in (
                ('octets past a nested vector', ExtensionType.key_share, HandshakeType.client_hello,
                 len(share).to_bytes(2, 'big') + share + b'\x00'),
                ('a nested vector past its own', ExtensionType.status_request, HandshakeType.client_hello,
                 b'\x01\x00\x08\x00\x02ab\x00\x00'),
                ('octets past the structure', ExtensionType.record_size_limit, HandshakeType.client_hello,
                 b'\x40\x00\x00'),
                ('octets in an empty structure', ExtensionType.extended_main_secret, HandshakeType.server_hello,
                 b'\x00'),
                ('a list no whole number of codes fills', ExtensionType.supported_groups,
                 HandshakeType.client_hello, b'\x00\x03\x00\x1d\x00'),
                ('an ECHConfig with octets past its contents', ExtensionType.encrypted_client_hello,
                 HandshakeType.encrypted_extensions,
                 b'\x00\x18\xfe\x0d\x00\x14\x07\x00\x20\x00\x01\x01\x00\x04\x00\x01\x00\x01\x00\x02ex\x00\x00\x00\x00'),
        ):
            with self.subTest(case=name):
                # Quiet only in the dispatcher's own block, as any parser's refusal is (#1845).
                with CaughtByCaller(ProtocolError), self.assertRaises(ProtocolError):
                    proto._read_ext_schema(code, data, msg_type=msg_type)  # pylint: disable=protected-access
                if msg_type == HandshakeType.client_hello:
                    hello = _client_hello(_ext(code, data))
                    with capture(logger) as logs:
                        ext, = TLS(hello, len(hello)).info.content[0].body.extensions
                    self.assertEqual(ext.data, data)
                    self.assertEqual(logs.messages, [])

    def test_raw_contents_of_the_defined_version_are_written_as_they_are(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.const.tls.handshake_type import HandshakeType
        from pcapkit.protocols.application.ssl.data import ECHConfig, ECHEncryptedExtensions
        from pcapkit.protocols.application.ssl.data import Extension as Data_Extension
        from pcapkit.protocols.application.tls.protocol import TLS

        wire = _client_hello()
        proto = TLS(wire, len(wire))
        config = ECHConfig(version=0xFE0D, contents=b'raw')
        built = proto._make_tls_extensions(  # pylint: disable=protected-access
            [Data_Extension(type=ExtensionType.encrypted_client_hello,
                            data=ECHEncryptedExtensions(retry_configs=(config,)))],
            msg_type=HandshakeType.encrypted_extensions)
        self.assertEqual(built.hex(), 'fe0d0009' '0007' 'fe0d0003' + b'raw'.hex())

    def test_the_registrar_takes_a_schema(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.foundation.registry.protocols import register_tls_extension
        from pcapkit.protocols.application.ssl.data import Padding
        from pcapkit.protocols.application.ssl.protocol import SSL
        from pcapkit.protocols.application.ssl.schema import Extension, UnknownExtension
        from pcapkit.protocols.application.tls.protocol import TLS
        from pcapkit.protocols.schema import schema_final
        from pcapkit.utilities.exceptions import StructError

        @schema_final
        class Heartbeat(Extension):
            """``extension_data`` of ``heartbeat``: a one-octet ``HeartbeatMode`` (RFC 6520 section 2)."""

            mode: 'int' = UInt8Field()

        seen = []

        def parser(ext_type: object, schema: object, *, msg_type: object) -> object:  # pylint: disable=unused-argument
            seen.append(type(schema))
            return Padding(padding=bytes([schema.mode]))  # type: ignore[attr-defined]

        def constructor(ext_type: object, data: object = None, *, msg_type: object,  # pylint: disable=unused-argument
                        mode: int = 1, **kwargs: object) -> object:
            return Heartbeat(mode=data.padding[0] if data is not None else mode)  # type: ignore[attr-defined]

        good, cut = _ext(15, b'\x02'), _ext(15, b'')
        shipped = dict(SSL.__extension__)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('error')
                register_tls_extension(ExtensionType.heartbeat, (parser, constructor), schema=Heartbeat)
            self.assertIs(Extension.registry[ExtensionType.heartbeat], Heartbeat)

            wire = _client_hello(good, cut)
            parsed = TLS(wire, len(wire))
            decoded, raw = parsed.info.content[0].body.extensions
            self.assertEqual(decoded.data, Padding(padding=b'\x02'))
            self.assertEqual(raw.data, b'')
            self.assertEqual(set(seen), {Heartbeat})
            self.assertEqual(bytes(TLS.from_data(parsed.info)).hex(), wire.hex())

            proto = TLS(wire, len(wire))
            msg_type = parsed.info.content[0].msg_type
            self.assertEqual(proto._make_tls_extensions(  # pylint: disable=protected-access
                [(ExtensionType.heartbeat, {'mode': 3})], msg_type=msg_type).hex(), _ext(15, b'\x03').hex())
            with self.assertRaisesRegex(StructError, r'^TLS: pack failed$'):
                proto._make_tls_extensions(  # pylint: disable=protected-access
                    [(ExtensionType.heartbeat, {'mode': 0x100})], msg_type=msg_type)
        finally:
            SSL.__extension__.clear()
            SSL.__extension__.update(shipped)
            Extension.__enum__.pop(ExtensionType.heartbeat, None)
        self.assertIs(Extension.registry[ExtensionType.heartbeat], UnknownExtension)

    def test_a_constructor_returning_octets_is_refused(self) -> None:
        """A constructor written for 1.6.x returns ``bytes``, which no longer packs."""
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.foundation.registry.protocols import register_tls_extension
        from pcapkit.protocols.application.ssl.protocol import SSL
        from pcapkit.protocols.application.tls.protocol import TLS
        from pcapkit.utilities.exceptions import ProtocolError

        def parser(ext_type: object, schema: object, *, msg_type: object) -> object:  # pylint: disable=unused-argument
            return bytes(schema)  # type: ignore[call-overload]

        def constructor(ext_type: object, data: object = None, *, msg_type: object,  # pylint: disable=unused-argument
                        **kwargs: object) -> bytes:
            return b'\x01'

        wire = _client_hello()
        proto = TLS(wire, len(wire))
        msg_type = proto.info.content[0].msg_type
        shipped = dict(SSL.__extension__)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('error')
                register_tls_extension(ExtensionType.heartbeat, (parser, constructor))
            with self.assertRaisesRegex(ProtocolError, r'constructor must return a Schema, not bytes$'):
                proto._make_tls_extensions([(ExtensionType.heartbeat, {})], msg_type=msg_type)  # pylint: disable=protected-access
        finally:
            SSL.__extension__.clear()
            SSL.__extension__.update(shipped)


class ExtensionValueTypeTests(unittest.TestCase):
    """A made value of the wrong type is refused with the ``TypeError`` ``main`` raised (#2833)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _make(self, msg_type: object, extensions: 'list[object]') -> bytes:
        from pcapkit.protocols.application.tls.protocol import TLS

        wire = _client_hello()
        return TLS(wire, len(wire))._make_tls_extensions(extensions, msg_type=msg_type)  # type: ignore[arg-type]  # pylint: disable=protected-access

    def test_none_in_an_integer_field_is_a_type_error(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType as ET
        from pcapkit.const.tls.handshake_type import HandshakeType as HT
        from pcapkit.protocols.application.ssl import data as D

        suite = D.HpkeSymmetricCipherSuite

        def config(**kwargs: object) -> object:
            key = {'config_id': 1, 'kem_id': 0x20, 'public_key': b'pk', 'cipher_suites': (suite(kdf_id=1, aead_id=1),)}
            body = {'maximum_name_length': 0, 'public_name': b'ex',
                    'extensions': (D.ECHConfigExtension(type=5, data=b'xy'),)}
            key.update({name: value for name, value in kwargs.items() if name in key})
            body.update({name: value for name, value in kwargs.items() if name in body})
            contents = D.ECHConfigContents(key_config=D.HpkeKeyConfig(**key), **body)
            return [(ET.encrypted_client_hello, {'retry_configs': (D.ECHConfig(version=0xFE0D, contents=contents),)})]

        outer = {'cipher_suite': suite(kdf_id=1, aead_id=1)}
        # NOTE: the HPKE identifiers are enumeration fields, which ``_make_index``
        # refuses as ProtocolError (#2851); test_tls_hpke_registries_2851_unit pins that.
        for name, msg_type, extensions in (
                ('KeyShareEntry.group', HT.client_hello, [(ET.key_share, {
                    'client_shares': (D.KeyShareEntry(group=None, key_exchange=b'k'),)})]),
                ('server_share group', HT.server_hello, [(ET.key_share, {
                    'server_share': D.KeyShareEntry(group=None, key_exchange=b'k')})]),
                ('ServerName.name_type', HT.client_hello, [(ET.server_name, {
                    'server_name_list': (D.ServerName(name_type=None, name=b'x'),)})]),
                ('PskIdentity.obfuscated_ticket_age', HT.client_hello, [(ET.pre_shared_key, {
                    'identities': (D.PskIdentity(identity=b'i', obfuscated_ticket_age=None),), 'binders': ()})]),
                ('selected_identity', HT.server_hello, [D.Extension(
                    type=ET.pre_shared_key, data=D.PreSharedKeyServerHello(selected_identity=None))]),
                ('selected_group', HT.hello_retry_request, [D.Extension(
                    type=ET.key_share, data=D.KeyShareHelloRetryRequest(selected_group=None))]),
                ('selected_version', HT.server_hello, [D.Extension(
                    type=ET.supported_versions, data=D.SupportedVersionsServerHello(selected_version=None))]),
                ('outer config_id', HT.client_hello, [(ET.encrypted_client_hello, dict(outer, config_id=None))]),
                ('ECHConfig.version', HT.encrypted_extensions, [(ET.encrypted_client_hello, {
                    'retry_configs': (D.ECHConfig(version=None, contents=b'x'),)})]),
                ('HpkeKeyConfig.config_id', HT.encrypted_extensions, config(config_id=None)),
                ('maximum_name_length', HT.encrypted_extensions, config(maximum_name_length=None)),
                ('ECHConfigExtension.type', HT.encrypted_extensions,
                 config(extensions=(D.ECHConfigExtension(type=None, data=b'x'),))),
                ('a NamedGroup item', HT.client_hello, [(ET.supported_groups, {'named_group_list': (None,)})]),
                ('a SignatureScheme item', HT.client_hello, [(ET.signature_algorithms, {
                    'supported_signature_algorithms': (0x0403, None)})]),
        ):
            with self.subTest(field=name), self.assertRaises(TypeError):
                self._make(msg_type, extensions)

    def test_an_octet_field_of_another_type_is_a_type_error(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType as ET
        from pcapkit.const.tls.handshake_type import HandshakeType as HT
        from pcapkit.protocols.application.ssl import data as D

        for name, msg_type, code, kwargs in (
                ('cookie str', HT.client_hello, ET.cookie, {'cookie': 'abc'}),
                ('cookie tuple', HT.client_hello, ET.cookie, {'cookie': ('a',)}),
                ('cookie list', HT.client_hello, ET.cookie, {'cookie': [1, 2]}),
                ('cookie dict', HT.client_hello, ET.cookie, {'cookie': {'a': 1}}),
                ('cid', HT.client_hello, ET.connection_id, {'cid': 'ab'}),
                ('renegotiated_connection', HT.client_hello, ET.renegotiation_info,
                 {'renegotiated_connection': {'a': 1}}),
                ('a ProtocolName', HT.client_hello, ET.application_layer_protocol_negotiation,
                 {'protocol_name_list': ('h2',)}),
                ('a SerializedSCT', HT.server_hello, ET.signed_certificate_timestamp, {'sct_list': ([1],)}),
                ('a PskBinderEntry', HT.client_hello, ET.pre_shared_key, {'identities': (), 'binders': ('b',)}),
                ('a PskIdentity identity', HT.client_hello, ET.pre_shared_key, {
                    'identities': (D.PskIdentity(identity='i', obfuscated_ticket_age=1),), 'binders': ()}),
                ('request_extensions', HT.client_hello, ET.status_request, {'request_extensions': (1,)}),
                ('a ResponderID', HT.client_hello, ET.status_request, {'responder_id_list': ('id',)}),
                ('key_exchange', HT.client_hello, ET.key_share, {
                    'client_shares': (D.KeyShareEntry(group=29, key_exchange='k'),)}),
                ('enc', HT.client_hello, ET.encrypted_client_hello, {
                    'cipher_suite': D.HpkeSymmetricCipherSuite(kdf_id=1, aead_id=1), 'enc': 'e'}),
        ):
            with self.subTest(field=name), self.assertRaises(TypeError):
                self._make(msg_type, [(code, kwargs)])

    def test_a_bytes_like_octet_field_still_builds(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType as ET
        from pcapkit.const.tls.handshake_type import HandshakeType as HT

        for value in (bytearray(b'ab'), memoryview(b'ab')):
            with self.subTest(kind=type(value).__name__):
                self.assertEqual(self._make(HT.client_hello, [(ET.cookie, {'cookie': value})]).hex(),
                                 _ext(44, b'\x00\x02ab').hex())


if __name__ == '__main__':
    unittest.main()
