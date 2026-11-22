# -*- coding: utf-8 -*-
"""The extensions a current ``ClientHello`` and ``ServerHello`` carry decode, byte for byte (#2810).

``SSL.__extension__`` decodes ``status_request``, ``ec_point_formats``,
``signed_certificate_timestamp``, ``padding``, ``extended_main_secret``,
``compress_certificate``, ``record_size_limit``, ``session_ticket``,
``pre_shared_key``, ``early_data``, ``cookie``, ``psk_key_exchange_modes``,
``post_handshake_auth``, ``encrypted_client_hello`` and ``renegotiation_info``,
on top of #2514's, each only in the messages its RFC sends it in. Each case is
hand-built from its specification's structure, checked against the field values
the octets carry, and rebuilt both ways: parse then ``from_data``, and ``make``
from the parsed content. GREASE (RFC 8701) stays raw.

"""
from __future__ import annotations

import ast
import inspect
import textwrap
import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): hand-picked round-trip cases, not a sweep.
__tier__ = 'ALL'

#: ``random`` of a ``HelloRetryRequest`` (RFC 9846 section 4.2.3).
HRR_RANDOM = bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c')


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


def _server_hello(*extensions: bytes, random: bytes = bytes(range(32, 64))) -> bytes:
    return _record(_handshake(2, b'\x03\x03' + random + b'\x00' + b'\x13\x01' + b'\x00'
                              + _vec(b''.join(extensions))))


def _retry_request(*extensions: bytes) -> bytes:
    return _server_hello(*extensions, random=HRR_RANDOM)


def _encrypted_extensions(*extensions: bytes) -> bytes:
    return _record(_handshake(8, _vec(b''.join(extensions))))


def _missing_ranges(cls: type) -> 'dict[str, list[tuple[int, int]]]':
    """The ``lo <= value <= hi`` branches of ``cls._missing_``, by the name each returns."""
    func = ast.parse(textwrap.dedent(inspect.getsource(cls._missing_))).body[0]  # type: ignore[attr-defined]
    ranges: 'dict[str, list[tuple[int, int]]]' = {}
    for node in ast.walk(func):
        if not (isinstance(node, ast.If) and isinstance(node.test, ast.Compare) and len(node.test.ops) == 2):
            continue
        for call in (n for stmt in node.body for n in ast.walk(stmt)):
            if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                    and call.func.attr == '_unregistered_member'):
                bounds = (ast.literal_eval(node.test.left), ast.literal_eval(node.test.comparators[1]))
                ranges.setdefault(ast.literal_eval(call.args[1]), []).append(bounds)
    return ranges


#: ``status_request`` (RFC 6066 section 8): ocsp, one ResponderID, empty request Extensions.
STATUS_REQUEST = _ext(5, b'\x01' + _vec(_vec(b'\x30\x03\x02\x01\x01')) + _vec(b'\x30\x00'))
#: ``ec_point_formats`` (RFC 8422 section 5.1.2): all three point formats.
EC_POINT_FORMATS = _ext(11, _vec(b'\x00\x01\x02', 1))
#: ``signed_certificate_timestamp`` in a ``ClientHello`` (RFC 6962 section 3.3.1): empty.
SCT_REQUEST = _ext(18, b'')
#: ``padding`` (RFC 7685 section 3): seven zero octets.
PADDING = _ext(21, bytes(7))
#: ``extended_main_secret`` (RFC 7627 section 5.1): empty.
EXTENDED_MAIN_SECRET = _ext(23, b'')
#: ``compress_certificate`` (RFC 8879 section 3): brotli, zlib.
COMPRESS_CERTIFICATE = _ext(27, _vec(b'\x00\x02\x00\x01', 1))
#: ``record_size_limit`` (RFC 8449 section 4): 2^14 + 1.
RECORD_SIZE_LIMIT = _ext(28, b'\x40\x01')
#: ``session_ticket`` (RFC 5077 section 3.2): the ticket itself, no length.
SESSION_TICKET = _ext(35, bytes(range(16)))
#: ``early_data`` in a ``ClientHello`` (RFC 9846 section 4.3.10): empty.
EARLY_DATA = _ext(42, b'')
#: ``cookie`` (RFC 9846 section 4.3.2).
COOKIE = _ext(44, _vec(b'cookie'))
#: ``psk_key_exchange_modes`` (RFC 9846 section 4.3.9): psk_dhe_ke, psk_ke.
PSK_KEY_EXCHANGE_MODES = _ext(45, _vec(b'\x01\x00', 1))
#: ``post_handshake_auth`` (RFC 9846 section 4.3.6): empty.
POST_HANDSHAKE_AUTH = _ext(49, b'')
#: Outer ``encrypted_client_hello`` (RFC 9849 section 5): HKDF-SHA256/AES-128-GCM, config 0x2A.
ECH_OUTER = _ext(0xFE0D, b'\x00' + b'\x00\x01\x00\x01' + b'\x2a' + _vec(bytes(range(32))) + _vec(bytes(range(16))))
#: ``renegotiation_info`` on an initial handshake (RFC 5746 section 3.2): empty verify_data.
RENEGOTIATION_INFO = _ext(0xFF01, _vec(b'', 1))
#: ``pre_shared_key`` in a ``ClientHello`` (RFC 9846 section 4.3.11): one identity, one 32-octet binder.
PRE_SHARED_KEY = _ext(41, _vec(_vec(b'ticket') + b'\x01\x02\x03\x04') + _vec(_vec(bytes(range(32)), 1)))
#: ``supported_versions`` in a ``ClientHello``: TLS 1.3, TLS 1.2.
VERSIONS = _ext(43, _vec(b'\x03\x04\x03\x03', 1))

#: An ``ECHConfig`` of version 0xFE0D (RFC 9849 section 4): DHKEM(X25519, HKDF-SHA256), two
#: cipher suites and one GREASE configuration extension.
ECH_CONFIG = b'\xfe\x0d' + _vec(b'\x2a' + b'\x00\x20' + _vec(bytes(range(32)))
                                + _vec(b'\x00\x01\x00\x01\x00\x01\x00\x03') + b'\x00'
                                + _vec(b'public.example', 1) + _vec(_ext(0xFAFA, b'\x00')))
#: An ``ECHConfig`` of a version RFC 9849 does not define, which a client skips.
ECH_CONFIG_OTHER = b'\xfe\x0c' + _vec(b'opaque')

#: Each hello message, by its ``HandshakeType`` name, and how to build one.
MESSAGES = {'client_hello': _client_hello, 'server_hello': _server_hello,
            'hello_retry_request': _retry_request, 'encrypted_extensions': _encrypted_extensions}
#: The extensions whose structure is the same in every message that carries them: the
#: messages each RFC sends it in, a body that decodes there, and the ``make`` arguments
#: that build one. RFC 8422 sections 5.1 and 5.2; RFC 7685 section 3; RFC 7627 section 5.1;
#: RFC 8879 section 3; RFC 8449 sections 1 and 4, valid in every TLS version so in a TLS 1.2
#: ServerHello too; RFC 5077 section 3.2; RFC 9846 sections 4.3.2, 4.3.9 and 4.3.6; RFC 5746
#: section 3.2.
GATED = {
    11: ({'client_hello', 'server_hello'}, _vec(b'\x00', 1), {'ec_point_format_list': (0,)}),
    21: ({'client_hello'}, bytes(3), {'padding': bytes(3)}),
    23: ({'client_hello', 'server_hello'}, b'', {}),
    27: ({'client_hello'}, _vec(b'\x00\x01', 1), {'algorithms': (1,)}),
    28: ({'client_hello', 'server_hello', 'encrypted_extensions'}, b'\x40\x00', {'record_size_limit': 0x4000}),
    35: ({'client_hello', 'server_hello'}, b'abc', {'ticket': b'abc'}),
    44: ({'client_hello', 'hello_retry_request'}, _vec(b'cookie'), {'cookie': b'cookie'}),
    45: ({'client_hello'}, _vec(b'\x01', 1), {'ke_modes': (1,)}),
    49: ({'client_hello'}, b'', {}),
    0xFF01: ({'client_hello', 'server_hello'}, _vec(b'', 1), {}),
}


class HelloExtensionDecodingTests(unittest.TestCase):
    """Each extension decodes to its specification's fields, in each message it is defined for."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _extensions(self, wire: bytes) -> 'tuple':
        from pcapkit.protocols.application.tls.protocol import TLS

        parsed = TLS(wire, len(wire))
        self.assertEqual(bytes(TLS.from_data(parsed.info)).hex(), wire.hex())
        maker = object.__new__(TLS)
        made = maker.make(content_type=parsed.info.content_type, version=parsed.info.version,
                          content=parsed.info.content)
        self.assertEqual(bytes(made).hex(), wire.hex())
        return parsed.info.content[0].body.extensions

    def test_client_hello_extensions(self) -> None:
        from pcapkit.const.tls.certificate_compression_algorithm import CertificateCompressionAlgorithm
        from pcapkit.const.tls.certificate_status_type import CertificateStatusType
        from pcapkit.const.tls.ec_point_format import ECPointFormat
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.const.tls.psk_key_exchange_mode import PskKeyExchangeMode
        from pcapkit.protocols.application.ssl import data as models

        extensions = self._extensions(_client_hello(
            STATUS_REQUEST, EC_POINT_FORMATS, SCT_REQUEST, PADDING, EXTENDED_MAIN_SECRET, COMPRESS_CERTIFICATE,
            RECORD_SIZE_LIMIT, SESSION_TICKET, EARLY_DATA, COOKIE, PSK_KEY_EXCHANGE_MODES, POST_HANDSHAKE_AUTH,
            ECH_OUTER, RENEGOTIATION_INFO, PRE_SHARED_KEY))
        expected = (
            (ExtensionType.status_request, models.CertificateStatusRequest(
                status_type=CertificateStatusType.ocsp, request=models.OCSPStatusRequest(
                    responder_id_list=(b'\x30\x03\x02\x01\x01',), request_extensions=b'\x30\x00'))),
            (ExtensionType.ec_point_formats, models.ECPointFormatList(ec_point_format_list=(
                ECPointFormat.uncompressed, ECPointFormat.ansiX962_compressed_prime,
                ECPointFormat.ansiX962_compressed_char2))),
            (ExtensionType.signed_certificate_timestamp, models.Empty()),
            (ExtensionType.padding, models.Padding(padding=bytes(7))),
            (ExtensionType.extended_main_secret, models.Empty()),
            (ExtensionType.compress_certificate, models.CertificateCompressionAlgorithms(algorithms=(
                CertificateCompressionAlgorithm.brotli, CertificateCompressionAlgorithm.zlib))),
            (ExtensionType.record_size_limit, models.RecordSizeLimit(record_size_limit=0x4001)),
            (ExtensionType.session_ticket, models.SessionTicket(ticket=bytes(range(16)))),
            (ExtensionType.early_data, models.Empty()),
            (ExtensionType.cookie, models.Cookie(cookie=b'cookie')),
            (ExtensionType.psk_key_exchange_modes, models.PskKeyExchangeModes(ke_modes=(
                PskKeyExchangeMode.psk_dhe_ke, PskKeyExchangeMode.psk_ke))),
            (ExtensionType.post_handshake_auth, models.Empty()),
            (ExtensionType.encrypted_client_hello, models.ECHClientHelloOuter(
                cipher_suite=models.HpkeSymmetricCipherSuite(kdf_id=0x0001, aead_id=0x0001), config_id=0x2A,
                enc=bytes(range(32)), payload=bytes(range(16)))),
            (ExtensionType.renegotiation_info, models.RenegotiationInfo(renegotiated_connection=b'')),
            (ExtensionType.pre_shared_key, models.OfferedPsks(
                identities=(models.PskIdentity(identity=b'ticket', obfuscated_ticket_age=0x01020304),),
                binders=(bytes(range(32)),))),
        )
        self.assertEqual(len(extensions), len(expected))
        for ext, (ext_type, model) in zip(extensions, expected):
            with self.subTest(ext_type=ext_type.name):
                self.assertEqual(ext.type, ext_type)
                self.assertIsInstance(ext.data, type(model))
                self.assertEqual(ext.data, model)

    def test_enumerated_fields_decode_to_their_members(self) -> None:
        from pcapkit.const.tls.certificate_compression_algorithm import CertificateCompressionAlgorithm
        from pcapkit.const.tls.certificate_status_type import CertificateStatusType
        from pcapkit.const.tls.ec_point_format import ECPointFormat
        from pcapkit.const.tls.psk_key_exchange_mode import PskKeyExchangeMode

        status, points, compress, modes = self._extensions(_client_hello(
            STATUS_REQUEST, EC_POINT_FORMATS, COMPRESS_CERTIFICATE, PSK_KEY_EXCHANGE_MODES))
        self.assertIs(type(status.data.status_type), CertificateStatusType)
        for values, enum in ((points.data.ec_point_format_list, ECPointFormat),
                             (compress.data.algorithms, CertificateCompressionAlgorithm),
                             (modes.data.ke_modes, PskKeyExchangeMode)):
            with self.subTest(enum=enum.__name__):
                self.assertTrue(values)
                self.assertTrue(all(type(value) is enum for value in values))

    def test_server_hello_extensions(self) -> None:
        from pcapkit.protocols.application.ssl import data as models

        extensions = self._extensions(_server_hello(
            _ext(5, b''), _ext(11, _vec(b'\x00', 1)), _ext(18, _vec(_vec(b'sct-one') + _vec(b'sct-two'))),
            _ext(23, b''), _ext(28, b'\x40\x00'), _ext(35, b''), _ext(41, b'\x00\x01'),
            _ext(0xFF01, _vec(bytes(range(24)), 1))))
        self.assertEqual([ext.data for ext in extensions], [
            models.Empty(),
            models.ECPointFormatList(ec_point_format_list=(0,)),
            models.SignedCertificateTimestampList(sct_list=(b'sct-one', b'sct-two')),
            models.Empty(),
            models.RecordSizeLimit(record_size_limit=0x4000),
            models.SessionTicket(ticket=b''),
            models.PreSharedKeyServerHello(selected_identity=1),
            models.RenegotiationInfo(renegotiated_connection=bytes(range(24))),
        ])

    def test_hello_retry_request_extensions(self) -> None:
        from pcapkit.protocols.application.ssl import data as models

        versions, cookie, ech = self._extensions(_retry_request(
            _ext(43, b'\x03\x04'), _ext(44, _vec(b'cookie')), _ext(0xFE0D, bytes(range(8)))))
        self.assertEqual(versions.data, models.SupportedVersionsServerHello(selected_version=0x0304))
        self.assertEqual(cookie.data, models.Cookie(cookie=b'cookie'))
        self.assertEqual(ech.data, models.ECHHelloRetryRequest(confirmation=bytes(range(8))))

    def test_encrypted_extensions(self) -> None:
        from pcapkit.protocols.application.ssl import data as models

        early, limit, ech = self._extensions(_encrypted_extensions(
            _ext(42, b''), _ext(28, b'\x40\x01'), _ext(0xFE0D, _vec(ECH_CONFIG + ECH_CONFIG_OTHER))))
        self.assertEqual(early.data, models.Empty())
        self.assertEqual(limit.data, models.RecordSizeLimit(record_size_limit=0x4001))
        self.assertEqual(ech.data, models.ECHEncryptedExtensions(retry_configs=(
            models.ECHConfig(version=0xFE0D, contents=models.ECHConfigContents(
                key_config=models.HpkeKeyConfig(
                    config_id=0x2A, kem_id=0x0020, public_key=bytes(range(32)), cipher_suites=(
                        models.HpkeSymmetricCipherSuite(kdf_id=0x0001, aead_id=0x0001),
                        models.HpkeSymmetricCipherSuite(kdf_id=0x0001, aead_id=0x0003))),
                maximum_name_length=0, public_name=b'public.example',
                extensions=(models.ECHConfigExtension(type=0xFAFA, data=b'\x00'),))),
            models.ECHConfig(version=0xFE0C, contents=b'opaque'),
        )))

    def test_inner_encrypted_client_hello(self) -> None:
        """The inner variant carries its type octet alone (RFC 9849 section 5)."""
        from pcapkit.protocols.application.ssl.data import ECHClientHelloInner

        ech, = self._extensions(_client_hello(_ext(0xFE0D, b'\x01')))
        self.assertEqual(ech.data, ECHClientHelloInner())

    def test_dtls_client_hello_extensions(self) -> None:
        """DTLS shares the registry, so its ``ClientHello`` decodes the same."""
        from pcapkit.protocols.application.dtls.protocol import DTLS
        from pcapkit.protocols.application.ssl.data import Empty, PskKeyExchangeModes

        body = (b'\xfe\xfd' + bytes(32) + b'\x00' + b'\x00' + _vec(b'\x13\x01') + _vec(b'\x00', 1)
                + _vec(PSK_KEY_EXCHANGE_MODES + EXTENDED_MAIN_SECRET))
        message = (b'\x01' + len(body).to_bytes(3, 'big') + bytes(2) + bytes(3)
                   + len(body).to_bytes(3, 'big') + body)
        wire = b'\x16\xfe\xfd' + bytes(2) + (1).to_bytes(6, 'big') + _vec(message)
        parsed = DTLS(wire, len(wire))
        modes, ems = parsed.info.content[0].body.extensions
        self.assertEqual(modes.data, PskKeyExchangeModes(ke_modes=(1, 0)))
        self.assertEqual(ems.data, Empty())
        self.assertEqual(bytes(DTLS.from_data(parsed.info)).hex(), wire.hex())


class HelloExtensionMalformedTests(unittest.TestCase):
    """A body its decoder cannot read exactly keeps its octets, and the list after it still decodes."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_malformed_bodies_stay_raw_and_rebuild(self) -> None:
        from pcapkit.protocols.application.tls.protocol import TLS
        from pcapkit.protocols.application.ssl.data import RecordSizeLimit
        from pcapkit.protocols.application.ssl.data import SupportedVersionsClientHello
        from pcapkit.protocols.application.ssl.data import SupportedVersionsServerHello

        suite = b'\x00\x01\x00\x01'
        cases = {
            'status_request of a status type other than ocsp': (_client_hello, _ext(5, b'\x02' + _vec(b'') + _vec(b''))),
            'status_request trailing octets': (_client_hello, _ext(5, b'\x01' + _vec(b'') + _vec(b'') + b'\x00')),
            'status_request responder id past its list': (_client_hello, _ext(5, b'\x01' + _vec(b'\x00\x05ab') + _vec(b''))),
            'status_request not empty in a ServerHello': (_server_hello, _ext(5, b'\x01')),
            'ec_point_formats length mismatch': (_client_hello, _ext(11, b'\x02\x00')),
            'signed_certificate_timestamp not empty in a ClientHello': (_client_hello, _ext(18, b'\x00')),
            'signed_certificate_timestamp list length mismatch': (_server_hello, _ext(18, b'\x00\x05\x00\x01a')),
            'extended_main_secret not empty': (_client_hello, _ext(23, b'\x00')),
            'compress_certificate odd length': (_client_hello, _ext(27, _vec(b'\x00\x02\x00', 1))),
            'record_size_limit too short': (_client_hello, _ext(28, b'\x40')),
            'record_size_limit too long': (_client_hello, _ext(28, b'\x40\x00\x00')),
            'pre_shared_key identity past its list': (_client_hello, _ext(41, _vec(b'\x00\x05ab') + _vec(b''))),
            'pre_shared_key obfuscated_ticket_age cut': (_client_hello, _ext(41, _vec(_vec(b'id') + b'\x00\x00') + _vec(b''))),
            'pre_shared_key trailing octets': (_client_hello, _ext(41, _vec(b'') + _vec(b'') + b'\x00')),
            'pre_shared_key selected_identity too long': (_server_hello, _ext(41, b'\x00\x00\x00')),
            'early_data not empty in a ClientHello': (_client_hello, _ext(42, b'\x00\x00\x00\x01')),
            'early_data not empty in EncryptedExtensions': (_encrypted_extensions, _ext(42, b'\x00')),
            'cookie length mismatch': (_client_hello, _ext(44, b'\x00\x05abc')),
            'psk_key_exchange_modes length mismatch': (_client_hello, _ext(45, b'\x02\x01')),
            'post_handshake_auth not empty': (_client_hello, _ext(49, b'\x00')),
            'encrypted_client_hello of an undefined type': (_client_hello, _ext(0xFE0D, b'\x02')),
            'encrypted_client_hello inner with octets': (_client_hello, _ext(0xFE0D, b'\x01\x00')),
            'encrypted_client_hello outer cut': (_client_hello, _ext(0xFE0D, b'\x00' + suite + b'\x2a\x00\x20')),
            'encrypted_client_hello outer trailing octets': (
                _client_hello, _ext(0xFE0D, b'\x00' + suite + b'\x2a' + _vec(b'') + _vec(b'x') + b'\x00')),
            'encrypted_client_hello confirmation too short': (_retry_request, _ext(0xFE0D, bytes(7))),
            'encrypted_client_hello retry_configs length mismatch': (
                _encrypted_extensions, _ext(0xFE0D, b'\x00\x09' + ECH_CONFIG_OTHER)),
            'encrypted_client_hello config contents trailing octets': (
                _encrypted_extensions, _ext(0xFE0D, _vec(ECH_CONFIG[:2] + _vec(ECH_CONFIG[4:] + b'\x00')))),
            'encrypted_client_hello cipher_suites not a multiple of 4': (
                _encrypted_extensions, _ext(0xFE0D, _vec(b'\xfe\x0d' + _vec(
                    b'\x2a\x00\x20' + _vec(b'k') + _vec(b'\x00\x01') + b'\x00' + _vec(b'p', 1) + _vec(b''))))),
            'renegotiation_info length mismatch': (_client_hello, _ext(0xFF01, b'\x05\x00')),
        }
        trailer = {
            _client_hello: (VERSIONS, SupportedVersionsClientHello),
            _server_hello: (_ext(43, b'\x03\x04'), SupportedVersionsServerHello),
            _retry_request: (_ext(43, b'\x03\x04'), SupportedVersionsServerHello),
            _encrypted_extensions: (_ext(28, b'\x40\x00'), RecordSizeLimit),
        }
        for name, (hello, extension) in cases.items():
            with self.subTest(case=name):
                after, model = trailer[hello]
                wire = hello(extension, after)
                parsed = TLS(wire, len(wire))
                ext, last = parsed.info.content[0].body.extensions
                self.assertEqual(ext.data, extension[4:])
                self.assertIsInstance(last.data, model)
                self.assertEqual(bytes(TLS.from_data(parsed.info)).hex(), wire.hex())

    def test_a_structure_the_message_does_not_have_stays_raw(self) -> None:
        from pcapkit.protocols.application.tls.protocol import TLS

        for name, wire, extension in (
                ('status_request in EncryptedExtensions', _encrypted_extensions, _ext(5, b'\x01')),
                ('status_request in a HelloRetryRequest', _retry_request, _ext(5, b'')),
                ('signed_certificate_timestamp in EncryptedExtensions', _encrypted_extensions, _ext(18, b'')),
                ('pre_shared_key in EncryptedExtensions', _encrypted_extensions, _ext(41, b'\x00\x00')),
                ('early_data in a ServerHello', _server_hello, _ext(42, b'')),
                ('encrypted_client_hello in a ServerHello', _server_hello, _ext(0xFE0D, b'\x00')),
        ):
            with self.subTest(case=name):
                octets = wire(extension)
                parsed = TLS(octets, len(octets))
                ext, = parsed.info.content[0].body.extensions
                self.assertEqual(ext.data, extension[4:])
                self.assertEqual(bytes(TLS.from_data(parsed.info)).hex(), octets.hex())

    def test_each_decodes_only_in_the_messages_its_rfc_sends_it_in(self) -> None:
        from pcapkit.protocols.application.tls.protocol import TLS
        from pcapkit.protocols.application.ssl.data import ExtensionData

        for code, (defined, body, _) in GATED.items():
            for message, hello in MESSAGES.items():
                with self.subTest(code=code, message=message):
                    octets = hello(_ext(code, body))
                    parsed = TLS(octets, len(octets))
                    ext, = parsed.info.content[0].body.extensions
                    if message in defined:
                        self.assertIsInstance(ext.data, ExtensionData)
                    else:
                        self.assertIsInstance(ext.data, bytes)
                        self.assertEqual(ext.data, body)
                    self.assertEqual(bytes(TLS.from_data(parsed.info)).hex(), octets.hex())


class HelloExtensionConstructionTests(unittest.TestCase):
    """``make`` builds each extension from keyword arguments, and refuses what it cannot write."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _hello(extensions: 'tuple', *, msg_type: str = 'client_hello', random: bytes = bytes(range(32))) -> bytes:
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.const.tls.handshake_type import HandshakeType
        from pcapkit.protocols.application.tls.protocol import TLS
        from pcapkit.protocols.application.ssl.data import ClientHello, EncryptedExtensions
        from pcapkit.protocols.application.ssl.data import Handshake, ServerHello

        if msg_type == 'server_hello':
            body = ServerHello(version=0x0303, random=random, session_id=b'', cipher_suite=0x1301,
                               compression_method=0, extensions=extensions)  # type: object
        elif msg_type == 'encrypted_extensions':
            body = EncryptedExtensions(extensions=extensions)
        else:
            body = ClientHello(version=0x0303, random=random, session_id=b'', cookie=None,
                               cipher_suites=(0x1301,), compression_methods=(0,), extensions=extensions)
        maker = object.__new__(TLS)
        return bytes(maker.make(content_type=ContentType.handshake, version=0x0303,
                                content=(Handshake(msg_type=HandshakeType[msg_type], length=0, body=body),)))

    def test_client_hello_from_keyword_arguments(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.const.tls.ec_point_format import ECPointFormat
        from pcapkit.protocols.application.ssl.data import HpkeSymmetricCipherSuite, PskIdentity

        made = self._hello((
            (ExtensionType.status_request, {'responder_id_list': (b'\x30\x03\x02\x01\x01',),
                                            'request_extensions': b'\x30\x00'}),
            (ExtensionType.ec_point_formats, {'ec_point_format_list': (ECPointFormat.uncompressed, 1, 2)}),
            (ExtensionType.signed_certificate_timestamp, {}),
            (ExtensionType.padding, {'padding': bytes(7)}),
            (ExtensionType.extended_main_secret, {}),
            (27, {'algorithms': (2, 1)}),
            (ExtensionType.record_size_limit, {'record_size_limit': 0x4001}),
            (ExtensionType.session_ticket, {'ticket': bytes(range(16))}),
            (ExtensionType.early_data, {}),
            (ExtensionType.cookie, {'cookie': b'cookie'}),
            (ExtensionType.psk_key_exchange_modes, {'ke_modes': (1, 0)}),
            (ExtensionType.post_handshake_auth, {}),
            (ExtensionType.encrypted_client_hello, {
                'cipher_suite': HpkeSymmetricCipherSuite(kdf_id=1, aead_id=1), 'config_id': 0x2A,
                'enc': bytes(range(32)), 'payload': bytes(range(16))}),
            (ExtensionType.renegotiation_info, {}),
            (ExtensionType.pre_shared_key, {
                'identities': (PskIdentity(identity=b'ticket', obfuscated_ticket_age=0x01020304),),
                'binders': (bytes(range(32)),)}),
        ))
        self.assertEqual(made.hex(), _client_hello(
            STATUS_REQUEST, EC_POINT_FORMATS, SCT_REQUEST, PADDING, EXTENDED_MAIN_SECRET, COMPRESS_CERTIFICATE,
            RECORD_SIZE_LIMIT, SESSION_TICKET, EARLY_DATA, COOKIE, PSK_KEY_EXCHANGE_MODES, POST_HANDSHAKE_AUTH,
            ECH_OUTER, RENEGOTIATION_INFO, PRE_SHARED_KEY).hex())

        self.assertEqual(self._hello(((ExtensionType.encrypted_client_hello, {'inner': True}),)).hex(),
                         _client_hello(_ext(0xFE0D, b'\x01')).hex())
        self.assertEqual(self._hello(((ExtensionType.status_request, {}),)).hex(),
                         _client_hello(_ext(5, b'\x01\x00\x00\x00\x00')).hex())

    def test_server_messages_from_keyword_arguments(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.protocols.application.ssl.data import ECHConfig

        made = self._hello(((ExtensionType.status_request, {}),
                            (ExtensionType.signed_certificate_timestamp, {'sct_list': (b'sct-one', b'sct-two')}),
                            (ExtensionType.pre_shared_key, {'selected_identity': 1})),
                           msg_type='server_hello', random=bytes(range(32, 64)))
        self.assertEqual(made.hex(), _server_hello(_ext(5, b''), _ext(18, _vec(_vec(b'sct-one') + _vec(b'sct-two'))),
                                                   _ext(41, b'\x00\x01')).hex())

        made = self._hello(((ExtensionType.cookie, {'cookie': b'cookie'}),
                            (ExtensionType.encrypted_client_hello, {'confirmation': bytes(range(8))})),
                           msg_type='server_hello', random=HRR_RANDOM)
        self.assertEqual(made.hex(), _retry_request(_ext(44, _vec(b'cookie')), _ext(0xFE0D, bytes(range(8)))).hex())

        made = self._hello(((ExtensionType.early_data, {}),
                            (ExtensionType.encrypted_client_hello, {'retry_configs': (
                                ECHConfig(version=0xFE0C, contents=b'opaque'),)})),
                           msg_type='encrypted_extensions')
        self.assertEqual(made.hex(), _encrypted_extensions(_ext(42, b''), _ext(0xFE0D, _vec(ECH_CONFIG_OTHER))).hex())

    def test_what_make_cannot_write_raises(self) -> None:
        from pcapkit.const.tls.certificate_status_type import CertificateStatusType
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.protocols.application.ssl.data import CertificateStatusRequest, Cookie, Extension
        from pcapkit.protocols.application.ssl.data import ECHHelloRetryRequest, OCSPStatusRequest
        from pcapkit.utilities.exceptions import ProtocolError

        request = OCSPStatusRequest(responder_id_list=(), request_extensions=b'')
        for name, extensions, kwargs in (
                ('ec_point_format as a bool', ((ExtensionType.ec_point_formats, {'ec_point_format_list': (True,)}),), {}),
                ('ec_point_format by name', ((ExtensionType.ec_point_formats,
                                              {'ec_point_format_list': ('uncompressed',)}),), {}),
                ('ec_point_format too wide', ((ExtensionType.ec_point_formats, {'ec_point_format_list': (0x100,)}),), {}),
                ('ke_mode negative', ((ExtensionType.psk_key_exchange_modes, {'ke_modes': (-1,)}),), {}),
                ('compression algorithm too wide', ((ExtensionType.compress_certificate,
                                                     {'algorithms': (0x10000,)}),), {}),
                ('status_type by name', ((ExtensionType.status_request, {'status_type': 'ocsp'}),), {}),
                ('status_type not ocsp', (Extension(type=ExtensionType.status_request, data=CertificateStatusRequest(
                    status_type=CertificateStatusType.ocsp_multi_RESERVED, request=request)),), {}),
                ('status_request in EncryptedExtensions', ((ExtensionType.status_request, {}),),
                 {'msg_type': 'encrypted_extensions'}),
                ('signed_certificate_timestamp in EncryptedExtensions',
                 ((ExtensionType.signed_certificate_timestamp, {}),), {'msg_type': 'encrypted_extensions'}),
                ('record_size_limit missing', ((ExtensionType.record_size_limit, {}),), {}),
                ('selected_identity missing', ((ExtensionType.pre_shared_key, {}),), {'msg_type': 'server_hello'}),
                ('early_data in a ServerHello', ((ExtensionType.early_data, {}),), {'msg_type': 'server_hello'}),
                ('cipher_suite missing', ((ExtensionType.encrypted_client_hello, {}),), {}),
                ('confirmation too short', (Extension(type=ExtensionType.encrypted_client_hello,
                                                      data=ECHHelloRetryRequest(confirmation=bytes(7))),),
                 {'msg_type': 'server_hello', 'random': HRR_RANDOM}),
                ('a model under an always-empty type', (Extension(type=ExtensionType.extended_main_secret,
                                                                  data=Cookie(cookie=b'x')),), {}),
        ):
            with self.subTest(case=name), self.assertRaises(ProtocolError):
                self._hello(extensions, **kwargs)

    def test_keyword_arguments_build_only_in_the_messages_its_rfc_sends_it_in(self) -> None:
        from pcapkit.protocols.application.ssl.data import Cookie, Extension
        from pcapkit.utilities.exceptions import ProtocolError

        options = {'client_hello': {}, 'server_hello': {'msg_type': 'server_hello', 'random': bytes(range(32, 64))},
                   'hello_retry_request': {'msg_type': 'server_hello', 'random': HRR_RANDOM},
                   'encrypted_extensions': {'msg_type': 'encrypted_extensions'}}
        for code, (defined, body, kwargs) in GATED.items():
            for message, hello in MESSAGES.items():
                with self.subTest(code=code, message=message):
                    if message in defined:
                        self.assertEqual(self._hello(((code, kwargs),), **options[message]).hex(),
                                         hello(_ext(code, body)).hex())
                    else:
                        with self.assertRaises(ProtocolError):
                            self._hello(((code, kwargs),), **options[message])

        # NOTE: a decoded body decides the structure itself, whatever message carries it.
        made = self._hello((Extension(type=44, data=Cookie(cookie=b'cookie')),), msg_type='encrypted_extensions')
        self.assertEqual(made.hex(), _encrypted_extensions(_ext(44, _vec(b'cookie'))).hex())


class GreaseTests(unittest.TestCase):
    """GREASE values (RFC 8701 section 2) stay as they were sent."""

    #: The GREASE ExtensionType values: 0x0A0A, 0x1A1A, ..., 0xFAFA.
    EXTENSION_TYPES = tuple(0x0A0A | (nibble << 12) | (nibble << 4) for nibble in range(16))
    #: The GREASE PskKeyExchangeMode values.
    PSK_KEY_EXCHANGE_MODES = (0x0B, 0x2A, 0x49, 0x68, 0x87, 0xA6, 0xC5, 0xE4)

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_grease_extension_types_stay_raw(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.protocols.application.ssl.protocol import SSL
        from pcapkit.protocols.application.tls.protocol import TLS

        wire = _client_hello(*(_ext(code, bytes([index])) for index, code in enumerate(self.EXTENSION_TYPES)))
        parsed = TLS(wire, len(wire))
        for index, (code, ext) in enumerate(zip(self.EXTENSION_TYPES, parsed.info.content[0].body.extensions)):
            with self.subTest(code=hex(code)):
                self.assertNotIn(code, SSL.__extension__)
                self.assertIsInstance(ext.type, ExtensionType)
                self.assertEqual(int(ext.type), code)
                self.assertEqual(ext.data, bytes([index]))
        self.assertEqual(bytes(TLS.from_data(parsed.info)).hex(), wire.hex())

    def test_grease_key_exchange_modes_keep_their_values(self) -> None:
        from pcapkit.const.tls.psk_key_exchange_mode import PskKeyExchangeMode
        from pcapkit.protocols.application.tls.protocol import TLS

        wire = _client_hello(_ext(45, _vec(bytes(self.PSK_KEY_EXCHANGE_MODES) + b'\x01', 1)))
        parsed = TLS(wire, len(wire))
        modes, = parsed.info.content[0].body.extensions
        self.assertEqual(tuple(int(mode) for mode in modes.data.ke_modes), self.PSK_KEY_EXCHANGE_MODES + (1,))
        self.assertTrue(all(isinstance(mode, PskKeyExchangeMode) for mode in modes.data.ke_modes))
        self.assertEqual(bytes(TLS.from_data(parsed.info)).hex(), wire.hex())


class HelloExtensionRegistryTests(unittest.TestCase):
    """The IANA value sets the extensions use, as their crawlers render them."""

    def test_names_and_ranges(self) -> None:
        from pcapkit.const.tls.certificate_compression_algorithm import CertificateCompressionAlgorithm
        from pcapkit.const.tls.certificate_status_type import CertificateStatusType
        from pcapkit.const.tls.ec_point_format import ECPointFormat
        from pcapkit.const.tls.psk_key_exchange_mode import PskKeyExchangeMode

        for enum, width, members in (
                (ECPointFormat, 8, {0: 'uncompressed', 1: 'ansiX962_compressed_prime',
                                    2: 'ansiX962_compressed_char2'}),
                (CertificateStatusType, 8, {0: 'Reserved_0', 1: 'ocsp'}),
                (PskKeyExchangeMode, 8, {0: 'psk_ke', 1: 'psk_dhe_ke'}),
                (CertificateCompressionAlgorithm, 16, {0: 'Reserved_0', 1: 'zlib', 2: 'brotli', 3: 'zstd'}),
        ):
            with self.subTest(enum=enum.__name__):
                for value, name in members.items():
                    self.assertEqual(enum(value).name, name)
                # NOTE: the probes come from ``_missing_``'s own ranges, so an IANA assignment
                # moves them rather than turning the test red.
                ranges = _missing_ranges(enum)
                self.assertIn('Unassigned', ranges)
                for name, spans in ranges.items():
                    for low, high in spans:
                        self.assertEqual((enum(low).name, enum(high).name), (name, name))
                with self.assertRaises(ValueError):
                    enum(1 << width)

    def test_crawlers_read_their_own_columns(self) -> None:
        from pcapkit.vendor.tls.certificate_compression_algorithm import CertificateCompressionAlgorithm
        from pcapkit.vendor.tls.certificate_status_type import CertificateStatusType
        from pcapkit.vendor.tls.ec_point_format import ECPointFormat
        from pcapkit.vendor.tls.psk_key_exchange_mode import PskKeyExchangeMode

        five = ['Value,Description,Other,Reference,Comment', '1,first,Y,[RFC 8422],A note.', '2-9,Unassigned,,,']
        four = ['Value,Description,Reference,Comment', '1,first,[RFC 8422],A note.', '2-9,Unassigned,,']
        for cls, data in ((ECPointFormat, five), (PskKeyExchangeMode, five),
                          (CertificateStatusType, four), (CertificateCompressionAlgorithm, four)):
            with self.subTest(crawler=cls.__name__):
                crawler = object.__new__(cls)
                crawler.NAME = cls.__name__
                crawler.record = crawler.count(data)
                enum, miss = crawler.process(data)
                self.assertEqual(enum, ['#: first [:rfc:`8422`] -- A note.\n    first = 1'])
                self.assertEqual(miss[0], 'if 2 <= value <= 9:')
                self.assertEqual(miss[2], "    return cls._unregistered_member(value, 'Unassigned')")


if __name__ == '__main__':
    unittest.main()
