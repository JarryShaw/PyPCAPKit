# -*- coding: utf-8 -*-
"""An ``encrypted_client_hello``'s HPKE identifiers are members of the IANA HPKE registries (#2851).

``ECHConfig``'s ``kem_id`` and ``HpkeSymmetricCipherSuite``'s ``kdf_id`` and
``aead_id`` (RFC 9849 section 4) parse as ``HpkeKemId``, ``HpkeKdfId`` and
``HpkeAeadId`` members, an unassigned code included, with the octets unchanged
both ways; ``make`` takes a member or an ``int`` and refuses anything else.

"""
from __future__ import annotations

import ast
import inspect
import textwrap
import unittest

from tests._support import reimport_once_per_class

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


def _encrypted_extensions(*extensions: bytes) -> bytes:
    return _record(_handshake(8, _vec(b''.join(extensions))))


def _u16(code: int) -> bytes:
    return code.to_bytes(2, 'big')


def _outer(kdf_id: int, aead_id: int) -> bytes:
    """An outer ``ECHClientHello`` (RFC 9849 section 5) for one cipher suite, config 0x2A."""
    return _ext(0xFE0D, b'\x00' + _u16(kdf_id) + _u16(aead_id) + b'\x2a' + _vec(bytes(range(32)))
                + _vec(bytes(range(16))))


def _config(kem_id: int, *suites: 'tuple[int, int]') -> bytes:
    """An ``ECHConfig`` of version 0xFE0D (RFC 9849 section 4), with no extensions."""
    return b'\xfe\x0d' + _vec(b'\x2a' + _u16(kem_id) + _vec(bytes(range(32)))
                              + _vec(b''.join(_u16(kdf) + _u16(aead) for kdf, aead in suites))
                              + b'\x00' + _vec(b'public.example', 1) + _vec(b''))


def _unassigned(cls: type) -> int:
    """The lowest code ``cls._missing_`` calls ``Unassigned``, so an IANA assignment moves it."""
    func = ast.parse(textwrap.dedent(inspect.getsource(cls._missing_))).body[0]  # type: ignore[attr-defined]
    lows = []
    for node in ast.walk(func):
        if isinstance(node, ast.If) and isinstance(node.test, ast.Compare) and len(node.test.ops) == 2:
            calls = [n for stmt in node.body for n in ast.walk(stmt) if isinstance(n, ast.Call)]
            if any(ast.literal_eval(call.args[1]) == 'Unassigned' for call in calls
                   if isinstance(call.func, ast.Attribute) and call.func.attr == '_unregistered_member'):
                lows.append(ast.literal_eval(node.test.left))
    assert lows, f'{cls.__name__}._missing_ defines no Unassigned range'
    return min(lows)


class HpkeRegistryTests(unittest.TestCase):
    """The registries name RFC 9180 section 7's identifiers."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_rfc_9180_identifiers(self) -> None:
        from pcapkit.const.tls.hpke_aead_id import HpkeAeadId
        from pcapkit.const.tls.hpke_kdf_id import HpkeKdfId
        from pcapkit.const.tls.hpke_kem_id import HpkeKemId

        # NOTE: RFC 9180 section 7.1 table 2, section 7.2 table 3 and section 7.3 table 5.
        for cls, value, name in (
                (HpkeKemId, 0x0010, 'DHKEM_P_256_HKDF_SHA256'), (HpkeKemId, 0x0011, 'DHKEM_P_384_HKDF_SHA384'),
                (HpkeKemId, 0x0012, 'DHKEM_P_521_HKDF_SHA512'), (HpkeKemId, 0x0020, 'DHKEM_X25519_HKDF_SHA256'),
                (HpkeKemId, 0x0021, 'DHKEM_X448_HKDF_SHA512'), (HpkeKdfId, 0x0001, 'HKDF_SHA256'),
                (HpkeKdfId, 0x0002, 'HKDF_SHA384'), (HpkeKdfId, 0x0003, 'HKDF_SHA512'),
                (HpkeAeadId, 0x0001, 'AES_128_GCM'), (HpkeAeadId, 0x0002, 'AES_256_GCM'),
                (HpkeAeadId, 0x0003, 'ChaCha20Poly1305'), (HpkeAeadId, 0xFFFF, 'Export_only'),
                (HpkeKemId, 0x0000, 'Reserved_0x0000'), (HpkeKdfId, 0x0000, 'Reserved_0x0000'),
                (HpkeAeadId, 0x0000, 'Reserved_0x0000'),
        ):
            with self.subTest(registry=cls.__name__, value=hex(value)):
                self.assertIs(cls.get(value), cls[name])
                self.assertEqual(int(cls[name]), value)

        for cls in (HpkeKemId, HpkeKdfId, HpkeAeadId):
            with self.subTest(registry=cls.__name__):
                code = _unassigned(cls)
                self.assertEqual(cls.get(code).name, 'Unassigned')
                self.assertEqual(int(cls.get(code)), code)
                with self.assertRaises(ValueError):
                    cls(0x10000)

    def test_exported_from_pcapkit_const(self) -> None:
        import pcapkit.const as const
        import pcapkit.const.tls as tls
        from pcapkit.const.tls.hpke_aead_id import HpkeAeadId
        from pcapkit.const.tls.hpke_kdf_id import HpkeKdfId
        from pcapkit.const.tls.hpke_kem_id import HpkeKemId

        for name, cls in (('TLS_HpkeKemId', HpkeKemId), ('TLS_HpkeKdfId', HpkeKdfId),
                          ('TLS_HpkeAeadId', HpkeAeadId)):
            with self.subTest(name=name):
                self.assertIs(getattr(tls, name), cls)
                self.assertIs(getattr(const, name), cls)


class EchHpkeFieldTests(unittest.TestCase):
    """The ``encrypted_client_hello`` fields parse to members and rebuild byte for byte."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _parse(self, wire: bytes) -> 'object':
        """The ``encrypted_client_hello`` body of ``wire``, once both rebuilds give ``wire`` back."""
        from pcapkit.protocols.application.tls.protocol import TLS

        parsed = TLS(wire, len(wire))
        self.assertEqual(bytes(TLS.from_data(parsed.info)).hex(), wire.hex())
        maker = object.__new__(TLS)
        made = maker.make(content_type=parsed.info.content_type, version=parsed.info.version,
                          content=parsed.info.content)
        self.assertEqual(bytes(made).hex(), wire.hex())
        ech, = parsed.info.content[0].body.extensions
        return ech.data

    def test_outer_cipher_suite(self) -> None:
        from pcapkit.const.tls.hpke_aead_id import HpkeAeadId
        from pcapkit.const.tls.hpke_kdf_id import HpkeKdfId

        suite = self._parse(_client_hello(_outer(0x0001, 0x0003))).cipher_suite  # type: ignore[attr-defined]
        self.assertIs(suite.kdf_id, HpkeKdfId.HKDF_SHA256)
        self.assertIs(suite.aead_id, HpkeAeadId.ChaCha20Poly1305)

    def test_retry_config(self) -> None:
        from pcapkit.const.tls.hpke_aead_id import HpkeAeadId
        from pcapkit.const.tls.hpke_kdf_id import HpkeKdfId
        from pcapkit.const.tls.hpke_kem_id import HpkeKemId

        body = self._parse(_encrypted_extensions(_ext(0xFE0D, _vec(_config(0x0020, (0x0001, 0x0001),
                                                                          (0x0003, 0xFFFF))))))
        key = body.retry_configs[0].contents.key_config  # type: ignore[attr-defined]
        self.assertIs(key.kem_id, HpkeKemId.DHKEM_X25519_HKDF_SHA256)
        self.assertEqual([(suite.kdf_id, suite.aead_id) for suite in key.cipher_suites],
                         [(HpkeKdfId.HKDF_SHA256, HpkeAeadId.AES_128_GCM),
                          (HpkeKdfId.HKDF_SHA512, HpkeAeadId.Export_only)])
        for value in (key.kem_id, *(item for suite in key.cipher_suites for item in (suite.kdf_id, suite.aead_id))):
            self.assertIn(type(value), (HpkeKemId, HpkeKdfId, HpkeAeadId))

    def test_unassigned_codes(self) -> None:
        from pcapkit.const.tls.hpke_aead_id import HpkeAeadId
        from pcapkit.const.tls.hpke_kdf_id import HpkeKdfId
        from pcapkit.const.tls.hpke_kem_id import HpkeKemId

        kem, kdf, aead = _unassigned(HpkeKemId), _unassigned(HpkeKdfId), _unassigned(HpkeAeadId)
        suite = self._parse(_client_hello(_outer(kdf, aead))).cipher_suite  # type: ignore[attr-defined]
        body = self._parse(_encrypted_extensions(_ext(0xFE0D, _vec(_config(kem, (kdf, aead))))))
        key = body.retry_configs[0].contents.key_config  # type: ignore[attr-defined]
        for value, cls, code in ((suite.kdf_id, HpkeKdfId, kdf), (suite.aead_id, HpkeAeadId, aead),
                                 (key.kem_id, HpkeKemId, kem), (key.cipher_suites[0].kdf_id, HpkeKdfId, kdf),
                                 (key.cipher_suites[0].aead_id, HpkeAeadId, aead)):
            with self.subTest(registry=cls.__name__):
                self.assertIsInstance(value, cls)
                self.assertEqual((value.name, int(value)), ('Unassigned', code))


class EchHpkeMakeTests(unittest.TestCase):
    """``make`` resolves each identifier through ``_make_index``."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _hello(extensions: 'tuple', *, msg_type: str = 'client_hello') -> bytes:
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.const.tls.handshake_type import HandshakeType
        from pcapkit.protocols.application.ssl.data import ClientHello, EncryptedExtensions, Handshake
        from pcapkit.protocols.application.tls.protocol import TLS

        if msg_type == 'encrypted_extensions':
            body = EncryptedExtensions(extensions=extensions)  # type: object
        else:
            body = ClientHello(version=0x0303, random=bytes(range(32)), session_id=b'', cookie=None,
                               cipher_suites=(0x1301,), compression_methods=(0,), extensions=extensions)
        maker = object.__new__(TLS)
        return bytes(maker.make(content_type=ContentType.handshake, version=0x0303,
                                content=(Handshake(msg_type=HandshakeType[msg_type], length=0, body=body),)))

    @classmethod
    def _retry(cls, kem_id: object, kdf_id: object, aead_id: object) -> bytes:
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.protocols.application.ssl import data as D

        key = D.HpkeKeyConfig(config_id=0x2A, kem_id=kem_id, public_key=bytes(range(32)),
                              cipher_suites=(D.HpkeSymmetricCipherSuite(kdf_id=kdf_id, aead_id=aead_id),))
        contents = D.ECHConfigContents(key_config=key, maximum_name_length=0, public_name=b'public.example',
                                       extensions=())
        return cls._hello(((ExtensionType.encrypted_client_hello, {
            'retry_configs': (D.ECHConfig(version=0xFE0D, contents=contents),)}),), msg_type='encrypted_extensions')

    @classmethod
    def _outer(cls, kdf_id: object, aead_id: object) -> bytes:
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.protocols.application.ssl.data import HpkeSymmetricCipherSuite

        return cls._hello(((ExtensionType.encrypted_client_hello, {
            'cipher_suite': HpkeSymmetricCipherSuite(kdf_id=kdf_id, aead_id=aead_id), 'config_id': 0x2A,
            'enc': bytes(range(32)), 'payload': bytes(range(16))}),))

    def test_member_or_int(self) -> None:
        from pcapkit.const.tls.hpke_aead_id import HpkeAeadId
        from pcapkit.const.tls.hpke_kdf_id import HpkeKdfId
        from pcapkit.const.tls.hpke_kem_id import HpkeKemId

        retry = _encrypted_extensions(_ext(0xFE0D, _vec(_config(0x0020, (0x0001, 0x0003)))))
        for kem, kdf, aead in ((HpkeKemId.DHKEM_X25519_HKDF_SHA256, HpkeKdfId.HKDF_SHA256, HpkeAeadId.ChaCha20Poly1305),
                               (0x0020, 0x0001, 0x0003)):
            with self.subTest(kind=type(kem).__name__):
                self.assertEqual(self._retry(kem, kdf, aead).hex(), retry.hex())
                self.assertEqual(self._outer(kdf, aead).hex(), _client_hello(_outer(0x0001, 0x0003)).hex())

    def test_refuses_what_is_not_a_two_octet_code(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        for bad in (None, 'HKDF_SHA256', True, -1, 0x10000, 1.0):
            for field, build in (('kdf_id', lambda v: self._outer(v, 1)), ('aead_id', lambda v: self._outer(1, v)),
                                 ('kem_id', lambda v: self._retry(v, 1, 1)),
                                 ('kdf_id', lambda v: self._retry(0x20, v, 1)),
                                 ('aead_id', lambda v: self._retry(0x20, 1, v))):
                with self.subTest(field=field, value=bad), \
                        self.assertRaisesRegex(ProtocolError, rf'invalid encrypted_client_hello\.{field}: '):
                    build(bad)


if __name__ == '__main__':
    unittest.main()
