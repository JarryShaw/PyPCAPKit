# -*- coding: utf-8 -*-
"""HIP verifies its HMAC and signature parameters with caller supplied keys.

GitHub issue #2939: given a ``HIPContext``, HIP verifies ``HIP_MAC`` and ``HIP_MAC_2``
(RFC 7401 section 6.4.1) and ``HIP_SIGNATURE`` and ``HIP_SIGNATURE_2`` (section 6.4.2),
and records the outcome as the parameter's ``hmac_status`` or ``signature_status``,
changing nothing else of the parse. The packets are written out by hand, and the
HMACs, signatures and KEYMAT computed here with :mod:`hmac` and ``cryptography``, not
with pcapkit.

"""
from __future__ import annotations

import hmac
import importlib.util
import ipaddress
import struct
import sys
import types
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class

HAS_CRYPTO = importlib.util.find_spec('cryptography') is not None

#: The Initiator's and the Responder's HITs: ORCHIDs whose OGA ID is 1, RSA,DSA/SHA-256.
HIT_I = ipaddress.IPv6Address('2001:21::1')
HIT_R = ipaddress.IPv6Address('2001:21::2')
#: HIP-gl and HIP-lg integrity keys, of SHA-256's length; HIT_R is HOST_g.
KEY_GL, KEY_LG = bytes(range(32)), bytes(range(32, 64))

#: Packet types (RFC 7401 section 5.3).
R1, I2, R2, UPDATE = 2, 3, 4, 16
#: Parameter types (RFC 7401 section 5.2).
SEQ, PUZZLE, HOST_ID, ECHO_RESPONSE_UNSIGNED = 385, 257, 705, 63425
HIP_MAC, HIP_MAC_2, HIP_SIGNATURE_2, HIP_SIGNATURE = 61505, 61569, 61633, 61697
#: Host Identity algorithms (RFC 7401 section 5.2.9, RFC 9374 section 3.4.1).
DSA, RSA, ECDSA, ECDSA_LOW, EDDSA = 3, 5, 7, 9, 13

#: A SEQ parameter, Update ID 7.
SEQ_TLV = struct.pack('!HHI', SEQ, 4, 7)


def tlv(code: int, value: bytes) -> bytes:
    """A parameter of type ``code`` holding ``value``, padded to 8 octets."""
    record = struct.pack('!HH', code, len(value)) + value
    return record + bytes(-len(record) % 8)


def packet(ptype: int, sender: object, receiver: object, *params: bytes, version: int = 2) -> bytes:
    """A HIP packet, its Checksum non-zero as on the wire."""
    body = b''.join(params)
    return (bytes([59, (40 + len(body)) // 8 - 1, ptype, version << 4 | 1]) + b'\x5a\xa5'
            + b'\x00\x00' + sender.packed + receiver.packed + body)  # type: ignore[attr-defined]


def covered(octets: bytes, extra: bytes = b'') -> bytes:
    """``octets`` and ``extra`` as RFC 7401 section 6.4 covers them: Checksum zeroed,
    Header Length counting them."""
    scope = bytearray(octets + extra)
    scope[1] = len(scope) // 8 - 1
    scope[4:6] = b'\x00\x00'
    return bytes(scope)


def mac(key: bytes, octets: bytes, extra: bytes = b'', digest: str = 'sha256') -> bytes:
    """The HMAC over what ``octets`` and ``extra`` cover."""
    return hmac.new(key, covered(octets, extra), digest).digest()


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int, digest: str = 'sha256') -> bytes:
    """HKDF, RFC 5869 section 2."""
    prk, block, okm = hmac.new(salt, ikm, digest).digest(), b'', b''
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([len(okm) // len(prk) + 1]), digest).digest()
        okm += block
    return okm[:length]


def host_id(algorithm: int, hi: bytes, di: bytes = b'') -> bytes:
    """A HOST_ID parameter, its Domain Identifier an FQDN when ``di`` is given."""
    di_word = (1 << 12 | len(di)) if di else 0
    return tlv(HOST_ID, struct.pack('!HHH', len(hi), di_word, algorithm) + hi + di)


class AuthTestCase(unittest.TestCase):
    """Imports and helpers every test here shares."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import protocol as hip_module
        from pcapkit.protocols.internet.hip.protocol import (HIP, HIPAssociation, HIPAuthStatus,
                                                             HIPContext, HIPIdentity)
        from pcapkit.utilities.exceptions import ProtocolError
        from pcapkit.utilities.warnings import ProtocolWarning

        self.HIP, self.Parameter, self.module = HIP, Parameter, hip_module
        self.Association, self.Identity, self.Context = HIPAssociation, HIPIdentity, HIPContext
        self.Status, self.ProtocolError, self.ProtocolWarning = HIPAuthStatus, ProtocolError, ProtocolWarning

    def parse(self, octets: bytes, *keys: object, context: object = ...) -> 'tuple[object, list[str]]':
        """``octets`` parsed as HIP with ``keys``, and the ProtocolWarnings it raised."""
        if context is ...:
            context = self.Context(*keys)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            layer = self.HIP(octets, context=context)
        return layer, [str(item.message) for item in caught
                       if issubclass(item.category, self.ProtocolWarning)]

    def status(self, octets: bytes, code: int, *keys: object) -> 'tuple[object, list[str]]':
        """The status the parameter ``code`` of ``octets`` records, and the warnings."""
        layer, messages = self.parse(octets, *keys)
        param = layer.info.parameters[self.Parameter(code)]
        return param.get('hmac_status', param.get('signature_status')), messages

    def association(self, **kwargs: object) -> object:
        """The association of HIT_I and HIT_R."""
        return self.Association(HIT_I, HIT_R, **{'integrity_gl': KEY_GL, 'integrity_lg': KEY_LG, **kwargs})

    def identity(self, hit: object, algorithm: int, hi: bytes, di: bytes = b'') -> object:
        """The identity of ``hit``, from a HOST_ID as an R1 carries it."""
        r1 = self.HIP(packet(R1, hit, HIT_I, host_id(algorithm, hi, di)))
        return self.Identity(hit, r1.info.parameters[self.Parameter.HOST_ID])


class HMACTests(AuthTestCase):
    """HIP_MAC and HIP_MAC_2, RFC 7401 section 6.4.1."""

    def update(self, sender: object, receiver: object, key: bytes) -> bytes:
        """An UPDATE with a HIP_MAC, and an ECHO_RESPONSE_UNSIGNED it leaves out."""
        head = packet(UPDATE, sender, receiver, SEQ_TLV)
        return packet(UPDATE, sender, receiver, SEQ_TLV, tlv(HIP_MAC, mac(key, head)),
                      tlv(ECHO_RESPONSE_UNSIGNED, b'echo'))

    def test_each_host_sends_under_its_own_key(self) -> None:
        for sender, receiver, key in ((HIT_R, HIT_I, KEY_GL), (HIT_I, HIT_R, KEY_LG)):
            with self.subTest(sender=str(sender)):
                octets = self.update(sender, receiver, key)
                self.assertEqual(self.status(octets, HIP_MAC, self.association()),
                                 (self.Status.VALID, []))
                swapped = self.association(integrity_gl=KEY_LG, integrity_lg=KEY_GL)
                status, messages = self.status(octets, HIP_MAC, swapped)
                self.assertIs(status, self.Status.INVALID)
                self.assertEqual(messages, ['HIPv2: HIP_MAC: the HMAC does not verify'])

    def test_covers_the_header_and_the_parameters_before_it(self) -> None:
        octets = self.update(HIT_R, HIT_I, KEY_GL)
        # Packet Type, Version, Controls and the SEQ; a HIT would change the association.
        for at in (2, 3, 6, 44):
            with self.subTest(at=at):
                tampered = octets[:at] + bytes([octets[at] ^ 1]) + octets[at + 1:]
                self.assertIs(self.status(tampered, HIP_MAC, self.association())[0], self.Status.INVALID)
        # Not the Checksum, its own padding, nor the ECHO_RESPONSE_UNSIGNED after it.
        for at in (4, 5, len(octets) - 9, len(octets) - 1):
            with self.subTest(at=at):
                tampered = octets[:at] + bytes([octets[at] ^ 1]) + octets[at + 1:]
                self.assertIs(self.status(tampered, HIP_MAC, self.association())[0], self.Status.VALID)

    def test_no_key_is_quiet_and_no_context_records_nothing(self) -> None:
        octets = self.update(HIT_R, HIT_I, KEY_GL)
        other = self.Association('2001:21::3', HIT_R, integrity_gl=KEY_GL, integrity_lg=KEY_LG)
        self.assertEqual(self.status(octets, HIP_MAC, other), (self.Status.NO_KEY, []))
        layer, messages = self.parse(octets, context=None)
        self.assertNotIn('hmac_status', layer.info.parameters[self.Parameter.HIP_MAC])
        self.assertEqual(messages, [])

    def test_hip_mac_2_covers_the_responders_host_id(self) -> None:
        hi_tlv = host_id(RSA, b'\x01\x03' + bytes(range(1, 65)), b'\x03www\x07example\x00')
        head = packet(R2, HIT_R, HIT_I, SEQ_TLV)
        octets = packet(R2, HIT_R, HIT_I, SEQ_TLV, tlv(HIP_MAC_2, mac(KEY_GL, head, hi_tlv)))
        identity = self.identity(HIT_R, RSA, b'\x01\x03' + bytes(range(1, 65)), b'\x03www\x07example\x00')
        self.assertEqual(self.status(octets, HIP_MAC_2, self.association(), identity),
                         (self.Status.VALID, []))
        # Without the Responder's identity there is nothing to append, and without it
        # appended the HMAC is not HIP_MAC_2's.
        self.assertEqual(self.status(octets, HIP_MAC_2, self.association()), (self.Status.NO_KEY, []))
        other = self.identity(HIT_R, RSA, b'\x01\x03' + bytes(range(2, 66)))
        self.assertIs(self.status(octets, HIP_MAC_2, self.association(), other)[0], self.Status.INVALID)

    def test_hip_mac_2_whose_header_length_cannot_count_its_scope(self) -> None:
        # 2008 octets before HIP_MAC_2, then a HOST_ID of 80: past the 2048 Header Length counts.
        filler = tlv(SEQ + 2, bytes(1964))
        octets = packet(R2, HIT_R, HIT_I, filler, tlv(HIP_MAC_2, bytes(32)))
        identity = self.identity(HIT_R, RSA, b'\x01\x03' + bytes(range(1, 65)))
        status, messages = self.status(octets, HIP_MAC_2, self.association(), identity)
        self.assertIs(status, self.Status.INVALID)
        self.assertEqual(messages, ['HIPv2: HIP_MAC_2: the Header Length cannot count what the HMAC covers'])

    def test_suite_selects_rhash(self) -> None:
        # The OGA ID of the Responder's HIT, 2 here, names ECDSA/SHA-384.
        responder = ipaddress.IPv6Address('2001:22::2')
        keys = bytes(48), bytes(range(48))
        head = packet(UPDATE, HIT_I, responder, SEQ_TLV)
        octets = packet(UPDATE, HIT_I, responder, SEQ_TLV, tlv(HIP_MAC, mac(keys[1], head, digest='sha384')))
        association = self.Association(HIT_I, responder, integrity_gl=keys[0], integrity_lg=keys[1])
        self.assertEqual(association.suite.name, 'ECDSA_SHA_384')
        self.assertEqual(self.status(octets, HIP_MAC, association), (self.Status.VALID, []))
        explicit = self.Association('2001:db8::1', '2001:db8::2', suite=3,
                                    integrity_gl=bytes(20), integrity_lg=bytes(20))
        self.assertEqual(explicit.suite.name, 'ECDSA_LOW_SHA_1')

    def test_hip_version_1_is_not_verified(self) -> None:
        head = packet(UPDATE, HIT_R, HIT_I, SEQ_TLV, version=1)
        octets = packet(UPDATE, HIT_R, HIT_I, SEQ_TLV, tlv(HIP_MAC, mac(KEY_GL, head)), version=1)
        status, messages = self.status(octets, HIP_MAC, self.association())
        self.assertIs(status, self.Status.UNSUPPORTED)
        self.assertEqual(messages, ['HIPv1: HIP_MAC: only HIP version 2 is verified'])

    def test_verified_inside_ipv4_and_ipv6(self) -> None:
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.internet.ipv6.protocol import IPv6

        octets = self.update(HIT_R, HIT_I, KEY_GL)
        context = self.Context(self.association())
        v4 = (b'\x45\x00' + (20 + len(octets)).to_bytes(2, 'big') + bytes(4) + b'\x40\x8b'
              + bytes(2) + bytes([192, 0, 2, 1, 192, 0, 2, 2]))
        v6 = (b'\x60\x00\x00\x00' + len(octets).to_bytes(2, 'big') + b'\x8b\x40'
              + ipaddress.IPv6Address('2001:db8::1').packed + ipaddress.IPv6Address('2001:db8::2').packed)
        for ip, cls in ((v4, IPv4), (v6, IPv6)):
            with self.subTest(ip=cls.__name__), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                layer = cls(ip + octets, context=context)
                hip = layer.payload if cls is IPv4 else layer.extension_headers.getlist(139)[0]
                self.assertIs(hip.info.parameters[self.Parameter.HIP_MAC].hmac_status, self.Status.VALID)
                self.assertEqual(cls.from_data(layer.info).data, ip + octets)

    def test_rebuilds_byte_for_byte_and_reports_the_status(self) -> None:
        octets = self.update(HIT_R, HIT_I, KEY_GL)
        layer, _ = self.parse(octets, self.association())
        self.assertEqual(self.HIP.from_data(layer.info).data, octets)
        self.assertEqual(layer.info.to_dict()['parameters'][self.Parameter.HIP_MAC]['hmac_status'],
                         self.Status.VALID)


class KeymatTests(AuthTestCase):
    """KEYMAT, RFC 7401 section 6.5, and the association's arguments."""

    def test_hkdf_matches_rfc_5869(self) -> None:
        # RFC 5869 Appendix A.1.
        okm = self.Association._hkdf('sha256', bytes(range(13)), b'\x0b' * 22,
                                     bytes(range(0xf0, 0xfa)), 42)
        self.assertEqual(okm.hex(), '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c'
                                    '5db02d56ecc4c5bf34007208d5b887185865')
        self.assertEqual(hkdf(bytes(range(13)), b'\x0b' * 22, bytes(range(0xf0, 0xfa)), 42), okm)

    def test_draws_the_integrity_keys(self) -> None:
        initiator = ipaddress.IPv6Address('2001:21::9')  # HOST_g, so sort() puts HIT_R first
        kij, random_i, random_j = bytes(range(100, 164)), bytes(range(32)), bytes(range(1, 33))
        for cipher, enc in ((1, 0), (2, 16), (4, 32)):
            with self.subTest(cipher=cipher):
                keymat = hkdf(random_i + random_j, kij, HIT_R.packed + initiator.packed, 2 * (enc + 32))
                association = self.Association.from_keymat(initiator, HIT_R, kij=kij, random_i=random_i,
                                                           random_j=random_j, cipher=cipher)
                self.assertEqual(association.integrity_gl, keymat[enc:enc + 32])
                self.assertEqual(association.integrity_lg, keymat[2 * enc + 32:])
        as_ints = self.Association.from_keymat(initiator, HIT_R, kij=kij, cipher=4,
                                               random_i=int.from_bytes(random_i, 'big'),
                                               random_j=int.from_bytes(random_j, 'big'))
        self.assertEqual(as_ints.integrity_lg, association.integrity_lg)

    def test_refuses_bad_arguments(self) -> None:
        good = {'integrity_gl': KEY_GL, 'integrity_lg': KEY_LG}
        cases = [
            ((True, HIT_R), good),
            (('2001:db8::zz', HIT_R), good),
            ((HIT_I, HIT_I), good),
            ((HIT_I, '2001:db8::2'), good),
            ((HIT_I, HIT_R), {**good, 'suite': True}),
            ((HIT_I, HIT_R), {**good, 'suite': 'RSA_DSA_SHA_256'}),
            ((HIT_I, HIT_R), {**good, 'suite': 5}),
            ((HIT_I, HIT_R), {**good, 'suite': 99}),
            ((HIT_I, HIT_R), {'integrity_gl': KEY_GL, 'integrity_lg': KEY_LG[:20]}),
        ]
        for args, kwargs in cases:
            with self.subTest(args=args, kwargs=kwargs), self.assertRaises(self.ProtocolError):
                self.Association(*args, **kwargs)
        keymat = {'kij': b'k', 'random_i': bytes(32), 'random_j': bytes(32), 'cipher': 2}
        for bad in ({'cipher': 3}, {'cipher': True}, {'cipher': 'AES_128_CBC'}, {'random_i': True},
                    {'random_j': 1 << 256}, {'random_i': 'ab'}):
            with self.subTest(bad=bad), self.assertRaises(self.ProtocolError):
                self.Association.from_keymat(HIT_I, HIT_R, **{**keymat, **bad})

    def test_repr_holds_no_key(self) -> None:
        association = self.association()
        self.assertEqual(repr(association), '<HIPAssociation initiator=2001:21::1 '
                                            'responder=2001:21::2 suite=RSA_DSA_SHA_256>')
        self.assertEqual((association.initiator, association.responder), (HIT_I, HIT_R))
        self.assertTrue(association.matches(HIT_R, HIT_I))
        self.assertFalse(association.matches(HIT_R, '2001:21::3'))


class ContextTests(AuthTestCase):
    """HIPContext and HIPIdentity themselves."""

    def test_registers_and_matches(self) -> None:
        identity = self.identity(HIT_R, RSA, b'\x01\x03' + bytes(64))
        association = self.association()
        context = self.Context(identity, association)
        self.assertEqual(self.Context.protocol(), ('HIP',))
        self.assertEqual((context.identities, context.associations), ((identity,), (association,)))
        self.assertIs(context.match_identity(HIT_R.packed), identity)
        self.assertIsNone(context.match_identity(int(HIT_I)))
        self.assertIs(context.match_association(HIT_I, HIT_R), association)
        self.assertIsNone(context.match_association(HIT_I, '2001:21::3'))
        self.assertEqual(repr(context), '<HIPContext identities=1 associations=1 registrations=0>')
        self.assertEqual(repr(identity), '<HIPIdentity hit=2001:21::2 algorithm=RSA>')
        self.assertEqual(identity.hit, HIT_R)
        self.assertEqual(identity.host_id.algorithm, RSA)

    def test_refuses_what_is_no_key(self) -> None:
        with self.assertRaises(self.ProtocolError):
            self.Context(b'key')
        with self.assertRaises(self.ProtocolError):
            self.Identity(HIT_R, b'\x01\x03')


class SignatureStatusTests(AuthTestCase):
    """The signature outcomes decided before ``cryptography`` is reached."""

    def unsigned(self, algorithm: int) -> bytes:
        """An UPDATE from HIT_R whose HIP_SIGNATURE of ``algorithm`` holds zeros."""
        return packet(UPDATE, HIT_R, HIT_I, SEQ_TLV,
                      tlv(HIP_SIGNATURE, struct.pack('!H', algorithm) + bytes(128)))

    def test_no_identity_and_a_mismatched_algorithm(self) -> None:
        identity = self.identity(HIT_R, RSA, b'\x01\x03' + bytes(64))
        self.assertEqual(self.status(self.unsigned(RSA), HIP_SIGNATURE, self.association()),
                         (self.Status.NO_KEY, []))
        self.assertEqual(self.status(self.unsigned(DSA), HIP_SIGNATURE, identity), (self.Status.INVALID, [
            "HIPv2: HIP_SIGNATURE: signature algorithm DSA is not the Host Identity's RSA"]))

    def test_without_cryptography_a_signature_is_unsupported(self) -> None:
        identity = self.identity(HIT_R, RSA, b'\x01\x03' + bytes(64))
        with mock.patch.object(self.module, '_load_cryptography', return_value=None):
            status = self.status(self.unsigned(RSA), HIP_SIGNATURE, identity)
        self.assertEqual(status, (self.Status.UNSUPPORTED, [
            'HIPv2: HIP_SIGNATURE: verifying a signature needs the optional "cryptography" '
            'dependency, which is not installed (pip install pypcapkit[crypto])']))
        with mock.patch.object(self.module, '_CRYPTO', NotImplemented), \
                mock.patch.dict(sys.modules, {'cryptography': None}):
            self.assertIsNone(self.module._load_cryptography())


@unittest.skipUnless(HAS_CRYPTO, 'cryptography not installed')
class SignatureTests(AuthTestCase):
    """HIP_SIGNATURE and HIP_SIGNATURE_2, RFC 7401 section 6.4.2."""

    def setUp(self) -> None:
        super().setUp()
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        self.hashes, self.padding, self.ec = hashes, padding, ec
        self.decode, self.Encoding, self.PublicFormat = decode_dss_signature, Encoding, PublicFormat
        cls = type(self)
        if not hasattr(cls, 'keys'):
            cls.keys = types.SimpleNamespace(
                rsa=rsa.generate_private_key(public_exponent=65537, key_size=1024),
                dsa=dsa.generate_private_key(key_size=1024),
                p256=ec.generate_private_key(ec.SECP256R1()),
                p384=ec.generate_private_key(ec.SECP384R1()),
                ed25519=ed25519.Ed25519PrivateKey.generate(),
                ed448=ed448.Ed448PrivateKey.generate(),
            )

    def rsa_hi(self) -> bytes:
        """The RSA Host Identity, RFC 3110 section 2."""
        numbers = self.keys.rsa.public_key().public_numbers()
        exponent = numbers.e.to_bytes(3, 'big')
        return bytes([len(exponent)]) + exponent + numbers.n.to_bytes(128, 'big')

    def dsa_hi(self) -> bytes:
        """The DSA Host Identity, RFC 2536 section 2, T being 8."""
        numbers = self.keys.dsa.public_key().public_numbers()
        params = numbers.parameter_numbers
        return (b'\x08' + params.q.to_bytes(20, 'big') + params.p.to_bytes(128, 'big')
                + params.g.to_bytes(128, 'big') + numbers.y.to_bytes(128, 'big'))

    def raw(self, name: str) -> bytes:
        """The raw public key of the EdDSA key ``name``."""
        return getattr(self.keys, name).public_key().public_bytes(self.Encoding.Raw, self.PublicFormat.Raw)

    def ec_point(self, key: object, form: str) -> bytes:
        """``key``'s public point as X9.62 encodes it in ``form``."""
        fmt = self.PublicFormat.CompressedPoint if form == 'compressed' else self.PublicFormat.UncompressedPoint
        return key.public_key().public_bytes(self.Encoding.X962, fmt)  # type: ignore[attr-defined]

    def sign(self, name: str, data: bytes) -> bytes:
        """``data`` signed with the key ``name``, as HIP_SIGNATURE encodes it."""
        key = getattr(self.keys, name)
        if name == 'rsa':
            return key.sign(data, self.padding.PSS(mgf=self.padding.MGF1(self.hashes.SHA256()),
                                                   salt_length=32), self.hashes.SHA256())
        if name == 'dsa':
            r, s = self.decode(key.sign(data, self.hashes.SHA256()))
            return b'\x08' + r.to_bytes(20, 'big') + s.to_bytes(20, 'big')
        if name in ('p256', 'p384'):
            size = 32 if name == 'p256' else 48
            r, s = self.decode(key.sign(data, self.ec.ECDSA(self.hashes.SHA384())))
            return r.to_bytes(size, 'big') + s.to_bytes(size, 'big')
        return key.sign(data)

    def signed(self, name: str, algorithm: int, *, ptype: int = UPDATE, tamper: int = 0) -> bytes:
        """A packet from HIT_R signed with ``name``, an octet before the signature flipped."""
        head = packet(ptype, HIT_R, HIT_I, SEQ_TLV)
        signature = self.sign(name, covered(head))
        octets = packet(ptype, HIT_R, HIT_I, SEQ_TLV,
                        tlv(HIP_SIGNATURE, struct.pack('!H', algorithm) + signature),
                        tlv(ECHO_RESPONSE_UNSIGNED, b'echo'))
        if tamper:
            octets = octets[:tamper] + bytes([octets[tamper] ^ 1]) + octets[tamper + 1:]
        return octets

    def test_each_algorithm(self) -> None:
        cases = [
            ('rsa', RSA, self.rsa_hi()),
            ('dsa', DSA, self.dsa_hi()),
            ('p256', ECDSA, b'\x00\x01' + self.ec_point(self.keys.p256, 'uncompressed')[1:]),
            ('p256', ECDSA, b'\x00\x01' + self.ec_point(self.keys.p256, 'uncompressed')),
            ('p256', ECDSA, b'\x00\x01' + self.ec_point(self.keys.p256, 'compressed')),
            ('p256', ECDSA, b'\x00\x01' + self.ec_point(self.keys.p256, 'compressed')[1:]),
            ('p384', ECDSA, b'\x00\x02' + self.ec_point(self.keys.p384, 'uncompressed')[1:]),
            ('p384', ECDSA, b'\x00\x02' + self.ec_point(self.keys.p384, 'compressed')[1:]),
            ('ed25519', EDDSA, b'\x00\x01' + self.raw('ed25519')),
            ('ed25519', EDDSA, b'\x00\x01\x00\x00' + self.raw('ed25519')),
            ('ed448', EDDSA, b'\x00\x03' + self.raw('ed448')),
        ]
        for name, algorithm, hi in cases:
            with self.subTest(name=name, hi=len(hi)):
                identity = self.identity(HIT_R, algorithm, hi)
                self.assertEqual(self.status(self.signed(name, algorithm), HIP_SIGNATURE, identity),
                                 (self.Status.VALID, []))
                status, messages = self.status(self.signed(name, algorithm, tamper=46), HIP_SIGNATURE,
                                               identity)
                self.assertIs(status, self.Status.INVALID)
                self.assertEqual(messages, ['HIPv2: HIP_SIGNATURE: the signature does not verify'])

    def test_hip_signature_2_zeroes_the_initiators_hit_and_the_puzzle(self) -> None:
        hi = self.rsa_hi()
        params = (tlv(PUZZLE, b'\x0a\x25' + b'\xaa\xbb' + bytes(range(32))), host_id(RSA, hi))
        presigned = bytearray(packet(R1, HIT_R, ipaddress.IPv6Address(0), *params))
        presigned[46:48 + 32] = bytes(34)  # PUZZLE's Opaque and Random #I
        sig = tlv(HIP_SIGNATURE_2, struct.pack('!H', RSA) + self.sign('rsa', covered(bytes(presigned))))
        octets = packet(R1, HIT_R, HIT_I, *params, sig)
        identity = self.identity(HIT_R, RSA, hi)
        self.assertEqual(self.status(octets, HIP_SIGNATURE_2, identity), (self.Status.VALID, []))
        # The Controls and #K stay covered.
        for at in (6, 44):
            with self.subTest(at=at):
                tampered = octets[:at] + bytes([octets[at] ^ 1]) + octets[at + 1:]
                self.assertIs(self.status(tampered, HIP_SIGNATURE_2, identity)[0], self.Status.INVALID)

    def test_r2_signature_covers_its_hip_mac_2(self) -> None:
        hi = self.rsa_hi()
        head = packet(R2, HIT_R, HIT_I, SEQ_TLV)
        with_mac = packet(R2, HIT_R, HIT_I, SEQ_TLV, tlv(HIP_MAC_2, mac(KEY_GL, head, host_id(RSA, hi))))
        sig = tlv(HIP_SIGNATURE, struct.pack('!H', RSA) + self.sign('rsa', covered(with_mac)))
        octets = packet(R2, HIT_R, HIT_I, SEQ_TLV, tlv(HIP_MAC_2, mac(KEY_GL, head, host_id(RSA, hi))), sig)
        layer, messages = self.parse(octets, self.identity(HIT_R, RSA, hi), self.association())
        params = layer.info.parameters
        self.assertEqual((params[self.Parameter.HIP_MAC_2].hmac_status,
                          params[self.Parameter.HIP_SIGNATURE].signature_status, messages),
                         (self.Status.VALID, self.Status.VALID, []))

    def test_what_cannot_verify(self) -> None:
        octets = self.signed('rsa', RSA)
        cases = [
            ('ecdsa_low', self.signed('rsa', ECDSA_LOW), self.identity(HIT_R, ECDSA_LOW, b'\x00\x01' + bytes(40)),
             self.Status.UNSUPPORTED, 'Host Identity algorithm ECDSA_LOW is not implemented'),
            ('curve', self.signed('rsa', ECDSA), self.identity(HIT_R, ECDSA, b'\x00\x00' + bytes(64)),
             self.Status.UNSUPPORTED, 'ECDSA curves other than NIST P-256 and P-384 are not implemented'),
            ('prehash', self.signed('rsa', EDDSA), self.identity(HIT_R, EDDSA, b'\x00\x02' + bytes(32)),
             self.Status.UNSUPPORTED, 'EdDSA curves other than EdDSA25519 and EdDSA448 are not implemented'),
        ]
        malformed = [
            ('rsa', octets, self.identity(HIT_R, RSA, b'\x00')),
            ('rsa-exponent', octets, self.identity(HIT_R, RSA, b'\x05\x01\x02' + bytes(64))),
            ('rsa-long-exponent', octets, self.identity(HIT_R, RSA, b'\x00\x00\x05\x01')),
            ('dsa-t', self.signed('dsa', DSA), self.identity(HIT_R, DSA, b'\x09' + bytes(40))),
            ('dsa-length', self.signed('dsa', DSA), self.identity(HIT_R, DSA, b'\x00' + bytes(40))),
            ('dsa-signature', self.signed('rsa', DSA), self.identity(HIT_R, DSA, self.dsa_hi())),
            ('ecdsa-key', self.signed('p256', ECDSA), self.identity(HIT_R, ECDSA, b'\x00\x01' + bytes(65))),
            ('ecdsa-signature', self.signed('rsa', ECDSA), self.identity(HIT_R, ECDSA, b'\x00\x01' + bytes(64))),
        ]
        cases.extend((name, packet_, identity, self.Status.INVALID,
                      'the Host Identity or the signature is malformed')
                     for name, packet_, identity in malformed)
        for name, packet_, identity, status, message in cases:
            with self.subTest(name=name):
                self.assertEqual(self.status(packet_, HIP_SIGNATURE, identity),
                                 (status, [f'HIPv2: HIP_SIGNATURE: {message}']))

    def test_a_host_id_built_by_hand_needs_its_curve(self) -> None:
        from pcapkit.const.hip.di import DITypes
        from pcapkit.const.hip.hi_algorithm import HIAlgorithm
        from pcapkit.protocols.internet.hip.data import HostIDParameter

        param = HostIDParameter(type=self.Parameter.HOST_ID, critical=True, length=16, hi_len=4,
                                di_type=DITypes.none_included, di_len=0, algorithm=HIAlgorithm.ECDSA,
                                hi=b'\x00\x01ab', di=b'')
        self.assertEqual(self.status(self.signed('p256', ECDSA), HIP_SIGNATURE, self.Identity(HIT_R, param)),
                         (self.Status.INVALID, ['HIPv2: HIP_SIGNATURE: the Host Identity or the signature '
                                                'is malformed']))

    def test_rsa_needs_cryptography_37(self) -> None:
        # cryptography before 37 has no PSS.AUTO to recover the salt length with.
        from cryptography.hazmat.primitives.asymmetric import padding

        identity = self.identity(HIT_R, RSA, self.rsa_hi())
        with mock.patch.object(self.module, '_CRYPTO', NotImplemented), \
                mock.patch.object(padding, 'PSS', type('PSS', (), {})):
            older = self.module._load_cryptography()
        self.assertIsNone(older.pss_auto)
        with mock.patch.object(self.module, '_load_cryptography', return_value=older):
            status, messages = self.status(self.signed('rsa', RSA), HIP_SIGNATURE, identity)
        self.assertEqual((status, messages), (self.Status.UNSUPPORTED, [
            'HIPv2: HIP_SIGNATURE: RSASSA-PSS needs "cryptography" 37 or later, which recovers the salt length']))

    def test_reports_what_cryptography_cannot_apply(self) -> None:
        from cryptography.exceptions import UnsupportedAlgorithm

        identity = self.identity(HIT_R, EDDSA, b'\x00\x03' + self.raw('ed448'))
        loaded = self.module._load_cryptography()
        refusing = mock.Mock(**{'from_public_bytes.side_effect': UnsupportedAlgorithm('no Ed448')})
        ed448 = types.SimpleNamespace(Ed448PublicKey=refusing)
        with mock.patch.object(self.module, '_load_cryptography',
                               return_value=types.SimpleNamespace(**{**vars(loaded), 'ed448': ed448})):
            status, messages = self.status(self.signed('ed448', EDDSA), HIP_SIGNATURE, identity)
        self.assertEqual((status, messages), (self.Status.UNSUPPORTED, [
            'HIPv2: HIP_SIGNATURE: "cryptography" cannot apply the Host Identity: no Ed448']))


if __name__ == '__main__':
    unittest.main()
