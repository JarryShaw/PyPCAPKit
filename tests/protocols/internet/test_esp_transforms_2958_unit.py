# -*- coding: utf-8 -*-
"""GitHub issue #2958: the remaining registered ESP transforms, each pinned by a known answer.

Every transform the issue adds is checked against a published vector and
round-tripped, construct -> parse -> construct, byte for byte:

=========================== ================================================================
Transform                   Known answer
=========================== ================================================================
``ENCR_AES_CTR``            RFC 3686 s6, every vector
``ENCR_AES_CCM_*``          NIST CAVP CCM (SP 800-38C): VNT at the 11-octet nonce ESP uses,
                            VTT at the 8- and 12-octet tags
``ENCR_CHACHA20_POLY1305``  RFC 7634 Appendix A, the whole ESP packet
``ENCR_NULL_AUTH_AES_GMAC`` NIST CAVP GCM with an empty plaintext, which RFC 4543 s6 names
                            (as erratum 1921 corrects its reference to SP 800-38D), and
                            draft-mcgrew-gcm-test-01's GMAC packet
``ENCR_CAMELLIA_CBC``       RFC 3713 Appendix A, chained over two CBC blocks
``AUTH_AES_CMAC_96``        RFC 4494 s5, test cases 2 to 4
=========================== ================================================================

No published vector frames AES-CCM as ESP does, an 11-octet nonce with the
8-octet SPI and sequence number as associated data, so the CCM known answers
run through the AEAD step itself (``SecurityAssociation._seal`` and ``_open``),
and the RFC 4309 s4 and s5 framing is checked against an AES-CCM computed in
the test from the RFC's own nonce and AAD layout. RFC 4494's empty-message case
has no ESP form, since the SPI and sequence number are always covered.

"""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import struct
import sys
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): cryptography's releases vary by interpreter -- PyPy below 3.11
#: is capped under 46 -- and Camellia's import path varies with them.
__tier__ = 'ALL'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


def _cryptography_imports() -> bool:
    """Whether cryptography is installed and its compiled binding loads.

    PyPy 3.12 (PyPy 8.0.1) exports its C API without the ``PyPy`` prefix PyO3
    links against, so a cryptography built there fails to import on an undefined
    ``PyPy*`` symbol, and ``find_spec`` alone would run the known answers against
    a cryptography pcapkit rightly reports unavailable.

    """
    if importlib.util.find_spec('cryptography') is None:
        return False
    try:
        import cryptography.hazmat.primitives.ciphers.aead  # pylint: disable=import-outside-toplevel,unused-import
    except ImportError:
        return False
    return True


HAS_CRYPTO = _cryptography_imports()


def hx(value: str) -> bytes:
    """Decode a whitespace-formatted hex string, as the RFCs print them."""
    return bytes.fromhex(''.join(value.split()))


def xor(left: bytes, right: bytes) -> bytes:
    """XOR two equal-length octet strings."""
    return bytes(a ^ b for a, b in zip(left, right))


#: RFC 3686 s6 -- (AES key, nonce, IV, plaintext, ciphertext), test vectors #1 to #9.
CTR_VECTORS = (
    ('AE6852F8 121067CC 4BF7A576 5577F39E', '00000030', '00000000 00000000',
     '53696E67 6C652062 6C6F636B 206D7367', 'E4095D4F B7A7B379 2D6175A3 261311B8'),
    ('7E240678 17FAE0D7 43D6CE1F 32539163', '006CB6DB', 'C0543B59 DA48D90B',
     '00010203 04050607 08090A0B 0C0D0E0F 10111213 14151617 18191A1B 1C1D1E1F',
     '5104A106 168A72D9 790D41EE 8EDAD388 EB2E1EFC 46DA57C8 FCE630DF 9141BE28'),
    ('7691BE03 5E5020A8 AC6E6185 29F9A0DC', '00E0017B', '27777F3F 4A1786F0',
     '00010203 04050607 08090A0B 0C0D0E0F 10111213 14151617 18191A1B 1C1D1E1F 20212223',
     'C1CF48A8 9F2FFDD9 CF4652E9 EFDB72D7 4540A42B DE6D7836 D59A5CEA AEF31053 25B2072F'),
    ('16AF5B14 5FC9F579 C175F93E 3BFB0EED 863D06CC FDB78515', '00000048', '36733C14 7D6D93CB',
     '53696E67 6C652062 6C6F636B 206D7367', '4B55384F E259C9C8 4E7935A0 03CBE928'),
    ('7C5CB240 1B3DC33C 19E73408 19E0F69C 678C3DB8 E6F6A91A', '0096B03B', '020C6EAD C2CB500D',
     '00010203 04050607 08090A0B 0C0D0E0F 10111213 14151617 18191A1B 1C1D1E1F',
     '453243FC 609B2332 7EDFAAFA 7131CD9F 8490701C 5AD4A79C FC1FE0FF 42F4FB00'),
    ('02BF391E E8ECB159 B959617B 0965279B F59B60A7 86D3E0FE', '0007BDFD', '5CBD6027 8DCC0912',
     '00010203 04050607 08090A0B 0C0D0E0F 10111213 14151617 18191A1B 1C1D1E1F 20212223',
     '96893FC5 5E5C722F 540B7DD1 DDF7E758 D288BC95 C6916588 4536C811 662F2188 ABEE0935'),
    ('776BEFF2 851DB06F 4C8A0542 C8696F6C 6A81AF1E EC96B4D3 7FC1D689 E6C1C104', '00000060',
     'DB5672C9 7AA8F0B2', '53696E67 6C652062 6C6F636B 206D7367',
     '145AD01D BF824EC7 560863DC 71E3E0C0'),
    ('F6D66D6B D52D59BB 07963658 79EFF886 C66DD51A 5B6A9974 4B50590C 87A23884', '00FAAC24',
     'C1585EF1 5A43D875',
     '00010203 04050607 08090A0B 0C0D0E0F 10111213 14151617 18191A1B 1C1D1E1F',
     'F05E231B 3894612C 49EE000B 804EB2A9 B8306B50 8F839D6A 5530831D 9344AF1C'),
    ('FF7A617C E69148E4 F1726E2F 43581DE2 AA62D9F8 05532EDF F1EED687 FB54153D', '001CC5B7',
     '51A51D70 A1C11148',
     '00010203 04050607 08090A0B 0C0D0E0F 10111213 14151617 18191A1B 1C1D1E1F 20212223',
     'EB6C5282 1D0BBBF7 CE759446 2ACA4FAA B407DF86 6569FD07 F48CC0B5 83D6071F 1EC0E6B8'),
)

#: NIST CAVP CCM (SP 800-38C) -- (cipher, key, nonce, associated data, payload, CT || tag).
#: VNT128 and VNT256 ``[Nlen = 11]`` count 40, VTT128 ``[Tlen = 8]`` count 20 and
#: ``[Tlen = 12]`` count 40.
CCM_VECTORS = (
    ('ENCR_AES_CCM_16', 'e6ab9e70a4fb51b01c2e262233e64c0d', '74e689eb5af9441dd690a6',
     '42f6518ee0fbe42f28e13b4bb2eb60517b37c9744394d9143393a879c3e107c7',
     'ba15916733550d7aa82b2f6b117cd3f54c83ddc16cd0288a',
     'dcc151443288f35d39ed8fae6f0ce1d1eb656f4f7fd65c0b16f322ce85d7c54e71ac560fd4da9651'),
    ('ENCR_AES_CCM_16', '97bc7482a87ba005475dfa3448f59d4b3f9c4c969d08b39b1b21ef965c0f5125',
     '0bcf78103ec52d6df28887',
     '049c10f0cb37ae08eae2d0766563b7c5a8454f841c2061a4f71a0a2158ae6ce5',
     'b99bf4dc781795fc4d3a8467b06e1665d4e543657f23129f',
     '0d3891fa0caac1f7ebe41b480920ffd34d4155064c24f3b17a483163dd8f228d1f20cd4f86cf38fd'),
    ('ENCR_AES_CCM_8', '368f35a1f80eaaacd6bb136609389727', '842a8445847502ea77363a16b6',
     '34396dfcfa6f742aea7040976bd596497a7a6fa4fb85ee8e4ca394d02095b7bf',
     '1cccd55825316a94c5979e049310d1d717cdfb7624289dac',
     '1a58094f0e8c6035a5584bfa8d1009c5f78fd2ca487ff222f6d1d897d6051618'),
    ('ENCR_AES_CCM_12', '3ee186594f110fb788a8bf8aa8be5d4a', '44f705d52acf27b7f17196aa9b',
     '2c16724296ff85e079627be3053ea95adf35722c21886baba343bd6c79b5cb57',
     'd71864877f2578db092daba2d6a1f9f4698a9c356c7830a1',
     'b4dd74e7a0cc51aea45dfb401a41d5822c96901a83247ea0d6965f5aa6e31302a9cc2b36'),
)

#: NIST CAVP GCM (SP 800-38D), gcmEncryptExtIV128 and gcmEncryptExtIV256
#: ``[IVlen = 96] [PTlen = 0] [AADlen = 128] [Taglen = 128]`` count 0 -- (key, IV, AAD, tag).
GMAC_VECTORS = (
    ('77be63708971c4e240d1cb79e8d77feb', 'e0e00f19fed7ba0136a797f3',
     '7a43ec1d9c0a5a78a0b16533a6213cab', '209fcc8d3675ed938e9c7166709dd946'),
    ('78dc4e0aaf52d935c3c01eea57428f00ca1fd475f5da86a49c8dd73d68c8e223',
     'd79cf22d504cc793c3fb6c8a', 'b96baa8c1c75a671bfb2d08d06be5f36',
     '3e5d486aa2e30b22e040b85723a06e76'),
)

#: draft-mcgrew-gcm-test-01 s4 -- AES-GMAC-ESP, 128-bit key, salt ``22433c64`` taken
#: from the published nonce ``22433c640000000000000000``.
GMAC_KEYMAT = hx('4c80cdef bb5d10da 906ac73c 3613a634 22433c64')
GMAC_PACKET = hx('''
    00004321 00000007 00000000 00000000
    45000030 da3a0000 8001df3b c0a80005
    c0a80001 0800c6cd 02000700 61626364
    65666768 696a6b6c 6d6e6f70 71727374
    01020201 f2a9a836 e155106a a8dcd618
    e4099aaa''')

#: RFC 7634 Appendix A -- the KEYMAT, then the source packet the SA tunnels and
#: the IPv4 packet that carries it as ESP.
CHACHA_KEYMAT = bytes(range(0x80, 0xa4))
CHACHA_SOURCE = hx('''
    45 00 00 54 a6 f2 00 00 40 01 e7 78 c6 33 64 05
    c0 00 02 05 08 00 5b 7a 3a 08 00 00 55 3b ec 10
    00 07 36 27 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13
    14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23
    24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33
    34 35 36 37''')
CHACHA_PACKET = hx('''
    45 00 00 8c 23 45 00 00 40 32 de 5b cb 00 71 99
    cb 00 71 05 01 02 03 04 00 00 00 05 10 11 12 13
    14 15 16 17 24 03 94 28 b9 7f 41 7e 3c 13 75 3a
    4f 05 08 7b 67 c3 52 e6 a7 fa b1 b9 82 d4 66 ef
    40 7a e5 c6 14 ee 80 99 d5 28 44 eb 61 aa 95 df
    ab 4c 02 f7 2a a7 1e 7c 4c 4f 64 c9 be fe 2f ac
    c6 38 e8 f3 cb ec 16 3f ac 46 9b 50 27 73 f6 fb
    94 e6 64 da 91 65 b8 28 29 f6 41 e0 76 aa a8 26
    6b 7f b0 f7 b1 1b 36 99 07 e1 ad 43''')
CHACHA_TAG = hx('76 aa a8 26 6b 7f b0 f7 b1 1b 36 99 07 e1 ad 43')

#: RFC 3713 Appendix A -- (key, ciphertext), every key over the same plaintext.
CAMELLIA_PLAINTEXT = hx('01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10')
CAMELLIA_VECTORS = (
    ('01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10',
     '67 67 31 38 54 96 69 73 08 57 06 56 48 ea be 43'),
    ('01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10 00 11 22 33 44 55 66 77',
     'b4 99 34 01 b3 e9 96 f8 4e e5 ce e7 d7 9b 09 b9'),
    ('01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10 00 11 22 33 44 55 66 77'
     ' 88 99 aa bb cc dd ee ff',
     '9a cc 23 7d ff 16 d7 6c 20 ef 7c 91 9e 3a 75 09'),
)

#: RFC 4494 s5 -- the key, then (message, AES-CMAC-96) for test cases 2 to 4.
CMAC_KEY = hx('2b7e1516 28aed2a6 abf71588 09cf4f3c')
CMAC_VECTORS = (
    ('6bc1bee2 2e409f96 e93d7e11 7393172a', '070a16b4 6b4d4144 f79bdd9d'),
    ('6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51'
     ' 30c81c46 a35ce411', 'dfa66747 de9ae630 30ca3261'),
    ('6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51'
     ' 30c81c46 a35ce411 e5fbc119 1a0a52ef f69f2445 df4f9b17 ad2b417b e66c3710',
     '51f0bebf 7e3b9d92 fc497417'),
)

#: Inner IPv4/TCP datagram the round trips protect.
INNER_TCP = hx('''
    45000028 00010000 4006f97e c0a80101 c0a80102
    00140050 00000000 00000000 50022000 00000000''')

#: The transforms #2958 adds, with keying material of the length each takes.
NEW_CIPHERS = (
    ('ENCR_AES_CTR', 20), ('ENCR_AES_CCM_8', 19), ('ENCR_AES_CCM_12', 27),
    ('ENCR_AES_CCM_16', 35), ('ENCR_NULL_AUTH_AES_GMAC', 36), ('ENCR_CAMELLIA_CBC', 24),
    ('ENCR_CHACHA20_POLY1305', 36),
)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class SuiteTableTests(unittest.TestCase):
    """What the suite tables hold, and what they leave out."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_new_cipher_suites(self) -> None:
        from pcapkit.protocols.internet.esp.protocol import CIPHER_SUITES, Cipher, CipherSuite

        expected = {
            # cipher: (is_aead, iv_length, block_size, icv_length, key_sizes, salt_length)
            Cipher.ENCR_AES_CTR: (False, 8, 1, 0, (16, 24, 32), 4),             # RFC 3686 s3.1, s5.1
            Cipher.ENCR_AES_CCM_8: (True, 8, 1, 8, (16, 24, 32), 3),            # RFC 4309 s3.1, s7.1
            Cipher.ENCR_AES_CCM_12: (True, 8, 1, 12, (16, 24, 32), 3),
            Cipher.ENCR_AES_CCM_16: (True, 8, 1, 16, (16, 24, 32), 3),
            Cipher.ENCR_NULL_AUTH_AES_GMAC: (True, 8, 1, 16, (16, 24, 32), 4),  # RFC 4543 s3.1, s3.4, s5.4
            Cipher.ENCR_CAMELLIA_CBC: (False, 16, 16, 0, (16, 24, 32), 0),      # RFC 5529 s2.1, s4.1
            Cipher.ENCR_CHACHA20_POLY1305: (True, 8, 1, 16, (32,), 4),          # RFC 7634 s2
        }
        for cipher, (is_aead, iv_length, block_size, icv_length, key_sizes, salt_length) in expected.items():
            with self.subTest(cipher=cipher.name):
                suite = CIPHER_SUITES[cipher]
                self.assertIs(CipherSuite.get(cipher.value), suite)
                self.assertIs(suite.cipher, cipher)
                self.assertIs(suite.is_aead, is_aead)
                self.assertEqual(suite.iv_length, iv_length)
                self.assertEqual(suite.block_size, block_size)
                self.assertEqual(suite.icv_length, icv_length)
                self.assertEqual(suite.key_sizes, key_sizes)
                self.assertEqual(suite.salt_length, salt_length)
                self.assertTrue(suite.requires_cryptography)

        # the prefix-stripped and hyphenated spellings resolve too
        for spelling, cipher in (('AES-CTR', Cipher.ENCR_AES_CTR), ('aes_ccm_8', Cipher.ENCR_AES_CCM_8),
                                 ('CHACHA20-POLY1305', Cipher.ENCR_CHACHA20_POLY1305),
                                 ('NULL_AUTH_AES_GMAC', Cipher.ENCR_NULL_AUTH_AES_GMAC),
                                 ('camellia-cbc', Cipher.ENCR_CAMELLIA_CBC)):
            with self.subTest(spelling=spelling):
                self.assertIs(CipherSuite.get(spelling).cipher, cipher)

        # keyed in transform ID order, so the error message lists them that way
        self.assertEqual(list(CIPHER_SUITES), sorted(CIPHER_SUITES, key=int))

    def test_integrity_suites(self) -> None:
        from pcapkit.protocols.internet.esp.protocol import (INTEGRITY_SUITES, Integrity,
                                                             IntegritySuite)

        cmac = IntegritySuite.get('AES-CMAC-96')
        self.assertIs(cmac, INTEGRITY_SUITES[Integrity.AUTH_AES_CMAC_96])
        # RFC 4494 s2 and s4: a 128-bit key, the MAC truncated to 96 bits
        self.assertEqual((cmac.mac, cmac.digest, cmac.icv_length, cmac.key_size), ('cmac', None, 12, 16))
        self.assertTrue(cmac.requires_cryptography)

        for integrity, digest in ((Integrity.AUTH_HMAC_SHA1_96, 'sha1'),
                                  (Integrity.AUTH_HMAC_SHA2_256_128, 'sha256'),
                                  (Integrity.AUTH_HMAC_SHA2_384_192, 'sha384'),
                                  (Integrity.AUTH_HMAC_SHA2_512_256, 'sha512')):
            with self.subTest(integrity=integrity.name):
                suite = INTEGRITY_SUITES[integrity]
                self.assertEqual((suite.mac, suite.digest), ('hmac', digest))
                self.assertFalse(suite.requires_cryptography)

        none = INTEGRITY_SUITES[Integrity.NONE]
        self.assertEqual((none.mac, none.digest), (None, None))
        self.assertFalse(none.requires_cryptography)
        self.assertEqual(list(INTEGRITY_SUITES), sorted(INTEGRITY_SUITES, key=int))

    def test_gaps_are_refused(self) -> None:
        """What cryptography cannot apply, and what is ESP's to refuse, stays out."""
        from pcapkit.protocols.internet.esp.protocol import CipherSuite, IntegritySuite
        from pcapkit.utilities.exceptions import ProtocolError

        for name in ('ENCR_CAMELLIA_CTR', 'ENCR_CAMELLIA_CCM_8', 'ENCR_CAMELLIA_CCM_12',
                     'ENCR_CAMELLIA_CCM_16', 'ENCR_AES_CCM_8_IIV', 'ENCR_AES_GCM_16_IIV',
                     'ENCR_CHACHA20_POLY1305_IIV', 'ENCR_KUZNYECHIK_MGM_KTREE',
                     'ENCR_MAGMA_MGM_KTREE', 'ENCR_KUZNYECHIK_MGM_MAC_KTREE',
                     'ENCR_MAGMA_MGM_MAC_KTREE'):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ProtocolError, f"^ESP: unsupported encryption algorithm: '{name}'"):
                    CipherSuite.get(name)

        # AES-XCBC-MAC has no cryptography primitive, and RFC 4543 s5.3 keeps the
        # AUTH_AES_*_GMAC transforms off ESP
        for name in ('AUTH_AES_XCBC_96', 'AUTH_AES_128_GMAC', 'AUTH_AES_192_GMAC',
                     'AUTH_AES_256_GMAC'):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ProtocolError, f"^ESP: unsupported integrity algorithm: '{name}'"):
                    IntegritySuite.get(name)

    def test_salt_split(self) -> None:
        """Each suite takes its salt from the end of the IKEv2 KEYMAT."""
        from pcapkit.protocols.internet.esp.protocol import SecurityAssociation

        keymat = bytes(range(64))
        for name, length, salt in (('ENCR_AES_CTR', 20, 4), ('ENCR_AES_CCM_8', 35, 3),
                                   ('ENCR_NULL_AUTH_AES_GMAC', 28, 4),
                                   ('ENCR_CHACHA20_POLY1305', 36, 4), ('ENCR_CAMELLIA_CBC', 32, 0)):
            with self.subTest(name=name):
                integrity = {'integrity': 'HMAC_SHA2_256_128', 'integrity_key': bytes(32)} \
                    if name == 'ENCR_AES_CTR' else {}
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    sa = SecurityAssociation(spi=1, encryption=name, encryption_key=keymat[:length],
                                             **integrity)
                self.assertEqual(sa.encryption_key, keymat[:length - salt])
                self.assertEqual(sa.salt, keymat[length - salt:length])

    def test_aes_ctr_needs_an_integrity_algorithm(self) -> None:
        """RFC 3686 s3.3: AES-CTR MUST be used with a non-NULL integrity algorithm."""
        from pcapkit.protocols.internet.esp.protocol import SecurityAssociation
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError) as ctx:
            SecurityAssociation(spi=1, encryption='AES_CTR', encryption_key=bytes(20))
        self.assertEqual(str(ctx.exception),
                         "ESP: invalid integrity algorithm: ENCR_AES_CTR must be used with an "
                         "integrity algorithm (RFC 3686 s3.3), not 'NONE'")

    def test_aes_cmac_takes_a_128_bit_key(self) -> None:
        from pcapkit.protocols.internet.esp.protocol import SecurityAssociation
        from pcapkit.utilities.exceptions import ProtocolError

        for length in (15, 24, 32):
            with self.subTest(length=length):
                with self.assertRaises(ProtocolError) as ctx:
                    SecurityAssociation(spi=1, integrity='AES_CMAC_96', integrity_key=bytes(length))
                self.assertEqual(str(ctx.exception),
                                 f'ESP: invalid integrity key: AUTH_AES_CMAC_96 needs a 16-octet '
                                 f'key, got {length} octets')


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class WithoutCryptographyTests(unittest.TestCase):
    """Without cryptography, an SA naming a new transform leaves its payload opaque."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_new_ciphers_degrade(self) -> None:
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.esp import protocol as esp_module
        from pcapkit.protocols.internet.esp.protocol import (ESP, ESPContext, ESPStatus,
                                                             SecurityAssociation)

        for name, length in NEW_CIPHERS:
            with self.subTest(name=name):
                suite = esp_module.CipherSuite.get(name)
                integrity = {'integrity': 'AES_CMAC_96', 'integrity_key': bytes(16)} \
                    if not suite.is_aead else {}
                with mock.patch.object(esp_module, 'load_cryptography', return_value=None), \
                        mock.patch.object(esp_module, 'warn') as warned:
                    sa = SecurityAssociation(spi=0x77, encryption=name, encryption_key=bytes(length),
                                             **integrity)
                    warned.assert_called_once()
                    self.assertEqual(sa.unavailable(),
                                     f"ESP: unavailable encryption algorithm: '{name}' needs the "
                                     f'optional "cryptography" dependency, which is not installed '
                                     f'(pip install pypcapkit[crypto])')
                    body = bytes(range(48))
                    packet = struct.pack('!II', 0x77, 1) + body
                    info = ESP(packet, len(packet), context=ContextRegistry.make(ESPContext(sa))).info
                self.assertIs(info.status, ESPStatus.UNSUPPORTED)
                self.assertIsNone(info.plaintext)
                # the ICV length comes from the SA, so it is still split off
                self.assertEqual(info.icv, body[len(body) - sa.icv_length:])

    def test_aes_cmac_degrades_under_null_encryption(self) -> None:
        """An integrity algorithm alone can need cryptography, and says so as integrity."""
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.esp import protocol as esp_module
        from pcapkit.protocols.internet.esp.protocol import (ESP, ESPContext, ESPStatus,
                                                             SecurityAssociation)
        from pcapkit.utilities.exceptions import ProtocolError

        expected = ("ESP: unavailable integrity algorithm: 'AUTH_AES_CMAC_96' needs the optional "
                    '"cryptography" dependency, which is not installed')
        with mock.patch.object(esp_module, 'load_cryptography', return_value=None), \
                mock.patch.object(esp_module, 'warn'):
            sa = SecurityAssociation(spi=0x77, integrity='AES_CMAC_96', integrity_key=CMAC_KEY)
            self.assertEqual(sa.unavailable(), f'{expected} (pip install pypcapkit[crypto])')
            with self.assertRaises(ProtocolError) as ctx:
                sa.compute_icv(0x77, 1, b'body')
            self.assertEqual(str(ctx.exception), expected)

            packet = struct.pack('!II', 0x77, 1) + b'payload' + bytes([1, 2, 2, 6]) + bytes(12)
            info = ESP(packet, len(packet), context=ContextRegistry.make(ESPContext(sa))).info
        self.assertIs(info.status, ESPStatus.UNSUPPORTED)
        self.assertEqual(info.icv, bytes(12))

    def test_loader_reports_a_missing_cryptography(self) -> None:
        from pcapkit.protocols.internet.esp import protocol as esp_module

        # a None entry makes the import raise ImportError, as an absent package does
        absent = {name: None for name in list(sys.modules) if name.startswith('cryptography.')}
        absent['cryptography'] = None
        with mock.patch.object(esp_module, '_CRYPTO', NotImplemented), \
                mock.patch.dict(sys.modules, absent):
            self.assertIsNone(esp_module.load_cryptography())
            self.assertIsNone(esp_module._CRYPTO)  # pylint: disable=protected-access

    def test_a_cryptography_that_fails_to_import_degrades(self) -> None:
        """An installed cryptography whose binding fails to load, as on PyPy 3.12, raises nothing."""
        import builtins  # pylint: disable=import-outside-toplevel

        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.esp import protocol as esp_module
        from pcapkit.protocols.internet.esp.protocol import (ESP, CipherSuite, ESPContext,
                                                             ESPStatus, SecurityAssociation)
        from pcapkit.utilities.exceptions import ProtocolError

        real_import = builtins.__import__

        def broken_import(name: str, *args: 'Any', **kwargs: 'Any') -> 'Any':
            # the import error PyPy 3.12 raises from any cryptography module, cached or not
            if name == 'cryptography' or name.startswith('cryptography.'):
                raise ImportError('_rust.pypy312-pp80-x86_64-linux-gnu.so: undefined symbol: PyPyLong_Type')
            return real_import(name, *args, **kwargs)

        body = bytes(range(48))
        packet = struct.pack('!II', 0x77, 1) + body
        with mock.patch.object(esp_module, '_CRYPTO', NotImplemented), \
                mock.patch('builtins.__import__', broken_import), \
                mock.patch.object(esp_module, 'warn') as warned:
            self.assertIsNone(esp_module.load_cryptography())
            for name, length in NEW_CIPHERS:
                with self.subTest(name=name):
                    integrity = {} if CipherSuite.get(name).is_aead else {'integrity': 'AES_CMAC_96',
                                                                          'integrity_key': CMAC_KEY}
                    sa = SecurityAssociation(spi=0x77, encryption=name, encryption_key=bytes(length),
                                             **integrity)
                    self.assertIn(f"unavailable encryption algorithm: '{name}'", sa.unavailable())
                    esp = ESP(packet, len(packet), context=ContextRegistry.make(ESPContext(sa)))
                    self.assertIs(esp.info.status, ESPStatus.UNSUPPORTED)
                    self.assertIsNone(esp.info.plaintext)
                    self.assertEqual(esp.info.payload_data + esp.info.icv, body)
                    self.assertEqual(str(esp.protochain), 'ESP:Raw')

            # an integrity algorithm needing it fails as configuration, never as ImportError
            cmac = SecurityAssociation(spi=0x77, integrity='AES_CMAC_96', integrity_key=CMAC_KEY)
            self.assertIn("unavailable integrity algorithm: 'AUTH_AES_CMAC_96'", cmac.unavailable())
            with self.assertRaises(ProtocolError):
                cmac.compute_icv(0x77, 1, body)
        self.assertTrue(warned.called)

    def test_hmac_needs_no_cryptography(self) -> None:
        """An HMAC suite computes on the standard library alone."""
        from pcapkit.protocols.internet.esp import protocol as esp_module
        from pcapkit.protocols.internet.esp.protocol import SecurityAssociation

        with mock.patch.object(esp_module, 'load_cryptography', return_value=None):
            sa = SecurityAssociation(spi=1, integrity='HMAC_SHA2_256_128', integrity_key=bytes(32))
            self.assertIsNone(sa.unavailable())
            self.assertEqual(sa.compute_icv(1, 2, b'body'),
                             hmac.new(bytes(32), struct.pack('!II', 1, 2) + b'body',
                                      hashlib.sha256).digest()[:16])


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
@unittest.skipUnless(HAS_CRYPTO, 'cryptography not installed, or its binding does not load')
class KnownAnswerTests(unittest.TestCase):
    """Each new transform against its published vectors."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def context(self, *associations: 'Any') -> 'Any':
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.esp.protocol import ESPContext

        return ContextRegistry.make(ESPContext(*associations))

    def test_loader_carries_aead_cmac_and_camellia(self) -> None:
        from cryptography.hazmat.primitives import cmac
        from cryptography.hazmat.primitives.ciphers import Cipher, aead, modes
        from cryptography.utils import CryptographyDeprecationWarning

        from pcapkit.protocols.internet.esp import protocol as esp_module

        with mock.patch.object(esp_module, '_CRYPTO', NotImplemented):
            with warnings.catch_warnings():
                # the moved Camellia warns on its old spelling, so the loader takes the new one
                warnings.simplefilter('error', CryptographyDeprecationWarning)
                crypto = esp_module.load_cryptography()
        self.assertEqual(len(crypto), 7)
        self.assertIs(crypto[0], Cipher)
        self.assertIs(crypto[2], modes)
        self.assertIs(crypto[4], aead)
        self.assertIs(crypto[5], cmac)
        key, ciphertext = (hx(value) for value in CAMELLIA_VECTORS[0])
        encryptor = Cipher(crypto[6](key), modes.ECB()).encryptor()
        self.assertEqual(encryptor.update(CAMELLIA_PLAINTEXT) + encryptor.finalize(), ciphertext)

    def test_loader_falls_back_to_camellia_beside_aes(self) -> None:
        """A release with no decrepit Camellia keeps it in the ciphers' algorithms module."""
        from cryptography.hazmat.primitives.ciphers import algorithms

        from pcapkit.protocols.internet.esp import protocol as esp_module

        with mock.patch.object(esp_module, '_CRYPTO', NotImplemented), \
                mock.patch.dict(sys.modules, {'cryptography.hazmat.decrepit.ciphers.algorithms': None}), \
                warnings.catch_warnings():
            warnings.simplefilter('ignore')
            crypto = esp_module.load_cryptography()
            self.assertIs(crypto[6], algorithms.Camellia)

    def test_aes_ctr_rfc3686(self) -> None:
        from pcapkit.protocols.internet.esp.protocol import SecurityAssociation

        for number, (key, nonce, iv, plaintext, ciphertext) in enumerate(CTR_VECTORS, 1):
            with self.subTest(vector=number):
                sa = SecurityAssociation(spi=1, encryption='AES_CTR', encryption_key=hx(key + nonce),
                                         integrity='HMAC_SHA1_96', integrity_key=bytes(20))
                body = hx(iv) + hx(ciphertext)
                self.assertEqual(sa.encrypt(1, 1, hx(plaintext), hx(iv)), (body, b''))
                self.assertEqual(sa.decrypt(1, 1, body, b''), hx(plaintext))

    def test_aes_ccm_nist(self) -> None:
        from cryptography.exceptions import InvalidTag

        from pcapkit.protocols.internet.esp.protocol import SecurityAssociation, load_cryptography

        crypto = load_cryptography()
        for name, key, nonce, aad, payload, sealed in CCM_VECTORS:
            with self.subTest(name=name, key=len(key) // 2):
                sa = SecurityAssociation(spi=1, encryption=name, encryption_key=hx(key) + bytes(3))
                ciphertext, tag = hx(sealed)[:-sa.icv_length], hx(sealed)[-sa.icv_length:]
                self.assertEqual(sa._seal(crypto, hx(nonce), hx(aad), hx(payload)), (ciphertext, tag))
                self.assertEqual(sa._open(crypto, hx(nonce), hx(aad), ciphertext, tag), hx(payload))
                with self.assertRaises(InvalidTag):
                    sa._open(crypto, hx(nonce), hx(aad), ciphertext, xor(tag, b'\x01'.ljust(len(tag), b'\0')))

    def test_aes_ccm_rfc4309_framing(self) -> None:
        """RFC 4309 s4 and s5: an 11-octet nonce of salt and IV, and the SPI and sequence number as AAD."""
        from cryptography.hazmat.primitives.ciphers.aead import AESCCM

        from pcapkit.protocols.internet.esp.protocol import SecurityAssociation

        key, salt, iv = hx(CCM_VECTORS[0][1]), hx('a0a1a2'), hx('0102030405060708')
        for name, icv in (('ENCR_AES_CCM_8', 8), ('ENCR_AES_CCM_12', 12), ('ENCR_AES_CCM_16', 16)):
            with self.subTest(name=name):
                sa = SecurityAssociation(spi=0x4321, encryption=name, encryption_key=key + salt)
                sealed = AESCCM(key, tag_length=icv).encrypt(salt + iv, INNER_TCP, hx('00004321 0000000b'))
                self.assertEqual(sa.encrypt(0x4321, 11, INNER_TCP, iv), (iv + sealed[:-icv], sealed[-icv:]))
                self.assertEqual(sa.decrypt(0x4321, 11, iv + sealed[:-icv], sealed[-icv:]), INNER_TCP)

    def test_chacha20_poly1305_rfc7634_appendix_a(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.esp.protocol import ESP, ESPStatus, SecurityAssociation
        from pcapkit.protocols.internet.ipv4.protocol import IPv4

        sa = SecurityAssociation(spi=0x01020304, encryption='CHACHA20_POLY1305',
                                 encryption_key=CHACHA_KEYMAT)
        self.assertEqual(sa.salt, hx('a0 a1 a2 a3'))
        context = self.context(sa)

        ip = IPv4(CHACHA_PACKET, len(CHACHA_PACKET), context=context)
        self.assertEqual(str(ip.protochain), 'IPv4:ESP:IPv4:ICMP')
        info = ip.payload.info
        self.assertIs(info.status, ESPStatus.DECRYPTED)
        self.assertEqual((info.spi, info.seq), (0x01020304, 5))
        self.assertEqual(info.plaintext, CHACHA_SOURCE)
        self.assertEqual((info.padding, info.pad_len, info.next), (b'\x01\x02', 2, TransType.IPv4))
        self.assertEqual(info.icv, CHACHA_TAG)

        # make -> the RFC's packet, and parse -> rebuild, byte for byte
        built = ESP.from_fields(spi=0x01020304, seq=5, next=TransType.IPv4, encrypt=True,
                                iv=hx('10 11 12 13 14 15 16 17'), payload=CHACHA_SOURCE, context=context)
        self.assertEqual(bytes(built), CHACHA_PACKET[20:])
        self.assertEqual(bytes(ESP.from_data(info)), CHACHA_PACKET[20:])

        tampered = CHACHA_PACKET[:40] + xor(CHACHA_PACKET[40:41], b'\x01') + CHACHA_PACKET[41:]
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            failed = IPv4(tampered, len(tampered), context=context).payload.info
        self.assertIs(failed.status, ESPStatus.AUTH_FAILED)

    def test_aes_gmac_nist(self) -> None:
        """GMAC is GCM over an empty plaintext, RFC 4543 s3.5."""
        from cryptography.exceptions import InvalidTag

        from pcapkit.protocols.internet.esp.protocol import SecurityAssociation, load_cryptography

        crypto = load_cryptography()
        for key, iv, aad, tag in GMAC_VECTORS:
            with self.subTest(key=len(key) // 2):
                sa = SecurityAssociation(spi=1, encryption='NULL_AUTH_AES_GMAC',
                                         encryption_key=hx(key) + bytes(4))
                self.assertEqual(sa._seal(crypto, hx(iv), hx(aad), b''), (b'', hx(tag)))
                self.assertEqual(sa._open(crypto, hx(iv), hx(aad), b'', hx(tag)), b'')
                with self.assertRaises(InvalidTag):
                    sa._open(crypto, hx(iv), xor(hx(aad), b'\x01'), b'', hx(tag))

    def test_aes_gmac_mcgrew_packet(self) -> None:
        """RFC 4543 Figure 4, as erratum 62 confirms: the IV and payload are associated data."""
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.esp.protocol import ESP, ESPStatus, SecurityAssociation

        sa = SecurityAssociation(spi=0x4321, encryption='NULL_AUTH_AES_GMAC', encryption_key=GMAC_KEYMAT)
        context = self.context(sa)

        esp = ESP(GMAC_PACKET, len(GMAC_PACKET), context=context)
        info = esp.info
        self.assertIs(info.status, ESPStatus.DECRYPTED)
        # nothing is encrypted: the plaintext is the payload as sent, after the IV
        self.assertEqual(info.plaintext, GMAC_PACKET[16:-20])
        self.assertEqual((info.pad_len, info.next), (2, TransType.ICMP))
        self.assertEqual(info.icv, GMAC_PACKET[-16:])

        built = ESP.from_fields(spi=0x4321, seq=7, next=TransType.ICMP, encrypt=True, iv=bytes(8),
                                payload=info.plaintext, context=context)
        self.assertEqual(bytes(built), GMAC_PACKET)
        self.assertEqual(bytes(ESP.from_data(info)), GMAC_PACKET)

        # the tag covers the IV, the payload and the trailer
        for offset in (8, 20, len(GMAC_PACKET) - 17):
            with self.subTest(offset=offset):
                tampered = GMAC_PACKET[:offset] + xor(GMAC_PACKET[offset:offset + 1], b'\x01') + \
                    GMAC_PACKET[offset + 1:]
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    failed = ESP(tampered, len(tampered), context=context).info
                self.assertIs(failed.status, ESPStatus.AUTH_FAILED)

    def test_camellia_cbc_rfc3713(self) -> None:
        """RFC 3713's block, chained: P1 = P ^ IV and P2 = P ^ C both encrypt to C."""
        from pcapkit.protocols.internet.esp.protocol import SecurityAssociation

        iv = bytes(range(0xf0, 0x100))
        for key, ciphertext in CAMELLIA_VECTORS:
            with self.subTest(key=len(hx(key))):
                sa = SecurityAssociation(spi=1, encryption='CAMELLIA_CBC', encryption_key=hx(key))
                plaintext = xor(CAMELLIA_PLAINTEXT, iv) + xor(CAMELLIA_PLAINTEXT, hx(ciphertext))
                body = iv + hx(ciphertext) * 2
                self.assertEqual(sa.encrypt(1, 1, plaintext, iv), (body, b''))
                self.assertEqual(sa.decrypt(1, 1, body, b''), plaintext)

    def test_aes_cmac_96_rfc4494(self) -> None:
        """The ICV covers the SPI, the sequence number and the body, RFC 4303 s2.8."""
        from pcapkit.protocols.internet.esp.protocol import SecurityAssociation

        sa = SecurityAssociation(spi=None, integrity='AES_CMAC_96', integrity_key=CMAC_KEY)
        for message, mac in CMAC_VECTORS:
            with self.subTest(length=len(hx(message))):
                spi, seq = struct.unpack('!II', hx(message)[:8])
                self.assertEqual(sa.compute_icv(spi, seq, hx(message)[8:]), hx(mac))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
@unittest.skipUnless(HAS_CRYPTO, 'cryptography not installed, or its binding does not load')
class RoundTripTests(unittest.TestCase):
    """make -> parse -> rebuild under every new transform, and a wrong key never decodes."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def association(self, name: str, keymat: bytes, ikey: bytes = CMAC_KEY) -> 'Any':
        from pcapkit.protocols.internet.esp.protocol import CipherSuite, SecurityAssociation

        integrity = {} if CipherSuite.get(name).is_aead else {'integrity': 'AES_CMAC_96',
                                                              'integrity_key': ikey}
        return SecurityAssociation(spi=0x2958, encryption=name, encryption_key=keymat, **integrity)

    def test_round_trip(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.esp.protocol import ESP, ESPContext, ESPStatus

        for name, length in NEW_CIPHERS:
            with self.subTest(name=name):
                keymat = bytes(range(1, length + 1))
                sa = self.association(name, keymat)
                context = ContextRegistry.make(ESPContext(sa))
                iv = bytes(range(0x40, 0x40 + sa.cipher_suite.iv_length))
                built = ESP.from_fields(spi=0x2958, seq=3, next=TransType.IPv4, encrypt=True, iv=iv,
                                        payload=INNER_TCP, context=context)
                wire = bytes(built)
                # RFC 4303 s2.4: the trailer aligns the ICV on 4 octets, or on the block
                self.assertFalse((len(wire) - 8 - sa.icv_length) % max(sa.cipher_suite.block_size, 4))

                esp = ESP(wire, len(wire), context=context)
                self.assertIs(esp.info.status, ESPStatus.DECRYPTED)
                self.assertEqual(esp.info.plaintext, INNER_TCP)
                self.assertEqual(str(esp.protochain), 'ESP:IPv4:TCP')
                self.assertEqual(bytes(ESP.from_data(esp.info)), wire)
                rebuilt = ESP.from_fields(spi=0x2958, seq=3, next=esp.info.next, encrypt=True, iv=iv,
                                          pad_len=esp.info.pad_len, payload=esp.info.plaintext,
                                          context=context)
                self.assertEqual(bytes(rebuilt), wire)

                # wrong keys throughout: a combined mode fails its tag, the others their ICV
                wrong = ContextRegistry.make(ESPContext(self.association(name, bytes(length),
                                                                         bytes(16))))
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    failed = ESP(wire, len(wire), context=wrong).info
                self.assertIs(failed.status, ESPStatus.AUTH_FAILED)
                self.assertIsNone(failed.plaintext)

    def test_aes_cmac_icv_on_the_wire(self) -> None:
        """The CMAC ICV is recomputed here over RFC 4303 s2.8's coverage, independently of pcapkit."""
        from cryptography.hazmat.primitives import cmac
        from cryptography.hazmat.primitives.ciphers import algorithms

        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.esp.protocol import ESP, ESPContext, ESPStatus

        sa = self.association('ENCR_AES_CTR', bytes(20))
        context = ContextRegistry.make(ESPContext(sa))
        wire = bytes(ESP.from_fields(spi=0x2958, seq=9, next=TransType.IPv4, encrypt=True,
                                     iv=bytes(8), payload=INNER_TCP, context=context))
        mac = cmac.CMAC(algorithms.AES(CMAC_KEY))
        mac.update(wire[:-12])
        self.assertEqual(wire[-12:], mac.finalize()[:12])

        # a wrong integrity key is caught before decryption
        wrong = ContextRegistry.make(ESPContext(self.association('ENCR_AES_CTR', bytes(20), bytes(16))))
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            failed = ESP(wire, len(wire), context=wrong).info
        self.assertIs(failed.status, ESPStatus.AUTH_FAILED)
        self.assertIn('integrity check value does not verify', failed.error)


if __name__ == '__main__':
    unittest.main()
