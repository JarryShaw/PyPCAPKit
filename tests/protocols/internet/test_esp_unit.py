"""Unit tests for :mod:`pcapkit.protocols.internet.esp`.

Cryptographic behaviour is pinned with *published* test vectors rather than
with round trips alone, so that a change to the nonce, associated data or
trailer handling cannot pass unnoticed:

* **AES-CBC** -- :rfc:`3602` §4, cases 5 and 7. These are complete ESP
  packets (transport mode and tunnel mode respectively) with encryption only,
  and give the key, IV, plaintext and ciphertext.
* **AES-GCM** -- ``draft-mcgrew-gcm-test-01`` §4, "Test Cases for the use of
  Galois/Counter Mode (GCM) and Galois Message Authentication Code (GMAC) in
  IPsec ESP", which is the packet level companion to :rfc:`4106`. Two
  non-ESN cases are used, one with a 128-bit and one with a 256-bit key.
* **HMAC-SHA-256-128 integrity** -- no published ESP packet vector exists, so
  the expected ICV is recomputed in the test with :mod:`hmac` over the
  coverage :rfc:`4303` §2.8 specifies, independently of
  :meth:`SecurityAssociation.compute_icv
  <pcapkit.protocols.internet.esp.SecurityAssociation.compute_icv>`, and the
  resulting bytes are additionally pinned.

"""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import os
import struct
import tempfile
import unittest
from unittest import mock

from tests._support import close_extractor, purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)
HAS_CRYPTO = importlib.util.find_spec('cryptography') is not None


def hx(value: str) -> bytes:
    """Decode a whitespace-formatted hex string, as the RFCs print them."""
    return bytes.fromhex(''.join(value.split()))


# RFC 3602 s4 case 5 -- transport mode ESP, AES-CBC-128, no integrity.
CASE5_KEY = hx('90d382b4 10eeba7a d938c46c ec1a82bf')
CASE5_IP = hx('4500007c 08f20000 4032f9a5 c0a87b03 c0a87b64')
CASE5_ESP = hx('''
    00004321 00000001
    e96e8c08 ab465763 fd098d45 dd3ff893
    f663c25d 325c18c6 a9453e19 4e120849 a4870b66 cc6b9965 330013b4 898dc856
    a4699e52 3a55db08 0b59ec3a 8e4b7e52 775b07d1 db34ed9c 538ab50c 551b874a
    a269add0 47ad2d59 13ac19b7 cfbad4a6''')
CASE5_PLAINTEXT = hx('''
    08000ebd a70a0000 8e9c083d b95b0700 08090a0b 0c0d0e0f 10111213 14151617
    18191a1b 1c1d1e1f 20212223 24252627 28292a2b 2c2d2e2f 30313233 34353637''')
CASE5_PADDING = hx('01020304 05060708 090a0b0c 0d0e')

# RFC 3602 s4 case 7 -- tunnel mode ESP, AES-CBC-128, no integrity.
CASE7_KEY = hx('01234567 89abcdef 01234567 89abcdef')
CASE7_IP = hx('4500008c 09050000 4032f91e c0a87b03 c0a87bc8')
CASE7_ESP = hx('''
    00008765 00000002
    f4e76524 4f6407ad f13dc138 0f673f37
    773b5241 a4c44922 5e4f3ce5 ed611b0c 237ca96c f74a9301 3c1b0ea1 a0cf70f8
    e4ecaec7 8ac53aad 7a0f022b 859243c6 47752e94 a859352b 8a4d4d2d ecd136e5
    c177f132 ad3fbfb2 201ac990 4c74ee0a 109e0ca1 e4dfe9d5 a100b842 f1c22f0d''')
CASE7_PLAINTEXT = hx('''
    45000054 09040000 4001f988 c0a87b03 c0a87bc8 08009f76 a90a0100 b49c083d
    02a20400 08090a0b 0c0d0e0f 10111213 14151617 18191a1b 1c1d1e1f 20212223
    24252627 28292a2b 2c2d2e2f 30313233 34353637''')

# draft-mcgrew-gcm-test-01 s4 -- AES-GCM-ESP, 128-bit key, 4-octet salt
# ``cafebabe`` taken from the published nonce ``cafebabefacedbaddecaf888``.
GCM128_KEYMAT = hx('feffe992 8665731c 6d6a8f94 67308308 cafebabe')
GCM128_PACKET = hx('''
    0000a5f8 0000000a facedbad decaf888
    deb22cd9 b07c72c1 6e3a65be eb8df304
    a5a5897d 33ae530f 1ba76d5d 114d2a5c
    3de81827 c10e9a4f 51330d0e ec416642
    cfbb85a5 b47e48a4 ec3b9ba9 5d918bd1
    83b70d3a a8bc6ee4 c309e9d8 5a41ad4a''')
GCM128_DECRYPTED = hx('''
    4500003e 698f0000 80114dcc c0a80102
    c0a80101 0a980035 002a2343 b2d00100
    00010000 00000000 03736970 09637962
    65726369 74790264 6b000001 00010001''')

# draft-mcgrew-gcm-test-01 s4 -- AES-GCM-ESP, 256-bit key, salt ``11223344``.
GCM256_KEYMAT = hx('''
    abbccdde f0011223 34455667 78899aab
    abbccdde f0011223 34455667 78899aab
    11223344''')
GCM256_PACKET = hx('''
    4a2cbfe3 00000002 01020304 05060708
    ff425c9b 724599df 7a3bcd51 0194e00d
    6a78107f 1b0b1cbf 06efae9d 65a5d763
    748a6379 85771d34 7f054565 9f14e99d
    ef842d8e b335f4ee cfdbf831 824b4c49
    15956c96''')
GCM256_DECRYPTED = hx('''
    45000030 69a64000 80062690 c0a80102
    9389155e 0a9e008b 2dc57ee0 00000000
    70024000 20bf0000 020405b4 01010402
    01020201''')

#: Inner IPv4/TCP datagram used for the ``make(encrypt=True)`` round trip.
INNER_TCP = hx('''
    45000028 00010000 4006f97e c0a80101 c0a80102
    00140050 00000000 00000000 50022000 00000000''')


def make_pcap(frame: bytes) -> str:
    """Write a one frame Ethernet PCAP file to a temporary directory."""
    path = os.path.join(tempfile.mkdtemp(prefix='pcapkit-esp-'), 'esp.pcap')
    with open(path, 'wb') as file:
        # little endian, v2.4, LINKTYPE_ETHERNET
        file.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        file.write(struct.pack('<IIII', 0, 0, len(frame), len(frame)))
        file.write(frame)
    return path


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ESPRegistryTests(unittest.TestCase):
    """Algorithm registries and Security Association validation."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_cipher_registry(self) -> None:
        from pcapkit.const.esp.cipher import Cipher as Const_Cipher
        from pcapkit.protocols.internet.esp import CIPHER_SUITES, Cipher, CipherSuite
        from pcapkit.utilities.exceptions import ProtocolError

        # the enumeration is the generated IANA registry, re-exported
        self.assertIs(Cipher, Const_Cipher)

        # IKEv2 transform type 1 identifiers
        self.assertEqual(Cipher.ENCR_NULL, 11)
        self.assertEqual(Cipher.ENCR_AES_CBC, 12)
        self.assertEqual(Cipher.ENCR_AES_GCM_8, 18)
        self.assertEqual(Cipher.ENCR_AES_GCM_12, 19)
        self.assertEqual(Cipher.ENCR_AES_GCM_16, 20)

        # ... and their prefix-stripped aliases, which is how ESP names them
        self.assertIs(Cipher.NULL, Cipher.ENCR_NULL)
        self.assertIs(Cipher.AES_CBC, Cipher.ENCR_AES_CBC)
        self.assertIs(Cipher.AES_GCM_8, Cipher.ENCR_AES_GCM_8)
        self.assertIs(Cipher.AES_GCM_12, Cipher.ENCR_AES_GCM_12)
        self.assertIs(Cipher.AES_GCM_16, Cipher.ENCR_AES_GCM_16)

        for spelling in ('AES-CBC', 'aes_cbc', 'ENCR_AES_CBC', 12, Cipher.AES_CBC):
            with self.subTest(spelling=spelling):
                self.assertIs(CipherSuite.get(spelling).cipher, Cipher.ENCR_AES_CBC)

        # registration is not support: the registry is much larger than the
        # set of algorithms pcapkit can apply, and the suite table is the
        # authority on the latter
        self.assertGreater(len(Cipher), 30)
        self.assertEqual(set(CIPHER_SUITES), {
            Cipher.ENCR_NULL, Cipher.ENCR_AES_CBC, Cipher.ENCR_AES_GCM_8,
            Cipher.ENCR_AES_GCM_12, Cipher.ENCR_AES_GCM_16,
        })

        null = CIPHER_SUITES[Cipher.ENCR_NULL]
        cbc = CIPHER_SUITES[Cipher.ENCR_AES_CBC]
        gcm16 = CIPHER_SUITES[Cipher.ENCR_AES_GCM_16]
        self.assertFalse(cbc.is_aead)
        self.assertTrue(gcm16.is_aead)
        self.assertEqual(cbc.iv_length, 16)
        self.assertEqual(gcm16.iv_length, 8)
        self.assertEqual(null.iv_length, 0)
        self.assertEqual(cbc.block_size, 16)
        self.assertEqual(gcm16.block_size, 1)
        self.assertEqual(CIPHER_SUITES[Cipher.ENCR_AES_GCM_8].icv_length, 8)
        self.assertEqual(CIPHER_SUITES[Cipher.ENCR_AES_GCM_12].icv_length, 12)
        self.assertEqual(gcm16.icv_length, 16)
        self.assertEqual(cbc.icv_length, 0)
        self.assertEqual(gcm16.salt_length, 4)
        self.assertEqual(cbc.salt_length, 0)
        self.assertEqual(null.key_sizes, (0,))
        self.assertEqual(cbc.key_sizes, (16, 24, 32))
        self.assertFalse(null.requires_cryptography)
        self.assertTrue(cbc.requires_cryptography)

        # deliberately unimplemented, but registered: the enumeration holds
        # them -- and its own permissive ``get`` answers only "did IANA
        # register this" -- while the suite lookup refuses them
        self.assertEqual(Cipher.ENCR_3DES, 3)
        self.assertEqual(Cipher.ENCR_CHACHA20_POLY1305, 28)
        self.assertIs(Cipher.get('ENCR_3DES'), Cipher.ENCR_3DES)
        with self.assertRaises(ProtocolError):
            CipherSuite.get('3DES')
        with self.assertRaises(ProtocolError):
            CipherSuite.get('CHACHA20_POLY1305')
        with self.assertRaises(ProtocolError):
            CipherSuite.get(3)
        # and a name that is in no registry at all
        with self.assertRaises(ProtocolError):
            CipherSuite.get('ROT13')

    def test_integrity_registry(self) -> None:
        from pcapkit.const.esp.integrity import Integrity as Const_Integrity
        from pcapkit.protocols.internet.esp import INTEGRITY_SUITES, Integrity, IntegritySuite
        from pcapkit.utilities.exceptions import ProtocolError

        self.assertIs(Integrity, Const_Integrity)

        # IKEv2 transform type 3 identifiers; the registry spells 0 ``NONE``
        # rather than ``AUTH_NONE``, so that member carries no alias
        self.assertEqual(Integrity.NONE, 0)
        self.assertEqual(Integrity.AUTH_HMAC_SHA1_96, 2)
        self.assertEqual(Integrity.AUTH_HMAC_SHA2_256_128, 12)
        self.assertEqual(Integrity.AUTH_HMAC_SHA2_384_192, 13)
        self.assertEqual(Integrity.AUTH_HMAC_SHA2_512_256, 14)
        self.assertIs(Integrity.HMAC_SHA1_96, Integrity.AUTH_HMAC_SHA1_96)
        self.assertIs(Integrity.HMAC_SHA2_256_128, Integrity.AUTH_HMAC_SHA2_256_128)
        self.assertIs(Integrity.HMAC_SHA2_384_192, Integrity.AUTH_HMAC_SHA2_384_192)
        self.assertIs(Integrity.HMAC_SHA2_512_256, Integrity.AUTH_HMAC_SHA2_512_256)
        self.assertNotIn('AUTH_NONE', Integrity.__members__)

        for spelling in ('HMAC-SHA2-256-128', 'AUTH_HMAC_SHA2_256_128',
                         'hmac_sha_256_128', 12):
            with self.subTest(spelling=spelling):
                self.assertIs(IntegritySuite.get(spelling).integrity,
                              Integrity.AUTH_HMAC_SHA2_256_128)

        self.assertEqual(set(INTEGRITY_SUITES), {
            Integrity.NONE, Integrity.AUTH_HMAC_SHA1_96, Integrity.AUTH_HMAC_SHA2_256_128,
            Integrity.AUTH_HMAC_SHA2_384_192, Integrity.AUTH_HMAC_SHA2_512_256,
        })

        # RFC 4868 truncation lengths and key sizes
        self.assertEqual(INTEGRITY_SUITES[Integrity.AUTH_HMAC_SHA1_96].icv_length, 12)
        self.assertEqual(INTEGRITY_SUITES[Integrity.AUTH_HMAC_SHA2_256_128].icv_length, 16)
        self.assertEqual(INTEGRITY_SUITES[Integrity.AUTH_HMAC_SHA2_384_192].icv_length, 24)
        self.assertEqual(INTEGRITY_SUITES[Integrity.AUTH_HMAC_SHA2_512_256].icv_length, 32)
        self.assertEqual(INTEGRITY_SUITES[Integrity.AUTH_HMAC_SHA1_96].key_size, 20)
        self.assertEqual(INTEGRITY_SUITES[Integrity.AUTH_HMAC_SHA2_512_256].key_size, 64)
        self.assertIsNone(INTEGRITY_SUITES[Integrity.NONE].digest)
        self.assertEqual(INTEGRITY_SUITES[Integrity.AUTH_HMAC_SHA2_256_128].digest, 'sha256')

        # registered but unimplemented, as above
        self.assertEqual(Integrity.AUTH_HMAC_MD5_96, 1)
        self.assertEqual(Integrity.AUTH_AES_XCBC_96, 5)
        with self.assertRaises(ProtocolError):
            IntegritySuite.get('HMAC_MD5_96')
        with self.assertRaises(ProtocolError):
            IntegritySuite.get('AES_XCBC_96')
        with self.assertRaises(ProtocolError):
            IntegritySuite.get('HMAC_SHA3_256')

    def test_security_association_validation(self) -> None:
        from pcapkit.protocols.internet.esp import Cipher, Integrity, SecurityAssociation
        from pcapkit.utilities.exceptions import ProtocolError

        # RFC 4106 s8.1: the last four octets of the keying material are the salt
        sa = SecurityAssociation(spi=1, encryption=Cipher.AES_GCM_16,
                                 encryption_key=GCM128_KEYMAT)
        self.assertEqual(sa.encryption_key, GCM128_KEYMAT[:16])
        self.assertEqual(sa.salt, hx('cafebabe'))
        self.assertEqual(sa.icv_length, 16)
        self.assertTrue(sa.authenticated)

        # an explicitly supplied salt is accepted too
        split = SecurityAssociation(spi=1, encryption='aes-gcm-16',
                                    encryption_key=GCM128_KEYMAT[:16],
                                    salt=hx('cafebabe'))
        self.assertEqual(split.encryption_key, sa.encryption_key)
        self.assertEqual(split.salt, sa.salt)

        # AEAD provides its own integrity; combining is a configuration error
        with self.assertRaises(ProtocolError):
            SecurityAssociation(spi=1, encryption=Cipher.AES_GCM_16,
                                encryption_key=GCM128_KEYMAT,
                                integrity=Integrity.HMAC_SHA2_256_128,
                                integrity_key=bytes(32))

        # AES key lengths are a hard requirement
        with self.assertRaises(ProtocolError):
            SecurityAssociation(spi=1, encryption=Cipher.AES_CBC, encryption_key=bytes(15))
        with self.assertRaises(ProtocolError):
            SecurityAssociation(spi=1, encryption=Cipher.AES_GCM_16, encryption_key=bytes(4))
        with self.assertRaises(ProtocolError):
            SecurityAssociation(spi=-1)
        with self.assertRaises(ProtocolError):
            SecurityAssociation(spi=1, icv_length=-1)

        # RFC 8221 s6 notes implementations that truncate SHA-256 to 96 bits
        truncated = SecurityAssociation(spi=1, integrity=Integrity.HMAC_SHA2_256_128,
                                        integrity_key=bytes(32), icv_length=12)
        self.assertEqual(truncated.icv_length, 12)

        # an unprotected SA is legitimate: it says where the trailer is
        null = SecurityAssociation(spi=1)
        self.assertEqual(null.icv_length, 0)
        self.assertFalse(null.authenticated)
        self.assertIsNone(null.unavailable())

    def test_security_association_repr_holds_no_key_material(self) -> None:
        from pcapkit.protocols.internet.esp import (Cipher, ESPContext, Integrity,
                                                    SecurityAssociation)

        akey = bytes(range(32))
        sa = SecurityAssociation(spi=0x1234, encryption=Cipher.AES_CBC,
                                 encryption_key=CASE5_KEY,
                                 integrity=Integrity.HMAC_SHA2_256_128, integrity_key=akey,
                                 destination='192.168.123.100')
        text = repr(sa)
        self.assertNotIn(CASE5_KEY.hex(), text.lower())
        self.assertNotIn(akey.hex(), text.lower())
        self.assertIn('0x00001234', text)
        self.assertIn('AES_CBC', text)
        self.assertIn('192.168.123.100', text)

        self.assertNotIn(CASE5_KEY.hex(), repr(ESPContext(sa)).lower())

    def test_context_registry_normalisation(self) -> None:
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.esp import ESPContext, SecurityAssociation
        from pcapkit.utilities.exceptions import RegistryError

        context = ESPContext(SecurityAssociation(spi=1))
        self.assertEqual(ESPContext.protocol(), ('ESP',))

        for value in (context, [context], {'ESP': context}, ContextRegistry(context)):
            with self.subTest(value=type(value).__name__):
                registry = ContextRegistry.make(value)
                self.assertIs(registry['esp'], context)
                self.assertIn('ESP', registry)
                self.assertEqual(len(registry), 1)
                self.assertTrue(registry)
                self.assertEqual(list(registry), ['ESP'])
                self.assertIs(registry.match(('ESP',)), context)
                self.assertIs(registry.match(('ESP',), ESPContext), context)
                self.assertIsNone(registry.match(('AH',)))

        empty = ContextRegistry.make(None)
        self.assertFalse(empty)
        self.assertNotIn('ESP', empty)
        self.assertNotIn(50, empty)

        # a context of the wrong type is ignored rather than handed over
        self.assertIsNone(ContextRegistry.make(context).match(('ESP',), SecurityAssociation))  # type: ignore[arg-type]

        with self.assertRaises(RegistryError):
            ContextRegistry(context).register(context)
        with self.assertRaises(RegistryError):
            ContextRegistry.make(object())
        with self.assertRaises(RegistryError):
            ContextRegistry().register('not-a-context')  # type: ignore[arg-type]

    def test_association_matching_prefers_the_most_specific(self) -> None:
        import ipaddress

        from pcapkit.protocols.internet.esp import ESPContext, SecurityAssociation
        from pcapkit.utilities.exceptions import ProtocolError

        dst = ipaddress.ip_address('192.168.123.100')
        wildcard = SecurityAssociation()
        pinned = SecurityAssociation(spi=0x4321)
        addressed = SecurityAssociation(spi=0x4321, destination='192.168.123.100')

        context = ESPContext(wildcard, pinned, addressed)
        self.assertEqual(context.associations, (wildcard, pinned, addressed))
        self.assertIs(context.match(0x4321, dst), addressed)
        self.assertIs(context.match(0x9999, dst), wildcard)
        # the destination cannot be confirmed, so the pinned SA wins on SPI
        self.assertIs(context.match(0x4321), pinned)
        # a destination that is known and different rules the SA out
        other = ipaddress.ip_address('10.0.0.1')
        self.assertIs(context.match(0x4321, other), pinned)
        self.assertEqual(addressed.matches(0x4321, other), -1)
        self.assertEqual(addressed.matches(0x1111, dst), -1)

        with self.assertRaises(ProtocolError):
            ESPContext().register('not-an-sa')  # type: ignore[arg-type]


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ESPProtocolTests(unittest.TestCase):
    """Parsing, decryption and construction."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    ##########################################################################
    # Registration and identity.
    ##########################################################################

    def test_identity_and_registration(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.internet.esp import ESP
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.internet.ipsec import IPsec

        self.assertEqual(ESP.id(), ('ESP',))
        self.assertEqual(IPsec.id(), ('AH', 'ESP'))
        self.assertEqual(ESP.__index__(), TransType.ESP)
        self.assertEqual(ESP.__index__(), 50)
        self.assertEqual(object.__new__(ESP).__length_hint__(), 8)
        self.assertEqual(object.__new__(ESP).name, 'Encapsulating Security Payload')
        self.assertTrue(issubclass(ESP, IPsec))

        # IP protocol 50 must reach ESP rather than falling through to Raw
        registered = Internet.__proto__[TransType.ESP]
        if isinstance(registered, ModuleDescriptor):
            registered = registered.klass
        self.assertIs(registered, ESP)

    def test_module_is_importable_and_exported(self) -> None:
        import pcapkit
        from pcapkit.protocols.internet.esp import ESP

        self.assertIn('ESP', pcapkit.__all__)
        self.assertIs(pcapkit.ESP, ESP)
        self.assertIs(pcapkit.protocols.__proto__['ESP'], ESP)

    ##########################################################################
    # Without SA context.
    ##########################################################################

    def test_no_sa_reports_opaque_payload(self) -> None:
        from pcapkit.protocols.internet.esp import ESP, ESPStatus

        esp = ESP(CASE5_ESP, len(CASE5_ESP))
        info = esp.info

        self.assertEqual(info.spi, 0x4321)
        self.assertEqual(info.seq, 1)
        self.assertEqual(info.length, len(CASE5_ESP))
        self.assertEqual(esp.length, len(CASE5_ESP))
        self.assertIs(info.status, ESPStatus.NO_SA)
        self.assertIn('no security association', info.error)

        # the remainder is opaque; nothing about the trailer is guessed at
        self.assertEqual(info.payload_data, CASE5_ESP[8:])
        self.assertEqual(info.icv, b'')
        self.assertIsNone(info.next)
        self.assertIsNone(info.pad_len)
        self.assertIsNone(info.padding)
        self.assertIsNone(info.plaintext)

        # and the payload is still reachable, as Raw
        self.assertEqual(str(esp.protochain), 'ESP:Raw')
        self.assertEqual(esp.payload.data, CASE5_ESP[8:])

    def test_no_sa_never_raises_on_a_short_packet(self) -> None:
        from pcapkit.protocols.internet.esp import ESP, ESPStatus

        payload = struct.pack('!II', 0xdeadbeef, 42)
        esp = ESP(payload, len(payload))
        self.assertIs(esp.info.status, ESPStatus.NO_SA)
        self.assertEqual(esp.info.spi, 0xdeadbeef)
        self.assertEqual(esp.info.seq, 42)
        self.assertEqual(esp.info.payload_data, b'')

    def test_null_cipher_recovers_the_trailer_without_cryptography(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.esp import ESP, ESPContext, ESPStatus, SecurityAssociation

        # ESP-NULL: padding 01 02, pad length 2, next header 6 (TCP)
        packet = struct.pack('!II', 7, 3) + b'plaintext-payload' + bytes([1, 2, 2, 6])
        registry = ContextRegistry.make(ESPContext(SecurityAssociation(spi=7)))

        esp = ESP(packet, len(packet), __context__=registry)
        info = esp.info
        self.assertIs(info.status, ESPStatus.DECRYPTED)
        self.assertEqual(info.plaintext, b'plaintext-payload')
        self.assertEqual(info.pad_len, 2)
        self.assertEqual(info.padding, bytes([1, 2]))
        self.assertEqual(info.next, TransType.TCP)
        self.assertEqual(info.icv, b'')

    ##########################################################################
    # AES-CBC, RFC 3602 known answer vectors.
    ##########################################################################

    @unittest.skipUnless(HAS_CRYPTO, 'cryptography not installed')
    def test_aes_cbc_transport_mode_rfc3602_case5(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.esp import (ESP, Cipher, ESPContext, ESPStatus,
                                                    SecurityAssociation)

        sa = SecurityAssociation(spi=0x4321, encryption=Cipher.AES_CBC,
                                 encryption_key=CASE5_KEY)
        esp = ESP(CASE5_ESP, len(CASE5_ESP),
                  __context__=ContextRegistry.make(ESPContext(sa)))
        info = esp.info

        self.assertIs(info.status, ESPStatus.DECRYPTED)
        self.assertIsNone(info.error)
        self.assertEqual(info.spi, 0x4321)
        self.assertEqual(info.seq, 1)
        self.assertEqual(info.plaintext, CASE5_PLAINTEXT)
        self.assertEqual(info.pad_len, 0x0e)
        self.assertEqual(info.padding, CASE5_PADDING)
        self.assertEqual(info.next, TransType.ICMP)
        self.assertEqual(info.icv, b'')
        # the IV stays on the wire as part of the payload data
        self.assertEqual(info.payload_data, CASE5_ESP[8:])

    @unittest.skipUnless(HAS_CRYPTO, 'cryptography not installed')
    def test_aes_cbc_tunnel_mode_rfc3602_case7_decodes_inner_ip(self) -> None:
        import ipaddress

        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.esp import (Cipher, ESPContext, ESPStatus,
                                                    SecurityAssociation)
        from pcapkit.protocols.internet.ipv4 import IPv4

        sa = SecurityAssociation(spi=0x8765, encryption=Cipher.AES_CBC,
                                 encryption_key=CASE7_KEY)
        packet = CASE7_IP + CASE7_ESP
        ipv4 = IPv4(packet, len(packet), __context__=ContextRegistry.make(ESPContext(sa)))

        esp = ipv4.payload
        self.assertIs(esp.info.status, ESPStatus.DECRYPTED)
        self.assertEqual(esp.info.plaintext, CASE7_PLAINTEXT)
        self.assertEqual(esp.info.pad_len, 0x0a)
        self.assertEqual(esp.info.next, TransType.IPv4)

        # the encapsulated datagram is dispatched to the next layer
        self.assertEqual(str(ipv4.protochain), 'IPv4:ESP:IPv4:ICMP')
        inner = esp.payload
        self.assertEqual(inner.info.src, ipaddress.ip_address('192.168.123.3'))
        self.assertEqual(inner.info.dst, ipaddress.ip_address('192.168.123.200'))

    @unittest.skipUnless(HAS_CRYPTO, 'cryptography not installed')
    def test_destination_keyed_association(self) -> None:
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.esp import (Cipher, ESPContext, ESPStatus,
                                                    SecurityAssociation)
        from pcapkit.protocols.internet.ipv4 import IPv4

        packet = CASE7_IP + CASE7_ESP

        def parse(destination: str) -> 'ESPStatus':
            sa = SecurityAssociation(spi=0x8765, encryption=Cipher.AES_CBC,
                                     encryption_key=CASE7_KEY, destination=destination)
            ipv4 = IPv4(packet, len(packet),
                        __context__=ContextRegistry.make(ESPContext(sa)))
            return ipv4.payload.info.status

        # the outer IPv4 destination reaches ESP, so an SA pinned to the right
        # address matches and one pinned elsewhere does not
        self.assertIs(parse('192.168.123.200'), ESPStatus.DECRYPTED)
        self.assertIs(parse('10.0.0.1'), ESPStatus.NO_SA)

    ##########################################################################
    # AES-GCM, draft-mcgrew-gcm-test-01 known answer vectors.
    ##########################################################################

    @unittest.skipUnless(HAS_CRYPTO, 'cryptography not installed')
    def test_aes_gcm_128_mcgrew_vector(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.esp import (ESP, Cipher, ESPContext, ESPStatus,
                                                    SecurityAssociation)

        sa = SecurityAssociation(spi=0x0000a5f8, encryption=Cipher.AES_GCM_16,
                                 encryption_key=GCM128_KEYMAT)
        esp = ESP(GCM128_PACKET, len(GCM128_PACKET),
                  __context__=ContextRegistry.make(ESPContext(sa)))
        info = esp.info

        self.assertIs(info.status, ESPStatus.DECRYPTED)
        self.assertEqual(info.spi, 0x0000a5f8)
        self.assertEqual(info.seq, 10)
        # pad length 0, next header 1 -- the last two octets of the plaintext
        self.assertEqual(info.pad_len, 0)
        self.assertEqual(info.padding, b'')
        self.assertEqual(info.next, TransType.ICMP)
        self.assertEqual(info.plaintext, GCM128_DECRYPTED[:-2])
        # the AEAD tag is the ICV, and it is not part of the payload data
        self.assertEqual(info.icv, GCM128_PACKET[-16:])
        self.assertEqual(info.payload_data, GCM128_PACKET[8:-16])

    @unittest.skipUnless(HAS_CRYPTO, 'cryptography not installed')
    def test_aes_gcm_256_mcgrew_vector(self) -> None:
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.esp import ESP, ESPContext, ESPStatus, SecurityAssociation

        sa = SecurityAssociation(spi=0x4a2cbfe3, encryption='aes-gcm-16',
                                 encryption_key=GCM256_KEYMAT)
        self.assertEqual(sa.encryption_key, GCM256_KEYMAT[:32])
        self.assertEqual(sa.salt, hx('11223344'))

        esp = ESP(GCM256_PACKET, len(GCM256_PACKET),
                  __context__=ContextRegistry.make(ESPContext(sa)))
        info = esp.info

        self.assertIs(info.status, ESPStatus.DECRYPTED)
        self.assertEqual(info.seq, 2)
        self.assertEqual(info.plaintext, GCM256_DECRYPTED[:-4])
        self.assertEqual(info.pad_len, 2)
        self.assertEqual(info.padding, bytes([1, 2]))
        self.assertEqual(info.icv, GCM256_PACKET[-16:])

    ##########################################################################
    # Failure modes.
    ##########################################################################

    @unittest.skipUnless(HAS_CRYPTO, 'cryptography not installed')
    def test_wrong_encryption_key_fails_cleanly(self) -> None:
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet import esp as esp_module
        from pcapkit.protocols.internet.esp import (ESP, Cipher, ESPContext, ESPStatus,
                                                    SecurityAssociation)

        sa = SecurityAssociation(spi=0x4321, encryption=Cipher.AES_CBC,
                                 encryption_key=bytes(16))
        registry = ContextRegistry.make(ESPContext(sa))

        with mock.patch.object(esp_module, 'warn') as warned:
            esp = ESP(CASE5_ESP, len(CASE5_ESP), __context__=registry)
        info = esp.info

        # no garbage plaintext is produced, and the failure is announced
        self.assertIs(info.status, ESPStatus.DECRYPT_FAILED)
        self.assertIsNone(info.plaintext)
        self.assertIsNone(info.next)
        self.assertIsNone(info.pad_len)
        self.assertIn('most likely wrong', info.error)
        warned.assert_called()
        self.assertEqual(str(esp.protochain), 'ESP:Raw')

    @unittest.skipUnless(HAS_CRYPTO, 'cryptography not installed')
    def test_wrong_aead_key_fails_the_tag_check(self) -> None:
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.esp import (ESP, Cipher, ESPContext, ESPStatus,
                                                    SecurityAssociation)

        sa = SecurityAssociation(spi=0x0000a5f8, encryption=Cipher.AES_GCM_16,
                                 encryption_key=bytes(16) + hx('cafebabe'))
        esp = ESP(GCM128_PACKET, len(GCM128_PACKET),
                  __context__=ContextRegistry.make(ESPContext(sa)))

        self.assertIs(esp.info.status, ESPStatus.AUTH_FAILED)
        self.assertIsNone(esp.info.plaintext)
        self.assertIn('authentication tag does not verify', esp.info.error)

    @unittest.skipUnless(HAS_CRYPTO, 'cryptography not installed')
    def test_padding_pattern_is_only_decisive_without_integrity(self) -> None:
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet import esp as esp_module
        from pcapkit.protocols.internet.esp import (ESP, Cipher, ESPContext, ESPStatus,
                                                    SecurityAssociation)

        # build a packet whose padding is zeros rather than the RFC 4303 s2.4
        # monotonically increasing sequence; 16 payload + 14 padding + 2
        # trailer octets is a whole number of AES blocks
        key = CASE5_KEY
        builder = SecurityAssociation(spi=0x55, encryption=Cipher.AES_CBC, encryption_key=key)
        plaintext = b'sixteen-byte-pay' + bytes(14) + bytes([14, 6])
        self.assertEqual(len(plaintext) % 16, 0)
        body, _ = builder.encrypt(0x55, 1, plaintext, iv=bytes(range(16)))
        packet = struct.pack('!II', 0x55, 1) + body

        # strict, unauthenticated -> the mismatch is treated as a wrong key
        strict = ContextRegistry.make(ESPContext(
            SecurityAssociation(spi=0x55, encryption=Cipher.AES_CBC, encryption_key=key)))
        self.assertIs(ESP(packet, len(packet), __context__=strict).info.status,
                      ESPStatus.DECRYPT_FAILED)

        # strict=False -> warn, but accept the payload
        lenient = ContextRegistry.make(ESPContext(
            SecurityAssociation(spi=0x55, encryption=Cipher.AES_CBC, encryption_key=key,
                                strict=False)))
        with mock.patch.object(esp_module, 'warn') as warned:
            esp = ESP(packet, len(packet), __context__=lenient)
        self.assertIs(esp.info.status, ESPStatus.DECRYPTED)
        self.assertEqual(esp.info.plaintext, b'sixteen-byte-pay')
        self.assertEqual(esp.info.padding, bytes(14))
        warned.assert_called()

    @unittest.skipUnless(HAS_CRYPTO, 'cryptography not installed')
    def test_truncated_icv_is_reported(self) -> None:
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.esp import (ESP, Cipher, ESPContext, ESPStatus,
                                                    SecurityAssociation)

        sa = SecurityAssociation(spi=0x0000a5f8, encryption=Cipher.AES_GCM_16,
                                 encryption_key=GCM128_KEYMAT)
        registry = ContextRegistry.make(ESPContext(sa))

        # only the SPI, the sequence number and 8 octets remain, which cannot
        # hold the 16-octet ICV the SA declares
        short = GCM128_PACKET[:16]
        esp = ESP(short, len(short), __context__=registry)
        self.assertIs(esp.info.status, ESPStatus.TRUNCATED)
        self.assertIn('shorter than the 16-octet ICV', esp.info.error)
        self.assertIsNone(esp.info.plaintext)
        self.assertEqual(esp.info.payload_data, short[8:])

        # a payload that is not a whole number of AES blocks fails too
        cbc = ContextRegistry.make(ESPContext(
            SecurityAssociation(spi=0x4321, encryption=Cipher.AES_CBC,
                                encryption_key=CASE5_KEY)))
        clipped = CASE5_ESP[:-3]
        esp = ESP(clipped, len(clipped), __context__=cbc)
        self.assertIs(esp.info.status, ESPStatus.DECRYPT_FAILED)
        self.assertIsNone(esp.info.plaintext)

    def test_degrades_without_cryptography(self) -> None:
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet import esp as esp_module
        from pcapkit.protocols.internet.esp import (ESP, Cipher, ESPContext, ESPStatus,
                                                    SecurityAssociation)

        with mock.patch.object(esp_module, 'load_cryptography', return_value=None):
            with mock.patch.object(esp_module, 'warn') as warned:
                sa = SecurityAssociation(spi=0x4321, encryption=Cipher.AES_CBC,
                                         encryption_key=CASE5_KEY)
            # the SA warns as soon as it is built, so the problem is visible
            # before a single packet has been parsed
            warned.assert_called_once()
            self.assertIn('cryptography', warned.call_args.args[0])
            self.assertIsNotNone(sa.unavailable())

            esp = ESP(CASE5_ESP, len(CASE5_ESP),
                      __context__=ContextRegistry.make(ESPContext(sa)))

        info = esp.info
        self.assertIs(info.status, ESPStatus.UNSUPPORTED)
        self.assertIn('cryptography', info.error)
        self.assertIsNone(info.plaintext)
        # ... and the packet still parses, down the opaque payload path
        self.assertEqual(info.spi, 0x4321)
        self.assertEqual(info.payload_data, CASE5_ESP[8:])
        self.assertEqual(str(esp.protochain), 'ESP:Raw')

    ##########################################################################
    # Integrity.
    ##########################################################################

    @unittest.skipUnless(HAS_CRYPTO, 'cryptography not installed')
    def test_hmac_sha256_integrity_round_trip_and_mismatch(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.esp import (ESP, Cipher, ESPContext, ESPStatus, Integrity,
                                                    SecurityAssociation)

        akey = bytes(range(32))
        iv = bytes(range(16))

        def association(ckey: bytes = CASE5_KEY, ikey: bytes = akey) -> 'SecurityAssociation':
            return SecurityAssociation(spi=0x1234, encryption=Cipher.AES_CBC,
                                       encryption_key=ckey,
                                       integrity=Integrity.HMAC_SHA2_256_128,
                                       integrity_key=ikey)

        registry = ContextRegistry.make(ESPContext(association()))
        built = ESP(spi=0x1234, seq=7, next=TransType.IPv4, encrypt=True, iv=iv,
                    payload=INNER_TCP, __context__=registry)
        wire = bytes(built)

        # RFC 4303 s2.8: the ICV covers the SPI, the sequence number, the
        # payload data (IV included) and the explicit trailer -- everything
        # transmitted bar the ICV itself. Recomputed here with the standard
        # library rather than with pcapkit's own helper.
        expected = hmac.new(akey, wire[:-16], hashlib.sha256).digest()[:16]
        self.assertEqual(wire[-16:], expected)
        # pinned, so a change in the covered range cannot pass silently
        self.assertEqual(wire[-16:].hex(), '29003487091e61aebabd417e11ee3242')

        esp = ESP(wire, len(wire), __context__=registry)
        info = esp.info
        self.assertIs(info.status, ESPStatus.DECRYPTED)
        self.assertEqual(info.plaintext, INNER_TCP)
        self.assertEqual(info.next, TransType.IPv4)
        self.assertEqual(info.icv, expected)
        # an ESP tunnelled TCP segment decodes as TCP
        self.assertEqual(str(esp.protochain), 'ESP:IPv4:TCP')
        self.assertEqual(esp.payload.payload.info.dstport, 80)

        # a wrong integrity key is caught before decryption is attempted
        bad_auth = ContextRegistry.make(ESPContext(association(ikey=bytes(32))))
        failed = ESP(wire, len(wire), __context__=bad_auth)
        self.assertIs(failed.info.status, ESPStatus.AUTH_FAILED)
        self.assertIsNone(failed.info.plaintext)
        self.assertIn('integrity check value does not verify', failed.info.error)

        # a right integrity key with a wrong cipher key gets past the ICV and
        # is caught by the trailer instead
        bad_cipher = ContextRegistry.make(ESPContext(association(ckey=bytes(16))))
        failed = ESP(wire, len(wire), __context__=bad_cipher)
        self.assertIs(failed.info.status, ESPStatus.DECRYPT_FAILED)
        self.assertIsNone(failed.info.plaintext)

        # a corrupted ICV is a mismatch
        tampered = wire[:-1] + bytes([wire[-1] ^ 0xFF])
        failed = ESP(tampered, len(tampered), __context__=registry)
        self.assertIs(failed.info.status, ESPStatus.AUTH_FAILED)

    def test_compute_icv_requires_an_integrity_algorithm(self) -> None:
        from pcapkit.protocols.internet.esp import Integrity, SecurityAssociation
        from pcapkit.utilities.exceptions import ProtocolError

        sa = SecurityAssociation(spi=1, integrity=Integrity.HMAC_SHA1_96,
                                 integrity_key=bytes(20))
        icv = sa.compute_icv(1, 1, b'body')
        self.assertEqual(len(icv), 12)
        self.assertEqual(icv, hmac.new(bytes(20), struct.pack('!II', 1, 1) + b'body',
                                       hashlib.sha1).digest()[:12])

        with self.assertRaises(ProtocolError):
            SecurityAssociation(spi=1).compute_icv(1, 1, b'body')

    ##########################################################################
    # Construction.
    ##########################################################################

    def test_make_verbatim_round_trip(self) -> None:
        from pcapkit.protocols.internet.esp import ESP, ESPStatus

        built = ESP(spi=9, seq=3, payload=b'opaque-ciphertext', icv=b'ICV!')
        wire = bytes(built)
        self.assertEqual(wire, struct.pack('!II', 9, 3) + b'opaque-ciphertextICV!')

        schema = object.__new__(ESP).make(spi=9, seq=3, payload=b'body')
        self.assertEqual(schema.spi, 9)
        self.assertEqual(schema.seq, 3)
        self.assertEqual(schema.payload, b'body')

        parsed = ESP(wire, len(wire))
        self.assertIs(parsed.info.status, ESPStatus.NO_SA)
        self.assertEqual(parsed.info.payload_data, b'opaque-ciphertextICV!')

        # from_data reproduces the packet byte for byte, without needing keys
        values = ESP._make_data(parsed.info)
        self.assertEqual(values, {'spi': 9, 'seq': 3,
                                  'payload': b'opaque-ciphertextICV!'})
        self.assertEqual(bytes(ESP.from_data(parsed.info)), wire)

    @unittest.skipUnless(HAS_CRYPTO, 'cryptography not installed')
    def test_make_encrypt_pads_to_the_block_size(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.esp import (ESP, Cipher, ESPContext, ESPStatus,
                                                    SecurityAssociation)
        from pcapkit.utilities.exceptions import ProtocolError, ProtocolUnbound

        sa = SecurityAssociation(spi=0x77, encryption=Cipher.AES_CBC,
                                 encryption_key=CASE5_KEY)
        registry = ContextRegistry.make(ESPContext(sa))

        for size in range(0, 20):
            with self.subTest(size=size):
                built = ESP(spi=0x77, seq=1, next=TransType.UDP, encrypt=True,
                            iv=bytes(16), payload=bytes(size), __context__=registry)
                wire = bytes(built)
                # 8 octets of header, 16 of IV, then whole AES blocks
                self.assertEqual((len(wire) - 24) % 16, 0)

                esp = ESP(wire, len(wire), __context__=registry)
                self.assertIs(esp.info.status, ESPStatus.DECRYPTED)
                self.assertEqual(esp.info.plaintext, bytes(size))
                self.assertEqual(esp.info.next, TransType.UDP)
                # RFC 4303 s2.4: padding is 1, 2, 3, ...
                self.assertEqual(esp.info.padding,
                                 bytes(range(1, esp.info.pad_len + 1)))

        # an explicit pad length that breaks the alignment is refused
        with self.assertRaises(ProtocolError):
            ESP(spi=0x77, seq=1, encrypt=True, pad_len=1, payload=bytes(8),
                __context__=registry)
        # ... as is asking to encrypt with no SA at all
        with self.assertRaises(ProtocolError):
            ESP(spi=0x99, seq=1, encrypt=True, payload=b'x')
        # ... and a payload that is neither bytes, a schema nor a protocol
        with self.assertRaises(ProtocolUnbound):
            object.__new__(ESP)._payload_bytes(object())

    @unittest.skipUnless(HAS_CRYPTO, 'cryptography not installed')
    def test_make_encrypt_aead_round_trip(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.esp import (ESP, Cipher, ESPContext, ESPStatus,
                                                    SecurityAssociation)

        for cipher, icv_length in ((Cipher.AES_GCM_8, 8),
                                   (Cipher.AES_GCM_12, 12),
                                   (Cipher.AES_GCM_16, 16)):
            with self.subTest(cipher=cipher.name):
                sa = SecurityAssociation(spi=0x88, encryption=cipher,
                                         encryption_key=GCM128_KEYMAT)
                self.assertEqual(sa.icv_length, icv_length)
                registry = ContextRegistry.make(ESPContext(sa))

                built = ESP(spi=0x88, seq=5, next=TransType.IPv4, encrypt=True,
                            iv=bytes(range(8)), payload=INNER_TCP, __context__=registry)
                wire = bytes(built)
                esp = ESP(wire, len(wire), __context__=registry)

                self.assertIs(esp.info.status, ESPStatus.DECRYPTED)
                self.assertEqual(esp.info.plaintext, INNER_TCP)
                self.assertEqual(len(esp.info.icv), icv_length)
                self.assertEqual(str(esp.protochain), 'ESP:IPv4:TCP')

    ##########################################################################
    # Extraction, end to end.
    ##########################################################################

    @unittest.skipUnless(HAS_CRYPTO, 'cryptography not installed')
    def test_extract_end_to_end_with_context(self) -> None:
        import pcapkit
        from pcapkit.protocols.internet.esp import (Cipher, ESPContext, ESPStatus,
                                                    SecurityAssociation)

        ethernet = hx('001122334455 66778899aabb 0800')
        path = make_pcap(ethernet + CASE7_IP + CASE7_ESP)
        output = os.path.join(os.path.dirname(path), 'out.txt')

        sa = SecurityAssociation(spi=0x8765, encryption=Cipher.AES_CBC,
                                 encryption_key=CASE7_KEY,
                                 destination='192.168.123.200')
        extraction = pcapkit.extract(fin=path, fout=output, format='tree',
                                     context=ESPContext(sa))
        try:
            frame = extraction.frame[0]
            self.assertEqual(str(frame.protochain), 'Ethernet:IPv4:ESP:IPv4:ICMP')
            esp = frame.info.ethernet.ipv4.esp
            self.assertIs(esp.status, ESPStatus.DECRYPTED)
            self.assertEqual(esp.plaintext, CASE7_PLAINTEXT)
        finally:
            close_extractor(extraction)

        # the dump carries the packet, but never the key material
        with open(output, 'r', encoding='utf-8') as file:
            text = file.read()
        self.assertIn('ESP', text)
        self.assertNotIn(CASE7_KEY.hex(), text.lower().replace(' ', ''))
        self.assertNotIn('SecurityAssociation', text)
        self.assertNotIn('encryption_key', text)

        # without the context, the same capture still extracts
        extraction = pcapkit.extract(fin=path, nofile=True)
        try:
            frame = extraction.frame[0]
            self.assertEqual(str(frame.protochain), 'Ethernet:IPv4:ESP:Raw')
            self.assertIs(frame.info.ethernet.ipv4.esp.status, ESPStatus.NO_SA)
        finally:
            close_extractor(extraction)

    @unittest.skipUnless(HAS_CRYPTO, 'cryptography not installed')
    def test_ipv6_extension_header_position(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.esp import (ESP, Cipher, ESPContext, ESPStatus,
                                                    SecurityAssociation)
        from pcapkit.protocols.internet.ipv6 import IPv6

        sa = SecurityAssociation(spi=0x66, encryption=Cipher.AES_CBC,
                                 encryption_key=CASE5_KEY)
        registry = ContextRegistry.make(ESPContext(sa))

        built = ESP(spi=0x66, seq=1, next=TransType.TCP, encrypt=True, iv=bytes(16),
                    payload=INNER_TCP[20:], __context__=registry)
        body = bytes(built)

        # IPv6 header with next header 50 (ESP)
        header = (bytes([0x60, 0, 0, 0]) + struct.pack('!H', len(body)) + bytes([50, 64])
                  + bytes.fromhex('20010db8' + '00' * 12)
                  + bytes.fromhex('20010db8' + '00' * 11 + '01'))
        packet = header + body

        ipv6 = IPv6(packet, len(packet), __context__=registry)
        esp = ipv6.info.esp
        self.assertIs(esp.status, ESPStatus.DECRYPTED)
        self.assertEqual(esp.next, TransType.TCP)
        self.assertEqual(esp.plaintext, INNER_TCP[20:])
        # ESP terminates the IPv6 header chain, so it is recorded as an
        # extension header and carries the inner layer itself
        self.assertIn(str(ESP.__index__()), [str(key) for key in ipv6.extension_headers])
        self.assertIn('ESP', str(ipv6.protochain))


if __name__ == '__main__':
    unittest.main()
