# -*- coding: utf-8 -*-
"""ESP - Encapsulating Security Payload
==========================================

.. module:: pcapkit.protocols.internet.esp

:mod:`pcapkit.protocols.internet.esp` contains
:class:`~pcapkit.protocols.internet.esp.ESP` only,
which implements extractor for Encapsulating
Security Payload (ESP) [*]_, whose structure is
described as below:

======= ========= ===================== ==============================================
Octets      Bits        Name                    Description
======= ========= ===================== ==============================================
  0           0   ``esp.spi``             Security Parameters Index (SPI)
  4          32   ``esp.seq``             Sequence Number
  8          64   ``esp.payload_data``    Payload Data (variable, encrypted)
  ?           ?                           Padding (0-255 bytes, encrypted)
  ?           ?   ``esp.pad_len``         Pad Length (encrypted)
  ?           ?   ``esp.next``            Next Header (encrypted)
  ?           ?   ``esp.icv``             Integrity Check Value (ICV, variable)
======= ========= ===================== ==============================================

Unlike every other protocol in :mod:`pcapkit`, ESP is **not** self
describing. :rfc:`4303` places the ``Pad Length`` and ``Next Header``
fields *inside* the ciphertext, and leaves the length of the ``Integrity
Check Value`` to be determined by the Security Association (SA), which is
negotiated out of band. Therefore:

* **Without** SA context, :class:`ESP` parses the ``SPI`` and ``Sequence
  Number``, reports the remainder as an opaque encrypted payload, and says
  so through :attr:`esp.status <pcapkit.protocols.data.internet.esp.ESP.status>`.
  It does *not* guess at the trailer, and it does not raise.
* **With** SA context, :class:`ESP` splits off the ICV, verifies integrity,
  decrypts, strips the padding using ``Pad Length``, and dispatches the
  recovered plaintext to the next layer using ``Next Header`` -- so an
  ESP tunnelled TCP segment decodes as TCP.

SA context is supplied through the generic, protocol keyed context channel
in :mod:`pcapkit.corekit.context`:

.. code-block:: python

   import pcapkit
   from pcapkit.protocols.internet.esp import (Cipher, ESPContext, Integrity,
                                               SecurityAssociation)

   sa = SecurityAssociation(
       spi=0x4321,
       encryption=Cipher.AES_CBC,
       encryption_key=bytes.fromhex('90d382b410eeba7ad938c46cec1a82bf'),
       integrity=Integrity.HMAC_SHA2_256_128,
       integrity_key=bytes.fromhex('00' * 32),
       destination='192.168.123.100',   # optional, disambiguates several tunnels
   )
   extraction = pcapkit.extract('esp.pcap', context=ESPContext(sa))

Registered algorithms, and supported ones
-----------------------------------------

ESP has no algorithm registry of its own -- an SA's algorithms are negotiated
by IKEv2 -- so :class:`Cipher <pcapkit.const.esp.cipher.Cipher>` and
:class:`Integrity <pcapkit.const.esp.integrity.Integrity>` are generated from
the IKEv2 *transform ID* sub-registries and enumerate everything **IANA has
registered**: 3DES, AES-CTR, the AES-CCM and Camellia families,
ChaCha20-Poly1305, the implicit IV variants of :rfc:`8750`, the :rfc:`9227`
MGM suites, and the transforms long since deprecated.

**Registration is not support.** A member of either enumeration says only that
IANA assigned the transform an ID; what :mod:`pcapkit` can actually apply is
the separate, explicit :data:`CIPHER_SUITES` and :data:`INTEGRITY_SUITES`
tables, and :meth:`CipherSuite.get` / :meth:`IntegritySuite.get` refuse
anything outside them rather than half-working:

.. code-block:: python

   >>> Cipher.get('ENCR_3DES')          # registered, so the enum has it
   <Cipher.ENCR_3DES: 3>
   >>> CipherSuite.get('ENCR_3DES')     # but ESP cannot apply it
   Traceback (most recent call last):
     ...
   pcapkit.utilities.exceptions.ProtocolError: unsupported ESP encryption
   algorithm: ENCR_3DES; pcapkit implements ENCR_NULL, ENCR_AES_CBC,
   ENCR_AES_GCM_8, ENCR_AES_GCM_12, ENCR_AES_GCM_16

Decryption requires the optional |cryptography|_ dependency
(``pip install pypcapkit[crypto]``). :mod:`pcapkit` imports and works
without it; an SA that names an AES suite simply degrades to the opaque
payload path, with a warning.

The supported set is anchored on the *mandatory to implement* algorithms of
:rfc:`8221`. The rows marked ``yes`` are exactly the keys of
:data:`CIPHER_SUITES`; everything else the registry lists is enumerated and
rejected.

============================ =================== ============ ==================================
Encryption                   :rfc:`8221` status   Implemented  Notes
============================ =================== ============ ==================================
``ENCR_NULL``                MUST                yes          :rfc:`2410`; needs no ``cryptography``
``ENCR_AES_CBC``             MUST                yes          :rfc:`3602`; 128/192/256-bit keys
``ENCR_AES_GCM_16``          MUST                yes          :rfc:`4106`; 8-octet explicit IV
``ENCR_AES_GCM_8``           --                  yes          :rfc:`4106`, 8-octet ICV
``ENCR_AES_GCM_12``          --                  yes          :rfc:`4106`, 12-octet ICV
``ENCR_AES_CCM_8``           SHOULD              **no**       registered, not implemented
``ENCR_CHACHA20_POLY1305``   SHOULD              **no**       registered, not implemented
``ENCR_3DES``                SHOULD NOT          **no**       registered, deliberately omitted
DES, Blowfish, 3IDEA         MUST NOT            **no**       registered, deliberately omitted
============================ =================== ============ ==================================

"DES, Blowfish, 3IDEA" above covers ``ENCR_DES``, ``ENCR_DES_IV64``,
``ENCR_DES_IV32``, ``ENCR_BLOWFISH`` and ``ENCR_3IDEA``.

Likewise, the rows marked ``yes`` below are exactly the keys of
:data:`INTEGRITY_SUITES`:

============================ =================== ============ ==================================
Integrity                    :rfc:`8221` status   Implemented  Notes
============================ =================== ============ ==================================
``NONE``                     MUST (AEAD only)    yes          for AEAD suites
``AUTH_HMAC_SHA2_256_128``   MUST                yes          :rfc:`4868`
``AUTH_HMAC_SHA2_512_256``   SHOULD              yes          :rfc:`4868`
``AUTH_HMAC_SHA2_384_192``   --                  yes          :rfc:`4868`
``AUTH_HMAC_SHA1_96``        MUST-               yes          :rfc:`2404`; still widely captured
``AUTH_AES_XCBC_96``         SHOULD / MAY        **no**       registered, not implemented
``AUTH_AES_*_GMAC``          MAY                 **no**       registered, not implemented
MD5, DES-MAC, KPDK-MD5       MUST NOT            **no**       registered, deliberately omitted
============================ =================== ============ ==================================

"MD5, DES-MAC, KPDK-MD5" above covers ``AUTH_HMAC_MD5_96``,
``AUTH_HMAC_MD5_128``, ``AUTH_DES_MAC`` and ``AUTH_KPDK_MD5``. The registry
spells the "no integrity algorithm" transform ``NONE`` rather than
``AUTH_NONE``, and :attr:`Integrity.NONE
<pcapkit.const.esp.integrity.Integrity.NONE>` follows it.

Both enumerations additionally carry each transform's prefix-stripped spelling
as an alias, since that is how ESP and :rfc:`8221` name the algorithms, so
:attr:`Cipher.AES_CBC <pcapkit.const.esp.cipher.Cipher.AES_CBC>` and
:attr:`Cipher.ENCR_AES_CBC <pcapkit.const.esp.cipher.Cipher.ENCR_AES_CBC>`
are the same member.

Known limitations
-----------------

* **Extended Sequence Numbers (ESN,** :rfc:`4303` **§2.2.1) are not
  supported.** The high-order 32 bits of an ESN are not transmitted, and a
  stateless parser cannot recover them; they are required both for the ICV
  computation and for the AEAD associated data. An ESN protected packet
  therefore fails the integrity check *cleanly* rather than being decoded.
* **Traffic Flow Confidentiality (TFC) padding (§2.4) is not detected.**
  TFC padding is indistinguishable from real payload without inspecting the
  inner protocol's own length field, so it is handed to the next layer as
  part of the plaintext.
* **Anti-replay is not performed.** :mod:`pcapkit` is an analyser, not a
  receiver; the sequence number is reported, never checked.
* The ICV is *verified* but a failure is reported rather than raised, so
  that one bad packet does not abort a capture.

.. |cryptography| replace:: ``cryptography``
.. _cryptography: https://cryptography.io

.. [*] https://en.wikipedia.org/wiki/IPsec

"""
import enum
import hashlib
import hmac
import ipaddress
import os
from typing import TYPE_CHECKING, overload

from pcapkit.const.esp.cipher import Cipher
from pcapkit.corekit.infoclass import Info, info_final
from pcapkit.const.esp.integrity import Integrity
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.context import ProtocolContext
from pcapkit.protocols.data.internet.esp import ESP as Data_ESP
from pcapkit.protocols.internet.ipsec import IPsec
from pcapkit.protocols.schema.internet.esp import ESP as Schema_ESP
from pcapkit.protocols.schema.schema import Schema
from pcapkit.utilities.exceptions import ProtocolError, ProtocolUnbound
from pcapkit.utilities.warnings import ProtocolWarning, warn

__all__ = ['ESP', 'ESPStatus', 'Cipher', 'Integrity', 'CipherSuite', 'IntegritySuite',
           'CIPHER_SUITES', 'INTEGRITY_SUITES', 'SecurityAssociation', 'ESPContext']

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from ipaddress import IPv4Address, IPv6Address
    from typing import IO, Any, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase as Protocol

#: Cached :mod:`cryptography` primitives, c.f. :func:`load_cryptography`.
#: :data:`NotImplemented` means the import has not been attempted yet, and
#: :data:`None` that it was attempted and |cryptography|_ is not installed --
#: three states, so a missing dependency is not retried on every frame.
_CRYPTO = NotImplemented  # type: Any


def load_cryptography() -> 'Optional[tuple[Any, Any, Any, Type[Exception]]]':
    """Load the optional |cryptography|_ primitives.

    Returns:
        A 4-tuple of ``(Cipher, algorithms, modes, InvalidTag)`` taken from
        :mod:`cryptography.hazmat.primitives.ciphers` and
        :mod:`cryptography.exceptions`, or :data:`None` when
        |cryptography|_ is not installed.

    Notes:
        The import is attempted at most once and the outcome is cached, so
        that a capture full of ESP packets does not pay for a failing import
        on every frame.

    """
    global _CRYPTO  # pylint: disable=global-statement

    if _CRYPTO is NotImplemented:
        try:
            from cryptography.exceptions import \
                InvalidTag as _InvalidTag  # pylint: disable=import-outside-toplevel
            from cryptography.hazmat.primitives.ciphers import \
                Cipher as _CryptoCipher  # pylint: disable=import-outside-toplevel
            from cryptography.hazmat.primitives.ciphers import \
                algorithms as _crypto_algorithms  # pylint: disable=import-outside-toplevel
            from cryptography.hazmat.primitives.ciphers import \
                modes as _crypto_modes  # pylint: disable=import-outside-toplevel
        except ImportError:
            _CRYPTO = None
        else:
            _CRYPTO = (_CryptoCipher, _crypto_algorithms, _crypto_modes, _InvalidTag)
    return _CRYPTO


##############################################################################
# Algorithm support.
##############################################################################


def _resolve(registry: 'Type[Cipher] | Type[Integrity]', value: 'Any',
             prefix: 'str', kind: 'str') -> 'Any':
    """Resolve ``value`` to a member of an IKEv2 transform registry.

    Args:
        registry: :class:`Cipher <pcapkit.const.esp.cipher.Cipher>` or
            :class:`Integrity <pcapkit.const.esp.integrity.Integrity>`.
        value: A member of ``registry``, an IKEv2 transform ID, or a
            transform name.
        prefix: Prefix the registry spells its names with, i.e. ``'ENCR_'``
            or ``'AUTH_'``.
        kind: Word naming the registry for the error message, i.e.
            ``'encryption'`` or ``'integrity'``.

    Returns:
        The corresponding member of ``registry``.

    Raises:
        ProtocolError: If ``value`` names nothing the registry holds.

    Notes:
        Both enumerations carry each transform's prefix-stripped spelling as
        an alias, so a plain lookup already accepts ``'AES_CBC'`` as well as
        ``'ENCR_AES_CBC'``. ``prefix`` is still needed for the few names that
        are no Python identifier once stripped, and so have no alias --
        ``ENCR_3DES`` and ``ENCR_3IDEA``.

        Resolution is deliberately separate from *support*: it answers only
        whether IANA registered the transform. See :meth:`CipherSuite.get`.

    """
    if isinstance(value, registry):
        return value
    if isinstance(value, int):
        try:
            return registry(value)
        except ValueError:
            raise ProtocolError(f'unknown ESP {kind} algorithm: {value}') from None

    name = str(value).upper().replace('-', '_')
    for candidate in (name, f'{prefix}{name}'):
        if candidate in registry.__members__:
            return registry[candidate]
    raise ProtocolError(f'unknown ESP {kind} algorithm: {value!r}')


@info_final
class CipherSuite(Info):
    """Parameters of an ESP encryption algorithm :mod:`pcapkit` implements.

    A member of :class:`Cipher <pcapkit.const.esp.cipher.Cipher>` records only
    that IANA registered the transform. This records how to apply it, and
    membership of :data:`CIPHER_SUITES` is what "supported" means -- see the
    module docstring.

    """

    #: Encryption algorithm the suite describes.
    cipher: 'Cipher'
    #: Whether the algorithm is a combined mode (AEAD) algorithm, i.e. one
    #: that provides its own integrity protection.
    is_aead: 'bool'
    #: Length of the explicit IV carried at the head of the payload data.
    iv_length: 'int'
    #: Cipher block size, in octets. :rfc:`4303` §2.4 additionally requires
    #: the ciphertext to be a multiple of 4 octets, which is why
    #: :meth:`ESP.make` aligns to ``max(block_size, 4)`` rather than to this
    #: value alone.
    block_size: 'int'
    #: Length of the ICV the algorithm itself produces (AEAD only).
    icv_length: 'int'
    #: Permitted lengths of the key, in octets, excluding any salt.
    key_sizes: 'tuple[int, ...]'
    #: Length of the salt taken from the keying material [:rfc:`4106` §8.1].
    salt_length: 'int'
    #: Whether the algorithm needs the optional |cryptography|_ dependency.
    requires_cryptography: 'bool'

    @classmethod
    def get(cls, value: 'Cipher | str | int') -> 'CipherSuite':
        """Look up how to apply an encryption algorithm.

        Args:
            value: A :class:`Cipher <pcapkit.const.esp.cipher.Cipher>` member,
                an IKEv2 transform ID, or a name such as ``'AES-CBC'``,
                ``'aes_cbc'`` or ``'ENCR_AES_CBC'``.

        Returns:
            The suite describing how to apply the algorithm.

        Raises:
            ProtocolError: If ``value`` names no registered algorithm, or
                names one :mod:`pcapkit` does not implement. The registry is
                far larger than the set of suites here, so the second case is
                the common one.

        """
        cipher = _resolve(Cipher, value, 'ENCR_', 'encryption')
        suite = CIPHER_SUITES.get(cipher)
        if suite is None:
            raise ProtocolError(f'unsupported ESP encryption algorithm: {cipher.name}; pcapkit '
                                f'implements {", ".join(key.name for key in CIPHER_SUITES)}')
        return suite


@info_final
class IntegritySuite(Info):
    """Parameters of an ESP integrity algorithm :mod:`pcapkit` implements.

    As with :class:`CipherSuite`, membership of :data:`INTEGRITY_SUITES` --
    not membership of the IANA registry -- is what makes an algorithm
    supported.

    """

    #: Integrity algorithm the suite describes.
    integrity: 'Integrity'
    #: Name of the underlying hash, for :func:`hmac.new`, or :data:`None` when
    #: the algorithm computes no ICV of its own.
    digest: 'Optional[str]'
    #: Length of the truncated ICV, in octets.
    icv_length: 'int'
    #: Key length required by the specification, in octets.
    key_size: 'int'

    @classmethod
    def get(cls, value: 'Integrity | str | int') -> 'IntegritySuite':
        """Look up how to apply an integrity algorithm.

        Args:
            value: An :class:`Integrity
                <pcapkit.const.esp.integrity.Integrity>` member, an IKEv2
                transform ID, or a name such as ``'HMAC-SHA-256-128'``,
                ``'hmac_sha2_256_128'`` or ``'AUTH_HMAC_SHA2_256_128'``.

        Returns:
            The suite describing how to apply the algorithm.

        Raises:
            ProtocolError: If ``value`` names no registered algorithm, or
                names one :mod:`pcapkit` does not implement.

        """
        if isinstance(value, str):
            # accept the RFC 4868 spelling ``HMAC_SHA_256_128`` as well as the
            # IKEv2 spelling ``HMAC_SHA2_256_128``
            name = value.upper().replace('-', '_').replace('HMAC_SHA_', 'HMAC_SHA2_')
            if name in ('HMAC_SHA2_1_96', 'HMAC_SHA2_1'):
                name = 'HMAC_SHA1_96'
            value = name

        integrity = _resolve(Integrity, value, 'AUTH_', 'integrity')
        suite = INTEGRITY_SUITES.get(integrity)
        if suite is None:
            raise ProtocolError(f'unsupported ESP integrity algorithm: {integrity.name}; pcapkit '
                                f'implements {", ".join(key.name for key in INTEGRITY_SUITES)}')
        return suite


#: Encryption algorithms :mod:`pcapkit` implements, keyed by IKEv2 transform.
#: This table -- not :class:`Cipher <pcapkit.const.esp.cipher.Cipher>`, which
#: is the whole IANA registry -- defines what an SA may name.
CIPHER_SUITES = {
    Cipher.ENCR_NULL: CipherSuite(
        cipher=Cipher.ENCR_NULL, is_aead=False, iv_length=0, block_size=1, icv_length=0,
        key_sizes=(0,), salt_length=0, requires_cryptography=False,
    ),
    Cipher.ENCR_AES_CBC: CipherSuite(
        cipher=Cipher.ENCR_AES_CBC, is_aead=False, iv_length=16, block_size=16, icv_length=0,
        key_sizes=(16, 24, 32), salt_length=0, requires_cryptography=True,
    ),
    Cipher.ENCR_AES_GCM_8: CipherSuite(
        cipher=Cipher.ENCR_AES_GCM_8, is_aead=True, iv_length=8, block_size=1, icv_length=8,
        key_sizes=(16, 24, 32), salt_length=4, requires_cryptography=True,
    ),
    Cipher.ENCR_AES_GCM_12: CipherSuite(
        cipher=Cipher.ENCR_AES_GCM_12, is_aead=True, iv_length=8, block_size=1, icv_length=12,
        key_sizes=(16, 24, 32), salt_length=4, requires_cryptography=True,
    ),
    Cipher.ENCR_AES_GCM_16: CipherSuite(
        cipher=Cipher.ENCR_AES_GCM_16, is_aead=True, iv_length=8, block_size=1, icv_length=16,
        key_sizes=(16, 24, 32), salt_length=4, requires_cryptography=True,
    ),
}  # type: dict[Cipher, CipherSuite]

#: Integrity algorithms :mod:`pcapkit` implements, keyed by IKEv2 transform.
#: :attr:`Integrity.NONE <pcapkit.const.esp.integrity.Integrity.NONE>` is here
#: because "no separate integrity algorithm" is a supported configuration --
#: it is what an AEAD suite, and an unprotected SA, use.
INTEGRITY_SUITES = {
    Integrity.NONE: IntegritySuite(
        integrity=Integrity.NONE, digest=None, icv_length=0, key_size=0,
    ),
    Integrity.AUTH_HMAC_SHA1_96: IntegritySuite(
        integrity=Integrity.AUTH_HMAC_SHA1_96, digest='sha1', icv_length=12, key_size=20,
    ),
    Integrity.AUTH_HMAC_SHA2_256_128: IntegritySuite(
        integrity=Integrity.AUTH_HMAC_SHA2_256_128, digest='sha256', icv_length=16, key_size=32,
    ),
    Integrity.AUTH_HMAC_SHA2_384_192: IntegritySuite(
        integrity=Integrity.AUTH_HMAC_SHA2_384_192, digest='sha384', icv_length=24, key_size=48,
    ),
    Integrity.AUTH_HMAC_SHA2_512_256: IntegritySuite(
        integrity=Integrity.AUTH_HMAC_SHA2_512_256, digest='sha512', icv_length=32, key_size=64,
    ),
}  # type: dict[Integrity, IntegritySuite]


##############################################################################
# Payload processing status.
##############################################################################


class ESPStatus(enum.IntEnum):
    """Outcome of ESP payload processing."""

    #: The payload was decrypted and its trailer recovered.
    DECRYPTED = 0
    #: No Security Association matched the packet's SPI, so the payload is
    #: reported as opaque ciphertext. This is the expected state for a
    #: capture taken without keys, and is **not** an error.
    NO_SA = 1
    #: A Security Association matched, but the ICV did not verify.
    AUTH_FAILED = 2
    #: A Security Association matched and the packet was authentic (or
    #: unauthenticated), but decryption did not yield a self consistent
    #: :rfc:`4303` trailer -- most commonly a wrong encryption key.
    DECRYPT_FAILED = 3
    #: The packet is shorter than the Security Association says it must be.
    TRUNCATED = 4
    #: A Security Association matched but its algorithms cannot be applied,
    #: e.g. because the optional |cryptography|_ dependency is missing.
    UNSUPPORTED = 5


##############################################################################
# Security Association.
##############################################################################


class SecurityAssociation:
    """An inbound IPsec Security Association, as far as ESP parsing needs one.

    Args:
        spi: Security Parameters Index the SA applies to; :data:`None`
            matches any SPI, which is convenient for a capture holding a
            single tunnel.
        encryption: Encryption algorithm, c.f. :meth:`CipherSuite.get`. Must
            be one :mod:`pcapkit` implements; being in the IANA registry is
            not enough.
        encryption_key: Encryption keying material. For an AEAD suite this
            is the AES key followed by the 4-octet salt [:rfc:`4106` §8.1],
            unless ``salt`` is given separately.
        salt: AEAD salt, when not appended to ``encryption_key``.
        integrity: Integrity algorithm, c.f. :meth:`IntegritySuite.get`. Must
            be :attr:`Integrity.NONE` for an AEAD suite, which provides its own.
        integrity_key: Integrity key.
        icv_length: Override for the ICV length, in octets. Needed for the
            long standing implementation bug noted in :rfc:`8221` §6, where
            ``AUTH_HMAC_SHA2_256_128`` is truncated to 96 rather than 128
            bits.
        destination: Outer destination address the SA applies to. IPsec keys
            an SA by ``(SPI, destination, protocol)``, and supplying the
            address is what lets several tunnels sharing an SPI be told
            apart. Matched only when the outer destination is known to
            :mod:`pcapkit`; see :meth:`ESP.read`. Must not be a :obj:`bool`
            -- see ``Raises`` below.
        strict: Whether a padding pattern that does not follow the
            monotonically increasing sequence of :rfc:`4303` §2.4 should be
            treated as a decryption failure. Only applied when nothing else
            authenticated the packet, since a verified ICV or AEAD tag is a
            far better signal than the padding is. Some implementations pad
            with zeros; set to :data:`False` for those.

    Raises:
        ProtocolError: If the algorithms or key lengths are inconsistent, or
            ``destination`` is a :obj:`bool` (c.f. #491) -- :obj:`bool` is an
            :class:`int` subclass, and :func:`ipaddress.ip_address` treats
            any :class:`int` below ``2**32`` as IPv4, so without this check
            ``destination=True`` would silently become
            ``IPv4Address('0.0.0.1')`` with no exception and no warning; pass
            ``int(destination)`` if the numeric value is what is wanted.

    Important:
        Key material is held in *private* attributes of this object, and is
        exposed only through :attr:`encryption_key` / :attr:`integrity_key`.
        It is deliberately absent from :meth:`~object.__repr__`, and it is
        never copied into the ESP data model, which is the only thing that
        reaches :meth:`Info.to_dict <pcapkit.corekit.infoclass.Info.to_dict>`
        and hence the output dumpers.

    """

    def __init__(self, spi: 'Optional[int]' = None, *,
                 encryption: 'Cipher | str | int' = Cipher.ENCR_NULL,
                 encryption_key: 'bytes' = b'',
                 salt: 'Optional[bytes]' = None,
                 integrity: 'Integrity | str | int' = Integrity.NONE,
                 integrity_key: 'bytes' = b'',
                 icv_length: 'Optional[int]' = None,
                 destination: 'Optional[IPv4Address | IPv6Address | str | int | bytes]' = None,
                 strict: 'bool' = True) -> 'None':
        if spi is not None and not 0 <= spi <= 0xFFFFFFFF:
            raise ProtocolError(f'invalid SPI: {spi}')

        if isinstance(destination, bool):
            # NOTE: checked before the ``ipaddress.ip_address`` call below, for
            # the same reason as ``_reject_bool`` in
            # ``pcapkit.corekit.fields.ipaddress`` (this module calls
            # ``ipaddress.ip_address`` directly rather than through a Field, so
            # it needs its own copy of the guard): ``bool`` is an ``int``
            # subclass, and ``ipaddress.ip_address()`` treats any ``int`` below
            # ``2**32`` as IPv4 -- so without this check, ``destination=True``
            # would silently become ``IPv4Address('0.0.0.1')``, with no
            # exception and no warning (c.f. #491).
            raise ProtocolError(
                f'invalid destination: must not be a bool, not {destination!r} -- '
                f'pass int({destination!r}) if the numeric value is what is wanted')

        #: Optional[int]: Security Parameters Index, or :data:`None` for any.
        self.spi = spi
        #: CipherSuite: How to apply the encryption algorithm.
        self.cipher_suite = CipherSuite.get(encryption)
        #: IntegritySuite: How to apply the integrity algorithm.
        self.integrity_suite = IntegritySuite.get(integrity)
        #: Cipher: Encryption algorithm, i.e. its IKEv2 transform.
        self.encryption = self.cipher_suite.cipher
        #: Integrity: Integrity algorithm, i.e. its IKEv2 transform.
        self.integrity = self.integrity_suite.integrity
        #: bool: Whether to enforce the :rfc:`4303` §2.4 padding pattern.
        self.strict = strict
        #: Optional[IPv4Address | IPv6Address]: Outer destination address.
        self.destination = ipaddress.ip_address(destination) if destination is not None else None

        if self.cipher_suite.is_aead and self.integrity is not Integrity.NONE:
            raise ProtocolError(
                f'{self.encryption.name} is a combined mode algorithm and provides its own '
                f'integrity; {self.integrity.name} must not be configured alongside it'
            )

        key, self.__salt__ = self._split_key(self.cipher_suite, encryption_key, salt)
        self.__key__ = key
        self.__integrity_key__ = bytes(integrity_key)

        if self.integrity is not Integrity.NONE:
            expected = self.integrity_suite.key_size
            if len(self.__integrity_key__) != expected:
                warn(f'{self.integrity.name} expects a {expected}-octet key, got '
                     f'{len(self.__integrity_key__)} octets; the ICV will very likely '
                     f'fail to verify', ProtocolWarning)

        if icv_length is not None and icv_length < 0:
            raise ProtocolError(f'invalid ICV length: {icv_length}')
        self.__icv_length__ = icv_length

        unavailable = self.unavailable()
        if unavailable is not None:
            warn(f'{unavailable}; ESP payloads for SPI '
                 f'{"any" if self.spi is None else f"{self.spi:#010x}"} will be reported as '
                 f'opaque ciphertext', ProtocolWarning)

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def encryption_key(self) -> 'bytes':
        """Encryption key, excluding any AEAD salt."""
        return self.__key__

    @property
    def salt(self) -> 'bytes':
        """AEAD salt."""
        return self.__salt__

    @property
    def integrity_key(self) -> 'bytes':
        """Integrity key."""
        return self.__integrity_key__

    @property
    def icv_length(self) -> 'int':
        """Length of the ICV field carried on the wire, in octets."""
        if self.__icv_length__ is not None:
            return self.__icv_length__
        if self.cipher_suite.is_aead:
            return self.cipher_suite.icv_length
        return self.integrity_suite.icv_length

    @property
    def authenticated(self) -> 'bool':
        """Whether the SA provides any integrity protection at all."""
        return self.cipher_suite.is_aead or self.integrity is not Integrity.NONE

    ##########################################################################
    # Methods.
    ##########################################################################

    def matches(self, spi: 'int',
                destination: 'Optional[IPv4Address | IPv6Address]' = None) -> 'int':
        """Score how well the SA matches a packet.

        Args:
            spi: SPI read from the packet.
            destination: Outer destination address, if known.

        Returns:
            A non-negative score, where a higher score is a better match, or
            ``-1`` when the SA does not apply at all. An SA pinned to this
            exact SPI outranks a wildcard one, and an SA whose destination
            was confirmed outranks one whose destination is unconstrained.

        """
        if self.spi is not None and self.spi != spi:
            return -1

        score = 2 if self.spi is not None else 0
        if self.destination is not None:
            if destination is None:
                # The outer destination is unknown here, so the constraint
                # cannot be confirmed; treat the SA as a weaker candidate
                # rather than discarding it.
                return score
            if self.destination != destination:
                return -1
            score += 1
        return score

    def unavailable(self) -> 'Optional[str]':
        """Say whether the SA's algorithms can be applied at all.

        This is checked before a packet is processed, so that a missing
        optional dependency is reported as a configuration problem once per
        packet rather than raised as an error from
        :meth:`decrypt` -- it is not a defect in the packet.

        Returns:
            A reason the SA cannot be applied, or :data:`None` when it can.

        """
        if self.cipher_suite.requires_cryptography and load_cryptography() is None:
            return (f'{self.encryption.name} needs the optional "cryptography" dependency, '
                    f'which is not installed (pip install pypcapkit[crypto])')
        return None

    def compute_icv(self, spi: 'int', seq: 'int', body: 'bytes') -> 'bytes':
        """Compute the ICV over the integrity protected part of the packet.

        The integrity computation of :rfc:`4303` §2.8 covers the SPI, the
        Sequence Number, the payload data (including any explicit IV) and
        the explicit ESP trailer -- that is, everything transmitted except
        the ICV itself.

        Args:
            spi: Security Parameters Index.
            seq: Sequence number.
            body: Payload data and ESP trailer, as transmitted.

        Returns:
            The truncated ICV.

        Raises:
            ProtocolError: If the SA has no separate integrity algorithm.

        """
        digest = self.integrity_suite.digest
        if digest is None:
            raise ProtocolError(f'{self.integrity.name} computes no ICV')

        mac = hmac.new(self.__integrity_key__,
                       spi.to_bytes(4, 'big') + seq.to_bytes(4, 'big') + body,
                       getattr(hashlib, digest))
        return mac.digest()[:self.icv_length]

    def decrypt(self, spi: 'int', seq: 'int', body: 'bytes', icv: 'bytes') -> 'bytes':
        """Decrypt the payload data of an ESP packet.

        Args:
            spi: Security Parameters Index.
            seq: Sequence number.
            body: Payload data as transmitted, i.e. the explicit IV (if the
                algorithm uses one) followed by the ciphertext.
            icv: ICV as transmitted; for an AEAD algorithm this is the
                authentication tag and is an input to the decryption.

        Returns:
            The plaintext, i.e. the inner payload followed by the ESP
            trailer (padding, pad length, next header).

        Raises:
            ProtocolError: If the payload is malformed for the algorithm, or
                if |cryptography|_ is needed and unavailable.
            cryptography.exceptions.InvalidTag: If an AEAD tag fails to
                verify -- typically a wrong key.

        """
        cipher = self.encryption
        suite = self.cipher_suite
        if cipher is Cipher.ENCR_NULL:
            return body

        crypto = load_cryptography()
        if crypto is None:
            raise ProtocolError(f'{cipher.name} needs the optional "cryptography" dependency, '
                                f'which is not installed')
        crypto_cipher, algorithms, modes, _ = crypto

        iv_length = suite.iv_length
        if len(body) < iv_length:
            raise ProtocolError(f'ESP payload is {len(body)} octets, too short for the '
                                f'{iv_length}-octet {cipher.name} IV')
        iv, ciphertext = body[:iv_length], body[iv_length:]

        if cipher is Cipher.ENCR_AES_CBC:
            if not ciphertext or len(ciphertext) % suite.block_size:
                raise ProtocolError(f'ESP ciphertext of {len(ciphertext)} octets is not a '
                                    f'positive multiple of the {suite.block_size}-octet '
                                    f'{cipher.name} block size')
            decryptor = crypto_cipher(algorithms.AES(self.__key__), modes.CBC(iv)).decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()

        # AEAD, i.e. AES-GCM [RFC 4106]: the nonce is the salt from the
        # keying material followed by the explicit IV, and the associated
        # data is the SPI and the sequence number.
        if not icv:
            raise ProtocolError(f'{cipher.name} requires an authentication tag, but the '
                                f'packet carries no ICV')
        nonce = self.__salt__ + iv
        aad = spi.to_bytes(4, 'big') + seq.to_bytes(4, 'big')
        decryptor = crypto_cipher(
            algorithms.AES(self.__key__),
            modes.GCM(nonce, icv, min_tag_length=len(icv)),
        ).decryptor()
        decryptor.authenticate_additional_data(aad)
        return decryptor.update(ciphertext) + decryptor.finalize()

    def encrypt(self, spi: 'int', seq: 'int', plaintext: 'bytes',
                iv: 'Optional[bytes]' = None) -> 'tuple[bytes, bytes]':
        """Encrypt the payload data of an ESP packet.

        This is the inverse of :meth:`decrypt`, used by :meth:`ESP.make`.

        Args:
            spi: Security Parameters Index.
            seq: Sequence number.
            plaintext: Inner payload followed by the ESP trailer.
            iv: Explicit IV; a random one is generated when not given.

        Returns:
            A 2-tuple of the payload data as it goes on the wire (explicit
            IV followed by ciphertext) and the AEAD tag, which is empty for
            a non-AEAD algorithm.

        Raises:
            ProtocolError: If ``iv`` is of the wrong length, or if
                |cryptography|_ is needed and unavailable.

        """
        cipher = self.encryption
        suite = self.cipher_suite
        if cipher is Cipher.ENCR_NULL:
            return plaintext, b''

        crypto = load_cryptography()
        if crypto is None:
            raise ProtocolError(f'{cipher.name} needs the optional "cryptography" dependency, '
                                f'which is not installed')
        crypto_cipher, algorithms, modes, _ = crypto

        iv_length = suite.iv_length
        if iv is None:
            iv = os.urandom(iv_length)
        elif len(iv) != iv_length:
            raise ProtocolError(f'{cipher.name} needs a {iv_length}-octet IV, got {len(iv)}')

        if cipher is Cipher.ENCR_AES_CBC:
            encryptor = crypto_cipher(algorithms.AES(self.__key__), modes.CBC(iv)).encryptor()
            return iv + encryptor.update(plaintext) + encryptor.finalize(), b''

        nonce = self.__salt__ + iv
        aad = spi.to_bytes(4, 'big') + seq.to_bytes(4, 'big')
        encryptor = crypto_cipher(algorithms.AES(self.__key__), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + ciphertext, encryptor.tag[:self.icv_length]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @staticmethod
    def _split_key(suite: 'CipherSuite', material: 'bytes',
                   salt: 'Optional[bytes]') -> 'tuple[bytes, bytes]':
        """Split keying material into the key and the AEAD salt.

        Args:
            suite: Encryption algorithm parameters.
            material: Keying material as supplied by the caller.
            salt: Explicit salt, if the caller kept it separate.

        Returns:
            A 2-tuple of the key and the salt.

        Raises:
            ProtocolError: If the lengths do not match the algorithm.

        """
        material = bytes(material)
        salt_length = suite.salt_length

        if salt is None:
            # RFC 4106 s8.1: the last four octets of the keying material are
            # the salt value.
            if salt_length and len(material) > salt_length:
                material, salt = material[:-salt_length], material[-salt_length:]
            else:
                salt = b''
        else:
            salt = bytes(salt)

        if len(salt) != salt_length:
            raise ProtocolError(f'{suite.cipher.name} needs a {salt_length}-octet salt, '
                                f'got {len(salt)}')
        if len(material) not in suite.key_sizes:
            raise ProtocolError(f'{suite.cipher.name} needs a key of '
                                f'{" or ".join(map(str, suite.key_sizes))} octets, '
                                f'got {len(material)}')
        return material, salt

    ##########################################################################
    # Data models.
    ##########################################################################

    def __repr__(self) -> 'str':
        """Representation of the SA, free of any key material."""
        spi = 'any' if self.spi is None else f'{self.spi:#010x}'
        dst = '' if self.destination is None else f' dst={self.destination!s}'
        return (f'<SecurityAssociation spi={spi} encryption={self.encryption.name} '
                f'integrity={self.integrity.name} icv={self.icv_length}{dst}>')


class ESPContext(ProtocolContext):
    """Caller supplied Security Association context for :class:`ESP`.

    Args:
        *associations: Security Associations to make available to the
            parser, in order of preference for otherwise equal matches.

    """

    def __init__(self, *associations: 'SecurityAssociation') -> 'None':
        self.__associations__ = []  # type: list[SecurityAssociation]
        for association in associations:
            self.register(association)

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def associations(self) -> 'tuple[SecurityAssociation, ...]':
        """Registered Security Associations."""
        return tuple(self.__associations__)

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def protocol(cls) -> 'tuple[Literal["ESP"]]':
        """Index ID of the protocol this context applies to."""
        return ('ESP',)

    def register(self, association: 'SecurityAssociation') -> 'None':
        """Add a Security Association to the context.

        Args:
            association: Security Association to add.

        Raises:
            ProtocolError: If ``association`` is not a
                :class:`SecurityAssociation`.

        """
        if not isinstance(association, SecurityAssociation):
            raise ProtocolError(f'not a security association: {association!r}')
        self.__associations__.append(association)

    def match(self, spi: 'int',
              destination: 'Optional[IPv4Address | IPv6Address]' = None) -> 'Optional[SecurityAssociation]':  # pylint: disable=line-too-long
        """Find the Security Association that best fits a packet.

        Args:
            spi: SPI read from the packet.
            destination: Outer destination address, if known.

        Returns:
            The best matching SA, or :data:`None` when none applies.

        """
        best = None  # type: Optional[SecurityAssociation]
        best_score = -1
        for association in self.__associations__:
            score = association.matches(spi, destination)
            if score > best_score:
                best, best_score = association, score
        return best

    ##########################################################################
    # Data models.
    ##########################################################################

    def __repr__(self) -> 'str':
        """Representation of the context, free of any key material."""
        return f'<ESPContext associations={len(self.__associations__)}>'


##############################################################################
# Protocol.
##############################################################################


class ESP(IPsec[Data_ESP, Schema_ESP],
          schema=Schema_ESP, data=Data_ESP):
    """This class implements Encapsulating Security Payload."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Encapsulating Security Payload"]':
        """Name of corresponding protocol."""
        return 'Encapsulating Security Payload'

    @property
    def length(self) -> 'int':
        """Length of the ESP header, payload, trailer and ICV.

        Note:
            Unlike most protocols, this is *not* just the fixed header:
            :rfc:`4303` puts the trailer and the ICV at the end of the
            packet, and the next layer is recovered from inside the
            ciphertext rather than from the bytes that follow. Every byte
            ESP owns is therefore counted here.

        """
        return self._info.length

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, *, version: 'Literal[4, 6]' = 4,  # pylint: disable=arguments-differ,unused-argument
             extension: 'bool' = False, **kwargs: 'Any') -> 'Data_ESP':
        """Read Encapsulating Security Payload.

        Structure of ESP header [:rfc:`4303`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ----
           |               Security Parameters Index (SPI)                 | ^Int.
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
           |                      Sequence Number                          | |ered
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | ----
           |                    Payload Data* (variable)                   | |   ^
           ~                                                               ~ |   |
           |                                                               | |Conf.
           +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
           |               |     Padding (0-255 bytes)                     | |ered*
           +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |   |
           |                               |  Pad Length   | Next Header   | v   v
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ------
           |         Integrity Check Value-ICV   (variable)                |
           ~                                                               ~
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            version: IP protocol version.
            extension: If the protocol is used as an IPv6 extension header.
                Unlike the other extension headers, ESP terminates the
                header chain -- everything after it is encrypted -- so it
                decodes its own next layer either way.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Notes:
            The outer destination address, used to disambiguate Security
            Associations that share an SPI, is taken from the ``packet``
            information the enclosing IP layer passes down. It is not
            available for every encapsulation, and an SA that names a
            destination still matches when it cannot be confirmed -- see
            :meth:`SecurityAssociation.matches`.

        """
        schema = self.__header__

        data = schema.payload
        spi, seq = schema.spi, schema.seq
        total = 8 + len(data)

        packet = kwargs.get('packet')
        if packet is None:
            packet = {}
        context = self._get_context(ESPContext)
        association = context.match(spi, packet.get('dst')) if context is not None else None

        if association is None:
            return self._make_opaque(
                spi, seq, total, data, ESPStatus.NO_SA,
                f'no security association for SPI {spi:#010x}',
                version=version, packet=packet, warning=False,
            )

        # NOTE: The ICV length comes from the security association, not from
        # |cryptography|_, so the split and the truncation check are both
        # possible whether or not the algorithms are available. Doing them
        # first means a truncated packet is reported as TRUNCATED rather than
        # masked as UNSUPPORTED, and that an UNSUPPORTED packet still reports
        # the ``icv`` it carries -- which for a combined-mode algorithm is the
        # authentication tag a caller may well want to see.
        icv_length = association.icv_length
        if icv_length > len(data):
            return self._make_opaque(
                spi, seq, total, data, ESPStatus.TRUNCATED,
                f'ESP payload is {len(data)} octets, shorter than the {icv_length}-octet '
                f'ICV the security association declares',
                version=version, packet=packet,
            )
        body, icv = (data[:len(data) - icv_length], data[len(data) - icv_length:]) \
            if icv_length else (data, b'')

        unavailable = association.unavailable()
        if unavailable is not None:
            return self._make_opaque(
                spi, seq, total, body, ESPStatus.UNSUPPORTED, unavailable,
                icv=icv, version=version, packet=packet,
            )

        # Separate integrity algorithm, RFC 4303 s3.4.4.1. A combined mode
        # algorithm verifies its own tag as part of decryption instead.
        if association.integrity is not Integrity.NONE:
            if not hmac.compare_digest(association.compute_icv(spi, seq, body), icv):
                return self._make_opaque(
                    spi, seq, total, body, ESPStatus.AUTH_FAILED,
                    f'integrity check value does not verify for SPI {spi:#010x} '
                    f'sequence {seq}', icv=icv, version=version, packet=packet,
                )

        crypto = load_cryptography()
        invalid_tag = crypto[3] if crypto is not None else ()  # type: Any
        try:
            plaintext = association.decrypt(spi, seq, body, icv)
        except ProtocolError as exc:
            return self._make_opaque(
                spi, seq, total, body, ESPStatus.DECRYPT_FAILED, str(exc),
                icv=icv, version=version, packet=packet,
            )
        except invalid_tag:
            return self._make_opaque(
                spi, seq, total, body, ESPStatus.AUTH_FAILED,
                f'authentication tag does not verify for SPI {spi:#010x} sequence {seq}; '
                f'the encryption key is most likely wrong',
                icv=icv, version=version, packet=packet,
            )

        trailer = self._read_trailer(plaintext, association, spi)
        if isinstance(trailer, str):
            return self._make_opaque(
                spi, seq, total, body, ESPStatus.DECRYPT_FAILED, trailer,
                icv=icv, version=version, packet=packet,
            )
        inner, padding, pad_len, next_ = trailer
        next_type = Enum_TransType.get(next_)

        esp = Data_ESP(
            spi=spi,
            seq=seq,
            length=total,
            payload_data=body,
            icv=icv,
            status=ESPStatus.DECRYPTED,
            error=None,
            next=next_type,
            pad_len=pad_len,
            padding=padding,
            plaintext=inner,
        )
        return self._decode_next_layer(esp, next_type, len(inner), packet=packet,
                                       version=version, payload=inner)

    def make(self,
             spi: 'int' = 0,
             seq: 'int' = 0,
             next: 'Enum_TransType | StdlibEnum | AenumEnum | str | int' = Enum_TransType.UDP,  # pylint: disable=redefined-builtin
             next_default: 'Optional[int]' = None,
             next_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             next_reversed: 'bool' = False,
             encrypt: 'bool' = False,
             iv: 'Optional[bytes]' = None,
             pad_len: 'Optional[int]' = None,
             icv: 'bytes' = b'',
             payload: 'bytes | Protocol | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_ESP':
        """Make (construct) packet data.

        There are two modes, chosen by ``encrypt``:

        * ``encrypt=False`` (the default) writes ``payload`` after the SPI
          and sequence number verbatim, followed by ``icv``. This is the
          mode used to reproduce a captured packet byte for byte, and is
          what :meth:`_make_data` drives -- re-encrypting a packet that was
          only ever read would change its bytes.
        * ``encrypt=True`` treats ``payload`` as the inner plaintext: it
          appends :rfc:`4303` §2.4 padding, the pad length and ``next``,
          encrypts the result under the Security Association matching
          ``spi``, and appends the resulting ICV.

        Args:
            spi: Security Parameters Index.
            seq: Sequence number.
            next: Next header type, written into the ESP trailer. Only used
                when ``encrypt`` is :data:`True`.
            next_default: Default value of next header type.
            next_namespace: Namespace of next header type.
            next_reversed: If the namespace is reversed.
            encrypt: Whether to protect ``payload``, as described above.
            iv: Explicit IV to use; a random one is generated when omitted.
                Only used when ``encrypt`` is :data:`True`.
            pad_len: Pad length to use; the smallest value that satisfies
                the alignment requirement is chosen when omitted. Only used
                when ``encrypt`` is :data:`True`.
            icv: Integrity check value. Ignored when ``encrypt`` is
                :data:`True`, where it is computed instead.
            payload: Payload of current instance.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``encrypt`` is :data:`True` and no Security
                Association is available for ``spi``, or if ``pad_len`` does
                not satisfy the algorithm's alignment requirement.

        """
        if not encrypt:
            # the ICV goes after the payload data, so the two have to be
            # concatenated by hand; without one, the payload is handed to the
            # schema untouched, so that a Protocol or Schema payload is packed
            # by the field rather than here
            if icv:
                return Schema_ESP(spi=spi, seq=seq, payload=self._payload_bytes(payload) + icv)
            return Schema_ESP(spi=spi, seq=seq, payload=payload)

        context = self._get_context(ESPContext)
        association = context.match(spi) if context is not None else None
        if association is None:
            raise ProtocolError(f'no security association for SPI {spi:#010x}; ESP cannot be '
                                f'constructed with encrypt=True without one')

        next_value = self._make_index(next, next_default, namespace=next_namespace,
                                      reversed=next_reversed, pack=False)

        plain = self._payload_bytes(payload)
        align = max(association.cipher_suite.block_size, 4)
        if pad_len is None:
            pad_len = -(len(plain) + 2) % align
        elif (len(plain) + pad_len + 2) % align:
            raise ProtocolError(f'pad length {pad_len} leaves '
                                f'{len(plain) + pad_len + 2} octets, which is not a multiple '
                                f'of the required {align}-octet alignment')
        if not 0 <= pad_len <= 255:
            raise ProtocolError(f'invalid pad length: {pad_len}')

        # RFC 4303 s2.4: padding bytes are a monotonically increasing
        # sequence starting at 1.
        plaintext = plain + bytes(range(1, pad_len + 1)) + bytes([pad_len, next_value])
        body, tag = association.encrypt(spi, seq, plaintext, iv)
        if association.integrity is not Integrity.NONE:
            tag = association.compute_icv(spi, seq, body)

        return Schema_ESP(
            spi=spi,
            seq=seq,
            payload=body + tag,
        )

    @classmethod
    def id(cls) -> 'tuple[Literal["ESP"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return ('ESP',)

    ##########################################################################
    # Data models.
    ##########################################################################

    @overload
    def __post_init__(self, file: 'IO[bytes] | bytes', length: 'Optional[int]' = ..., *,  # pylint: disable=arguments-differ
                      version: 'Literal[4, 6]' = ..., extension: 'bool' = ...,
                      **kwargs: 'Any') -> 'None': ...
    @overload
    def __post_init__(self, **kwargs: 'Any') -> 'None': ...  # pylint: disable=arguments-differ

    def __post_init__(self, file: 'Optional[IO[bytes] | bytes]' = None, length: 'Optional[int]' = None, *,  # pylint: disable=arguments-differ
                      version: 'Literal[4, 6]' = 4, extension: 'bool' = False,
                      **kwargs: 'Any') -> 'None':
        """Post initialisation hook.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            version: IP protocol version.
            extension: If the protocol is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For construction argument, please refer to :meth:`self.make <ESP.make>`.

        """
        #: bool: If the protocol is used as an IPv6 extension header.
        self._extf = extension

        # call super __post_init__
        super().__post_init__(file, length, version=version, extension=extension, **kwargs)  # type: ignore[arg-type]

    def __length_hint__(self) -> 'Literal[8]':
        """Return an estimated length for the object."""
        return 8

    @classmethod
    def __index__(cls) -> 'Enum_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return Enum_TransType.ESP  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_ESP') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        The payload is reproduced verbatim rather than re-encrypted, so that
        reconstruction is byte exact and does not need the keys.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'spi': data.spi,
            'seq': data.seq,
            'payload': data.payload_data + data.icv,
        }

    @staticmethod
    def _payload_bytes(payload: 'bytes | Protocol | Schema') -> 'bytes':
        """Render ``payload`` as :obj:`bytes`.

        Args:
            payload: Payload as supplied to :meth:`make`.

        Returns:
            Packed payload.

        Raises:
            ProtocolUnbound: If ``payload`` is of an unsupported type. This
                mirrors :meth:`Schema.pack <pcapkit.protocols.schema.schema.Schema.pack>`,
                which rejects the same set.

        """
        from pcapkit.protocols.protocol import \
            ProtocolBase  # pylint: disable=import-outside-toplevel

        if isinstance(payload, bytes):
            return payload
        if isinstance(payload, Schema):
            return payload.pack()
        if isinstance(payload, ProtocolBase):
            return bytes(payload)
        raise ProtocolUnbound(f'unsupported type {type(payload)}')

    @staticmethod
    def _read_trailer(plaintext: 'bytes', association: 'SecurityAssociation',
                      spi: 'int') -> 'tuple[bytes, bytes, int, int] | str':
        """Split the ESP trailer off the decrypted plaintext.

        Args:
            plaintext: Decrypted payload data, i.e. the inner payload
                followed by the ESP trailer.
            association: Security Association the packet was decrypted with.
            spi: Security Parameters Index, for the diagnostic message.

        Returns:
            A 4-tuple of the inner payload, the padding, the pad length and
            the next header, or a :obj:`str` explaining why the trailer is
            not self consistent.

        """
        if len(plaintext) < 2:
            return (f'decrypted ESP payload for SPI {spi:#010x} is {len(plaintext)} octets, '
                    f'too short to hold a pad length and next header')

        pad_len, next_ = plaintext[-2], plaintext[-1]
        if pad_len + 2 > len(plaintext):
            return (f'decrypted ESP payload for SPI {spi:#010x} declares {pad_len} octets of '
                    f'padding but holds only {len(plaintext) - 2}; the encryption key is most '
                    f'likely wrong')

        padding = plaintext[len(plaintext) - 2 - pad_len:len(plaintext) - 2]
        inner = plaintext[:len(plaintext) - 2 - pad_len]

        if padding != bytes(range(1, pad_len + 1)):
            message = (f'padding of the decrypted ESP payload for SPI {spi:#010x} does not '
                       f'follow the monotonically increasing sequence of RFC 4303 s2.4')
            if association.strict and not association.authenticated:
                # Nothing authenticated this packet, so the padding pattern
                # is the only wrong-key signal available.
                return f'{message}; the encryption key is most likely wrong'
            warn(message, ProtocolWarning)

        return inner, padding, pad_len, next_

    def _make_opaque(self, spi: 'int', seq: 'int', total: 'int', payload_data: 'bytes',
                     status: 'ESPStatus', error: 'str', *, icv: 'bytes' = b'',
                     version: 'Literal[4, 6]' = 4,
                     packet: 'Optional[dict[str, Any]]' = None,
                     warning: 'bool' = True) -> 'Data_ESP':
        """Report an ESP packet whose payload was not decrypted.

        The payload is surfaced as :class:`~pcapkit.protocols.misc.raw.Raw`
        -- which is what a next header of :data:`None` resolves to -- so that
        :attr:`self.payload <pcapkit.protocols.protocol.ProtocolBase.payload>`
        and the protocol chain behave as they do for any other protocol, and
        the trailer fields are left :data:`None` rather than guessed at.

        Args:
            spi: Security Parameters Index.
            seq: Sequence number.
            total: Total length of the ESP portion of the packet.
            payload_data: Payload data, excluding the ICV.
            status: Why the payload was not decrypted.
            error: Human readable form of ``status``.
            icv: Integrity check value, when its length is known.
            version: IP protocol version.
            packet: Packet information from the enclosing layer.
            warning: Whether to warn; a capture taken without keys is the
                expected case and does not warrant one.

        Returns:
            Parsed packet data.

        """
        if warning:
            warn(error, ProtocolWarning)

        esp = Data_ESP(
            spi=spi,
            seq=seq,
            length=total,
            payload_data=payload_data,
            icv=icv,
            status=status,
            error=error,
            next=None,
            pad_len=None,
            padding=None,
            plaintext=None,
        )
        return self._decode_next_layer(esp, None, len(payload_data) + len(icv),
                                       packet=packet or None, version=version,
                                       payload=payload_data + icv)
