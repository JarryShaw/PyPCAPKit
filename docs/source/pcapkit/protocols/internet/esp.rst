ESP - Encapsulating Security Payload
====================================

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

* **Without** SA context, :class:`~pcapkit.protocols.internet.esp.ESP`
  parses the ``SPI`` and ``Sequence Number``, reports the remainder as an
  opaque encrypted payload, and says so through
  :attr:`esp.status <pcapkit.protocols.data.internet.esp.ESP.status>`.
  It does *not* guess at the trailer, and it does not raise.
* **With** SA context, :class:`~pcapkit.protocols.internet.esp.ESP` splits
  off the ICV, verifies integrity, decrypts, strips the padding using
  ``Pad Length``, and dispatches the recovered plaintext to the next layer
  using ``Next Header`` -- so an ESP tunnelled TCP segment decodes as TCP.

.. autoclass:: pcapkit.protocols.internet.esp.ESP
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: length

   .. automethod:: id

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data
   .. automethod:: _payload_bytes
   .. automethod:: _read_trailer
   .. automethod:: _make_opaque

   .. automethod:: __post_init__
   .. automethod:: __index__

Security Associations
---------------------

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

.. autoclass:: pcapkit.protocols.internet.esp.SecurityAssociation
   :no-members:
   :show-inheritance:

   .. autoproperty:: encryption_key
   .. autoproperty:: salt
   .. autoproperty:: integrity_key
   .. autoproperty:: icv_length
   .. autoproperty:: authenticated

   .. automethod:: matches
   .. automethod:: unavailable
   .. automethod:: compute_icv
   .. automethod:: decrypt
   .. automethod:: encrypt

   .. automethod:: _split_key
   .. automethod:: __repr__

.. autoclass:: pcapkit.protocols.internet.esp.ESPContext
   :no-members:
   :show-inheritance:

   .. autoproperty:: associations

   .. automethod:: protocol
   .. automethod:: register
   .. automethod:: match
   .. automethod:: __repr__

Algorithm Registries
--------------------

ESP has no algorithm registry of its own -- an SA's algorithms are negotiated
by IKEv2 -- so :class:`Cipher <pcapkit.const.esp.cipher.Cipher>` and
:class:`Integrity <pcapkit.const.esp.integrity.Integrity>` are generated from
the IKEv2 *transform ID* sub-registries and enumerate everything **IANA has
registered**: 3DES, AES-CTR, the AES-CCM and Camellia families,
ChaCha20-Poly1305, the implicit IV variants of :rfc:`8750`, the :rfc:`9227`
MGM suites, and the transforms long since deprecated.

The enumerations themselves are generated into :mod:`pcapkit.const.esp` and
re-exported here for convenience:
:class:`Cipher <pcapkit.const.esp.cipher.Cipher>` is
:class:`pcapkit.const.esp.cipher.Cipher` and :class:`Integrity
<pcapkit.const.esp.integrity.Integrity>` is
:class:`pcapkit.const.esp.integrity.Integrity`.

Both enumerations additionally carry each transform's prefix-stripped spelling
as an alias, since that is how ESP and :rfc:`8221` name the algorithms, so
:attr:`Cipher.AES_CBC <pcapkit.const.esp.cipher.Cipher.AES_CBC>` and
:attr:`Cipher.ENCR_AES_CBC <pcapkit.const.esp.cipher.Cipher.ENCR_AES_CBC>`
are the same member. The registry spells the "no integrity algorithm"
transform ``NONE`` rather than ``AUTH_NONE``, and :attr:`Integrity.NONE
<pcapkit.const.esp.integrity.Integrity.NONE>` follows it.

Algorithm Support
-----------------

A registry enumerates what IANA assigned an ID to, which is far more than
:mod:`pcapkit` implements. **Registration is not support.** A member of either
enumeration says only that IANA assigned the transform an ID; what
:mod:`pcapkit` can actually apply is the separate, explicit
:data:`~pcapkit.protocols.internet.esp.CIPHER_SUITES` and
:data:`~pcapkit.protocols.internet.esp.INTEGRITY_SUITES` tables, and
:meth:`CipherSuite.get <pcapkit.protocols.internet.esp.CipherSuite.get>` /
:meth:`IntegritySuite.get <pcapkit.protocols.internet.esp.IntegritySuite.get>`
refuse anything outside them rather than half-working:

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

.. |cryptography| replace:: ``cryptography``
.. _cryptography: https://cryptography.io

The supported set is anchored on the *mandatory to implement* algorithms of
:rfc:`8221`. The tables below are the authority on what an SA may actually
name; the rows marked ``yes`` are exactly the keys of
:data:`~pcapkit.protocols.internet.esp.CIPHER_SUITES`, and everything else the
registry lists is enumerated and rejected.

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
:data:`~pcapkit.protocols.internet.esp.INTEGRITY_SUITES`:

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
``AUTH_HMAC_MD5_128``, ``AUTH_DES_MAC`` and ``AUTH_KPDK_MD5``.

.. autoclass:: pcapkit.protocols.internet.esp.CipherSuite
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.esp.IntegritySuite
   :members:
   :undoc-members:
   :show-inheritance:

.. autodata:: pcapkit.protocols.internet.esp.CIPHER_SUITES

.. autodata:: pcapkit.protocols.internet.esp.INTEGRITY_SUITES

Known Limitations
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

Processing Status
-----------------

.. autoclass:: pcapkit.protocols.internet.esp.ESPStatus
   :members:
   :show-inheritance:

.. autofunction:: pcapkit.protocols.internet.esp.load_cryptography

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.internet.esp

.. autoclass:: pcapkit.protocols.schema.internet.esp.ESP
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.data.internet.esp

.. autoclass:: pcapkit.protocols.data.internet.esp.ESP
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/IPsec
