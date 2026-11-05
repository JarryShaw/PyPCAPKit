ESP - Encapsulating Security Payload
====================================

.. module:: pcapkit.protocols.internet.esp
.. module:: pcapkit.protocols.internet.esp.protocol

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.internet.esp._CRYPTO``,
   ``pcapkit.protocols.internet.esp.load_cryptography``,
   ``pcapkit.protocols.internet.esp._resolve``,
   ``pcapkit.protocols.internet.esp.CipherSuite``,
   ``pcapkit.protocols.internet.esp.IntegritySuite``,
   ``pcapkit.protocols.internet.esp.CIPHER_SUITES``,
   ``pcapkit.protocols.internet.esp.INTEGRITY_SUITES``,
   ``pcapkit.protocols.internet.esp.ESPStatus``,
   ``pcapkit.protocols.internet.esp.SecurityAssociation`` and
   ``pcapkit.protocols.internet.esp.ESPContext``, with no alias: they are in this
   module, and :mod:`pcapkit.protocols.internet.esp` exports the protocol class alone.
   ``pcapkit.protocols.internet.esp.Cipher`` and
   ``pcapkit.protocols.internet.esp.Integrity``, which it re-exported, with no alias:
   use :class:`pcapkit.const.esp.cipher.Cipher` and
   :class:`pcapkit.const.esp.integrity.Integrity` instead (:issue:`2534`).

:mod:`pcapkit.protocols.internet.esp.protocol` contains
:class:`~pcapkit.protocols.internet.esp.protocol.ESP`, the extractor for
Encapsulating Security Payload (ESP) [*]_, and the security association,
algorithm and status types below. The ESP structure:

======= ========= ===================== ==============================================
Octets      Bits        Name                    Description
======= ========= ===================== ==============================================
  0           0   ``esp.spi``             Security Parameters Index (SPI)
  4          32   ``esp.seq``             Sequence Number
  8          64   ``esp.payload_data``    Payload Data (variable, encrypted)
  ?           ?   ``esp.padding``         Padding (0-255 bytes, encrypted)
  ?           ?   ``esp.pad_len``         Pad Length (encrypted)
  ?           ?   ``esp.next``            Next Header (encrypted)
  ?           ?   ``esp.icv``             Integrity Check Value (ICV, variable)
======= ========= ===================== ==============================================

ESP is **not** self describing: :rfc:`4303` puts ``Pad Length`` and ``Next Header``
*inside* the ciphertext, and leaves the ``Integrity Check Value``'s length to the
Security Association (SA), negotiated out of band. So:

* **Without** SA context, :class:`~pcapkit.protocols.internet.esp.protocol.ESP`
  parses the ``SPI`` and ``Sequence Number`` and reports the rest as an opaque
  encrypted payload, saying so through
  :attr:`esp.status <pcapkit.protocols.internet.esp.data.ESP.status>`. It
  neither guesses at the trailer nor raises.
* **With** SA context, it splits off the ICV, verifies integrity, decrypts,
  strips the padding by ``Pad Length``, and dispatches the plaintext on
  ``Next Header`` -- so an ESP-tunnelled TCP segment decodes as TCP.

.. versionadded:: 1.5.0

.. autoclass:: pcapkit.protocols.internet.esp.protocol.ESP
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: protocol
   .. autoproperty:: length

   .. automethod:: read
   .. automethod:: make
   .. automethod:: id

   .. automethod:: __post_init__
   .. automethod:: __index__

   .. automethod:: _make_data
   .. automethod:: _make_opaque
   .. automethod:: _read_trailer
   .. automethod:: _payload_bytes

Security Associations
---------------------

SA context is supplied through the protocol-keyed context channel of
:mod:`pcapkit.corekit.context`:

.. code-block:: python

   import pcapkit
   from pcapkit.protocols.internet.esp.protocol import (Cipher, ESPContext, Integrity,
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

.. autoclass:: pcapkit.protocols.internet.esp.protocol.SecurityAssociation
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

   .. automethod:: __repr__

   .. automethod:: _split_key

.. autoclass:: pcapkit.protocols.internet.esp.protocol.ESPContext
   :no-members:
   :show-inheritance:

   .. autoproperty:: associations

   .. automethod:: protocol
   .. automethod:: register
   .. automethod:: match
   .. automethod:: __repr__

Algorithm Registries
--------------------

ESP has no algorithm registry of its own -- IKEv2 negotiates an SA's
algorithms -- so :class:`Cipher <pcapkit.const.esp.cipher.Cipher>` and
:class:`Integrity <pcapkit.const.esp.integrity.Integrity>` are generated into
:mod:`pcapkit.const.esp` from the IKEv2 *transform ID* sub-registries, and
re-exported from this module. They enumerate everything **IANA has
registered**: 3DES, AES-CTR, the AES-CCM and Camellia families,
ChaCha20-Poly1305, the implicit IV variants of :rfc:`8750`, the :rfc:`9227`
MGM suites, and the transforms long since deprecated.

Each also carries a transform's prefix-stripped spelling as an alias, as ESP
and :rfc:`8221` name the algorithms, so
:attr:`Cipher.AES_CBC <pcapkit.const.esp.cipher.Cipher.AES_CBC>` and
:attr:`Cipher.ENCR_AES_CBC <pcapkit.const.esp.cipher.Cipher.ENCR_AES_CBC>`
are one member. The registry spells "no integrity algorithm" ``NONE``, not
``AUTH_NONE``, and :attr:`Integrity.NONE
<pcapkit.const.esp.integrity.Integrity.NONE>` follows it.

.. _esp-algorithm-support:

Algorithm Support
-----------------

**Registration is not support.** A member of either enumeration says only that
IANA assigned the transform an ID; what :mod:`pcapkit` can apply is the separate
:data:`~pcapkit.protocols.internet.esp.protocol.CIPHER_SUITES` and
:data:`~pcapkit.protocols.internet.esp.protocol.INTEGRITY_SUITES` tables, and
:meth:`CipherSuite.get <pcapkit.protocols.internet.esp.protocol.CipherSuite.get>` /
:meth:`IntegritySuite.get <pcapkit.protocols.internet.esp.protocol.IntegritySuite.get>`
refuse anything outside them rather than half-working:

.. code-block:: python

   >>> Cipher.get('ENCR_3DES')          # registered, so the enum has it
   <Cipher.ENCR_3DES: 3>
   >>> CipherSuite.get('ENCR_3DES')     # but ESP cannot apply it
   Traceback (most recent call last):
     ...
   pcapkit.utilities.exceptions.ProtocolError: ESP: unsupported encryption
   algorithm: 'ENCR_3DES'; pcapkit implements ENCR_NULL, ENCR_AES_CBC,
   ENCR_AES_GCM_8, ENCR_AES_GCM_12, ENCR_AES_GCM_16

An AES suite needs the optional |cryptography|_ dependency
(``pip install pypcapkit[crypto]``). :mod:`pcapkit` works without it; an SA
naming such a suite then warns and leaves its payloads opaque.

The supported set is anchored on :rfc:`8221`'s *mandatory to implement*
algorithms. The tables below are the authority on what an SA may name: the rows
marked ``yes`` are exactly the keys of
:data:`~pcapkit.protocols.internet.esp.protocol.CIPHER_SUITES`, and everything else
the registry lists is enumerated and rejected.

============================ =================== ============ ==================================
Encryption                   :rfc:`8221` status   Implemented  Notes
============================ =================== ============ ==================================
``ENCR_NULL``                MUST                yes          :rfc:`2410`; needs no |cryptography|_
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
:data:`~pcapkit.protocols.internet.esp.protocol.INTEGRITY_SUITES`:

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

The implemented suites' parameters, as
:data:`~pcapkit.protocols.internet.esp.protocol.CIPHER_SUITES` and
:data:`~pcapkit.protocols.internet.esp.protocol.INTEGRITY_SUITES` record them, with
lengths and sizes in octets:

========================== =========== ============== ============== ============== ============== =============== =========================
Encryption                 ``is_aead`` ``iv_length``  ``block_size`` ``icv_length`` ``key_sizes``  ``salt_length`` ``requires_cryptography``
========================== =========== ============== ============== ============== ============== =============== =========================
``ENCR_NULL``              no          0              1              0              0              0               no
``ENCR_AES_CBC``           no          16             16             0              16, 24, 32     0               yes
``ENCR_AES_GCM_8``         yes         8              1              8              16, 24, 32     4               yes
``ENCR_AES_GCM_12``        yes         8              1              12             16, 24, 32     4               yes
``ENCR_AES_GCM_16``        yes         8              1              16             16, 24, 32     4               yes
========================== =========== ============== ============== ============== ============== =============== =========================

========================== ============== ============== ==============
Integrity                  ``digest``     ``icv_length`` ``key_size``
========================== ============== ============== ==============
``NONE``                   :data:`None`   0              0
``AUTH_HMAC_SHA1_96``      ``sha1``       12             20
``AUTH_HMAC_SHA2_256_128`` ``sha256``     16             32
``AUTH_HMAC_SHA2_384_192`` ``sha384``     24             48
``AUTH_HMAC_SHA2_512_256`` ``sha512``     32             64
========================== ============== ============== ==============

.. autoclass:: pcapkit.protocols.internet.esp.protocol.CipherSuite
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.internet.esp.protocol.IntegritySuite
   :members:
   :undoc-members:
   :show-inheritance:

.. autodata:: pcapkit.protocols.internet.esp.protocol.CIPHER_SUITES
   :no-value:

.. autodata:: pcapkit.protocols.internet.esp.protocol.INTEGRITY_SUITES
   :no-value:

Known Limitations
-----------------

* **Extended Sequence Numbers (ESN,** :rfc:`4303` **§2.2.1) are not
  supported.** An ESN's high-order 32 bits are not transmitted, so a stateless
  parser cannot recover them for the ICV or the AEAD associated data; an
  ESN-protected packet fails the integrity check *cleanly* rather than being
  decoded.
* **Traffic Flow Confidentiality (TFC) padding (§2.7) is not detected.** It
  cannot be told from real payload without the inner protocol's own length
  field, so the next layer gets it as plaintext.
* **Anti-replay is not performed.** :mod:`pcapkit` is an analyser, not a
  receiver; the sequence number is reported, never checked.
* An ICV failure is reported rather than raised, so one bad packet does not
  abort a capture.

Processing Status
-----------------

Where in :meth:`ESP.read <pcapkit.protocols.internet.esp.protocol.ESP.read>` each
status is set:

.. mermaid::

   flowchart TD
       R["ESP.read: SPI, sequence number,<br/>the rest as payload"] --> M
       M{"an ESPContext SA matching<br/>the SPI and outer destination?"}
       M -->|no| NOSA["NO\_SA: kept opaque, no warning"]
       M -->|yes| T{"payload shorter than the SA's ICV?"}
       T -->|yes| TR["TRUNCATED"]
       T -->|no| SPLIT["split off the ICV"]
       SPLIT --> U{"association.unavailable() gives a reason?<br/>e.g. cryptography not installed"}
       U -->|yes| UN["UNSUPPORTED: the ICV still reported"]
       U -->|no| I{"a separate integrity algorithm?"}
       I -->|"yes, and compute\_icv differs from the ICV"| AF["AUTH\_FAILED"]
       I -->|"no, or the ICV verifies"| D["association.decrypt"]
       D -->|"InvalidTag: a combined-mode tag fails,<br/>most likely a wrong key"| AF
       D -->|ProtocolError| DF["DECRYPT\_FAILED"]
       D -->|plaintext| TRL{"\_read\_trailer: the trailer self-consistent?"}
       TRL -->|no| DF
       TRL -->|yes| OK["DECRYPTED"]
       OK --> NXT["plaintext dispatched on Next Header"]

       click R "esp.html#pcapkit.protocols.internet.esp.protocol.ESP.read"
       click M "esp.html#pcapkit.protocols.internet.esp.protocol.ESPContext.match"
       click U "esp.html#pcapkit.protocols.internet.esp.protocol.SecurityAssociation.unavailable"
       click D "esp.html#pcapkit.protocols.internet.esp.protocol.SecurityAssociation.decrypt"
       click TRL "esp.html#pcapkit.protocols.internet.esp.protocol.ESP._read_trailer"

``TRUNCATED`` is checked before ``UNSUPPORTED`` since the ICV length comes from the
SA, not from |cryptography|_, and every status but ``DECRYPTED`` is made by
:meth:`~pcapkit.protocols.internet.esp.protocol.ESP._make_opaque`.

.. autoclass:: pcapkit.protocols.internet.esp.protocol.ESPStatus
   :members:
   :show-inheritance:

.. autofunction:: pcapkit.protocols.internet.esp.protocol.load_cryptography

.. autodata:: pcapkit.protocols.internet.esp.protocol._CRYPTO
   :no-value:

.. autofunction:: pcapkit.protocols.internet.esp.protocol._resolve

Header Schemas
--------------

.. module:: pcapkit.protocols.internet.esp.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.internet.esp``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.internet.esp.schema.ESP
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.internet.esp.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.internet.esp``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.internet.esp.data.ESP
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/IPsec
