=============================================================================
:class:`~pcapkit.protocols.misc.pcapng.protocol.PCAPNG` Constant Enumerations
=============================================================================

.. module:: pcapkit.const.pcapng

.. list-table::

   * - :class:`PCAPNG_BlockType <pcapkit.const.pcapng.block_type.BlockType>`
     - Block Types [*]_
   * - :class:`PCAPNG_OptionType <pcapkit.const.pcapng.option_type.OptionType>`
     - Option Types [*]_
   * - :class:`PCAPNG_HashAlgorithm <pcapkit.const.pcapng.hash_algorithm.HashAlgorithm>`
     - Hash Algorithms [*]_
   * - :class:`PCAPNG_VerdictType <pcapkit.const.pcapng.verdict_type.VerdictType>`
     - Verdict Types [*]_
   * - :class:`PCAPNG_RecordType <pcapkit.const.pcapng.record_type.RecordType>`
     - Record Types [*]_
   * - :class:`PCAPNG_SecretsType <pcapkit.const.pcapng.secrets_type.SecretsType>`
     - Secrets Types [*]_
   * - :class:`PCAPNG_FilterType <pcapkit.const.pcapng.filter_type.FilterType>`
     - Filter Types [*]_
   * - :class:`PCAPNG_TLSKeyLabel <pcapkit.const.pcapng.tls_key_label.TLSKeyLabel>`
     - TLS Key Log Labels [*]_

Block Types
===========

.. module:: pcapkit.const.pcapng.block_type

Generated from :class:`pcapkit.vendor.pcapng.block_type.BlockType`.

.. autoclass:: pcapkit.const.pcapng.block_type.BlockType
   :members:
   :undoc-members:
   :show-inheritance:

Hash Algorithms
===============

.. module:: pcapkit.const.pcapng.hash_algorithm

Generated from :class:`pcapkit.vendor.pcapng.hash_algorithm.HashAlgorithm`.

.. autoclass:: pcapkit.const.pcapng.hash_algorithm.HashAlgorithm
   :members:
   :undoc-members:
   :show-inheritance:

Option Types
============

.. module:: pcapkit.const.pcapng.option_type

Generated from :class:`pcapkit.vendor.pcapng.option_type.OptionType`.

.. versionchanged:: 1.1.0.post1

   A member converts with :class:`int` to its option code, and compares,
   orders and hashes as that code.

.. autoclass:: pcapkit.const.pcapng.option_type.OptionType
   :members:
   :undoc-members:
   :show-inheritance:
   :special-members: __new__

   .. autoattribute:: __members_ns__
      :no-value:

Record Types
============

.. module:: pcapkit.const.pcapng.record_type

Generated from :class:`pcapkit.vendor.pcapng.record_type.RecordType`.

.. autoclass:: pcapkit.const.pcapng.record_type.RecordType
   :members:
   :undoc-members:
   :show-inheritance:

Secrets Types
=============

.. module:: pcapkit.const.pcapng.secrets_type

Generated from :class:`pcapkit.vendor.pcapng.secrets_type.SecretsType`.

.. autoclass:: pcapkit.const.pcapng.secrets_type.SecretsType
   :members:
   :undoc-members:
   :show-inheritance:

Verdict Types
=============

.. module:: pcapkit.const.pcapng.verdict_type

Generated from :class:`pcapkit.vendor.pcapng.verdict_type.VerdictType`.

.. autoclass:: pcapkit.const.pcapng.verdict_type.VerdictType
   :members:
   :undoc-members:
   :show-inheritance:

Filter Types
============

.. module:: pcapkit.const.pcapng.filter_type

Generated from :class:`pcapkit.vendor.pcapng.filter_type.FilterType`.

.. autoclass:: pcapkit.const.pcapng.filter_type.FilterType
   :members:
   :undoc-members:
   :show-inheritance:

TLS Key Log Labels
===================

.. module:: pcapkit.const.pcapng.tls_key_label

Generated from :class:`pcapkit.vendor.pcapng.tls_key_label.TLSKeyLabel`.

.. versionadded:: 1.5.0

   Moved here from :mod:`pcapkit.protocols.misc.pcapng.protocol` (:issue:`886`).

.. autoclass:: pcapkit.const.pcapng.tls_key_label.TLSKeyLabel
   :members:
   :undoc-members:
   :show-inheritance:

.. raw:: html

   <br />

.. [*] https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-standardized-block-type-cod
.. [*] https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-options
.. [*] https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-enhanced-packet-block-optio
.. [*] https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-enhanced-packet-block
.. [*] https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-name-resolution-block
.. [*] https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-decryption-secrets-block
.. [*] https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-interface-description-block
.. [*] https://www.iana.org/assignments/tls-parameters/tls-sslkeylogfile-labels.csv, cf. :rfc:`9850#section-4.2`
