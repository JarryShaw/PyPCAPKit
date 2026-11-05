=============================================================================
:class:`~pcapkit.protocols.misc.pcapng.protocol.PCAPNG` Vendor Crawlers
=============================================================================

.. module:: pcapkit.vendor.pcapng

.. list-table::

   * - :class:`PCAPNG_BlockType <pcapkit.vendor.pcapng.block_type.BlockType>`
     - Block Types [*]_
   * - :class:`PCAPNG_OptionType <pcapkit.vendor.pcapng.option_type.OptionType>`
     - Option Types [*]_
   * - :class:`PCAPNG_HashAlgorithm <pcapkit.vendor.pcapng.hash_algorithm.HashAlgorithm>`
     - Hash Algorithms [*]_
   * - :class:`PCAPNG_VerdictType <pcapkit.vendor.pcapng.verdict_type.VerdictType>`
     - Verdict Types [*]_
   * - :class:`PCAPNG_RecordType <pcapkit.vendor.pcapng.record_type.RecordType>`
     - Record Types [*]_
   * - :class:`PCAPNG_SecretsType <pcapkit.vendor.pcapng.secrets_type.SecretsType>`
     - Secrets Types [*]_
   * - :class:`PCAPNG_FilterType <pcapkit.vendor.pcapng.filter_type.FilterType>`
     - Filter Types [*]_
   * - :class:`PCAPNG_TLSKeyLabel <pcapkit.vendor.pcapng.tls_key_label.TLSKeyLabel>`
     - TLS Key Log Labels [*]_

.. note::

   The crawlers that scrape a registry table --
   :class:`BlockType <pcapkit.vendor.pcapng.block_type.BlockType>`,
   :class:`OptionType <pcapkit.vendor.pcapng.option_type.OptionType>` and
   :class:`RecordType <pcapkit.vendor.pcapng.record_type.RecordType>` -- read
   revision ``-03`` of the draft, as each one's ``LINK`` below shows. Revision
   ``-02`` renders its registries as ASCII art inside ``<pre>``, so the
   ``table-1`` through ``table-10`` ids these crawlers select exist only in
   ``-03``. The footnotes below point at ``-03`` for the same reason.

Block Types
===========

.. module:: pcapkit.vendor.pcapng.block_type

Generates :class:`pcapkit.const.pcapng.block_type.BlockType`.

.. autoclass:: pcapkit.vendor.pcapng.block_type.BlockType
   :members: FLAG, LINK
   :show-inheritance:

Hash Algorithms
===============

.. module:: pcapkit.vendor.pcapng.hash_algorithm

Generates :class:`pcapkit.const.pcapng.hash_algorithm.HashAlgorithm`.

.. autoclass:: pcapkit.vendor.pcapng.hash_algorithm.HashAlgorithm
   :members: FLAG
   :show-inheritance:

Option Types
============

.. module:: pcapkit.vendor.pcapng.option_type

Generates :class:`pcapkit.const.pcapng.option_type.OptionType`.

.. autoclass:: pcapkit.vendor.pcapng.option_type.OptionType
   :members: FLAG, LINK
   :show-inheritance:

Record Types
============

.. module:: pcapkit.vendor.pcapng.record_type

Generates :class:`pcapkit.const.pcapng.record_type.RecordType`.

.. autoclass:: pcapkit.vendor.pcapng.record_type.RecordType
   :members: FLAG, LINK
   :show-inheritance:

Secrets Types
=============

.. module:: pcapkit.vendor.pcapng.secrets_type

Generates :class:`pcapkit.const.pcapng.secrets_type.SecretsType`.

.. autoclass:: pcapkit.vendor.pcapng.secrets_type.SecretsType
   :members: FLAG
   :show-inheritance:

Verdict Types
=============

.. module:: pcapkit.vendor.pcapng.verdict_type

Generates :class:`pcapkit.const.pcapng.verdict_type.VerdictType`.

.. autoclass:: pcapkit.vendor.pcapng.verdict_type.VerdictType
   :members: FLAG
   :show-inheritance:

Filter Types
============

.. module:: pcapkit.vendor.pcapng.filter_type

Generates :class:`pcapkit.const.pcapng.filter_type.FilterType`.

.. autoclass:: pcapkit.vendor.pcapng.filter_type.FilterType
   :members: FLAG
   :show-inheritance:

TLS Key Log Labels
===================

.. module:: pcapkit.vendor.pcapng.tls_key_label

Generates :class:`pcapkit.const.pcapng.tls_key_label.TLSKeyLabel`.

.. autoclass:: pcapkit.vendor.pcapng.tls_key_label.TLSKeyLabel
   :members: LINK
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-standardized-block-type-cod
.. [*] https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-options
.. [*] https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-enhanced-packet-block-optio
.. [*] https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-enhanced-packet-block
.. [*] https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-name-resolution-block
.. [*] https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-decryption-secrets-block
.. [*] https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-interface-description-block
.. [*] https://www.iana.org/assignments/tls-parameters/tls-sslkeylogfile-labels.csv, cf. :rfc:`9850#section-4.2`
