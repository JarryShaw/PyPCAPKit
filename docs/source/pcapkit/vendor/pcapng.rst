====================================================================
:class:`~pcapkit.protocols.misc.pcapng.PCAPNG` Vendor Crawlers
====================================================================

.. module:: pcapkit.vendor.pcapng

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.misc.pcapng.PCAPNG` implementations. Available
vendor crawlers include:

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

Block Types
===========

.. module:: pcapkit.vendor.pcapng.block_type

This module contains the vendor crawler for **Block Types**,
which is automatically generating :class:`pcapkit.const.pcapng.block_type.BlockType`.

.. autoclass:: pcapkit.vendor.pcapng.block_type.BlockType
   :members: FLAG, LINK
   :show-inheritance:

Hash Algorithms
===============

.. module:: pcapkit.vendor.pcapng.hash_algorithm

This module contains the vendor crawler for **Hash Algorithms**,
which is automatically generating :class:`pcapkit.const.pcapng.hash_algorithm.HashAlgorithm`.

.. autoclass:: pcapkit.vendor.pcapng.hash_algorithm.HashAlgorithm
   :members: FLAG
   :show-inheritance:

Option Types
============

.. module:: pcapkit.vendor.pcapng.option_type

This module contains the vendor crawler for **Option Types**,
which is automatically generating :class:`pcapkit.const.pcapng.option_type.OptionType`.

.. autoclass:: pcapkit.vendor.pcapng.option_type.OptionType
   :members: FLAG, LINK
   :show-inheritance:

Record Types
============

.. module:: pcapkit.vendor.pcapng.record_type

This module contains the vendor crawler for **Record Types**,
which is automatically generating :class:`pcapkit.const.pcapng.record_type.RecordType`.

.. autoclass:: pcapkit.vendor.pcapng.record_type.RecordType
   :members: FLAG, LINK
   :show-inheritance:

Secrets Types
=============

.. module:: pcapkit.vendor.pcapng.secrets_type

This module contains the vendor crawler for **Secrets Types**,
which is automatically generating :class:`pcapkit.const.pcapng.secrets_type.SecretsType`.

.. autoclass:: pcapkit.vendor.pcapng.secrets_type.SecretsType
   :members: FLAG
   :show-inheritance:

Verdict Types
=============

.. module:: pcapkit.vendor.pcapng.verdict_type

This module contains the vendor crawler for **Verdict Types**,
which is automatically generating :class:`pcapkit.const.pcapng.verdict_type.VerdictType`.

.. autoclass:: pcapkit.vendor.pcapng.verdict_type.VerdictType
   :members: FLAG
   :show-inheritance:

Filter Types
============

.. module:: pcapkit.vendor.pcapng.filter_type

This module contains the vendor crawler for **Filter Types**,
which is automatically generating :class:`pcapkit.const.pcapng.filter_type.FilterType`.

.. autoclass:: pcapkit.vendor.pcapng.filter_type
   :members: FLAG
   :show-inheritance:

.. raw:: html

   <br />

.. [*] https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html#name-standardized-block-type-cod
.. [*] https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html#name-options
.. [*] https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html#name-enhanced-packet-block-flags
.. [*] https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html#name-enhanced-packet-block
.. [*] https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html#name-name-resolution-block
.. [*] https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html#name-decryption-secrets-block
.. [*] https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html#name-interface-description-block
