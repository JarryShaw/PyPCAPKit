# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.misc.pcapng.PCAPNG` Constant Enumerations
==========================================================================

.. module:: pcapkit.const.pcapng

This module contains all constant enumerations of
:class:`~pcapkit.protocols.misc.pcapng.PCAPNG` implementations. Available
enumerations include:

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

.. [*] https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html#name-standardized-block-type-cod
.. [*] https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html#name-options
.. [*] https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html#name-enhanced-packet-block-flags
.. [*] https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html#name-enhanced-packet-block
.. [*] https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html#name-name-resolution-block
.. [*] https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html#name-decryption-secrets-block
.. [*] https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html#name-interface-description-block

"""

from pcapkit.const.pcapng.block_type import BlockType as PCAPNG_BlockType
from pcapkit.const.pcapng.filter_type import FilterType as PCAPNG_FilterType
from pcapkit.const.pcapng.hash_algorithm import HashAlgorithm as PCAPNG_HashAlgorithm
from pcapkit.const.pcapng.option_type import OptionType as PCAPNG_OptionType
from pcapkit.const.pcapng.record_type import RecordType as PCAPNG_RecordType
from pcapkit.const.pcapng.secrets_type import SecretsType as PCAPNG_SecretsType
from pcapkit.const.pcapng.verdict_type import VerdictType as PCAPNG_VerdictType

___all__ = [
    'PCAPNG_BlockType', 'PCAPNG_OptionType', 'PCAPNG_HashAlgorithm',
    'PCAPNG_VerdictType', 'PCAPNG_RecordType', 'PCAPNG_SecretsType',
    'PCAPNG_FilterType',
]
