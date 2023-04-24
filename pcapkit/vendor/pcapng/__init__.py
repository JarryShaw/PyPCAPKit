# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.misc.pcapng.PCAPNG` Vendor Crawler
===================================================================

.. module:: pcapkit.vendor.pcapng

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.misc.pcapng.PCAPNG` implementations. Available
crawlers include:

.. list-table::

   * - :class:`BlockType <pcapkit.vendor.pcapng.block_type.BlockType>`
     - Block Types [*]_
   * - :class:`OptionType <pcapkit.vendor.pcapng.option_type.OptionType>`
     - Option Types [*]_

.. [*] https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html
.. [*] https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html

"""

from pcapkit.vendor.pcapng.block_type import BlockType as PCAPNG_BlockType
from pcapkit.vendor.pcapng.option_type import OptionType as PCAPNG_OptionType

__all__ = [
    'PCAPNG_BlockType', 'PCAPNG_OptionType',
]
