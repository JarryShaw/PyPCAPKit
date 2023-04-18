# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.misc.pcapng.PCAPNG` Constant Enumerations
==========================================================================

.. module:: pcapkit.const.pcapng

This module contains all constant enumerations of
:class:`~pcapkit.protocols.misc.pcapng.PCAPNG` implementations. Available
enumerations include:

.. list-table::

   * - :class:`BlockType <pcapkit.const.pcapng.block_type.BlockType>`
     - Block Types [*]_

.. [*] https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html

"""

from pcapkit.const.pcapng.block_type import BlockType as PCAPNG_BlockType

___all__ = [
    'PCAPNG_BlockType',
]
