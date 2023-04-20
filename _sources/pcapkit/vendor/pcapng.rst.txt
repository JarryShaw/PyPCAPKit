====================================================================
:class:`~pcapkit.protocols.misc.pcapng.PCAPNG` Vendor Crawlers
====================================================================

.. module:: pcapkit.vendor.pcapng

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.misc.pcapng.PCAPNG` implementations. Available
vendor crawlers include:

.. list-table::

   * - :class:`BlockType <pcapkit.vendor.pcapng.block_type.BlockType>`
     - Block Types [*]_

Block Types
===========

.. module:: pcapkit.vendor.pcapng.block_type

This module contains the vendor crawler for **Block Types**,
which is automatically generating :class:`pcapkit.const.pcapng.block_type.BlockType`.

.. autoclass:: pcapkit.vendor.pcapng.block_type.BlockType
   :members: FLAG, LINK
   :show-inheritance:

.. raw:: html

   <br />

.. [*] https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html
