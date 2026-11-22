===============================================================================
:class:`~pcapkit.protocols.link.pppoe.protocol.PPPoE` Vendor Crawlers
===============================================================================

.. module:: pcapkit.vendor.pppoe

.. list-table::

   * - :class:`PPPoE_Code <pcapkit.vendor.pppoe.code.Code>`
     - PPPoE Active Discovery Code Fields [*]_
   * - :class:`PPPoE_Tag <pcapkit.vendor.pppoe.tag.Tag>`
     - PPPoE TAG Values [*]_

PPPoE Active Discovery Code Fields
==================================

.. module:: pcapkit.vendor.pppoe.code

Generates :class:`pcapkit.const.pppoe.code.Code`.

.. autoclass:: pcapkit.vendor.pppoe.code.Code
   :members: FLAG, LINK, WIDTH, hexlify
   :show-inheritance:

PPPoE TAG Values
================

.. module:: pcapkit.vendor.pppoe.tag

Generates :class:`pcapkit.const.pppoe.tag.Tag`.

.. autoclass:: pcapkit.vendor.pppoe.tag.Tag
   :members: FLAG, LINK, WIDTH
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.iana.org/assignments/pppoe-parameters/pppoe-parameters.xhtml#pppoe-parameters-2
.. [*] https://www.iana.org/assignments/pppoe-parameters/pppoe-parameters.xhtml#pppoe-parameters-1
