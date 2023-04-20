============================================
Protocol Type Registry Vendor Crawlers
============================================

.. module:: pcapkit.vendor.reg

This module contains all vendor crawlers of protocol type registry
implementations. Available vendor crawlers include:

.. list-table::

   * - :class:`LINKTYPE <pcapkit.vendor.reg.linktype.LinkType>`
     - Link-Layer Header Type Values [*]_
   * - :class:`ETHERTYPE <pcapkit.vendor.reg.ethertype.EtherType>`
     - Ethertype IEEE 802 Numbers [*]_
   * - :class:`TRANSTYPE <pcapkit.vendor.reg.transtype.TransType>`
     - Transport Layer Protocol Numbers [*]_

Link-Layer Header Type Values
=============================

.. module:: pcapkit.vendor.reg.linktype

This module contains the vendor crawler for **Link-Layer Header Type Values**,
which is automatically generating :class:`pcapkit.const.reg.linktype.LinkType`.

.. autoclass:: pcapkit.vendor.reg.linktype.LinkType
   :members: FLAG, LINK
   :show-inheritance:

Ethertype IEEE 802 Numbers
==========================

.. module:: pcapkit.vendor.reg.ethertype

This module contains the vendor crawler for **Ethertype IEEE 802 Numbers**,
which is automatically generating :class:`pcapkit.const.reg.ethertype.EtherType`.

.. autoclass:: pcapkit.vendor.reg.ethertype.EtherType
   :members: FLAG, LINK
   :show-inheritance:

Transport Layer Protocol Numbers
================================

.. module:: pcapkit.vendor.reg.transtype

This module contains the vendor crawler for **Transport Layer Protocol Numbers**,
which is automatically generating :class:`pcapkit.const.reg.transtype.TransType`.

.. autoclass:: pcapkit.vendor.reg.transtype.TransType
   :members: FLAG, LINK
   :show-inheritance:

.. raw:: html

   <hr />

.. [*] http://www.tcpdump.org/linktypes.html
.. [*] https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml#ieee-802-numbers-1
.. [*] https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml#protocol-numbers-1
