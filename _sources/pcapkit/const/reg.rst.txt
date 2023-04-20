============================================
Protocol Type Registry Constant Enumerations
============================================

.. module:: pcapkit.const.reg

This module contains all constant enumerations of protocol type registry
implementations. Available enumerations include:

.. list-table::

   * - :class:`LINKTYPE <pcapkit.const.reg.linktype.LinkType>`
     - Link-Layer Header Type Values [*]_
   * - :class:`ETHERTYPE <pcapkit.const.reg.ethertype.EtherType>`
     - Ethertype IEEE 802 Numbers [*]_
   * - :class:`TRANSTYPE <pcapkit.const.reg.transtype.TransType>`
     - Transport Layer Protocol Numbers [*]_

Link-Layer Header Type Values
=============================

.. module:: pcapkit.const.reg.linktype

This module contains the constant enumeration for **Link-Layer Header Type Values**,
which is automatically generated from :class:`pcapkit.vendor.reg.linktype.LinkType`.

.. autoclass:: pcapkit.const.reg.linktype.LinkType
   :members:
   :undoc-members:
   :show-inheritance:

Ethertype IEEE 802 Numbers
==========================

.. module:: pcapkit.const.reg.ethertype

This module contains the constant enumeration for **Ethertype IEEE 802 Numbers**,
which is automatically generated from :class:`pcapkit.vendor.reg.ethertype.EtherType`.

.. autoclass:: pcapkit.const.reg.ethertype.EtherType
   :members:
   :undoc-members:
   :show-inheritance:

Transport Layer Protocol Numbers
================================

.. module:: pcapkit.const.reg.transtype

This module contains the constant enumeration for **Transport Layer Protocol Numbers**,
which is automatically generated from :class:`pcapkit.vendor.reg.transtype.TransType`.

.. autoclass:: pcapkit.const.reg.transtype.TransType
   :members:
   :undoc-members:
   :show-inheritance:

.. raw:: html

   <hr />

.. [*] http://www.tcpdump.org/linktypes.html
.. [*] https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml#ieee-802-numbers-1
.. [*] https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml#protocol-numbers-1
