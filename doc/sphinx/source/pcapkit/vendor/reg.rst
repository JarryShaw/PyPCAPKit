Protocol Type Registry Vendor Crawlers
======================================

.. module:: pcapkit.vendor.reg

This module contains all vendor crawlers of protocol type registry
implementations. Available enumerations include:

.. list-table::

   * - :class:`LINKTYPE <pcapkit.vendor.reg.linktype.LinkType>`
     - Link-Layer Header Type Values [*]_
   * - :class:`ETHERTYPE <pcapkit.vendor.reg.ethertype.EtherType>`
     - Ethertype IEEE 802 Numbers [*]_
   * - :class:`TRANSTYPE <pcapkit.vendor.reg.transtype.TransType>`
     - Transport Layer Protocol Numbers [*]_

.. automodule:: pcapkit.vendor.reg.linktype
   :no-members:

.. autoclass:: pcapkit.vendor.reg.linktype.LinkType
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

.. automodule:: pcapkit.vendor.reg.ethertype
   :no-members:

.. autoclass:: pcapkit.vendor.reg.ethertype.EtherType
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

.. automodule:: pcapkit.vendor.reg.transtype
   :no-members:

.. autoclass:: pcapkit.vendor.reg.transtype.TransType
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

.. raw:: html

   <hr />

.. [*] http://www.tcpdump.org/linktypes.html
.. [*] https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml#ieee-802-numbers-1
.. [*] https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml#protocol-numbers-1
