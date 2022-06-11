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

.. automodule:: pcapkit.const.reg.linktype
   :no-members:

.. autoclass:: pcapkit.const.reg.linktype.LinkType
   :members:
   :private-members:
   :show-inheritance:

.. automodule:: pcapkit.const.reg.ethertype
   :no-members:

.. autoclass:: pcapkit.const.reg.ethertype.EtherType
   :members:
   :private-members:
   :show-inheritance:

.. automodule:: pcapkit.const.reg.transtype
   :no-members:

.. autoclass:: pcapkit.const.reg.transtype.TransType
   :members:
   :private-members:
   :show-inheritance:

.. raw:: html

   <hr />

.. [*] http://www.tcpdump.org/linktypes.html
.. [*] https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml#ieee-802-numbers-1
.. [*] https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml#protocol-numbers-1
