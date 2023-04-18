========================================================
:class:`~pcapkit.protocols.link.arp.ARP` Vendor Crawlers
========================================================

.. module:: pcapkit.vendor.arp

This module contains all vendor crawlers of :class:`~pcapkit.protocols.link.arp.ARP`
and :class:`~pcapkit.protocols.link.rarp.RARP` implementations. Available
vendor crawlers include:

.. list-table::

   * - :class:`ARP_Hardware <pcapkit.vendor.arp.hardware.Hardware>`
     - ARP Hardware Types [*]_
   * - :class:`ARP_Operation <pcapkit.vendor.arp.operation.Operation>`
     - Operation Codes [*]_

Hardware Types
==============

.. module:: pcapkit.vendor.arp.hardware

This module contains the vendor crawler for **Hardware Types**,
which is automatically generating :class:`pcapkit.const.arp.hardware.Hardware`.

.. autoclass:: pcapkit.vendor.arp.hardware.Hardware
   :members: FLAG, LINK
   :show-inheritance:

Operation Codes
===============

.. module:: pcapkit.vendor.arp.operation

This module contains the vendor crawler for **Operation Codes**,
which is automatically generating :class:`pcapkit.const.arp.operation.Operation`.

.. autoclass:: pcapkit.vendor.arp.operation.Operation
   :members: FLAG, LINK
   :show-inheritance:

.. raw:: html

   <hr />

.. [*] https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-2
.. [*] https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-1
