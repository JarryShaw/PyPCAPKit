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

.. automodule:: pcapkit.vendor.arp.hardware
   :no-members:

.. autoclass:: pcapkit.vendor.arp.hardware.Hardware
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.arp.operation
   :no-members:

.. autoclass:: pcapkit.vendor.arp.operation.Operation
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. raw:: html

   <hr />

.. [*] https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-2
.. [*] https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-1
