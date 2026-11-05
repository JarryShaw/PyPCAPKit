=================================================================
:class:`~pcapkit.protocols.link.arp.protocol.ARP` Vendor Crawlers
=================================================================

.. module:: pcapkit.vendor.arp

Shared with :class:`~pcapkit.protocols.application.rarp.protocol.RARP`.

.. list-table::

   * - :class:`ARP_Hardware <pcapkit.vendor.arp.hardware.Hardware>`
     - ARP Hardware Types [*]_
   * - :class:`ARP_Operation <pcapkit.vendor.arp.operation.Operation>`
     - Operation Codes [*]_

Hardware Types
==============

.. module:: pcapkit.vendor.arp.hardware

Generates :class:`pcapkit.const.arp.hardware.Hardware`.

.. autoclass:: pcapkit.vendor.arp.hardware.Hardware
   :members: FLAG, LINK
   :show-inheritance:

Operation Codes
===============

.. module:: pcapkit.vendor.arp.operation

Generates :class:`pcapkit.const.arp.operation.Operation`.

.. autoclass:: pcapkit.vendor.arp.operation.Operation
   :members: FLAG, LINK
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-2
.. [*] https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-1
