==============================================================
:class:`~pcapkit.protocols.link.arp.ARP` Constant Enumerations
==============================================================

.. module:: pcapkit.const.arp

This module contains all constant enumerations of :class:`~pcapkit.protocols.link.arp.ARP`
and :class:`~pcapkit.protocols.link.rarp.RARP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`ARP_Hardware <pcapkit.const.arp.hardware.Hardware>`
     - ARP Hardware Types [*]_
   * - :class:`ARP_Operation <pcapkit.const.arp.operation.Operation>`
     - Operation Codes [*]_

Hardware Types
==============

.. module:: pcapkit.const.arp.hardware

This module contains the constant enumeration for **Hardware Types**,
which is automatically generated from :class:`pcapkit.vendor.arp.hardware.Hardware`.

.. autoclass:: pcapkit.const.arp.hardware.Hardware
   :members:
   :undoc-members:
   :show-inheritance:

Operation Codes
===============

.. module:: pcapkit.const.arp.operation

This module contains the constant enumeration for **Operation Codes**,
which is automatically generated from :class:`pcapkit.vendor.arp.operation.Operation`.

.. autoclass:: pcapkit.const.arp.operation.Operation
   :members:
   :undoc-members:
   :show-inheritance:

.. raw:: html

   <hr />

.. [*] https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-2
.. [*] https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-1
