:class:`~pcapkit.protocols.link.ospf.OSPF` Vendor Crawlers
==========================================================

.. module:: pcapkit.vendor.ospf

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.link.ospf.OSPF` implementations. Available
enumerations include:

.. list-table::

   * - :class:`OSPF_Authentication <pcapkit.vendor.ospf.authentication.Authentication>`
     - Authentication Codes [*]_
   * - :class:`OSPF_Packet <pcapkit.vendor.ospf.packet.Packet>`
     - OSPF Packet Types [*]_

.. automodule:: pcapkit.vendor.ospf.authentication
   :no-members:

.. autoclass:: pcapkit.vendor.ospf.authentication.Authentication
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.ospf.packet
   :no-members:

.. autoclass:: pcapkit.vendor.ospf.packet.Packet
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. raw:: html

   <hr />

.. [*] https://www.iana.org/assignments/ospf-authentication-codes/ospf-authentication-codes.xhtml#authentication-codes
.. [*] https://www.iana.org/assignments/ospfv2-parameters/ospfv2-parameters.xhtml#ospfv2-parameters-3
