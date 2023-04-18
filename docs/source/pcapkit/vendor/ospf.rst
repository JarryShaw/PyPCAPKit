================================================================
:class:`~pcapkit.protocols.link.ospf.OSPF` Vendor Crawlers
================================================================

.. module:: pcapkit.vendor.ospf

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.link.ospf.OSPF` implementations. Available
vendor crawlers include:

.. list-table::

   * - :class:`OSPF_Authentication <pcapkit.vendor.ospf.authentication.Authentication>`
     - Authentication Codes [*]_
   * - :class:`OSPF_Packet <pcapkit.vendor.ospf.packet.Packet>`
     - OSPF Packet Types [*]_

Authentication Types
====================

.. module:: pcapkit.vendor.ospf.authentication

This module contains the vendor crawler for **Authentication Types**,
which is automatically generating :class:`pcapkit.const.ospf.authentication.Authentication`.

.. autoclass:: pcapkit.vendor.ospf.authentication.Authentication
   :members: FLAG, LINK
   :show-inheritance:

OSPF Packet Types
=================

.. module:: pcapkit.vendor.ospf.packet

This module contains the vendor crawler for **OSPF Packet Types**,
which is automatically generating :class:`pcapkit.const.ospf.packet.Packet`.

.. autoclass:: pcapkit.vendor.ospf.packet.Packet
   :members: FLAG, LINK
   :show-inheritance:

.. raw:: html

   <hr />

.. [*] https://www.iana.org/assignments/ospf-authentication-codes/ospf-authentication-codes.xhtml#authentication-codes
.. [*] https://www.iana.org/assignments/ospfv2-parameters/ospfv2-parameters.xhtml#ospfv2-parameters-3
