# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.link.ospf.OSPF` Vendor Crawlers
================================================================

.. module:: pcapkit.vendor.ospf

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.link.ospf.OSPF` implementations. Available
enumerations include:

.. list-table::

   * - :class:`OSPF_Authentication <pcapkit.vendor.ospf.authentication.Authentication>`
     - Authentication Codes [*]_
   * - :class:`OSPF_Packet <pcapkit.vendor.ospf.packet.Packet>`
     - OSPF Packet Types [*]_

.. [*] https://www.iana.org/assignments/ospf-authentication-codes/ospf-authentication-codes.xhtml#authentication-codes
.. [*] https://www.iana.org/assignments/ospfv2-parameters/ospfv2-parameters.xhtml#ospfv2-parameters-3

"""

from pcapkit.vendor.ospf.authentication import Authentication as OSPF_Authentication
from pcapkit.vendor.ospf.packet import Packet as OSPF_Packet

__all__ = ['OSPF_Authentication', 'OSPF_Packet']
