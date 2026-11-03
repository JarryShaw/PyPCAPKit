# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.application.ospf.OSPF` Constant Enumerations
=============================================================================

.. module:: pcapkit.const.ospf

This module contains all constant enumerations of
:class:`~pcapkit.protocols.application.ospf.OSPF` implementations. Available
enumerations include:

.. list-table::

   * - :class:`OSPF_Authentication <pcapkit.const.ospf.authentication.Authentication>`
     - Authentication Codes [*]_
   * - :class:`OSPF_Packet <pcapkit.const.ospf.packet.Packet>`
     - OSPF Packet Types [*]_

.. [*] https://www.iana.org/assignments/ospf-authentication-codes/ospf-authentication-codes.xhtml#authentication-codes
.. [*] https://www.iana.org/assignments/ospfv2-parameters/ospfv2-parameters.xhtml#ospfv2-parameters-3

"""

from typing import TYPE_CHECKING

from pcapkit.utilities.lazy import lazy_exports

if TYPE_CHECKING:
    from pcapkit.const.ospf.authentication import Authentication as OSPF_Authentication
    from pcapkit.const.ospf.packet import Packet as OSPF_Packet

__all__ = ['OSPF_Authentication', 'OSPF_Packet']

__getattr__, __dir__ = lazy_exports(__name__, globals(), {
    'OSPF_Authentication': ('authentication', 'Authentication'),
    'OSPF_Packet': ('packet', 'Packet'),
})
