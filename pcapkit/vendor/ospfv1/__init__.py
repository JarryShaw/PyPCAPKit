# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.application.ospfv1.protocol.OSPFv1` Vendor Crawlers
====================================================================================

.. module:: pcapkit.vendor.ospfv1

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.application.ospfv1.protocol.OSPFv1` implementations. Available
crawlers include:

.. list-table::

   * - :class:`OSPFv1_Authentication <pcapkit.vendor.ospfv1.authentication.Authentication>`
     - OSPFv1 Authentication Types [*]_
   * - :class:`OSPFv1_Packet <pcapkit.vendor.ospfv1.packet.Packet>`
     - OSPFv1 Packet Types [*]_

.. [*] https://datatracker.ietf.org/doc/html/rfc1131
.. [*] https://datatracker.ietf.org/doc/html/rfc1131

"""

from pcapkit.vendor.ospfv1.authentication import Authentication as OSPFv1_Authentication
from pcapkit.vendor.ospfv1.packet import Packet as OSPFv1_Packet

__all__ = ['OSPFv1_Authentication', 'OSPFv1_Packet']
