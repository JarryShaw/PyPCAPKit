# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.internet.mh.MH` Constant Enumerations
======================================================================

This module contains all constant enumerations of
:class:`~pcapkit.protocols.internet.mh.MH` implementations. Available
enumerations include:

.. list-table::

   * - :class:`MH_Packet <pcapkit.const.mh.packet.Packet>`
     - Mobility Header Types [*]_

.. [*] https://www.iana.org/assignments/mobility-parameters/mobility-parameters.xhtml#mobility-parameters-1

"""

from pcapkit.const.mh.packet import Packet as MH_Packet

__all__ = ['MH_Packet']
