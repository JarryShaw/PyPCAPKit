# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.link.arp.ARP` Constant Enumerations
=====================================================================

This module contains all constant enumerations of :class:`~pcapkit.protocols.link.arp.ARP`
and :class:`~pcapkit.protocols.link.rarp.RARP` implementations. Available
enumerations include:

.. list-table::
   :widths: auto

   * - :class:`ARP_Hardware <pcapkit.const.arp.hardware.Hardware>`
     - :doc:`hardware` [*]_
   * - :class:`ARP_Operation <pcapkit.const.arp.operation.Operation>`
     - :doc:`operation` [*]_

"""

from pcapkit.const.arp.hardware import Hardware as ARP_Hardware
from pcapkit.const.arp.operation import Operation as ARP_Operation

__all__ = ['ARP_Hardware', 'ARP_Operation']
