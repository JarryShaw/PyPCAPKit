# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.link.arp.ARP` Constant Enumerations
====================================================================

This module contains all constant enumerations of :class:`~pcapkit.protocols.link.arp.ARP`
and :class:`~pcapkit.protocols.application.rarp.RARP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`ARP_Hardware <pcapkit.const.arp.hardware.Hardware>`
     - ARP Hardware Types [*]_
   * - :class:`ARP_Operation <pcapkit.const.arp.operation.Operation>`
     - Operation Codes [*]_

.. [*] https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-2
.. [*] https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-1

"""

from typing import TYPE_CHECKING

from pcapkit.utilities.lazy import lazy_exports

if TYPE_CHECKING:
    from pcapkit.const.arp.hardware import Hardware as ARP_Hardware
    from pcapkit.const.arp.operation import Operation as ARP_Operation

__all__ = ['ARP_Hardware', 'ARP_Operation']

__getattr__, __dir__ = lazy_exports(__name__, globals(), {
    'ARP_Hardware': ('hardware', 'Hardware'),
    'ARP_Operation': ('operation', 'Operation'),
})
