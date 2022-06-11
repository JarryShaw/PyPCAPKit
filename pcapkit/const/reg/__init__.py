# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""Protocol Type Registry Constant Enumerations
==================================================

This module contains all constant enumerations of protocol type registry
implementations. Available enumerations include:

.. list-table::

   * - :class:`LINKTYPE <pcapkit.const.reg.linktype.LinkType>`
     - Link-Layer Header Type Values [*]_
   * - :class:`ETHERTYPE <pcapkit.const.reg.ethertype.EtherType>`
     - Ethertype IEEE 802 Numbers [*]_
   * - :class:`TRANSTYPE <pcapkit.const.reg.transtype.TransType>`
     - Transport Layer Protocol Numbers [*]_

.. [*] http://www.tcpdump.org/linktypes.html
.. [*] https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml#ieee-802-numbers-1
.. [*] https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml#protocol-numbers-1

"""

from pcapkit.const.reg.ethertype import EtherType as ETHERTYPE
from pcapkit.const.reg.linktype import LinkType as LINKTYPE
from pcapkit.const.reg.transtype import TransType as TRANSTYPE

__all__ = ['ETHERTYPE', 'LINKTYPE', 'TRANSTYPE']
