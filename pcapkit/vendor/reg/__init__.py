# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""Protocol Type Registry Vendor Crawlers
============================================

This module contains all vendor crawlers of protocol type registry
implementations. Available enumerations include:

.. list-table::

   * - :class:`LINKTYPE <pcapkit.vendor.reg.linktype.LinkType>`
     - Link-Layer Header Type Values [*]_
   * - :class:`ETHERTYPE <pcapkit.vendor.reg.ethertype.EtherType>`
     - Ethertype IEEE 802 Numbers [*]_
   * - :class:`TRANSTYPE <pcapkit.vendor.reg.transtype.TransType>`
     - Transport Layer Protocol Numbers [*]_

.. [*] http://www.tcpdump.org/linktypes.html
.. [*] https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml#ieee-802-numbers-1
.. [*] https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml#protocol-numbers-1

"""

from pcapkit.vendor.reg.ethertype import EtherType
from pcapkit.vendor.reg.linktype import LinkType
from pcapkit.vendor.reg.transtype import TransType

__all__ = ['EtherType', 'LinkType', 'TransType']
