# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.link.ppp.protocol.PPP` Vendor Crawlers
=======================================================================

.. module:: pcapkit.vendor.ppp

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.link.ppp.protocol.PPP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`PPP_Protocol <pcapkit.vendor.ppp.protocol.Protocol>`
     - PPP DLL Protocol Numbers [*]_

.. [*] https://www.iana.org/assignments/ppp-numbers/ppp-numbers.xhtml#ppp-numbers-2

"""

from pcapkit.vendor.ppp.protocol import Protocol as PPP_Protocol

__all__ = ['PPP_Protocol']
