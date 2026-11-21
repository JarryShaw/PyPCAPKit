# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.link.pppoe.protocol.PPPoE` Vendor Crawlers
===========================================================================

.. module:: pcapkit.vendor.pppoe

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.link.pppoe.protocol.PPPoE` implementations. Available
enumerations include:

.. list-table::

   * - :class:`PPPoE_Code <pcapkit.vendor.pppoe.code.Code>`
     - PPPoE Active Discovery Code Fields [*]_
   * - :class:`PPPoE_Tag <pcapkit.vendor.pppoe.tag.Tag>`
     - PPPoE TAG Values [*]_

.. [*] https://www.iana.org/assignments/pppoe-parameters/pppoe-parameters.xhtml#pppoe-parameters-2
.. [*] https://www.iana.org/assignments/pppoe-parameters/pppoe-parameters.xhtml#pppoe-parameters-1

"""

from pcapkit.vendor.pppoe.code import Code as PPPoE_Code
from pcapkit.vendor.pppoe.tag import Tag as PPPoE_Tag

__all__ = ['PPPoE_Code', 'PPPoE_Tag']
