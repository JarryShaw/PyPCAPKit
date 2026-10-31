# -*- coding: utf-8 -*-
# pylint: disable=unused-import, wrong-import-position
""":class:`~pcapkit.protocols.internet.igmp.IGMP` Vendor Crawlers
====================================================================

.. module:: pcapkit.vendor.igmp

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.internet.igmp.IGMP` implementations. Available
crawlers include:

.. list-table::

   * - :class:`IGMP_Type <pcapkit.vendor.igmp.type.Type>`
     - IGMP Type Numbers [*]_

.. [*] https://www.iana.org/assignments/igmp-type-numbers/igmp-type-numbers.xhtml

"""

from pcapkit.vendor.igmp.type import Type as IGMP_Type

__all__ = ['IGMP_Type']
