# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.internet.igmp.IGMP` Constant Enumerations
==========================================================================

.. module:: pcapkit.const.igmp

This module contains all constant enumerations of
:class:`~pcapkit.protocols.internet.igmp.IGMP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`IGMP_Type <pcapkit.const.igmp.type.Type>`
     - IGMP Type Numbers [*]_

.. [*] https://www.iana.org/assignments/igmp-type-numbers/igmp-type-numbers.xhtml

"""

from pcapkit.const.igmp.type import Type as IGMP_Type

__all__ = ['IGMP_Type']
