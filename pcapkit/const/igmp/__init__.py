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
   * - :class:`IGMP_RecordType <pcapkit.const.igmp.record_type.RecordType>`
     - IGMP Group Record Types [*]_

.. [*] https://www.iana.org/assignments/igmp-type-numbers/igmp-type-numbers.xhtml
.. [*] https://www.rfc-editor.org/rfc/rfc3376#section-4.2.12

"""

from pcapkit.const.igmp.record_type import RecordType as IGMP_RecordType
from pcapkit.const.igmp.type import Type as IGMP_Type

__all__ = ['IGMP_Type', 'IGMP_RecordType']
