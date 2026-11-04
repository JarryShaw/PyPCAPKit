# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.internet.igmp.protocol.IGMP` Constant Enumerations
===================================================================================

.. module:: pcapkit.const.igmp

This module contains all constant enumerations of
:class:`~pcapkit.protocols.internet.igmp.protocol.IGMP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`IGMP_Type <pcapkit.const.igmp.type.Type>`
     - IGMP Type Numbers [*]_
   * - :class:`IGMP_RecordType <pcapkit.const.igmp.record_type.RecordType>`
     - IGMP Group Record Types [*]_

.. [*] https://www.iana.org/assignments/igmp-type-numbers/igmp-type-numbers.xhtml
.. [*] https://www.rfc-editor.org/rfc/rfc3376#section-4.2.12

"""

from typing import TYPE_CHECKING

from pcapkit.utilities.importlib import lazy_exports

if TYPE_CHECKING:
    from pcapkit.const.igmp.record_type import RecordType as IGMP_RecordType
    from pcapkit.const.igmp.type import Type as IGMP_Type

__all__ = ['IGMP_Type', 'IGMP_RecordType']

__getattr__, __dir__ = lazy_exports(__name__, globals(), {
    'IGMP_Type': ('type', 'Type'),
    'IGMP_RecordType': ('record_type', 'RecordType'),
})
