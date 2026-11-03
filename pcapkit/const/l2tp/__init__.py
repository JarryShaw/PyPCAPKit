# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.link.l2tp.L2TP` Constant Enumerations
======================================================================

.. module:: pcapkit.const.l2tp

This module contains all constant enumerations of
:class:`~pcapkit.protocols.link.l2tp.L2TP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`L2TP_Type <pcapkit.const.l2tp.type.Type>`
     - L2TP Types

"""

from typing import TYPE_CHECKING

from pcapkit.utilities.lazy import lazy_exports

if TYPE_CHECKING:
    from pcapkit.const.l2tp.type import Type as L2TP_Type

__all__ = ['L2TP_Type']

__getattr__, __dir__ = lazy_exports(__name__, globals(), {
    'L2TP_Type': ('type', 'Type'),
})
