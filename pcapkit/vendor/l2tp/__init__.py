# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.link.l2tp.L2TP` Vendor Crawlers
================================================================

.. module:: pcapkit.vendor.l2tp

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.link.l2tp.L2TP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`L2TP_Type <pcapkit.vendor.l2tp.type.Type>`
     - L2TP Types

"""

from pcapkit.vendor.l2tp.type import Type as L2TP_Type

__all__ = ['L2TP_Type']
