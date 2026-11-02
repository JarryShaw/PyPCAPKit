# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.link.ieee802_11.IEEE802_11` Constant Enumerations
==================================================================================

.. module:: pcapkit.const.ieee802_11

This module contains all constant enumerations of
:class:`~pcapkit.protocols.link.ieee802_11.IEEE802_11` implementations, each
from IEEE Std 802.11-2020, Table 9-1, *Valid type and subtype combinations*.
Available enumerations include:

.. list-table::

   * - :class:`IEEE802_11_Type <pcapkit.const.ieee802_11.type.Type>`
     - Frame Types
   * - :class:`IEEE802_11_ManagementSubtype <pcapkit.const.ieee802_11.management_subtype.ManagementSubtype>`
     - Management Frame Subtypes
   * - :class:`IEEE802_11_ControlSubtype <pcapkit.const.ieee802_11.control_subtype.ControlSubtype>`
     - Control Frame Subtypes
   * - :class:`IEEE802_11_DataSubtype <pcapkit.const.ieee802_11.data_subtype.DataSubtype>`
     - Data Frame Subtypes
   * - :class:`IEEE802_11_ExtensionSubtype <pcapkit.const.ieee802_11.extension_subtype.ExtensionSubtype>`
     - Extension Frame Subtypes

"""

from pcapkit.const.ieee802_11.control_subtype import ControlSubtype as IEEE802_11_ControlSubtype
from pcapkit.const.ieee802_11.data_subtype import DataSubtype as IEEE802_11_DataSubtype
from pcapkit.const.ieee802_11.extension_subtype import \
    ExtensionSubtype as IEEE802_11_ExtensionSubtype
from pcapkit.const.ieee802_11.management_subtype import \
    ManagementSubtype as IEEE802_11_ManagementSubtype
from pcapkit.const.ieee802_11.type import Type as IEEE802_11_Type

__all__ = [
    'IEEE802_11_Type', 'IEEE802_11_ManagementSubtype', 'IEEE802_11_ControlSubtype',
    'IEEE802_11_DataSubtype', 'IEEE802_11_ExtensionSubtype',
]
