# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Filter Types
==================

.. module:: pcapkit.const.pcapng.filter_type

This module contains the constant enumeration for **Filter Types**,
which is automatically generated from :class:`pcapkit.vendor.pcapng.filter_type.FilterType`.

"""

from aenum import IntEnum, extend_enum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['FilterType']


class FilterType(EnumRegistry, IntEnum):
    """[FilterType] Filter Types"""


    @classmethod
    def _missing_(cls, value: 'int') -> 'FilterType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x00<= value <= 0xFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)
