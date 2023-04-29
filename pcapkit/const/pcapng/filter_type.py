# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Filter Types
==================

.. module:: pcapkit.const.pcapng.filter_type

This module contains the constant enumeration for **Filter Types**,
which is automatically generated from :class:`pcapkit.vendor.pcapng.filter_type.FilterType`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['FilterType']


class FilterType(IntEnum):
    """[FilterType] Filter Types"""


    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'FilterType':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return FilterType(key)
        if key not in FilterType._member_map_:  # pylint: disable=no-member
            return extend_enum(FilterType, key, default)
        return FilterType[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'FilterType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x00<= value <= 0xFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)
