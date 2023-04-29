# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Option Classes
====================

.. module:: pcapkit.const.ipv4.option_class

This module contains the constant enumeration for **Option Classes**,
which is automatically generated from :class:`pcapkit.vendor.ipv4.option_class.OptionClass`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['OptionClass']


class OptionClass(IntEnum):
    """[OptionClass] Option Classes"""

    control = 0

    reserved_for_future_use_1 = 1

    debugging_and_measurement = 2

    reserved_for_future_use_3 = 3

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'OptionClass':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return OptionClass(key)
        if key not in OptionClass._member_map_:  # pylint: disable=no-member
            return extend_enum(OptionClass, key, default)
        return OptionClass[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'OptionClass':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 3):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)
