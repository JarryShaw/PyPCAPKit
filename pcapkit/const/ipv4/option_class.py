# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Option Classes
====================

.. module:: pcapkit.const.ipv4.option_class

This module contains the constant enumeration for **Option Classes**,
which is automatically generated from :class:`pcapkit.vendor.ipv4.option_class.OptionClass`.

"""

from aenum import IntEnum, extend_enum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['OptionClass']


class OptionClass(EnumRegistry, IntEnum):
    """[OptionClass] Option Classes"""

    control = 0

    reserved_for_future_use_1 = 1

    debugging_and_measurement = 2

    reserved_for_future_use_3 = 3

    @classmethod
    def _missing_(cls, value: 'int') -> 'OptionClass':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 3):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)
