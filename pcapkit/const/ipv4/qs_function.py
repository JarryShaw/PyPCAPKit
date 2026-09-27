# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""QS Functions
==================

.. module:: pcapkit.const.ipv4.qs_function

This module contains the constant enumeration for **QS Functions**,
which is automatically generated from :class:`pcapkit.vendor.ipv4.qs_function.QSFunction`.

"""

from aenum import IntEnum, extend_enum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['QSFunction']


class QSFunction(EnumRegistry, IntEnum):
    """[QSFunction] QS Functions"""

    Quick_Start_Request = 0

    Report_of_Approved_Rate = 8

    @classmethod
    def _missing_(cls, value: 'int') -> 'QSFunction':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 8):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)
