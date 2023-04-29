# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""QS Functions
==================

.. module:: pcapkit.const.ipv4.qs_function

This module contains the constant enumeration for **QS Functions**,
which is automatically generated from :class:`pcapkit.vendor.ipv4.qs_function.QSFunction`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['QSFunction']


class QSFunction(IntEnum):
    """[QSFunction] QS Functions"""

    Quick_Start_Request = 0

    Report_of_Approved_Rate = 8

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'QSFunction':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return QSFunction(key)
        if key not in QSFunction._member_map_:  # pylint: disable=no-member
            return extend_enum(QSFunction, key, default)
        return QSFunction[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'QSFunction':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 8):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)
