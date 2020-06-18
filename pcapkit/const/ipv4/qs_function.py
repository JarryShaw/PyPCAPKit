# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""QS Functions"""

from aenum import IntEnum, extend_enum

__all__ = ['QSFunction']


class QSFunction(IntEnum):
    """[QSFunction] QS Functions"""

    Quick_Start_Request = 0

    Report_of_Approved_Rate = 8

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return QSFunction(key)
        if key not in QSFunction._member_map_:  # pylint: disable=no-member
            extend_enum(QSFunction, key, default)
        return QSFunction[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 8):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned_%d' % value, value)
        return cls(value)
