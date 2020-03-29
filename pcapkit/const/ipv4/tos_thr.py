# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""ToS (DS Field) Throughput"""

from aenum import IntEnum, extend_enum

__all__ = ['ToS_THR']


class ToS_THR(IntEnum):
    """[ToS_THR] ToS (DS Field) Throughput"""

    _ignore_ = 'ToS_THR _'
    ToS_THR = vars()

    ToS_THR['NORMAL'] = 0

    ToS_THR['HIGH'] = 1

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ToS_THR(key)
        if key not in ToS_THR._member_map_:  # pylint: disable=no-member
            extend_enum(ToS_THR, key, default)
        return ToS_THR[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
