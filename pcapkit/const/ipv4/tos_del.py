# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""ToS (DS Field) Delay"""

from aenum import IntEnum, extend_enum

__all__ = ['ToS_DEL']


class ToS_DEL(IntEnum):
    """[ToS_DEL] ToS (DS Field) Delay"""

    _ignore_ = 'ToS_DEL _'
    ToS_DEL = vars()

    ToS_DEL['NORMAL'] = 0

    ToS_DEL['LOW'] = 1

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ToS_DEL(key)
        if key not in ToS_DEL._member_map_:  # pylint: disable=no-member
            extend_enum(ToS_DEL, key, default)
        return ToS_DEL[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
