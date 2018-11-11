# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class TOS_DEL(IntEnum):
    """Enumeration class for TOS_DEL."""
    _ignore_ = 'TOS_DEL _'
    TOS_DEL = vars()

    # TOS (DS Field) Delay
    TOS_DEL['NORMAL'] = 0
    TOS_DEL['LOW'] = 1

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return TOS_DEL(key)
        if key not in TOS_DEL._member_map_:
            extend_enum(TOS_DEL, key, default)
        return TOS_DEL[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
        super()._missing_(value)
