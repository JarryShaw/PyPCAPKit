# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class TOS_REL(IntEnum):
    """Enumeration class for TOS_REL."""
    _ignore_ = 'TOS_REL _'
    TOS_REL = vars()

    # TOS (DS Field) Reliability
    TOS_REL['NORMAL'] = 0
    TOS_REL['HIGH'] = 1

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return TOS_REL(key)
        if key not in TOS_REL._member_map_:
            extend_enum(TOS_REL, key, default)
        return TOS_REL[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
        super()._missing_(value)
