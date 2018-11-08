# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class ProtAuth(IntEnum):
    """Enumeration class for ProtAuth."""
    _ignore_ = 'ProtAuth _'
    ProtAuth = vars()

    # Protection Authority Bit Assignments
    ProtAuth['GENSER'] = 0
    ProtAuth['SIOP-ESI'] = 1
    ProtAuth['SCI'] = 2
    ProtAuth['NSA'] = 3
    ProtAuth['DOE'] = 4
    ProtAuth['Unassigned [5]'] = 5
    ProtAuth['Unassigned [6]'] = 6
    ProtAuth['Field Termination Indicator'] = 7

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ProtAuth(key)
        if key not in ProtAuth._member_map_:
            extend_enum(ProtAuth, key, default)
        return ProtAuth[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 7):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
