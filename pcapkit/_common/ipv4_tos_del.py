# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class Delay(IntEnum):
    """Enumeration class for Delay."""
    _ignore_ = 'Delay _'
    Delay = vars()

    # TOS (DS Field) Delay
    Delay['NORMAL'] = 0
    Delay['LOW'] = 1

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Delay(key)
        if key not in Delay._member_map_:
            extend_enum(Delay, key, default)
        return Delay[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
