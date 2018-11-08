# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class Precedence(IntEnum):
    """Enumeration class for Precedence."""
    _ignore_ = 'Precedence _'
    Precedence = vars()

    # TOS (DS Field) Precedence
    Precedence['Network Control'] = 7
    Precedence['Internetwork Control'] = 6
    Precedence['CRITIC/ECP'] = 5
    Precedence['Flash Override'] = 4
    Precedence['Flash'] = 3
    Precedence['Immediate'] = 2
    Precedence['Priority'] = 1
    Precedence['Routine'] = 0

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Precedence(key)
        if key not in Precedence._member_map_:
            extend_enum(Precedence, key, default)
        return Precedence[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0b000 <= value <= 0b111):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
