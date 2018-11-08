# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class Reliability(IntEnum):
    """Enumeration class for Reliability."""
    _ignore_ = 'Reliability _'
    Reliability = vars()

    # TOS (DS Field) Reliability
    Reliability['NORMAL'] = 0
    Reliability['HIGH'] = 1

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Reliability(key)
        if key not in Reliability._member_map_:
            extend_enum(Reliability, key, default)
        return Reliability[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
