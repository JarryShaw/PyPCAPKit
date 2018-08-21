# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class Relibility(IntEnum):
    """Enumeration class for Relibility."""
    _ignore_ = 'Relibility _'
    Relibility = vars()

    # TOS (DS Field) Relibility
    Relibility['NORMAL'] = 0
    Relibility['HIGH'] = 1

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Relibility(key)
        if key not in Relibility._member_map_:
            extend_enum(Relibility, key, default)
        return Relibility[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
