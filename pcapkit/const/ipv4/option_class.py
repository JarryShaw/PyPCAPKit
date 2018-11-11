# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class OptionClass(IntEnum):
    """Enumeration class for OptionClass."""
    _ignore_ = 'OptionClass _'
    OptionClass = vars()

    # Option Classes
    OptionClass['control'] = 0
    OptionClass['reserved for future use [1]'] = 1
    OptionClass['debugging and measurement'] = 2
    OptionClass['reserved for future use [3]'] = 3

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return OptionClass(key)
        if key not in OptionClass._member_map_:
            extend_enum(OptionClass, key, default)
        return OptionClass[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 3):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
        super()._missing_(value)
