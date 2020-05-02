# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Option Classes"""

from aenum import IntEnum, extend_enum

__all__ = ['OptionClass']


class OptionClass(IntEnum):
    """[OptionClass] Option Classes"""

    _ignore_ = 'OptionClass _'
    OptionClass = vars()

    OptionClass['Control'] = 0

    OptionClass['Reserved_For_Future_Use_1'] = 1

    OptionClass['Debugging_And_Measurement'] = 2

    OptionClass['Reserved_For_Future_Use_3'] = 3

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return OptionClass(key)
        if key not in OptionClass._member_map_:  # pylint: disable=no-member
            extend_enum(OptionClass, key, default)
        return OptionClass[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 3):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
