# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""ToS (DS Field) Precedence"""

from aenum import IntEnum, extend_enum

__all__ = ['ToSPrecedence']


class ToSPrecedence(IntEnum):
    """[ToSPrecedence] ToS (DS Field) Precedence"""

    _ignore_ = 'ToSPrecedence _'
    ToSPrecedence = vars()

    ToSPrecedence['Network_Control'] = 7

    ToSPrecedence['Internetwork_Control'] = 6

    ToSPrecedence['CRITIC_ECP'] = 5

    ToSPrecedence['Flash_Override'] = 4

    ToSPrecedence['Flash'] = 3

    ToSPrecedence['Immediate'] = 2

    ToSPrecedence['Priority'] = 1

    ToSPrecedence['Routine'] = 0

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ToSPrecedence(key)
        if key not in ToSPrecedence._member_map_:  # pylint: disable=no-member
            extend_enum(ToSPrecedence, key, default)
        return ToSPrecedence[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0b000 <= value <= 0b111):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
