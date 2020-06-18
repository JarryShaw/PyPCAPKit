# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""ToS (DS Field) Precedence"""

from aenum import IntEnum, extend_enum

__all__ = ['ToSPrecedence']


class ToSPrecedence(IntEnum):
    """[ToSPrecedence] ToS (DS Field) Precedence"""

    Network_Control = 7

    Internetwork_Control = 6

    CRITIC_ECP = 5

    Flash_Override = 4

    Flash = 3

    Immediate = 2

    Priority = 1

    Routine = 0

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
        extend_enum(cls, 'Unassigned_%d' % value, value)
        return cls(value)
