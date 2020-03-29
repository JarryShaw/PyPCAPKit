# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""ToS (DS Field) Reliability"""

from aenum import IntEnum, extend_enum

__all__ = ['ToS_REL']


class ToS_REL(IntEnum):
    """[ToS_REL] ToS (DS Field) Reliability"""

    _ignore_ = 'ToS_REL _'
    ToS_REL = vars()

    ToS_REL['NORMAL'] = 0

    ToS_REL['HIGH'] = 1

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ToS_REL(key)
        if key not in ToS_REL._member_map_:  # pylint: disable=no-member
            extend_enum(ToS_REL, key, default)
        return ToS_REL[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
