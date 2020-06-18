# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""ToS (DS Field) Reliability"""

from aenum import IntEnum, extend_enum

__all__ = ['ToSReliability']


class ToSReliability(IntEnum):
    """[ToSReliability] ToS (DS Field) Reliability"""

    NORMAL = 0

    HIGH = 1

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ToSReliability(key)
        if key not in ToSReliability._member_map_:  # pylint: disable=no-member
            extend_enum(ToSReliability, key, default)
        return ToSReliability[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned_%d' % value, value)
        return cls(value)
