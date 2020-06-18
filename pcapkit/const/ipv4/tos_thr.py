# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""ToS (DS Field) Throughput"""

from aenum import IntEnum, extend_enum

__all__ = ['ToSThroughput']


class ToSThroughput(IntEnum):
    """[ToSThroughput] ToS (DS Field) Throughput"""

    NORMAL = 0

    HIGH = 1

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ToSThroughput(key)
        if key not in ToSThroughput._member_map_:  # pylint: disable=no-member
            extend_enum(ToSThroughput, key, default)
        return ToSThroughput[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned_%d' % value, value)
        return cls(value)
