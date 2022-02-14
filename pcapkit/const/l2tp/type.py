# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""L2TP Type"""

from aenum import IntEnum, extend_enum

__all__ = ['Type']


class Type(IntEnum):
    """[Type] L2TP Type"""

    Control = 0

    Data = 1

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'Type':
        """Backport support for original codes."""
        if isinstance(key, int):
            return Type(key)
        if key not in Type._member_map_:  # pylint: disable=no-member
            extend_enum(Type, key, default)
        return Type[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'Type':
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned_%d' % value, value)
        return cls(value)
