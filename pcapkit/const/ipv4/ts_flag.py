# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""TS Flag"""

from aenum import IntEnum, extend_enum

__all__ = ['TSFlag']


class TSFlag(IntEnum):
    """[TSFlag] TS Flag"""

    Timestamp_Only = 0

    IP_with_Timestamp = 1

    Prespecified_IP_with_Timestamp = 3

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'TSFlag':
        """Backport support for original codes."""
        if isinstance(key, int):
            return TSFlag(key)
        if key not in TSFlag._member_map_:  # pylint: disable=no-member
            extend_enum(TSFlag, key, default)
        return TSFlag[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'TSFlag':
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0b0000 <= value <= 0b1111):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned_%d' % value, value)
        return cls(value)
