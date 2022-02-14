# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Option Classes"""

from aenum import IntEnum, extend_enum

__all__ = ['OptionClass']


class OptionClass(IntEnum):
    """[OptionClass] Option Classes"""

    control = 0

    reserved_for_future_use_1 = 1

    debugging_and_measurement = 2

    reserved_for_future_use_3 = 3

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'OptionClass':
        """Backport support for original codes."""
        if isinstance(key, int):
            return OptionClass(key)
        if key not in OptionClass._member_map_:  # pylint: disable=no-member
            extend_enum(OptionClass, key, default)
        return OptionClass[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'OptionClass':
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 3):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned_%d' % value, value)
        return cls(value)
