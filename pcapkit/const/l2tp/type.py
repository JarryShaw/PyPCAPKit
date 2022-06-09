# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""L2TP Type
===============

This module contains the constant enumeration for **L2TP Type**,
which is automatically generated from :class:`pcapkit.vendor.l2tp.type.Type`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Type']


class Type(IntEnum):
    """[Type] L2TP Type"""

    Control = 0

    Data = 1

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'Type':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        """
        if isinstance(key, int):
            return Type(key)
        if key not in Type._member_map_:  # pylint: disable=no-member
            extend_enum(Type, key, default)
        return Type[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'Type':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned_%d' % value, value)
        return cls(value)
