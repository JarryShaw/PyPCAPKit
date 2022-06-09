# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""ToS (DS Field) Reliability
================================

This module contains the constant enumeration for **ToS (DS Field) Reliability**,
which is automatically generated from :class:`pcapkit.vendor.ipv4.tos_rel.ToSReliability`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['ToSReliability']


class ToSReliability(IntEnum):
    """[ToSReliability] ToS (DS Field) Reliability"""

    NORMAL = 0

    HIGH = 1

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'ToSReliability':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        """
        if isinstance(key, int):
            return ToSReliability(key)
        if key not in ToSReliability._member_map_:  # pylint: disable=no-member
            extend_enum(ToSReliability, key, default)
        return ToSReliability[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'ToSReliability':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned_%d' % value, value)
        return cls(value)
