# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""ToS (DS Field) Throughput
===============================

This module contains the constant enumeration for **ToS (DS Field) Throughput**,
which is automatically generated from :class:`pcapkit.vendor.ipv4.tos_thr.ToSThroughput`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['ToSThroughput']


class ToSThroughput(IntEnum):
    """[ToSThroughput] ToS (DS Field) Throughput"""

    NORMAL = 0

    HIGH = 1

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'ToSThroughput':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        """
        if isinstance(key, int):
            return ToSThroughput(key)
        if key not in ToSThroughput._member_map_:  # pylint: disable=no-member
            extend_enum(ToSThroughput, key, default)
        return ToSThroughput[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'ToSThroughput':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned_%d' % value, value)
        return cls(value)
