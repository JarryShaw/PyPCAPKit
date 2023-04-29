# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""ToS (DS Field) Delay
==========================

.. module:: pcapkit.const.ipv4.tos_del

This module contains the constant enumeration for **ToS (DS Field) Delay**,
which is automatically generated from :class:`pcapkit.vendor.ipv4.tos_del.ToSDelay`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['ToSDelay']


class ToSDelay(IntEnum):
    """[ToSDelay] ToS (DS Field) Delay"""

    NORMAL = 0

    LOW = 1

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'ToSDelay':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return ToSDelay(key)
        if key not in ToSDelay._member_map_:  # pylint: disable=no-member
            return extend_enum(ToSDelay, key, default)
        return ToSDelay[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'ToSDelay':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)
