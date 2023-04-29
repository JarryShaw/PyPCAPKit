# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""ToS (DS Field) Precedence
===============================

.. module:: pcapkit.const.ipv4.tos_pre

This module contains the constant enumeration for **ToS (DS Field) Precedence**,
which is automatically generated from :class:`pcapkit.vendor.ipv4.tos_pre.ToSPrecedence`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['ToSPrecedence']


class ToSPrecedence(IntEnum):
    """[ToSPrecedence] ToS (DS Field) Precedence"""

    Network_Control = 7

    Internetwork_Control = 6

    CRITIC_ECP = 5

    Flash_Override = 4

    Flash = 3

    Immediate = 2

    Priority = 1

    Routine = 0

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'ToSPrecedence':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return ToSPrecedence(key)
        if key not in ToSPrecedence._member_map_:  # pylint: disable=no-member
            return extend_enum(ToSPrecedence, key, default)
        return ToSPrecedence[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'ToSPrecedence':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0b000 <= value <= 0b111):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)
