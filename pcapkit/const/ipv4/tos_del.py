# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""ToS (DS Field) Delay
==========================

.. module:: pcapkit.const.ipv4.tos_del

This module contains the constant enumeration for **ToS (DS Field) Delay**,
which is automatically generated from :class:`pcapkit.vendor.ipv4.tos_del.ToSDelay`.

"""

from aenum import IntEnum, extend_enum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['ToSDelay']


class ToSDelay(EnumRegistry, IntEnum):
    """[ToSDelay] ToS (DS Field) Delay"""

    NORMAL = 0

    LOW = 1

    @classmethod
    def _missing_(cls, value: 'int') -> 'ToSDelay':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)
