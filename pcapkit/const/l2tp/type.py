# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""L2TP Type
===============

.. module:: pcapkit.const.l2tp.type

This module contains the constant enumeration for **L2TP Type**,
which is automatically generated from :class:`pcapkit.vendor.l2tp.type.Type`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['Type']


class Type(EnumRegistry, IntEnum):
    """[Type] L2TP Type"""

    Control = 0

    Data = 1

    @classmethod
    def _missing_(cls, value: 'int') -> 'Type':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')
