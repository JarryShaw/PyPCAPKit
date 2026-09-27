# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""ToS (DS Field) Reliability
================================

.. module:: pcapkit.const.ipv4.tos_rel

This module contains the constant enumeration for **ToS (DS Field) Reliability**,
which is automatically generated from :class:`pcapkit.vendor.ipv4.tos_rel.ToSReliability`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['ToSReliability']


class ToSReliability(EnumRegistry, IntEnum):
    """[ToSReliability] ToS (DS Field) Reliability"""

    NORMAL = 0

    HIGH = 1

    @classmethod
    def _missing_(cls, value: 'int') -> 'ToSReliability':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')
