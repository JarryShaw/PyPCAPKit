# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""TS Flag
=============

.. module:: pcapkit.const.ipv4.ts_flag

This module contains the constant enumeration for **TS Flag**,
which is automatically generated from :class:`pcapkit.vendor.ipv4.ts_flag.TSFlag`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['TSFlag']


class TSFlag(EnumRegistry, IntEnum):
    """[TSFlag] TS Flag"""

    Timestamp_Only = 0

    IP_with_Timestamp = 1

    Prespecified_IP_with_Timestamp = 3

    @classmethod
    def _missing_(cls, value: 'int') -> 'TSFlag':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0b0000 <= value <= 0b1111):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')
