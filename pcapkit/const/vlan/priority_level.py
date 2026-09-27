# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Priority levels defined in IEEE 802.1p
============================================

.. module:: pcapkit.const.vlan.priority_level

This module contains the constant enumeration for **Priority levels defined in IEEE 802.1p**,
which is automatically generated from :class:`pcapkit.vendor.vlan.priority_level.PriorityLevel`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['PriorityLevel']


class PriorityLevel(EnumRegistry, IntEnum):
    """[PriorityLevel] Priority levels defined in IEEE 802.1p"""

    #: Background (lowest)
    BK = 0b001

    #: Best effort (default)
    BE = 0b000

    #: Excellent effort
    EE = 0b010

    #: Critical applications
    CA = 0b011

    #: Video, < 100 ms latency and jitter
    VI = 0b100

    #: Voice, < 10 ms latency and jitter
    VO = 0b101

    #: Internetwork control
    IC = 0b110

    #: Network control (highest)
    NC = 0b111

    @classmethod
    def _missing_(cls, value: 'int') -> 'PriorityLevel':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0b000 <= value <= 0b111):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')
