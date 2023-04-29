# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Priority levels defined in IEEE 802.1p
============================================

.. module:: pcapkit.const.vlan.priority_level

This module contains the constant enumeration for **Priority levels defined in IEEE 802.1p**,
which is automatically generated from :class:`pcapkit.vendor.vlan.priority_level.PriorityLevel`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['PriorityLevel']


class PriorityLevel(IntEnum):
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

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'PriorityLevel':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return PriorityLevel(key)
        if key not in PriorityLevel._member_map_:  # pylint: disable=no-member
            return extend_enum(PriorityLevel, key, default)
        return PriorityLevel[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'PriorityLevel':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0b000 <= value <= 0b111):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned [0b%s]' % bin(value)[2:].zfill(3), value)
