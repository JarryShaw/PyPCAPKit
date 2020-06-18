# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Multipath TCP options [:rfc:`6824`]"""

from aenum import IntEnum, extend_enum

__all__ = ['MPTCPOption']


class MPTCPOption(IntEnum):
    """[MPTCPOption] Multipath TCP options [:rfc:`6824`]"""

    MP_CAPABLE = 0

    MP_JOIN = 1

    DSS = 2

    ADD_ADDR = 3

    REMOVE_ADDR = 4

    MP_PRIO = 5

    MP_FAIL = 6

    MP_FASTCLOSE = 7

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return MPTCPOption(key)
        if key not in MPTCPOption._member_map_:  # pylint: disable=no-member
            extend_enum(MPTCPOption, key, default)
        return MPTCPOption[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned_%d' % value, value)
        return cls(value)
