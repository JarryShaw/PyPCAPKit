# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Multipath TCP options
===========================

This module contains the constant enumeration for **Multipath TCP options**,
which is automatically generated from :class:`pcapkit.vendor.tcp.mp_tcp_option.MPTCPOption`.

"""

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
    def get(key: 'int | str', default: 'int' = -1) -> 'MPTCPOption':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        """
        if isinstance(key, int):
            return MPTCPOption(key)
        if key not in MPTCPOption._member_map_:  # pylint: disable=no-member
            extend_enum(MPTCPOption, key, default)
        return MPTCPOption[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'MPTCPOption':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned_%d' % value, value)
        return cls(value)
