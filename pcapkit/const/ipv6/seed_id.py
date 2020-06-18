# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Seed-ID Types"""

from aenum import IntEnum, extend_enum

__all__ = ['SeedID']


class SeedID(IntEnum):
    """[SeedID] Seed-ID Types"""

    IPV6_SOURCE_ADDRESS = 0b00

    SEEDID_16_BIT_UNSIGNED_INTEGER = 0b01

    SEEDID_64_BIT_UNSIGNED_INTEGER = 0b10

    SEEDID_128_BIT_UNSIGNED_INTEGER = 0b11

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return SeedID(key)
        if key not in SeedID._member_map_:  # pylint: disable=no-member
            extend_enum(SeedID, key, default)
        return SeedID[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0b00 <= value <= 0b11):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned_0b%s' % bin(value)[2:].zfill(2), value)
        return cls(value)
