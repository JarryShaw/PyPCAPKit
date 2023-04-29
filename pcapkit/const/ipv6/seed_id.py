# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Seed-ID Types
===================

.. module:: pcapkit.const.ipv6.seed_id

This module contains the constant enumeration for **Seed-ID Types**,
which is automatically generated from :class:`pcapkit.vendor.ipv6.seed_id.SeedID`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['SeedID']


class SeedID(IntEnum):
    """[SeedID] Seed-ID Types"""

    IPV6_SOURCE_ADDRESS = 0b00

    SEEDID_16_BIT_UNSIGNED_INTEGER = 0b01

    SEEDID_64_BIT_UNSIGNED_INTEGER = 0b10

    SEEDID_128_BIT_UNSIGNED_INTEGER = 0b11

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'SeedID':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return SeedID(key)
        if key not in SeedID._member_map_:  # pylint: disable=no-member
            return extend_enum(SeedID, key, default)
        return SeedID[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'SeedID':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0b00 <= value <= 0b11):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_0b%s' % bin(value)[2:].zfill(2), value)
