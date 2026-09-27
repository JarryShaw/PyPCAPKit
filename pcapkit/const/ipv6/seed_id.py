# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Seed-ID Types
===================

.. module:: pcapkit.const.ipv6.seed_id

This module contains the constant enumeration for **Seed-ID Types**,
which is automatically generated from :class:`pcapkit.vendor.ipv6.seed_id.SeedID`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['SeedID']


class SeedID(EnumRegistry, IntEnum):
    """[SeedID] Seed-ID Types"""

    IPV6_SOURCE_ADDRESS = 0b00

    SEEDID_16_BIT_UNSIGNED_INTEGER = 0b01

    SEEDID_64_BIT_UNSIGNED_INTEGER = 0b10

    SEEDID_128_BIT_UNSIGNED_INTEGER = 0b11

    @classmethod
    def _missing_(cls, value: 'int') -> 'SeedID':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0b00 <= value <= 0b11):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')
