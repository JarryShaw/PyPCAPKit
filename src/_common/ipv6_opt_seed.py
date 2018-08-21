# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class SeedID(IntEnum):
    """Enumeration class for SeedID."""
    _ignore_ = 'SeedID _'
    SeedID = vars()

    # Seed-ID Types
    SeedID['IPV6 SOURCE ADDRESS'] = 0b00
    SeedID['16-BIT UNSIGNED INTEGER'] = 0b01
    SeedID['64-BIT UNSIGNED INTEGER'] = 0b10
    SeedID['128-BIT UNSIGNED INTEGER'] = 0b11

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return SeedID(key)
        if key not in SeedID._member_map_:
            extend_enum(SeedID, key, default)
        return SeedID[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0b00 <= value <= 0b11):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [0b%s]' % bin(value)[2:].zfill(2), value)
        return cls(value)
