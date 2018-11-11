# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class Checksum(IntEnum):
    """Enumeration class for Checksum."""
    _ignore_ = 'Checksum _'
    Checksum = vars()

    # [RFC 1146]
    Checksum['TCP checksum'] = 0
    Checksum["8-bit Fletcher's algorithm"] = 1
    Checksum["16-bit Fletcher's algorithm"] = 2
    Checksum['Redundant Checksum Avoidance'] = 3

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Checksum(key)
        if key not in Checksum._member_map_:
            extend_enum(Checksum, key, default)
        return Checksum[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
        super()._missing_(value)
