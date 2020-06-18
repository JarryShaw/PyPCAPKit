# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""TCP Checksum [:rfc:`1146`]"""

from aenum import IntEnum, extend_enum

__all__ = ['Checksum']


class Checksum(IntEnum):
    """[Checksum] TCP Checksum [:rfc:`1146`]"""

    TCP_checksum = 0

    Checksum_8_bit_Fletcher_s_algorithm = 1

    Checksum_16_bit_Fletcher_s_algorithm = 2

    Redundant_Checksum_Avoidance = 3

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Checksum(key)
        if key not in Checksum._member_map_:  # pylint: disable=no-member
            extend_enum(Checksum, key, default)
        return Checksum[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned_%d' % value, value)
        return cls(value)
