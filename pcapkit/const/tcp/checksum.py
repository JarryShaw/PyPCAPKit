# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""TCP Checksum [:rfc:`1146`]"""

from aenum import IntEnum, extend_enum

__all__ = ['Checksum']


class Checksum(IntEnum):
    """[Checksum] TCP Checksum [:rfc:`1146`]"""

    _ignore_ = 'Checksum _'
    Checksum = vars()

    Checksum['TCP_Checksum'] = 0

    Checksum['8_bit_Fletcher_s_Algorithm'] = 1

    Checksum['16_bit_Fletcher_s_Algorithm'] = 2

    Checksum['Redundant_Checksum_Avoidance'] = 3

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
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
