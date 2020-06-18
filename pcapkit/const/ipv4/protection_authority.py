# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Protection Authority Bit Assignments"""

from aenum import IntEnum, extend_enum

__all__ = ['ProtectionAuthority']


class ProtectionAuthority(IntEnum):
    """[ProtectionAuthority] Protection Authority Bit Assignments"""

    GENSER = 0

    SIOP_ESI = 1

    SCI = 2

    NSA = 3

    DOE = 4

    Unassigned_5 = 5

    Unassigned_6 = 6

    Field_Termination_Indicator = 7

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ProtectionAuthority(key)
        if key not in ProtectionAuthority._member_map_:  # pylint: disable=no-member
            extend_enum(ProtectionAuthority, key, default)
        return ProtectionAuthority[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 7):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned_%d' % value, value)
        return cls(value)
