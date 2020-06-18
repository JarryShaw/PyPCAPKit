# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Group IDs"""

from aenum import IntEnum, extend_enum

__all__ = ['Group']


class Group(IntEnum):
    """[Group] Group IDs"""

    #: Reserved [:rfc:`7401`]
    Reserved = 0

    #: 384-bit group [:rfc:`5201`] DEPRECATED
    Group_384_bit_group = 1

    #: OAKLEY well known group 1 [:rfc:`5201`] DEPRECATED
    OAKLEY_well_known_group_1 = 2

    #: 1536-bit MODP group [:rfc:`7401`]
    Group_1536_bit_MODP_group = 3

    #: 3072-bit MODP group [:rfc:`7401`]
    Group_3072_bit_MODP_group = 4

    #: 6144-bit MODP group [:rfc:`5201`] DEPRECATED
    Group_6144_bit_MODP_group = 5

    #: 8192-bit MODP group [:rfc:`5201`] DEPRECATED
    Group_8192_bit_MODP_group = 6

    #: NIST P-256 [:rfc:`7401`]
    NIST_P_256 = 7

    #: NIST P-384 [:rfc:`7401`]
    NIST_P_384 = 8

    #: NIST P-521 [:rfc:`7401`]
    NIST_P_521 = 9

    #: SECP160R1 [:rfc:`7401`]
    SECP160R1 = 10

    #: 2048-bit MODP group [:rfc:`7401`]
    Group_2048_bit_MODP_group = 11

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Group(key)
        if key not in Group._member_map_:  # pylint: disable=no-member
            extend_enum(Group, key, default)
        return Group[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 12 <= value <= 255:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        return super()._missing_(value)
