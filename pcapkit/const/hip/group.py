# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Group IDs
===============

.. module:: pcapkit.const.hip.group

This module contains the constant enumeration for **Group IDs**,
which is automatically generated from :class:`pcapkit.vendor.hip.group.Group`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Group']


class Group(IntEnum):
    """[Group] Group IDs"""

    #: Reserved [:rfc:`7401`]
    Reserved_0 = 0

    #: 384-bit group (DEPRECATED) [:rfc:`5201`]
    Group_384_bit_group = 1

    #: OAKLEY well known group 1 (DEPRECATED) [:rfc:`5201`]
    OAKLEY_well_known_group_1 = 2

    #: 1536-bit MODP group [:rfc:`7401`]
    Group_1536_bit_MODP_group = 3

    #: 3072-bit MODP group [:rfc:`7401`]
    Group_3072_bit_MODP_group = 4

    #: 6144-bit MODP group (DEPRECATED) [:rfc:`5201`]
    Group_6144_bit_MODP_group = 5

    #: 8192-bit MODP group (DEPRECATED) [:rfc:`5201`]
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
    def get(key: 'int | str', default: 'int' = -1) -> 'Group':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return Group(key)
        if key not in Group._member_map_:  # pylint: disable=no-member
            return extend_enum(Group, key, default)
        return Group[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'Group':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 12 <= value <= 255:
            # Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
