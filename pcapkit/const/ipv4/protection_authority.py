# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Protection Authority Bit Assignments
==========================================

.. module:: pcapkit.const.ipv4.protection_authority

This module contains the constant enumeration for **Protection Authority Bit Assignments**,
which is automatically generated from :class:`pcapkit.vendor.ipv4.protection_authority.ProtectionAuthority`.

"""

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
    def get(key: 'int | str', default: 'int' = -1) -> 'ProtectionAuthority':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return ProtectionAuthority(key)
        if key not in ProtectionAuthority._member_map_:  # pylint: disable=no-member
            return extend_enum(ProtectionAuthority, key, default)
        return ProtectionAuthority[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'ProtectionAuthority':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and value >= 0):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)
