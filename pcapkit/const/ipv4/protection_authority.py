# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Protection Authority Bit Assignments
==========================================

.. module:: pcapkit.const.ipv4.protection_authority

This module contains the constant enumeration for **Protection Authority Bit Assignments**,
which is automatically generated from :class:`pcapkit.vendor.ipv4.protection_authority.ProtectionAuthority`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['ProtectionAuthority']


class ProtectionAuthority(EnumRegistry, IntEnum):
    """[ProtectionAuthority] Protection Authority Bit Assignments"""

    GENSER = 0

    SIOP_ESI = 1

    SCI = 2

    NSA = 3

    DOE = 4

    Unassigned_5 = 5

    Unassigned_6 = 6

    Field_Termination_Indicator = 7

    @classmethod
    def _missing_(cls, value: 'int') -> 'ProtectionAuthority':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and value >= 0):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')
