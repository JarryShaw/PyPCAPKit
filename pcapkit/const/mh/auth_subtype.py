# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Subtype Field of the MN-HA and MN-AAA Authentication Mobility Options
===========================================================================

.. module:: pcapkit.const.mh.auth_subtype

This module contains the constant enumeration for **Subtype Field of the MN-HA and MN-AAA Authentication Mobility Options**,
which is automatically generated from :class:`pcapkit.vendor.mh.auth_subtype.AuthSubtype`.

"""

from aenum import IntEnum, extend_enum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['AuthSubtype']


class AuthSubtype(EnumRegistry, IntEnum):
    """[AuthSubtype] Subtype Field of the MN-HA and MN-AAA Authentication Mobility Options"""

    #: MN-HA authentication mobility option [:rfc:`4285`]
    MN_HA = 1

    #: MN-AAA authentication mobility option [:rfc:`4285`]
    MN_AAA = 2

    @classmethod
    def _missing_(cls, value: 'int') -> 'AuthSubtype':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)
