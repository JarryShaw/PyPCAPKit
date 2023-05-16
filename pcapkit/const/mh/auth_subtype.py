# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Subtype Field of the MN-HA and MN-AAA Authentication Mobility Options
===========================================================================

.. module:: pcapkit.const.mh.auth_subtype

This module contains the constant enumeration for **Subtype Field of the MN-HA and MN-AAA Authentication Mobility Options**,
which is automatically generated from :class:`pcapkit.vendor.mh.auth_subtype.AuthSubtype`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['AuthSubtype']


class AuthSubtype(IntEnum):
    """[AuthSubtype] Subtype Field of the MN-HA and MN-AAA Authentication Mobility Options"""

    #: MN-HA authentication mobility option [:rfc:`4285`]
    MN_HA = 1

    #: MN-AAA authentication mobility option [:rfc:`4285`]
    MN_AAA = 2

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'AuthSubtype':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return AuthSubtype(key)
        if key not in AuthSubtype._member_map_:  # pylint: disable=no-member
            return extend_enum(AuthSubtype, key, default)
        return AuthSubtype[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'AuthSubtype':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)
