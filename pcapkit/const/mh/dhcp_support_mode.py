# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""IPv4 DHCP Support Mode Flags
==================================

.. module:: pcapkit.const.mh.dhcp_support_mode

This module contains the constant enumeration for **IPv4 DHCP Support Mode Flags**,
which is automatically generated from :class:`pcapkit.vendor.mh.dhcp_support_mode.DHCPSupportMode`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['DHCPSupportMode']


class DHCPSupportMode(IntEnum):
    """[DHCPSupportMode] IPv4 DHCP Support Mode Flags"""

    #: Unassigned
    Unassigned_0x0 = 0x0

    #: (S) flag [:rfc:`5844`]
    S_flag = 0x1

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'DHCPSupportMode':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return DHCPSupportMode(key)
        if key not in DHCPSupportMode._member_map_:  # pylint: disable=no-member
            return extend_enum(DHCPSupportMode, key, default)
        return DHCPSupportMode[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'DHCPSupportMode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)
