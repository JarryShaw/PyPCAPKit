# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""IPv4 Home Address Reply Status Codes
==========================================

.. module:: pcapkit.const.mh.home_address_reply

This module contains the constant enumeration for **IPv4 Home Address Reply Status Codes**,
which is automatically generated from :class:`pcapkit.vendor.mh.home_address_reply.HomeAddressReply`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['HomeAddressReply']


class HomeAddressReply(IntEnum):
    """[HomeAddressReply] IPv4 Home Address Reply Status Codes"""

    #: Success [:rfc:`5844`]
    Success = 0

    #: Failure, Reason Unspecified [:rfc:`5844`]
    Failure_Reason_Unspecified = 128

    #: Administratively prohibited [:rfc:`5844`]
    Administratively_prohibited = 129

    #: Incorrect IPv4 home address [:rfc:`5844`]
    Incorrect_IPv4_home_address = 130

    #: Invalid IPv4 address [:rfc:`5844`]
    Invalid_IPv4_address = 131

    #: Dynamic IPv4 home address assignment not available [:rfc:`5844`]
    Dynamic_IPv4_home_address_assignment_not_available = 132

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'HomeAddressReply':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return HomeAddressReply(key)
        if key not in HomeAddressReply._member_map_:  # pylint: disable=no-member
            return extend_enum(HomeAddressReply, key, default)
        return HomeAddressReply[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'HomeAddressReply':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 1 <= value <= 127:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 133 <= value <= 255:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
