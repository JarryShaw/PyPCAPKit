# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""IPv4 Home Address Reply Status Codes
==========================================

.. module:: pcapkit.const.mh.home_address_reply

This module contains the constant enumeration for **IPv4 Home Address Reply Status Codes**,
which is automatically generated from :class:`pcapkit.vendor.mh.home_address_reply.HomeAddressReply`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['HomeAddressReply']


class HomeAddressReply(EnumRegistry, IntEnum):
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
            return cls._unregistered_member(value, 'Unassigned')
        if 133 <= value <= 255:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
