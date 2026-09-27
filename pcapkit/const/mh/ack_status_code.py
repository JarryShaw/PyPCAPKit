# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Pseudo Home Address Acknowledgement Status Codes
======================================================

.. module:: pcapkit.const.mh.ack_status_code

This module contains the constant enumeration for **Pseudo Home Address Acknowledgement Status Codes**,
which is automatically generated from :class:`pcapkit.vendor.mh.ack_status_code.ACKStatusCode`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['ACKStatusCode']


class ACKStatusCode(EnumRegistry, IntEnum):
    """[ACKStatusCode] Pseudo Home Address Acknowledgement Status Codes"""

    #: Success [:rfc:`5726`]
    Success = 0

    #: Failure, reason unspecified [:rfc:`5726`]
    Failure_reason_unspecified = 128

    #: Administratively prohibited [:rfc:`5726`]
    Administratively_prohibited = 129

    #: Incorrect pseudo home address [:rfc:`5726`]
    Incorrect_pseudo_home_address = 130

    #: Invalid pseudo home address [:rfc:`5726`]
    Invalid_pseudo_home_address = 131

    #: Dynamic pseudo home address assignment not available [:rfc:`5726`]
    Dynamic_pseudo_home_address_assignment_not_available = 132

    @classmethod
    def _missing_(cls, value: 'int') -> 'ACKStatusCode':
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
