# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""ICMP Destination Unreachable Codes
========================================

.. module:: pcapkit.const.icmp.destination_unreachable_code

This module contains the constant enumeration for **ICMP Destination Unreachable Codes**,
which is automatically generated from :class:`pcapkit.vendor.icmp.destination_unreachable_code.DestinationUnreachableCode`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['DestinationUnreachableCode']


class DestinationUnreachableCode(EnumRegistry, IntEnum):
    """[DestinationUnreachableCode] ICMP Destination Unreachable Codes [:rfc:`792`]"""

    #: Net Unreachable [:rfc:`792`]
    Net_Unreachable = 0

    #: Host Unreachable [:rfc:`792`]
    Host_Unreachable = 1

    #: Protocol Unreachable [:rfc:`792`]
    Protocol_Unreachable = 2

    #: Port Unreachable [:rfc:`792`]
    Port_Unreachable = 3

    #: Fragmentation Needed and Don't         Fragment was Set [:rfc:`792`]
    Fragmentation_Needed_and_Don_t_Fragment_was_Set = 4

    #: Source Route Failed [:rfc:`792`]
    Source_Route_Failed = 5

    #: Destination Network Unknown [:rfc:`1122`]
    Destination_Network_Unknown = 6

    #: Destination Host Unknown [:rfc:`1122`]
    Destination_Host_Unknown = 7

    #: Source Host Isolated [:rfc:`1122`]
    Source_Host_Isolated = 8

    #: Communication with Destination         Network is Administratively
    #: Prohibited [:rfc:`1122`]
    Communication_with_Destination_Network_is_Administratively_Prohibited = 9

    #: Communication with Destination Host is         Administratively Prohibited
    #: [:rfc:`1122`]
    Communication_with_Destination_Host_is_Administratively_Prohibited = 10

    #: Destination Network Unreachable for Type         of Service [:rfc:`1122`]
    Destination_Network_Unreachable_for_Type_of_Service = 11

    #: Destination Host Unreachable for Type of         Service [:rfc:`1122`]
    Destination_Host_Unreachable_for_Type_of_Service = 12

    #: Communication Administratively Prohibited [:rfc:`1812`]
    Communication_Administratively_Prohibited = 13

    #: Host Precedence Violation [:rfc:`1812`]
    Host_Precedence_Violation = 14

    #: Precedence cutoff in effect [:rfc:`1812`]
    Precedence_cutoff_in_effect = 15

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Reject ``value`` unless it passes the range check :meth:`_missing_` makes.

        Overrides :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value`
        with that check and the message it raises, so
        :meth:`~pcapkit.corekit.enum.EnumRegistry.register` refuses exactly the
        values :meth:`~pcapkit.corekit.enum.EnumLookup.get` refuses, in the
        same words (:issue:`1816`).

        Args:
            value: Value about to be looked up or minted.

        Raises:
            EnumValueError: If ``value`` fails that check. A
                :exc:`ValueError`, so an ``except ValueError`` caller is
                unaffected.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'DestinationUnreachableCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')
