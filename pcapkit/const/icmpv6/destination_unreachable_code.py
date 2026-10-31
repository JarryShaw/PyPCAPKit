# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""ICMPv6 Destination Unreachable Codes
==========================================

.. module:: pcapkit.const.icmpv6.destination_unreachable_code

This module contains the constant enumeration for **ICMPv6 Destination Unreachable Codes**,
which is automatically generated from :class:`pcapkit.vendor.icmpv6.destination_unreachable_code.DestinationUnreachableCode`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['DestinationUnreachableCode']


class DestinationUnreachableCode(EnumRegistry, IntEnum):
    """[DestinationUnreachableCode] ICMPv6 Destination Unreachable Codes [:rfc:`4443`]"""

    #: no route to destination
    no_route_to_destination = 0

    #: communication with destination administratively prohibited
    communication_with_destination_administratively_prohibited = 1

    #: beyond scope of source address [:rfc:`4443`]
    beyond_scope_of_source_address = 2

    #: address unreachable
    address_unreachable = 3

    #: port unreachable
    port_unreachable = 4

    #: source address failed ingress/egress policy [:rfc:`4443`]
    source_address_failed_ingress_egress_policy = 5

    #: reject route to destination [:rfc:`4443`]
    reject_route_to_destination = 6

    #: Error in Source Routing Header [:rfc:`6550`][:rfc:`6554`]
    Error_in_Source_Routing_Header = 7

    #: Headers too long [:rfc:`8883`]
    Headers_too_long = 8

    #: Error in P-Route [:rfc:`9914`]
    Error_in_P_Route = 9

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
