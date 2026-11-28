# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""DHCP Message Type 53 Values
=================================

.. module:: pcapkit.const.dhcp.message_type

This module contains the constant enumeration for **DHCP Message Type 53 Values**,
which is automatically generated from :class:`pcapkit.vendor.dhcp.message_type.MessageType`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['MessageType']


class MessageType(EnumRegistry, IntEnum):
    """[MessageType] DHCP Message Type 53 Values"""

    #: DHCPDISCOVER [:rfc:`2132`]
    DHCPDISCOVER = 1

    #: DHCPOFFER [:rfc:`2132`]
    DHCPOFFER = 2

    #: DHCPREQUEST [:rfc:`2132`]
    DHCPREQUEST = 3

    #: DHCPDECLINE [:rfc:`2132`]
    DHCPDECLINE = 4

    #: DHCPACK [:rfc:`2132`]
    DHCPACK = 5

    #: DHCPNAK [:rfc:`2132`]
    DHCPNAK = 6

    #: DHCPRELEASE [:rfc:`2132`]
    DHCPRELEASE = 7

    #: DHCPINFORM [:rfc:`2132`]
    DHCPINFORM = 8

    #: DHCPFORCERENEW [:rfc:`3203`]
    DHCPFORCERENEW = 9

    #: DHCPLEASEQUERY [:rfc:`4388`]
    DHCPLEASEQUERY = 10

    #: DHCPLEASEUNASSIGNED [:rfc:`4388`]
    DHCPLEASEUNASSIGNED = 11

    #: DHCPLEASEUNKNOWN [:rfc:`4388`]
    DHCPLEASEUNKNOWN = 12

    #: DHCPLEASEACTIVE [:rfc:`4388`]
    DHCPLEASEACTIVE = 13

    #: DHCPBULKLEASEQUERY [:rfc:`6926`]
    DHCPBULKLEASEQUERY = 14

    #: DHCPLEASEQUERYDONE [:rfc:`6926`]
    DHCPLEASEQUERYDONE = 15

    #: DHCPACTIVELEASEQUERY [:rfc:`7724`]
    DHCPACTIVELEASEQUERY = 16

    #: DHCPLEASEQUERYSTATUS [:rfc:`7724`]
    DHCPLEASEQUERYSTATUS = 17

    #: DHCPTLS [:rfc:`7724`]
    DHCPTLS = 18

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
    def _missing_(cls, value: 'int') -> 'MessageType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')
