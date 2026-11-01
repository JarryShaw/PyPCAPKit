# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""IEEE 802.11 Management Frame Subtypes
===========================================

.. module:: pcapkit.const.ieee802_11.management_subtype

This module contains the constant enumeration for **IEEE 802.11 Management Frame Subtypes**,
which is automatically generated from :class:`pcapkit.vendor.ieee802_11.management_subtype.ManagementSubtype`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['ManagementSubtype']


class ManagementSubtype(EnumRegistry, IntEnum):
    """[ManagementSubtype] IEEE 802.11 Management Frame Subtypes [IEEE Std 802.11-2020, Table 9-1]"""

    #: Association Request
    Association_Request = 0

    #: Association Response
    Association_Response = 1

    #: Reassociation Request
    Reassociation_Request = 2

    #: Reassociation Response
    Reassociation_Response = 3

    #: Probe Request
    Probe_Request = 4

    #: Probe Response
    Probe_Response = 5

    #: Timing Advertisement
    Timing_Advertisement = 6

    #: Reserved
    Reserved_7 = 7

    #: Beacon
    Beacon = 8

    #: ATIM
    ATIM = 9

    #: Disassociation
    Disassociation = 10

    #: Authentication
    Authentication = 11

    #: Deauthentication
    Deauthentication = 12

    #: Action
    Action = 13

    #: Action No Ack (NACK)
    Action_No_Ack = 14

    #: Reserved
    Reserved_15 = 15

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
        if not (isinstance(value, int) and 0b0000 <= value <= 0b1111):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'ManagementSubtype':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0b0000 <= value <= 0b1111):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)
