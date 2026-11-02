# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""DCCP Reset Codes
======================

.. module:: pcapkit.const.dccp.reset_code

This module contains the constant enumeration for **DCCP Reset Codes**,
which is automatically generated from :class:`pcapkit.vendor.dccp.reset_code.ResetCode`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['ResetCode']


class ResetCode(EnumRegistry, IntEnum):
    """[ResetCode] DCCP Reset Codes"""

    #: Unspecified [:rfc:`4340`]
    Unspecified = 0

    #: Closed [:rfc:`4340`]
    Closed = 1

    #: Aborted [:rfc:`4340`]
    Aborted = 2

    #: No Connection [:rfc:`4340`]
    No_Connection = 3

    #: Packet Error [:rfc:`4340`]
    Packet_Error = 4

    #: Option Error [:rfc:`4340`]
    Option_Error = 5

    #: Mandatory Error [:rfc:`4340`]
    Mandatory_Error = 6

    #: Connection Refused [:rfc:`4340`]
    Connection_Refused = 7

    #: Bad Service Code [:rfc:`4340`]
    Bad_Service_Code = 8

    #: Too Busy [:rfc:`4340`]
    Too_Busy = 9

    #: Bad Init Cookie [:rfc:`4340`]
    Bad_Init_Cookie = 10

    #: Aggression Penalty [:rfc:`4340`]
    Aggression_Penalty = 11

    #: Encapsulated Port Reuse [:rfc:`6773`]
    Encapsulated_Port_Reuse = 12

    #: Abrupt MP termination [:rfc:`9897`]
    Abrupt_MP_termination = 13

    #: Unassigned [:rfc:`4340`]
    Unassigned_127 = 127

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
    def _missing_(cls, value: 'int') -> 'ResetCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 14 <= value <= 119:
            #: Unassigned [:rfc:`4340`]
            return cls._unregistered_member(value, 'Unassigned')
        if 120 <= value <= 126:
            #: Reserved [:rfc:`4340`]
            return cls._unregistered_member(value, 'Reserved')
        if 128 <= value <= 255:
            #: CCID-specific codes [:rfc:`4340`]
            return cls._unregistered_member(value, 'CCID_specific_codes')
        return super()._missing_(value)
