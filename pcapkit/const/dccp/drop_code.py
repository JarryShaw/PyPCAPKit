# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""DCCP Drop Codes
=====================

.. module:: pcapkit.const.dccp.drop_code

This module contains the constant enumeration for **DCCP Drop Codes**,
which is automatically generated from :class:`pcapkit.vendor.dccp.drop_code.DropCode`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['DropCode']


class DropCode(EnumRegistry, IntEnum):
    """[DropCode] DCCP Drop Codes"""

    #: Protocol Constraints [:rfc:`4340`]
    Protocol_Constraints = 0

    #: Application Not Listening [:rfc:`4340`]
    Application_Not_Listening = 1

    #: Receive Buffer [:rfc:`4340`]
    Receive_Buffer = 2

    #: Corrupt [:rfc:`4340`]
    Corrupt = 3

    #: Delivered Corrupt [:rfc:`4340`]
    Delivered_Corrupt = 7

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
        if not (isinstance(value, int) and 0 <= value <= 7):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'DropCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 7):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 4 <= value <= 6:
            #: Unassigned [:rfc:`4340`]
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
