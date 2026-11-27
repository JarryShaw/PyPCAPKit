# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""LLC Supervisory Functions
===============================

.. module:: pcapkit.const.llc.supervisory_function

This module contains the constant enumeration for **LLC Supervisory Functions**,
which is automatically generated from :class:`pcapkit.vendor.llc.supervisory_function.SupervisoryFunction`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['SupervisoryFunction']


class SupervisoryFunction(EnumRegistry, IntEnum):
    """[SupervisoryFunction] LLC Supervisory Functions [IEEE Std 802.2]"""

    #: Receive Ready
    RR = 0x00

    #: Receive Not Ready
    RNR = 0x04

    #: Reject
    REJ = 0x08

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
        if not (isinstance(value, int) and 0x00 <= value <= 0x0C and not value & 0x03):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'SupervisoryFunction':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x00 <= value <= 0x0C and not value & 0x03):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')
