# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""TS Flag
=============

.. module:: pcapkit.const.ipv4.ts_flag

This module contains the constant enumeration for **TS Flag**,
which is automatically generated from :class:`pcapkit.vendor.ipv4.ts_flag.TSFlag`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['TSFlag']


class TSFlag(EnumRegistry, IntEnum):
    """[TSFlag] TS Flag"""

    Timestamp_Only = 0

    IP_with_Timestamp = 1

    Prespecified_IP_with_Timestamp = 3

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
    def _missing_(cls, value: 'int') -> 'TSFlag':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0b0000 <= value <= 0b1111):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')
