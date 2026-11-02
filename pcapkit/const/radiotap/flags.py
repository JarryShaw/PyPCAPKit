# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Radiotap Flags
====================

.. module:: pcapkit.const.radiotap.flags

This module contains the constant enumeration for **Radiotap Flags**,
which is automatically generated from :class:`pcapkit.vendor.radiotap.flags.Flags`.

"""

from typing import TYPE_CHECKING

from aenum import IntFlag

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['Flags']


class Flags(EnumRegistry, IntFlag):
    """[Flags] Radiotap Flags"""

    #: sent/received during CFP
    F_CFP = 1 << 0

    #: sent/received with short preamble
    F_SHORTPRE = 1 << 1

    #: sent/received with WEP encryption
    F_WEP = 1 << 2

    #: sent/received with fragmentation
    F_FRAG = 1 << 3

    #: frame includes FCS
    F_FCS = 1 << 4

    #: frame has padding between 802.11 header and payload (to 32-bit boundary)
    F_DATAPAD = 1 << 5

    #: frame failed FCS check
    F_BADFCS = 1 << 6

    #: frame used short guard interval (HT) [Currently unspecified but used]
    F_SHORTGI = 1 << 7

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
        if not (isinstance(value, int) and 0 <= value <= 0xFF):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'Flags':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)
