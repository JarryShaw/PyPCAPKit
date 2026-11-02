# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Radiotap S1G Known Flags
==============================

.. module:: pcapkit.const.radiotap.s1g_known

This module contains the constant enumeration for **Radiotap S1G Known Flags**,
which is automatically generated from :class:`pcapkit.vendor.radiotap.s1g_known.S1GKnown`.

"""

from typing import TYPE_CHECKING

from aenum import IntFlag

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['S1GKnown']


class S1GKnown(EnumRegistry, IntFlag):
    """[S1GKnown] Radiotap S1G Known Flags"""

    #: S1G PPDU Format known
    S1G_KNOWN_PPDU_FORMAT = 1 << 0

    #: Response indication known
    S1G_KNOWN_RESPONSE_IND = 1 << 1

    #: Guard interval known
    S1G_KNOWN_GI = 1 << 2

    #: NSS known
    S1G_KNOWN_NSS = 1 << 3

    #: Bandwidth known
    S1G_KNOWN_BW = 1 << 4

    #: MCS known
    S1G_KNOWN_MCS = 1 << 5

    #: Color known
    S1G_KNOWN_COLOR = 1 << 6

    #: uplink indication known
    S1G_KNOWN_UPLINK_IND = 1 << 7

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
        if not (isinstance(value, int) and 0 <= value <= 0xFFFF):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'S1GKnown':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)
