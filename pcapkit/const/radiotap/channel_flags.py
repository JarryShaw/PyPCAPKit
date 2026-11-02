# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Radiotap Channel Flags
============================

.. module:: pcapkit.const.radiotap.channel_flags

This module contains the constant enumeration for **Radiotap Channel Flags**,
which is automatically generated from :class:`pcapkit.vendor.radiotap.channel_flags.ChannelFlags`.

"""

from typing import TYPE_CHECKING

from aenum import IntFlag

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['ChannelFlags']


class ChannelFlags(EnumRegistry, IntFlag):
    """[ChannelFlags] Radiotap Channel Flags"""

    #: S1G 700MHz spectrum channel
    CHAN_700MHZ = 1 << 0

    #: S1G 800MHz spectrum channel
    CHAN_800MHZ = 1 << 1

    #: S1G 900MHz spectrum channel
    CHAN_900MHZ = 1 << 2

    #: Turbo Channel
    CHAN_TURBO = 1 << 4

    #: CCK channel
    CHAN_CCK = 1 << 5

    #: OFDM channel
    CHAN_OFDM = 1 << 6

    #: 2 GHz spectrum channel
    CHAN_2GHZ = 1 << 7

    #: 5 GHz spectrum channel
    CHAN_5GHZ = 1 << 8

    #: Only passive scan allowed
    CHAN_PASSIVE = 1 << 9

    #: Dynamic CCK-OFDM channel
    CHAN_DYN = 1 << 10

    #: GFSK channel (FHSS PHY)
    CHAN_GFSK = 1 << 11

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
    def _missing_(cls, value: 'int') -> 'ChannelFlags':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)
