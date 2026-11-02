# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Radiotap TX Flags
=======================

.. module:: pcapkit.const.radiotap.tx_flags

This module contains the constant enumeration for **Radiotap TX Flags**,
which is automatically generated from :class:`pcapkit.vendor.radiotap.tx_flags.TXFlags`.

"""

from typing import TYPE_CHECKING

from aenum import IntFlag

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['TXFlags']


class TXFlags(EnumRegistry, IntFlag):
    """[TXFlags] Radiotap TX Flags"""

    #: Transmission failed due to excessive retries
    F_TX_FAIL = 1 << 0

    #: Transmission used CTS-to-self protection
    F_TX_CTS = 1 << 1

    #: Transmission used RTS/CTS handshake
    F_TX_RTS = 1 << 2

    #: Transmission shall not expect an ACK frame and not retry when no ACK is
    #: received
    F_TX_NOACK = 1 << 3

    #: Transmission includes a pre-configured sequence number that should not be
    #: changed by the driver’s TX handlers
    F_TX_NOSEQNO = 1 << 4

    #: Transmission should not be reordered relative to other frames that have this
    #: flag set
    F_TX_ORDER = 1 << 5

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
    def _missing_(cls, value: 'int') -> 'TXFlags':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)
