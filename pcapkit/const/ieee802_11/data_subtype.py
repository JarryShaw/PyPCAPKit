# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""IEEE 802.11 Data Frame Subtypes
=====================================

.. module:: pcapkit.const.ieee802_11.data_subtype

This module contains the constant enumeration for **IEEE 802.11 Data Frame Subtypes**,
which is automatically generated from :class:`pcapkit.vendor.ieee802_11.data_subtype.DataSubtype`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['DataSubtype']


class DataSubtype(EnumRegistry, IntEnum):
    """[DataSubtype] IEEE 802.11 Data Frame Subtypes [IEEE Std 802.11-2020, Table 9-1]"""

    #: Data
    Data = 0

    #: Null (no data)
    Null = 4

    #: QoS Data
    QoS_Data = 8

    #: QoS Data + CF-ACK
    QoS_Data_CF_ACK = 9

    #: QoS Data + CF-Poll
    QoS_Data_CF_Poll = 10

    #: QoS Data + CF-ACK + CF-Poll
    QoS_Data_CF_ACK_CF_Poll = 11

    #: QoS Null (no data)
    QoS_Null = 12

    #: Reserved
    Reserved_13 = 13

    #: QoS CF-Poll (no data)
    QoS_CF_Poll = 14

    #: QoS CF-ACK + CF-Poll (no data)
    QoS_CF_ACK_CF_Poll = 15

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
    def _missing_(cls, value: 'int') -> 'DataSubtype':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0b0000 <= value <= 0b1111):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 1 <= value <= 3:
            #: Reserved
            return cls._unregistered_member(value, 'Reserved')
        if 5 <= value <= 7:
            #: Reserved
            return cls._unregistered_member(value, 'Reserved')
        return super()._missing_(value)
