# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""IEEE 802.11 Control Frame Subtypes
========================================

.. module:: pcapkit.const.ieee802_11.control_subtype

This module contains the constant enumeration for **IEEE 802.11 Control Frame Subtypes**,
which is automatically generated from :class:`pcapkit.vendor.ieee802_11.control_subtype.ControlSubtype`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['ControlSubtype']


class ControlSubtype(EnumRegistry, IntEnum):
    """[ControlSubtype] IEEE 802.11 Control Frame Subtypes [IEEE Std 802.11-2020, Table 9-1]"""

    #: Trigger
    Trigger = 2

    #: TACK
    TACK = 3

    #: Beamforming Report Poll
    Beamforming_Report_Poll = 4

    #: VHT/HE NDP Announcement
    VHT_HE_NDP_Announcement = 5

    #: Control Frame Extension
    Control_Frame_Extension = 6

    #: Control Wrapper
    Control_Wrapper = 7

    #: Block Ack Request (BAR)
    Block_Ack_Request = 8

    #: Block Ack (BA)
    Block_Ack = 9

    #: PS-Poll
    PS_Poll = 10

    #: RTS
    RTS = 11

    #: CTS
    CTS = 12

    #: ACK
    ACK = 13

    #: CF-End
    CF_End = 14

    #: CF-End + CF-ACK
    CF_End_CF_ACK = 15

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
    def _missing_(cls, value: 'int') -> 'ControlSubtype':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0b0000 <= value <= 0b1111):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0 <= value <= 1:
            #: Reserved
            return cls._unregistered_member(value, 'Reserved')
        return super()._missing_(value)
