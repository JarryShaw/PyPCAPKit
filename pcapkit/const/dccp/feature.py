# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""DCCP Feature Numbers
==========================

.. module:: pcapkit.const.dccp.feature

This module contains the constant enumeration for **DCCP Feature Numbers**,
which is automatically generated from :class:`pcapkit.vendor.dccp.feature.Feature`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['Feature']


class Feature(EnumRegistry, IntEnum):
    """[Feature] DCCP Feature Numbers"""

    #: Reserved [:rfc:`4340`]
    Reserved_0 = 0

    #: Congestion Control ID (CCID) [:rfc:`4340`]
    Congestion_Control_ID = 1

    #: Allow Short Seqnos [:rfc:`4340`]
    Allow_Short_Seqnos = 2

    #: Sequence Window [:rfc:`4340`]
    Sequence_Window = 3

    #: ECN Incapable [:rfc:`4340`]
    ECN_Incapable = 4

    #: Ack Ratio [:rfc:`4340`]
    Ack_Ratio = 5

    #: Send Ack Vector [:rfc:`4340`]
    Send_Ack_Vector = 6

    #: Send NDP Count [:rfc:`4340`]
    Send_NDP_Count = 7

    #: Minimum Checksum Coverage [:rfc:`4340`]
    Minimum_Checksum_Coverage = 8

    #: Check Data Checksum [:rfc:`4340`]
    Check_Data_Checksum = 9

    #: Multipath Capable [:rfc:`9897`]
    Multipath_Capable = 10

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
    def _missing_(cls, value: 'int') -> 'Feature':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 11 <= value <= 119:
            #: Unassigned [:rfc:`4340`]
            return cls._unregistered_member(value, 'Unassigned')
        if 120 <= value <= 126:
            #: Reserved [:rfc:`4340`]
            return cls._unregistered_member(value, 'Reserved')
        if 128 <= value <= 255:
            #: CCID-specific codes [:rfc:`4340`]
            return cls._unregistered_member(value, 'CCID_specific_codes')
        return super()._missing_(value)
