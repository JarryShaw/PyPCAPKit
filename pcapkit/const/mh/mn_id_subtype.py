# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Mobile Node Identifier Option Subtypes
============================================

.. module:: pcapkit.const.mh.mn_id_subtype

This module contains the constant enumeration for **Mobile Node Identifier Option Subtypes**,
which is automatically generated from :class:`pcapkit.vendor.mh.mn_id_subtype.MNIDSubtype`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['MNIDSubtype']


class MNIDSubtype(EnumRegistry, IntEnum):
    """[MNIDSubtype] Mobile Node Identifier Option Subtypes"""

    #: NAI [:rfc:`4283`]
    NAI = 1

    #: IPv6 Address [:rfc:`8371`]
    IPv6_Address = 2

    #: IMSI [:rfc:`8371`]
    IMSI = 3

    #: P-TMSI [:rfc:`8371`]
    P_TMSI = 4

    #: EUI-48 address [:rfc:`8371`]
    EUI_48_address = 5

    #: EUI-64 address [:rfc:`8371`]
    EUI_64_address = 6

    #: GUTI [:rfc:`8371`]
    GUTI = 7

    #: DUID [:rfc:`8371`]
    DUID = 8

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
    def _missing_(cls, value: 'int') -> 'MNIDSubtype':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 9 <= value <= 15:
            #: Reserved [:rfc:`8371`]
            return cls._unregistered_member(value, 'Reserved')
        if 16 <= value <= 255:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
