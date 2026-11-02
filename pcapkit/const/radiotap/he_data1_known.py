# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Radiotap HE Data1 Known Flags
===================================

.. module:: pcapkit.const.radiotap.he_data1_known

This module contains the constant enumeration for **Radiotap HE Data1 Known Flags**,
which is automatically generated from :class:`pcapkit.vendor.radiotap.he_data1_known.HEData1Known`.

"""

from typing import TYPE_CHECKING

from aenum import IntFlag

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['HEData1Known']


class HEData1Known(EnumRegistry, IntFlag):
    """[HEData1Known] Radiotap HE Data1 Known Flags"""

    #: BSS Color known
    HE_DATA1_BSS_COLOR_KNOWN = 1 << 2

    #: Beam Change known
    HE_DATA1_BEAM_CHANGE_KNOWN = 1 << 3

    #: UL/DL known
    HE_DATA1_UL_DL_KNOWN = 1 << 4

    #: data MCS known
    HE_DATA1_DATA_MCS_KNOWN = 1 << 5

    #: data DCM known
    HE_DATA1_DATA_DCM_KNOWN = 1 << 6

    #: Coding known
    HE_DATA1_CODING_KNOWN = 1 << 7

    #: LDPC extra symbol segment known
    HE_DATA1_LDPC_XSYMSEG_KNOWN = 1 << 8

    #: STBC known
    HE_DATA1_STBC_KNOWN = 1 << 9

    #: Spatial Reuse known (Spatial Reuse 1 for HE_TRIG format)
    HE_DATA1_SPTL_REUSE_KNOWN = 1 << 10

    #: Spatial Reuse 2 known (HE_TRIG format), STA-ID known (HE_MU format)
    HE_DATA1_SPTL_REUSE2_KNOWN = 1 << 11

    #: Spatial Reuse 3 known (HE_TRIG format)
    HE_DATA1_SPTL_REUSE3_KNOWN = 1 << 12

    #: Spatial Reuse 4 known (HE_TRIG format)
    HE_DATA1_SPTL_REUSE4_KNOWN = 1 << 13

    #: data BW/RU allocation known
    HE_DATA1_BW_RU_ALLOC_KNOWN = 1 << 14

    #: Doppler known
    HE_DATA1_DOPPLER_KNOWN = 1 << 15

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
    def _missing_(cls, value: 'int') -> 'HEData1Known':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)
