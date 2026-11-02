# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Radiotap HE Data2 Known Flags
===================================

.. module:: pcapkit.const.radiotap.he_data2_known

This module contains the constant enumeration for **Radiotap HE Data2 Known Flags**,
which is automatically generated from :class:`pcapkit.vendor.radiotap.he_data2_known.HEData2Known`.

"""

from typing import TYPE_CHECKING

from aenum import IntFlag

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['HEData2Known']


class HEData2Known(EnumRegistry, IntFlag):
    """[HEData2Known] Radiotap HE Data2 Known Flags"""

    #: pri/sec 80 MHz known
    HE_DATA2_PRISEC_80_KNOWN = 1 << 0

    #: GI known
    HE_DATA2_GI_KNOWN = 1 << 1

    #: number of LTF symbols known
    HE_DATA2_NUM_LTF_SYMS_KNOWN = 1 << 2

    #: Pre-FEC Padding Factor known
    HE_DATA2_PRE_FEC_PAD_KNOWN = 1 << 3

    #: TxBF known
    HE_DATA2_TXBF_KNOWN = 1 << 4

    #: PE Disambiguity known
    HE_DATA2_PE_DISAMBIG_KNOWN = 1 << 5

    #: TXOP known
    HE_DATA2_TXOP_KNOWN = 1 << 6

    #: midamble periodicity known
    HE_DATA2_MIDAMBLE_KNOWN = 1 << 7

    #: RU allocation offset known
    HE_DATA2_RU_OFFSET_KNOWN = 1 << 14

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
    def _missing_(cls, value: 'int') -> 'HEData2Known':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)
