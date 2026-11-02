# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Radiotap EHT Known Flags
==============================

.. module:: pcapkit.const.radiotap.eht_known

This module contains the constant enumeration for **Radiotap EHT Known Flags**,
which is automatically generated from :class:`pcapkit.vendor.radiotap.eht_known.EHTKnown`.

"""

from typing import TYPE_CHECKING

from aenum import IntFlag

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['EHTKnown']


class EHTKnown(EnumRegistry, IntFlag):
    """[EHTKnown] Radiotap EHT Known Flags"""

    #: Spatial Reuse Known
    EHT_KNOWN_SPATIAL_REUSE = 1 << 1

    #: GI (Guard Interval) Known
    EHT_KNOWN_GI = 1 << 2

    #: number of LTF symbols Known
    EHT_KNOWN_EHT_LTF = 1 << 4

    #: OFDMA (including TB), MU-MIMO: LDPC Extra Symbol Segment Known
    EHT_KNOWN_LDPC_EXTRA_SYM_OM = 1 << 5

    #: OFDMA (including TB), MU-MIMO: Pre-FEC Padding Factor Known
    EHT_KNOWN_PRE_PADD_FACOR_OM = 1 << 6

    #: OFDMA (including TB), MU-MIMO: PE Disambiguity Known
    EHT_KNOWN_PE_DISAMBIGUITY_OM = 1 << 7

    #: OFDMA (including TB), MU-MIMO: Disregard Known
    EHT_KNOWN_DISREGARD_O = 1 << 8

    #: EHT sounding: Disregard Known
    EHT_KNOWN_DISREGARD_S = 1 << 9

    #: CRC1 Known
    EHT_KNOWN_CRC1 = 1 << 13

    #: Tail1 Known
    EHT_KNOWN_TAIL1 = 1 << 14

    #: OFDMA (including TB): CRC2 Known
    EHT_KNOWN_CRC2_O = 1 << 15

    #: OFDMA (including TB): Tail2 Known
    EHT_KNOWN_TAIL2_O = 1 << 16

    #: EHT sounding: NSS Known
    EHT_KNOWN_NSS_S = 1 << 17

    #: EHT sounding: Beamformed Known
    EHT_KNOWN_BEAMFORMED_S = 1 << 18

    #: MU-MIMO: Number Of Non-OFDMA Users Known
    EHT_KNOWN_NR_NON_OFDMA_USERS_M = 1 << 19

    #: MU-MIMO: User Encoding Block CRC Known
    EHT_KNOWN_ENCODING_BLOCK_CRC_M = 1 << 20

    #: MU-MIMO: User Encoding Block Tail Known
    EHT_KNOWN_ENCODING_BLOCK_TAIL_M = 1 << 21

    #: OFDMA (including TB), MU-MIMO: RU/MRU Size Known
    EHT_KNOWN_RU_MRU_SIZE_OM = 1 << 22

    #: OFDMA (including TB), MU-MIMO: RU/MRU Index Known
    EHT_KNOWN_RU_MRU_INDEX_OM = 1 << 23

    #: OFDMA (including TB), MU-MIMO: RU Allocation (TB format) Known
    EHT_KNOWN_RU_ALLOC_TB_FMT = 1 << 24

    #: Primary 80 MHz Channel Position known
    EHT_KNOWN_PRIMARY_80 = 1 << 25

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
        if not (isinstance(value, int) and 0 <= value <= 0xFFFFFFFF):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'EHTKnown':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFFFFFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)
