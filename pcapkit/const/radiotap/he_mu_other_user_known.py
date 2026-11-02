# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Radiotap HE-MU-other-user Known Flags
===========================================

.. module:: pcapkit.const.radiotap.he_mu_other_user_known

This module contains the constant enumeration for **Radiotap HE-MU-other-user Known Flags**,
which is automatically generated from :class:`pcapkit.vendor.radiotap.he_mu_other_user_known.HEMUOtherUserKnown`.

"""

from typing import TYPE_CHECKING

from aenum import IntFlag

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['HEMUOtherUserKnown']


class HEMUOtherUserKnown(EnumRegistry, IntFlag):
    """[HEMUOtherUserKnown] Radiotap HE-MU-other-user Known Flags"""

    #: user field position known
    user_field_position_known = 1 << 0

    #: STA-ID known (B0-10)
    STA_ID_known = 1 << 1

    #: NSTS known (B11-13, only for non-MU-MIMO)
    NSTS_known = 1 << 2

    #: Tx Beamforming known (B14, only for non-MU-MIMO)
    Tx_Beamforming_known = 1 << 3

    #: Spatial Configuration known (B11-B14, only for MU-MIMO)
    Spatial_Configuration_known = 1 << 4

    #: MCS known (B15-18)
    MCS_known = 1 << 5

    #: DCM known (B19)
    DCM_known = 1 << 6

    #: Coding known (B20)
    Coding_known = 1 << 7

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
        if not (isinstance(value, int) and 0 <= value <= 0xFF):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'HEMUOtherUserKnown':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)
