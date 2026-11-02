# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Radiotap HE-MU Flags1 Known Flags
=======================================

.. module:: pcapkit.const.radiotap.he_mu_flags1_known

This module contains the constant enumeration for **Radiotap HE-MU Flags1 Known Flags**,
which is automatically generated from :class:`pcapkit.vendor.radiotap.he_mu_flags1_known.HEMUFlags1Known`.

"""

from typing import TYPE_CHECKING

from aenum import IntFlag

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['HEMUFlags1Known']


class HEMUFlags1Known(EnumRegistry, IntFlag):
    """[HEMUFlags1Known] Radiotap HE-MU Flags1 Known Flags"""

    #: SIG-B MCS known
    HE_MU_FLAGS1_SIG_B_MCS_KNOWN = 1 << 4

    #: SIG-B DCM known
    HE_MU_FLAGS1_SIG_B_DCM_KNOWN = 1 << 6

    #: (Channel 2) Center 26-tone RU bit known
    HE_MU_FLAGS1_CH2_CTR_26T_RU_KNOWN = 1 << 7

    #: Channel 1 RUs known (which depends on BW)
    HE_MU_FLAGS1_CH1_RU_KNOWN = 1 << 8

    #: Channel 2 RUs known (which depends on BW)
    HE_MU_FLAGS1_CH2_RU_KNOWN = 1 << 9

    #: (Channel 1) Center 26-tone RU bit known
    HE_MU_FLAGS1_CH1_CTR_26T_RU_KNOWN = 1 << 12

    #: SIG-B Compression known
    HE_MU_FLAGS1_SIG_B_COMP_KNOWN = 1 << 14

    #: # of HE-SIG-B Symbols/MU-MIMO Users known
    HE_MU_FLAGS1_SIG_B_SYMS_USERS_KNOWN = 1 << 15

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
    def _missing_(cls, value: 'int') -> 'HEMUFlags1Known':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)
