# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Radiotap HE-MU Flags2 Known Flags
=======================================

.. module:: pcapkit.const.radiotap.he_mu_flags2_known

This module contains the constant enumeration for **Radiotap HE-MU Flags2 Known Flags**,
which is automatically generated from :class:`pcapkit.vendor.radiotap.he_mu_flags2_known.HEMUFlags2Known`.

"""

from typing import TYPE_CHECKING

from aenum import IntFlag

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['HEMUFlags2Known']


class HEMUFlags2Known(EnumRegistry, IntFlag):
    """[HEMUFlags2Known] Radiotap HE-MU Flags2 Known Flags"""

    #: bandwidth from Bandwidth field in HE-SIG-A known
    HE_MU_FLAGS2_BW_FROM_SIG_A_BW_KNOWN = 1 << 2

    #: preamble puncturing from Bandwidth field in HE-SIG-A known
    HE_MU_FLAGS2_PUNC_FROM_SIG_A_BW_KNOWN = 1 << 10

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
    def _missing_(cls, value: 'int') -> 'HEMUFlags2Known':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)
