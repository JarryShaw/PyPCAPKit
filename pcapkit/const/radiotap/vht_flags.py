# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Radiotap VHT Flags
========================

.. module:: pcapkit.const.radiotap.vht_flags

This module contains the constant enumeration for **Radiotap VHT Flags**,
which is automatically generated from :class:`pcapkit.vendor.radiotap.vht_flags.VHTFlags`.

"""

from typing import TYPE_CHECKING

from aenum import IntFlag

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['VHTFlags']


class VHTFlags(EnumRegistry, IntFlag):
    """[VHTFlags] Radiotap VHT Flags"""

    #: STBC -- Space-time block coding. Set to 0 if no spatial streams of any user
    #: has STBC. Set to 1 if all spatial streams of all users have STBC.
    VHT_FLAG_STBC = 1 << 0

    #: TXOP_PS_NOT_ALLOWED -- Valid only for AP transmitters. Set to 0 if STAs may
    #: doze during TXOP. Set to 1 if STAs may not doze during TXOP or transmitter
    #: is non-AP.
    VHT_FLAG_TXOP_PS_NA = 1 << 1

    #: Guard interval. -- Set to 0 for long GI. Set to 1 for short GI.
    VHT_FLAG_SGI = 1 << 2

    #: Short GI NSYM disambiguation -- Valid only if short GI is used. Set to 0 if
    #: NSYM mod 10 != 9 or short GI not used. Set to 1 if NSYM mod 10 = 9.
    VHT_FLAG_SGI_NSYM_M10_9 = 1 << 3

    #: LDPC Extra OFDM symbol -- Set to 1 if one or more users are using LDPC and
    #: the encoding process resulted in extra OFDM symbol(s). Set to 0 otherwise.
    VHT_FLAG_LDPC_EXTRA_OFDM_SYM = 1 << 4

    #: Beamformed -- Valid for SU PPDUs only.
    VHT_FLAG_BEAMFORMED = 1 << 5

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
    def _missing_(cls, value: 'int') -> 'VHTFlags':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)
