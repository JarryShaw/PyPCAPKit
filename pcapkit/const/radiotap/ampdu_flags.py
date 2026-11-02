# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Radiotap A-MPDU Status Flags
==================================

.. module:: pcapkit.const.radiotap.ampdu_flags

This module contains the constant enumeration for **Radiotap A-MPDU Status Flags**,
which is automatically generated from :class:`pcapkit.vendor.radiotap.ampdu_flags.AMPDUFlags`.

"""

from typing import TYPE_CHECKING

from aenum import IntFlag

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['AMPDUFlags']


class AMPDUFlags(EnumRegistry, IntFlag):
    """[AMPDUFlags] Radiotap A-MPDU Status Flags"""

    #: driver reports 0-length subframes
    AMPDU_REPORT_ZEROLEN = 1 << 0

    #: frame is 0-length subframe (valid only if 0x0001 is set)
    AMPDU_IS_ZEROLEN = 1 << 1

    #: last subframe is known (should be set for all subframes in an A-MPDU)
    AMPDU_LAST_KNOWN = 1 << 2

    #: this frame is the last subframe
    AMPDU_IS_LAST = 1 << 3

    #: delimiter CRC error
    AMPDU_DELIM_CRC_ERR = 1 << 4

    #: delimiter CRC value known: the delimiter CRC value field is valid
    AMPDU_DELIM_CRC_KNOWN = 1 << 5

    #: EOF value
    AMPDU_EOF = 1 << 6

    #: EOF value known
    AMPDU_EOF_KNOWN = 1 << 7

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
    def _missing_(cls, value: 'int') -> 'AMPDUFlags':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)
