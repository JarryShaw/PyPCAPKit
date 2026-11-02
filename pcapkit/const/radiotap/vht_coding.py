# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Radiotap VHT Coding Flags
===============================

.. module:: pcapkit.const.radiotap.vht_coding

This module contains the constant enumeration for **Radiotap VHT Coding Flags**,
which is automatically generated from :class:`pcapkit.vendor.radiotap.vht_coding.VHTCoding`.

"""

from typing import TYPE_CHECKING

from aenum import IntFlag

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['VHTCoding']


class VHTCoding(EnumRegistry, IntFlag):
    """[VHTCoding] Radiotap VHT Coding Flags"""

    #: Coding for user 0 -- Set to 0 for BCC. Set to 1 for LDPC.
    CODING_LDPC_USER0 = 1 << 0

    #: Coding for user 1 -- Set to 0 for BCC. Set to 1 for LDPC.
    CODING_LDPC_USER1 = 1 << 1

    #: Coding for user 2 -- Set to 0 for BCC. Set to 1 for LDPC.
    CODING_LDPC_USER2 = 1 << 2

    #: Coding for user 3 -- Set to 0 for BCC. Set to 1 for LDPC.
    CODING_LDPC_USER3 = 1 << 3

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
    def _missing_(cls, value: 'int') -> 'VHTCoding':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)
