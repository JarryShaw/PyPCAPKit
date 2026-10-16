# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Binding Update Flags
==========================

.. module:: pcapkit.const.mh.binding_update_flag

This module contains the constant enumeration for **Binding Update Flags**,
which is automatically generated from :class:`pcapkit.vendor.mh.binding_update_flag.BindingUpdateFlag`.

"""

from typing import TYPE_CHECKING

from aenum import IntFlag

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['BindingUpdateFlag']


class BindingUpdateFlag(EnumRegistry, IntFlag):
    """[BindingUpdateFlag] Binding Update Flags"""

    #: A [:rfc:`6275`]
    A = 0x8000

    #: H [:rfc:`6275`]
    H = 0x4000

    #: L [:rfc:`6275`]
    L = 0x2000

    #: K [:rfc:`6275`]
    K = 0x1000

    #: M [:rfc:`4140`]
    M = 0x0800

    #: R [:rfc:`3963`]
    R = 0x0400

    #: P [:rfc:`5213`]
    P = 0x0200

    #: F [:rfc:`5555`]
    F = 0x0100

    #: T [:rfc:`5845`]
    T = 0x0080

    #: B [:rfc:`6602`]
    B = 0x0040

    #: S [:rfc:`7161`]
    S = 0x0020

    #: D [:rfc:`8885`]
    D = 0x0010

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
    def _missing_(cls, value: 'int') -> 'BindingUpdateFlag':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)
