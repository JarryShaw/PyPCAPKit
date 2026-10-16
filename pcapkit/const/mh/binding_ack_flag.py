# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Binding Acknowledgment Flags
==================================

.. module:: pcapkit.const.mh.binding_ack_flag

This module contains the constant enumeration for **Binding Acknowledgment Flags**,
which is automatically generated from :class:`pcapkit.vendor.mh.binding_ack_flag.BindingACKFlag`.

"""

from typing import TYPE_CHECKING

from aenum import IntFlag

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['BindingACKFlag']


class BindingACKFlag(EnumRegistry, IntFlag):
    """[BindingACKFlag] Binding Acknowledgment Flags"""

    #: K [:rfc:`6275`]
    K = 0x80

    #: R [:rfc:`3963`]
    R = 0x40

    #: P [:rfc:`5213`]
    P = 0x20

    #: T [:rfc:`5845`]
    T = 0x10

    #: B [:rfc:`6602`]
    B = 0x08

    #: S [:rfc:`7161`]
    S = 0x04

    #: D [:rfc:`8885`]
    D = 0x02

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
    def _missing_(cls, value: 'int') -> 'BindingACKFlag':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)
