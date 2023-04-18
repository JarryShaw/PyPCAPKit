# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Binding Update Flags
==========================

.. module:: pcapkit.const.mh.binding_update_flag

This module contains the constant enumeration for **Binding Update Flags**,
which is automatically generated from :class:`pcapkit.vendor.mh.binding_update_flag.BindingUpdateFlag`.

"""

from aenum import IntFlag

__all__ = ['BindingUpdateFlag']


class BindingUpdateFlag(IntFlag):
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

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'BindingUpdateFlag':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return BindingUpdateFlag(key)
        return BindingUpdateFlag[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'BindingUpdateFlag':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls(value)
