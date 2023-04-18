# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Binding Acknowledgment Flags
==================================

.. module:: pcapkit.const.mh.binding_ack_flag

This module contains the constant enumeration for **Binding Acknowledgment Flags**,
which is automatically generated from :class:`pcapkit.vendor.mh.binding_ack_flag.BindingACKFlag`.

"""

from aenum import IntFlag

__all__ = ['BindingACKFlag']


class BindingACKFlag(IntFlag):
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

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'BindingACKFlag':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return BindingACKFlag(key)
        return BindingACKFlag[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'BindingACKFlag':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls(value)
