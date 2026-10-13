# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Binding Acknowledgment Flags
==================================

.. module:: pcapkit.const.mh.binding_ack_flag

This module contains the constant enumeration for **Binding Acknowledgment Flags**,
which is automatically generated from :class:`pcapkit.vendor.mh.binding_ack_flag.BindingACKFlag`.

"""

from aenum import IntFlag

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['BindingACKFlag']


class BindingACKFlag(EnumRegistry, IntFlag):
    """[BindingACKFlag] Binding Acknowledgment Flags"""

    #: K [RFC 6275]
    K = 0x80

    #: R [RFC 3963]
    R = 0x40

    #: P [RFC 5213]
    P = 0x20

    #: T [RFC 5845]
    T = 0x10

    #: B [RFC 6602]
    B = 0x08

    #: S [RFC 7161]
    S = 0x04

    #: D [RFC 8885]
    D = 0x02

    @classmethod
    def _missing_(cls, value: 'int') -> 'BindingACKFlag':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)
