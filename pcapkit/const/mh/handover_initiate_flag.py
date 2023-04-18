# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Handover Initiate Flags
=============================

.. module:: pcapkit.const.mh.handover_initiate_flag

This module contains the constant enumeration for **Handover Initiate Flags**,
which is automatically generated from :class:`pcapkit.vendor.mh.handover_initiate_flag.HandoverInitiateFlag`.

"""

from aenum import IntFlag

__all__ = ['HandoverInitiateFlag']


class HandoverInitiateFlag(IntFlag):
    """[HandoverInitiateFlag] Handover Initiate Flags"""

    #: Assigned Address Configuration flag [:rfc:`5568`]
    S = 0x80

    #: Buffer flag [:rfc:`5568`]
    U = 0x40

    #: Proxy flag [:rfc:`5949`]
    P = 0x20

    #: Forwarding flag [:rfc:`5949`]
    F = 0x10

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'HandoverInitiateFlag':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return HandoverInitiateFlag(key)
        return HandoverInitiateFlag[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'HandoverInitiateFlag':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls(value)
