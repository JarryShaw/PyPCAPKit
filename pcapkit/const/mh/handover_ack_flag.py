# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Handover Acknowledge Flags
================================

.. module:: pcapkit.const.mh.handover_ack_flag

This module contains the constant enumeration for **Handover Acknowledge Flags**,
which is automatically generated from :class:`pcapkit.vendor.mh.handover_ack_flag.HandoverACKFlag`.

"""

from aenum import IntFlag

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['HandoverACKFlag']


class HandoverACKFlag(EnumRegistry, IntFlag):
    """[HandoverACKFlag] Handover Acknowledge Flags"""

    #: Buffer flag [:rfc:`5949`]
    U = 0x80

    #: Proxy flag [:rfc:`5949`]
    P = 0x40

    #: Forwarding flag [:rfc:`5949`]
    F = 0x20

    @classmethod
    def _missing_(cls, value: 'int') -> 'HandoverACKFlag':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)
