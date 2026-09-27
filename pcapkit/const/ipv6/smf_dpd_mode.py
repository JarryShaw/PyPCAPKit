# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Simplified Multicast Forwarding Duplicate Packet Detection (``SMF_DPD``) Options
======================================================================================

.. module:: pcapkit.const.ipv6.smf_dpd_mode

This module contains the constant enumeration for **Simplified Multicast Forwarding Duplicate Packet Detection (``SMF_DPD``) Options**,
which is automatically generated from :class:`pcapkit.vendor.ipv6.smf_dpd_mode.SMFDPDMode`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['SMFDPDMode']


class SMFDPDMode(EnumRegistry, IntEnum):
    """[SMFDPDMode] Simplified Multicast Forwarding Duplicate Packet Detection (``SMF_DPD``) Options"""

    I_DPD = 0

    H_DPD = 1

    @classmethod
    def _missing_(cls, value: 'int') -> 'SMFDPDMode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')
