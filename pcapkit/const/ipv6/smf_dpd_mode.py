# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Simplified Multicast Forwarding Duplicate Packet Detection (``SMF_DPD``) Options
======================================================================================

.. module:: pcapkit.const.ipv6.smf_dpd_mode

This module contains the constant enumeration for **Simplified Multicast Forwarding Duplicate Packet Detection (``SMF_DPD``) Options**,
which is automatically generated from :class:`pcapkit.vendor.ipv6.smf_dpd_mode.SMFDPDMode`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['SMFDPDMode']


class SMFDPDMode(IntEnum):
    """[SMFDPDMode] Simplified Multicast Forwarding Duplicate Packet Detection (``SMF_DPD``) Options"""

    I_DPD = 0

    H_DPD = 1

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'SMFDPDMode':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return SMFDPDMode(key)
        if key not in SMFDPDMode._member_map_:  # pylint: disable=no-member
            return extend_enum(SMFDPDMode, key, default)
        return SMFDPDMode[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'SMFDPDMode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)
