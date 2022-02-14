# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Simplified Multicast Forwarding Duplicate Packet Detection (``SMF_DPD``) Options"""

from aenum import IntEnum, extend_enum

__all__ = ['SMFDPDMode']


class SMFDPDMode(IntEnum):
    """[SMFDPDMode] Simplified Multicast Forwarding Duplicate Packet Detection (``SMF_DPD``) Options"""

    I_DPD = 0

    H_DPD = 1

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'SMFDPDMode':
        """Backport support for original codes."""
        if isinstance(key, int):
            return SMFDPDMode(key)
        if key not in SMFDPDMode._member_map_:  # pylint: disable=no-member
            extend_enum(SMFDPDMode, key, default)
        return SMFDPDMode[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'SMFDPDMode':
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned_%d' % value, value)
        return cls(value)
