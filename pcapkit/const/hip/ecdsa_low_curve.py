# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""ECDSA_LOW Curve Label"""

from aenum import IntEnum, extend_enum

__all__ = ['ECDSALowCurve']


class ECDSALowCurve(IntEnum):
    """[ECDSALowCurve] ECDSA_LOW Curve Label"""

    #: RESERVED [:rfc:`7401`]
    RESERVED_0 = 0

    #: SECP160R1 [:rfc:`7401`]
    SECP160R1 = 1

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'ECDSALowCurve':
        """Backport support for original codes."""
        if isinstance(key, int):
            return ECDSALowCurve(key)
        if key not in ECDSALowCurve._member_map_:  # pylint: disable=no-member
            extend_enum(ECDSALowCurve, key, default)
        return ECDSALowCurve[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'ECDSALowCurve':
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 2 <= value <= 65535:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        return super()._missing_(value)
